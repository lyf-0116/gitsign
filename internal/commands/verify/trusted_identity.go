// Copyright 2026 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package verify

import (
	"bufio"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	gogit "github.com/go-git/go-git/v5"
	cosignopts "github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/gitsign/internal/sigstore/compat"
)

// IdentitySource records where the expected certificate identity came from, so
// the success output can distinguish an identity the verifier was explicitly
// told to trust from one merely read off the certificate (or the commit).
type IdentitySource int

const (
	// IdentitySourceNone means no identity policy was applied: the output
	// describes the certificate, not a trusted allowlist.
	IdentitySourceNone IdentitySource = iota
	// IdentitySourceFlag means the identity came from --certificate-identity*
	// flags (or the equivalent config), i.e. an explicit trust decision.
	IdentitySourceFlag
	// IdentitySourceAllowlist means the identity came from a trusted
	// identities allowlist configured for the repository.
	IdentitySourceAllowlist
)

// allowlistHTTPClient is overridable in tests to serve a stub allowlist without
// touching the network.
var allowlistHTTPClient = http.DefaultClient

// leafCertificate extracts the first signer certificate embedded in a gitsign
// CMS signature. The certificate is read without validating the signature;
// callers still run the full cryptographic verification before trusting any
// claim derived from it. The cert is used only to pick the matching trusted
// identity policy ahead of verification.
func LeafCertificate(sig []byte) (*x509.Certificate, error) {
	sd, err := compat.ParseSignaturePEM(sig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signature: %w", err)
	}
	certs, err := sd.GetCertificates()
	if err != nil {
		return nil, fmt.Errorf("error getting signature certificates: %w", err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in signature")
	}
	return certs[0], nil
}

// resolveCertIdentity makes sure verification always runs against an identity
// the caller or the repository configuration actually trusts. It never derives
// the expected identity from the commit's committer field: that field is part
// of the signed object and is trivially forgeable, so matching it only proves
// the certificate repeats whatever the commit claims.
//
// An explicit --certificate-identity / --certificate-identity-regexp (with its
// issuer) is left untouched. When neither is given, the configured trusted
// identities are loaded and, if the certificate's SAN + issuer match an entry,
// that entry is pinned as the expected identity. If no allowlist is configured
// or nothing matches, an error is returned rather than failing open.
func ResolveCertIdentity(ctx context.Context, cfg *config.Config, opts *cosignopts.CertVerifyOptions, repo *gogit.Repository, certSANs []string, certIssuer string) (IdentitySource, error) {
	if opts.CertIdentity != "" || opts.CertIdentityRegexp != "" {
		if err := requireIssuerPair(opts); err != nil {
			return IdentitySourceNone, err
		}
		return IdentitySourceFlag, nil
	}

	trusted, err := loadTrustedIdentities(ctx, cfg, repo)
	if err != nil {
		return IdentitySourceNone, err
	}
	if len(trusted) == 0 {
		return IdentitySourceNone, fmt.Errorf(
			"no trusted certificate identity configured: pass --certificate-identity together with --certificate-oidc-issuer, " +
				"or configure gitsign.trustedIdentities / gitsign.trustedIdentitiesFile; " +
				"the commit committer email is not a trusted identity source")
	}

	for _, entry := range trusted {
		if entry.Issuer != certIssuer {
			continue
		}
		for _, san := range certSANs {
			if san == entry.Identity {
				opts.CertIdentity = entry.Identity
				opts.CertOidcIssuer = entry.Issuer
				return IdentitySourceAllowlist, nil
			}
		}
	}

	return IdentitySourceNone, fmt.Errorf(
		"certificate identity %v (issuer %q) is not in the repository's trusted identities allowlist",
		certSANs, certIssuer)
}

// requireIssuerPair enforces that an identity claim and an OIDC issuer claim
// are always supplied together. An identity without an issuer accepts a
// matching SAN from any issuer, and an issuer without an identity accepts any
// subject from that issuer; either half alone leaves "who signed this"
// undecided.
func requireIssuerPair(opts *cosignopts.CertVerifyOptions) error {
	hasIdentity := opts.CertIdentity != "" || opts.CertIdentityRegexp != ""
	hasIssuer := opts.CertOidcIssuer != "" || opts.CertOidcIssuerRegexp != ""
	if hasIdentity && !hasIssuer {
		return fmt.Errorf("--certificate-oidc-issuer or --certificate-oidc-issuer-regexp is required together with a certificate identity")
	}
	if hasIssuer && !hasIdentity {
		return fmt.Errorf("--certificate-identity or --certificate-identity-regexp is required together with a certificate oidc issuer")
	}
	return nil
}

// loadTrustedIdentities returns the configured trusted identities, preferring
// inline gitsign.trustedIdentities entries and then the allowlist referenced by
// gitsign.trustedIdentitiesFile.
func loadTrustedIdentities(ctx context.Context, cfg *config.Config, repo *gogit.Repository) ([]config.TrustedIdentity, error) {
	if cfg == nil {
		return nil, nil
	}
	if len(cfg.TrustedIdentities) > 0 {
		return cfg.TrustedIdentities, nil
	}
	if cfg.TrustedIdentitiesFile == "" {
		return nil, nil
	}

	loc, err := allowlistLocation(cfg.TrustedIdentitiesFile, repo)
	if err != nil {
		return nil, err
	}
	data, err := readAllowlist(ctx, loc)
	if err != nil {
		return nil, fmt.Errorf("reading trusted identities file %q: %w", cfg.TrustedIdentitiesFile, err)
	}
	return parseAllowlist(data), nil
}

// allowlistLocation resolves a gitsign.trustedIdentitiesFile value to a URL or
// local path. Absolute http(s) URLs and absolute/local file paths are used as
// given; a repo-relative path (no scheme, not an absolute path) is joined onto
// the origin remote so the allowlist can be read straight from the hosting
// repository.
func allowlistLocation(loc string, repo *gogit.Repository) (string, error) {
	if u, err := url.Parse(loc); err == nil && (u.Scheme == "http" || u.Scheme == "https" || u.Scheme == "file") {
		return loc, nil
	}
	if strings.HasPrefix(loc, "/") || strings.HasPrefix(loc, "./") || strings.HasPrefix(loc, "../") {
		return loc, nil
	}

	remoteURL, err := originURL(repo)
	if err != nil {
		return "", err
	}
	base, err := url.Parse(remoteURL)
	if err != nil {
		return "", fmt.Errorf("parsing origin URL %q: %w", remoteURL, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return "", fmt.Errorf("cannot resolve repo-relative allowlist %q from non-HTTP origin %q; use an absolute URL or local path", loc, remoteURL)
	}
	base.Path = strings.TrimSuffix(base.Path, ".git")
	base.Path = strings.TrimSuffix(base.Path, "/") + "/raw/" + loc
	return base.String(), nil
}

// originURL returns the first URL of the origin remote.
func originURL(repo *gogit.Repository) (string, error) {
	if repo == nil {
		return "", fmt.Errorf("no git repository available to resolve origin remote")
	}
	remote, err := repo.Remote("origin")
	if err != nil {
		return "", fmt.Errorf("resolving origin remote for trusted identities file: %w", err)
	}
	urls := remote.Config().URLs
	if len(urls) == 0 || urls[0] == "" {
		return "", fmt.Errorf("origin remote has no URL configured")
	}
	return urls[0], nil
}

// readAllowlist fetches an http(s) allowlist or reads a local file.
func readAllowlist(ctx context.Context, loc string) ([]byte, error) {
	if strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, loc, nil)
		if err != nil {
			return nil, err
		}
		resp, err := allowlistHTTPClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close() // nolint:errcheck
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
		}
		return io.ReadAll(resp.Body)
	}

	path := strings.TrimPrefix(loc, "file://")
	return os.ReadFile(path) // nolint:gosec
}

// parseAllowlist reads one "identity issuer" pair per line. Blank lines and
// lines starting with # are ignored; malformed lines are skipped rather than
// widening the allowlist with an incomplete pair.
func parseAllowlist(data []byte) []config.TrustedIdentity {
	var out []config.TrustedIdentity
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		out = append(out, config.TrustedIdentity{Identity: fields[0], Issuer: fields[1]})
	}
	return out
}
