// Copyright 2023 The Sigstore Authors
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
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	cosignopts "github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/gitsign/internal"
	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/gitsign/internal/gitsign"
	"github.com/sigstore/gitsign/pkg/git"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/spf13/cobra"
)

type options struct {
	Config *config.Config
	cosignopts.CertVerifyOptions
}

func (o *options) AddFlags(cmd *cobra.Command) {
	o.CertVerifyOptions.AddFlags(cmd)
}

func (o *options) Run(_ io.Writer, args []string) error {
	ctx := context.Background()
	repo, err := gogit.PlainOpenWithOptions(".", &gogit.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		return err
	}

	revision := "HEAD"
	if len(args) > 0 {
		revision = args[0]
	}

	h, err := repo.ResolveRevision(plumbing.Revision(revision))
	if err != nil {
		return fmt.Errorf("error resolving commit object: %w", err)
	}

	obj, err := repo.Storer.EncodedObject(plumbing.CommitObject, *h)
	if err != nil {
		return fmt.Errorf("error reading commit object: %w", err)
	}
	r, err := obj.Reader()
	if err != nil {
		return err
	}
	defer r.Close() // nolint:errcheck

	c, err := git.SplitCommit(r)
	if err != nil {
		return fmt.Errorf("error extracting commit signature: %w", err)
	}

	// Per the SHA-256 transition spec a commit can carry gpgsig (SHA-1
	// form), gpgsig-sha256 (SHA-256 form), or both. Prefer gpgsig — every
	// repo go-git can read today is SHA-1 form, so its gpgsig matches the
	// stripped Payload. gpgsig-sha256 is the fallback for SHA-256-only
	// signed commits.
	sig := c.Gpgsig
	if sig == nil {
		sig = c.GpgsigSha256
	}
	if sig == nil {
		return fmt.Errorf("commit has no gpgsig or gpgsig-sha256 signature")
	}

	p, _ := pem.Decode(sig)
	if p == nil {
		return fmt.Errorf("%w: not a PEM block", git.ErrUnsupportedSignatureType)
	}
	if p.Type != "SIGNED MESSAGE" {
		return fmt.Errorf("%w: %q", git.ErrUnsupportedSignatureType, p.Type)
	}

	// Extract the signer certificate up front so the identity policy can be
	// decided before any verification runs. The cert is part of the CMS
	// signature; the signature itself is still fully validated below.
	leaf, err := LeafCertificate(sig)
	if err != nil {
		return fmt.Errorf("error reading signer certificate: %w", err)
	}
	leafExt := cosign.CertExtensions{Cert: leaf}

	// Decide which identity the certificate is allowed to carry before
	// verifying. The expected identity comes only from explicit flags or from
	// the repository's trusted allowlist - never from the commit's committer
	// field, which is attacker-controlled text.
	source, err := ResolveCertIdentity(
		ctx, o.Config, &o.CertVerifyOptions, repo,
		cryptoutils.GetSubjectAlternateNames(leaf),
		leafExt.GetIssuer(),
	)
	if err != nil {
		return err
	}

	v, err := gitsign.NewVerifierWithCosignOpts(ctx, o.Config, &o.CertVerifyOptions)
	if err != nil {
		return err
	}
	summary, err := v.Verify(ctx, c.Payload, sig, true)
	if err != nil {
		return err
	}

	PrintSummary(os.Stdout, summary, source)

	return nil
}

// PrintSummary writes the human-readable verification result. The identity
// source is called out explicitly so the "Good signature" line never presents
// a certificate- or commit-derived name as if it were a trusted identity.
func PrintSummary(w io.Writer, summary *git.VerificationSummary, source IdentitySource) {
	fpr := internal.CertHexFingerprint(summary.Cert)

	fmt.Fprintln(w, "tlog index:", *summary.LogEntry.LogIndex)                                           // nolint:errcheck
	fmt.Fprintf(w, "gitsign: Signature made using certificate ID 0x%s | %v\n", fpr, summary.Cert.Issuer) // nolint:errcheck

	ce := cosign.CertExtensions{Cert: summary.Cert}
	switch source {
	case IdentitySourceFlag:
		fmt.Fprintf(w, "gitsign: Good signature from %v(%s); identity source: command-line/config flags\n", cryptoutils.GetSubjectAlternateNames(summary.Cert), ce.GetIssuer()) // nolint:errcheck
	case IdentitySourceAllowlist:
		fmt.Fprintf(w, "gitsign: Good signature from %v(%s); identity source: repository trusted identities allowlist\n", cryptoutils.GetSubjectAlternateNames(summary.Cert), ce.GetIssuer()) // nolint:errcheck
	default:
		fmt.Fprintf(w, "gitsign: Signature certificate subject %v(%s); no trusted identity policy applied\n", cryptoutils.GetSubjectAlternateNames(summary.Cert), ce.GetIssuer()) // nolint:errcheck
	}

	for _, c := range summary.Claims {
		fmt.Fprintf(w, "%s: %t\n", string(c.Key), c.Value) // nolint:errcheck
	}
}

func New(cfg *config.Config) *cobra.Command {
	o := &options{Config: cfg}

	cmd := &cobra.Command{
		Use:          "verify [commit]",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		Short:        "Verify a commit",
		Long: `Verify a commit.

verify verifies a commit against a set of certificate claims.
This should generally be used over git verify-commit, since verify will
check the identity included in the signature's certificate.

The expected signer identity must come from a trusted source: pass
--certificate-identity together with --certificate-oidc-issuer, or configure
a repository allowlist via gitsign.trustedIdentities /
gitsign.trustedIdentitiesFile. The commit's committer email is never used as
the expected identity, because it is attacker-controlled text inside the
commit. Identity and OIDC issuer are always checked as a pair.

If no revision is specified, HEAD is used.`,
		RunE: func(_ *cobra.Command, args []string) error {
			// Simulate unknown flag errors.
			if o.Cert != "" {
				return fmt.Errorf("unknown flag: --certificate")
			}
			if o.CertChain != "" {
				return fmt.Errorf("unknown flag: --certificate-chain")
			}

			return o.Run(os.Stdout, args)
		},
	}
	o.AddFlags(cmd)

	// Hide flags we don't implement.
	// --certificate: The cert should always come from the commit.
	_ = cmd.Flags().MarkHidden("certificate")
	// --certificate-chain: We only support reading from a TUF root at the moment.
	// TODO: add support for this.
	_ = cmd.Flags().MarkHidden("certificate-chain")
	// --ca-intermediates and --ca-roots
	_ = cmd.Flags().MarkHidden("ca-intermediates")
	_ = cmd.Flags().MarkHidden("ca-roots")

	return cmd
}
