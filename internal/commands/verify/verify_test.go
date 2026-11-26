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
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	gogit "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	cosignopts "github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/gitsign/pkg/git"
)

// TestRun_RejectsUnsupportedSignatureType confirms the sentinel is wrapped
// so callers can errors.Is on it. End-to-end coverage of the GHSA
// trust-confusion attack lives in
// internal/gitsign/invalid_object_test.go::TestDuplicateTreeTrustConfusion.
func TestRun_RejectsUnsupportedSignatureType(t *testing.T) {
	tmpDir := t.TempDir()
	repo, err := gogit.PlainInit(tmpDir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}

	// Well-formed commit but with a PGP SIGNATURE (not SIGNED MESSAGE) in gpgsig.
	raw := []byte(`tree b333504b8cf3d9c314fed2cc242c5c38e89534a5
author Alice <alice@example.com> 1700000000 +0000
committer Alice <alice@example.com> 1700000000 +0000
gpgsig -----BEGIN PGP SIGNATURE-----
 ZmFrZQ==
 -----END PGP SIGNATURE-----

hi
`)

	obj := repo.Storer.NewEncodedObject()
	obj.SetType(plumbing.CommitObject)
	w, err := obj.Writer()
	if err != nil {
		t.Fatalf("obj.Writer: %v", err)
	}
	if _, err := w.Write(raw); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	h, err := repo.Storer.SetEncodedObject(obj)
	if err != nil {
		t.Fatalf("SetEncodedObject: %v", err)
	}

	t.Chdir(tmpDir)

	opts := &options{}
	err = opts.Run(io.Discard, []string{h.String()})
	if !errors.Is(err, git.ErrUnsupportedSignatureType) {
		t.Fatalf("want error wrapping ErrUnsupportedSignatureType, got %v", err)
	}
}

// TestResolveCertIdentity covers the trust rules behind `gitsign verify`:
// the expected identity comes from explicit flags or a repository allowlist,
// never from the commit's committer field, and identity + issuer are always
// required together.
func TestResolveCertIdentity(t *testing.T) {
	tmpDir := t.TempDir()
	repo, err := gogit.PlainInit(tmpDir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}

	raw := []byte(`tree b333504b8cf3d9c314fed2cc242c5c38e89534a5
author Alice <alice@example.com> 1700000000 +0000
committer Alice <alice@example.com> 1700000000 +0000

hi
`)
	obj := repo.Storer.NewEncodedObject()
	obj.SetType(plumbing.CommitObject)
	w, err := obj.Writer()
	if err != nil {
		t.Fatalf("obj.Writer: %v", err)
	}
	if _, err := w.Write(raw); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	h, err := repo.Storer.SetEncodedObject(obj)
	if err != nil {
		t.Fatalf("SetEncodedObject: %v", err)
	}
	_ = h

	ctx := context.Background()
	const (
		alice   = "alice@example.com"
		issuer  = "https://oauth2.sigstore.dev/auth"
		bob     = "bob@example.com"
		issuer2 = "https://token.actions.githubusercontent.com"
	)

	t.Run("explicit identity and issuer are trusted as flags", func(t *testing.T) {
		opts := &cosignopts.CertVerifyOptions{CertIdentity: bob, CertOidcIssuer: issuer}
		source, err := ResolveCertIdentity(ctx, nil, opts, repo, []string{bob}, issuer)
		if err != nil {
			t.Fatalf("ResolveCertIdentity: %v", err)
		}
		if source != IdentitySourceFlag {
			t.Errorf("source = %v, want IdentitySourceFlag", source)
		}
	})

	t.Run("regexp identity and regexp issuer are accepted as a pair", func(t *testing.T) {
		opts := &cosignopts.CertVerifyOptions{
			CertIdentityRegexp:   ".*@example.com",
			CertOidcIssuerRegexp: "https://.*",
		}
		source, err := ResolveCertIdentity(ctx, nil, opts, repo, []string{alice}, issuer)
		if err != nil {
			t.Fatalf("ResolveCertIdentity: %v", err)
		}
		if source != IdentitySourceFlag {
			t.Errorf("source = %v, want IdentitySourceFlag", source)
		}
	})

	t.Run("identity without issuer is rejected", func(t *testing.T) {
		opts := &cosignopts.CertVerifyOptions{CertIdentity: bob}
		if _, err := ResolveCertIdentity(ctx, nil, opts, repo, []string{bob}, issuer); err == nil {
			t.Fatal("want error when identity has no issuer, got nil")
		}
	})

	t.Run("issuer without identity is rejected", func(t *testing.T) {
		opts := &cosignopts.CertVerifyOptions{CertOidcIssuer: issuer}
		if _, err := ResolveCertIdentity(ctx, nil, opts, repo, []string{alice}, issuer); err == nil {
			t.Fatal("want error when issuer has no identity, got nil")
		}
	})

	t.Run("no flags and no allowlist fails instead of trusting the committer", func(t *testing.T) {
		opts := &cosignopts.CertVerifyOptions{}
		_, err := ResolveCertIdentity(ctx, &config.Config{}, opts, repo, []string{alice}, issuer)
		if err == nil {
			t.Fatal("want error with no trusted identity configured, got nil")
		}
		if opts.CertIdentity != "" {
			t.Errorf("CertIdentity = %q, want empty (must not default to the committer)", opts.CertIdentity)
		}
	})

	t.Run("inline allowlist pins a matching identity and issuer", func(t *testing.T) {
		cfg := &config.Config{TrustedIdentities: []config.TrustedIdentity{
			{Identity: alice, Issuer: issuer},
		}}
		opts := &cosignopts.CertVerifyOptions{}
		source, err := ResolveCertIdentity(ctx, cfg, opts, repo, []string{alice}, issuer)
		if err != nil {
			t.Fatalf("ResolveCertIdentity: %v", err)
		}
		if source != IdentitySourceAllowlist {
			t.Errorf("source = %v, want IdentitySourceAllowlist", source)
		}
		if opts.CertIdentity != alice || opts.CertOidcIssuer != issuer {
			t.Errorf("opts = %+v, want identity %q issuer %q", opts, alice, issuer)
		}
	})

	t.Run("matching identity from a different issuer is rejected", func(t *testing.T) {
		cfg := &config.Config{TrustedIdentities: []config.TrustedIdentity{
			{Identity: alice, Issuer: issuer},
		}}
		opts := &cosignopts.CertVerifyOptions{}
		if _, err := ResolveCertIdentity(ctx, cfg, opts, repo, []string{alice}, issuer2); err == nil {
			t.Fatal("want error when identity matches but issuer does not")
		}
	})

	t.Run("identity not on the allowlist is rejected", func(t *testing.T) {
		cfg := &config.Config{TrustedIdentities: []config.TrustedIdentity{
			{Identity: bob, Issuer: issuer},
		}}
		opts := &cosignopts.CertVerifyOptions{}
		if _, err := ResolveCertIdentity(ctx, cfg, opts, repo, []string{alice}, issuer); err == nil {
			t.Fatal("want error for untrusted identity, got nil")
		}
	})
}

// TestLoadTrustedIdentitiesFromFile covers the local and HTTP allowlist
// fallbacks that keep one-command verification working once committer-derived
// identities are removed, including the repo-relative origin resolution.
func TestLoadTrustedIdentitiesFromFile(t *testing.T) {
	ctx := context.Background()
	allowlist := "# trusted signers\n" +
		"alice@example.com https://oauth2.sigstore.dev/auth\n" +
		"malformed-line\n" +
		"https://myorg/workflow https://token.actions.githubusercontent.com\n"

	t.Run("local file path", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "trusted-identities")
		if err := os.WriteFile(path, []byte(allowlist), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := &config.Config{TrustedIdentitiesFile: path}
		got, err := loadTrustedIdentities(ctx, cfg, nil)
		if err != nil {
			t.Fatalf("loadTrustedIdentities: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d entries, want 2 (malformed line skipped): %+v", len(got), got)
		}
		if got[0].Identity != "alice@example.com" || got[0].Issuer != "https://oauth2.sigstore.dev/auth" {
			t.Errorf("first entry = %+v", got[0])
		}
	})

	t.Run("http URL", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, allowlist)
		}))
		defer srv.Close()

		cfg := &config.Config{TrustedIdentitiesFile: srv.URL + "/trusted-identities"}
		got, err := loadTrustedIdentities(ctx, cfg, nil)
		if err != nil {
			t.Fatalf("loadTrustedIdentities: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d entries, want 2", len(got))
		}
	})

	t.Run("http error is surfaced", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "nope", http.StatusForbidden)
		}))
		defer srv.Close()

		cfg := &config.Config{TrustedIdentitiesFile: srv.URL + "/missing"}
		if _, err := loadTrustedIdentities(ctx, cfg, nil); err == nil {
			t.Fatal("want error when the allowlist cannot be fetched, got nil")
		}
	})

	t.Run("repo-relative path resolves against origin", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/org/repo/raw/.gitsign/trusted-identities" {
				http.NotFound(w, r)
				return
			}
			fmt.Fprint(w, allowlist)
		}))
		defer srv.Close()

		repo, err := gogit.PlainInit(t.TempDir(), false)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.CreateRemote(&gitconfig.RemoteConfig{
			Name: "origin",
			URLs: []string{srv.URL + "/org/repo.git"},
		}); err != nil {
			t.Fatal(err)
		}

		cfg := &config.Config{TrustedIdentitiesFile: ".gitsign/trusted-identities"}
		got, err := loadTrustedIdentities(ctx, cfg, repo)
		if err != nil {
			t.Fatalf("loadTrustedIdentities: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d entries, want 2", len(got))
		}
	})
}
