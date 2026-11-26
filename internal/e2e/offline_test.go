// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/sigstore/gitsign/internal/fulcio/fulcioroots"
	"github.com/sigstore/gitsign/internal/git/gittest"
	"github.com/sigstore/gitsign/internal/sigstore/compat"
	"github.com/sigstore/gitsign/pkg/git"
	"github.com/sigstore/gitsign/pkg/rekor"
	"github.com/sigstore/sigstore/pkg/tuf"
)

func TestVerifyOffline(t *testing.T) {
	ctx := context.Background()

	// Initialize to prod root.
	tuf.Initialize(ctx, tuf.DefaultRemoteRoot, nil)
	root, intermediate, err := fulcioroots.New(x509.NewCertPool(), fulcioroots.FromTUF(ctx))
	if err != nil {
		t.Fatalf("error getting certificate root: %v", err)
	}

	client, err := rekor.New("https://rekor.sigstore.dev")
	if err != nil {
		t.Fatal(err)
	}

	commit := gittest.ParseCommit(t, "testdata/offline.commit")
	body := gittest.MarshalCommitBody(t, commit)
	sig := []byte(commit.PGPSignature)

	verifier, err := git.NewCertVerifier(git.WithRootPool(root), git.WithIntermediatePool(intermediate))
	if err != nil {
		t.Fatal(err)
	}

	// Resolve the signing certificate from the signature before looking up
	// its Rekor entry.
	sd, err := compat.ParseSignaturePEM(sig)
	if err != nil {
		t.Fatal(err)
	}
	sdCerts, err := sd.GetCertificates()
	if err != nil {
		t.Fatal(err)
	}
	raw := sd.Raw()
	if len(raw.SignerInfos) == 0 {
		t.Fatal("no signers found in signature")
	}
	cert, err := raw.SignerInfos[0].FindCertificate(sdCerts)
	if err != nil {
		t.Fatal(err)
	}

	tlog, err := client.VerifyInclusion(ctx, sig, cert)
	if err != nil {
		t.Fatal(err)
	}
	// Pin the chain check to the entry's attested inclusion time and assert
	// it lies within the signing certificate's validity window.
	verifyTime, err := git.CheckIntegratedTime(cert, tlog)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(ctx, body, sig, true, verifyTime); err != nil {
		t.Fatal(err)
	}
	t.Log(*tlog.LogIndex)
}
