//
// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package git

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/sigstore/gitsign/internal/sigstore/compat"
	"github.com/sigstore/gitsign/pkg/rekor"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/rekor/pkg/generated/models"
)

// VerificationSummary holds artifacts of the gitsign verification of a Git commit or tag.
type VerificationSummary struct {
	// Certificate used to sign the commit.
	Cert *x509.Certificate
	// Rekor log entry of the commit.
	LogEntry *models.LogEntryAnon
	// Bundle is the sigstore bundle the signature was verified as. It is only
	// populated by the experimental bundle verification path (cfg.EnableSigstoreGo);
	// the legacy path leaves it nil.
	Bundle *protobundle.Bundle
	// List of claims about what succeeded / failed during validation.
	// This can be used to get details on what succeeded / failed during
	// validation. This is not an exhaustive list - claims may be missing
	// if validation ended early.
	Claims []Claim
}

// Claim is a key value pair representing the status of a given ClaimCondition.
type Claim struct {
	Key   ClaimCondition
	Value bool
}

type ClaimCondition string

const (
	ClaimValidatedSignature  ClaimCondition = "Validated Git signature"
	ClaimValidatedRekorEntry ClaimCondition = "Validated Rekor entry"
	ClaimValidatedCerificate ClaimCondition = "Validated Certificate claims"
)

func NewClaim(c ClaimCondition, ok bool) Claim {
	return Claim{
		Key:   c,
		Value: ok,
	}
}

// Verify takes a context, rekor verifier client, Git object data (everything but the signature), and a Git signature.
// A VerificationSummary is returned with the signing certificate & Rekor transparency log index of the Git object, if found,
// and whether each is valid for the given Git data.
func Verify(ctx context.Context, git Verifier, rekor rekor.Verifier, data, sig []byte, detached bool) (*VerificationSummary, error) {
	claims := []Claim{}

	// Parse the signature once so the signing time can be resolved before the
	// chain check runs. The chain must be verified at the attested signing
	// time (RFC3161 timestamp or Rekor integrated time), not at a time chosen
	// from the certificate's own validity window.
	sd, err := compat.ParseSignaturePEM(sig)
	if err != nil {
		return nil, err
	}
	certs, err := sd.GetCertificates()
	if err != nil {
		return nil, fmt.Errorf("error getting signature certs: %w", err)
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificates found in signature")
	}
	// Resolve the certificate the first SignerInfo actually authenticates
	// with, rather than whatever sits at certs[0] (the cert bag order is not
	// controlled by the signer). gitsign signatures carry a single signer.
	raw := sd.Raw()
	if len(raw.SignerInfos) == 0 {
		return nil, errors.New("no signers found in signature")
	}
	cert, err := raw.SignerInfos[0].FindCertificate(certs)
	if err != nil {
		return nil, fmt.Errorf("finding signer certificate: %w", err)
	}

	hasTS, err := sd.HasTimestamps()
	if err != nil {
		return nil, err
	}

	var (
		tlog       *models.LogEntryAnon
		verifyTime time.Time
	)
	if hasTS {
		// The RFC3161 timestamp is verified inside the CMS verifier and
		// supplies the verification time itself. The Rekor entry still has to
		// exist (inclusion is a separate guarantee), but its integrated time is
		// not needed to pin the chain check - the two sources are
		// substitutable.
		verifyTime = time.Time{}
	}

	// Offline path first: signatures produced by current gitsign embed the
	// Rekor entry in the CMS unsigned attributes. These entries always carry
	// an integrated time, which is checked against the cert validity window
	// before being used as the verification time.
	if tlog, err = rekor.VerifyInclusion(ctx, sig, cert); err == nil {
		if !hasTS {
			t, terr := CheckIntegratedTime(cert, tlog)
			if terr != nil {
				return nil, terr
			}
			verifyTime = t
		}
	} else {
		// Legacy rekor lookup: reconstruct the object hash that the legacy rekor
		// entries were keyed on. We assume sig is the SHA-1-form signature (gpgsig
		// for commits, in-body PEM for tags) — which matches how legacy rekor
		// entries were generated. For new gpgsig-sha256 signatures there are no
		// legacy entries to look up, so this reconstruction is best-effort.
		commit, herr := ObjectHashFromSignature(data, sig)
		if herr != nil {
			return nil, herr
		}
		tlog, err = rekor.Verify(ctx, commit, cert)
		if err != nil {
			return nil, fmt.Errorf("failed to validate rekor entry: %w", err)
		}
		// Legacy "online" entries predate the embedded-entry format and may not
		// carry an integrated time in every deployment. Grade them explicitly:
		// an entry with an integrated time is checked against the cert window
		// like the offline path; an entry without one cannot pin a time and is
		// downgraded to a current-time chain check rather than silently using a
		// time from the cert's own window. The inclusion proof above still
		// attests the entry.
		if !hasTS {
			t, terr := CheckIntegratedTime(cert, tlog)
			switch {
			case terr == nil:
				verifyTime = t
			case errors.Is(terr, ErrNoIntegratedTime):
				verifyTime = time.Now()
			default:
				return nil, terr
			}
		}
	}

	cert, err = git.Verify(ctx, data, sig, detached, verifyTime)
	if err != nil {
		return nil, err
	}
	claims = append(claims, NewClaim(ClaimValidatedSignature, true))
	claims = append(claims, NewClaim(ClaimValidatedRekorEntry, true))

	return &VerificationSummary{
		Cert:     cert,
		LogEntry: tlog,
		Claims:   claims,
	}, nil
}

// VerifySignature verifies for a given Git data + signature pair.
//
// Data should be the Git data that was signed (i.e. everything in the commit
// besides the signature). Note: passing in the commit object itself will not
// work.
//
// Signatures should be CMS/PKCS7 formatted.
//
// Deprecated: Use CertVerifier.Verify instead.
func VerifySignature(data, sig []byte, detached bool, rootCerts, intermediates *x509.CertPool) (*x509.Certificate, error) {
	v, err := NewCertVerifier(WithRootPool(rootCerts), WithIntermediatePool(intermediates))
	if err != nil {
		return nil, err
	}

	// This convenience wrapper has no Rekor client and no way to source an
	// attested signing time, so it verifies at the current time. Full
	// verification (integrated-time / timestamp based) goes through Verify.
	return v.Verify(context.Background(), data, sig, detached, time.Now())
}

// ObjectHashFromSignature reconstructs the git-core object hash from the object
// body (everything but the signature) and the signature, by reassembling the
// raw object bytes (gpgsig for commits, in-body PEM for tags) and hashing them.
// This is the hash legacy "online" Rekor entries are keyed on.
func ObjectHashFromSignature(data, sig []byte) (string, error) {
	var (
		raw []byte
		err error
	)
	switch {
	case bytes.HasPrefix(data, []byte("tree ")):
		raw, err = JoinCommit(&CommitSig{Payload: data, Gpgsig: sig})
	case bytes.HasPrefix(data, []byte("object ")):
		raw, err = JoinTag(&TagSig{Payload: data, InBody: sig})
	default:
		return "", errors.New("could not determine Git object type")
	}
	if err != nil {
		return "", err
	}
	return ObjectHash(raw)
}

// ObjectHash returns the git-core hash of an object given its raw bytes
// (the same bytes git stores in the object database, without the
// "<type> <size>\0" prefix). The object type is inferred from the first
// header line: "tree " for commits, "object " for tags.
func ObjectHash(raw []byte) (string, error) {
	var objType plumbing.ObjectType
	switch {
	case bytes.HasPrefix(raw, []byte("tree ")):
		objType = plumbing.CommitObject
	case bytes.HasPrefix(raw, []byte("object ")):
		objType = plumbing.TagObject
	default:
		return "", errors.New("could not determine Git object type")
	}

	obj := &plumbing.MemoryObject{}
	obj.SetType(objType)
	if _, err := obj.Write(raw); err != nil {
		return "", err
	}
	return obj.Hash().String(), nil
}
