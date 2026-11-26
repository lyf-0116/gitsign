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
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/sigstore/gitsign/internal/fulcio/fulcioroots"
	"github.com/sigstore/gitsign/internal/sigstore/compat"
	"github.com/sigstore/sigstore/pkg/tuf"
)

// Verifier verifies git commit signature data.
type Verifier interface {
	Verify(ctx context.Context, data, sig []byte, detached bool, verifyTime time.Time) (*x509.Certificate, error)
}

// CertVerifier is the default implementation of Verifier.
// It verifies git commits against a given CertPool. By default, the system
// CertPool + Fulcio roots are used for validation.
type CertVerifier struct {
	roots         *x509.CertPool
	intermediates *x509.CertPool
	tsa           *x509.CertPool
}

type CertVerifierOption func(*CertVerifier) error

func NewCertVerifier(opts ...CertVerifierOption) (*CertVerifier, error) {
	v := &CertVerifier{}

	for _, o := range opts {
		if err := o(v); err != nil {
			return nil, err
		}
	}

	// Use empty pool if not set - this makes it so that we don't fallback
	// to the system pool.
	if v.roots == nil {
		v.roots = x509.NewCertPool()
	}

	return v, nil
}

// WithRootPool sets the base CertPool for the verifier.
func WithRootPool(pool *x509.CertPool) CertVerifierOption {
	return func(v *CertVerifier) error {
		v.roots = pool
		return nil
	}
}

// WithIntermediatePool sets the base intermediate CertPool for the verifier.
func WithIntermediatePool(pool *x509.CertPool) CertVerifierOption {
	return func(v *CertVerifier) error {
		v.intermediates = pool
		return nil
	}
}

// WithIntermediatePool sets the base intermediate CertPool for the verifier.
func WithTimestampCertPool(pool *x509.CertPool) CertVerifierOption {
	return func(v *CertVerifier) error {
		v.tsa = pool
		return nil
	}
}

// Verify verifies for a given Git data + signature pair.
//
// Data should be the Git data that was signed (i.e. everything in the commit
// besides the signature). Note: passing in the commit object itself will not
// work.
//
// Signatures should be CMS/PKCS7 formatted.
//
// verifyTime pins the certificate validity-window check to an independently
// sourced signing time (a Rekor entry's integrated time, or zero when the
// signature carries a verified RFC3161 timestamp, which the internal CMS
// verifier uses itself). Passing zero for a signature without a timestamp is
// an error: the verifier no longer invents a time inside the cert's own
// window.
func (v *CertVerifier) Verify(_ context.Context, data, sig []byte, detached bool, verifyTime time.Time) (*x509.Certificate, error) {
	// Parse signature (PEM-armored or raw DER).
	sd, err := compat.ParseSignaturePEM(sig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signature: %w", err)
	}

	// Fail fast with a clear error if the cert bag is empty — otherwise the
	// internal verifier's per-SignerInfo FindCertificate error is what the
	// caller sees, and the message is less obvious.
	if certs, err := sd.GetCertificates(); err != nil {
		return nil, fmt.Errorf("error getting signature certs: %w", err)
	} else if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in signature")
	}

	opts := x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: v.intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		// Pin the chain check to the attested signing time. When the
		// signature carries an RFC3161 timestamp the internal CMS verifier
		// verifies the token and overrides this with its GenTime; otherwise
		// the caller must pass the Rekor integrated time. A zero value with
		// no timestamp fails explicitly instead of defaulting to a time
		// inside the cert's own validity window.
		CurrentTime: verifyTime,
	}

	tsaOpts := x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	if v.tsa != nil {
		tsaOpts.Roots = v.tsa
	}

	var chains [][][]*x509.Certificate
	if detached {
		chains, err = sd.VerifyDetached(data, opts, tsaOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to verify detached signature: %w", err)
		}
	} else {
		chains, err = sd.Verify(opts, tsaOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to verify attached signature: %w", err)
		}
	}

	// Return the leaf of the first verified chain — this is the certificate
	// the internal CMS verifier actually authenticated the signature against,
	// not whatever happens to sit at certs[0].
	if len(chains) == 0 || len(chains[0]) == 0 || len(chains[0][0]) == 0 {
		return nil, fmt.Errorf("no verified certificate chains returned")
	}
	return chains[0][0][0], nil
}

// NewDefaultVerifier returns a new CertVerifier with the default Fulcio roots loaded from the local TUF client.
// See https://docs.sigstore.dev/system_config/custom_components/ for how to customize this behavior.
func NewDefaultVerifier(ctx context.Context) (*CertVerifier, error) {
	if err := tuf.Initialize(ctx, tuf.DefaultRemoteRoot, nil); err != nil {
		return nil, err
	}
	root, intermediate, err := fulcioroots.New(x509.NewCertPool(), fulcioroots.FromTUF(ctx))
	if err != nil {
		return nil, err
	}
	return NewCertVerifier(WithRootPool(root), WithIntermediatePool(intermediate))
}
