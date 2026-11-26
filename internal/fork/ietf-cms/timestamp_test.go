package cms

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/github/smimesign/fakeca"
	"github.com/github/smimesign/ietf-cms/oid"
	"github.com/github/smimesign/ietf-cms/protocol"
	"github.com/sigstore/gitsign/internal/fork/ietf-cms/timestamp"
)

func TestAddTimestamps(t *testing.T) {
	// Good response
	tsa.Clear()
	sd, _ := NewSignedData([]byte("hi"))
	sd.Sign(leaf.Chain(), leaf.PrivateKey)
	if err := sd.AddTimestamps("https://google.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := sd.Verify(intermediateOpts, intermediateOpts); err != nil {
		t.Fatal(err)
	}
	if _, err := getTimestamp(sd.psd.SignerInfos[0], intermediateOpts); err != nil {
		t.Fatal(err)
	}

	// Error status in response
	tsa.HookResponse(func(resp timestamp.Response) timestamp.Response {
		resp.Status.Status = 1
		return resp
	})
	sd, _ = NewSignedData([]byte("hi"))
	sd.Sign(leaf.Chain(), leaf.PrivateKey)
	if err := sd.AddTimestamps("https://google.com"); err != nil {
		if _, isStatusErr := err.(timestamp.PKIStatusInfo); !isStatusErr {
			t.Fatalf("expected timestamp.PKIStatusInfo error, got %v", err)
		}
	}

	// Bad nonce
	tsa.HookInfo(func(info timestamp.Info) timestamp.Info {
		info.Nonce.SetInt64(123123)
		return info
	})
	sd, _ = NewSignedData([]byte("hi"))
	sd.Sign(leaf.Chain(), leaf.PrivateKey)
	if err := sd.AddTimestamps("https://google.com"); err == nil || err.Error() != "invalid message imprint" {
		t.Fatalf("expected 'invalid message imprint', got %v", err)
	}

	// Bad message imprint
	tsa.HookInfo(func(info timestamp.Info) timestamp.Info {
		info.MessageImprint.HashedMessage[0] ^= 0xFF
		return info
	})
	sd, _ = NewSignedData([]byte("hi"))
	sd.Sign(leaf.Chain(), leaf.PrivateKey)
	if err := sd.AddTimestamps("https://google.com"); err == nil || err.Error() != "invalid message imprint" {
		t.Fatalf("expected 'invalid message imprint', got %v", err)
	}
}

func TestTimestampsVerifications(t *testing.T) {
	getTimestampedSignedData := func() *SignedData {
		sd, _ := NewSignedData([]byte("hi"))
		sd.Sign(leaf.Chain(), leaf.PrivateKey)
		tsReq, _ := tsRequest(sd.psd.SignerInfos[0])
		tsResp, _ := tsa.Do(tsReq)
		tsAttr, _ := protocol.NewAttribute(oid.AttributeTimeStampToken, tsResp.TimeStampToken)
		sd.psd.SignerInfos[0].UnsignedAttrs = append(sd.psd.SignerInfos[0].UnsignedAttrs, tsAttr)
		return sd
	}

	// Good timestamp
	tsa.Clear()
	sd := getTimestampedSignedData()
	if _, err := getTimestamp(sd.psd.SignerInfos[0], intermediateOpts); err != nil {
		t.Fatal(err)
	}
	if _, err := sd.Verify(intermediateOpts, intermediateOpts); err != nil {
		t.Fatal(err)
	}

	// Timestamped maybe before not-before
	//
	//       Not-Before                       Not-After
	//          |--------------------------------|
	//     |--------|
	//  sig-min   sig-max
	tsa.HookInfo(func(info timestamp.Info) timestamp.Info {
		info.Accuracy.Seconds = 30
		info.GenTime = leaf.Certificate.NotBefore
		return info
	})
	sd = getTimestampedSignedData()
	if _, err := getTimestamp(sd.psd.SignerInfos[0], intermediateOpts); err != nil {
		t.Fatal(err)
	}
	if _, err := sd.Verify(intermediateOpts, intermediateOpts); err == nil || !strings.HasPrefix(err.Error(), "x509: certificate has expired") {
		t.Fatalf("expected expired error, got %v", err)
	}

	// Timestamped after not-before
	//
	//       Not-Before                       Not-After
	//          |--------------------------------|
	//          |--------|
	//      sig-min   sig-max
	tsa.HookInfo(func(info timestamp.Info) timestamp.Info {
		info.Accuracy.Seconds = 30
		info.GenTime = leaf.Certificate.NotBefore.Add(31 * time.Second)
		return info
	})
	sd = getTimestampedSignedData()
	if _, err := getTimestamp(sd.psd.SignerInfos[0], intermediateOpts); err != nil {
		t.Fatal(err)
	}
	if _, err := sd.Verify(intermediateOpts, intermediateOpts); err != nil {
		t.Fatal(err)
	}

	// Timestamped maybe after not-after
	//
	//       Not-Before                       Not-After
	//          |--------------------------------|
	//                                      |--------|
	//                                  sig-min   sig-max
	tsa.HookInfo(func(info timestamp.Info) timestamp.Info {
		info.Accuracy.Seconds = 30
		info.GenTime = leaf.Certificate.NotAfter
		return info
	})
	sd = getTimestampedSignedData()
	if _, err := getTimestamp(sd.psd.SignerInfos[0], intermediateOpts); err != nil {
		t.Fatal(err)
	}
	if _, err := sd.Verify(intermediateOpts, intermediateOpts); err == nil || !strings.HasPrefix(err.Error(), "x509: certificate has expired") {
		t.Fatalf("expected expired error, got %v", err)
	}

	// Timestamped before not-after
	//
	//       Not-Before                       Not-After
	//          |--------------------------------|
	//                                  |--------|
	//                              sig-min   sig-max
	tsa.HookInfo(func(info timestamp.Info) timestamp.Info {
		info.Accuracy.Seconds = 30
		info.GenTime = leaf.Certificate.NotAfter.Add(-31 * time.Second)
		return info
	})
	sd = getTimestampedSignedData()
	if _, err := getTimestamp(sd.psd.SignerInfos[0], intermediateOpts); err != nil {
		t.Fatal(err)
	}
	if _, err := sd.Verify(intermediateOpts, intermediateOpts); err != nil {
		t.Fatal(err)
	}

	// Bad message imprint
	tsa.HookInfo(func(info timestamp.Info) timestamp.Info {
		info.MessageImprint.HashedMessage[0] ^= 0xFF
		return info
	})
	sd = getTimestampedSignedData()
	if _, err := getTimestamp(sd.psd.SignerInfos[0], intermediateOpts); err == nil || err.Error() != "invalid message imprint" {
		t.Fatalf("expected 'invalid message imprint', got %v", err)
	}

	// Untrusted signature
	tsa.HookToken(func(tst *protocol.SignedData) *protocol.SignedData {
		badIdent := fakeca.New()
		tst.SignerInfos = nil
		tst.AddSignerInfo(badIdent.Chain(), badIdent.PrivateKey)
		return tst
	})
	sd = getTimestampedSignedData()
	if _, err := getTimestamp(sd.psd.SignerInfos[0], intermediateOpts); err == nil {
		t.Fatal("expected error")
	} else if _, ok := err.(x509.UnknownAuthorityError); !ok {
		t.Fatalf("expected x509.UnknownAuthorityError, got %v", err)
	}

	// Bad signature
	tsa.HookToken(func(tst *protocol.SignedData) *protocol.SignedData {
		tst.SignerInfos[0].Signature[0] ^= 0xFF
		return tst
	})
	sd = getTimestampedSignedData()
	if _, err := getTimestamp(sd.psd.SignerInfos[0], intermediateOpts); err != rsa.ErrVerification {
		t.Fatalf("expected %v, got %v", rsa.ErrVerification, err)
	}
}

// TestVerificationTimeSubstitutability pins the contract between the two
// trusted signing-time sources: without an RFC3161 timestamp the caller must
// supply a verification time itself (the verifier must not invent one from
// the cert's NotBefore); with a verified timestamp the token's GenTime is
// used even when the caller supplies no time.
func TestVerificationTimeSubstitutability(t *testing.T) {
	// No timestamp, no caller time: explicit failure instead of default pass.
	plain, _ := NewSignedData([]byte("hi"))
	if err := plain.Sign(leaf.Chain(), leaf.PrivateKey); err != nil {
		t.Fatal(err)
	}
	if _, err := plain.Verify(intermediateOpts, intermediateOpts); !errors.Is(err, ErrNoVerificationTime) {
		t.Fatalf("plain Verify() = %v; want ErrNoVerificationTime", err)
	}

	// No timestamp, but the caller pins a time inside the cert window: passes.
	opts := intermediateOpts
	opts.CurrentTime = time.Now()
	if _, err := plain.Verify(opts, intermediateOpts); err != nil {
		t.Fatalf("Verify with caller-pinned time = %v; want success", err)
	}

	// Verified timestamp supplies the time itself (no caller time needed).
	tsa.Clear()
	timestamped, _ := NewSignedData([]byte("hi"))
	if err := timestamped.Sign(leaf.Chain(), leaf.PrivateKey); err != nil {
		t.Fatal(err)
	}
	tsReq, _ := tsRequest(timestamped.psd.SignerInfos[0])
	tsResp, _ := tsa.Do(tsReq)
	tsAttr, _ := protocol.NewAttribute(oid.AttributeTimeStampToken, tsResp.TimeStampToken)
	timestamped.psd.SignerInfos[0].UnsignedAttrs = append(timestamped.psd.SignerInfos[0].UnsignedAttrs, tsAttr)
	if _, err := timestamped.Verify(intermediateOpts, intermediateOpts); err != nil {
		t.Fatalf("timestamped Verify() = %v; want success from the token's GenTime", err)
	}
}
