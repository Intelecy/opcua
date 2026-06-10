package server

import (
	"testing"

	"github.com/gopcua/opcua/ua"
)

// TestBuildAuthRejectsUnencryptedPasswordUnlessPolicyNone guards against a
// client downgrading a UserName token: an unencrypted password
// (EncryptionAlgorithm == "") must only be accepted when the user-token policy
// is explicitly None. On any secured policy — or an unknown/missing PolicyID —
// it must be rejected rather than trusted as cleartext.
func TestBuildAuthRejectsUnencryptedPasswordUnlessPolicyNone(t *testing.T) {
	sess := &session{serverNonce: make([]byte, 32)}

	mk := func(policyID string) *ua.ActivateSessionRequest {
		return &ua.ActivateSessionRequest{
			RequestHeader: &ua.RequestHeader{},
			UserIdentityToken: ua.NewExtensionObject(&ua.UserNameIdentityToken{
				PolicyID:            policyID,
				UserName:            "scada",
				Password:            []byte("s3cr3t"),
				EncryptionAlgorithm: "", // claims no encryption
			}),
		}
	}

	// unencrypted password on a secured (non-None) policy → reject
	// (sc is nil: this branch must return before any DecryptUserPassword call)
	if _, err := buildAuthenticationRequest(nil, sess, mk("username_basic256sha256")); err != ua.StatusBadIdentityTokenInvalid {
		t.Fatalf("unencrypted password on a secured policy must be rejected, got %v", err)
	}

	// unknown / empty PolicyID → default-deny
	if _, err := buildAuthenticationRequest(nil, sess, mk("")); err != ua.StatusBadIdentityTokenInvalid {
		t.Fatalf("unencrypted password with unknown policy must be rejected, got %v", err)
	}

	// explicitly None policy → cleartext password accepted
	areq, err := buildAuthenticationRequest(nil, sess, mk("username_none"))
	if err != nil {
		t.Fatalf("None-policy cleartext password should be accepted, got %v", err)
	}
	if string(areq.Password) != "s3cr3t" || areq.UserName != "scada" || areq.TokenType != ua.UserTokenTypeUserName {
		t.Fatalf("unexpected auth request: %+v", areq)
	}
}
