// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package uasc

import (
	"bytes"
	"encoding/binary"

	"github.com/gopcua/opcua/errors"
	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uapolicy"
)

// DecryptUserPassword decrypts the password of a UserNameIdentityToken received
// in an ActivateSessionRequest. It is the server-side inverse of
// EncryptUserPassword.
//
// The encrypted secret is "length (4 byte LE) | password | serverNonce" where
// serverNonce is the nonce the server sent in the previous
// CreateSessionResponse. The nonce is verified here and not returned.
//
// If policyURI is empty the secure channel's security policy is used. If the
// effective policy is None the password is returned as-is (it was sent in
// plaintext).
func (s *SecureChannel) DecryptUserPassword(policyURI string, password, nonce []byte) ([]byte, error) {
	if policyURI == "" {
		policyURI = s.cfg.SecurityPolicyURI
	}

	if policyURI == ua.SecurityPolicyURINone {
		return password, nil
	}

	enc, err := uapolicy.Asymmetric(policyURI, s.cfg.LocalKey, nil)
	if err != nil {
		return nil, err
	}

	secret, err := enc.Decrypt(password)
	if err != nil {
		return nil, err
	}

	if len(secret) < 4 {
		return nil, errors.New("invalid encrypted password")
	}

	l := int(binary.LittleEndian.Uint32(secret[:4]))
	secret = secret[4:]

	if l < len(nonce) || l > len(secret) {
		return nil, errors.New("invalid encrypted password length")
	}

	pass, tokenNonce := secret[:l-len(nonce)], secret[l-len(nonce):l]

	if !bytes.Equal(tokenNonce, nonce) {
		return nil, errors.New("user token nonce mismatch")
	}

	return pass, nil
}
