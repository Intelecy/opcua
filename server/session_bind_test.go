package server

import (
	"testing"

	"github.com/gopcua/opcua/ua"
)

// TestCheckSessionBindsSessionToChannel guards the session-fixation / token-replay
// bypass: an activated session's AuthenticationToken (a non-secret 31-bit value
// the server hands to the client) must only be usable from the secure channel
// the session was created on. A request replaying it on a different channel must
// be rejected.
func TestCheckSessionBindsSessionToChannel(t *testing.T) {
	srv := New(WithAuthenticator(func(*AuthenticationRequest) error { return nil }))

	// a session activated on secure channel 7
	sess := srv.sb.NewSession()
	srv.sb.Update(sess.AuthTokenID, func(s *session) {
		s.activated = true
		s.scID = 7
	})

	req := &ua.ReadRequest{RequestHeader: &ua.RequestHeader{AuthenticationToken: sess.AuthTokenID}}
	read := ua.ServiceTypeID(req)

	// same channel → allowed
	if err := srv.checkSession(7, read, req); err != nil {
		t.Fatalf("request on the session's own channel should pass, got %v", err)
	}

	// different channel → rejected (the bypass)
	if err := srv.checkSession(9, read, req); err != ua.StatusBadSecureChannelIDInvalid {
		t.Fatalf("token replayed on another channel must be rejected with "+
			"BadSecureChannelIDInvalid, got %v", err)
	}

	// channel id 0 (unknown/unopened) → rejected
	if err := srv.checkSession(0, read, req); err != ua.StatusBadSecureChannelIDInvalid {
		t.Fatalf("request with no channel id must be rejected, got %v", err)
	}

	// unknown token → rejected
	bogus := &ua.ReadRequest{RequestHeader: &ua.RequestHeader{AuthenticationToken: ua.NewNumericNodeID(0, 0xDEADBEEF)}}
	if err := srv.checkSession(7, read, bogus); err != ua.StatusBadSessionIDInvalid {
		t.Fatalf("unknown token must be rejected with BadSessionIDInvalid, got %v", err)
	}

	// a non-activated session on the right channel → rejected as not activated
	sess2 := srv.sb.NewSession()
	srv.sb.Update(sess2.AuthTokenID, func(s *session) { s.scID = 7 })
	req2 := &ua.ReadRequest{RequestHeader: &ua.RequestHeader{AuthenticationToken: sess2.AuthTokenID}}
	if err := srv.checkSession(7, read, req2); err != ua.StatusBadSessionNotActivated {
		t.Fatalf("non-activated session must be rejected with BadSessionNotActivated, got %v", err)
	}

	// a sessionless service (GetEndpoints) needs no session/channel
	ge := &ua.GetEndpointsRequest{RequestHeader: &ua.RequestHeader{}}
	if err := srv.checkSession(0, ua.ServiceTypeID(ge), ge); err != nil {
		t.Fatalf("discovery service must not require a session, got %v", err)
	}
}
