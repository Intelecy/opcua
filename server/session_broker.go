package server

import (
	mrand "math/rand"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/gopcua/opcua/ua"
)

type session struct {
	cfg sessionConfig

	ID                *ua.NodeID
	AuthTokenID       *ua.NodeID
	serverNonce       []byte
	remoteCertificate []byte

	// metadata recorded at CreateSession/ActivateSession time. Writes go
	// through sessionBroker.Update so snapshots can be taken from other
	// goroutines.
	created           time.Time
	endpointURL       string
	remoteAddr        string
	clientDescription *ua.ApplicationDescription
	activated         bool
	auth              *AuthenticationRequest
	scID              uint32 // secure channel this session was created on

	PublishRequests chan PubReq
}

// SessionInfo is a point-in-time snapshot of a session for monitoring
// purposes.
type SessionInfo struct {
	// ID is the session ID.
	ID string

	// Created is when the session was created.
	Created time.Time

	// Activated reports whether the session has been successfully
	// activated.
	Activated bool

	// EndpointURL is the endpoint the session was created against.
	EndpointURL string

	// RemoteAddr is the network address of the client.
	RemoteAddr string

	// ApplicationURI, ApplicationName and ProductURI describe the client
	// application as provided in CreateSession.
	ApplicationURI  string
	ApplicationName string
	ProductURI      string

	// TokenType is the user identity token type used to activate the
	// session.
	TokenType ua.UserTokenType

	// UserName is the user name when TokenType is
	// ua.UserTokenTypeUserName.
	UserName string
}

type sessionConfig struct {
	sessionTimeout time.Duration
}

type sessionBroker struct {
	// mu protects concurrent modification of s
	mu sync.Mutex

	// s contains all sessions watched by the session broker
	s      map[string]*session
	logger Logger
}

func newSessionBroker(logger Logger) *sessionBroker {
	return &sessionBroker{
		s:      make(map[string]*session),
		logger: logger,
	}
}

func (sb *sessionBroker) NewSession() *session {
	s := &session{
		ID:              ua.NewGUIDNodeID(1, uuid.New().String()),
		AuthTokenID:     ua.NewNumericNodeID(0, uint32(mrand.Int31())),
		PublishRequests: make(chan PubReq, 100),
		created:         time.Now(),
	}

	sb.mu.Lock()
	sb.s[s.AuthTokenID.String()] = s
	sb.mu.Unlock()

	return s
}

func (sb *sessionBroker) Close(authToken *ua.NodeID) error {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if sb.s[authToken.String()] == nil {
		if sb.logger != nil {
			sb.logger.Warn("sessionBroker.Close: error looking up session %v", authToken)
		}
	}
	delete(sb.s, authToken.String())

	return nil
}

func (sb *sessionBroker) Session(authToken *ua.NodeID) *session {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	s := sb.s[authToken.String()]
	if s == nil {
		if sb.logger != nil {
			sb.logger.Warn("sessionBroker.Session: error looking up session %v", authToken)
		}
	}

	return s
}

// check looks up the session for authToken and returns the secure channel it
// is bound to and whether it has been activated. ok is false if no such session
// exists. Unlike Session() it does not log on a miss, so it is safe to call on
// the per-request enforcement path (a flood of bogus tokens can't spam logs).
func (sb *sessionBroker) check(authToken *ua.NodeID) (scID uint32, activated, ok bool) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	s := sb.s[authToken.String()]
	if s == nil {
		return 0, false, false
	}
	return s.scID, s.activated, true
}

// Update applies fn to the session identified by authToken while holding the
// broker lock. It is a no-op if the session does not exist.
func (sb *sessionBroker) Update(authToken *ua.NodeID, fn func(*session)) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if s := sb.s[authToken.String()]; s != nil {
		fn(s)
	}
}

// SessionInfos returns a snapshot of all current sessions.
func (sb *sessionBroker) SessionInfos() []SessionInfo {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	infos := make([]SessionInfo, 0, len(sb.s))

	for _, s := range sb.s {
		info := SessionInfo{
			ID:          s.ID.String(),
			Created:     s.created,
			Activated:   s.activated,
			EndpointURL: s.endpointURL,
			RemoteAddr:  s.remoteAddr,
		}

		if cd := s.clientDescription; cd != nil {
			info.ApplicationURI = cd.ApplicationURI
			info.ProductURI = cd.ProductURI
			if cd.ApplicationName != nil {
				info.ApplicationName = cd.ApplicationName.Text
			}
		}

		if a := s.auth; a != nil {
			info.TokenType = a.TokenType
			info.UserName = a.UserName
		}

		infos = append(infos, info)
	}

	return infos
}
