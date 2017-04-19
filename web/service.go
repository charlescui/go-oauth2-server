package web

import (
	"github.com/adam-hanna/go-oauth2-server/config"
	"github.com/adam-hanna/go-oauth2-server/oauth"
	"github.com/adam-hanna/go-oauth2-server/session"
)

// Service struct keeps variables for reuse
type Service struct {
	cnf            *config.Config
	oauthService   oauth.ServiceInterface
	sessionService session.ServiceInterface
}

// InitWebService starts a new Service instance
func (s *Service) InitWebService(cnf *config.Config, oauthService oauth.ServiceInterface, sessionService session.ServiceInterface) {
	s = &Service{
		cnf:            cnf,
		oauthService:   oauthService,
		sessionService: sessionService,
	}
}

// GetConfig returns config.Config instance
func (s *Service) GetConfig() *config.Config {
	return s.cnf
}

// GetOauthService returns oauth.Service instance
func (s *Service) GetOauthService() oauth.ServiceInterface {
	return s.oauthService
}

// GetSessionService returns session.Service instance
func (s *Service) GetSessionService() session.ServiceInterface {
	return s.sessionService
}
