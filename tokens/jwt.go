package tokens

import (
	"bytes"
	"encoding/json"
)

// JWT is a JWT
type JWT interface {
	AccessToken() string
	IDToken() string
	ExpiresIn() int64
	RefreshExpiresIn() int64
	RefreshToken() string
	TokenType() string
	NotBeforePolicy() int64
	SessionState() string
	Scope() string
}

type defaultJWT struct {
	AccessTokenValue      string `json:"access_token"`
	IDTokenValue          string `json:"id_token"`
	ExpiresInValue        int64  `json:"expires_in"`
	RefreshExpiresInValue int64  `json:"refresh_expires_in"`
	RefreshTokenValue     string `json:"refresh_token"`
	TokenTypeValue        string `json:"token_type"`
	NotBeforePolicyValue  int64  `json:"not-before-policy"`
	SessionStateValue     string `json:"session_state"`
	ScopeValue            string `json:"scope"`
}

func (j *defaultJWT) AccessToken() string {
	return j.AccessTokenValue
}
func (j *defaultJWT) IDToken() string {
	return j.IDTokenValue
}
func (j *defaultJWT) ExpiresIn() int64 {
	return j.ExpiresInValue
}
func (j *defaultJWT) RefreshExpiresIn() int64 {
	return j.RefreshExpiresInValue
}
func (j *defaultJWT) RefreshToken() string {
	return j.RefreshTokenValue
}
func (j *defaultJWT) TokenType() string {
	return j.TokenTypeValue
}
func (j *defaultJWT) NotBeforePolicy() int64 {
	return j.NotBeforePolicyValue
}
func (j *defaultJWT) SessionState() string {
	return j.SessionStateValue
}
func (j *defaultJWT) Scope() string {
	return j.ScopeValue
}

// DefaultJWT tries to parse a JWT from bytes using the default implementation.
func DefaultJWT(rawData []byte) (JWT, error) {
	jwt := &defaultJWT{}
	unmarshalErr := json.NewDecoder(bytes.NewReader(rawData)).Decode(jwt)
	return jwt, unmarshalErr
}
