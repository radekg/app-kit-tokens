package tokens

import (
	"testing"

	"gopkg.in/square/go-jose.v2/jwt"
)

// AccessToken represents an access token.
type AccessToken interface {
	// Default access token properties
	ClientID() (string, bool)
	Exp() (int64, bool)
	Iat() (int64, bool)
	Iss() (string, bool)
	Jti() (string, bool)
	Scope() (string, bool)
	Sub() (string, bool)
	// Common convenience properties:
	Aud() (interface{}, bool)
	Nbf() (int64, bool)
	Typ() (string, bool)
	// Other convenience methods:
	RawClaims() Claims
}

type defaultAccessToken struct {
	defaultToken
	claims Claims
}

func (at *defaultAccessToken) Aud() (interface{}, bool) {
	return at.claims.GetClaim("aud")
}
func (at *defaultAccessToken) ClientID() (string, bool) {
	return at.claims.GetClaimMustString("client_id")
}
func (at *defaultAccessToken) Exp() (int64, bool) {
	return at.claims.getInt64Claim("exp")
}
func (at *defaultAccessToken) Iat() (int64, bool) {
	return at.claims.getInt64Claim("iat")
}
func (at *defaultAccessToken) Iss() (string, bool) {
	return at.claims.GetClaimMustString("iss")
}
func (at *defaultAccessToken) Jti() (string, bool) {
	return at.claims.GetClaimMustString("jti")
}
func (at *defaultAccessToken) Nbf() (int64, bool) {
	return at.claims.getInt64Claim("nbf")
}
func (at *defaultAccessToken) Scope() (string, bool) {
	// ORY Hydra returns this claim as scp.
	// Keycloak returns this as scope (as specified in the spec).
	for _, claimName := range []string{"scp", "scope"} {
		if at.claims.HasClaim(claimName) {
			return at.claims.GetClaimMustString(claimName)
		}
	}
	return "", false
}
func (at *defaultAccessToken) Sub() (string, bool) {
	return at.claims.GetClaimMustString("sub")
}
func (at *defaultAccessToken) Typ() (string, bool) {
	return at.claims.GetClaimMustString("typ")
}

// convenience:

// DefaultAccessToken returns an instacne of the access token.
// Call this function using claims returned from jwks.Validator.ValidateToken(string).
func DefaultAccessToken(claims Claims) AccessToken {
	return &defaultAccessToken{claims: claims}
}

func defaultInsecureAccessToken(t *testing.T, rawToken string) (AccessToken, error) {
	token, parseErr := jwt.ParseSigned(rawToken)
	if parseErr != nil {
		return nil, parseErr
	}
	cl := map[string]interface{}{}
	if claimsErr := token.UnsafeClaimsWithoutVerification(&cl); claimsErr != nil {
		return nil, claimsErr
	}
	return DefaultAccessToken(cl), nil
}
