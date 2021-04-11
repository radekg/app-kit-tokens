package tokens

import (
	"testing"

	"gopkg.in/square/go-jose.v2/jwt"
)

// RefreshToken represents a refresh token.
type RefreshToken interface {
	// Default refresh token properties
	Azp() (string, bool)
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

type defaultRefreshToken struct {
	defaultToken
	claims Claims
}

func (rt *defaultRefreshToken) Aud() (interface{}, bool) {
	return rt.claims.GetClaim("aud")
}
func (rt *defaultRefreshToken) Azp() (string, bool) {
	return rt.claims.GetClaimMustString("azp")
}
func (rt *defaultRefreshToken) Exp() (int64, bool) {
	return rt.claims.getInt64Claim("exp")
}
func (rt *defaultRefreshToken) Iat() (int64, bool) {
	return rt.claims.getInt64Claim("iat")
}
func (rt *defaultRefreshToken) Iss() (string, bool) {
	return rt.claims.GetClaimMustString("iss")
}
func (rt *defaultRefreshToken) Jti() (string, bool) {
	return rt.claims.GetClaimMustString("jti")
}
func (rt *defaultRefreshToken) Nbf() (int64, bool) {
	return rt.claims.getInt64Claim("nbf")
}
func (rt *defaultRefreshToken) Scope() (string, bool) {
	// ORY Hydra returns this claim as scp.
	// Keycloak returns this as scope (as specified in the spec).
	for _, claimName := range []string{"scp", "scope"} {
		if rt.claims.HasClaim(claimName) {
			return rt.claims.GetClaimMustString(claimName)
		}
	}
	return "", false
}
func (rt *defaultRefreshToken) Sub() (string, bool) {
	return rt.claims.GetClaimMustString("sub")
}
func (rt *defaultRefreshToken) Typ() (string, bool) {
	return rt.claims.GetClaimMustString("typ")
}

// DefaultRefreshToken returns an instacne of the refresh token.
// Call this function using claims returned from jwks.Validator.ValidateToken(string).
func DefaultRefreshToken(claims Claims) RefreshToken {
	return &defaultRefreshToken{claims: claims}
}

func defaultInsecureRefreshToken(t *testing.T, rawToken string) (RefreshToken, error) {
	token, parseErr := jwt.ParseSigned(rawToken)
	if parseErr != nil {
		return nil, parseErr
	}
	cl := map[string]interface{}{}
	if claimsErr := token.UnsafeClaimsWithoutVerification(&cl); claimsErr != nil {
		return nil, claimsErr
	}
	return DefaultRefreshToken(cl), nil
}
