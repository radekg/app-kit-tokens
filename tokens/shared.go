package tokens

import "fmt"

// Claims represents token claims.
type Claims map[string]interface{}

func (c Claims) getFloat64Claim(claim string) (float64, bool) {
	if value, ok := c[claim]; ok {
		switch tvalue := value.(type) {
		case float32:
			return float64(tvalue), true
		case uint:
			return float64(tvalue), true
		case uint32:
			return float64(tvalue), true
		case uint64:
			return float64(tvalue), true
		case int:
			return float64(tvalue), true
		case int32:
			return float64(tvalue), true
		case int64:
			return float64(tvalue), true
		case float64:
			return tvalue, true
		default:
			return 0, false
		}
	}
	return 0, false
}

func (c Claims) getInt64Claim(claim string) (int64, bool) {
	if value, ok := c[claim]; ok {
		switch tvalue := value.(type) {
		case float32:
			return int64(tvalue), true
		case float64:
			return int64(tvalue), true
		case uint:
			return int64(tvalue), true
		case uint32:
			return int64(tvalue), true
		case uint64:
			return int64(tvalue), true
		case int:
			return int64(tvalue), true
		case int32:
			return int64(tvalue), true
		case int64:
			return tvalue, true
		default:
			return 0, false
		}
	}
	return 0, false
}

func (c Claims) getBoolClaim(claim string) (bool, bool) {
	if value, ok := c[claim]; ok {
		switch tvalue := value.(type) {
		case bool:
			return tvalue, true
		default:
			return false, false
		}
	}
	return false, false
}

func (c Claims) HasClaim(claim string) bool {
	_, ok := c[claim]
	return ok
}

func (c Claims) GetClaim(claim string) (interface{}, bool) {
	value, ok := c[claim]
	return value, ok
}

func (c Claims) GetClaimMustString(claim string) (string, bool) {
	if value, ok := c[claim]; ok {
		switch tvalue := value.(type) {
		case string:
			return tvalue, ok
		default:
			return fmt.Sprintf("%v", tvalue), ok
		}
	}
	return "", false
}

// TokenType is a token type.
type TokenType string

const (
	// BearerTokenType is a bearer token type.
	BearerTokenType TokenType = "Bearer"
	// RefreshTokenType is a refresh token type.
	RefreshTokenType TokenType = "Refresh"
)

func getTokenParts(parts []string) (string, string, string) {
	return parts[0], parts[1], parts[2]
}

type defaultToken struct {
	claims Claims
}

func (at *defaultToken) RawClaims() Claims {
	return at.claims
}
