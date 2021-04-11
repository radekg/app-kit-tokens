package tokens

import (
	"encoding/json"
	"testing"
	"time"
)

func TestJWTParse(t *testing.T) {
	expectedValues := map[string]interface{}{
		"access_token":       "token",
		"id_token":           "token",
		"refresh_token":      "token",
		"token_type":         "jwt",
		"expires_in":         int64(60),
		"refresh_expires_in": int64(60),
		"not-before-policy":  int64(time.Now().Unix()),
		"session_state":      "state",
		"scope":              "test",
	}

	bytes, _ := json.Marshal(&expectedValues)

	jwt, err := DefaultJWT(bytes)
	if err != nil {
		t.Fatalf("expected jwt like string to parse but received '%v'", err)
	}

	if jwt.AccessToken() != expectedValues["access_token"] {
		t.Fatalf("expected jwt access token value different than expected: expected '%v', got '%v'",
			expectedValues["access_token"],
			jwt.AccessToken())
	}

	if jwt.IDToken() != expectedValues["id_token"] {
		t.Fatalf("expected jwt iD token value different than expected: expected '%v', got '%v'",
			expectedValues["id_token"],
			jwt.IDToken())
	}

	if jwt.RefreshToken() != expectedValues["refresh_token"] {
		t.Fatalf("expected jwt refresh token value different than expected: expected '%v', got '%v'",
			expectedValues["refresh_token"],
			jwt.RefreshToken())
	}

	if jwt.TokenType() != expectedValues["token_type"] {
		t.Fatalf("expected jwt token type value different than expected: expected '%v', got '%v'",
			expectedValues["token_type"],
			jwt.TokenType())
	}

	if jwt.SessionState() != expectedValues["session_state"] {
		t.Fatalf("expected jwt session state value different than expected: expected '%v', got '%v'",
			expectedValues["session_state"],
			jwt.SessionState())
	}

	if jwt.Scope() != expectedValues["scope"] {
		t.Fatalf("expected jwt scope value different than expected: expected '%v', got '%v'",
			expectedValues["scope"],
			jwt.Scope())
	}

	if jwt.ExpiresIn() != expectedValues["expires_in"] {
		t.Fatalf("expected jwt value different than expected: expected '%v', got '%v'",
			expectedValues["expires_in"],
			jwt.ExpiresIn())
	}

	if jwt.RefreshExpiresIn() != expectedValues["refresh_expires_in"] {
		t.Fatalf("expected jwt value different than expected: expected '%v', got '%v'",
			expectedValues["refresh_expires_in"],
			jwt.RefreshExpiresIn())
	}

	if jwt.NotBeforePolicy() != expectedValues["not-before-policy"] {
		t.Fatalf("expected jwt value different than expected: expected '%v', got '%v'",
			expectedValues["not-before-policy"],
			jwt.NotBeforePolicy())
	}

}
