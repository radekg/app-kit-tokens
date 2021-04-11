package webfinger

import "fmt"

// KeycloakBaseURL returns Keycloak specific webfinger base URL.
func KeycloakBaseURL(baseURL, realm string) string {
	return fmt.Sprintf("%s/auth/realms/%s", baseURL, realm)
}
