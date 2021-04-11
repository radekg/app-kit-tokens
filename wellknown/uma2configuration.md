```go
package wellknown

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/radekg/app-kit-tokens/tokens"
)

// ResourceServerDecisionResponse represents an UMA2 error response.
type ResourceServerDecisionResponse struct {
	Result bool `json:"result"`
}

// ResourceServerPermissionsError represents an UMA2 error response.
type ResourceServerPermissionsError struct {
	ErrorReason      string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (e *ResourceServerPermissionsError) Error() string {
	return fmt.Sprintf("%s: %s", e.ErrorReason, e.ErrorDescription)
}

// ObtainRPT obtains the RPT from the resource server.
func (u *UMA2Configuration) ObtainRPT(accessToken string, opts ...ObtainPermissionOpt) (*tokens.JWT, error) {
	// call parameters:
	form := url.Values{}
	form.Add("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	form.Add("audience", u.config.ClientID())
	for _, opt := range opts {
		opt.Apply(&form)
	}
	requestBody := form.Encode()
	// construct the request:
	request, requestError := http.NewRequest("POST", u.TokenEndpoint, bytes.NewBuffer([]byte(requestBody)))
	if requestError != nil {
		return nil, requestError
	}
	// add headers:
	request.Header.Add("Authorization", "Bearer "+accessToken)
	request.Header.Add("Content-Length", fmt.Sprintf("%d", len(requestBody)))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	// issue the request:
	response, responseErr := u.httpClient.Do(request)
	if responseErr != nil {
		return nil, responseErr
	}
	defer response.Body.Close()

	// check if request was successful:
	if int(response.StatusCode/100) != 2 {
		// try parsing as error:
		err := &ResourceServerPermissionsError{}
		if jsonErr := json.NewDecoder(response.Body).Decode(err); jsonErr != nil {
			return nil, jsonErr
		}
		return nil, err
	}

	// seems like it was successful:
	jwt := &tokens.JWT{}
	if jsonErr := json.NewDecoder(response.Body).Decode(jwt); jsonErr != nil {
		return nil, jsonErr
	}

	return jwt, nil
}

// ObtainPermissionsOnly attempts obtaining permissions from the resource server.
// Indicates that responses from the server should contain any permission granted by the server by returning a JSON with the following format:
// [
//     {
//         'rsid': 'My Resource'
//         'scopes': ['view', 'update']
//     },
//     ...
// ]
func (u *UMA2Configuration) ObtainPermissionsOnly(accessToken string, opts ...ObtainPermissionOpt) ([]*tokens.UMAPermission, error) {
	// call parameters:
	form := url.Values{}
	form.Add("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	form.Add("audience", u.config.ClientID())
	form.Add("response_mode", "permissions")
	for _, opt := range opts {
		opt.Apply(&form)
	}
	requestBody := form.Encode()
	// construct the request:
	request, requestError := http.NewRequest("POST", u.TokenEndpoint, bytes.NewBuffer([]byte(requestBody)))
	if requestError != nil {
		return nil, requestError
	}
	// add headers:
	request.Header.Add("Authorization", "Bearer "+accessToken)
	request.Header.Add("Content-Length", fmt.Sprintf("%d", len(requestBody)))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	// issue the request:
	response, responseErr := u.httpClient.Do(request)
	if responseErr != nil {
		return nil, responseErr
	}
	defer response.Body.Close()

	// check if request was successful:
	if int(response.StatusCode/100) != 2 {
		// try parsing as error:
		err := &ResourceServerPermissionsError{}
		if jsonErr := json.NewDecoder(response.Body).Decode(err); jsonErr != nil {
			return nil, jsonErr
		}
		return nil, err
	}

	// seems like it was successful:
	var permissions []*tokens.UMAPermission
	if jsonErr := json.NewDecoder(response.Body).Decode(&permissions); jsonErr != nil {
		return nil, jsonErr
	}

	return permissions, nil
}

// ObtainDecisionOnly obtaining permissions decision from the resource server.
// Indicates that responses from the server should only represent the overall decision by returning a JSON with the following format:
// {
//    "result": true
// }
func (u *UMA2Configuration) ObtainDecisionOnly(accessToken string, opts ...ObtainPermissionOpt) (*ResourceServerDecisionResponse, error) {
	// call parameters:
	form := url.Values{}
	form.Add("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	form.Add("audience", u.config.ClientID())
	form.Add("response_mode", "decision")
	for _, opt := range opts {
		opt.Apply(&form)
	}
	requestBody := form.Encode()
	// construct the request:
	request, requestError := http.NewRequest("POST", u.TokenEndpoint, bytes.NewBuffer([]byte(requestBody)))
	if requestError != nil {
		return nil, requestError
	}
	// add headers:
	request.Header.Add("Authorization", "Bearer "+accessToken)
	request.Header.Add("Content-Length", fmt.Sprintf("%d", len(requestBody)))
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	// issue the request:
	response, responseErr := u.httpClient.Do(request)
	if responseErr != nil {
		return nil, responseErr
	}
	defer response.Body.Close()

	// check if request was successful:
	if int(response.StatusCode/100) != 2 {
		// try parsing as error:
		err := &ResourceServerPermissionsError{}
		if jsonErr := json.NewDecoder(response.Body).Decode(err); jsonErr != nil {
			return nil, jsonErr
		}
		return nil, err
	}

	// seems like it was successful:
	decision := &ResourceServerDecisionResponse{}
	if jsonErr := json.NewDecoder(response.Body).Decode(decision); jsonErr != nil {
		return nil, jsonErr
	}

	return decision, nil
}
```