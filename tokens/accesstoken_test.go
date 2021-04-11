package tokens

import "testing"

const tokenHydra = `eyJhbGciOiJSUzI1NiIsImtpZCI6InB1YmxpYzpiMWNiZDQzZi03YmY3LTRmODAtYTA0Zi02ZDFkMGFhZTIyNTMiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOltdLCJjbGllbnRfaWQiOiJteS1jbGllbnQiLCJleHAiOjE2MTgxNTMyMDEsImV4dCI6e30sImlhdCI6MTYxODE0OTYwMSwiaXNzIjoiaHR0cDovLzEyNy4wLjAuMTo0NDQ0LyIsImp0aSI6IjI2YzVjZDQ3LWE3NzgtNDY5ZC05NzkwLWZkOWFkNWQ0N2JjZiIsIm5iZiI6MTYxODE0OTYwMSwic2NwIjpbIm9wZW5pZCIsIm9mZmxpbmUiXSwic3ViIjoibXktY2xpZW50In0.sONnqIY8gUepilbE0edgIV8SEjlALsmA61xUNVKKXxCoLTgGesvj0m3lUXbo0SKCiPNo3ZZwLbfSMnQFWj3fWoNLFwYMVJCVIx9e-n-o91G1dlRrc2u5nW0j2spJRKqO51uETBex90UC5e67FGXWR29ikS1jLREDb06RKEHROUOsGt6FHmQat3cacFt-f7vipyPVwDgErq1OOUDFzS3kUcW356WsoVGXFP21EmXrdwYNUfyKiY8zrv7WhzkrsTrn2e60y8rmXG0RiOjCOgCtg6Gu9_PyuEFM1x5Re1WijxbUKewaIWo21UNIuCHfQe4mZQpBN5stifRi-BlciZN_B8EINaJ_rniL7v_OY6soOlV19WJarW7hVtOxHGAXNbW2_okB4oE4hGIsBJ6545t8EUEKHiul-LHa3U-Ts6dso-qucW3dvy2InbQKA1ksx7IQjezBvJJBUwvy5nk0Kr7f-WPqueCP9pYew8gfu0hUinATdLKeeHoowLXxtWChWuhCeNXvuxvZUJ72GpYOH5CpGoClFW_qg5zUjsMj3DVdveXwf_FvdegKSXr22iJgNlWCilidFMtvNlCKEPG4Saw5lJaXmSGFvCn168cIorgtjM8WV5eKc5aXg9xC0W8FxEdKUbsqGzreLrCbAPmL1ZXku9mvRajNTiaksHDiHi2mUpY`
const tokenKeycloak = `eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJWaU9wSlFLUHBHMWpvdEFqaW1KT3R6WEI4dXUzODhWdEQzWkJNMlowRDZzIn0.eyJleHAiOjE2MTgxNTEyMjgsImlhdCI6MTYxODE1MDkyOCwianRpIjoiZGRkZDJjNjUtNGI1Yy00NjdhLTlmNWMtZTNhZTE3M2I5NDI2IiwiaXNzIjoiaHR0cDovLzEyNy4wLjAuMTo4MDgxL2F1dGgvcmVhbG1zL211bHRpLWN1c3RvbWVyIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6IjU0OTVjMmZmLTAzMzUtNDM3My04YjM2LTRjZDk0MzYwMWUyYyIsInR5cCI6IkJlYXJlciIsImF6cCI6ImN1c3RvbWVycyIsInNlc3Npb25fc3RhdGUiOiIzYjY1ZTQ2YS1hNmFkLTRkZmYtODU4NC00OWIwZTZhMjFhMjMiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbImh0dHA6Ly9sb2NhbGhvc3Q6ODA4MSJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJtZW1iZXJAc2VydmljZS10ZWFtIiwiZW1haWwiOiJtZW1iZXJAc2VydmljZS10ZWFtIn0.a33z9wEqjVtUVzDwzvgQzJh_fMq61YpZnKPg4hXj_BOTARnNTMq_aI-hA1yW-h8TpakjCuhgET8ciCRbbb0a63pK-DLUPzeaqUfsvDH7Kap1EqA-wrpe_4KpS60ig72MedQ4WBF4u09dSoEEVLwzQ-eXGSiJ9NbkmvN-_fJasl0XHusf_aynWoD3PQcz5Dji-1MA9bNRTDR0YAMtPJlr2n6Oyxo-08NRVoBTw5Ui4rq_iShQ4SlKdmfATLGAKkaUk2CS4KcFopJeXF1baLrD_RGw1LGpQT-1BOncmkzWJWoyqZF_epTfB4tgd4WcTqdSAj4aCWXd7hA8iadov16kUA`

func TestParseHydraAccessToken(t *testing.T) {
	accessToken, parseErr := defaultInsecureAccessToken(t, tokenHydra)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	expiry, expiryOK := accessToken.Exp()
	if !expiryOK {
		t.Fatal("Expected token expiry to be OK")
	}
	if expiry <= 0 {
		t.Fatalf("Expected expiry to be greater than 0 but received '%d'", expiry)
	}

	scope, scopeOK := accessToken.Scope()
	if !scopeOK {
		t.Fatal("Expected token scope to be OK")
	}
	if scope == "" {
		t.Fatal("Expected scope to be non-empty")
	}
}

func TestParseKeycloakAccessToken(t *testing.T) {
	accessToken, parseErr := defaultInsecureAccessToken(t, tokenKeycloak)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	expiry, expiryOK := accessToken.Exp()
	if !expiryOK {
		t.Fatal("Expected token expiry to be OK")
	}
	if expiry <= 0 {
		t.Fatalf("Expected expiry to be greater than 0 but received '%d'", expiry)
	}

	scope, scopeOK := accessToken.Scope()
	if !scopeOK {
		t.Fatal("Expected token scope to be OK")
	}
	if scope == "" {
		t.Fatal("Expected scope to be non-empty")
	}
}
