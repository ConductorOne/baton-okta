package oktaerrors

import (
	"embed"
	"encoding/json"
	"sync"
)

// Found in https://developer.okta.com/docs/reference/error-codes/
// Embed into the JS
//
//go:embed error.json
var embeddedErrors embed.FS

var MappedErrors = sync.OnceValue(func() map[string]*OktaError {
	data, err := embeddedErrors.ReadFile("error.json")
	if err != nil {
		panic(err)
	}

	errors := struct {
		Release string      `json:"release"`
		Build   string      `json:"build"`
		Errors  []OktaError `json:"errors"`
	}{}

	err = json.Unmarshal(data, &errors)
	if err != nil {
		panic(err)
	}

	mappedErrors := make(map[string]*OktaError)
	for _, e := range errors.Errors {
		mappedErrors[e.ErrorCode] = &e
	}

	return mappedErrors
})

type OktaError struct {
	Title                    string `json:"title"`
	IncludesExceptionMessage bool   `json:"includesExceptionMessage"`
	StatusCode               int    `json:"statusCode"`
	StatusReasonPhrase       string `json:"statusReasonPhrase"`
	ErrorCode                string `json:"errorCode"`
	ErrorSummary             string `json:"errorSummary"`
	ErrorDescription         string `json:"errorDescription"`
}

func FindError(errorCode string) *OktaError {
	errors := MappedErrors()

	return errors[errorCode]
}
