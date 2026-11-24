package server

import (
	"net/http"

	"github.com/nuomiiiii/lite-agent/requestheaders"
)

func authorizeAgentRequest(request *http.Request, token string) {
	requestheaders.ApplyAgentAuthentication(request.Header, token, flags.CFAccessClientID, flags.CFAccessClientSecret)
}
