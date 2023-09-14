package gosdjwt

import (
	"fmt"
	"strings"
)

// EnvelopePresentation is the envelope presentation
type EnvelopePresentation struct {
	AUD   string `json:"aud"`
	IAT   int64  `json:"iat"`
	Nonce string `json:"nonce"`
	SDJWT string `json:"_sd_jwt"`
}

// JWSPresentation is the JWS presentation, RFC7515
type JWSPresentation struct {
	Payload     string   `json:"payload"`
	Protected   string   `json:"protected"`
	Signature   string   `json:"signature"`
	Disclosures []string `json:"disclosures"`
}

// JWSPresentationWithKeyBinding is the JWS presentation with key binding
type JWSPresentationWithKeyBinding struct {
	JWSPresentation
	KeyBinding string `json:"key_binding"`
}

// StandardPresentation is the standard presentation between Holder and Verifier but in serialized format
type StandardPresentation struct {
	JWT         string
	Disclosures []string
	KeyBinding  string
}

func (s StandardPresentation) String() string {
	t := s.JWT
	if s.Disclosures != nil {
		t += fmt.Sprintf("~%s~", strings.Join(s.Disclosures, "~"))
	}
	if s.KeyBinding != "" {
		t += fmt.Sprintf("%s", s.KeyBinding)
	}
	fmt.Println(t)
	return t
}
