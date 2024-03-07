package gosdjwt

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Presentation interface {
	String() string
}

// PresentationEnvelope is the envelope presentation
type PresentationEnvelope struct {
	AUD            string `json:"aud"`
	IAT            int64  `json:"iat"`
	Nonce          string `json:"nonce"`
	SDJWT          string `json:"_sd_jwt"`
	originalSource *SDJWT
}

// PresentationEnvelope returns a presentation envelope
func (s *SDJWT) PresentationEnvelope(aud, nonce string, iat int64) *PresentationEnvelope {
	return &PresentationEnvelope{
		AUD:            aud,
		IAT:            iat,
		Nonce:          nonce,
		SDJWT:          s.PresentationFlat().String(),
		originalSource: s,
	}
}

func (p PresentationEnvelope) String() (string, error) {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// PresentationJWS is the JWS presentation, RFC7515
type PresentationJWS struct {
	Payload        string   `json:"payload"`
	Protected      string   `json:"protected"`
	Signature      string   `json:"signature"`
	Disclosures    []string `json:"disclosures"`
	originalSource *SDJWT
}

func (s *SDJWT) PresentationJWS() *PresentationJWS {
	return &PresentationJWS{
		Payload:        s.JWT,
		Disclosures:    s.Disclosures.ArrayHashes(),
		originalSource: s,
	}
}

func (p PresentationJWS) String() string {
	return ""
}

// PresentationJWSWithKeyBinding is the JWS presentation with key binding
type PresentationJWSWithKeyBinding struct {
	PresentationJWS
	KeyBinding string `json:"key_binding"`
}

func (p PresentationJWSWithKeyBinding) String() string {
	return ""
}

// PresentationFlat is the standard presentation between Holder and Verifier but in serialized format
type PresentationFlat struct {
	JWT            string
	Disclosures    []string
	KeyBinding     string
	originalSource *SDJWT
}

func (s *SDJWT) PresentationFlat() *PresentationFlat {
	presentation := &PresentationFlat{
		JWT:            s.JWT,
		Disclosures:    s.Disclosures.ArrayHashes(),
		KeyBinding:     s.KeyBinding,
		originalSource: s,
	}
	return presentation
}

func (p *PresentationFlat) String() string {
	t := p.JWT
	if len(p.Disclosures) != 0 {
		t += fmt.Sprintf("~%s~", strings.Join(p.originalSource.Disclosures.ArrayHashes(), "~"))
	}
	if p.KeyBinding != "" {
		t += p.KeyBinding
	}
	return t
}
