package gosdjwt

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestParseAndValidate(t *testing.T) {
	type want struct {
		jwt        jwt.MapClaims
		validation *Validation
	}
	tts := []struct {
		name string
		have string
		want want
	}{
		{
			name: "test 1",
			have: mockSDJWT,
			want: want{
				jwt: jwt.MapClaims{
					"_sd_alg": "sha-256",
					"sub":     "test-2",
					"address": map[string]any{
						"_sd": []any{
							"NTMxZGRlNGZjODk0NzRmZDA1N2MyY2U4NjdiMDU4NWE4YTU1ZWUyZjQ1MTYwZTE0MDZjNDMzOWRjYWIzMjBiZg",
						},
						"country": "sweden",
					},
					"_sd": []any{
						"MzE0ZDU5NzY0NGQ4YjRlZTM1YjJjYWMwNGFlNmMwM2JiNGFmYTk5ODQxMDhjMzIzNGQ3ZTY2NmZmMWJmYzk4Nw",
						"Zjc4YWM0MzQ5ODJiY2RiZmIyN2RkNDMwZmY5M2Q3N2FhOGYxMzQ2YWQ4ODYyZGVjMTQ4NjQ2YzcxM2E0MDUzZg",
					},
				},
				validation: &Validation{
					SignaturePolicy: SignaturePolicyPassed,
					Verify:          true,
				},
			},
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			gotJWT, validation, err := parseJWTAndValidate(tt.have, "mura")
			assert.NoError(t, err)
			assert.Equal(t, tt.want.jwt, gotJWT)
			assert.Equal(t, tt.want.validation, validation)
		})
	}
}

func TestSplitSDJWT(t *testing.T) {
	type want struct {
		jwt         string
		disclosures []string
		keyBinding  string
	}
	tts := []struct {
		name string
		have string
		want StandardPresentation
	}{
		{
			name: "test 0",
			have: "xx.xxx.xxx",
			want: StandardPresentation{
				JWT:         "xx.xxx.xxx",
				Disclosures: nil,
				KeyBinding:  "",
			},
		},
		{
			name: "test 1",
			have: "xx.xxx.xxx~d1~",
			want: StandardPresentation{
				JWT:         "xx.xxx.xxx",
				Disclosures: []string{"d1"},
				KeyBinding:  "",
			},
		},
		{
			name: "test 2",
			have: "xx.xxx.xxx~d1~d2~",
			want: StandardPresentation{
				JWT: "xx.xxx.xxx",
				Disclosures: []string{
					"d1",
					"d2",
				},
				KeyBinding: "",
			},
		},
		{
			name: "test 3",
			have: "xx.xxx.xxx~d1~d2~kb",
			want: StandardPresentation{
				JWT: "xx.xxx.xxx",
				Disclosures: []string{
					"d1",
					"d2",
				},
				KeyBinding: "kb",
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got := splitSDJWT(tt.have)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRun(t *testing.T) {
	type have struct {
		claims      jwt.MapClaims
		disclosures []string
	}
	tts := []struct {
		name        string
		have        have
		disclosures []string
		want        jwt.MapClaims
	}{
		{
			name: "test 1",
			have: have{
				claims: jwt.MapClaims{
					"_sd_alg": "sha-256",
					"sub":     "test-2",
					"address": jwt.MapClaims{
						"_sd": []any{
							"NTMxZGRlNGZjODk0NzRmZDA1N2MyY2U4NjdiMDU4NWE4YTU1ZWUyZjQ1MTYwZTE0MDZjNDMzOWRjYWIzMjBiZg",
						},
						"country": "sweden",
					},
					"_sd": []any{
						"MzE0ZDU5NzY0NGQ4YjRlZTM1YjJjYWMwNGFlNmMwM2JiNGFmYTk5ODQxMDhjMzIzNGQ3ZTY2NmZmMWJmYzk4Nw",
						"Zjc4YWM0MzQ5ODJiY2RiZmIyN2RkNDMwZmY5M2Q3N2FhOGYxMzQ2YWQ4ODYyZGVjMTQ4NjQ2YzcxM2E0MDUzZg",
					},
				},
				disclosures: []string{
					mockBirthdayDisclosure,
				},
			},
			want: jwt.MapClaims{
				"sub": "test-2",
				"address": jwt.MapClaims{
					"country": "sweden",
				},
				"birthdate": "1970-01-01",
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got := run(tt.have.claims, tt.have.disclosures)
			b, _ := json.Marshal(got)
			fmt.Println("JSON: ", string(b))
			//assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRemoveSDClaims(t *testing.T) {
	tts := []struct {
		name        string
		have        jwt.MapClaims
		disclosures []string
		want        jwt.MapClaims
	}{
		{
			name: "test 1",
			have: jwt.MapClaims{
				"_sd_alg": "sha-256",
				"sub":     "test-2",
				"address": jwt.MapClaims{
					"_sd": []any{
						"NTMxZGRlNGZjODk0NzRmZDA1N2MyY2U4NjdiMDU4NWE4YTU1ZWUyZjQ1MTYwZTE0MDZjNDMzOWRjYWIzMjBiZg",
					},
					"country": "sweden",
				},
				"_sd": []any{
					"MzE0ZDU5NzY0NGQ4YjRlZTM1YjJjYWMwNGFlNmMwM2JiNGFmYTk5ODQxMDhjMzIzNGQ3ZTY2NmZmMWJmYzk4Nw",
					"Zjc4YWM0MzQ5ODJiY2RiZmIyN2RkNDMwZmY5M2Q3N2FhOGYxMzQ2YWQ4ODYyZGVjMTQ4NjQ2YzcxM2E0MDUzZg",
				},
			},
			disclosures: []string{
				mockBirthdayDisclosure,
			},
			want: jwt.MapClaims{
				"sub": "test-2",
				"address": jwt.MapClaims{
					"country": "sweden",
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			removeSDClaims(tt.have)
			b, _ := json.Marshal(tt.have)
			fmt.Println("JSON: ", string(b))
			assert.Equal(t, tt.want, tt.have)
		})
	}
}

func TestVerifier(t *testing.T) {
	type have struct {
		sdjwt string
		key   string
	}
	type want struct {
		validation *Validation
		jwt        jwt.MapClaims
	}
	tts := []struct {
		name string
		have have
		want want
	}{
		{
			name: "test 1",
			have: have{
				sdjwt: mockSDJWTWithGivenNameDisclosure,
				key:   "mura",
			},
			want: want{
				validation: &Validation{
					SignaturePolicy: SignaturePolicyPassed,
					Verify:          true,
				},
				jwt: jwt.MapClaims{
					"sub": "test-2",
					"address": map[string]any{
						"country": "sweden",
					},
					"given_name": "John",
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			gotJWT, gotValidation, err := Verify(tt.have.sdjwt, tt.have.key)
			b, _ := json.Marshal(gotJWT)
			fmt.Println("JSON: ", string(b))
			assert.NoError(t, err)
			assert.Equal(t, tt.want.jwt, gotJWT)
			assert.Equal(t, tt.want.validation, gotValidation)
		})
	}
}
