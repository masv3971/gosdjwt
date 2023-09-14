package gosdjwt

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestParseAndValidate(t *testing.T) {
	tts := []struct {
		name string
		have string
		want jwt.MapClaims
	}{
		{
			name: "test 1",
			have: mockSDJWT,
			want: jwt.MapClaims{
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
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseJWTAndValidate(tt.have, "mura")
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
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

func TestCleanClaims(t *testing.T) {
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
				disclosures: []string{
					mockBirthdayDisclosure,
				},
			},
			want: jwt.MapClaims{
				"sub": "test-2",
				"address": map[string]any{
					"country": "sweden",
				},
				"birthdate": "1970-01-01",
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := run(tt.have.claims, tt.have.disclosures)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
