package gosdjwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
)

func TestUntangle(t *testing.T) {
	tts := []struct {
		name         string
		run          bool
		instructions []*Instruction
		want         jwt.Claims
	}{
		{
			name: "no children",
			run:  true,
			instructions: []*Instruction{
				{
					name:  "birthdate",
					value: "1970-01-01",
					sd:    true,
				},
				{
					name:  "sub",
					value: "test-1",
					sd:    true,
				},
			},
			want: jwt.MapClaims{
				"birthdate": "1970-01-01",
				"sub":       "test-1",
			},
		},
		{
			run:  true,
			name: "simple with children",
			instructions: []*Instruction{
				{
					name: "address",
					children: []*Instruction{
						{
							name:  "street_address",
							value: "testgatan 3",
						},
					},
				},
				{
					name:  "sub",
					value: "test-1",
				},
			},
			want: jwt.MapClaims{
				"address": jwt.MapClaims{
					"street_address": "testgatan 3",
				},
				"sub": "test-1",
			},
		},
		{
			run:  true,
			name: "two children",
			instructions: []*Instruction{
				{
					name: "address",
					children: []*Instruction{
						{
							name:  "street_address",
							value: "testgatan 3",
						},
						{
							name:  "country",
							value: "sweden",
						},
					},
				},
				{
					name:  "sub",
					value: "test-1",
				},
			},
			want: jwt.MapClaims{
				"address": jwt.MapClaims{
					"street_address": "testgatan 3",
					"country":        "sweden",
				},
				"sub": "test-1",
			},
		},
		{
			run:  true,
			name: "children array",
			instructions: []*Instruction{
				{
					name: "nationalities",
					children: []*Instruction{
						{
							value: "se",
						},
						{
							value: "uk",
						},
					},
				},
				{
					name:  "sub",
					value: "test-1",
				},
			},
			want: jwt.MapClaims{
				"nationalities": []any{
					"se",
					"uk",
				},
				"sub": "test-1",
			},
		},
		{
			run:  true,
			name: "complete",
			instructions: []*Instruction{
				{
					name: "nationalities",
					children: []*Instruction{
						{
							value: "se",
						},
						{
							value: "uk",
						},
					},
				},
				{
					name:  "birthdate",
					value: "1970-01-01",
					sd:    true,
				},
				{
					name:  "updated_at",
					value: 1570000000,
				},
				{
					name:  "sub",
					value: "test-1",
					sd:    true,
				},
				{
					name: "address",
					children: []*Instruction{
						{
							name:  "street_address",
							value: "testgatan 3",
						},
						{
							name:  "country",
							value: "sweden",
						},
					},
				},
			},
			want: jwt.MapClaims{
				"nationalities": []any{
					"se",
					"uk",
				},
				"sub":        "test-1",
				"birthdate":  "1970-01-01",
				"updated_at": 1570000000,
				"address": jwt.MapClaims{
					"street_address": "testgatan 3",
					"country":        "sweden",
				},
			},
		},
	}
	for _, tt := range tts {
		if !tt.run {
			t.SkipNow()
		}
		t.Run(tt.name, func(t *testing.T) {
			storage := jwt.MapClaims{}
			untangle(jwt.MapClaims{}, "", tt.instructions, storage)
			fmt.Println(storage)
			b, err := json.Marshal(storage)
			assert.NoError(t, err)
			fmt.Println("XXXXX", string(b))
			assert.Equal(t, tt.want, storage)

		})
	}
}

func TestMakeSD(t *testing.T) {
	tts := []struct {
		name         string
		run          bool
		instructions []*Instruction
		wantSDJWT    jwt.Claims
		wantDisclose []Disclosure
	}{
		{
			name: "no children, one _sd",
			run:  true,
			instructions: []*Instruction{
				{
					name:  "birthdate",
					value: "1970-01-01",
					sd:    true,
				},
			},
			wantSDJWT: jwt.MapClaims{
				"_sd": []any{
					"Zjc4YWM0MzQ5ODJiY2RiZmIyN2RkNDMwZmY5M2Q3N2FhOGYxMzQ2YWQ4ODYyZGVjMTQ4NjQ2YzcxM2E0MDUzZg",
				},
			},
			wantDisclose: []Disclosure{
				{
					salt:           "salt_zyx",
					value:          "1970-01-01",
					name:           "birthdate",
					disclosureHash: "WyJzYWx0X3p5eCIsImJpcnRoZGF0ZSIsIjE5NzAtMDEtMDEiXQ",
				},
			},
		},
		{
			name: "no children, two _sd",
			run:  true,
			instructions: []*Instruction{
				{
					name:  "birthdate",
					value: "1970-01-01",
					sd:    true,
				},
				{
					name:  "email",
					value: "test@example.com",
					sd:    true,
				},
			},
			wantSDJWT: jwt.MapClaims{
				"_sd": []any{
					"Zjc4YWM0MzQ5ODJiY2RiZmIyN2RkNDMwZmY5M2Q3N2FhOGYxMzQ2YWQ4ODYyZGVjMTQ4NjQ2YzcxM2E0MDUzZg",
					"YmM1OTExODBmNTBlOGQzYjg4N2YzYTFkNWZkNjhjYWM5NTQ4YjhkMzI4ZjBjY2JmMjg5YTE1ZTY4MTdhYzA3Yw",
				},
			},
			wantDisclose: []Disclosure{
				{
					salt:           "salt_zyx",
					value:          "1970-01-01",
					disclosureHash: "WyJzYWx0X3p5eCIsImJpcnRoZGF0ZSIsIjE5NzAtMDEtMDEiXQ",
					name:           "birthdate",
				},
				{
					salt:           "salt_zyx",
					value:          "test@example.com",
					disclosureHash: "WyJzYWx0X3p5eCIsImVtYWlsIiwidGVzdEBleGFtcGxlLmNvbSJd",
					name:           "email",
				},
			},
		},
		{
			name: "no children, one _sd of two claims",
			run:  true,
			instructions: []*Instruction{
				{
					name:  "birthdate",
					value: "1970-01-01",
					sd:    true,
				},
				{
					name:  "email",
					value: "test@example.com",
					sd:    false,
				},
			},
			wantSDJWT: jwt.MapClaims{
				"_sd": []any{
					"Zjc4YWM0MzQ5ODJiY2RiZmIyN2RkNDMwZmY5M2Q3N2FhOGYxMzQ2YWQ4ODYyZGVjMTQ4NjQ2YzcxM2E0MDUzZg",
				},
				"email": "test@example.com",
			},
			wantDisclose: []Disclosure{
				{
					salt:           "salt_zyx",
					value:          "1970-01-01",
					disclosureHash: "WyJzYWx0X3p5eCIsImJpcnRoZGF0ZSIsIjE5NzAtMDEtMDEiXQ",
					name:           "birthdate",
				},
			},
		},
		{
			name: "one parent one child, one claim, sd all parent",
			run:  true,
			instructions: []*Instruction{
				{
					name: "address",
					children: []*Instruction{
						{
							name:  "street_address",
							value: "testgatan 3",
						},
					},
					sd: true,
				},
			},
			wantSDJWT: jwt.MapClaims{
				"_sd": []any{
					"NTMxZGRlNGZjODk0NzRmZDA1N2MyY2U4NjdiMDU4NWE4YTU1ZWUyZjQ1MTYwZTE0MDZjNDMzOWRjYWIzMjBiZg",
				},
			},
			wantDisclose: []Disclosure{
				{
					salt:           "salt_zyx",
					value:          "testgatan 3",
					disclosureHash: "WyJzYWx0X3p5eCIsInN0cmVldF9hZGRyZXNzIiwidGVzdGdhdGFuIDMiXQ",
					name:           "address",
				},
			},
		},
		{
			name: "two parent one child per, one claim, sd all parent",
			run:  true,
			instructions: []*Instruction{
				{
					name: "address",
					children: []*Instruction{
						{
							name:  "street_address",
							value: "testgatan 3",
						},
					},
					sd: true,
				},
				{
					name: "name",
					children: []*Instruction{
						{
							name:  "given_name",
							value: "test",
						},
					},
					sd: true,
				},
			},
			wantSDJWT: jwt.MapClaims{
				"_sd": []any{
					"NTMxZGRlNGZjODk0NzRmZDA1N2MyY2U4NjdiMDU4NWE4YTU1ZWUyZjQ1MTYwZTE0MDZjNDMzOWRjYWIzMjBiZg",
					"MDQzMzc4NGFlNzk0MGJjMTU3ZDIxZmFmODE1NmIwYmJlNGNkMTdjYWVkZTAzNjViYzllM2Q2ODZkZTBhZGZlYQ",
				},
			},
			wantDisclose: []Disclosure{
				{
					salt:           "salt_zyx",
					value:          "testgatan 3",
					disclosureHash: "WyJzYWx0X3p5eCIsInN0cmVldF9hZGRyZXNzIiwidGVzdGdhdGFuIDMiXQ",
					name:           "address",
				},
				{
					salt:           "salt_zyx",
					value:          "test",
					disclosureHash: "WyJzYWx0X3p5eCIsImdpdmVuX25hbWUiLCJ0ZXN0Il0",
					name:           "name",
				},
			},
		},
		{
			name: "one child, one _sd claim, keep parent visible",
			run:  true,
			instructions: []*Instruction{
				{
					name: "address",
					children: []*Instruction{
						{
							name:  "street_address",
							value: "testgatan 3",
							sd:    true,
						},
					},
				},
			},
			wantSDJWT: jwt.MapClaims{
				"address": jwt.MapClaims{
					"_sd": []any{
						"NTMxZGRlNGZjODk0NzRmZDA1N2MyY2U4NjdiMDU4NWE4YTU1ZWUyZjQ1MTYwZTE0MDZjNDMzOWRjYWIzMjBiZg",
					},
				},
			},
			wantDisclose: []Disclosure{
				{
					salt:           "salt_zyx",
					value:          "testgatan 3",
					disclosureHash: "WyJzYWx0X3p5eCIsInN0cmVldF9hZGRyZXNzIiwidGVzdGdhdGFuIDMiXQ",
					name:           "street_address",
				},
			},
		},
		{
			name: "one parent two children, individual sd for each claim, keep parent visible",
			run:  true,
			instructions: []*Instruction{
				{
					name: "address",
					children: []*Instruction{
						{
							name:  "street_address",
							value: "testgatan 3",
							sd:    true,
						},
						{
							name:  "country",
							value: "sweden",
							sd:    true,
						},
					},
				},
			},
			wantSDJWT: jwt.MapClaims{
				"address": jwt.MapClaims{
					"_sd": []any{
						"NTMxZGRlNGZjODk0NzRmZDA1N2MyY2U4NjdiMDU4NWE4YTU1ZWUyZjQ1MTYwZTE0MDZjNDMzOWRjYWIzMjBiZg",
						"ZTNiMGJhZWY5MDRlODQzZDgxOTEyNjI4NDQ2YTUzYTdlNGY1OTM4ZTkwODI4NGQ4NmMwNjVkODBjOWFiNTk2NA",
					},
				},
			},
			wantDisclose: []Disclosure{
				{
					salt:           "salt_zyx",
					value:          "testgatan 3",
					disclosureHash: "WyJzYWx0X3p5eCIsInN0cmVldF9hZGRyZXNzIiwidGVzdGdhdGFuIDMiXQ",
					name:           "street_address",
				},
				{
					salt:           "salt_zyx",
					value:          "sweden",
					disclosureHash: "WyJzYWx0X3p5eCIsImNvdW50cnkiLCJzd2VkZW4iXQ",
					name:           "country",
				},
			},
		},
		{
			name: "one parent two children, one sd claim, keep parent visible",
			run:  true,
			instructions: []*Instruction{
				{
					name: "address",
					children: []*Instruction{
						{
							name:  "street_address",
							value: "testgatan 3",
							sd:    true,
						},
						{
							name:  "country",
							value: "sweden",
							sd:    false,
						},
					},
				},
			},
			wantSDJWT: jwt.MapClaims{
				"address": jwt.MapClaims{
					"_sd": []any{
						"NTMxZGRlNGZjODk0NzRmZDA1N2MyY2U4NjdiMDU4NWE4YTU1ZWUyZjQ1MTYwZTE0MDZjNDMzOWRjYWIzMjBiZg",
					},
					"country": "sweden",
				},
			},
			wantDisclose: []Disclosure{
				{
					salt:           "zyx",
					value:          "testgatan 3",
					disclosureHash: "WyJzYWx0X3p5eCIsInN0cmVldF9hZGRyZXNzIiwidGVzdGdhdGFuIDMiXQ",
					name:           "street_address",
				},
			},
		},
		{
			name: "one parent with two array-like children claims with sd claim for each child, keep parent visible",
			run:  true,
			instructions: []*Instruction{
				{
					name: "nationalities",
					children: []*Instruction{
						{
							value: "se",
							sd:    true,
						},
						{
							value: "uk",
							sd:    true,
						},
					},
				},
			},
			wantSDJWT: jwt.MapClaims{
				"nationalities": []any{
					jwt.MapClaims{
						"...": "YTZkZWNmMTQxZDg3ZGMxMDUzNDQwNThhM2E5ODUyZjZhZDBiNmUzZmIzOTY0YjJiYjI5MWQ1M2E2MDA1M2U2Ng",
					},
					jwt.MapClaims{
						"...": "ZmRmMzhkY2FiZmUzNTBjYjI2MWQyZjNlYmJkN2M4ODk4NzQ2MDkxMzRhZjcyMzkwZGZjYmIxN2Y3YjY5NDgxZQ",
					},
				},
			},
			wantDisclose: []Disclosure{
				{
					salt:           "salt_zyx",
					value:          "se",
					disclosureHash: "WyJzYWx0X3p5eCIsIiIsInNlIl0",
				},
				{
					salt:           "salt_zyx",
					value:          "uk",
					disclosureHash: "WyJzYWx0X3p5eCIsIiIsInVrIl0",
				},
			},
		},
		{
			name: "one parent with two array-like children claims with one sd claim for one child",
			run:  true,
			instructions: []*Instruction{
				{
					name: "nationalities",
					children: []*Instruction{
						{
							value: "se",
							sd:    true,
						},
						{
							value: "uk",
							sd:    false,
						},
					},
				},
			},
			wantSDJWT: jwt.MapClaims{
				"nationalities": []any{
					jwt.MapClaims{
						"...": "YTZkZWNmMTQxZDg3ZGMxMDUzNDQwNThhM2E5ODUyZjZhZDBiNmUzZmIzOTY0YjJiYjI5MWQ1M2E2MDA1M2U2Ng",
					},
					"uk",
				},
			},
			wantDisclose: []Disclosure{
				{
					salt:           "salt_zyx",
					value:          "se",
					disclosureHash: "WyJzYWx0X3p5eCIsIiIsInNlIl0",
				},
			},
		},
		{
			name: "one parent with two array-like children claims with one sd claim for one child, reverse order",
			run:  true,
			instructions: []*Instruction{
				{
					name: "nationalities",
					children: []*Instruction{
						{
							value: "se",
							sd:    false,
						},
						{
							value: "uk",
							sd:    true,
						},
					},
				},
			},
			wantSDJWT: jwt.MapClaims{
				"nationalities": []any{
					"se",
					jwt.MapClaims{
						"...": "ZmRmMzhkY2FiZmUzNTBjYjI2MWQyZjNlYmJkN2M4ODk4NzQ2MDkxMzRhZjcyMzkwZGZjYmIxN2Y3YjY5NDgxZQ",
					},
				},
			},
			wantDisclose: []Disclosure{
				{
					salt:           "salt_zyx",
					value:          "uk",
					disclosureHash: "WyJzYWx0X3p5eCIsIiIsInVrIl0",
				},
			},
		},
		{
			name: "one sd claim and one non-sd claim",
			run:  true,
			instructions: []*Instruction{
				{
					name:  "birthdate",
					value: "1970-01-01",
					sd:    true,
				},
				{
					name:  "first_name",
					value: "test",
				},
			},
			wantSDJWT: jwt.MapClaims{
				"_sd": []any{
					"Zjc4YWM0MzQ5ODJiY2RiZmIyN2RkNDMwZmY5M2Q3N2FhOGYxMzQ2YWQ4ODYyZGVjMTQ4NjQ2YzcxM2E0MDUzZg",
				},
				"first_name": "test",
			},
			wantDisclose: []Disclosure{
				{
					salt:           "salt_zyx",
					name:           "birthdate",
					value:          "1970-01-01",
					disclosureHash: "WyJzYWx0X3p5eCIsImJpcnRoZGF0ZSIsIjE5NzAtMDEtMDEiXQ",
				},
			},
		},
	}

	for _, tt := range tts {
		if !tt.run {
			t.SkipNow()
		}
		t.Run(tt.name, func(t *testing.T) {
			newSalt = func() string {
				return "salt_zyx"
			}
			storage := jwt.MapClaims{}
			disclosures := disclosures{}
			err := makeSD(jwt.MapClaims{}, "", false, tt.instructions, storage, disclosures)
			assert.NoError(t, err)
			assert.Equal(t, tt.wantSDJWT, storage)

			opts := cmp.Options{
				cmp.AllowUnexported(Disclosure{}),
				cmpopts.IgnoreFields(Disclosure{}, "salt"),
			}

			if !cmp.Equal(tt.wantDisclose, disclosures.makeArray(), opts) {
				t.Logf("disclosures want: %v, got: %v", tt.wantDisclose, disclosures.makeArray())
				t.FailNow()
			}
		})
	}
}

func TestRecursiveClaim(t *testing.T) {
	type want struct {
		disclosures []Disclosure
		sdJWT       jwt.MapClaims
	}
	tts := []struct {
		name         string
		run          bool
		instructions []*Instruction
		want         want
	}{
		{
			name: "recursive claim",
			run:  true,
			instructions: []*Instruction{
				{
					name: "address",
					sd:   true,
					children: []*Instruction{
						{
							name:  "street",
							value: "testgatan 3",
							sd:    true,
						},
						{
							name:  "location",
							value: "skaraborg",
							sd:    true,
						},
					},
				},
			},
			want: want{
				sdJWT: jwt.MapClaims{
					"_sd": []any{"xyz"},
				},
				disclosures: []Disclosure{
					{
						salt:           "salt_zyx",
						value:          "testgatan 3",
						disclosureHash: "xyz",
						name:           "street",
					},
					{
						salt:           "salt_zyx",
						value:          "skaraborg",
						disclosureHash: "xyz",
						name:           "location",
					},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.run {
				t.SkipNow()
			}
			storage := jwt.MapClaims{}
			disclosures := disclosures{}
			makeSD(jwt.MapClaims{}, "", false, tt.instructions, storage, disclosures)

			opts := cmp.Options{
				cmp.AllowUnexported(Disclosure{}),
				cmpopts.IgnoreFields(Disclosure{}, "salt"),
			}

			assert.Equal(t, tt.want.sdJWT, storage)

			if !cmp.Equal(tt.want.disclosures, disclosures.makeArray(), opts) {
				t.Logf("disclosures want: %v, got: %v", tt.want.disclosures, disclosures.makeArray())
				t.FailNow()
			}
		})
	}
}

func TestDisclosuresString(t *testing.T) {
	tts := []struct {
		name string
		run  bool
		have disclosures
		want string
	}{
		{
			name: "one disclosure",
			run:  true,
			have: disclosures{
				"birthdate": Disclosure{
					salt:           "zyx",
					value:          "xyz",
					disclosureHash: "xyz",
				},
			},
			want: "~xyz~",
		},
		{
			name: "two disclosure",
			run:  true,
			have: disclosures{
				"birthdate": Disclosure{
					salt:           "zyx",
					value:          "xyz",
					disclosureHash: "xyz",
				},
				"givename": Disclosure{
					salt:           "zyx",
					value:          "xyz",
					disclosureHash: "xyz",
				},
			},
			want: "~xyz~xyz~",
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.have.string()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDisclosuresArray(t *testing.T) {
	tts := []struct {
		name string
		run  bool
		have disclosures
		want []Disclosure
	}{
		{
			name: "one disclosure",
			run:  true,
			have: disclosures{
				"birthdate": Disclosure{
					salt:           "zyx",
					value:          "xyz",
					disclosureHash: "xyz",
				},
			},
			want: []Disclosure{
				{
					salt:           "zyx",
					value:          "xyz",
					disclosureHash: "xyz",
				},
			},
		},
		{
			name: "two disclosure",
			run:  true,
			have: disclosures{
				"birthdate": Disclosure{
					salt:           "zyx",
					value:          "xyz",
					disclosureHash: "xyz",
				},
				"givename": Disclosure{
					salt:           "zyx",
					value:          "xyz",
					disclosureHash: "xyz",
				},
			},
			want: []Disclosure{
				{
					salt:           "zyx",
					value:          "xyz",
					disclosureHash: "xyz",
				},
				{
					salt:           "zyx",
					value:          "xyz",
					disclosureHash: "xyz",
				},
			},
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.run {
				t.SkipNow()
			}
			got := tt.have.makeArray()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBase64Encode(t *testing.T) {
	type want struct {
		s string
		a string
	}
	tts := []struct {
		name string
		run  bool
		have Instruction
		want want
	}{
		{
			name: "string value in instruction",
			run:  true,
			have: Instruction{
				salt:  "salt_zyx",
				value: "xyz",
				name:  "birthdate",
			},
			want: want{
				s: "WyJzYWx0X3p5eCIsImJpcnRoZGF0ZSIsInh5eiJd",
				a: "[\"salt_zyx\",\"birthdate\",\"xyz\"]",
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.run {
				t.SkipNow()
			}
			tt.have.makeDisclosureHash()
			assert.Equal(t, tt.want.s, tt.have.disclosureHash)

			gotDecoded, err := base64.RawStdEncoding.DecodeString(tt.have.disclosureHash)
			assert.NoError(t, err)
			fmt.Println("gotDecoded", string(gotDecoded))
			assert.Equal(t, tt.want.a, string(gotDecoded))
		})
	}
}

func TestSHA256Hash(t *testing.T) {
	tts := []struct {
		name string
		run  bool
		have *Instruction
		want string
	}{
		{
			name: "first",
			run:  true,
			have: &Instruction{
				salt:           "zyx",
				value:          "xyz",
				name:           "birthdate",
				disclosureHash: "WyJ6eXgiLCJiaXJ0aGRhdGUiLCJ4eXoiXQ==",
			},
			want: "ZWFjZjU3ZjllYTA0ZDllZTY5NDFjMTBlY2NlMzM0YjY0ZTAwNDdiNDFjNTdmYWVhYWIzYmNlMTQ3YTNkZjk4Nw",
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.run {
				t.SkipNow()
			}
			err := tt.have.makeClaimHash()
			assert.NoError(t, err)
			fmt.Println("claimHash", tt.have.claimHash)
			assert.Equal(t, tt.want, tt.have.claimHash)
		})
	}
}
