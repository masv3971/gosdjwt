package gosdjwt

import (
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
		instructions []instruction
		want         jwt.Claims
	}{
		{
			name: "no children",
			run:  true,
			instructions: []instruction{
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
			instructions: []instruction{
				{
					name: "address",
					children: []instruction{
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
			instructions: []instruction{
				{
					name: "address",
					children: []instruction{
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
			instructions: []instruction{
				{
					name: "nationalities",
					children: []instruction{
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
			instructions: []instruction{
				{
					name: "nationalities",
					children: []instruction{
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
					children: []instruction{
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
		instructions []instruction
		wantSDJWT    jwt.Claims
		wantDisclose []Disclosure
	}{
		{
			name: "no children, one _sd",
			run:  true,
			instructions: []instruction{
				{
					name:  "birthdate",
					value: "1970-01-01",
					sd:    true,
				},
			},
			wantSDJWT: jwt.MapClaims{
				"_sd": []any{
					"xyz",
				},
			},
			wantDisclose: []Disclosure{
				{
					salt:   "salt_zyx",
					value:  "xyz",
					name:   "birthdate",
					sdHash: "xyz",
				},
			},
		},
		{
			name: "no children, two _sd",
			run:  true,
			instructions: []instruction{
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
					"xyz",
					"xyz",
				},
			},
			wantDisclose: []Disclosure{
				{
					salt:   "salt_zyx",
					value:  "xyz",
					sdHash: "xyz",
					name:   "birthdate",
				},
				{
					salt:   "salt_zyx",
					value:  "xyz",
					sdHash: "xyz",
					name:   "email",
				},
			},
		},
		{
			name: "no children, one _sd of two claims",
			run:  true,
			instructions: []instruction{
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
					"xyz",
				},
				"email": "test@example.com",
			},
			wantDisclose: []Disclosure{
				{
					salt:   "salt_zyx",
					value:  "xyz",
					sdHash: "xyz",
					name:   "birthdate",
				},
			},
		},
		{
			name: "one parent one child, one claim, sd all parent",
			run:  true,
			instructions: []instruction{
				{
					name: "address",
					children: []instruction{
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
					"xyz",
				},
			},
			wantDisclose: []Disclosure{
				{
					salt:   "salt_zyx",
					value:  "xyz",
					sdHash: "xyz",
					name:   "address",
				},
			},
		},
		{
			name: "two parent one child per, one claim, sd all parent",
			run:  true,
			instructions: []instruction{
				{
					name: "address",
					children: []instruction{
						{
							name:  "street_address",
							value: "testgatan 3",
						},
					},
					sd: true,
				},
				{
					name: "name",
					children: []instruction{
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
					"xyz",
					"xyz",
				},
			},
			wantDisclose: []Disclosure{
				{
					salt:   "salt_zyx",
					value:  "xyz",
					sdHash: "xyz",
					name:   "address",
				},
				{
					salt:   "salt_zyx",
					value:  "xyz",
					sdHash: "xyz",
					name:   "name",
				},
			},
		},
		{
			name: "one child, one _sd claim, keep parent visible",
			run:  true,
			instructions: []instruction{
				{
					name: "address",
					children: []instruction{
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
						"xyz",
					},
				},
			},
			wantDisclose: []Disclosure{
				{
					salt:   "salt_zyx",
					value:  "xyz",
					sdHash: "xyz",
					name:   "street_address",
				},
			},
		},
		{
			name: "one parent two children, individual sd for each claim, keep parent visible",
			run:  true,
			instructions: []instruction{
				{
					name: "address",
					children: []instruction{
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
						"xyz",
						"xyz",
					},
				},
			},
			wantDisclose: []Disclosure{
				{
					salt:   "salt_zyx",
					value:  "xyz",
					sdHash: "xyz",
					name:   "street_address",
				},
				{
					salt:   "salt_zyx",
					value:  "xyz",
					sdHash: "xyz",
					name:   "country",
				},
			},
		},
		{
			name: "one parent two children, one sd claim, keep parent visible",
			run:  true,
			instructions: []instruction{
				{
					name: "address",
					children: []instruction{
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
						"xyz",
					},
					"country": "sweden",
				},
			},
			wantDisclose: []Disclosure{
				{
					salt:   "zyx",
					value:  "xyz",
					sdHash: "xyz",
					name:   "street_address",
				},
			},
		},
		{
			name: "one parent with two array-like children claims with sd claim for each child, keep parent visible",
			run:  true,
			instructions: []instruction{
				{
					name: "nationalities",
					children: []instruction{
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
						"...": "xyz",
					},
					jwt.MapClaims{
						"...": "xyz",
					},
				},
			},
			wantDisclose: []Disclosure{
				{
					salt:   "salt_zyx",
					value:  "se",
					sdHash: "xyz",
				},
				{
					salt:   "salt_zyx",
					value:  "uk",
					sdHash: "xyz",
				},
			},
		},
		{
			name: "one parent with two array-like children claims with one sd claim for one child",
			run:  true,
			instructions: []instruction{
				{
					name: "nationalities",
					children: []instruction{
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
						"...": "xyz",
					},
					"uk",
				},
			},
			wantDisclose: []Disclosure{
				{
					salt:   "salt_zyx",
					value:  "se",
					sdHash: "xyz",
				},
			},
		},
		{
			name: "one parent with two array-like children claims with one sd claim for one child, reverse order",
			run:  true,
			instructions: []instruction{
				{
					name: "nationalities",
					children: []instruction{
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
						"...": "xyz",
					},
				},
			},
			wantDisclose: []Disclosure{
				{
					salt:   "salt_zyx",
					value:  "uk",
					sdHash: "xyz",
				},
			},
		},
		{
			name: "one sd claim and one non-sd claim",
			run:  true,
			instructions: []instruction{
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
					"xyz",
				},
				"first_name": "test",
			},
			wantDisclose: []Disclosure{
				{
					salt:   "salt_zyx",
					name:   "birthdate",
					value:  "xyz",
					sdHash: "xyz",
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
			disclosures := disclosures{}
			makeSD(jwt.MapClaims{}, "", false, tt.instructions, storage, disclosures)
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
					salt:   "zyx",
					value:  "xyz",
					sdHash: "xyz",
				},
			},
			want: "~xyz~",
		},
		{
			name: "two disclosure",
			run:  true,
			have: disclosures{
				"birthdate": Disclosure{
					salt:   "zyx",
					value:  "xyz",
					sdHash: "xyz",
				},
				"givename": Disclosure{
					salt:   "zyx",
					value:  "xyz",
					sdHash: "xyz",
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
					salt:   "zyx",
					value:  "xyz",
					sdHash: "xyz",
				},
			},
			want: []Disclosure{
				{
					salt:   "zyx",
					value:  "xyz",
					sdHash: "xyz",
				},
			},
		},
		{
			name: "two disclosure",
			run:  true,
			have: disclosures{
				"birthdate": Disclosure{
					salt:   "zyx",
					value:  "xyz",
					sdHash: "xyz",
				},
				"givename": Disclosure{
					salt:   "zyx",
					value:  "xyz",
					sdHash: "xyz",
				},
			},
			want: []Disclosure{
				{
					salt:   "zyx",
					value:  "xyz",
					sdHash: "xyz",
				},
				{
					salt:   "zyx",
					value:  "xyz",
					sdHash: "xyz",
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
