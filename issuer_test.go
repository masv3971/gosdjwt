package gosdjwt

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
)

var mockCompleteSDJWT = Instructions{
	{
		Name:  "_sd_alg",
		Value: "sha-256",
	},
	{
		Name:  "sub",
		Value: "test-2",
	},
	{
		Name:  "given_name",
		Value: "John",
		SD:    true,
	},
	{
		Name: "address",
		Children: []*Instruction{
			{
				Name:  "street_address",
				Value: "testgatan 3",
				SD:    true,
			},
			{
				Name:  "country",
				Value: "sweden",
			},
		},
	},
	{
		Name:  "birthdate",
		Value: "1970-01-01",
		SD:    true,
	},
}

var (
	mockSDJWTWithGivenNameDisclosure             = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfc2QiOlsiTXpFMFpEVTVOelkwTkdRNFlqUmxaVE0xWWpKallXTXdOR0ZsTm1Nd00ySmlOR0ZtWVRrNU9EUXhNRGhqTXpJek5HUTNaVFkyTm1abU1XSm1Zems0TnciLCJaamM0WVdNME16UTVPREppWTJSaVptSXlOMlJrTkRNd1ptWTVNMlEzTjJGaE9HWXhNelEyWVdRNE9EWXlaR1ZqTVRRNE5qUTJZemN4TTJFME1EVXpaZyJdLCJfc2RfYWxnIjoic2hhLTI1NiIsImFkZHJlc3MiOnsiX3NkIjpbIk5UTXhaR1JsTkdaak9EazBOelJtWkRBMU4yTXlZMlU0TmpkaU1EVTROV0U0WVRVMVpXVXlaalExTVRZd1pURTBNRFpqTkRNek9XUmpZV0l6TWpCaVpnIl0sImNvdW50cnkiOiJzd2VkZW4ifSwic3ViIjoidGVzdC0yIn0.O60CIBHS-AaOOUFgbatYzg9eCLMBvRZ5rDhRuSWjDk8~WyJzYWx0X3p5eCIsImdpdmVuX25hbWUiLCJKb2huIl0~"
	mockSDJWTWithGivenNameAndBirthdateDisclosure = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfc2QiOlsiTXpFMFpEVTVOelkwTkdRNFlqUmxaVE0xWWpKallXTXdOR0ZsTm1Nd00ySmlOR0ZtWVRrNU9EUXhNRGhqTXpJek5HUTNaVFkyTm1abU1XSm1Zems0TnciLCJaamM0WVdNME16UTVPREppWTJSaVptSXlOMlJrTkRNd1ptWTVNMlEzTjJGaE9HWXhNelEyWVdRNE9EWXlaR1ZqTVRRNE5qUTJZemN4TTJFME1EVXpaZyJdLCJfc2RfYWxnIjoic2hhLTI1NiIsImFkZHJlc3MiOnsiX3NkIjpbIk5UTXhaR1JsTkdaak9EazBOelJtWkRBMU4yTXlZMlU0TmpkaU1EVTROV0U0WVRVMVpXVXlaalExTVRZd1pURTBNRFpqTkRNek9XUmpZV0l6TWpCaVpnIl0sImNvdW50cnkiOiJzd2VkZW4ifSwic3ViIjoidGVzdC0yIn0.O60CIBHS-AaOOUFgbatYzg9eCLMBvRZ5rDhRuSWjDk8~WyJzYWx0X3p5eCIsImdpdmVuX25hbWUiLCJKb2huIl0~WyJzYWx0X3p5eCIsImJpcnRoZGF0ZSIsIjE5NzAtMDEtMDEiXQ~"

	mockSDJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfc2QiOlsiTXpFMFpEVTVOelkwTkdRNFlqUmxaVE0xWWpKallXTXdOR0ZsTm1Nd00ySmlOR0ZtWVRrNU9EUXhNRGhqTXpJek5HUTNaVFkyTm1abU1XSm1Zems0TnciLCJaamM0WVdNME16UTVPREppWTJSaVptSXlOMlJrTkRNd1ptWTVNMlEzTjJGaE9HWXhNelEyWVdRNE9EWXlaR1ZqTVRRNE5qUTJZemN4TTJFME1EVXpaZyJdLCJfc2RfYWxnIjoic2hhLTI1NiIsImFkZHJlc3MiOnsiX3NkIjpbIk5UTXhaR1JsTkdaak9EazBOelJtWkRBMU4yTXlZMlU0TmpkaU1EVTROV0U0WVRVMVpXVXlaalExTVRZd1pURTBNRFpqTkRNek9XUmpZV0l6TWpCaVpnIl0sImNvdW50cnkiOiJzd2VkZW4ifSwic3ViIjoidGVzdC0yIn0.O60CIBHS-AaOOUFgbatYzg9eCLMBvRZ5rDhRuSWjDk8"

	mockGivenNameDisclosure = "WyJzYWx0X3p5eCIsImdpdmVuX25hbWUiLCJKb2huIl0"
	mockBirthdayDisclosure  = "WyJzYWx0X3p5eCIsImJpcnRoZGF0ZSIsIjE5NzAtMDEtMDEiXQ"
)

func TestNewSalt(t *testing.T) {
	got := newSalt()
	assert.NotEmpty(t, got)
}

func TestMakeSD(t *testing.T) {
	tts := []struct {
		name         string
		description  string
		run          bool
		instructions []*Instruction
		wantSDJWT    jwt.Claims
		wantDisclose []*Disclosure
	}{
		{
			name:        "test-1",
			description: "no children, one _sd",
			run:         true,
			instructions: []*Instruction{
				{
					Name:  "birthdate",
					Value: "1970-01-01",
					SD:    true,
				},
			},
			wantSDJWT: jwt.MapClaims{
				"_sd": []any{
					"Zjc4YWM0MzQ5ODJiY2RiZmIyN2RkNDMwZmY5M2Q3N2FhOGYxMzQ2YWQ4ODYyZGVjMTQ4NjQ2YzcxM2E0MDUzZg",
				},
			},
			wantDisclose: []*Disclosure{
				{
					salt:           "salt_zyx",
					value:          "1970-01-01",
					name:           "birthdate",
					disclosureHash: "WyJzYWx0X3p5eCIsImJpcnRoZGF0ZSIsIjE5NzAtMDEtMDEiXQ",
				},
			},
		},
		{
			name:        "test-2",
			description: "no children, two _sd",
			run:         true,
			instructions: []*Instruction{
				{
					Name:  "birthdate",
					Value: "1970-01-01",
					SD:    true,
				},
				{
					Name:  "email",
					Value: "test@example.com",
					SD:    true,
				},
			},
			wantSDJWT: jwt.MapClaims{
				"_sd": []any{
					"Zjc4YWM0MzQ5ODJiY2RiZmIyN2RkNDMwZmY5M2Q3N2FhOGYxMzQ2YWQ4ODYyZGVjMTQ4NjQ2YzcxM2E0MDUzZg",
					"YmM1OTExODBmNTBlOGQzYjg4N2YzYTFkNWZkNjhjYWM5NTQ4YjhkMzI4ZjBjY2JmMjg5YTE1ZTY4MTdhYzA3Yw",
				},
			},
			wantDisclose: []*Disclosure{
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
			name:        "test-3",
			description: "no children, one _sd of two claims",
			run:         true,
			instructions: []*Instruction{
				{
					Name:  "birthdate",
					Value: "1970-01-01",
					SD:    true,
				},
				{
					Name:  "email",
					Value: "test@example.com",
					SD:    false,
				},
			},
			wantSDJWT: jwt.MapClaims{
				"_sd": []any{
					"Zjc4YWM0MzQ5ODJiY2RiZmIyN2RkNDMwZmY5M2Q3N2FhOGYxMzQ2YWQ4ODYyZGVjMTQ4NjQ2YzcxM2E0MDUzZg",
				},
				"email": "test@example.com",
			},
			wantDisclose: []*Disclosure{
				{
					salt:           "salt_zyx",
					value:          "1970-01-01",
					disclosureHash: "WyJzYWx0X3p5eCIsImJpcnRoZGF0ZSIsIjE5NzAtMDEtMDEiXQ",
					name:           "birthdate",
				},
			},
		},
		{
			name:        "test-4",
			description: "one parent one child, one claim, sd all parent",
			run:         true,
			instructions: []*Instruction{
				{
					Name: "address",
					Children: []*Instruction{
						{
							Name:  "street_address",
							Value: "testgatan 3",
						},
					},
					SD: true,
				},
			},
			wantSDJWT: jwt.MapClaims{
				"_sd": []any{
					"NTMxZGRlNGZjODk0NzRmZDA1N2MyY2U4NjdiMDU4NWE4YTU1ZWUyZjQ1MTYwZTE0MDZjNDMzOWRjYWIzMjBiZg",
				},
			},
			wantDisclose: []*Disclosure{
				{
					salt:           "salt_zyx",
					value:          "testgatan 3",
					disclosureHash: "WyJzYWx0X3p5eCIsInN0cmVldF9hZGRyZXNzIiwidGVzdGdhdGFuIDMiXQ",
					name:           "address",
				},
			},
		},
		{
			name:        "test-5",
			description: "two parent one child per, one claim, sd all parent",
			run:         true,
			instructions: []*Instruction{
				{
					Name: "address",
					Children: []*Instruction{
						{
							Name:  "street_address",
							Value: "testgatan 3",
						},
					},
					SD: true,
				},
				{
					Name: "name",
					Children: []*Instruction{
						{
							Name:  "given_name",
							Value: "test",
						},
					},
					SD: true,
				},
			},
			wantSDJWT: jwt.MapClaims{
				"_sd": []any{
					"NTMxZGRlNGZjODk0NzRmZDA1N2MyY2U4NjdiMDU4NWE4YTU1ZWUyZjQ1MTYwZTE0MDZjNDMzOWRjYWIzMjBiZg",
					"MDQzMzc4NGFlNzk0MGJjMTU3ZDIxZmFmODE1NmIwYmJlNGNkMTdjYWVkZTAzNjViYzllM2Q2ODZkZTBhZGZlYQ",
				},
			},
			wantDisclose: []*Disclosure{
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
			name:        "test-6",
			description: "one child, one _sd claim, keep parent visible",
			run:         true,
			instructions: []*Instruction{
				{
					Name: "address",
					Children: []*Instruction{
						{
							Name:  "street_address",
							Value: "testgatan 3",
							SD:    true,
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
			wantDisclose: []*Disclosure{
				{
					salt:           "salt_zyx",
					value:          "testgatan 3",
					disclosureHash: "WyJzYWx0X3p5eCIsInN0cmVldF9hZGRyZXNzIiwidGVzdGdhdGFuIDMiXQ",
					name:           "street_address",
				},
			},
		},
		{
			name:        "test-7",
			description: "one parent two children, individual sd for each claim, keep parent visible",
			run:         true,
			instructions: []*Instruction{
				{
					Name: "address",
					Children: []*Instruction{
						{
							Name:  "street_address",
							Value: "testgatan 3",
							SD:    true,
						},
						{
							Name:  "country",
							Value: "sweden",
							SD:    true,
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
			wantDisclose: []*Disclosure{
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
			name:        "test-8",
			description: "one parent two children, one sd claim, keep parent visible",
			run:         true,
			instructions: []*Instruction{
				{
					Name: "address",
					Children: []*Instruction{
						{
							Name:  "street_address",
							Value: "testgatan 3",
							SD:    true,
						},
						{
							Name:  "country",
							Value: "sweden",
							SD:    false,
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
			wantDisclose: []*Disclosure{
				{
					salt:           "zyx",
					value:          "testgatan 3",
					disclosureHash: "WyJzYWx0X3p5eCIsInN0cmVldF9hZGRyZXNzIiwidGVzdGdhdGFuIDMiXQ",
					name:           "street_address",
				},
			},
		},
		{
			name:        "test-9",
			description: "one parent with two array-like children claims with sd claim for each child, keep parent visible",
			run:         true,
			instructions: []*Instruction{
				{
					Name: "nationalities",
					Children: []*Instruction{
						{
							Value: "se",
							SD:    true,
						},
						{
							Value: "uk",
							SD:    true,
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
			wantDisclose: []*Disclosure{
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
			name:        "test-10",
			description: "one parent with two array-like children claims with one sd claim for one child",
			run:         true,
			instructions: []*Instruction{
				{
					Name: "nationalities",
					Children: []*Instruction{
						{
							Value: "se",
							SD:    true,
						},
						{
							Value: "uk",
							SD:    false,
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
			wantDisclose: []*Disclosure{
				{
					salt:           "salt_zyx",
					value:          "se",
					disclosureHash: "WyJzYWx0X3p5eCIsIiIsInNlIl0",
				},
			},
		},
		{
			name:        "test-11",
			description: "one parent with two array-like children claims with one sd claim for one child, reverse order",
			run:         true,
			instructions: []*Instruction{
				{
					Name: "nationalities",
					Children: []*Instruction{
						{
							Value: "se",
							SD:    false,
						},
						{
							Value: "uk",
							SD:    true,
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
			wantDisclose: []*Disclosure{
				{
					salt:           "salt_zyx",
					value:          "uk",
					disclosureHash: "WyJzYWx0X3p5eCIsIiIsInVrIl0",
				},
			},
		},
		{
			name:        "test-12",
			description: "one sd claim and one non-sd claim",
			run:         true,
			instructions: []*Instruction{
				{
					Name:  "birthdate",
					Value: "1970-01-01",
					SD:    true,
				},
				{
					Name:  "first_name",
					Value: "test",
				},
			},
			wantSDJWT: jwt.MapClaims{
				"_sd": []any{
					"Zjc4YWM0MzQ5ODJiY2RiZmIyN2RkNDMwZmY5M2Q3N2FhOGYxMzQ2YWQ4ODYyZGVjMTQ4NjQ2YzcxM2E0MDUzZg",
				},
				"first_name": "test",
			},
			wantDisclose: []*Disclosure{
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
			err := makeSD("", false, tt.instructions, storage, disclosures)
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
					Name: "address",
					SD:   true,
					Children: []*Instruction{
						{
							Name:  "street",
							Value: "testgatan 3",
							SD:    true,
						},
						{
							Name:  "location",
							Value: "skaraborg",
							SD:    true,
						},
					},
				},
			},
			want: want{
				sdJWT: jwt.MapClaims{
					"_sd": []any{
						"MDI2OTliMDAxYWQwMWYzZWRjZDdiNWZkNzQ1MTc0MWYzMjg3ZGVmZjY2ODEwNmNjOTFjNDIyZjdmNGUxZGRlYg",
					},
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
			newSalt = func() string {
				return "salt_zyx"
			}
			storage := jwt.MapClaims{}
			disclosures := disclosures{}
			err := makeSD("", false, tt.instructions, storage, disclosures)
			assert.NoError(t, err)

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
				"birthdate": &Disclosure{
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
				"birthdate": &Disclosure{
					salt:           "zyx",
					value:          "xyz",
					disclosureHash: "xyz",
				},
				"givename": &Disclosure{
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
		want []*Disclosure
	}{
		{
			name: "one disclosure",
			run:  true,
			have: disclosures{
				"birthdate": &Disclosure{
					salt:           "zyx",
					value:          "xyz",
					disclosureHash: "xyz",
				},
			},
			want: []*Disclosure{
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
				"birthdate": &Disclosure{
					salt:           "zyx",
					value:          "xyz",
					disclosureHash: "xyz",
				},
				"givename": &Disclosure{
					salt:           "zyx",
					value:          "xyz",
					disclosureHash: "xyz",
				},
			},
			want: []*Disclosure{
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
				Salt:  "salt_zyx",
				Value: "xyz",
				Name:  "birthdate",
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
			assert.Equal(t, tt.want.s, tt.have.DisclosureHash)

			gotDecoded, err := base64.RawStdEncoding.DecodeString(tt.have.DisclosureHash)
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
				Salt:           "zyx",
				Value:          "xyz",
				Name:           "birthdate",
				DisclosureHash: "WyJ6eXgiLCJiaXJ0aGRhdGUiLCJ4eXoiXQ==",
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
			fmt.Println("claimHash", tt.have.ClaimHash)
			assert.Equal(t, tt.want, tt.have.ClaimHash)
		})
	}
}

func TestInstructionsAdd(t *testing.T) {
	type have struct {
		a Instructions
		b Instructions
	}
	tts := []struct {
		name string
		have have
		want Instructions
	}{
		{
			name: "test-1",
			have: have{
				a: []*Instruction{
					{
						Name:  "birthdate",
						Value: "1970-01-01",
					},
				},
				b: []*Instruction{
					{
						Name:  "given_name",
						Value: "John",
					},
				},
			},
			want: []*Instruction{
				{
					Name:  "birthdate",
					Value: "1970-01-01",
				},
				{
					Name:  "given_name",
					Value: "John",
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got := CombineInstructionsSets(tt.have.a, tt.have.b)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSDJWT(t *testing.T) {
	type want struct {
		claims      jwt.MapClaims
		disclosures []*Disclosure
	}
	tts := []struct {
		name string
		run  bool
		have Instructions
		want want
	}{
		{
			name: "one sd claim",
			run:  true,
			have: mockCompleteSDJWT,
			want: want{
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
				disclosures: []*Disclosure{
					{
						salt:           "salt_zyx",
						value:          "John",
						name:           "given_name",
						disclosureHash: "WyJzYWx0X3p5eCIsImdpdmVuX25hbWUiLCJKb2huIl0",
					},
					{
						salt:           "salt_zyx",
						value:          "testgatan 3",
						name:           "street_address",
						disclosureHash: "WyJzYWx0X3p5eCIsInN0cmVldF9hZGRyZXNzIiwidGVzdGdhdGFuIDMiXQ",
					},
					{
						salt:           "salt_zyx",
						value:          "1970-01-01",
						name:           "birthdate",
						disclosureHash: "WyJzYWx0X3p5eCIsImJpcnRoZGF0ZSIsIjE5NzAtMDEtMDEiXQ",
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
			newSalt = func() string {
				return "salt_zyx"
			}
			//client, err := New(context.TODO(), Config{})
			gotClaims, disclosures, err := tt.have.sdJWT()
			assert.NoError(t, err)

			assert.Equal(t, tt.want.claims, gotClaims)

			assert.Equal(t, tt.want.disclosures, disclosures.makeArray())

		})
	}
}

func TestJWTStringFormatted(t *testing.T) {
	tts := []struct {
		name string
		run  bool
		have Instructions
		want string
	}{
		{
			name: "one sd claim",
			run:  true,
			have: mockCompleteSDJWT,
			want: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfc2QiOlsiTXpFMFpEVTVOelkwTkdRNFlqUmxaVE0xWWpKallXTXdOR0ZsTm1Nd00ySmlOR0ZtWVRrNU9EUXhNRGhqTXpJek5HUTNaVFkyTm1abU1XSm1Zems0TnciLCJaamM0WVdNME16UTVPREppWTJSaVptSXlOMlJrTkRNd1ptWTVNMlEzTjJGaE9HWXhNelEyWVdRNE9EWXlaR1ZqTVRRNE5qUTJZemN4TTJFME1EVXpaZyJdLCJfc2RfYWxnIjoic2hhLTI1NiIsImFkZHJlc3MiOnsiX3NkIjpbIk5UTXhaR1JsTkdaak9EazBOelJtWkRBMU4yTXlZMlU0TmpkaU1EVTROV0U0WVRVMVpXVXlaalExTVRZd1pURTBNRFpqTkRNek9XUmpZV0l6TWpCaVpnIl0sImNvdW50cnkiOiJzd2VkZW4ifSwic3ViIjoidGVzdC0yIn0.O60CIBHS-AaOOUFgbatYzg9eCLMBvRZ5rDhRuSWjDk8~WyJzYWx0X3p5eCIsImdpdmVuX25hbWUiLCJKb2huIl0~WyJzYWx0X3p5eCIsInN0cmVldF9hZGRyZXNzIiwidGVzdGdhdGFuIDMiXQ~WyJzYWx0X3p5eCIsImJpcnRoZGF0ZSIsIjE5NzAtMDEtMDEiXQ~",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.run {
				t.SkipNow()
			}
			newSalt = func() string {
				return "salt_zyx"
			}
			client, err := New(context.TODO(), Config{})
			got, err := client.SDJWT(tt.have, "mura")
			assert.NoError(t, err)
			fmt.Println("got", got)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDisclosureParse(t *testing.T) {
	tts := []struct {
		name string
		have string
		want *Disclosure
	}{
		{
			name: "test 1",
			have: mockBirthdayDisclosure,
			want: &Disclosure{
				salt:           "salt_zyx",
				name:           "birthdate",
				value:          "1970-01-01",
				disclosureHash: mockBirthdayDisclosure,
				claimHash:      "Zjc4YWM0MzQ5ODJiY2RiZmIyN2RkNDMwZmY5M2Q3N2FhOGYxMzQ2YWQ4ODYyZGVjMTQ4NjQ2YzcxM2E0MDUzZg",
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			disclosure := &Disclosure{}
			err := disclosure.parse(tt.have)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, disclosure)
		})
	}

}

func TestDisclosuresNew(t *testing.T) {
	tts := []struct {
		name string
		have []string
		want disclosures
	}{
		{
			name: "test 1",
			have: []string{
				mockBirthdayDisclosure,
				mockGivenNameDisclosure,
			},
			want: disclosures{
				"Zjc4YWM0MzQ5ODJiY2RiZmIyN2RkNDMwZmY5M2Q3N2FhOGYxMzQ2YWQ4ODYyZGVjMTQ4NjQ2YzcxM2E0MDUzZg": &Disclosure{
					salt:           "salt_zyx",
					name:           "birthdate",
					value:          "1970-01-01",
					disclosureHash: mockBirthdayDisclosure,
					claimHash:      "Zjc4YWM0MzQ5ODJiY2RiZmIyN2RkNDMwZmY5M2Q3N2FhOGYxMzQ2YWQ4ODYyZGVjMTQ4NjQ2YzcxM2E0MDUzZg",
				},
				"MzE0ZDU5NzY0NGQ4YjRlZTM1YjJjYWMwNGFlNmMwM2JiNGFmYTk5ODQxMDhjMzIzNGQ3ZTY2NmZmMWJmYzk4Nw": &Disclosure{
					salt:           "salt_zyx",
					name:           "given_name",
					value:          "John",
					disclosureHash: mockGivenNameDisclosure,
					claimHash:      "MzE0ZDU5NzY0NGQ4YjRlZTM1YjJjYWMwNGFlNmMwM2JiNGFmYTk5ODQxMDhjMzIzNGQ3ZTY2NmZmMWJmYzk4Nw",
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			disclosures := disclosures{}
			err := disclosures.new(tt.have)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, disclosures)
		})
	}
}
