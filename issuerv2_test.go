package gosdjwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func testClaim(t *testing.T, inversSelectiveDisclosureClaim map[string][]any) {
	for claimHash, claim := range inversSelectiveDisclosureClaim {
		var s string

		switch len(claim) {
		case 2:
			s = fmt.Sprintf("[%q,%q]", claim[0], claim[1])
		case 3:
			switch claim[2].(type) {
			case string:
				s = fmt.Sprintf("[%q,%q,%q]", claim[0], claim[1], claim[2])
			case map[string][]any:
				c, err := json.Marshal(claim[2])
				assert.NoError(t, err)
				s = fmt.Sprintf("[%q,%q,%s]", claim[0], claim[1], string(c))
			case map[string]any:
				c, err := json.Marshal(claim[2])
				assert.NoError(t, err)
				s = fmt.Sprintf("[%q,%q,%s]", claim[0], claim[1], string(c))
			case map[string][]string:
				c, err := json.Marshal(claim[2])
				assert.NoError(t, err)
				s = fmt.Sprintf("[%q,%q,%s]", claim[0], claim[1], string(c))

			default:
				t.Fatalf("unknown type %T", claim[2])

			}
		}

		disclosureHash := base64.RawURLEncoding.EncodeToString([]byte(s))

		sha256Hash := hash(disclosureHash)

		assert.Equal(t, claimHash, sha256Hash)

	}
}

func TestMakeSDV2(t *testing.T) {
	type want struct {
		claims                         jwt.MapClaims
		disclosureHashes               []string
		inversSelectiveDisclosureClaim map[string][]any
	}
	tts := []struct {
		name string
		have []any
		want want
	}{
		{
			name: "Test 1 - Children: No Selective Disclosure",
			have: []any{
				&ParentInstructionV2{
					Name: "parent_a",
					Children: []any{
						&ParentInstructionV2{
							Name: "parent_b",
							Children: []any{
								&ChildInstructionV2{
									Name:  "child_a",
									Value: "test",
								},
							},
						},
					},
				},
			},
			want: want{
				claims: jwt.MapClaims{
					"parent_a": jwt.MapClaims{
						"parent_b": jwt.MapClaims{
							"child_a": "test",
						},
					},
				},
				disclosureHashes:               []string{},
				inversSelectiveDisclosureClaim: map[string][]any{},
			},
		},
		{
			name: "Test 2 - Children: Two Selective Disclosure Children to the same parent",
			have: []any{
				&ParentInstructionV2{
					Name: "parent_a",
					Children: []any{
						&ParentInstructionV2{
							Name: "parent_b",
							Children: []any{
								&ChildInstructionV2{
									Name:                "child_a",
									Value:               "test",
									SelectiveDisclosure: true,
								},
								&ChildInstructionV2{
									Name:                "child_b",
									Value:               "test",
									SelectiveDisclosure: true,
								},
							},
						},
					},
				},
			},
			want: want{
				claims: jwt.MapClaims{
					"parent_a": jwt.MapClaims{
						"parent_b": jwt.MapClaims{
							"_sd": []interface{}{
								"MTM1ZTE1NDBlZGIyMzc0NDJhYTIyNDY3ZmRlMzhlMDUyYTA5NTY4ZjVhMTI0MTVlMjc3MTIxMTU1ZjE1NDlhMg",
								"YjBkOGM1ZjJiYjdjMjNiNGI2MDVmZTc2NDMwMDdkNDI0MjFlNmE3NTc4ZGMxZGU1NzA0ODY0NDk2ODUzYzE2OQ",
							},
						},
					},
				},
				disclosureHashes: []string{"WyJzYWx0X3p5eCIsImNoaWxkX2EiLCJ0ZXN0Il0", "WyJzYWx0X3p5eCIsImNoaWxkX2IiLCJ0ZXN0Il0"},
				inversSelectiveDisclosureClaim: map[string][]any{
					"MTM1ZTE1NDBlZGIyMzc0NDJhYTIyNDY3ZmRlMzhlMDUyYTA5NTY4ZjVhMTI0MTVlMjc3MTIxMTU1ZjE1NDlhMg": {
						"salt_zyx", "child_a", "test",
					},
					"YjBkOGM1ZjJiYjdjMjNiNGI2MDVmZTc2NDMwMDdkNDI0MjFlNmE3NTc4ZGMxZGU1NzA0ODY0NDk2ODUzYzE2OQ": {
						"salt_zyx", "child_b", "test",
					},
				},
			},
		},
		{
			name: "Test 3 - ChildrenArray: Two non Selective Disclosure children to the same parent",
			have: []any{
				&ParentInstructionV2{
					Name: "parent_a",
					Children: []any{
						&ChildArrayInstructionV2{
							Name: "parent_b",
							Children: []ChildInstructionV2{
								{
									Value: "test1",
								},
								{
									Value: "test2",
								},
							},
						},
					},
				},
			},
			want: want{
				claims: jwt.MapClaims{
					"parent_a": jwt.MapClaims{
						"parent_b": []interface{}{
							"test1",
							"test2",
						},
					},
				},
				disclosureHashes:               []string{},
				inversSelectiveDisclosureClaim: map[string][]any{},
			},
		},
		{
			name: "Test 4 - ChildrenArray: Two Children to the same parent, one Selective Disclosure.",
			have: []any{
				&ParentInstructionV2{
					Name: "parent_a",
					Children: []any{
						&ChildArrayInstructionV2{
							Name: "parent_b",
							Children: []ChildInstructionV2{
								{
									Value: "test1",
								},
								{
									Value:               "test2",
									SelectiveDisclosure: true,
								},
							},
						},
					},
				},
			},
			want: want{
				claims: jwt.MapClaims{
					"parent_a": jwt.MapClaims{
						"parent_b": []interface{}{
							"test1",
							map[string]string{"...": "NTc0MGFhYzIxZTc2YTkzNDJiNWQ0NzIxMDYyZTdhNTlkYTQ3MzUyOWQ4NTYxNzc1YjRiMjMzNmQ5OGQ1NmFmNQ"},
						},
					},
				},
				disclosureHashes: []string{"WyJzYWx0X3p5eCIsIiIsInRlc3QyIl0"},
				inversSelectiveDisclosureClaim: map[string][]any{
					"NTc0MGFhYzIxZTc2YTkzNDJiNWQ0NzIxMDYyZTdhNTlkYTQ3MzUyOWQ4NTYxNzc1YjRiMjMzNmQ5OGQ1NmFmNQ": {
						"salt_zyx", "", "test2",
					},
				},
			},
		},
		{
			name: "Test 5 - Parent Selective Disclosure with one child that's not Selective Disclosure",
			have: []any{
				&ParentInstructionV2{
					Name:                "parent_a",
					SelectiveDisclosure: true,
					Children: []any{
						&ChildInstructionV2{
							Name:  "child_a",
							Value: "test",
						},
					},
				},
			},
			want: want{
				claims:           jwt.MapClaims{"_sd": []any{"ODk5MDE2NjM4OWFmYmJhMDFjYWQwZjBhYjlhYzg4ODM5NTY5ZDk4MzU2NWI5NWJjNmI3Zjc0MzAwZTU3MThiNQ"}},
				disclosureHashes: []string{"WyJzYWx0X3p5eCIsInBhcmVudF9hIix7ImNoaWxkX2EiOiJ0ZXN0In1d"},
				inversSelectiveDisclosureClaim: map[string][]any{
					"ODk5MDE2NjM4OWFmYmJhMDFjYWQwZjBhYjlhYzg4ODM5NTY5ZDk4MzU2NWI5NWJjNmI3Zjc0MzAwZTU3MThiNQ": {
						"salt_zyx", "parent_a", map[string]any{
							"child_a": "test",
						},
					},
				},
			},
		},
		{
			name: "Test 6 - Two parents, one with Selective Disclosure with one child that's not Selective Disclosure, and one without Selective Disclosure",
			have: []any{
				&ParentInstructionV2{
					Name: "parent_a",
					Children: []any{
						&ChildInstructionV2{
							Name:  "child_a",
							Value: "test",
						},
					},
				},
				&ParentInstructionV2{
					Name:                "parent_b",
					SelectiveDisclosure: true,
					Children: []any{
						&ChildInstructionV2{
							Name:  "child_b",
							Value: "test",
						},
					},
				},
			},
			want: want{
				claims: jwt.MapClaims{
					"_sd": []any{"ODJiZGJhNmQ3MWRlNGY3NzlkYmMzYTNlMjU1YjAwNDAwZjJjM2I5NTVlNGQ3ZDQ5MTU4ZDZhMTNjMzcwOGU0NA"},
					"parent_a": jwt.MapClaims{
						"child_a": "test",
					},
				},
				disclosureHashes: []string{"WyJzYWx0X3p5eCIsInBhcmVudF9iIix7ImNoaWxkX2IiOiJ0ZXN0In1d"},
				inversSelectiveDisclosureClaim: map[string][]any{
					"ODJiZGJhNmQ3MWRlNGY3NzlkYmMzYTNlMjU1YjAwNDAwZjJjM2I5NTVlNGQ3ZDQ5MTU4ZDZhMTNjMzcwOGU0NA": {
						"salt_zyx", "parent_b", map[string]any{
							"child_b": "test",
						},
					},
				},
			},
		},
		{
			name: "Test 7 - Recursive Selective Disclosure",
			have: []any{
				&RecursiveInstructionV2{
					Name: "parent_a",
					Children: []any{
						&ChildInstructionV2{
							Name:  "child_a",
							Value: "test_a",
						},
						&ChildInstructionV2{
							Name:  "child_b",
							Value: "test_b",
						},
					},
				},
			},
			want: want{
				claims: jwt.MapClaims{
					"_sd": []any{"NWM1NDg0MGFjNWFlMjY3MTc4MjAwYjMzMTM4OTViMzI1ZWMwOTI3MTJmMDRjMDRhMmU0ODBjMDhmOGJjNTBlNw"},
				},
				disclosureHashes: []string{"WyJzYWx0X3p5eCIsImNoaWxkX2EiLCJ0ZXN0X2EiXQ", "WyJzYWx0X3p5eCIsImNoaWxkX2IiLCJ0ZXN0X2IiXQ", "WyJzYWx0X3p5eCIsInBhcmVudF9hIix7Il9zZCI6WyJOR05sTURabE5qazFZakU0TmpWaE1qVmpaVFZoTXpsbU5EVXhaRGsxTnpBMlpqbGpaall4TVRrMVlqSmxOREU1TjJRek1qWmpZamMyTmprd1kyWmpNdyIsIk1tRTNaVGhoTTJZMVl6QmlORFU0TWpnNVpHUmxZV0U1WVRRM1lUTTROelV5TVRGaFl6TTFaVE0wTm1VNE1qQTBORFV3TXpVeE5UaGxOakpsTjJRMVpBIl19XQ"},
				inversSelectiveDisclosureClaim: map[string][]any{
					"NWM1NDg0MGFjNWFlMjY3MTc4MjAwYjMzMTM4OTViMzI1ZWMwOTI3MTJmMDRjMDRhMmU0ODBjMDhmOGJjNTBlNw": {
						"salt_zyx", "parent_a", map[string][]any{
							"_sd": {"NGNlMDZlNjk1YjE4NjVhMjVjZTVhMzlmNDUxZDk1NzA2ZjljZjYxMTk1YjJlNDE5N2QzMjZjYjc2NjkwY2ZjMw", "MmE3ZThhM2Y1YzBiNDU4Mjg5ZGRlYWE5YTQ3YTM4NzUyMTFhYzM1ZTM0NmU4MjA0NDUwMzUxNThlNjJlN2Q1ZA"},
						},
					},
				},
			},
		},
		{
			name: "Test 8 - Recursive: Two recursive parents with one or two children",
			have: []any{
				&RecursiveInstructionV2{
					Name: "parent_a",
					Children: []any{
						&ChildInstructionV2{
							Name:  "child_aa",
							Value: "test_aa",
						},
						&ChildInstructionV2{
							Name:  "child_ab",
							Value: "test_ab",
						},
					},
				},
				&RecursiveInstructionV2{
					Name: "parent_b",
					Children: []any{
						&ChildInstructionV2{
							Name:  "child_ba",
							Value: "test_ba",
						},
						&ChildInstructionV2{
							Name:  "child_bb",
							Value: "test_bb",
						},
					},
				},
			},
			want: want{
				claims: jwt.MapClaims{
					"_sd": []any{"Mzk3OWYxYTZmNWZhYzhiZjJkNWE1MjQ5NDEwYzZlZjNiNDRmY2IxNGQxYjQ1ZjM3Y2ExNjM2YzcyYjcyNjRjYw", "OWZlZWZiZGI3NGYwODJmNjJjNWYwZjQ0OGE5MTAyNzBkNTQ1MjU0OTE2MWVlNGNmODc1MzZlNTI5NDM3YTU4OA"},
				},
				disclosureHashes: []string{
					"WyJzYWx0X3p5eCIsImNoaWxkX2FhIiwidGVzdF9hYSJd",
					"WyJzYWx0X3p5eCIsImNoaWxkX2FiIiwidGVzdF9hYiJd",
					"WyJzYWx0X3p5eCIsImNoaWxkX2JhIiwidGVzdF9iYSJd",
					"WyJzYWx0X3p5eCIsImNoaWxkX2JiIiwidGVzdF9iYiJd",
					"WyJzYWx0X3p5eCIsInBhcmVudF9hIix7Il9zZCI6WyJZamt6TVRNM01HRmxNRGN6WXpOaFkySmxNR1ptTm1KaE5USm1PV1ZrTUdGaU1HVmtPV0pqT0RNeFpUQTFPVGRoTTJVeU16WTNabU0zT0RWaVpETmlaQSIsIllUTTNaR1U0WkRjeFl6WTVPVEU1TjJJeVpURmpOMlkwWWpOaU5XRTROR0ZrTkRFMVpXSTBZelV5WlRaaU1UTXdZVEV3WmpWak1EazJOemMzTVdZMU5nIl19XQ",
					"WyJzYWx0X3p5eCIsInBhcmVudF9iIix7Il9zZCI6WyJaamsxWm1JelpUWTNaREV6TTJGak16STBNV1ZsTlRFM01qZzJNV1kzTlRSall6ZzVaVE14WkRBM1pUZ3lOelk0TnpOak5HUTBPVGcxTnpBd09EZzVNQSIsIk5XVXhOelU1WkdVd01tSTVZMlEzTlRnME4yVmhOekEzTWpBNU5UZzVZbU5tT1RGbFkyTXhNV00yWWpBNU5qVmpNMkpoTURGaU9EZGhaREV4T0Rnek1RIl19XQ",
				},
				inversSelectiveDisclosureClaim: map[string][]any{
					"Mzk3OWYxYTZmNWZhYzhiZjJkNWE1MjQ5NDEwYzZlZjNiNDRmY2IxNGQxYjQ1ZjM3Y2ExNjM2YzcyYjcyNjRjYw": {
						"salt_zyx", "parent_a", map[string][]string{
							"_sd": {"YjkzMTM3MGFlMDczYzNhY2JlMGZmNmJhNTJmOWVkMGFiMGVkOWJjODMxZTA1OTdhM2UyMzY3ZmM3ODViZDNiZA", "YTM3ZGU4ZDcxYzY5OTE5N2IyZTFjN2Y0YjNiNWE4NGFkNDE1ZWI0YzUyZTZiMTMwYTEwZjVjMDk2Nzc3MWY1Ng"},
						},
					},
					"OWZlZWZiZGI3NGYwODJmNjJjNWYwZjQ0OGE5MTAyNzBkNTQ1MjU0OTE2MWVlNGNmODc1MzZlNTI5NDM3YTU4OA": {
						"salt_zyx", "parent_b", map[string][]any{
							"_sd": {"Zjk1ZmIzZTY3ZDEzM2FjMzI0MWVlNTE3Mjg2MWY3NTRjYzg5ZTMxZDA3ZTgyNzY4NzNjNGQ0OTg1NzAwODg5MA", "NWUxNzU5ZGUwMmI5Y2Q3NTg0N2VhNzA3MjA5NTg5YmNmOTFlY2MxMWM2YjA5NjVjM2JhMDFiODdhZDExODgzMQ"},
						},
					},
				},
			},
		},
		{
			name: "Test 9 - Recursive: Nested recursive parents",
			have: []any{
				&RecursiveInstructionV2{
					Name: "parent_a",
					Children: []any{
						&RecursiveInstructionV2{
							Name: "parent_b",
							Children: []any{
								&ChildInstructionV2{
									Name:  "child_b1",
									Value: "test_b1",
								},
								&ChildInstructionV2{
									Name:  "child_b2",
									Value: "test_b2",
								},
							},
						},
					},
				},
			},
			want: want{
				claims: map[string]any{
					"_sd": []any{"ZTM2OWYwMzg2NTI1MzlhZjhjNjIxNmUwMDQzYTA0OGVkMWVlMTM4MGQzNmI3MGExYWU2MDRlZGYxODk2YmQ0OA"},
				},
				disclosureHashes: []string{
					"WyJzYWx0X3p5eCIsImNoaWxkX2IxIiwidGVzdF9iMSJd",
					"WyJzYWx0X3p5eCIsImNoaWxkX2IyIiwidGVzdF9iMiJd",
					"WyJzYWx0X3p5eCIsInBhcmVudF9hIix7Il9zZCI6WyJNV1l6T0RFMlpERXpPV00yWldZM1lXTTBaR0V4TnpOaU5tWTJaVEkwTTJObE5UUTRPVGhrWkdJNE9ESTJORFZoWmprM05qWTRNR1JsTldJME1UQm1NUSJdfV0",
					"WyJzYWx0X3p5eCIsInBhcmVudF9iIix7Il9zZCI6WyJNV1EyWXpKa01HRTRZV0psTjJWak4yVmpNbU00TXpBMFpXUmpPV1kyWkRFMVl6UTFPV1V5TURNMFpEVmxObVppWm1WbVpXVmxZV001Wm1FMFlUZzNOQSIsIk56ZzBaR0UzTmpOa09EQTVaV1ptTUdNeE1tUTVOV000TkRNMU1EUTRNMk5qT0RsaVlXUm1aRE0yWmpoa1l6WmpPVFUyT0RFek1HVmlNVE01WTJJelpRIl19XQ",
				},
				inversSelectiveDisclosureClaim: map[string][]any{
					"ZTM2OWYwMzg2NTI1MzlhZjhjNjIxNmUwMDQzYTA0OGVkMWVlMTM4MGQzNmI3MGExYWU2MDRlZGYxODk2YmQ0OA": {
						"salt_zyx", "parent_a", map[string][]any{
							"_sd": {
								"MWYzODE2ZDEzOWM2ZWY3YWM0ZGExNzNiNmY2ZTI0M2NlNTQ4OThkZGI4ODI2NDVhZjk3NjY4MGRlNWI0MTBmMQ",
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			newSalt = func() string {
				return "salt_zyx"
			}
			storage := jwt.MapClaims{}
			disclosures := DisclosuresV2{}
			makeSDV2(tt.have, storage, disclosures)

			//s, err := json.Marshal(storage)
			//assert.NoError(t, err)
			//fmt.Println("storage", string(s))
			testClaim(t, tt.want.inversSelectiveDisclosureClaim)

			assert.Equal(t, tt.want.claims, storage)

			assert.Equal(t, tt.want.disclosureHashes, disclosures.ArrayHashes())

		})
	}
}

func TestRecursiveClaimHandler(t *testing.T) {
	tts := []struct {
		name string
		have []any
		want string
	}{
		{
			name: "Test 2",
			have: []any{
				&RecursiveInstructionV2{
					Name: "parent_a",
					Children: []any{
						&RecursiveInstructionV2{
							Name: "parent_b",
							Children: []any{
								&ChildInstructionV2{
									Name:  "child_a",
									Value: "test_a",
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			newSalt = func() string {
				return "salt_zyx"
			}
			disclosures := DisclosuresV2{}
			recursiveClaimHandler(tt.have, tt.have[0], disclosures)

			parent := tt.have[0].(*RecursiveInstructionV2)
			fmt.Printf("first parent, name: %s\n", parent.Name)
			fmt.Printf("first parent, childrenClaimHash: %v\n", parent.ChildrenClaimHash)
			fmt.Printf("first parent, claimHash: %s\n", parent.ClaimHash)
			fmt.Printf("first parent, disclosureHash: %s\n", parent.DisclosureHash)
			disclosureDecoded, err := decodeDisclosureHash(parent.DisclosureHash)
			assert.NoError(t, err)
			fmt.Printf("first parent, disclosure decoded: %s\n", disclosureDecoded)

			firstChild := tt.have[0].(*RecursiveInstructionV2).Children[0].(*RecursiveInstructionV2)
			fmt.Printf("first child, name: %s\n", firstChild.Name)
			fmt.Printf("first child, childrenClaimHash: %v\n", firstChild.ChildrenClaimHash)
			fmt.Printf("first child, claimHash: %s\n", firstChild.ClaimHash)
			fmt.Printf("first child, disclosureHash: %s\n", firstChild.DisclosureHash)
			disclosureDecoded, err = decodeDisclosureHash(firstChild.DisclosureHash)
			assert.NoError(t, err)
			fmt.Printf("first child, disclosure decoded: %s\n", disclosureDecoded)

			secondChild := tt.have[0].(*RecursiveInstructionV2).Children[0].(*RecursiveInstructionV2).Children[0].(*ChildInstructionV2)
			fmt.Printf("second child, name: %s\n", secondChild.Name)
			fmt.Printf("second child, claimHash: %s\n", secondChild.ClaimHash)
			fmt.Printf("second child, disclosureHash: %s\n", secondChild.DisclosureHash)
			disclosureDecoded, err = decodeDisclosureHash(secondChild.DisclosureHash)
			assert.NoError(t, err)
			fmt.Printf("second child, disclosure decoded: %s\n", disclosureDecoded)

		})
	}
}
