package gosdjwt

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestMakeSDV2(t *testing.T) {
	type want struct {
		claims           jwt.MapClaims
		disclosureHashes []string
	}
	tts := []struct {
		name string
		have []any
		want want
	}{
		{
			name: "Test 1 - Children: No Selective Disclosure",
			have: []any{
				ParentV2{
					Name: "parent_a",
					Children: []any{
						ParentV2{
							Name: "parent_b",
							Children: []any{
								ChildV2{
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
				disclosureHashes: []string{},
			},
		},
		{
			name: "Test 2 - Children: Two Selective Disclosure Children to the same parent",
			have: []any{
				ParentV2{
					Name: "parent_a",
					Children: []any{
						ParentV2{
							Name: "parent_b",
							Children: []any{
								ChildV2{
									Name:                "child_a",
									Value:               "test",
									SelectiveDisclosure: true,
								},
								ChildV2{
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
			},
		},
		{
			name: "Test 3 - ChildrenArray: Two non Selective Disclosure children to the same parent",
			have: []any{
				ParentV2{
					Name: "parent_a",
					Children: []any{
						ChildArrayV2{
							Name: "parent_b",
							Children: []ChildV2{
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
				disclosureHashes: []string{},
			},
		},
		{
			name: "Test 4 - ChildrenArray: Two Children to the same parent, one Selective Disclosure.",
			have: []any{
				ParentV2{
					Name: "parent_a",
					Children: []any{
						ChildArrayV2{
							Name: "parent_b",
							Children: []ChildV2{
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
			},
		},
		{
			name: "Test 5 - Parent Selective Disclosure with one child that's not Selective Disclosure",
			have: []any{
				ParentV2{
					Name:                "parent_a",
					SelectiveDisclosure: true,
					Children: []any{
						ChildV2{
							Name:  "child_a",
							Value: "test",
						},
					},
				},
			},
			want: want{
				claims:           jwt.MapClaims{"_sd": []any{"MzM3NjZkMjBlN2RlZmY2Y2ZlMDczYTM2ODA0ZjM5OWYxMjljNDNmMTcwZDM1OTk0MWY0YjNkNTc0NTc4N2RhOA"}},
				disclosureHashes: []string{"WyJzYWx0X3p5eCIsInBhcmVudF9hIixbeyJjaGlsZF9hIiAlIXEoYm9vbD1mYWxzZSkgIiIgInRlc3QiICIiICIifV1d"},
			},
		},
		{
			name: "Test 6 - Two parents, one with Selective Disclosure with one child that's not Selective Disclosure, and one without Selective Disclosure",
			have: []any{
				ParentV2{
					Name: "parent_a",
					Children: []any{
						ChildV2{
							Name:  "child_a",
							Value: "test",
						},
					},
				},
				ParentV2{
					Name:                "parent_b",
					SelectiveDisclosure: true,
					Children: []any{
						ChildV2{
							Name:  "child_b",
							Value: "test",
						},
					},
				},
			},
			want: want{
				claims: jwt.MapClaims{
					"_sd": []any{"Njg0OWMxNDE4MWQ3NzVmOTZhNTc5NzU3NmZiNmRlNDc2YWU4MGU1MGM1MzhmYmI2ZmFlOTVhZjc3NjliNGJiYg"},
					"parent_a": jwt.MapClaims{
						"child_a": "test",
					},
				},
				disclosureHashes: []string{"WyJzYWx0X3p5eCIsInBhcmVudF9iIixbeyJjaGlsZF9iIiAlIXEoYm9vbD1mYWxzZSkgIiIgInRlc3QiICIiICIifV1d"},
			},
		},
		{
			name: "Test 7 - Recursive Selective Disclosure",
			have: []any{
				&RecursiveInstructionV2{
					Name: "parent_a",
					Children: []any{
						ChildV2{
							Name:  "child_a",
							Value: "test_a",
						},
						ChildV2{
							Name:  "child_b",
							Value: "test_b",
						},
					},
				},
			},
			want: want{
				claims: jwt.MapClaims{
					"_sd": []any{"NjMyMzg1ZTYyMjA4MTJhMjRiZDc5NDc1ZDM3YjRmMTdjYjVkODQ4OWI0NjNjODA3YjgzMGY3MTBkNWNmMWJjOQ"},
				},
				disclosureHashes: []string{"WyJzYWx0X3p5eCIsImNoaWxkX2EiLCJ0ZXN0X2EiXQ", "WyJzYWx0X3p5eCIsImNoaWxkX2IiLCJ0ZXN0X2IiXQ"},
			},
		},
		{
			name: "Test 8 - Recursive: Two recursive parents with one or two children",
			have: []any{
				&RecursiveInstructionV2{
					Name: "parent_a",
					Children: []any{
						ChildV2{
							Name:  "child_aa",
							Value: "test_aa",
						},
						ChildV2{
							Name:  "child_ab",
							Value: "test_ab",
						},
					},
				},
				&RecursiveInstructionV2{
					Name: "parent_b",
					Children: []any{
						ChildV2{
							Name:  "child_ba",
							Value: "test_ba",
						},
						ChildV2{
							Name:  "child_bb",
							Value: "test_bb",
						},
					},
				},
			},
			want: want{
				claims: jwt.MapClaims{
					"_sd": []any{"NmU2ZDQwM2ZjZGVjOTdmMzAyYzQzZWFmMDQzNWQ4N2I0YjM3YTg3OWVmZTdiMDA2ZGM5NzBkM2U0ZTQ2ZWVjNQ", "ZDUxZTdjZmYwMjJjYzE2OGYxNDk2NTA1YTNiZWQ5MDNmZGY1N2M5ZThkZjYwODQwMDAyYTMzMzk4NDg3ODVmZg"},
				},
				disclosureHashes: []string{"WyJzYWx0X3p5eCIsImNoaWxkX2FhIiwidGVzdF9hYSJd", "WyJzYWx0X3p5eCIsImNoaWxkX2FiIiwidGVzdF9hYiJd", "WyJzYWx0X3p5eCIsImNoaWxkX2JhIiwidGVzdF9iYSJd", "WyJzYWx0X3p5eCIsImNoaWxkX2JiIiwidGVzdF9iYiJd"},
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

			s, err := json.Marshal(storage)
			assert.NoError(t, err)
			fmt.Println("storage", string(s))

			assert.Equal(t, tt.want.claims, storage)

			assert.Equal(t, tt.want.disclosureHashes, disclosures.ArrayHashes())

		})
	}
}
