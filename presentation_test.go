package gosdjwt

//func TestPresentationFlat(t *testing.T) {
//	tts := []struct {
//		name string
//		have SDJWT
//		want string
//	}{
//		{
//			name: "test 0 - no disclosures, no key binding",
//			have: SDJWT{
//				JWT:         "xx.xxx.xxx",
//				Disclosures: nil,
//				KeyBinding:  "",
//			},
//			want: "xx.xxx.xxx",
//		},
//		{
//			name: "test 1",
//			have: SDJWT{
//				JWT: "xx.xxx.xxx",
//				Disclosures: Disclosures{
//					"foo": &Disclosure{disclosureHash: "d1"},
//				},
//				KeyBinding: "",
//			},
//			want: "xx.xxx.xxx~d1~",
//		},
//		{
//			name: "test 2",
//			have: SDJWT{
//				JWT: "xx.xxx.xxx",
//				Disclosures: Disclosures{
//					"foo": &Disclosure{disclosureHash: "d1"},
//					"bar": &Disclosure{disclosureHash: "d2"},
//				},
//				KeyBinding: "",
//			},
//			want: "xx.xxx.xxx~d1~d2~",
//		},
//		{
//			name: "test 3",
//			have: SDJWT{
//				JWT: "xx.xxx.xxx",
//				Disclosures: Disclosures{
//					"foo": &Disclosure{disclosureHash: "d1"},
//				},
//				KeyBinding: "kb",
//			},
//			want: "xx.xxx.xxx~d1~kb",
//		},
//		{
//			name: "test 4",
//			have: SDJWT{
//				JWT:         "xx.xxx.xxx",
//				Disclosures: nil,
//				KeyBinding:  "kb",
//			},
//			want: "xx.xxx.xxxkb",
//		},
//	}
//
//	for _, tt := range tts {
//		t.Run(tt.name, func(t *testing.T) {
//			got := tt.have.PresentationFlat().String()
//			assert.Equal(t, tt.want, got)
//		})
//	}
//}
//
//func TestPresentationEnvelope(t *testing.T) {
//	type have struct {
//		sdjwt      *SDJWT
//		iat        int64
//		aud, nonce string
//	}
//	tts := []struct {
//		name string
//		have have
//		want string
//	}{
//		{
//			name: "test 0 - no disclosures, no key binding",
//			have: have{
//				sdjwt: &SDJWT{
//					JWT:         "xx.xxx.xxx",
//					Disclosures: nil,
//					KeyBinding:  "",
//				},
//			},
//			want: "{\n  \"aud\": \"\",\n  \"iat\": 0,\n  \"nonce\": \"\",\n  \"_sd_jwt\": \"xx.xxx.xxx\"\n}",
//		},
//		{
//			name: "test 1",
//			have: have{
//				sdjwt: &SDJWT{
//					JWT: "xx.xxx.xxx",
//					Disclosures: Disclosures{
//						"foo": &Disclosure{disclosureHash: "d1"},
//					},
//					KeyBinding: "",
//				},
//				aud:   "test_aud",
//				nonce: "test_nonce",
//				iat:   123,
//			},
//			want: "{\n  \"aud\": \"test_aud\",\n  \"iat\": 123,\n  \"nonce\": \"test_nonce\",\n  \"_sd_jwt\": \"xx.xxx.xxx~d1~\"\n}",
//		},
//		{
//			name: "test 2",
//			have: have{
//				sdjwt: &SDJWT{
//					JWT: "xx.xxx.xxx",
//					Disclosures: Disclosures{
//						"foo": &Disclosure{disclosureHash: "d1"},
//						"bar": &Disclosure{disclosureHash: "d2"},
//					},
//					KeyBinding: "",
//				},
//				aud:   "test_aud",
//				nonce: "test_nonce",
//				iat:   123,
//			},
//			want: "{\n  \"aud\": \"test_aud\",\n  \"iat\": 123,\n  \"nonce\": \"test_nonce\",\n  \"_sd_jwt\": \"xx.xxx.xxx~d1~d2~\"\n}",
//		},
//		{
//			name: "test 3",
//			have: have{
//				sdjwt: &SDJWT{
//					JWT: "xx.xxx.xxx",
//					Disclosures: Disclosures{
//						"foo": &Disclosure{disclosureHash: "d1"},
//					},
//					KeyBinding: "kb",
//				},
//				aud:   "test_aud",
//				nonce: "test_nonce",
//				iat:   123,
//			},
//			want: "{\n  \"aud\": \"test_aud\",\n  \"iat\": 123,\n  \"nonce\": \"test_nonce\",\n  \"_sd_jwt\": \"xx.xxx.xxx~d1~kb\"\n}",
//		},
//		{
//			name: "test 4",
//			have: have{
//				sdjwt: &SDJWT{
//					JWT:         "xx.xxx.xxx",
//					Disclosures: nil,
//					KeyBinding:  "kb",
//				},
//				aud:   "test_aud",
//				nonce: "test_nonce",
//				iat:   123,
//			},
//			want: "{\n  \"aud\": \"test_aud\",\n  \"iat\": 123,\n  \"nonce\": \"test_nonce\",\n  \"_sd_jwt\": \"xx.xxx.xxxkb\"\n}",
//		},
//	}
//
//	for _, tt := range tts {
//		t.Run(tt.name, func(t *testing.T) {
//			got, err := tt.have.sdjwt.PresentationEnvelope(tt.have.aud, tt.have.nonce, tt.have.iat).String()
//			assert.NoError(t, err)
//			assert.Equal(t, tt.want, got)
//			if diff := cmp.Diff(tt.want, got); diff != "" {
//				t.Errorf("mismatch (-want +got):\n%s", diff)
//			}
//		})
//	}
//}
//
