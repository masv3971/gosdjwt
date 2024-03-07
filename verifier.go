package gosdjwt

import (
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// SignaturePolicyPassed means that the signature policy passed
	SignaturePolicyPassed = "passed"
	// SignaturePolicyFailed means that the signature policy failed
	SignaturePolicyFailed = "failed"
)

func splitSDJWT(sdjwt string) PresentationFlat {
	split := strings.Split(sdjwt, "~")
	presentation := PresentationFlat{}
	if len(split) >= 1 {
		presentation.JWT = split[0]
	}
	if len(split) >= 2 {
		presentation.Disclosures = split[1 : len(split)-1]
		if split[len(split)-1] != "" {
			presentation.KeyBinding = split[len(split)-1]
		}
	}

	return presentation
}

func parseToken(token string) (string, []byte, error) {
	parts := strings.Split(token, ".")

	signatureString := strings.Join(parts[0:2], ".")
	sig, err := jwt.NewParser().DecodeSegment(parts[2])
	if err != nil {
		return "", nil, err
	}

	return signatureString, sig, nil
}

// VerifySignature verifies the signature of a token
func VerifySignature(token, signingAlg string, pubKey any) error {
	signingString, sig, err := parseToken(token)
	if err != nil {
		return err
	}

	jwtToken, _ := jwt.Parse(token, nil)
	return jwtToken.Method.Verify(signingString, sig, pubKey)
}

func parseJWTAndValidate(sdjwt, key string) (jwt.MapClaims, *Validation, error) {
	c := jwt.MapClaims{}
	validation := &Validation{
		SignaturePolicy: SignaturePolicyPassed, // TODO(masv): Fix this
	}

	token, err := jwt.ParseWithClaims(sdjwt, c, func(token *jwt.Token) (any, error) {
		return []byte(key), nil
	})
	if err != nil {
		return nil, validation, err
	}

	if token.Valid {
		validation.Verify = true
		return c, validation, nil
	}

	return nil, validation, ErrTokenNotValid
}

// TODO(masv): whats the point of this?
func run(claims jwt.MapClaims, s []string) (jwt.MapClaims, error) {
	disclosures := DisclosuresV2{}
	if err := disclosures.new(s); err != nil {
		return nil, err

	}

	_, err := addClaims(claims, disclosures, "")
	if err != nil {
		return nil, err
	}

	removeSDClaims(claims)
	return claims, nil
}

func removeSDClaims(claims jwt.MapClaims) {
	for claimKey, claimValue := range claims {
		switch claimKey {
		case "_sd_alg", "_sd":
			delete(claims, claimKey)
		}

		switch claimV := claimValue.(type) {
		case jwt.MapClaims:
			removeSDClaims(claimV)
		case map[string]any:
			removeSDClaims(claimV)
		}
	}
	fmt.Println("claims", claims)
}

func addClaims(claims jwt.MapClaims, disclosures DisclosuresV2, parentName string) (jwt.MapClaims, error) {
	for claimKey, claimValue := range claims {

		switch claimV := claimValue.(type) {
		case jwt.MapClaims:
			_, err := addClaims(claimV, disclosures, claimKey)
			if err != nil {
				return nil, err
			}

		case []any:
			fmt.Println("digg deeper in array")
			fmt.Println("claimKey", claimKey, "claimValue", claimValue)
			for i, v := range claimValue.([]any) {
				disco, ok := disclosures.get(v.(string))
				if !ok {
					fmt.Println("delete", claimKey, "index", i, "value", v)
					claims[claimKey].([]any)[i] = claims[claimKey].([]any)[len(claims[claimKey].([]any))-1]
				} else {
					if parentName == "" {
						fmt.Println("we are at the root level")
						claims[disco.name] = disco.value
					}
					fmt.Println("disco", disco)
					fmt.Println("xxxxx disclosure found", claimKey)
				}
			}
		}
	}
	return claims, nil
}

// Validation contains the result of the validation
type Validation struct {
	Verify          bool
	SignaturePolicy string
}

// Verify verifies the SDJWT and returns the claims and the validation
func Verify(sdjwt, key string) (jwt.MapClaims, *Validation, error) {
	sd := splitSDJWT(sdjwt)

	claims, validation, err := parseJWTAndValidate(sd.JWT, key)
	if err != nil {
		return nil, nil, err
	}

	j, err := run(claims, sd.Disclosures)
	if err != nil {
		return nil, nil, err
	}

	return j, validation, nil
}
