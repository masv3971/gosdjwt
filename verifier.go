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

func splitSDJWT(sdjwt string) StandardPresentation {
	split := strings.Split(sdjwt, "~")
	presentation := StandardPresentation{}
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

func parseJWTAndValidate(sdjwt, key string) (jwt.MapClaims, *Validation, error) {
	c := jwt.MapClaims{}
	validation := &Validation{
		SignaturePolicy: SignaturePolicyPassed, // TODO(masv): Fix this
	}

	token, err := jwt.ParseWithClaims(sdjwt, c, func(token *jwt.Token) (interface{}, error) {
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

func run(claims jwt.MapClaims, s []string) jwt.MapClaims {
	disclosures := disclosures{}
	disclosures.new(s)

	addClaims(claims, disclosures, "")

	removeSDClaims(claims)
	return claims
}

func removeSDClaims(claims jwt.MapClaims) {
	for claimKey, claimValue := range claims {
		switch claimKey {
		case "_sd_alg", "_sd":
			delete(claims, claimKey)
		}

		switch claimValue.(type) {
		case jwt.MapClaims:
			removeSDClaims(claimValue.(jwt.MapClaims))
		case map[string]any:
			removeSDClaims(claimValue.(map[string]any))
		}
	}
	fmt.Println("claims", claims)
}

func addClaims(claims jwt.MapClaims, disclosures disclosures, parentName string) (jwt.MapClaims, error) {
	for claimKey, claimValue := range claims {

		switch claimValue.(type) {
		case jwt.MapClaims:
			addClaims(claimValue.(jwt.MapClaims), disclosures, claimKey)

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

	j := run(claims, sd.Disclosures)

	return j, validation, nil
}
