package gosdjwt

import (
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
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

func parseJWTAndValidate(sdjwt, key string) (jwt.MapClaims, error) {
	c := jwt.MapClaims{}

	token, err := jwt.ParseWithClaims(sdjwt, c, func(token *jwt.Token) (interface{}, error) {
		return []byte(key), nil
	})
	if err != nil {
		return nil, err
	}

	if token.Valid {
		return c, nil
	}

	return nil, ErrTokenNotValid
}

func run(claims jwt.MapClaims, s []string) {
	disclosures := disclosures{}
	disclosures.new(s)

	cleanClaim(claims, disclosures)
}

func cleanClaim(claims jwt.MapClaims, disclosures disclosures) (jwt.MapClaims, error) {
	for claimKey, claimValue := range claims {
		fmt.Println("claimKey", claimKey, "claimValue", claimValue)
		switch claimValue.(type) {
		case map[string]any:
			fmt.Println("digg deeper")
		case []any:
			fmt.Println("digg deeper")
		case string:
			switch claimKey {
			case "_sd_alg":
				delete(claims, claimKey)
			case "_sd":
				if len(claimValue.([]any)) == 0 {
					delete(claims, claimKey)
				}
				for _, v := range claimValue.([]any) {
					if _, ok := disclosures.get(v.(string)); !ok {
						delete(claims, claimKey)
					}
				}
			}
		}
		fmt.Println(claimKey, claimValue)

	}
	return claims, nil
}

func Verifier(sdjwt, key string) (jwt.MapClaims, error) {
	sdClaims := splitSDJWT(sdjwt)

	claims, err := parseJWTAndValidate(sdClaims.JWT, key)
	if err != nil {
		return nil, err
	}
	fmt.Println(claims)

	return nil, ErrTokenNotValid
}
