package gosdjwt

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.step.sm/crypto/randutil"
)

// Instruction instructs how to build a SD-JWT
type Instruction struct {
	children       []*Instruction
	sd             bool
	salt           string
	value          any
	name           string
	disclosureHash string
	claimHash      string
}

// Disclosure keeps a disclosure
type Disclosure struct {
	salt           string
	value          any
	name           string
	disclosureHash string
	claimHash      string
}

type disclosures map[string]*Disclosure

var (
	newSalt = func() string {
		r, _ := randutil.ASCII(17)
		return base64.RawURLEncoding.EncodeToString([]byte(r))
	}
)

func newUUID() string {
	return uuid.NewString()
}

func (d disclosures) add(i *Instruction) {
	d[newUUID()] = &Disclosure{
		salt:           i.salt,
		value:          i.value,
		name:           i.name,
		disclosureHash: i.disclosureHash,
	}
}

func (d disclosures) addValue(i *Instruction, parentName string) {
	d[newUUID()] = &Disclosure{
		salt:           i.salt,
		value:          i.value,
		disclosureHash: i.disclosureHash,
	}
}

func (d disclosures) addAllChildren(i *Instruction) {
	for _, v := range i.children {
		random := newUUID()
		d[random] = &Disclosure{
			salt:           i.salt,
			value:          v.value,
			disclosureHash: i.disclosureHash,
		}
	}
}

func (d disclosures) addParent(i *Instruction, parentName string) {
	d[newUUID()] = &Disclosure{
		salt:           i.salt,
		value:          i.value,
		name:           parentName,
		disclosureHash: i.disclosureHash,
	}
}

func (d disclosures) string() string {
	s := "~"
	for _, v := range d {
		s += fmt.Sprintf("%s~", v.disclosureHash)
	}
	return s
}

func (d disclosures) makeArray() []*Disclosure {
	a := []*Disclosure{}
	for _, v := range d {
		fmt.Println("v", v)
		a = append(a, v)
	}
	return a
}

func (d disclosures) new(dd []string) error {
	for _, v := range dd {
		disclosure := &Disclosure{}
		if err := disclosure.parse(v); err != nil {
			return err
		}
		d[disclosure.claimHash] = disclosure
	}
	return nil
}

func (d disclosures) get(key string) (*Disclosure, bool) {
	v, ok := d[key]
	return v, ok
}

func (d *Disclosure) makeClaimHash() {
	d.claimHash = hash(d.disclosureHash)
}

func (d *Disclosure) parse(s string) error {
	decoded, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	d.disclosureHash = s

	k, _ := strings.CutPrefix(string(decoded), "[")
	k, _ = strings.CutSuffix(k, "]")

	for i, v := range strings.Split(k, ",") {
		v = strings.Trim(v, "\"")
		switch i {
		case 0:
			d.salt = v
		case 1:
			d.name = v
		case 2:
			d.value = v
		}
	}
	d.makeClaimHash()
	return nil
}

func (i *Instruction) hasChildren() bool {
	return i.children != nil
}

// isArrayValue returns true if the instruction lacks a name but has a value
func (i *Instruction) isArrayValue() bool {
	if i.name == "" {
		if i.value != nil {
			return true
		}
	}
	return false
}

func (i *Instruction) makeClaimHash() error {
	if i.disclosureHash == "" {
		return ErrBase64EncodedEmpty
	}
	i.claimHash = hash(i.disclosureHash)
	return nil
}

func (i *Instruction) makeDisclosureHash() {
	s := fmt.Sprintf("[%q,%q,%q]", i.salt, i.name, i.value)
	i.disclosureHash = base64.RawURLEncoding.EncodeToString([]byte(s))
}

type Instructions []*Instruction

func hash(disclosureHash string) string {
	sha256Encoded := fmt.Sprintf("%x", sha256.Sum256([]byte(disclosureHash)))
	return base64.RawURLEncoding.EncodeToString([]byte(sha256Encoded))
}

func addToArray(key string, value any, storage jwt.MapClaims) {
	claim, ok := storage[key]
	if !ok {
		storage[key] = []any{value}
	} else {
		storage[key] = append(claim.([]any), value)
	}
}

func addToClaimSD(parentName, childName string, value any, storage jwt.MapClaims) {
	parentClaim, ok := storage[parentName]
	if !ok {
		v := []any{value}
		storage[parentName] = jwt.MapClaims{childName: v}
	} else {
		childClaim, _ := parentClaim.(jwt.MapClaims)[childName].([]any)
		childClaim = append(childClaim, value)

		storage[parentName] = jwt.MapClaims{childName: childClaim}
	}
}

func addToMap(parentName, childName string, value any, storage jwt.MapClaims) {
	claim, ok := storage[parentName]
	if !ok {
		storage[parentName] = jwt.MapClaims{parentName: value}
	} else {
		claim.(jwt.MapClaims)[childName] = value
	}
}

func (i Instruction) collectAllChildClaims() error {
	t := jwt.MapClaims{}
	for _, v := range i.children {
		v.makeDisclosureHash()
		if err := v.makeClaimHash(); err != nil {
			return err
		}
		if !v.hasChildren() {
			t[v.name] = v.value
		}
	}
	i.value = t
	return nil
}

func (i *Instruction) addChildrenToParentValue(storage jwt.MapClaims) error {
	if err := i.collectAllChildClaims(); err != nil {
		return err
	}
	addToArray("_sd", i.claimHash, storage)
	return nil
}

func makeSD(parentStorage jwt.MapClaims, parentName string, parentSD bool, instructions Instructions, storage jwt.MapClaims, disclosures disclosures) error {
	for _, v := range instructions {
		v.salt = newSalt()
		if v.sd || parentSD {
			v.makeDisclosureHash()
			if err := v.makeClaimHash(); err != nil {
				return err
			}
		}
		if v.hasChildren() {
			makeSD(parentStorage, v.name, v.sd, v.children, storage, disclosures)
		} else {
			if parentName == "" {
				if v.sd {
					fmt.Println("sd no parent", v.name)
					disclosures.add(v)
					addToArray("_sd", v.claimHash, storage)
				} else {
					storage[v.name] = v.value
				}
			} else {
				if parentSD {
					// all under parent should be encrypted
					if err := v.addChildrenToParentValue(storage); err != nil {
						return err
					}
					disclosures.addParent(v, parentName)
					fmt.Println("parent is sd", v.value)
					if v.sd {
						fmt.Println("recursive sd")
						disclosures.addAllChildren(v)
						break
					}
				} else {
					if v.sd {
						if v.isArrayValue() {
							fmt.Println("Array-like sd")
							addToArray(parentName, jwt.MapClaims{"...": v.claimHash}, storage)
							disclosures.addValue(v, parentName)
						} else {
							fmt.Println("sd child")
							addToClaimSD(parentName, "_sd", v.claimHash, storage)
							disclosures.add(v)
						}
					} else {
						if v.isArrayValue() {

							addToArray(parentName, v.value, storage)
							fmt.Println("value", v.value, "parentName", parentName)

						} else {
							addToMap(parentName, v.name, v.value, storage)
							fmt.Println("Add to map")
						}
					}
				}
			}
		}
	}
	fmt.Println("storage", storage)
	fmt.Println("disclosures", disclosures)
	return nil
}

func (i Instructions) sdJWT() (jwt.MapClaims, disclosures, error) {
	storage := jwt.MapClaims{}
	disclosures := disclosures{}
	if err := makeSD(nil, "", false, i, storage, disclosures); err != nil {
		return nil, nil, err
	}
	return storage, disclosures, nil
}

func sign(claims jwt.MapClaims, signingKey string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(signingKey))
}

// SDJWT returns a signed SD-JWT with disclosures
// Maybe this should return a more structured return of jwt and disclosures
func (i Instructions) SDJWT(signingKey string) (string, error) {
	rawSDJWT, disclosures, err := i.sdJWT()
	if err != nil {
		return "", err
	}
	signedJWT, err := sign(rawSDJWT, signingKey)
	if err != nil {
		return "", err
	}
	sdjwt := fmt.Sprintf("%s%s", signedJWT, disclosures.string())
	return sdjwt, nil
}
