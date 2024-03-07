package gosdjwt

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.step.sm/crypto/randutil"
)

// Instruction instructs how to build a SD-JWT
//type Instruction struct {
//	//Children       Instructions `json:"children,omitempty" yaml:"children,omitempty"`
//	SD             bool         `json:"sd,omitempty" yaml:"sd,omitempty"`
//	Salt           string       `json:"salt,omitempty" yaml:"salt,omitempty"`
//	Value          any          `json:"value,omitempty" yaml:"value,omitempty"`
//	Name           string       `json:"name,omitempty" yaml:"name,omitempty"`
//	DisclosureHash string       `json:"disclosure_hash,omitempty" yaml:"disclosure_hash,omitempty"`
//	ClaimHash      string       `json:"claim_hash,omitempty" yaml:"claim_hash,omitempty"`
//	Heritage       int          `json:"heritage" yaml:"heritage,omitempty"`
//	ID             string       `json:"id,omitempty" yaml:"id,omitempty"`
//	ParentNames    []string     `json:"parent_names,omitempty" yaml:"parent_names,omitempty"`
//	IsParent       bool         `json:"is_parent,omitempty" yaml:"is_parent,omitempty"`
//}

// DefaultClaims holds the default claims
type DefaultClaims struct {
	IAT int64  `json:"iat" default:"0"`
	EXP int64  `json:"exp"`
	NBF int64  `json:"nbf"`
	ISS string `json:"iss"`
}

// Disclosures is a map of disclosures
//type Disclosures map[string]*Disclosure

// ArrayHashes returns a string array of disclosure hashes
//func (d Disclosures) ArrayHashes() []string {
//	a := []string{}
//	for _, v := range d {
//		a = append(a, v.disclosureHash)
//	}
//	return a
//}

// SDJWT is a sd-jwt
type SDJWT struct {
	JWT         string
	Disclosures DisclosuresV2
	KeyBinding  string
}

var (
	newSalt = func() string {
		r, _ := randutil.ASCII(17)
		return base64.RawURLEncoding.EncodeToString([]byte(r))
	}
)

func newUUID() string {
	return uuid.NewString()
}

//func (i *Instructions) makeID() {
//	for _, v := range *i {
//		v.ID = newUUID()
//		v.Children.makeID()
//	}
//}

//func (d Disclosures) add(i *Instruction) {
//	d[newUUID()] = &Disclosure{
//		salt:           i.Salt,
//		value:          i.Value,
//		name:           i.Name,
//		disclosureHash: i.DisclosureHash,
//	}
//}
//
//func (d Disclosures) addValue(i *Instruction, parentName string) {
//	d[newUUID()] = &Disclosure{
//		salt:           i.Salt,
//		value:          i.Value,
//		disclosureHash: i.DisclosureHash,
//	}
//}
//
//func (d Disclosures) addAllChildren(i *Instruction) {
//	for _, v := range i.Children {
//		random := newUUID()
//		d[random] = &Disclosure{
//			salt:           i.Salt,
//			value:          v.Value,
//			disclosureHash: i.DisclosureHash,
//		}
//	}
//}
//
//func (d Disclosures) addParent(i *Instruction, parentName string) {
//	d[newUUID()] = &Disclosure{
//		salt:           i.Salt,
//		value:          i.Value,
//		name:           parentName,
//		disclosureHash: i.DisclosureHash,
//	}
//}

//func (d Disclosures) makeArray() []*Disclosure {
//	a := []*Disclosure{}
//	for _, v := range d {
//		fmt.Println("v", v)
//		a = append(a, v)
//	}
//	return a
//}

//func (i *Instruction) hasChild() bool {
//	return i.Children != nil
//}

//func (s *Instruction) hasNoChild() bool {
//	return s.Children == nil
//}

// isArrayValue returns true if the instruction lacks a name but has a value
//func (i *Instruction) isArrayValue() bool {
//	if i.Name == "" {
//		if i.Value != nil {
//			return true
//		}
//	}
//	return false
//}

//func (i *Instruction) makeClaimHash() error {
//	if i.DisclosureHash == "" {
//		return ErrBase64EncodedEmpty
//	}
//	i.ClaimHash = hash(i.DisclosureHash)
//	return nil
//}

//func (i *Instruction) makeDisclosureHash() {
//	s := fmt.Sprintf("[%q,%q,%q]", i.Salt, i.Name, i.Value)
//	i.DisclosureHash = base64.RawURLEncoding.EncodeToString([]byte(s))
//}

// Instructions is a slice of instructions
//type Instructions []*Instruction

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

//func addToClaimSD(parentName, childName string, value any, storage jwt.MapClaims) {
//	parentClaim, ok := storage[parentName]
//	if !ok {
//		v := []any{value}
//		storage[parentName] = jwt.MapClaims{childName: v}
//	} else {
//		childClaim, _ := parentClaim.(jwt.MapClaims)[childName].([]any)
//		childClaim = append(childClaim, value)
//
//		storage[parentName] = jwt.MapClaims{childName: childClaim}
//	}
//}

//func addToMap(parentName, childName string, value any, storage jwt.MapClaims) {
//	claim, ok := storage[parentName]
//	if !ok {
//		storage[parentName] = jwt.MapClaims{childName: value}
//	} else {
//		claim.(jwt.MapClaims)[childName] = value
//	}
//}

//func (i Instruction) collectAllChildClaims() error {
//	t := jwt.MapClaims{}
//	for _, v := range i.Children {
//		v.makeDisclosureHash()
//		if err := v.makeClaimHash(); err != nil {
//			return err
//		}
//		if v.hasNoChild() {
//			t[v.Name] = v.Value
//		}
//	}
//	i.Value = t
//	return nil
//}

//func (i *Instruction) addChildrenToParentValue(storage jwt.MapClaims) error {
//	if err := i.collectAllChildClaims(); err != nil {
//		return err
//	}
//	addToArray("_sd", i.ClaimHash, storage)
//	return nil
//}

//func addNestedMap(parentNames []string, value any, storage jwt.MapClaims) {
//	for _, parentName := range parentNames {
//		if v, ok := storage[parentName]; ok {
//			parentNames := parentNames[1:]
//			addNestedMap(parentNames, value, v.(jwt.MapClaims))
//		}
//	}
//}

//func addParentToStorage(name string, storage jwt.MapClaims) {
//	storage[name] = jwt.MapClaims{}
//}

//func addToParent(parentName string, value any, storage jwt.MapClaims) {
//	storage["xxx"] = value
//	fmt.Println("len", len(storage))
//	for k, v := range storage {
//		fmt.Println("k", k)
//		fmt.Println("v", v)
//	}
//	//fmt.Println("parentName", parentName)
//	//fmt.Println("storage in addToMapV2", storage)
//	//storage = append(storage.([]any), value)
//
//}

func (i InstructionsV2) createSDJWT() (jwt.MapClaims, DisclosuresV2, error) {
	storage := jwt.MapClaims{}
	disclosures := DisclosuresV2{}
	if err := makeSDV2(i, storage, disclosures); err != nil {
		return nil, nil, err
	}
	return storage, disclosures, nil
}

// MergeInstructions merge two instructions, a and b where a has precedence
// Can be used to achieve a default instruction set within an implementation
//func MergeInstructions(a, b Instructions) Instructions {
//	for _, v := range a {
//		for i, vv := range b {
//			if v.Name == vv.Name {
//				b[i] = b[len(b)-1]
//				b = b[:len(b)-1]
//			}
//		}
//	}
//
//	return append(a, b...)
//}

func sign(claims jwt.MapClaims, signingMethod jwt.SigningMethod, signingKey any) (string, error) {
	//if c.config.SigningMethod == nil {
	//	c.config.SigningMethod = jwt.SigningMethodHS256
	//}
	token := jwt.NewWithClaims(signingMethod, claims)

	//	if c.config.JWTType == "" {
	//		token.Header["typ"] = "sd-jwt"
	//	} else {
	//		token.Header["typ"] = c.config.JWTType
	//	}

	return token.SignedString(signingKey)
}

// SDJWT returns a signed SD-JWT with disclosures.
// Maybe this should return a more structured return of jwt and disclosures
func (i InstructionsV2) SDJWT(signingMethod jwt.SigningMethod, signingKey string) (*SDJWT, error) {
	rawSDJWT, disclosures, err := i.createSDJWT()
	if err != nil {
		return nil, err
	}
	signedJWT, err := sign(rawSDJWT, signingMethod, signingKey)
	if err != nil {
		return nil, err
	}

	sdjwt := &SDJWT{
		JWT:         signedJWT,
		Disclosures: disclosures,
	}

	//sdjwt := fmt.Sprintf("%s%s", signedJWT, disclosures.string())
	return sdjwt, nil
}
