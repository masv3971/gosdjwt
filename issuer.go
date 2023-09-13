package gosdjwt

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

// Instruction instructs how to build a SD-JWT
type Instruction struct {
	children       []*Instruction
	salt           string
	value          any
	name           string
	sd             bool
	disclosureHash string
	claimHash      string
}

// Disclosure keeps a disclosure
type Disclosure struct {
	salt           string
	value          any
	name           string
	disclosureHash string
}

type disclosures map[string]Disclosure

var (
	newSalt = func() string {
		return uuid.NewString()
	}
)

func newUUID() string {
	return uuid.NewString()
}

func (d disclosures) add(i *Instruction) {
	d[newUUID()] = Disclosure{
		salt:           i.salt,
		value:          i.value,
		name:           i.name,
		disclosureHash: i.disclosureHash,
	}
}

func (d disclosures) addValue(i *Instruction, parentName string) {
	d[newUUID()] = Disclosure{
		salt:           i.salt,
		value:          i.value,
		disclosureHash: i.disclosureHash,
	}
}

func (d disclosures) addAllChildren(i *Instruction) {
	for _, v := range i.children {
		random := newUUID()
		d[random] = Disclosure{
			salt:           i.salt,
			value:          v.value,
			disclosureHash: i.disclosureHash,
		}
	}
}

func (d disclosures) addParent(i *Instruction, parentName string) {
	d[newUUID()] = Disclosure{
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

func (d disclosures) makeArray() []Disclosure {
	a := []Disclosure{}
	for _, v := range d {
		fmt.Println("v", v)
		a = append(a, v)
	}
	return a
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
		return errors.New("base64Encoded is empty")
	}
	sha256Encoded := fmt.Sprintf("%x", sha256.Sum256([]byte(i.disclosureHash)))
	i.claimHash = base64.RawURLEncoding.EncodeToString([]byte(sha256Encoded))
	return nil
}

func (i *Instruction) makeDisclosureHash() {
	s := fmt.Sprintf("[%q,%q,%q]", i.salt, i.name, i.value)
	i.disclosureHash = base64.RawURLEncoding.EncodeToString([]byte(s))
}

type instructions []*Instruction

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

func makeSD(parentStorage jwt.MapClaims, parentName string, parentSD bool, instructions instructions, storage jwt.MapClaims, disclosures disclosures) error {
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
