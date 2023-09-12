package gosdjwt

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

// Instruction instructs how to build a SD-JWT
type Instruction struct {
	children []Instruction
	value    any
	name     string
	sd       bool
}

// Disclosure keeps a disclosure
type Disclosure struct {
	salt   string
	value  any
	name   string
	sdHash string
}

type disclosures map[string]Disclosure

var salt = func() string {
	return uuid.NewString()
}

func (d disclosures) add(i Instruction) {
	d[salt()] = Disclosure{
		salt:   salt(),
		value:  i.value,
		name:   i.name,
		sdHash: i.makeHash(),
	}
}

func (d disclosures) addValue(i Instruction, parentName string) {
	d[salt()] = Disclosure{
		salt:   salt(),
		value:  i.value,
		sdHash: i.makeHash(),
	}
}

func (d disclosures) addParent(i Instruction, parentName string) {
	d[salt()] = Disclosure{
		salt:   salt(),
		value:  i.value,
		name:   parentName,
		sdHash: i.makeHash(),
	}
}

func (d disclosures) string() string {
	s := "~"
	for _, v := range d {
		s += fmt.Sprintf("%s~", v.sdHash)
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

func (i Instruction) hasChildren() bool {
	return i.children != nil
}

// isArrayValue returns true if the instruction lacks a name but has a value
func (i Instruction) isArrayValue() bool {
	if i.name == "" {
		if i.value != nil {
			return true
		}
	}
	return false
}

func (i Instruction) makeHash() string {
	return "xyz"
}

type instructions []Instruction

func untangle(parentStorage jwt.MapClaims, parentName string, instructions instructions, storage jwt.MapClaims) {
	for _, v := range instructions {
		if v.hasChildren() {
			untangle(parentStorage, v.name, v.children, storage)
		} else {
			if parentName == "" {
				storage[v.name] = v.value
			} else {
				if v.isArrayValue() {
					value := []any{v.value}

					claim, ok := storage[parentName]
					if !ok {
						storage[parentName] = value
					} else {
						storage[parentName] = append(claim.([]any), value...)
					}
					fmt.Println("value", v.value, "parentName", parentName)
				} else {
					parentStorage = jwt.MapClaims{
						v.name: v.value,
					}
					fmt.Println("parentStorage", parentStorage)
					claim, ok := storage[parentName]
					if !ok {
						storage[parentName] = parentStorage
					} else {
						claim.(jwt.MapClaims)[v.name] = v.value
					}
					fmt.Println("storage", storage)
				}
			}
		}
	}
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

func (i Instruction) collectAllChildClaims() {
	t := jwt.MapClaims{}
	for _, v := range i.children {
		if !v.hasChildren() {
			t[v.name] = v.value
		}
	}
	i.value = t
}

func (i *Instruction) addChildrenToParentValue(storage jwt.MapClaims) {
	i.collectAllChildClaims()
	i.makeHash()
	addToArray("_sd", i.makeHash(), storage)
}

func makeSD(parentStorage jwt.MapClaims, parentName string, parentSD bool, instructions instructions, storage jwt.MapClaims, disclosures disclosures) {
	for _, v := range instructions {
		if v.hasChildren() {
			makeSD(parentStorage, v.name, v.sd, v.children, storage, disclosures)
		} else {
			if parentName == "" {
				if v.sd {
					fmt.Println("sd no parent", v.name)
					addToArray("_sd", v.makeHash(), storage)
					disclosures.add(v)
				} else {
					storage[v.name] = v.value
				}
			} else {
				if parentSD {
					// all under parent should be encrypted
					v.addChildrenToParentValue(storage)
					disclosures.addParent(v, parentName)
					fmt.Println("parent is sd", v.value)
					if v.sd {
						fmt.Println("recursive sd")
						panic("Not implemented")
					}
				} else {
					if v.sd {
						if v.isArrayValue() {
							fmt.Println("Array-like sd")
							addToArray(parentName, jwt.MapClaims{"...": v.makeHash()}, storage)
							disclosures.addValue(v, parentName)
						} else {
							fmt.Println("sd child")
							addToClaimSD(parentName, "_sd", v.makeHash(), storage)
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
}
