package gosdjwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// ErrNotKnownInstruction is returned when the instruction is not known
	ErrNotKnownInstruction = fmt.Errorf("not a known instruction")

	// ErrValueAndChildrenPresent is returned when both value and children are present
	ErrValueAndChildrenPresent = fmt.Errorf("value and children present")
)

func (c *ChildInstructionV2) makeClaimHash() {
	c.Salt = newSalt()
	s := fmt.Sprintf("[%q,%q,%q]", c.Salt, c.Name, c.Value)
	c.DisclosureHash = base64.RawURLEncoding.EncodeToString([]byte(s))
	c.ClaimHash = hash(c.DisclosureHash)
}

func (r *RecursiveInstructionV2) makeClaimHash() error {
	r.Salt = newSalt()

	childClaims := map[string][]string{
		"_sd": r.ChildrenClaimHash,
	}

	j, err := json.Marshal(childClaims)
	if err != nil {
		return err
	}

	s := fmt.Sprintf("[%q,%q,%s]", r.Salt, r.Name, string(j))
	r.DisclosureHash = base64.RawURLEncoding.EncodeToString([]byte(s))
	r.ClaimHash = hash(r.DisclosureHash)

	return nil
}

func (p *ParentInstructionV2) makeClaimHash() error {
	p.Salt = newSalt()
	childrenClaims, err := claimStringRepresentation(p.Children)
	if err != nil {
		return err
	}
	s := fmt.Sprintf("[%q,%q,%s]", p.Salt, p.Name, childrenClaims)
	p.DisclosureHash = base64.RawURLEncoding.EncodeToString([]byte(s))
	p.ClaimHash = hash(p.DisclosureHash)

	return nil
}

//func (c *ChildArrayInstructionV2) makeClaimHash() {
//	c.Salt = newSalt()
//	s := fmt.Sprintf("[%q,%q]", c.Salt, c.Name)
//	c.DisclosureHash = base64.RawURLEncoding.EncodeToString([]byte(s))
//	c.ClaimHash = hash(c.DisclosureHash)
//}

func (r *RecursiveInstructionV2) recursiveHashClaim(claimHashes []string) error {
	// make claimHash of children claimHashes
	r.Salt = newSalt()
	childrenClaims := map[string][]string{
		"_sd": claimHashes,
	}

	b, err := json.Marshal(childrenClaims)
	if err != nil {
		return err
	}
	s := fmt.Sprintf("[%q,%q,%s]", r.Salt, r.Name, string(b))
	r.DisclosureHash = base64.RawURLEncoding.EncodeToString([]byte(s))
	r.ClaimHash = hash(r.DisclosureHash)

	return nil
}

func claimStringRepresentation(children []any) (string, error) {
	stringClaims := map[string]any{}
	for _, child := range children {
		switch claim := child.(type) {
		case *ChildInstructionV2:
			stringClaims[claim.Name] = claim.Value
		default:
			return "", ErrNotKnownInstruction
		}
	}

	d, err := json.Marshal(stringClaims)
	if err != nil {
		return "", err
	}
	return string(d), nil
}

func (c *ChildInstructionV2) addToDisclosures(d DisclosuresV2) {
	d[newUUID()] = Disclosure{
		salt:           c.Salt,
		value:          c.Value,
		name:           c.Name,
		disclosureHash: c.DisclosureHash,
	}
}

func (p *ParentInstructionV2) addToDisclosures(d DisclosuresV2) {
	values := map[string]any{}
	collectChildrenValues(p.Children, values)
	d[newUUID()] = Disclosure{
		salt:           p.Salt,
		value:          values,
		name:           p.Name,
		disclosureHash: p.DisclosureHash,
	}
}

//func (c *ChildArrayInstructionV2) addToDisclosures(d DisclosuresV2) {
//	values := []any{}
//	for _, child := range c.Children {
//		values = append(values, child.Value)
//	}
//	d[newUUID()] = Disclosure{
//		salt:           c.Salt,
//		value:          values,
//		name:           c.Name,
//		disclosureHash: c.DisclosureHash,
//	}
//}

func (r *RecursiveInstructionV2) addToDisclosures(d DisclosuresV2) {
	d[newUUID()] = Disclosure{
		salt:           r.Salt,
		name:           r.Name,
		disclosureHash: r.DisclosureHash,
	}
}

// ArrayHashes returns a string array of disclosure hashes
func (d DisclosuresV2) ArrayHashes() []string {
	a := []string{}
	for _, v := range d {
		a = append(a, v.disclosureHash)
	}
	sort.Strings(a)
	return a
}

func collectChildrenValues(children []any, storage map[string]any) {
	for _, child := range children {
		switch claim := child.(type) {
		case *ChildInstructionV2:
			storage[claim.Name] = claim.Value
		case ChildArrayInstructionV2:
		case *ParentInstructionV2:
			storage[claim.Name] = jwt.MapClaims{}
			collectChildrenValues(claim.Children, storage)
		}
	}
}

func addUID(instruction any) {
	switch ins := instruction.(type) {
	case *RecursiveInstructionV2:
		if ins.UID == "" {
			ins.UID = newUUID()
		}
		//	case *ParentV2:
		//		instruction.(*ParentV2).UID = newUUID()
	case *ChildInstructionV2:
		if ins.UID == "" {
			ins.UID = newUUID()
		}
		//	case *ChildArrayV2:
		//		instruction.(*ChildArrayV2).UID = newUUID()
	}
}

func recursiveClaimHandler(instructions []any, parent any, disclosures DisclosuresV2) error {
	for _, instruction := range instructions {
		switch instruction.(type) {
		case *RecursiveInstructionV2:
			addUID(instruction)
			child := instruction.(*RecursiveInstructionV2)
			if err := recursiveClaimHandler(child.Children, child, disclosures); err != nil {
				return err
			}
			if err := child.makeClaimHash(); err != nil {
				return err
			}
			child.addToDisclosures(disclosures)
			switch parentClaim := parent.(type) {
			case *RecursiveInstructionV2:
				if parentClaim.UID == child.UID {
					break
				}
				parentClaim.ChildrenClaimHash = append(parentClaim.ChildrenClaimHash, child.ClaimHash)
			default:
				return ErrNotKnownInstruction
			}
		case *ChildInstructionV2:
			addUID(instruction)
			child := instruction.(*ChildInstructionV2)
			child.makeClaimHash()
			child.addToDisclosures(disclosures)
			switch parentClaim := parent.(type) {
			case *RecursiveInstructionV2:
				parentClaim.ChildrenClaimHash = append(parentClaim.ChildrenClaimHash, child.ClaimHash)
			default:
				return ErrNotKnownInstruction
			}
		default:
			return ErrNotKnownInstruction
		}
	}
	return nil
}

func makeSDV2(instructions []any, storage jwt.MapClaims, disclosures DisclosuresV2) error {
	for _, i := range instructions {
		switch claim := i.(type) {
		case *ParentInstructionV2:

			if claim.SelectiveDisclosure {
				// Parent is Selective Disclosure witch means that all of its children are also Selective Disclosure, but not recursive.
				if err := claim.makeClaimHash(); err != nil {
					return err
				}
				addToArray("_sd", claim.ClaimHash, storage)

				claim.addToDisclosures(disclosures)

				break
			}

			storage[claim.Name] = jwt.MapClaims{}
			if err := makeSDV2(claim.Children, storage[claim.Name].(jwt.MapClaims), disclosures); err != nil {
				return err
			}

		case *RecursiveInstructionV2:
			if err := recursiveClaimHandler(claim.Children, claim, disclosures); err != nil {
				return err
			}

			if err := claim.recursiveHashClaim(claim.ChildrenClaimHash); err != nil {
				return err
			}

			claim.addToDisclosures(disclosures)

			addToArray("_sd", claim.ClaimHash, storage)

		case *ChildInstructionV2:
			if claim.SelectiveDisclosure {
				claim.makeClaimHash()
				claim.addToDisclosures(disclosures)
				addToArray("_sd", claim.ClaimHash, storage)
			} else {
				storage[claim.Name] = claim.Value
			}

		case *ChildArrayInstructionV2:
			for _, child := range claim.Children {
				if child.SelectiveDisclosure {
					child.makeClaimHash()
					addToArray(claim.Name, map[string]string{"...": child.ClaimHash}, storage)

					child.addToDisclosures(disclosures)
				} else {
					addToArray(claim.Name, child.Value, storage)
				}
			}

		default:
			return ErrNotKnownInstruction
		}
	}
	return nil
}

func decodeDisclosureHash(hash string) (string, error) {
	decoded, err := base64.RawStdEncoding.DecodeString(hash)
	if err != nil {
		return "", err
	}

	return string(decoded), nil
}
