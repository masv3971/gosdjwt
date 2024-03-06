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

// ParentInstructionV2 instructs how to build a SD-JWT
type ParentInstructionV2 struct {
	Name                string   `json:"name,omitempty" yaml:"name,omitempty"`
	Children            []any    `json:"children,omitempty" yaml:"children,omitempty"`
	SelectiveDisclosure bool     `json:"sd,omitempty" yaml:"sd,omitempty"`
	Salt                string   `json:"salt,omitempty" yaml:"salt,omitempty"`
	DisclosureHash      string   `json:"disclosure_hash,omitempty" yaml:"disclosure_hash,omitempty"`
	ClaimHash           string   `json:"claim_hash,omitempty" yaml:"claim_hash,omitempty"`
	ChildrenClaimHash   []string `json:"children_claim_hash,omitempty" yaml:"children_claim_hash,omitempty"`
}

// RecursiveInstructionV2 instructs how to build a SD-JWT
type RecursiveInstructionV2 struct {
	Name                string   `json:"name,omitempty" yaml:"name,omitempty"`
	Value               any      `json:"value,omitempty" yaml:"value,omitempty"`
	Children            []any    `json:"children,omitempty" yaml:"children,omitempty"`
	SelectiveDisclosure bool     `json:"sd,omitempty" yaml:"sd,omitempty"`
	Salt                string   `json:"salt,omitempty" yaml:"salt,omitempty"`
	DisclosureHash      string   `json:"disclosure_hash,omitempty" yaml:"disclosure_hash,omitempty"`
	ClaimHash           string   `json:"claim_hash,omitempty" yaml:"claim_hash,omitempty"`
	ChildrenClaimHash   []string `json:"children_claim_hash,omitempty" yaml:"children_claim_hash,omitempty"`
	UID                 string   `json:"uid,omitempty" yaml:"uid,omitempty"`
}

// ChildInstructionV2 instructs how to build a SD-JWT
type ChildInstructionV2 struct {
	Name                string `json:"name,omitempty" yaml:"name,omitempty"`
	SelectiveDisclosure bool   `json:"sd,omitempty" yaml:"sd,omitempty"`
	Salt                string `json:"salt,omitempty" yaml:"salt,omitempty"`
	Value               any    `json:"value,omitempty" yaml:"value,omitempty"`
	DisclosureHash      string `json:"disclosure_hash,omitempty" yaml:"disclosure_hash,omitempty"`
	ClaimHash           string `json:"claim_hash,omitempty" yaml:"claim_hash,omitempty"`
	UID                 string `json:"uid,omitempty" yaml:"uid,omitempty"`
}

// ChildArrayInstructionV2 is a child with slice values
type ChildArrayInstructionV2 struct {
	Name                string               `json:"name,omitempty" yaml:"name,omitempty"`
	Children            []ChildInstructionV2 `json:"children,omitempty" yaml:"children,omitempty"`
	SelectiveDisclosure bool                 `json:"sd,omitempty" yaml:"sd,omitempty"`
	Salt                string               `json:"salt,omitempty" yaml:"salt,omitempty"`
	Value               []any                `json:"value,omitempty" yaml:"value,omitempty"`
	DisclosureHash      string               `json:"disclosure_hash,omitempty" yaml:"disclosure_hash,omitempty"`
	ClaimHash           string               `json:"claim_hash,omitempty" yaml:"claim_hash,omitempty"`
}

func (c *ChildInstructionV2) makeClaimHash() {
	c.Salt = newSalt()
	s := fmt.Sprintf("[%q,%q,%q]", c.Salt, c.Name, c.Value)
	c.DisclosureHash = base64.RawURLEncoding.EncodeToString([]byte(s))
	c.ClaimHash = hash(c.DisclosureHash)
}

func (r *RecursiveInstructionV2) makeClaimHash() {
	r.Salt = newSalt()

	childClaims := map[string][]string{
		"_sd": r.ChildrenClaimHash,
	}

	j, err := json.Marshal(childClaims)
	if err != nil {
		panic(err)
	}

	s := fmt.Sprintf("[%q,%q,%s]", r.Salt, r.Name, string(j))
	r.DisclosureHash = base64.RawURLEncoding.EncodeToString([]byte(s))
	r.ClaimHash = hash(r.DisclosureHash)

}

func (p *ParentInstructionV2) makeClaimHash() error {
	p.Salt = newSalt()
	childrenClaims, err := claimStringRepresentation(p, p.Children)
	if err != nil {
		return err
	}
	s := fmt.Sprintf("[%q,%q,%s]", p.Salt, p.Name, childrenClaims)
	p.DisclosureHash = base64.RawURLEncoding.EncodeToString([]byte(s))
	p.ClaimHash = hash(p.DisclosureHash)

	return nil
}

func (c *ChildArrayInstructionV2) makeClaimHash() {
	c.Salt = newSalt()
	s := fmt.Sprintf("[%q,%q]", c.Salt, c.Name)
	c.DisclosureHash = base64.RawURLEncoding.EncodeToString([]byte(s))
	c.ClaimHash = hash(c.DisclosureHash)
}

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

type DisclosuresV2 map[string]Disclosure

func claimStringRepresentation(parent any, children []any) (string, error) {
	stringClaims := map[string]any{}
	for _, child := range children {
		switch child.(type) {
		case *ChildInstructionV2:
			claim := child.(*ChildInstructionV2)
			stringClaims[claim.Name] = claim.Value
		default:
			panic(ErrNotKnownInstruction)
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

func (c *ChildArrayInstructionV2) addToDisclosures(d DisclosuresV2) {
	values := []any{}
	for _, child := range c.Children {
		values = append(values, child.Value)
	}
	d[newUUID()] = Disclosure{
		salt:           c.Salt,
		value:          values,
		name:           c.Name,
		disclosureHash: c.DisclosureHash,
	}
}

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
		switch child.(type) {
		case *ChildInstructionV2, *ChildArrayInstructionV2:
			claim := child.(*ChildInstructionV2)
			storage[claim.Name] = claim.Value
		case *ParentInstructionV2:
			claim := child.(*ParentInstructionV2)
			storage[claim.Name] = jwt.MapClaims{}
			collectChildrenValues(claim.Children, storage)
		}
	}
}

func addUID(instruction any) {
	switch instruction.(type) {
	case *RecursiveInstructionV2:
		if instruction.(*RecursiveInstructionV2).UID == "" {
			instruction.(*RecursiveInstructionV2).UID = newUUID()
		}
		//	case *ParentV2:
		//		instruction.(*ParentV2).UID = newUUID()
	case *ChildInstructionV2:
		if instruction.(*ChildInstructionV2).UID == "" {
			instruction.(*ChildInstructionV2).UID = newUUID()
		}
		//	case *ChildArrayV2:
		//		instruction.(*ChildArrayV2).UID = newUUID()
	}
}

func recursiveClaimHandler(instructions []any, parent any, disclosures DisclosuresV2) {
	for _, instruction := range instructions {
		switch instruction.(type) {
		case *RecursiveInstructionV2:
			addUID(instruction)
			child := instruction.(*RecursiveInstructionV2)
			recursiveClaimHandler(child.Children, child, disclosures)
			child.makeClaimHash()
			child.addToDisclosures(disclosures)
			switch parent.(type) {
			case *RecursiveInstructionV2:
				parentClaim := parent.(*RecursiveInstructionV2)
				if parentClaim.UID == child.UID {
					break
				}
				parentClaim.ChildrenClaimHash = append(parentClaim.ChildrenClaimHash, child.ClaimHash)
			default:
				panic(ErrNotKnownInstruction)
			}
		case *ChildInstructionV2:
			addUID(instruction)
			child := instruction.(*ChildInstructionV2)
			child.makeClaimHash()
			child.addToDisclosures(disclosures)
			switch parent.(type) {
			case *RecursiveInstructionV2:
				parentClaim := parent.(*RecursiveInstructionV2)
				parentClaim.ChildrenClaimHash = append(parentClaim.ChildrenClaimHash, child.ClaimHash)
			default:
				panic(ErrNotKnownInstruction)
			}
		default:
			panic(ErrNotKnownInstruction)
		}
	}
}

func makeSDV2(instructions []any, storage jwt.MapClaims, disclosures DisclosuresV2) {
	for _, i := range instructions {
		switch i.(type) {
		case *ParentInstructionV2:
			claim := i.(*ParentInstructionV2)

			if claim.SelectiveDisclosure {
				// Parent is Selective Disclosure witch means that all of its children are also Selective Disclosure, but not recursive.
				claim.makeClaimHash()
				addToArray("_sd", claim.ClaimHash, storage)

				claim.addToDisclosures(disclosures)

				break
			}

			storage[claim.Name] = jwt.MapClaims{}
			makeSDV2(claim.Children, storage[claim.Name].(jwt.MapClaims), disclosures)

		case *RecursiveInstructionV2:
			claim := i.(*RecursiveInstructionV2)
			recursiveClaimHandler(claim.Children, claim, disclosures)

			if err := claim.recursiveHashClaim(claim.ChildrenClaimHash); err != nil {
				panic(err)
			}

			claim.addToDisclosures(disclosures)

			addToArray("_sd", claim.ClaimHash, storage)
			break

		case *ChildInstructionV2:
			claim := i.(*ChildInstructionV2)
			if claim.SelectiveDisclosure {
				claim.makeClaimHash()
				claim.addToDisclosures(disclosures)
				addToArray("_sd", claim.ClaimHash, storage)
			} else {
				storage[claim.Name] = claim.Value
			}

		case *ChildArrayInstructionV2:
			claim := i.(*ChildArrayInstructionV2)
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
			panic(ErrNotKnownInstruction)
		}
	}
}

func verifyClaim(claimHash, disclosureHash string) bool {
	return hash(disclosureHash) == claimHash
}

func decodeDisclosureHash(hash string) (string, error) {
	decoded, err := base64.RawStdEncoding.DecodeString(hash)
	if err != nil {
		return "", err
	}

	return string(decoded), nil
}

func (d DisclosuresV2) decodeHashes() (map[string]string, error) {
	decoded := map[string]string{}
	for k, v := range d {
		decodedDisclosure, err := decodeDisclosureHash(v.disclosureHash)
		if err != nil {
			return nil, err
		}
		decoded[k] = decodedDisclosure
	}
	return decoded, nil
}
