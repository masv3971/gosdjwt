package gosdjwt

import (
	"encoding/base64"
	"fmt"

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
}

// ChildInstructionV2 instructs how to build a SD-JWT
type ChildInstructionV2 struct {
	Name                string `json:"name,omitempty" yaml:"name,omitempty"`
	SelectiveDisclosure bool   `json:"sd,omitempty" yaml:"sd,omitempty"`
	Salt                string `json:"salt,omitempty" yaml:"salt,omitempty"`
	Value               any    `json:"value,omitempty" yaml:"value,omitempty"`
	DisclosureHash      string `json:"disclosure_hash,omitempty" yaml:"disclosure_hash,omitempty"`
	ClaimHash           string `json:"claim_hash,omitempty" yaml:"claim_hash,omitempty"`
}

// ChildSliceInstructionV2 is a child with slice values
type ChildSliceInstructionV2 struct {
	Name                string    `json:"name,omitempty" yaml:"name,omitempty"`
	Children            []ChildV2 `json:"children,omitempty" yaml:"children,omitempty"`
	SelectiveDisclosure bool      `json:"sd,omitempty" yaml:"sd,omitempty"`
	Salt                string    `json:"salt,omitempty" yaml:"salt,omitempty"`
	Value               []any     `json:"value,omitempty" yaml:"value,omitempty"`
	DisclosureHash      string    `json:"disclosure_hash,omitempty" yaml:"disclosure_hash,omitempty"`
	ClaimHash           string    `json:"claim_hash,omitempty" yaml:"claim_hash,omitempty"`
}

func (c *ChildV2) makeClaimHash() {
	c.Salt = newSalt()
	s := fmt.Sprintf("[%q,%q,%q]", c.Salt, c.Name, c.Value)
	c.DisclosureHash = base64.RawURLEncoding.EncodeToString([]byte(s))
	c.ClaimHash = hash(c.DisclosureHash)
}

func (p *ParentV2) makeClaimHash() {
	p.Salt = newSalt()
	s := fmt.Sprintf("[%q,%q,%q]", p.Salt, p.Name, p.Children)
	p.DisclosureHash = base64.RawURLEncoding.EncodeToString([]byte(s))
	p.ClaimHash = hash(p.DisclosureHash)
}

func (c *ChildArrayV2) makeClaimHash() {
	c.Salt = newSalt()
	s := fmt.Sprintf("[%q,%q]", c.Salt, c.Name)
	c.DisclosureHash = base64.RawURLEncoding.EncodeToString([]byte(s))
	c.ClaimHash = hash(c.DisclosureHash)
}

func (r *RecursiveInstructionV2) recursiveHashClaim(claimKey string, claimHashes []string) {
	// make claimHash of children claimHashes
	r.Salt = newSalt()
	childrenClaims := map[string][]string{
		"_sd": claimHashes,
	}
	s := fmt.Sprintf("[%q,%q,%v]", r.Salt, r.Name, childrenClaims)
	fmt.Println("recursiveHashClaim", s)
	r.DisclosureHash = base64.RawURLEncoding.EncodeToString([]byte(s))
	r.ClaimHash = hash(r.DisclosureHash)
}

type DisclosuresV2 map[string]Disclosure

func (c *ChildV2) addToDisclosures(d DisclosuresV2) {
	d[newUUID()] = Disclosure{
		salt:           c.Salt,
		value:          c.Value,
		name:           c.Name,
		disclosureHash: c.DisclosureHash,
	}
}

func (p *ParentV2) addToDisclosures(d DisclosuresV2) {
	values := map[string]any{}
	collectChildrenValues(p.Children, values)
	d[newUUID()] = Disclosure{
		salt:           p.Salt,
		value:          values,
		name:           p.Name,
		disclosureHash: p.DisclosureHash,
	}
}

func (c *ChildArrayV2) addToDisclosures(d DisclosuresV2) {
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
	//values := map[string]any{}
	//collectChildrenValues(r.Children, values)
	d[newUUID()] = Disclosure{
		salt:           r.Salt,
		value:          "mura",
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
	return a
}

func collectChildrenValues(children []any, storage map[string]any) {
	for _, child := range children {
		switch child.(type) {
		case ChildV2, ChildArrayV2:
			claim := child.(ChildV2)
			storage[claim.Name] = claim.Value
		case ParentV2:
			claim := child.(ParentV2)
			storage[claim.Name] = jwt.MapClaims{}
			collectChildrenValues(claim.Children, storage)
		}
	}
}

func (c *ChildV2) makeDisclosureHash() {
	c.Salt = newSalt()
	s := fmt.Sprintf("[%q,%q,%q]", c.Salt, c.Name, c.Value)
	c.DisclosureHash = base64.RawURLEncoding.EncodeToString([]byte(s))
}
func (p *ParentV2) makeDisclosureHash() {
	p.Salt = newSalt()
	s := fmt.Sprintf("[%q,%q,%q]", p.Salt, p.Name, p.Children)
	p.DisclosureHash = base64.RawURLEncoding.EncodeToString([]byte(s))
}

type (
	ParentV2 ParentInstructionV2
	ChildV2  ChildInstructionV2

	ChildArrayV2 ChildSliceInstructionV2
)

// InstructionsV2 is a map of InstructionV2
type InstructionsV2 map[string]any

func calculateRecursiveClaimHashes(children []any, claimHashes []string) {
	for _, child := range children {
		switch child.(type) {
		case ChildV2:
			fmt.Println("ChildV2 in RecursiveV2")
			claim := child.(ChildV2)
			claim.makeClaimHash()
			claimHashes = append(claimHashes, claim.ClaimHash)
		case ChildArrayV2:
			fmt.Println("ChildArrayV2 in RecursiveV2")
			claim := child.(ChildArrayV2)
			claim.makeClaimHash()
			claimHashes = append(claimHashes, claim.ClaimHash)
		case ParentV2:
			fmt.Println("ParentV2 in RecursiveV2")
			claim := child.(ParentV2)
			claim.makeClaimHash()
			calculateRecursiveClaimHashes(claim.Children, claimHashes)

		default:
			panic(ErrNotKnownInstruction)
		}
	}
	fmt.Println("claimHashes", claimHashes)

}

func linkChildClaimHashToParent(children []any, parent any, disclosures DisclosuresV2) {
	for _, child := range children {
		switch child.(type) {
		case ChildV2:
			fmt.Println("ChildV2 in Recursive")
			childClaim := child.(ChildV2)
			childClaim.makeClaimHash()
			fmt.Println("child claimhash", childClaim.ClaimHash)
			childClaim.makeDisclosureHash()
			childClaim.addToDisclosures(disclosures)
			switch parent.(type) {
			case ParentV2:
			case *RecursiveInstructionV2:
				parentClaim := parent.(*RecursiveInstructionV2)
				fmt.Println("parent name", parentClaim.Name, "childClaimHash", childClaim.ClaimHash)
				parentClaim.ChildrenClaimHash = append(parentClaim.ChildrenClaimHash, childClaim.ClaimHash)
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
		case ParentV2:
			fmt.Println("ParentV2")
			claim := i.(ParentV2)

			if claim.SelectiveDisclosure {
				// Parent is Selective Disclosure witch means that all of its children are also Selective Disclosure, but not recursive.
				claim.makeClaimHash()
				claim.makeDisclosureHash()
				addToArray("_sd", claim.ClaimHash, storage)

				claim.addToDisclosures(disclosures)

				break
			}

			storage[claim.Name] = jwt.MapClaims{}
			makeSDV2(claim.Children, storage[claim.Name].(jwt.MapClaims), disclosures)

		case *RecursiveInstructionV2:
			claim := i.(*RecursiveInstructionV2)
			fmt.Println("RecursiveInstructionV2", "name", claim.Name)
			//calculateRecursiveClaimHashes(claim.Children, []string{})
			linkChildClaimHashToParent(claim.Children, claim, disclosures)

			fmt.Println("claimHashes children xxxx", claim.ChildrenClaimHash)
			fmt.Println("claimHases parent xxxx", claim.ClaimHash)

			claim.recursiveHashClaim(claim.Name, claim.ChildrenClaimHash)

			// make claimHash of children claimHashes

			addToArray("_sd", claim.ClaimHash, storage)
			break

		case ChildV2:
			fmt.Println("ChildV2")
			claim := i.(ChildV2)

			if claim.SelectiveDisclosure {
				fmt.Println("SelectiveDisclosure child")
				claim.makeClaimHash()
				claim.addToDisclosures(disclosures)
				addToArray("_sd", claim.ClaimHash, storage)
			} else {
				storage[claim.Name] = claim.Value
			}

		case ChildArrayV2:
			fmt.Println("ChildSliceV2")
			claim := i.(ChildArrayV2)
			fmt.Println("children ", claim.Children)
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
