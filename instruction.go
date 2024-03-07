package gosdjwt

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

// InstructionsV2 is a list of instructions
type InstructionsV2 []any
