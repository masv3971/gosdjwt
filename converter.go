package gosdjwt

const (
	RuleSelectiveDisclosure = "sdjwt::rule::selective_disclosure"
)

// ConvertJSON2SDJWT converts a JSON document to a SDJWT
func ConvertJSON2SDJWT(document map[string]any, rules map[string]any) (InstructionsV2, error) {
	return InstructionsV2{}, nil
}
