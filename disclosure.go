package gosdjwt

import (
	"encoding/base64"
	"strings"
)

// Disclosure keeps a disclosure
type Disclosure struct {
	salt           string
	value          any
	name           string
	disclosureHash string
	claimHash      string
}

// DisclosuresV2 is a map of disclosures
type DisclosuresV2 map[string]Disclosure

//func (d DisclosuresV2) format() string {
//	if len(d) == 0 {
//		return ""
//	}
//	s := "~"
//	for _, v := range d {
//		s += v.disclosureHash + "~"
//	}
//	return s
//}

func (d DisclosuresV2) new(dd []string) error {
	for _, v := range dd {
		disclosure := Disclosure{}
		if err := disclosure.parse(v); err != nil {
			return err
		}
		d[disclosure.claimHash] = disclosure
	}
	return nil
}
func (d DisclosuresV2) get(key string) (Disclosure, bool) {
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
