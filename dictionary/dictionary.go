package dictionary

import (
	"bytes"
	"fmt"
	"strconv"
)

type AttributesOIDMap struct {
	Attribute *Attribute
	Map       map[int]*AttributesOIDMap
}

func (om *AttributesOIDMap) addAttribute(oid OID, a *Attribute) {
	if len(oid) == 0 {
		return
	}

	if om.Map == nil {
		om.Map = make(map[int]*AttributesOIDMap)
	}

	id := oid[0]
	var curr *AttributesOIDMap
	var found bool
	if curr, found = om.Map[id]; !found {
		curr = &AttributesOIDMap{}
		om.Map[id] = curr
	}

	if len(oid) == 1 {
		curr.Attribute = a
	} else {
		curr.addAttribute(oid[1:], a)
	}
}

func (om *AttributesOIDMap) getAttribute(oid OID) *Attribute {
	if len(oid) == 0 {
		return nil
	}

	id := oid[0]
	curr := om.Map[id]
	if len(oid) == 1 {
		return curr.Attribute
	}

	return curr.getAttribute(oid[1:])
}

type Dictionary struct {
	AttributesByOID AttributesOIDMap
	Attributes      []*Attribute
	Values          []*Value
	Vendors         []*Vendor
}

func (d *Dictionary) GetAttributeByOID(oid OID) *Attribute {
	return d.AttributesByOID.getAttribute(oid)
}

func (d *Dictionary) GoString() string {
	var b bytes.Buffer
	b.WriteString("&dictionary.Dictionary{")

	if len(d.Attributes) > 0 {
		b.WriteString("Attributes:[]*dictionary.Attribute{")
		for _, attr := range d.Attributes {
			fmt.Fprintf(&b, "%#v,", attr)
		}
		b.WriteString("},")
	}

	if len(d.Values) > 0 {
		b.WriteString("Values:[]*dictionary.Value{")
		for _, value := range d.Values {
			fmt.Fprintf(&b, "%#v,", value)
		}
		b.WriteString("},")
	}

	if len(d.Vendors) > 0 {
		b.WriteString("Vendors:[]*dictionary.Vendor{")
		for _, vendor := range d.Vendors {
			fmt.Fprintf(&b, "%#v,", vendor)
		}
		b.WriteString("},")
	}

	b.WriteString("}")
	return b.String()
}

func (d *Dictionary) addAttribute(a *Attribute) {
	d.Attributes = append(d.Attributes, a)
	d.AttributesByOID.addAttribute(a.OID, a)
}

type AttributeType int

const (
	AttributeString AttributeType = iota + 1
	AttributeOctets
	AttributeIPAddr
	AttributeDate
	AttributeInteger
	AttributeIPv6Addr
	AttributeIPv6Prefix
	AttributeIFID
	AttributeInteger64

	AttributeVSA

	AttributeEther
	AttributeABinary
	AttributeByte
	AttributeShort
	AttributeSigned
	AttributeTLV
	AttributeIPv4Prefix
)

func (t AttributeType) String() string {
	switch t {
	case AttributeString:
		return "string"
	case AttributeOctets:
		return "octets"
	case AttributeIPAddr:
		return "ipaddr"
	case AttributeDate:
		return "date"
	case AttributeInteger:
		return "integer"
	case AttributeIPv6Addr:
		return "ipv6addr"
	case AttributeIPv6Prefix:
		return "ipv6prefix"
	case AttributeIFID:
		return "ifid"
	case AttributeInteger64:
		return "integer64"

	case AttributeVSA:
		return "vsa"

	case AttributeEther:
		return "ether"
	case AttributeABinary:
		return "abinary"
	case AttributeByte:
		return "byte"
	case AttributeShort:
		return "short"
	case AttributeSigned:
		return "signed"
	case AttributeTLV:
		return "tlv"
	case AttributeIPv4Prefix:
		return "ipv4prefix"
	}
	return "AttributeType(" + strconv.Itoa(int(t)) + ")"
}

type OID []int

func (o OID) Equals(other OID) bool {
	if len(o) != len(other) {
		return false
	}
	for i, n := 0, len(o); i < n; i++ {
		if o[i] != other[i] {
			return false
		}
	}
	return true
}

func (o OID) String() string {
	if len(o) == 0 {
		return ""
	}

	const maximumIntLength = 3
	b := make([]byte, 0, len(o)*(maximumIntLength+1)-1)
	for i, e := range o {
		if i > 0 {
			b = append(b, '.')
		}
		b = strconv.AppendInt(b, int64(e), 10)
	}
	return string(b)
}

const (
	EncryptUserPassword   = 1
	EncryptTunnelPassword = 2
)

type Attribute struct {
	Name string
	OID  OID
	Type AttributeType

	Size IntFlag

	FlagEncrypt IntFlag
	FlagHasTag  BoolFlag
	FlagConcat  BoolFlag
}

func (a *Attribute) HasTag() bool {
	return a.FlagHasTag.Valid && a.FlagHasTag.Bool
}

func (a *Attribute) Equals(o *Attribute) bool {
	if a == o {
		return true
	}
	if a == nil || o == nil {
		return false
	}

	if a.Name != o.Name || !a.OID.Equals(o.OID) || a.Type != o.Type {
		return false
	}

	if a.Size != o.Size {
		return false
	}

	if a.FlagEncrypt != o.FlagEncrypt || a.FlagHasTag != o.FlagHasTag || a.FlagConcat != o.FlagConcat {
		return false
	}

	return true
}

func normalizedType(t AttributeType) AttributeType {
	if t == AttributeString {
		return AttributeOctets
	}

	return t
}

func (a *Attribute) MostlyEquals(o *Attribute) bool {
	if a == o {
		return true
	}
	if a == nil || o == nil {
		return false
	}

	if a.Name != o.Name || !a.OID.Equals(o.OID) {
		return false
	}

	if normalizedType(a.Type) != normalizedType(o.Type) {
		return false
	}

	if a.FlagEncrypt != o.FlagEncrypt || a.FlagHasTag != o.FlagHasTag || a.FlagConcat != o.FlagConcat {
		return false
	}

	return true
}

func (a *Attribute) GoString() string {
	var b bytes.Buffer
	b.WriteString("&dictionary.Attribute{")

	fmt.Fprintf(&b, "Name:%#v,", a.Name)
	fmt.Fprintf(&b, "OID:%#v,", a.OID)
	fmt.Fprintf(&b, "Type:%#v,", a.Type)

	if a.Size.Valid {
		fmt.Fprintf(&b, "Size:%#v,", a.Size)
	}

	if a.FlagEncrypt.Valid {
		fmt.Fprintf(&b, "FlagEncrypt:%#v,", a.FlagEncrypt)
	}
	if a.FlagHasTag.Valid {
		fmt.Fprintf(&b, "FlagHasTag:%#v,", a.FlagHasTag)
	}
	if a.FlagConcat.Valid {
		fmt.Fprintf(&b, "FlagConcat:%#v,", a.FlagConcat)
	}

	b.WriteString("}")
	return b.String()
}

type Value struct {
	Attribute string
	Name      string
	Number    uint
}

type Vendor struct {
	Name   string
	Number uint

	TypeOctets   *int
	LengthOctets *int

	AttributesByOID AttributesOIDMap
	Attributes      []*Attribute
	Values          []*Value
}

func (a *Vendor) Equals(b *Vendor) bool {
	if a == b {
		return true
	}

	if a == nil || b == nil {
		return false
	}

	return a.Name == b.Name && a.Number == a.Number
}

func (v *Vendor) GetAttributeByOID(oid OID) *Attribute {
	return v.AttributesByOID.getAttribute(oid)
}

func (v *Vendor) addAttribute(a *Attribute) {
	v.Attributes = append(v.Attributes, a)
	v.AttributesByOID.addAttribute(a.OID, a)
}

func (v *Vendor) GetTypeOctets() int {
	if v.TypeOctets == nil {
		return 1
	}
	return *v.TypeOctets
}

func (v *Vendor) GetLengthOctets() int {
	if v.LengthOctets == nil {
		return 1
	}
	return *v.LengthOctets
}

func (v *Vendor) GoString() string {
	var b bytes.Buffer
	b.WriteString("&dictionary.Vendor{")

	fmt.Fprintf(&b, "Name:%#v,", v.Name)
	fmt.Fprintf(&b, "Number:%#v,", v.Number)

	fmt.Fprintf(&b, "TypeOctets:%#v,", v.TypeOctets)
	fmt.Fprintf(&b, "LengthOctets:%#v,", v.LengthOctets)

	if len(v.Attributes) > 0 {
		b.WriteString("Attributes:[]*dictionary.Attribute{")
		for _, attr := range v.Attributes {
			fmt.Fprintf(&b, "%#v,", attr)
		}
		b.WriteString("},")
	}
	if len(v.Values) > 0 {
		b.WriteString("Values:[]*dictionary.Value{")
		for _, value := range v.Values {
			fmt.Fprintf(&b, "%#v,", value)
		}
		b.WriteString("},")
	}

	b.WriteString("}")
	return b.String()
}

type IntFlag struct {
	Int   int
	Valid bool
}

type BoolFlag struct {
	Bool  bool
	Valid bool
}
