package dictionary

import (
	"bytes"
	"fmt"
	"github.com/go-test/deep"
	"reflect"
	"testing"
)

func TestParseOID(t *testing.T) {
	tests := []struct {
		String string
		OID    OID
	}{
		{"", nil},
		{".", nil},
		{"..3", nil},
		{"1..3", nil},
		{".1.2.3", nil},

		{"1", OID{1}},
		{"123", OID{123}},
		{"123.1", OID{123, 1}},
		{"123.1.55", OID{123, 1, 55}},
	}

	for _, tt := range tests {
		out := parseOID(tt.String)
		if !tt.OID.Equals(out) {
			t.Errorf("input %#v: got %#v; expecting %#v", tt.String, out, tt.OID)
		}
	}
}

func TestParser(t *testing.T) {
	parser := Parser{
		Opener: &FileSystemOpener{
			Root: "testdata",
		},
	}

	d, err := parser.ParseFile("simple.dictionary")
	if err != nil {
		t.Fatal(err)
	}

	attributes := []*Attribute{
		{
			Name: "User-Name",
			OID:  OID{1},
			Type: AttributeString,
		},
		{
			Name:        "User-Password",
			OID:         OID{2},
			Type:        AttributeOctets,
			FlagEncrypt: IntFlag{1, true},
		},
		{
			Name: "Mode",
			OID:  OID{127},
			Type: AttributeInteger,
		},
		{
			Name: "ARAP-Challenge-Response",
			OID:  OID{84},
			Type: AttributeOctets,
			Size: IntFlag{8, true},
		},
	}
	expected := &Dictionary{
		AttributesByOID: AttributesOIDMap{
			Map: map[int]*AttributesOIDMap{
				1: &AttributesOIDMap{
					Attribute: attributes[0],
				},
				2: &AttributesOIDMap{
					Attribute: attributes[1],
				},
				127: &AttributesOIDMap{
					Attribute: attributes[2],
				},
				84: &AttributesOIDMap{
					Attribute: attributes[3],
				},
			},
		},
		Attributes: attributes,
		Values: []*Value{
			{
				Attribute: "Mode",
				Name:      "Full",
				Number:    1,
			},
			{
				Attribute: "Mode",
				Name:      "Half",
				Number:    2,
			},
			{
				Attribute: "Mode",
				Name:      "Quarter",
				Number:    4,
			},
		},
	}

	if !reflect.DeepEqual(d, expected) {
		t.Fatalf("got %s, expected %s", dictString(d), dictString(expected))
	}
}

func TestParser_recursiveinclude(t *testing.T) {
	parser := Parser{
		Opener: &FileSystemOpener{
			Root: "testdata",
		},
	}

	d, err := parser.ParseFile("recursive_1.dictionary")
	pErr, ok := err.(*ParseError)
	if !ok || pErr == nil || d != nil {
		t.Fatalf("got %v, expected *ParseError", pErr)
	}
	if _, ok := pErr.Inner.(*RecursiveIncludeError); !ok {
		t.Fatalf("got %v, expected *RecursiveIncludeError", pErr.Inner)
	}
}

func TestParser_override(t *testing.T) {
	parser := Parser{
		Opener: &FileSystemOpener{
			Root: "testdata",
		},
	}

	d, err := parser.ParseFile("override.dictionary")
	if err != nil {
		t.Fatal(err)
	}

	attributes := []*Attribute{
		{
			Name: "Test-Name",
			OID:  OID{5},
			Type: AttributeString,
		},
		{
			Name: "Test-Name2",
			OID:  OID{5},
			Type: AttributeString,
		},
	}
	expected := &Dictionary{
		AttributesByOID: AttributesOIDMap{
			Map: map[int]*AttributesOIDMap{
				5: &AttributesOIDMap{
					Attribute: attributes[1],
				},
			},
		},
		Attributes: attributes,
	}

	if diff := deep.Equal(d, expected); diff != nil {
		t.Error(diff)
	}

}

func writeAttributesOIDMap(b *bytes.Buffer, amap *AttributesOIDMap, indent string) {
	/*
	       if amap.Attribute != nil {
	           attr := amap.Attribute
	   		b.WriteString(fmt.Sprintf("%s: %q %q %q %#v %#v\n",indent , attr.Name, attr.OID, attr.Type, attr.FlagHasTag, attr.FlagEncrypt))
	       }
	*/
	b.WriteString(fmt.Sprintf("%s%#v\n", indent, amap))
}

func dictString(d *Dictionary) string {
	var b bytes.Buffer
	b.WriteString("dictionary.Dictionary\n")

	b.WriteString("\tAttributesByOID:\n")
	for _, attr := range d.AttributesByOID.Map {
		writeAttributesOIDMap(&b, attr, "\t\t")
	}
	b.WriteString("\tAttributes:\n")
	for _, attr := range d.Attributes {
		b.WriteString(fmt.Sprintf("\t\t%q %q %q %#v %#v\n", attr.Name, attr.OID, attr.Type, attr.FlagHasTag, attr.FlagEncrypt))
	}

	b.WriteString("\tValues:\n")
	for _, value := range d.Values {
		b.WriteString(fmt.Sprintf("\t\t%q %q %d\n", value.Attribute, value.Name, value.Number))
	}

	b.WriteString("\tVendors:\n")
	for _, vendor := range d.Vendors {
		b.WriteString(fmt.Sprintf("\t\t%q %d\n", vendor.Name, vendor.Number))

		b.WriteString("\t\tAttributes:\n")
		for _, attr := range vendor.Attributes {
			b.WriteString(fmt.Sprintf("\t\t%q %q %q %#v %#v\n", attr.Name, attr.OID, attr.Type, attr.FlagHasTag, attr.FlagEncrypt))
		}

		b.WriteString("\t\tValues:\n")
		for _, value := range vendor.Values {
			b.WriteString(fmt.Sprintf("\t\t%q %q %d\n", value.Attribute, value.Name, value.Number))
		}
	}

	return b.String()
}
