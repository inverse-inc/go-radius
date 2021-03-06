package dictionary

import (
	"github.com/go-test/deep"
	"testing"
)

func TestMerge(t *testing.T) {
	parser := &Parser{
		Opener: &FileSystemOpener{
			Root: "testdata",
		},
	}
	d1, err := parser.ParseFile("merge_1.dictionary")
	if err != nil {
		t.Fatal(err)
	}

	d2, err := parser.ParseFile("merge_2.dictionary")
	if err != nil {
		t.Fatal(err)
	}

	merged, err := Merge(d1, d2)
	if err != nil {
		t.Fatal(err)
	}

	vendorAttributes := []*Attribute{
		{
			Name: "Test-Vendor-Name",
			Type: AttributeString,
			OID:  OID{5},
		},
		{
			Name: "Test-Vendor-Int",
			Type: AttributeInteger,
			OID:  OID{10},
		},
	}
	expected := &Dictionary{
		Vendors: []*Vendor{
			{
				Name:       "Test",
				Number:     32473,
				Attributes: vendorAttributes,
				AttributesByOID: AttributesOIDMap{
					Map: map[int]*AttributesOIDMap{
						5: &AttributesOIDMap{
							Attribute: vendorAttributes[0],
						},
						10: &AttributesOIDMap{
							Attribute: vendorAttributes[1],
						},
					},
				},
			},
		},
	}

	if diff := deep.Equal(merged, expected); diff != nil {
		t.Error(diff)
	}

}
