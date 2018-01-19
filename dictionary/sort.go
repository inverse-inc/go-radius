package dictionary

import (
	"sort"
	"strconv"
)

func SortAttributes(attrs []*Attribute) {
	sort.Sort(sortAttributes(attrs))
}

type sortAttributes []*Attribute

func (s sortAttributes) Len() int { return len(s) }

func (s sortAttributes) Less(i, j int) bool {
	iOID, _ := strconv.Atoi(s[i].OID)
	jOID, _ := strconv.Atoi(s[j].OID)
	return iOID < jOID
}

func (s sortAttributes) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func SortValues(values []*Value) {
	sort.Sort(sortValues(values))
}

type sortValues []*Value

func (s sortValues) Len() int           { return len(s) }
func (s sortValues) Less(i, j int) bool { return s[i].Number < s[j].Number }
func (s sortValues) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
