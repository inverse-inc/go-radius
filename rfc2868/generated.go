// Code generated by radius-dict-gen. DO NOT EDIT.

package rfc2868

import (
	"crypto/rand"
	"strconv"

	radius "github.com/inverse-inc/go-radius"
)

const (
	TunnelType_Type           radius.Type = 64
	TunnelMediumType_Type     radius.Type = 65
	TunnelClientEndpoint_Type radius.Type = 66
	TunnelServerEndpoint_Type radius.Type = 67
	TunnelPassword_Type       radius.Type = 69
	TunnelPrivateGroupID_Type radius.Type = 81
	TunnelAssignmentID_Type   radius.Type = 82
	TunnelPreference_Type     radius.Type = 83
	TunnelClientAuthID_Type   radius.Type = 90
	TunnelServerAuthID_Type   radius.Type = 91
)

type TunnelType uint32

const (
	TunnelType_Value_PPTP   TunnelType = 1
	TunnelType_Value_L2F    TunnelType = 2
	TunnelType_Value_L2TP   TunnelType = 3
	TunnelType_Value_ATMP   TunnelType = 4
	TunnelType_Value_VTP    TunnelType = 5
	TunnelType_Value_AH     TunnelType = 6
	TunnelType_Value_IP     TunnelType = 7
	TunnelType_Value_MINIP  TunnelType = 8
	TunnelType_Value_ESP    TunnelType = 9
	TunnelType_Value_GRE    TunnelType = 10
	TunnelType_Value_DVS    TunnelType = 11
	TunnelType_Value_IPInIP TunnelType = 12
)

var TunnelType_Strings = map[TunnelType]string{
	TunnelType_Value_PPTP:   "PPTP",
	TunnelType_Value_L2F:    "L2F",
	TunnelType_Value_L2TP:   "L2TP",
	TunnelType_Value_ATMP:   "ATMP",
	TunnelType_Value_VTP:    "VTP",
	TunnelType_Value_AH:     "AH",
	TunnelType_Value_IP:     "IP",
	TunnelType_Value_MINIP:  "MIN-IP",
	TunnelType_Value_ESP:    "ESP",
	TunnelType_Value_GRE:    "GRE",
	TunnelType_Value_DVS:    "DVS",
	TunnelType_Value_IPInIP: "IP-in-IP",
}

func (a TunnelType) String() string {
	if str, ok := TunnelType_Strings[a]; ok {
		return str
	}
	return "TunnelType(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func TunnelType_Add(p *radius.Packet, tag byte, value TunnelType) (err error) {
	a := radius.NewInteger(uint32(value))
	if tag >= 0x01 && tag <= 0x1F {
		a[0] = tag
	} else {
		a[0] = 0x00
	}
	p.Add(TunnelType_Type, a)
	return
}

func TunnelType_Get(p *radius.Packet) (tag byte, value TunnelType) {
	tag, value, _ = TunnelType_Lookup(p)
	return
}

func TunnelType_Gets(p *radius.Packet) (tags []byte, values []TunnelType, err error) {
	var i uint32
	for _, attr := range p.Attributes[TunnelType_Type] {
		var tag byte
		if len(attr) >= 1 && attr[0] <= 0x1F {
			tag = attr[0]
			attr[0] = 0x00
		}
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, TunnelType(i))
		tags = append(tags, tag)
	}
	return
}

func TunnelType_Lookup(p *radius.Packet) (tag byte, value TunnelType, err error) {
	a, ok := p.Lookup(TunnelType_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	if len(a) >= 1 && a[0] <= 0x1F {
		tag = a[0]
		a[0] = 0x00
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = TunnelType(i)
	return
}

func TunnelType_Set(p *radius.Packet, tag byte, value TunnelType) (err error) {
	a := radius.NewInteger(uint32(value))
	if tag >= 0x01 && tag <= 0x1F {
		a[0] = tag
	} else {
		a[0] = 0x00
	}
	p.Set(TunnelType_Type, a)
	return
}

func TunnelType_Del(p *radius.Packet) {
	p.Attributes.Del(TunnelType_Type)
}

type TunnelMediumType uint32

const (
	TunnelMediumType_Value_IPv4        TunnelMediumType = 1
	TunnelMediumType_Value_IPv6        TunnelMediumType = 2
	TunnelMediumType_Value_NSAP        TunnelMediumType = 3
	TunnelMediumType_Value_HDLC        TunnelMediumType = 4
	TunnelMediumType_Value_BBN1822     TunnelMediumType = 5
	TunnelMediumType_Value_IEEE802     TunnelMediumType = 6
	TunnelMediumType_Value_E163        TunnelMediumType = 7
	TunnelMediumType_Value_E164        TunnelMediumType = 8
	TunnelMediumType_Value_F69         TunnelMediumType = 9
	TunnelMediumType_Value_X121        TunnelMediumType = 10
	TunnelMediumType_Value_IPX         TunnelMediumType = 11
	TunnelMediumType_Value_Appletalk   TunnelMediumType = 12
	TunnelMediumType_Value_DecNetIV    TunnelMediumType = 13
	TunnelMediumType_Value_BanyanVines TunnelMediumType = 14
	TunnelMediumType_Value_E164NSAP    TunnelMediumType = 15
)

var TunnelMediumType_Strings = map[TunnelMediumType]string{
	TunnelMediumType_Value_IPv4:        "IPv4",
	TunnelMediumType_Value_IPv6:        "IPv6",
	TunnelMediumType_Value_NSAP:        "NSAP",
	TunnelMediumType_Value_HDLC:        "HDLC",
	TunnelMediumType_Value_BBN1822:     "BBN-1822",
	TunnelMediumType_Value_IEEE802:     "IEEE-802",
	TunnelMediumType_Value_E163:        "E.163",
	TunnelMediumType_Value_E164:        "E.164",
	TunnelMediumType_Value_F69:         "F.69",
	TunnelMediumType_Value_X121:        "X.121",
	TunnelMediumType_Value_IPX:         "IPX",
	TunnelMediumType_Value_Appletalk:   "Appletalk",
	TunnelMediumType_Value_DecNetIV:    "DecNet-IV",
	TunnelMediumType_Value_BanyanVines: "Banyan-Vines",
	TunnelMediumType_Value_E164NSAP:    "E.164-NSAP",
}

func (a TunnelMediumType) String() string {
	if str, ok := TunnelMediumType_Strings[a]; ok {
		return str
	}
	return "TunnelMediumType(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func TunnelMediumType_Add(p *radius.Packet, tag byte, value TunnelMediumType) (err error) {
	a := radius.NewInteger(uint32(value))
	if tag >= 0x01 && tag <= 0x1F {
		a[0] = tag
	} else {
		a[0] = 0x00
	}
	p.Add(TunnelMediumType_Type, a)
	return
}

func TunnelMediumType_Get(p *radius.Packet) (tag byte, value TunnelMediumType) {
	tag, value, _ = TunnelMediumType_Lookup(p)
	return
}

func TunnelMediumType_Gets(p *radius.Packet) (tags []byte, values []TunnelMediumType, err error) {
	var i uint32
	for _, attr := range p.Attributes[TunnelMediumType_Type] {
		var tag byte
		if len(attr) >= 1 && attr[0] <= 0x1F {
			tag = attr[0]
			attr[0] = 0x00
		}
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, TunnelMediumType(i))
		tags = append(tags, tag)
	}
	return
}

func TunnelMediumType_Lookup(p *radius.Packet) (tag byte, value TunnelMediumType, err error) {
	a, ok := p.Lookup(TunnelMediumType_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	if len(a) >= 1 && a[0] <= 0x1F {
		tag = a[0]
		a[0] = 0x00
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = TunnelMediumType(i)
	return
}

func TunnelMediumType_Set(p *radius.Packet, tag byte, value TunnelMediumType) (err error) {
	a := radius.NewInteger(uint32(value))
	if tag >= 0x01 && tag <= 0x1F {
		a[0] = tag
	} else {
		a[0] = 0x00
	}
	p.Set(TunnelMediumType_Type, a)
	return
}

func TunnelMediumType_Del(p *radius.Packet) {
	p.Attributes.Del(TunnelMediumType_Type)
}

func TunnelClientEndpoint_Add(p *radius.Packet, tag byte, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Add(TunnelClientEndpoint_Type, a)
	return
}

func TunnelClientEndpoint_AddString(p *radius.Packet, tag byte, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Add(TunnelClientEndpoint_Type, a)
	return
}

func TunnelClientEndpoint_Get(p *radius.Packet) (tag byte, value []byte) {
	tag, value, _ = TunnelClientEndpoint_Lookup(p)
	return
}

func TunnelClientEndpoint_GetString(p *radius.Packet) (tag byte, value string) {
	_, value, _ = TunnelClientEndpoint_LookupString(p)
	return
}

func TunnelClientEndpoint_Gets(p *radius.Packet) (tags []byte, values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[TunnelClientEndpoint_Type] {
		var tag byte
		if len(attr) >= 1 && attr[0] <= 0x1F {
			tag = attr[0]
			attr = attr[1:]
		}
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
		tags = append(tags, tag)
	}
	return
}

func TunnelClientEndpoint_GetStrings(p *radius.Packet) (tags []byte, values []string, err error) {
	var i string
	for _, attr := range p.Attributes[TunnelClientEndpoint_Type] {
		var tag byte
		if len(attr) >= 1 && attr[0] <= 0x1F {
			tag = attr[0]
			attr = attr[1:]
		}
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
		tags = append(tags, tag)
	}
	return
}

func TunnelClientEndpoint_Lookup(p *radius.Packet) (tag byte, value []byte, err error) {
	a, ok := p.Lookup(TunnelClientEndpoint_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	if len(a) >= 1 && a[0] <= 0x1F {
		tag = a[0]
		a = a[1:]
	}
	value = radius.Bytes(a)
	return
}

func TunnelClientEndpoint_LookupString(p *radius.Packet) (tag byte, value string, err error) {
	a, ok := p.Lookup(TunnelClientEndpoint_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	if len(a) >= 1 && a[0] <= 0x1F {
		tag = a[0]
		a = a[1:]
	}
	value = radius.String(a)
	return
}

func TunnelClientEndpoint_Set(p *radius.Packet, tag byte, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Set(TunnelClientEndpoint_Type, a)
	return
}

func TunnelClientEndpoint_SetString(p *radius.Packet, tag byte, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Set(TunnelClientEndpoint_Type, a)
	return
}

func TunnelClientEndpoint_Del(p *radius.Packet) {
	p.Attributes.Del(TunnelClientEndpoint_Type)
}

func TunnelServerEndpoint_Add(p *radius.Packet, tag byte, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Add(TunnelServerEndpoint_Type, a)
	return
}

func TunnelServerEndpoint_AddString(p *radius.Packet, tag byte, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Add(TunnelServerEndpoint_Type, a)
	return
}

func TunnelServerEndpoint_Get(p *radius.Packet) (tag byte, value []byte) {
	tag, value, _ = TunnelServerEndpoint_Lookup(p)
	return
}

func TunnelServerEndpoint_GetString(p *radius.Packet) (tag byte, value string) {
	_, value, _ = TunnelServerEndpoint_LookupString(p)
	return
}

func TunnelServerEndpoint_Gets(p *radius.Packet) (tags []byte, values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[TunnelServerEndpoint_Type] {
		var tag byte
		if len(attr) >= 1 && attr[0] <= 0x1F {
			tag = attr[0]
			attr = attr[1:]
		}
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
		tags = append(tags, tag)
	}
	return
}

func TunnelServerEndpoint_GetStrings(p *radius.Packet) (tags []byte, values []string, err error) {
	var i string
	for _, attr := range p.Attributes[TunnelServerEndpoint_Type] {
		var tag byte
		if len(attr) >= 1 && attr[0] <= 0x1F {
			tag = attr[0]
			attr = attr[1:]
		}
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
		tags = append(tags, tag)
	}
	return
}

func TunnelServerEndpoint_Lookup(p *radius.Packet) (tag byte, value []byte, err error) {
	a, ok := p.Lookup(TunnelServerEndpoint_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	if len(a) >= 1 && a[0] <= 0x1F {
		tag = a[0]
		a = a[1:]
	}
	value = radius.Bytes(a)
	return
}

func TunnelServerEndpoint_LookupString(p *radius.Packet) (tag byte, value string, err error) {
	a, ok := p.Lookup(TunnelServerEndpoint_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	if len(a) >= 1 && a[0] <= 0x1F {
		tag = a[0]
		a = a[1:]
	}
	value = radius.String(a)
	return
}

func TunnelServerEndpoint_Set(p *radius.Packet, tag byte, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Set(TunnelServerEndpoint_Type, a)
	return
}

func TunnelServerEndpoint_SetString(p *radius.Packet, tag byte, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Set(TunnelServerEndpoint_Type, a)
	return
}

func TunnelServerEndpoint_Del(p *radius.Packet) {
	p.Attributes.Del(TunnelServerEndpoint_Type)
}

func TunnelPassword_Add(p *radius.Packet, tag byte, value []byte) (err error) {
	var a radius.Attribute
	var salt [2]byte
	_, err = rand.Read(salt[:])
	if err != nil {
		return
	}
	a, err = radius.NewTunnelPassword(value, salt[:], p.Secret, p.Authenticator[:])
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Add(TunnelPassword_Type, a)
	return
}

func TunnelPassword_AddString(p *radius.Packet, tag byte, value string) (err error) {
	var a radius.Attribute
	var salt [2]byte
	_, err = rand.Read(salt[:])
	if err != nil {
		return
	}
	a, err = radius.NewTunnelPassword([]byte(value), salt[:], p.Secret, p.Authenticator[:])
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Add(TunnelPassword_Type, a)
	return
}

func TunnelPassword_Get(p *radius.Packet) (tag byte, value []byte) {
	tag, value, _ = TunnelPassword_Lookup(p)
	return
}

func TunnelPassword_GetString(p *radius.Packet) (tag byte, value string) {
	_, value, _ = TunnelPassword_LookupString(p)
	return
}

func TunnelPassword_Gets(p *radius.Packet) (tags []byte, values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[TunnelPassword_Type] {
		var tag byte
		if len(attr) >= 1 && attr[0] <= 0x1F {
			tag = attr[0]
			attr = attr[1:]
		}
		i, _, err = radius.TunnelPassword(attr, p.Secret, p.Authenticator[:])
		if err != nil {
			return
		}
		values = append(values, i)
		tags = append(tags, tag)
	}
	return
}

func TunnelPassword_GetStrings(p *radius.Packet) (tags []byte, values []string, err error) {
	var i string
	for _, attr := range p.Attributes[TunnelPassword_Type] {
		var tag byte
		if len(attr) >= 1 && attr[0] <= 0x1F {
			tag = attr[0]
			attr = attr[1:]
		}
		var up []byte
		up, _, err = radius.TunnelPassword(attr, p.Secret, p.Authenticator[:])
		if err == nil {
			i = string(up)
		}
		if err != nil {
			return
		}
		values = append(values, i)
		tags = append(tags, tag)
	}
	return
}

func TunnelPassword_Lookup(p *radius.Packet) (tag byte, value []byte, err error) {
	a, ok := p.Lookup(TunnelPassword_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	if len(a) >= 1 && a[0] <= 0x1F {
		tag = a[0]
		a = a[1:]
	}
	value, _, err = radius.TunnelPassword(a, p.Secret, p.Authenticator[:])
	return
}

func TunnelPassword_LookupString(p *radius.Packet) (tag byte, value string, err error) {
	a, ok := p.Lookup(TunnelPassword_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	if len(a) >= 1 && a[0] <= 0x1F {
		tag = a[0]
		a = a[1:]
	}
	var b []byte
	b, _, err = radius.TunnelPassword(a, p.Secret, p.Authenticator[:])
	if err == nil {
		value = string(b)
	}
	return
}

func TunnelPassword_Set(p *radius.Packet, tag byte, value []byte) (err error) {
	var a radius.Attribute
	var salt [2]byte
	_, err = rand.Read(salt[:])
	if err != nil {
		return
	}
	a, err = radius.NewTunnelPassword(value, salt[:], p.Secret, p.Authenticator[:])
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Set(TunnelPassword_Type, a)
	return
}

func TunnelPassword_SetString(p *radius.Packet, tag byte, value string) (err error) {
	var a radius.Attribute
	var salt [2]byte
	_, err = rand.Read(salt[:])
	if err != nil {
		return
	}
	a, err = radius.NewTunnelPassword([]byte(value), salt[:], p.Secret, p.Authenticator[:])
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Set(TunnelPassword_Type, a)
	return
}

func TunnelPassword_Del(p *radius.Packet) {
	p.Attributes.Del(TunnelPassword_Type)
}

func TunnelPrivateGroupID_Add(p *radius.Packet, tag byte, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Add(TunnelPrivateGroupID_Type, a)
	return
}

func TunnelPrivateGroupID_AddString(p *radius.Packet, tag byte, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Add(TunnelPrivateGroupID_Type, a)
	return
}

func TunnelPrivateGroupID_Get(p *radius.Packet) (tag byte, value []byte) {
	tag, value, _ = TunnelPrivateGroupID_Lookup(p)
	return
}

func TunnelPrivateGroupID_GetString(p *radius.Packet) (tag byte, value string) {
	_, value, _ = TunnelPrivateGroupID_LookupString(p)
	return
}

func TunnelPrivateGroupID_Gets(p *radius.Packet) (tags []byte, values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[TunnelPrivateGroupID_Type] {
		var tag byte
		if len(attr) >= 1 && attr[0] <= 0x1F {
			tag = attr[0]
			attr = attr[1:]
		}
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
		tags = append(tags, tag)
	}
	return
}

func TunnelPrivateGroupID_GetStrings(p *radius.Packet) (tags []byte, values []string, err error) {
	var i string
	for _, attr := range p.Attributes[TunnelPrivateGroupID_Type] {
		var tag byte
		if len(attr) >= 1 && attr[0] <= 0x1F {
			tag = attr[0]
			attr = attr[1:]
		}
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
		tags = append(tags, tag)
	}
	return
}

func TunnelPrivateGroupID_Lookup(p *radius.Packet) (tag byte, value []byte, err error) {
	a, ok := p.Lookup(TunnelPrivateGroupID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	if len(a) >= 1 && a[0] <= 0x1F {
		tag = a[0]
		a = a[1:]
	}
	value = radius.Bytes(a)
	return
}

func TunnelPrivateGroupID_LookupString(p *radius.Packet) (tag byte, value string, err error) {
	a, ok := p.Lookup(TunnelPrivateGroupID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	if len(a) >= 1 && a[0] <= 0x1F {
		tag = a[0]
		a = a[1:]
	}
	value = radius.String(a)
	return
}

func TunnelPrivateGroupID_Set(p *radius.Packet, tag byte, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Set(TunnelPrivateGroupID_Type, a)
	return
}

func TunnelPrivateGroupID_SetString(p *radius.Packet, tag byte, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Set(TunnelPrivateGroupID_Type, a)
	return
}

func TunnelPrivateGroupID_Del(p *radius.Packet) {
	p.Attributes.Del(TunnelPrivateGroupID_Type)
}

func TunnelAssignmentID_Add(p *radius.Packet, tag byte, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Add(TunnelAssignmentID_Type, a)
	return
}

func TunnelAssignmentID_AddString(p *radius.Packet, tag byte, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Add(TunnelAssignmentID_Type, a)
	return
}

func TunnelAssignmentID_Get(p *radius.Packet) (tag byte, value []byte) {
	tag, value, _ = TunnelAssignmentID_Lookup(p)
	return
}

func TunnelAssignmentID_GetString(p *radius.Packet) (tag byte, value string) {
	_, value, _ = TunnelAssignmentID_LookupString(p)
	return
}

func TunnelAssignmentID_Gets(p *radius.Packet) (tags []byte, values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[TunnelAssignmentID_Type] {
		var tag byte
		if len(attr) >= 1 && attr[0] <= 0x1F {
			tag = attr[0]
			attr = attr[1:]
		}
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
		tags = append(tags, tag)
	}
	return
}

func TunnelAssignmentID_GetStrings(p *radius.Packet) (tags []byte, values []string, err error) {
	var i string
	for _, attr := range p.Attributes[TunnelAssignmentID_Type] {
		var tag byte
		if len(attr) >= 1 && attr[0] <= 0x1F {
			tag = attr[0]
			attr = attr[1:]
		}
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
		tags = append(tags, tag)
	}
	return
}

func TunnelAssignmentID_Lookup(p *radius.Packet) (tag byte, value []byte, err error) {
	a, ok := p.Lookup(TunnelAssignmentID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	if len(a) >= 1 && a[0] <= 0x1F {
		tag = a[0]
		a = a[1:]
	}
	value = radius.Bytes(a)
	return
}

func TunnelAssignmentID_LookupString(p *radius.Packet) (tag byte, value string, err error) {
	a, ok := p.Lookup(TunnelAssignmentID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	if len(a) >= 1 && a[0] <= 0x1F {
		tag = a[0]
		a = a[1:]
	}
	value = radius.String(a)
	return
}

func TunnelAssignmentID_Set(p *radius.Packet, tag byte, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Set(TunnelAssignmentID_Type, a)
	return
}

func TunnelAssignmentID_SetString(p *radius.Packet, tag byte, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Set(TunnelAssignmentID_Type, a)
	return
}

func TunnelAssignmentID_Del(p *radius.Packet) {
	p.Attributes.Del(TunnelAssignmentID_Type)
}

type TunnelPreference uint32

var TunnelPreference_Strings = map[TunnelPreference]string{}

func (a TunnelPreference) String() string {
	if str, ok := TunnelPreference_Strings[a]; ok {
		return str
	}
	return "TunnelPreference(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func TunnelPreference_Add(p *radius.Packet, tag byte, value TunnelPreference) (err error) {
	a := radius.NewInteger(uint32(value))
	if tag >= 0x01 && tag <= 0x1F {
		a[0] = tag
	} else {
		a[0] = 0x00
	}
	p.Add(TunnelPreference_Type, a)
	return
}

func TunnelPreference_Get(p *radius.Packet) (tag byte, value TunnelPreference) {
	tag, value, _ = TunnelPreference_Lookup(p)
	return
}

func TunnelPreference_Gets(p *radius.Packet) (tags []byte, values []TunnelPreference, err error) {
	var i uint32
	for _, attr := range p.Attributes[TunnelPreference_Type] {
		var tag byte
		if len(attr) >= 1 && attr[0] <= 0x1F {
			tag = attr[0]
			attr[0] = 0x00
		}
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, TunnelPreference(i))
		tags = append(tags, tag)
	}
	return
}

func TunnelPreference_Lookup(p *radius.Packet) (tag byte, value TunnelPreference, err error) {
	a, ok := p.Lookup(TunnelPreference_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	if len(a) >= 1 && a[0] <= 0x1F {
		tag = a[0]
		a[0] = 0x00
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = TunnelPreference(i)
	return
}

func TunnelPreference_Set(p *radius.Packet, tag byte, value TunnelPreference) (err error) {
	a := radius.NewInteger(uint32(value))
	if tag >= 0x01 && tag <= 0x1F {
		a[0] = tag
	} else {
		a[0] = 0x00
	}
	p.Set(TunnelPreference_Type, a)
	return
}

func TunnelPreference_Del(p *radius.Packet) {
	p.Attributes.Del(TunnelPreference_Type)
}

func TunnelClientAuthID_Add(p *radius.Packet, tag byte, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Add(TunnelClientAuthID_Type, a)
	return
}

func TunnelClientAuthID_AddString(p *radius.Packet, tag byte, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Add(TunnelClientAuthID_Type, a)
	return
}

func TunnelClientAuthID_Get(p *radius.Packet) (tag byte, value []byte) {
	tag, value, _ = TunnelClientAuthID_Lookup(p)
	return
}

func TunnelClientAuthID_GetString(p *radius.Packet) (tag byte, value string) {
	_, value, _ = TunnelClientAuthID_LookupString(p)
	return
}

func TunnelClientAuthID_Gets(p *radius.Packet) (tags []byte, values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[TunnelClientAuthID_Type] {
		var tag byte
		if len(attr) >= 1 && attr[0] <= 0x1F {
			tag = attr[0]
			attr = attr[1:]
		}
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
		tags = append(tags, tag)
	}
	return
}

func TunnelClientAuthID_GetStrings(p *radius.Packet) (tags []byte, values []string, err error) {
	var i string
	for _, attr := range p.Attributes[TunnelClientAuthID_Type] {
		var tag byte
		if len(attr) >= 1 && attr[0] <= 0x1F {
			tag = attr[0]
			attr = attr[1:]
		}
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
		tags = append(tags, tag)
	}
	return
}

func TunnelClientAuthID_Lookup(p *radius.Packet) (tag byte, value []byte, err error) {
	a, ok := p.Lookup(TunnelClientAuthID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	if len(a) >= 1 && a[0] <= 0x1F {
		tag = a[0]
		a = a[1:]
	}
	value = radius.Bytes(a)
	return
}

func TunnelClientAuthID_LookupString(p *radius.Packet) (tag byte, value string, err error) {
	a, ok := p.Lookup(TunnelClientAuthID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	if len(a) >= 1 && a[0] <= 0x1F {
		tag = a[0]
		a = a[1:]
	}
	value = radius.String(a)
	return
}

func TunnelClientAuthID_Set(p *radius.Packet, tag byte, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Set(TunnelClientAuthID_Type, a)
	return
}

func TunnelClientAuthID_SetString(p *radius.Packet, tag byte, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Set(TunnelClientAuthID_Type, a)
	return
}

func TunnelClientAuthID_Del(p *radius.Packet) {
	p.Attributes.Del(TunnelClientAuthID_Type)
}

func TunnelServerAuthID_Add(p *radius.Packet, tag byte, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Add(TunnelServerAuthID_Type, a)
	return
}

func TunnelServerAuthID_AddString(p *radius.Packet, tag byte, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Add(TunnelServerAuthID_Type, a)
	return
}

func TunnelServerAuthID_Get(p *radius.Packet) (tag byte, value []byte) {
	tag, value, _ = TunnelServerAuthID_Lookup(p)
	return
}

func TunnelServerAuthID_GetString(p *radius.Packet) (tag byte, value string) {
	_, value, _ = TunnelServerAuthID_LookupString(p)
	return
}

func TunnelServerAuthID_Gets(p *radius.Packet) (tags []byte, values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[TunnelServerAuthID_Type] {
		var tag byte
		if len(attr) >= 1 && attr[0] <= 0x1F {
			tag = attr[0]
			attr = attr[1:]
		}
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
		tags = append(tags, tag)
	}
	return
}

func TunnelServerAuthID_GetStrings(p *radius.Packet) (tags []byte, values []string, err error) {
	var i string
	for _, attr := range p.Attributes[TunnelServerAuthID_Type] {
		var tag byte
		if len(attr) >= 1 && attr[0] <= 0x1F {
			tag = attr[0]
			attr = attr[1:]
		}
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
		tags = append(tags, tag)
	}
	return
}

func TunnelServerAuthID_Lookup(p *radius.Packet) (tag byte, value []byte, err error) {
	a, ok := p.Lookup(TunnelServerAuthID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	if len(a) >= 1 && a[0] <= 0x1F {
		tag = a[0]
		a = a[1:]
	}
	value = radius.Bytes(a)
	return
}

func TunnelServerAuthID_LookupString(p *radius.Packet) (tag byte, value string, err error) {
	a, ok := p.Lookup(TunnelServerAuthID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	if len(a) >= 1 && a[0] <= 0x1F {
		tag = a[0]
		a = a[1:]
	}
	value = radius.String(a)
	return
}

func TunnelServerAuthID_Set(p *radius.Packet, tag byte, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Set(TunnelServerAuthID_Type, a)
	return
}

func TunnelServerAuthID_SetString(p *radius.Packet, tag byte, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	if tag <= 0x1F {
		a = append(radius.Attribute{tag}, a...)
	}
	p.Set(TunnelServerAuthID_Type, a)
	return
}

func TunnelServerAuthID_Del(p *radius.Packet) {
	p.Attributes.Del(TunnelServerAuthID_Type)
}
