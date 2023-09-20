package packet

import (
	"bytes"
	"fmt"

	bnet "github.com/bio-routing/bio-rd/net"
	"github.com/bio-routing/bio-rd/protocols/bgp/types"
	"github.com/bio-routing/bio-rd/util/decode"
	"github.com/bio-routing/bio-rd/util/log"
	"github.com/bio-routing/tflow2/convert"
)

const (
	LSMetric       = 1095
	LSPrefixMetric = 1155
	LSSPFCap       = 1180
	LSSeqNum       = 1181
	LSIPv4PfxLen   = 1182
	LSIPv6PfxLen   = 1183
	LSSPFStatus    = 1184
)

// LinkState represents a LinkState Information
type LinkState struct {
	Value  interface{}
	Type   uint16
	Length uint16
	Next   *LinkState
}

type Metric struct {
	Metric uint32
}

type PrefixMetric struct {
	PrefixMetric uint32
}

type SequenceNumber struct {
	SequenceNumber uint64
}

type PfxLen struct {
	PfxLen uint8
}

type SPFCap struct {
	SPFCap uint8
}

type SPFStatus struct {
	SPFStatus uint8
}

func decodeLinkStates(buf *bytes.Buffer, length uint16) (*LinkState, error) {
	var ret *LinkState
	var eol *LinkState
	var ls *LinkState
	var err error
	var consumed uint16
	p := uint16(0)

	for p < length {

		ls, consumed, err = decodeLinkState(buf)
		log.Infof("LS:%v,consumed:%v", ls.Value, consumed)
		if err != nil {
			return nil, fmt.Errorf("unable to decode LSAttr: %w", err)
		}
		p += uint16(consumed)

		if ret == nil {
			ret = ls
			eol = ls
			continue
		}

		eol.Next = ls
		eol = ls
	}

	return ret, nil
}

func decodeLinkState(buf *bytes.Buffer) (*LinkState, uint16, error) {
	ls := &LinkState{}

	consumed := uint16(0)
	var Type uint16
	err := decode.DecodeUint16(buf, &Type)
	if err != nil {
		return nil, consumed, err
	}
	ls.Type = Type
	consumed += 2

	var Length uint16
	err = decode.DecodeUint16(buf, &Length)
	if err != nil {
		return nil, consumed, err
	}
	ls.Length = Length
	consumed += 2
	switch Type {
	case LSMetric:
		var metric uint32
		err = decode.DecodeUint32(buf, &metric)
		if err != nil {
			return nil, consumed, err
		}
		ls.Value = &Metric{Metric: metric}
		consumed += 4
	case LSPrefixMetric:
		var metric uint32
		err = decode.DecodeUint32(buf, &metric)
		if err != nil {
			return nil, consumed, err
		}
		ls.Value = &PrefixMetric{PrefixMetric: metric}
		consumed += 4
	case LSSPFCap:
		var cap uint8
		err = decode.DecodeUint8(buf, &cap)
		if err != nil {
			return nil, consumed, err
		}
		ls.Value = &SPFCap{SPFCap: cap}
		consumed += 1
	case LSSeqNum:
		var seq uint64
		err = decode.DecodeUint64(buf, &seq)
		if err != nil {
			return nil, consumed, err
		}
		ls.Value = &SequenceNumber{SequenceNumber: seq}
		consumed += 8
	case LSIPv6PfxLen:
		var pfxlen uint8
		err = decode.DecodeUint8(buf, &pfxlen)
		if err != nil {
			return nil, consumed, err
		}
		ls.Value = &PfxLen{PfxLen: pfxlen}
		consumed += 1
	case LSIPv4PfxLen:
		var pfxlen uint8
		err = decode.DecodeUint8(buf, &pfxlen)
		if err != nil {
			return nil, consumed, err
		}
		ls.Value = &PfxLen{PfxLen: pfxlen}
		consumed += 1
	case LSSPFStatus:
		var status uint8
		err = decode.DecodeUint8(buf, &status)
		if err != nil {
			return nil, consumed, err
		}
		ls.Value = &SPFStatus{SPFStatus: status}
		consumed += 1
	default:
		return nil, consumed, fmt.Errorf("no such type:%v", Type)
	}
	return ls, consumed, nil
}

func (n *LinkState) serialize(buf *bytes.Buffer) uint8 {
	numBytes := uint8(0)
	buf.Write(convert.Uint16Byte(n.Type))
	numBytes += 2
	switch n.Type {
	case LSMetric:
		buf.Write(convert.Uint16Byte(uint16(4)))
		buf.Write(convert.Uint32Byte(n.Value.(*Metric).Metric))
		numBytes += 6
	case LSPrefixMetric:
		buf.Write(convert.Uint16Byte(uint16(4)))
		buf.Write(convert.Uint32Byte(n.Value.(*PrefixMetric).PrefixMetric))
		numBytes += 6
	case LSSeqNum:
		buf.Write(convert.Uint16Byte(uint16(8)))
		buf.Write(convert.Uint64Byte(n.Value.(*SequenceNumber).SequenceNumber))
		numBytes += 10
	case LSIPv6PfxLen:
		buf.Write(convert.Uint16Byte(uint16(1)))
		buf.Write(convert.Uint8Byte(n.Value.(*PfxLen).PfxLen))
		numBytes += 3
	case LSIPv4PfxLen:
		buf.Write(convert.Uint16Byte(uint16(1)))
		buf.Write(convert.Uint8Byte(n.Value.(*PfxLen).PfxLen))
		numBytes += 3
	case LSSPFCap:
		buf.Write(convert.Uint16Byte(uint16(1)))
		buf.Write(convert.Uint8Byte(n.Value.(*SPFCap).SPFCap))
		numBytes += 3
	case LSSPFStatus:
		buf.Write(convert.Uint16Byte(uint16(1)))
		buf.Write(convert.Uint8Byte(n.Value.(*SPFStatus).SPFStatus))
		numBytes += 3
	}
	return numBytes
}

// PathAttributes converts a path object into a linked list of path attributes
func PathAttributesLSSPF(local bnet.IP, iBGP bool, localAS uint32) (*PathAttribute, error) {
	asPath := &PathAttribute{
		TypeCode: ASPathAttr,
		Value:    types.NewASPath([]uint32{localAS}),
	}
	last := asPath
	nextHop := &PathAttribute{
		TypeCode: NextHopAttr,
		Value:    &local,
	}
	last.Next = nextHop
	last = nextHop
	origin := &PathAttribute{
		TypeCode: OriginAttr,
		Value:    uint8(2),
	}
	last.Next = origin
	last = origin

	med := &PathAttribute{
		TypeCode: MEDAttr,
		Value:    uint32(0),
		Optional: true,
	}

	last.Next = med
	last = med

	if iBGP {
		localPref := &PathAttribute{
			TypeCode: LocalPrefAttr,
			Value:    uint32(100),
		}
		last.Next = localPref
		last = localPref
	}

	// if rrClient {
	// 	originatorID := &PathAttribute{
	// 		TypeCode: OriginatorIDAttr,
	// 		Value:    p.BGPPath.BGPPathA.OriginatorID,
	// 	}
	// 	last.Next = originatorID
	// 	last = originatorID

	// 	clusterList := &PathAttribute{
	// 		TypeCode: ClusterListAttr,
	// 		Value:    p.BGPPath.ClusterList,
	// 	}
	// 	last.Next = clusterList
	// 	last = clusterList
	// }

	// optionals := last.AddOptionalPathAttributes(p)

	// last = optionals
	// for _, unknownAttr := range p.BGPPath.UnknownAttributes {
	// 	last.Next = &PathAttribute{
	// 		TypeCode:   unknownAttr.TypeCode,
	// 		Optional:   unknownAttr.Optional,
	// 		Transitive: unknownAttr.Transitive,
	// 		Partial:    unknownAttr.Partial,
	// 		Value:      unknownAttr.Value,
	// 	}
	// 	last = last.Next
	// }

	return asPath, nil
}
