package packet

import (
	"bytes"
	"fmt"

	bnet "github.com/bio-routing/bio-rd/net"
	"github.com/bio-routing/bio-rd/util/decode"
	"github.com/bio-routing/tflow2/convert"
)

const (
	NodeNLRI       = 1
	LinkNLRI       = 2
	IPv4PrefixNLRI = 3
	IPv6PrefixNLRI = 4
	LocalNode      = 256
	RemoteNode     = 257

	BGP_LS_AS                 = 512
	BGP_ROUTER_ID             = 516
	Link_Identifiers          = 258
	IPv4Addr                  = 259
	IPv4NeiAddr               = 260
	IPv6Addr                  = 261
	IPv6NeiAddr               = 262
	MultiTopo                 = 263
	IPReachabilityInformation = 265
)

type NodeDescriptor struct {
	Type   uint16
	Length uint16
	Value  *SubTLV
}

type Node struct {
	Type                uint16
	Length              uint16
	ProtocolID          uint8
	Identifier          uint64
	LocalNodeDescriptor *NodeDescriptor
}

type Link struct {
	Type                 uint16
	Length               uint16
	ProtocolID           uint8
	Identifier           uint64
	LocalNodeDescriptor  *NodeDescriptor
	RemoteNodeDescriptor *NodeDescriptor
	LinkDescriptor       *SubTLV
}

type Prefix struct {
	Type                uint16
	Length              uint16
	ProtocolID          uint8
	Identifier          uint64
	LocalNodeDescriptor *NodeDescriptor
	PrefixDescriptor    *SubTLV
}

type SubTLV struct {
	Type   uint16
	Length uint16
	Value  interface{}
	Next   *SubTLV
}
type LinkLocalRemoteIdentifier struct {
	LinkLocalIdentifier  uint32
	LinkRemoteIdentifier uint32
}
type ASTlv uint32
type BGPRID bnet.IP
type IPAddr bnet.IP
type MTID []uint16
type IPReachability bnet.Prefix

func decodeSPFTLV(buf *bytes.Buffer) (*NLRI, uint16, error) {
	nlri := &NLRI{}
	consumed := uint16(0)
	var Type uint16
	err := decode.DecodeUint16(buf, &Type)
	if err != nil {
		return nil, consumed, err
	}
	consumed += 2

	var Length uint16
	err = decode.DecodeUint16(buf, &Length)
	if err != nil {
		return nil, consumed, err
	}
	consumed += 2
	switch Type {
	case NodeNLRI:
		node, consumed_, err := decodeNodeNLRI(buf, Length)
		if err != nil {
			return nil, consumed, err
		}
		nlri.SPFValue = node
		consumed += consumed_
	case IPv4PrefixNLRI:
	case IPv6PrefixNLRI:
		node, consumed_, err := decodePrefixNLRI(buf, Length)
		if err != nil {
			return nil, consumed, err
		}
		nlri.SPFValue = node
		consumed += consumed_
	case LinkNLRI:
		node, consumed_, err := decodeLinkNLRI(buf, Length)
		if err != nil {
			return nil, consumed, err
		}
		nlri.SPFValue = node
		consumed += consumed_
	default:
		return nil, consumed, fmt.Errorf("type %v not found", Type)
	}
	return nlri, consumed, nil
}
func seralizeSPFTLV(buf *bytes.Buffer, Value interface{}) uint16 {
	switch n := Value.(type) {
	case *Node:
		node_buf, node_bytes := seralizeSubTLVs(n.LocalNodeDescriptor.Value)
		n.LocalNodeDescriptor.Length = node_bytes
		n.LocalNodeDescriptor.Type = LocalNode
		n.Length = 2 + 2 + n.LocalNodeDescriptor.Length + 9
		buf.Write(convert.Uint16Byte(n.Type))
		buf.Write(convert.Uint16Byte(n.Length))
		buf.Write(convert.Uint8Byte(n.ProtocolID))
		buf.Write(convert.Uint64Byte(n.Identifier))
		buf.Write(convert.Uint16Byte(n.LocalNodeDescriptor.Type))
		buf.Write(convert.Uint16Byte(n.LocalNodeDescriptor.Length))
		buf.Write(node_buf)
		return n.Length + 4
	case *Prefix:
		node_buf, node_bytes := seralizeSubTLVs(n.LocalNodeDescriptor.Value)
		n.LocalNodeDescriptor.Length = node_bytes
		n.LocalNodeDescriptor.Type = LocalNode
		prefix_buf, prefix_bytes := seralizeSubTLVs(n.PrefixDescriptor)
		n.Length = 2 + 2 + n.LocalNodeDescriptor.Length + prefix_bytes + 9
		buf.Write(convert.Uint16Byte(n.Type))
		buf.Write(convert.Uint16Byte(n.Length))
		buf.Write(convert.Uint8Byte(n.ProtocolID))
		buf.Write(convert.Uint64Byte(n.Identifier))
		buf.Write(convert.Uint16Byte(n.LocalNodeDescriptor.Type))
		buf.Write(convert.Uint16Byte(n.LocalNodeDescriptor.Length))
		buf.Write(node_buf)
		buf.Write(prefix_buf)
		return n.Length + 4
	case *Link:
		lnode_buf, lnode_bytes := seralizeSubTLVs(n.LocalNodeDescriptor.Value)
		n.LocalNodeDescriptor.Length = lnode_bytes
		n.LocalNodeDescriptor.Type = LocalNode
		rnode_buf, rnode_bytes := seralizeSubTLVs(n.RemoteNodeDescriptor.Value)
		n.RemoteNodeDescriptor.Length = rnode_bytes
		n.RemoteNodeDescriptor.Type = RemoteNode
		link_buf, link_bytes := seralizeSubTLVs(n.LinkDescriptor)
		n.Length = 2 + 2 + n.LocalNodeDescriptor.Length + 2 + 2 + n.RemoteNodeDescriptor.Length + link_bytes + 9
		buf.Write(convert.Uint16Byte(n.Type))
		buf.Write(convert.Uint16Byte(n.Length))
		buf.Write(convert.Uint8Byte(n.ProtocolID))
		buf.Write(convert.Uint64Byte(n.Identifier))
		buf.Write(convert.Uint16Byte(n.LocalNodeDescriptor.Type))
		buf.Write(convert.Uint16Byte(n.LocalNodeDescriptor.Length))
		buf.Write(lnode_buf)
		buf.Write(convert.Uint16Byte(n.RemoteNodeDescriptor.Type))
		buf.Write(convert.Uint16Byte(n.RemoteNodeDescriptor.Length))
		buf.Write(rnode_buf)
		buf.Write(link_buf)
		return n.Length + 4
	}
	return 0
}
func seralizeSubTLVs(Value *SubTLV) ([]byte, uint16) {
	tempBuf := new(bytes.Buffer)
	for cur := Value; cur != nil; cur = cur.Next {
		cur.serialize(tempBuf)
	}
	return tempBuf.Bytes(), uint16(tempBuf.Len())
}
func decodeSubTLVs(buf *bytes.Buffer, length uint16) (*SubTLV, error) {
	var ret *SubTLV
	var eol *SubTLV
	var nlri *SubTLV
	var err error
	var consumed uint16
	p := uint16(0)

	for p < length {
		nlri, consumed, err = decodeSubTLV(buf)
		// log.Infof("decode NLRI:%v,consumed:%v,totalLength:%v", nlri, consumed, length)
		if err != nil {
			return nil, fmt.Errorf("unable to decode NLRI SubTLV : %w", err)
		}
		p += uint16(consumed)

		if ret == nil {
			ret = nlri
			eol = nlri
			continue
		}

		eol.Next = nlri
		eol = nlri
	}

	return ret, nil
}
func decodeSubTLV(buf *bytes.Buffer) (*SubTLV, uint16, error) {
	this := &SubTLV{}
	consumed := uint16(0)
	err := decode.DecodeUint16(buf, &this.Type)
	if err != nil {
		return nil, consumed, err
	}
	consumed += 2
	err = decode.DecodeUint16(buf, &this.Length)
	if err != nil {
		return nil, consumed, err
	}
	consumed += 2
	switch this.Type {
	case BGP_LS_AS:
		var as uint32
		err := decode.DecodeUint32(buf, &as)
		if err != nil {
			return nil, consumed, err
		}
		this.Value = ASTlv(as)
		consumed += 4
	case BGP_ROUTER_ID:
		var as uint32
		err := decode.DecodeUint32(buf, &as)
		if err != nil {
			return nil, consumed, err
		}
		this.Value = bnet.IPv4(as)
		consumed += 4
	case Link_Identifiers:
		lid := LinkLocalRemoteIdentifier{}
		err := decode.Decode(buf, []interface{}{&lid})
		if err != nil {
			return nil, consumed, err
		}
		this.Value = &lid
		consumed += 8
	case IPv4Addr:
		fallthrough
	case IPv4NeiAddr:
		ipBytes := make([]byte, afiAddrLenBytes[AFIIPv4])
		buf.Read(ipBytes)
		ip, err := bnet.IPFromBytes(ipBytes)
		if err != nil {
			return nil, consumed, err
		}
		this.Value = ip
		consumed += 4
	case IPv6Addr:
		fallthrough
	case IPv6NeiAddr:
		ipBytes := make([]byte, afiAddrLenBytes[AFIIPv6])
		buf.Read(ipBytes)
		ip, err := bnet.IPFromBytes(ipBytes)
		if err != nil {
			return nil, consumed, err
		}
		this.Value = &ip
		consumed += 16
	case MultiTopo:
		return nil, consumed, fmt.Errorf("type: %v not implemented", this.Type)
	case IPReachabilityInformation:
		pfxLen, err := buf.ReadByte()
		if err != nil {
			return nil, consumed, err
		}
		consumed += 1
		length := BytesInAddr(pfxLen)
		pfx := make([]byte, length)
		buf.Read(pfx)
		pfx_ip, err := deserializePrefix(pfx, pfxLen, AFIIPv6)
		if err != nil {
			return nil, consumed, err
		}
		consumed += uint16(length)
		this.Value = pfx_ip
	default:
		return nil, consumed, fmt.Errorf("type:%v not found,%x", this.Type, buf.Bytes())
	}
	return this, consumed, nil

}
func decodeNodeNLRI(buf *bytes.Buffer, len uint16) (*Node, uint16, error) {
	this := &Node{
		Type:                NodeNLRI,
		LocalNodeDescriptor: &NodeDescriptor{},
	}
	consumed := uint16(0)
	// err := decode.DecodeUint16(buf, &this.Type)
	// if err != nil {
	// 	return nil, consumed, err
	// }
	// consumed += 2
	// err = decode.DecodeUint16(buf, &this.Length)
	// if err != nil {
	// 	return nil, consumed, err
	// }
	// consumed += 2
	err := decode.DecodeUint8(buf, &this.ProtocolID)
	if err != nil {
		return nil, consumed, err
	}
	consumed += 1
	err = decode.DecodeUint64(buf, &this.Identifier)
	if err != nil {
		return nil, consumed, err
	}
	consumed += 8
	err = decode.DecodeUint16(buf, &this.LocalNodeDescriptor.Type)
	if err != nil {
		return nil, consumed, err
	}
	consumed += 2
	err = decode.DecodeUint16(buf, &this.LocalNodeDescriptor.Length)
	if err != nil {
		return nil, consumed, err
	}
	consumed += 2
	// log.Infof("this node:%v,this node.LocalNodeDescriptor:%v,consumed:%v", this, this.LocalNodeDescriptor, consumed)
	tlv, err := decodeSubTLVs(buf, this.LocalNodeDescriptor.Length)
	if err != nil {
		return nil, consumed, err
	}
	this.LocalNodeDescriptor.Value = tlv
	consumed += this.LocalNodeDescriptor.Length
	return this, consumed, nil
}

func decodeLinkNLRI(buf *bytes.Buffer, len uint16) (*Link, uint16, error) {
	this := &Link{
		Type:                 NodeNLRI,
		RemoteNodeDescriptor: &NodeDescriptor{},
		LocalNodeDescriptor:  &NodeDescriptor{},
	}
	consumed := uint16(0)
	// err := decode.DecodeUint16(buf, &this.Type)
	// if err != nil {
	// 	return nil, consumed, err
	// }
	// consumed += 2
	// err = decode.DecodeUint16(buf, &this.Length)
	// if err != nil {
	// 	return nil, consumed, err
	// }
	// consumed += 2
	err := decode.DecodeUint8(buf, &this.ProtocolID)
	if err != nil {
		return nil, consumed, err
	}
	consumed += 1
	err = decode.DecodeUint64(buf, &this.Identifier)
	if err != nil {
		return nil, consumed, err
	}
	consumed += 8
	err = decode.DecodeUint16(buf, &this.LocalNodeDescriptor.Type)
	if err != nil {
		return nil, consumed, err
	}
	consumed += 2
	err = decode.DecodeUint16(buf, &this.LocalNodeDescriptor.Length)
	if err != nil {
		return nil, consumed, err
	}
	consumed += 2
	tlv, err := decodeSubTLVs(buf, this.LocalNodeDescriptor.Length)
	if err != nil {
		return nil, consumed, err
	}
	this.LocalNodeDescriptor.Value = tlv
	consumed += this.LocalNodeDescriptor.Length
	err = decode.DecodeUint16(buf, &this.RemoteNodeDescriptor.Type)
	if err != nil {
		return nil, consumed, err
	}
	consumed += 2
	err = decode.DecodeUint16(buf, &this.RemoteNodeDescriptor.Length)
	if err != nil {
		return nil, consumed, err
	}
	consumed += 2
	tlv, err = decodeSubTLVs(buf, this.RemoteNodeDescriptor.Length)
	if err != nil {
		return nil, consumed, err
	}
	this.RemoteNodeDescriptor.Value = tlv
	consumed += this.RemoteNodeDescriptor.Length
	tlv, err = decodeSubTLVs(buf, len-consumed)
	if err != nil {
		return nil, consumed, err
	}
	this.LinkDescriptor = tlv
	consumed += len - consumed
	return this, consumed, nil
}

func decodePrefixNLRI(buf *bytes.Buffer, len uint16) (*Prefix, uint16, error) {
	this := &Prefix{
		Type:                NodeNLRI,
		LocalNodeDescriptor: &NodeDescriptor{},
	}
	consumed := uint16(0)
	// err := decode.DecodeUint16(buf, &this.Type)
	// if err != nil {
	// 	return nil, consumed, err
	// }
	// consumed += 2
	// err = decode.DecodeUint16(buf, &this.Length)
	// if err != nil {
	// 	return nil, consumed, err
	// }
	// consumed += 2
	err := decode.DecodeUint8(buf, &this.ProtocolID)
	if err != nil {
		return nil, consumed, err
	}
	consumed += 1
	err = decode.DecodeUint64(buf, &this.Identifier)
	if err != nil {
		return nil, consumed, err
	}
	consumed += 8
	err = decode.DecodeUint16(buf, &this.LocalNodeDescriptor.Type)
	if err != nil {
		return nil, consumed, err
	}
	consumed += 2
	err = decode.DecodeUint16(buf, &this.LocalNodeDescriptor.Length)
	if err != nil {
		return nil, consumed, err
	}
	consumed += 2
	tlv, err := decodeSubTLVs(buf, this.LocalNodeDescriptor.Length)
	if err != nil {
		return nil, consumed, err
	}
	this.LocalNodeDescriptor.Value = tlv
	consumed += this.LocalNodeDescriptor.Length
	tlv, err = decodeSubTLVs(buf, len-consumed)
	if err != nil {
		return nil, consumed, err
	}
	this.PrefixDescriptor = tlv
	consumed += len - consumed
	return this, consumed, nil
}

func (this *SubTLV) serialize(buf *bytes.Buffer) uint16 {
	numBytes := uint16(0)
	switch this.Type {
	case BGP_LS_AS:
		buf.Write(convert.Uint16Byte(this.Type))
		buf.Write(convert.Uint16Byte(uint16(4)))
		buf.Write(convert.Uint32Byte(uint32(this.Value.(ASTlv))))
		numBytes += 8
	case BGP_ROUTER_ID:
		buf.Write(convert.Uint16Byte(this.Type))
		buf.Write(convert.Uint16Byte(uint16(4)))
		ip, _ := this.Value.(BGPRID)
		buf.Write(bnet.IP(ip).Bytes())
		numBytes += 8
	case Link_Identifiers:
		buf.Write(convert.Uint16Byte(this.Type))
		buf.Write(convert.Uint16Byte(uint16(8)))
		buf.Write(convert.Uint32Byte(uint32(this.Value.(LinkLocalRemoteIdentifier).LinkLocalIdentifier)))
		buf.Write(convert.Uint32Byte(uint32(this.Value.(LinkLocalRemoteIdentifier).LinkRemoteIdentifier)))
		numBytes += 20
	case IPv4Addr:
		fallthrough
	case IPv4NeiAddr:
		buf.Write(convert.Uint16Byte(this.Type))
		buf.Write(convert.Uint16Byte(uint16(4)))
		var ip IPAddr
		ip, _ = this.Value.(IPAddr)
		buf.Write(bnet.IP(ip).Bytes())
		numBytes += 4 + 2 + 2
	case IPv6Addr:
		fallthrough
	case IPv6NeiAddr:
		buf.Write(convert.Uint16Byte(this.Type))
		buf.Write(convert.Uint16Byte(uint16(16)))
		var ip IPAddr
		ip, _ = this.Value.(IPAddr)
		buf.Write(bnet.IP(ip).Bytes())
		numBytes += 16 + 2 + 2
	case IPReachabilityInformation:
		n := bnet.Prefix(this.Value.(IPReachability))
		pfxNumBytes := BytesInAddr(n.Len())
		buf.Write(convert.Uint16Byte(this.Type))
		buf.Write(convert.Uint16Byte(uint16(pfxNumBytes) + 1))
		buf.Write(convert.Uint8Byte(n.Len()))
		buf.Write(n.Addr().Bytes()[:pfxNumBytes])
		numBytes += uint16(pfxNumBytes) + 2 + 2
	}
	return numBytes
}
