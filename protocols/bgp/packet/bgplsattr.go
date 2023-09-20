package packet

import (
	"bytes"
)

// MultiProtocolReachNLRI represents network layer reachability information for an IP address family (rfc4760)
type LinkStateAttrs struct {
	LinkState *LinkState
}

func (n *LinkStateAttrs) serialize(buf *bytes.Buffer, opt *EncodeOptions) uint16 {

	tempBuf := bytes.NewBuffer(nil)

	for cur := n.LinkState; cur != nil; cur = cur.Next {
		cur.serialize(tempBuf)
	}

	buf.Write(tempBuf.Bytes())

	return uint16(tempBuf.Len())
}

func deserializeLinkState(b []byte) (LinkStateAttrs, error) {
	n := LinkStateAttrs{}
	buf := bytes.NewBuffer(b)
	ls, err := decodeLinkStates(buf, uint16(buf.Len()))
	if err != nil {
		return LinkStateAttrs{}, err
	}
	n.LinkState = ls

	return n, nil
}
