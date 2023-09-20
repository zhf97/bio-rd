package server

import (
	"bytes"
	"fmt"
	"sync/atomic"
	"time"

	bnet "github.com/bio-routing/bio-rd/net"
	"github.com/bio-routing/bio-rd/protocols/bgp/packet"
	"github.com/bio-routing/bio-rd/util/log"
)

type establishedState struct {
	fsm *FSM
}

func newEstablishedState(fsm *FSM) *establishedState {
	return &establishedState{
		fsm: fsm,
	}
}

func (s establishedState) run() (state, string) {
	if !s.fsm.ribsInitialized {
		err := s.init()
		if err != nil {
			return newCeaseState(), fmt.Sprintf("Init failed: %v", err)
		}
		// TODO: send NLRI to Rib_out
		as_tlv := packet.SubTLV{Value: packet.ASTlv(s.fsm.peer.localASN), Type: packet.BGP_LS_AS}
		router_id_tlv := packet.SubTLV{Type: packet.BGP_ROUTER_ID, Value: packet.BGPRID(bnet.IPv4(s.fsm.peer.routerID))}
		as_tlv.Next = &router_id_tlv
		NodeNLRI := &packet.Node{Type: packet.NodeNLRI, ProtocolID: 4, Identifier: 0, LocalNodeDescriptor: &packet.NodeDescriptor{Type: packet.LocalNode, Value: &as_tlv}}
		NLRI := &packet.NLRI{SPFValue: NodeNLRI}
		LSAttr := packet.LinkState{Type: packet.LSSPFCap, Value: &packet.SPFCap{SPFCap: 0}}
		LSAttr.Next = &packet.LinkState{Type: packet.LSSeqNum, Value: &packet.SequenceNumber{SequenceNumber: atomic.LoadUint64(&s.fsm.lsspf.SeqNum)}}
		pa, _ := packet.PathAttributesLSSPF(bnet.IPv4(s.fsm.peer.routerID), !s.fsm.peer.isEBGP(), s.fsm.peer.localASN)
		s.fsm.lsspf.updateSender.BgpUpdateMultiProtocolLSSPF(NLRI, &LSAttr, pa)
		// send this peer to others
		peerM := s.fsm.peer.server.peers
		peerM.peersMu.RLock()
		n := &packet.NLRI{}
		for _, v := range peerM.peers {
			rrouter_id_tlv := packet.SubTLV{Value: packet.BGPRID(bnet.IPv4((v.fsms[0].neighborID))), Type: packet.BGP_ROUTER_ID}
			ras_tlv := packet.SubTLV{Value: packet.ASTlv(v.peerASN), Type: packet.BGP_LS_AS}
			ras_tlv.Next = &rrouter_id_tlv
			link := packet.SubTLV{Value: packet.IPAddr(*v.localAddr), Type: packet.IPv6Addr}
			link.Next = &packet.SubTLV{Value: packet.IPAddr(*v.addr), Type: packet.IPv6NeiAddr}
			LinkNLRI := &packet.Link{Type: packet.LinkNLRI, ProtocolID: 4, Identifier: 0, LocalNodeDescriptor: &packet.NodeDescriptor{Type: packet.LocalNode, Value: &as_tlv}, RemoteNodeDescriptor: &packet.NodeDescriptor{Type: packet.RemoteNode, Value: &ras_tlv}, LinkDescriptor: &link}
			if n.SPFValue == nil {
				n.SPFValue = LinkNLRI
			} else {
				n.Next = &packet.NLRI{SPFValue: LinkNLRI}
			}
		}
		peerM.peersMu.RUnlock()
		LSAttr = packet.LinkState{Type: packet.LSMetric, Value: &packet.Metric{Metric: 10}}
		LSAttr.Next = &packet.LinkState{Type: packet.LSSeqNum, Value: &packet.SequenceNumber{SequenceNumber: atomic.LoadUint64(&s.fsm.lsspf.SeqNum)}}
		LSAttr.Next.Next = &packet.LinkState{Type: packet.LSIPv6PfxLen, Value: &packet.PfxLen{PfxLen: 64}}
		pa, _ = packet.PathAttributesLSSPF(bnet.IPv4(s.fsm.peer.routerID), !s.fsm.peer.isEBGP(), s.fsm.peer.localASN)
		s.fsm.lsspf.updateSender.BgpUpdateMultiProtocolLSSPF(n, &LSAttr, pa)
		as_tlv = packet.SubTLV{Value: packet.ASTlv(s.fsm.peer.localASN), Type: packet.BGP_LS_AS}
		router_id_tlv = packet.SubTLV{Type: packet.BGP_ROUTER_ID, Value: packet.BGPRID(bnet.IPv4(s.fsm.peer.routerID))}
		as_tlv.Next = &router_id_tlv
		ip, _ := bnet.IPFromString("a::1")
		NLRI = &packet.NLRI{SPFValue: &packet.Prefix{Type: packet.IPv6PrefixNLRI, ProtocolID: 4, Identifier: 0, LocalNodeDescriptor: &packet.NodeDescriptor{Type: packet.LocalNode, Value: &as_tlv}, PrefixDescriptor: &packet.SubTLV{Type: packet.IPReachabilityInformation, Value: packet.IPReachability(bnet.NewPfx(ip, 64))}}}
		LSAttr = packet.LinkState{Type: packet.LSPrefixMetric, Value: &packet.PrefixMetric{PrefixMetric: 10}}
		LSAttr.Next = &packet.LinkState{Type: packet.LSSeqNum, Value: &packet.SequenceNumber{SequenceNumber: atomic.LoadUint64(&s.fsm.lsspf.SeqNum)}}
		pa, _ = packet.PathAttributesLSSPF(bnet.IPv4(s.fsm.peer.routerID), !s.fsm.peer.isEBGP(), s.fsm.peer.localASN)
		s.fsm.lsspf.updateSender.BgpUpdateMultiProtocolLSSPF(NLRI, &LSAttr, pa)
	}
	keepaliveTimerC := make(<-chan time.Time)
	if s.fsm.keepaliveTimer != nil {
		keepaliveTimerC = s.fsm.keepaliveTimer.C
	}

	opt := s.fsm.decodeOptions()
	for {
		select {
		case e := <-s.fsm.eventCh:
			switch e {
			case ManualStop:
				return s.manualStop()
			case AutomaticStop:
				return s.automaticStop()
			case Cease:
				return s.cease()
			default:
				continue
			}
		case <-keepaliveTimerC:
			return s.keepaliveTimerExpired()
		case <-time.After(time.Second):
			return s.checkHoldtimer()
		case recvMsg := <-s.fsm.msgRecvCh:
			return s.msgReceived(recvMsg, opt, false, uint32(time.Now().Unix()))
		}
	}
}

func (s *establishedState) checkHoldtimer() (state, string) {
	if s.fsm.keepaliveTimer != nil && time.Since(s.fsm.lastUpdateOrKeepalive) > s.fsm.holdTime {
		return s.holdTimerExpired()
	}

	return newEstablishedState(s.fsm), s.fsm.reason
}

func (s *establishedState) init() error {
	if s.fsm.ipv4Unicast != nil {
		s.fsm.ipv4Unicast.init()
	}

	if s.fsm.ipv6Unicast != nil {
		s.fsm.ipv6Unicast.init()
	}
	if s.fsm.lsspf != nil {
		s.fsm.lsspf.init()
	}

	s.fsm.ribsInitialized = true
	return nil
}

func (s *establishedState) uninit() {
	if s.fsm.ipv4Unicast != nil {
		s.fsm.ipv4Unicast.dispose()
	}

	if s.fsm.ipv6Unicast != nil {
		s.fsm.ipv6Unicast.dispose()
	}

	s.fsm.counters.reset()

	s.fsm.ribsInitialized = false
}

func (s *establishedState) manualStop() (state, string) {
	s.fsm.sendNotification(packet.Cease, 0)
	s.uninit()
	stopTimer(s.fsm.connectRetryTimer)
	s.fsm.con.Close()
	s.fsm.connectRetryCounter = 0
	return newIdleState(s.fsm), "Manual stop event"
}

func (s *establishedState) automaticStop() (state, string) {
	s.fsm.sendNotification(packet.Cease, 0)
	s.uninit()
	stopTimer(s.fsm.connectRetryTimer)
	s.fsm.con.Close()
	s.fsm.connectRetryCounter++
	return newIdleState(s.fsm), "Automatic stop event"
}

func (s *establishedState) cease() (state, string) {
	s.fsm.sendNotification(packet.Cease, 0)
	s.uninit()
	s.fsm.con.Close()
	return newCeaseState(), "Cease"
}

func (s *establishedState) holdTimerExpired() (state, string) {
	s.fsm.sendNotification(packet.HoldTimeExpired, 0)
	s.uninit()
	stopTimer(s.fsm.connectRetryTimer)
	s.fsm.con.Close()
	s.fsm.connectRetryCounter++
	return newIdleState(s.fsm), "Holdtimer expired"
}

func (s *establishedState) keepaliveTimerExpired() (state, string) {
	err := s.fsm.sendKeepalive()
	if err != nil {
		s.uninit()
		stopTimer(s.fsm.connectRetryTimer)
		s.fsm.con.Close()
		s.fsm.connectRetryCounter++
		return newIdleState(s.fsm), fmt.Sprintf("Failed to send keepalive: %v", err)
	}

	s.fsm.keepaliveTimer.Reset(s.fsm.keepaliveTime)
	return newEstablishedState(s.fsm), s.fsm.reason
}

func (s *establishedState) msgReceived(data []byte, opt *packet.DecodeOptions, bmpPostPolicy bool, timestamp uint32) (state, string) {
	msg, err := packet.Decode(bytes.NewBuffer(data), opt)
	if err != nil {
		switch bgperr := err.(type) {
		case packet.BGPError:
			s.fsm.sendNotification(bgperr.ErrorCode, bgperr.ErrorSubCode)
		}
		stopTimer(s.fsm.connectRetryTimer)
		if s.fsm.con != nil {
			s.fsm.con.Close()
		}
		s.fsm.connectRetryCounter++
		return newIdleState(s.fsm), fmt.Sprintf("Failed to decode BGP message: %v", err)
	}

	switch msg.Header.Type {
	case packet.NotificationMsg:
		return s.notification()
	case packet.UpdateMsg:
		return s.update(msg.Body.(*packet.BGPUpdate), bmpPostPolicy, timestamp)
	case packet.KeepaliveMsg:
		return s.keepaliveReceived()
	default:
		return s.unexpectedMessage()
	}
}

func (s *establishedState) notification() (state, string) {
	stopTimer(s.fsm.connectRetryTimer)
	s.uninit()
	s.fsm.con.Close()
	s.fsm.connectRetryCounter++
	return newIdleState(s.fsm), "Received NOTIFICATION"
}

func (s *establishedState) update(u *packet.BGPUpdate, bmpPostPolicy bool, timestemp uint32) (state, string) {
	atomic.AddUint64(&s.fsm.counters.updatesReceived, 1)

	if s.fsm.holdTime != 0 {
		s.fsm.updateLastUpdateOrKeepalive()
	}

	if s.fsm.ipv4Unicast != nil {
		s.fsm.ipv4Unicast.processUpdate(u, bmpPostPolicy, timestemp)
	}

	if s.fsm.ipv6Unicast != nil {
		s.fsm.ipv6Unicast.processUpdate(u, bmpPostPolicy, timestemp)
	}
	if s.fsm.lsspf != nil {
		s.fsm.lsspf.processUpdate(u, bmpPostPolicy, timestemp)
	}

	afi, safi := s.updateAddressFamily(u)

	if safi != packet.SAFIUnicast && safi != packet.SAFIBGPLSSPF {
		// only unicast support, so other SAFIs are ignored
		return newEstablishedState(s.fsm), s.fsm.reason
	}

	switch afi {
	case packet.AFIIPv4:
		if s.fsm.ipv4Unicast == nil {
			log.Info("Received update for family IPv4 unicast, but this family is not configured.")
		}

	case packet.AFIIPv6:
		if s.fsm.ipv6Unicast == nil {
			log.Info("Received update for family IPv6 unicast, but this family is not configured.")
		}
	}

	return newEstablishedState(s.fsm), s.fsm.reason
}

func (s *establishedState) updateAddressFamily(u *packet.BGPUpdate) (afi uint16, safi uint8) {
	if u.WithdrawnRoutes != nil || u.NLRI != nil {
		return packet.AFIIPv4, packet.SAFIUnicast
	}

	for cur := u.PathAttributes; cur != nil; cur = cur.Next {
		if cur.TypeCode == packet.MultiProtocolReachNLRIAttr {
			a := cur.Value.(packet.MultiProtocolReachNLRI)
			return a.AFI, a.SAFI
		}

		if cur.TypeCode == packet.MultiProtocolUnreachNLRIAttr {
			a := cur.Value.(packet.MultiProtocolUnreachNLRI)
			return a.AFI, a.SAFI
		}
	}

	return
}

func (s *establishedState) keepaliveReceived() (state, string) {
	if s.fsm.holdTime != 0 {
		s.fsm.updateLastUpdateOrKeepalive()
	}
	return newEstablishedState(s.fsm), s.fsm.reason
}

func (s *establishedState) unexpectedMessage() (state, string) {
	s.fsm.sendNotification(packet.FiniteStateMachineError, 0)
	s.uninit()
	stopTimer(s.fsm.connectRetryTimer)
	s.fsm.con.Close()
	s.fsm.connectRetryCounter++
	return newIdleState(s.fsm), "FSM Error"
}
