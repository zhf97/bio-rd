package main

import (
	"time"

	bnet "github.com/bio-routing/bio-rd/net"
	"github.com/bio-routing/bio-rd/protocols/bgp/server"
	"github.com/bio-routing/bio-rd/routingtable"
	"github.com/bio-routing/bio-rd/routingtable/filter"
	"github.com/bio-routing/bio-rd/routingtable/vrf"
	"github.com/bio-routing/bio-rd/util/log"
	"github.com/sirupsen/logrus"
)

func main() {
	logrus.Printf("This is a BGP speaker\n")
	log.SetLogger(log.NewLogrusWrapper(logrus.New()))
	listen := []string{"[a::2]:179"}

	v, err := vrf.New(vrf.DefaultVRFName, 0)
	if err != nil {
		logrus.Fatal(err)
	}

	bCfg := server.BGPServerConfig{
		RouterID:         16843010,
		DefaultVRF:       v,
		ListenAddrsByVRF: map[string][]string{vrf.DefaultVRFName: listen},
	}
	b := server.NewBGPServer(bCfg)

	b.Start()
	logrus.Printf("before create peer\n")
	b.AddPeer(server.PeerConfig{
		AdminEnabled:      true,
		LocalAS:           2,
		PeerAS:            1,
		PeerAddress:       bnet.IPv6FromBlocks(0xa, 0, 0, 0, 0, 0, 0, 1).Ptr(),
		LocalAddress:      bnet.IPv6FromBlocks(0xa, 0, 0, 0, 0, 0, 0, 2).Ptr(),
		ReconnectInterval: time.Second * 1,
		HoldTime:          time.Second * 90,
		KeepAlive:         time.Second * 30,
		Passive:           false,
		RouterID:          b.RouterID(),
		Lsspf: &server.AddressFamilyConfig{
			ImportFilterChain: filter.NewAcceptAllFilterChain(),
			ExportFilterChain: filter.NewAcceptAllFilterChain(),
			AddPathSend: routingtable.ClientOptions{
				MaxPaths: 10,
			},
			AddPathRecv: true,
		},
		RouteServerClient: true,
		VRF:               v,
	})

	select {}
}
