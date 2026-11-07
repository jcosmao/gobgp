package server

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// A VRF neighbor with ADD-PATH send gets every path of a prefix both when
// it is updated and when its VRF is advertised as a whole (session up,
// graceful restart release, route refresh). The latter used to send only the
// best path: ADD-PATH was looked up for the VPN family instead of the VRF one.
func TestVrfNeighborAddPathSendAllPaths(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 65001, RouterId: "1.1.1.1", ListenPort: -1},
	}))
	rd := bgp.NewRouteDistinguisherTwoOctetAS(65000, 1)
	rt := bgp.NewTwoOctetAsSpecificExtended(bgp.EC_SUBTYPE_ROUTE_TARGET, 65000, 1, true)
	rts := []bgp.ExtendedCommunityInterface{rt}
	require.NoError(t, s.mgmtOperation(func() error {
		_, err := s.globalRib.AddVrf("vrf1", 1, rd, rts, rts, &table.PeerInfo{})
		return err
	}, true))

	addr := netip.MustParseAddr("10.0.0.1")
	p := newPeerandInfo(t, 65001, 65002, addr.String(), s.globalRib)
	p.policy = s.policy
	p.fsm.pConf.ReadOnly().Config.Vrf = "vrf1"
	for i := range p.fsm.pConf.ReadOnly().AfiSafis {
		p.fsm.pConf.ReadOnly().AfiSafis[i].AddPaths.Config.SendMax = 8
	}
	p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
	p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_SEND})
	require.NoError(t, s.mgmtOperation(func() error {
		s.neighborMap[addr] = p
		return nil
	}, true))
	t.Cleanup(func() {
		_ = s.mgmtOperation(func() error {
			clear(s.neighborMap)
			return nil
		}, false)
		cleanInfiniteChannel(p.fsm.outgoingCh)
		_ = s.StopBgp(context.Background(), &api.StopBgpRequest{})
	})

	nlri, err := bgp.NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix("30.0.0.1/32"), *bgp.NewMPLSLabelStack(100), rd)
	require.NoError(t, err)
	mpReach, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv4_VPN, []bgp.PathNLRI{{NLRI: nlri}}, netip.MustParseAddr("10.0.0.254"))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), mpReach, bgp.NewPathAttributeExtendedCommunities(rts)}
	var paths []*table.Path
	for id := uint32(1); id <= 3; id++ {
		src := netip.AddrFrom4([4]byte{9, 9, 9, byte(id)})
		paths = append(paths, table.NewPath(bgp.RF_IPv4_VPN, &table.PeerInfo{Address: src, ID: src}, bgp.PathNLRI{NLRI: nlri, ID: id}, false, attrs, time.Now(), false))
	}
	s.propagateUpdate(nil, paths)
	v4 := []bgp.Family{bgp.RF_IPv4_UC}
	require.Equal(t, 3, p.advertisedRoutes(v4))

	var dumped []*table.Path
	s.getBestFromLocalCallback(p, v4, false, false, func(l, _ []*table.Path) { dumped = l })
	require.Len(t, dumped, 3)
}

// A real dual-stack session (IPv4 and IPv6 unicast over one IPv4 transport,
// as MP-BGP) between a PE and an ADD-PATH neighbor in vrf1: paths added
// through the API with identifiers and IPv6 nexthops all reach the neighbor,
// those present at session up as those added, changed or withdrawn later,
// never the vrf2 ones, and ListPath on the VRF lists them.
func TestVrfNeighborEndToEndDualStackAddPath(t *testing.T) {
	ctx := context.Background()
	pe := runNewServer(t, 1, "1.1.1.1", 10179)
	ce := runNewServer(t, 2, "2.2.2.2", 20179)
	t.Cleanup(func() {
		_ = pe.StopBgp(ctx, &api.StopBgpRequest{})
		_ = ce.StopBgp(ctx, &api.StopBgpRequest{})
	})
	addVrf(t, pe, "vrf1", "111:111", []string{"111:111"}, []string{"111:111"}, 1)
	addVrf(t, pe, "vrf2", "222:222", []string{"222:222"}, []string{"222:222"}, 2)

	add := func(vrf, prefix string, id uint32, nexthop string) {
		t.Helper()
		pfx := netip.MustParsePrefix(prefix)
		nlri, err := bgp.NewIPAddrPrefix(pfx)
		require.NoError(t, err)
		fam := bgp.RF_IPv4_UC
		attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}
		if pfx.Addr().Is6() {
			fam = bgp.RF_IPv6_UC
			mp, err := bgp.NewPathAttributeMpReachNLRI(fam, []bgp.PathNLRI{{NLRI: nlri}}, netip.MustParseAddr(nexthop))
			require.NoError(t, err)
			attrs = append(attrs, mp)
		} else {
			nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr(nexthop))
			require.NoError(t, err)
			attrs = append(attrs, nh)
		}
		p, err := apiutil.NewPath(fam, nlri, false, attrs, time.Now())
		require.NoError(t, err)
		ap := mustApi2apiutilPath(p)
		ap.RemoteID = id
		_, err = pe.AddPath(apiutil.AddPathRequest{VRFID: vrf, Paths: []*apiutil.Path{ap}})
		require.NoError(t, err)
	}
	ceCount := func(fam bgp.Family) map[string]int {
		m := map[string]int{}
		require.NoError(t, ce.ListPath(apiutil.ListPathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL, Family: fam}, func(prefix bgp.NLRI, paths []*apiutil.Path) {
			m[prefix.String()] = len(paths)
		}))
		return m
	}
	ceHas := func(fam bgp.Family, want map[string]int) {
		t.Helper()
		require.Eventually(t, func() bool {
			got := ceCount(fam)
			if len(got) != len(want) {
				return false
			}
			for k, n := range want {
				if got[k] != n {
					return false
				}
			}
			return true
		}, 10*time.Second, 100*time.Millisecond, "%s: ce has %v, want %v", fam, ceCount(fam), want)
	}

	// Before the session: 2 paths per prefix in vrf1, one path in vrf2.
	add("vrf1", "2001:db8:1::/64", 1, "2001:db8:ff::1")
	add("vrf1", "2001:db8:1::/64", 2, "2001:db8:ff::2")
	add("vrf1", "10.1.0.0/24", 1, "1.1.1.1")
	add("vrf1", "10.1.0.0/24", 2, "1.1.1.2")
	add("vrf2", "2001:db8:2::/64", 1, "2001:db8:ff::1")

	addPath := func(sendMax uint8, receive bool) peerOption {
		return func(_ *BgpServer, _ *oc.Global, n *oc.Neighbor) {
			for _, f := range []oc.AfiSafiType{oc.AFI_SAFI_TYPE_IPV4_UNICAST, oc.AFI_SAFI_TYPE_IPV6_UNICAST} {
				n.AfiSafis = append(n.AfiSafis, oc.AfiSafi{
					Config:   oc.AfiSafiConfig{AfiSafiName: f, Enabled: true},
					AddPaths: oc.AddPaths{Config: oc.AddPathsConfig{Receive: receive, SendMax: sendMax}},
				})
			}
		}
	}
	inVrf1 := func(_ *BgpServer, _ *oc.Global, n *oc.Neighbor) { n.Config.Vrf = "vrf1" }
	require.NoError(t, peerTwoServers(t, ctx, pe, ce, nil, true, inVrf1, addPath(8, false)))
	require.NoError(t, peerTwoServers(t, ctx, ce, pe, nil, false, addPath(0, true)))
	wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	require.NoError(t, waitEstablished(t, wctx, pe, ce))

	// Session up: every path of vrf1, in both families.
	ceHas(bgp.RF_IPv6_UC, map[string]int{"2001:db8:1::/64": 2})
	ceHas(bgp.RF_IPv4_UC, map[string]int{"10.1.0.0/24": 2})

	// After the session: a third identifier, a new prefix, one more in vrf2.
	add("vrf1", "2001:db8:1::/64", 3, "2001:db8:ff::3")
	add("vrf1", "2001:db8:3::/64", 1, "2001:db8:ff::1")
	add("vrf2", "2001:db8:4::/64", 1, "2001:db8:ff::1")
	ceHas(bgp.RF_IPv6_UC, map[string]int{"2001:db8:1::/64": 3, "2001:db8:3::/64": 1})

	// A new nexthop for an identifier replaces its path.
	add("vrf1", "2001:db8:1::/64", 2, "2001:db8:ff::22")
	ceHas(bgp.RF_IPv6_UC, map[string]int{"2001:db8:1::/64": 3, "2001:db8:3::/64": 1})

	// Withdraw one identifier.
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:db8:1::/64"))
	mp, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{{NLRI: nlri}}, netip.MustParseAddr("2001:db8:ff::3"))
	p, _ := apiutil.NewPath(bgp.RF_IPv6_UC, nlri, false, []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), mp}, time.Now())
	dp := mustApi2apiutilPath(p)
	dp.RemoteID = 3
	require.NoError(t, pe.DeletePath(apiutil.DeletePathRequest{VRFID: "vrf1", Paths: []*apiutil.Path{dp}}))
	ceHas(bgp.RF_IPv6_UC, map[string]int{"2001:db8:1::/64": 2, "2001:db8:3::/64": 1})

	var vrfPrefixes []string
	require.NoError(t, pe.ListPath(apiutil.ListPathRequest{TableType: api.TableType_TABLE_TYPE_VRF, Name: "vrf1", Family: bgp.RF_IPv6_UC}, func(prefix bgp.NLRI, paths []*apiutil.Path) {
		vrfPrefixes = append(vrfPrefixes, prefix.String())
	}))
	require.ElementsMatch(t, []string{"111:111:2001:db8:1::/64", "111:111:2001:db8:3::/64"}, vrfPrefixes)

	require.NoError(t, pe.ResetPeer(ctx, &api.ResetPeerRequest{Address: "all", Soft: true, Direction: api.ResetPeerRequest_DIRECTION_OUT}))
	ceHas(bgp.RF_IPv6_UC, map[string]int{"2001:db8:1::/64": 2, "2001:db8:3::/64": 1})
	ceHas(bgp.RF_IPv4_UC, map[string]int{"10.1.0.0/24": 2})
}
