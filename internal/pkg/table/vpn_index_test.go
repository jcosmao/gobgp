package table

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func mustRT(t testing.TB, s string) bgp.ExtendedCommunityInterface {
	t.Helper()
	rt, err := bgp.ParseRouteTarget(s)
	require.NoError(t, err)
	return rt
}

func newTestVPNPath(t testing.TB, pi *PeerInfo, prefix netip.Prefix, rd bgp.RouteDistinguisherInterface, pathID, localPref uint32, rts ...bgp.ExtendedCommunityInterface) *Path {
	t.Helper()
	nlri, err := bgp.NewLabeledVPNIPAddrPrefix(prefix, *bgp.NewMPLSLabelStack(), rd)
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeLocalPref(localPref),
	}
	if len(rts) > 0 {
		attrs = append(attrs, bgp.NewPathAttributeExtendedCommunities(rts))
	}
	return NewPath(bgp.RF_IPv4_VPN, pi, bgp.PathNLRI{NLRI: nlri, ID: pathID}, false, attrs, time.Now(), false)
}

func testPeer(addr string) *PeerInfo {
	a := netip.MustParseAddr(addr)
	return &PeerInfo{Address: a, ID: a}
}

// Paths of the same destination, 100:1:10.0.0.1/32, from peer.
func newTestVPNPathTo(t testing.TB, peer string, pathID, localPref uint32, rts ...bgp.ExtendedCommunityInterface) *Path {
	t.Helper()
	rd := bgp.NewRouteDistinguisherTwoOctetAS(100, 1)
	return newTestVPNPath(t, testPeer(peer), netip.MustParsePrefix("10.0.0.1/32"), rd, pathID, localPref, rts...)
}

func newTestVPNTableManager() *TableManager {
	return NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_VPN}, oc.RouteSelectionOptionsConfig{}, oc.UseMultiplePathsConfig{})
}

// GetPathsByRT returns the best path of a destination only for a Route
// Target the best path carries, even if another path carries more.
func TestGetPathsByRTOnlyRouteTargetsOfTheBest(t *testing.T) {
	rtA, rtB := mustRT(t, "100:1"), mustRT(t, "100:2")
	fs := []bgp.Family{bgp.RF_IPv4_VPN}
	m := newTestVPNTableManager()

	best := newTestVPNPathTo(t, "1.1.1.1", 0, 200, rtA)
	other := newTestVPNPathTo(t, "2.2.2.2", 0, 100, rtA, rtB)
	m.Update(best)
	m.Update(other)
	require.Equal(t, []*Path{best}, m.GetPathsByRT(rtA, fs))
	require.Empty(t, m.GetPathsByRT(rtB, fs))

	m.Update(best.Clone(true))
	require.Equal(t, []*Path{other}, m.GetPathsByRT(rtA, fs))
	require.Equal(t, []*Path{other}, m.GetPathsByRT(rtB, fs))
}

// Two route reflectors send the same path: only the first is indexed. A path
// with a new Route Target is indexed, under each of its Route Targets. Once
// every path is withdrawn, the index is empty.
func TestVPNIndexOnePathPerRouteTarget(t *testing.T) {
	rtA, rtB := mustRT(t, "100:1"), mustRT(t, "100:2")
	m := newTestVPNTableManager()
	tbl, _ := m.GetTable(bgp.RF_IPv4_VPN)

	rr1 := newTestVPNPathTo(t, "1.1.1.1", 0, 100, rtA)
	rr2 := newTestVPNPathTo(t, "2.2.2.2", 0, 100, rtA)
	m.Update(rr1)
	m.Update(rr2)
	require.Equal(t, []*Path{rr1}, tbl.vpnIdx.GetPathsByRT(rtA))

	both := newTestVPNPathTo(t, "3.3.3.3", 0, 100, rtA, rtB)
	m.Update(both)
	require.ElementsMatch(t, []*Path{rr1, both}, tbl.vpnIdx.GetPathsByRT(rtA))
	require.Equal(t, []*Path{both}, tbl.vpnIdx.GetPathsByRT(rtB))

	for _, p := range []*Path{rr1, rr2, both} {
		m.Update(p.Clone(true))
	}
	require.Empty(t, tbl.vpnIdx.rts)
}
