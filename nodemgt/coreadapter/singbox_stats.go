package coreadapter

import (
	"context"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

const (
	statsDefaultTopN        = 30
	statsMaxDomainKeys      = 2048
	statsConnFlushBytes     = 64 * 1024
	statsConnFlushIntervalN = int64(2 * time.Second)
)

type InboundUsageDelta struct {
	InboundID string `json:"inbound_id"`
	UserID    string `json:"user_id"`
	UpBytes   int64  `json:"up_bytes"`
	DownBytes int64  `json:"down_bytes"`
}

type DomainUsageDelta struct {
	UserID    string `json:"user_id"`
	InboundID string `json:"inbound_id,omitempty"`
	Domain    string `json:"domain"`
	UpBytes   int64  `json:"up_bytes"`
	DownBytes int64  `json:"down_bytes"`
	Bytes     int64  `json:"bytes"`
}

type StatsBatch struct {
	InboundUsage []InboundUsageDelta `json:"inbound_usage"`
	DomainTop    []DomainUsageDelta  `json:"domain_top"`
}

func (b StatsBatch) Empty() bool {
	return len(b.InboundUsage) == 0 && len(b.DomainTop) == 0
}

type inbUserKey struct {
	inboundID string
	userID    string
}

type inbBytes struct {
	up   int64
	down int64
}

type userDomainKey struct {
	userID string
	domain string
}

// statsCollector aggregates per-(inbound, user) and per-(user, root-domain)
// byte counters in memory. When disabled, Enabled() returns false via a single
// atomic load so connections incur zero lock or wrapper overhead.
type statsCollector struct {
	enabled      atomic.Bool
	mu           sync.Mutex
	tagToInbound map[string]string
	inboundUsage map[inbUserKey]*inbBytes
	domainUsage  map[userDomainKey]*inbBytes
}

func newStatsCollector() *statsCollector {
	return &statsCollector{
		tagToInbound: map[string]string{},
		inboundUsage: map[inbUserKey]*inbBytes{},
		domainUsage:  map[userDomainKey]*inbBytes{},
	}
}

func (s *statsCollector) Enabled() bool {
	return s != nil && s.enabled.Load()
}

func (s *statsCollector) SetEnabled(on bool) {
	if s == nil {
		return
	}
	s.enabled.Store(on)
	if !on {
		s.mu.Lock()
		s.inboundUsage = map[inbUserKey]*inbBytes{}
		s.domainUsage = map[userDomainKey]*inbBytes{}
		s.mu.Unlock()
	}
}

func (s *statsCollector) setTagMap(m map[string]string) {
	if s == nil {
		return
	}
	cp := make(map[string]string, len(m))
	for k, v := range m {
		cp[k] = v
	}
	s.mu.Lock()
	s.tagToInbound = cp
	s.mu.Unlock()
}

func (s *statsCollector) resolveBaseInbound(tag string) string {
	tag = strings.TrimSpace(tag)
	if tag == "" || s == nil {
		return tag
	}
	s.mu.Lock()
	id, ok := s.tagToInbound[tag]
	s.mu.Unlock()
	if ok && id != "" {
		return id
	}
	return tag
}

func (s *statsCollector) record(inboundID, userID, domain string, up, down int64) {
	if s == nil || !s.enabled.Load() || (up <= 0 && down <= 0) {
		return
	}
	inboundID = strings.TrimSpace(inboundID)
	if inboundID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if userID != "" {
		k := inbUserKey{inboundID: inboundID, userID: userID}
		entry := s.inboundUsage[k]
		if entry == nil {
			entry = &inbBytes{}
			s.inboundUsage[k] = entry
		}
		if up > 0 {
			entry.up += up
		}
		if down > 0 {
			entry.down += down
		}
	}

	if userID != "" && domain != "" {
		dk := userDomainKey{userID: userID, domain: domain}
		entry := s.domainUsage[dk]
		if entry == nil {
			if len(s.domainUsage) < statsMaxDomainKeys {
				entry = &inbBytes{}
				s.domainUsage[dk] = entry
			}
		}
		if entry != nil {
			if up > 0 {
				entry.up += up
			}
			if down > 0 {
				entry.down += down
			}
		}
	}
}

// newConnCallbacks creates per-connection atomic accumulators that flush into
// statsCollector when buffered bytes reach statsConnFlushBytes, after
// statsConnFlushIntervalN, or when the returned flush callback is invoked on close.
func (s *statsCollector) newConnCallbacks(inboundID, userID, domain string) (upFn, downFn func(int64), flush func()) {
	var upBuf, downBuf atomic.Int64
	var lastFlush atomic.Int64
	lastFlush.Store(time.Now().UnixNano())

	flush = func() {
		u := upBuf.Swap(0)
		d := downBuf.Swap(0)
		if u > 0 || d > 0 {
			lastFlush.Store(time.Now().UnixNano())
			s.record(inboundID, userID, domain, u, d)
		}
	}
	maybeFlush := func() {
		if upBuf.Load()+downBuf.Load() >= statsConnFlushBytes {
			flush()
			return
		}
		nowNs := time.Now().UnixNano()
		if nowNs-lastFlush.Load() >= statsConnFlushIntervalN {
			flush()
		}
	}
	upFn = func(n int64) {
		if n <= 0 {
			return
		}
		upBuf.Add(n)
		maybeFlush()
	}
	downFn = func(n int64) {
		if n <= 0 {
			return
		}
		downBuf.Add(n)
		maybeFlush()
	}
	return upFn, downFn, flush
}

// Drain swaps out the accumulated counters and returns a StatsBatch with at most
// topN domains per userID.
func (s *statsCollector) Drain(topN int) StatsBatch {
	if s == nil {
		return StatsBatch{}
	}
	if topN <= 0 {
		topN = statsDefaultTopN
	}
	s.mu.Lock()
	inbMap := s.inboundUsage
	domMap := s.domainUsage
	s.inboundUsage = map[inbUserKey]*inbBytes{}
	s.domainUsage = map[userDomainKey]*inbBytes{}
	s.mu.Unlock()

	var batch StatsBatch
	if len(inbMap) > 0 {
		batch.InboundUsage = make([]InboundUsageDelta, 0, len(inbMap))
		for k, v := range inbMap {
			if v.up <= 0 && v.down <= 0 {
				continue
			}
			batch.InboundUsage = append(batch.InboundUsage, InboundUsageDelta{
				InboundID: k.inboundID,
				UserID:    k.userID,
				UpBytes:   v.up,
				DownBytes: v.down,
			})
		}
	}

	if len(domMap) > 0 {
		byUser := map[string][]DomainUsageDelta{}
		for k, v := range domMap {
			total := v.up + v.down
			if total <= 0 {
				continue
			}
			byUser[k.userID] = append(byUser[k.userID], DomainUsageDelta{
				UserID:    k.userID,
				Domain:    k.domain,
				UpBytes:   v.up,
				DownBytes: v.down,
				Bytes:     total,
			})
		}
		for _, list := range byUser {
			sort.Slice(list, func(i, j int) bool {
				if list[i].Bytes != list[j].Bytes {
					return list[i].Bytes > list[j].Bytes
				}
				return list[i].Domain < list[j].Domain
			})
			if len(list) > topN {
				list = list[:topN]
			}
			batch.DomainTop = append(batch.DomainTop, list...)
		}
	}
	return batch
}

type statsTracker struct {
	policy    *policyEngine
	collector *statsCollector
}

func newStatsTracker(policy *policyEngine, collector *statsCollector) *statsTracker {
	return &statsTracker{policy: policy, collector: collector}
}

func (t *statsTracker) extractMeta(metadata adapter.InboundContext) (inboundID, userID, domain string, ok bool) {
	if t == nil || t.collector == nil || !t.collector.Enabled() {
		return "", "", "", false
	}
	baseInb := t.collector.resolveBaseInbound(metadata.Inbound)
	if baseInb == "" {
		return "", "", "", false
	}
	_, vtag := SplitVirtualUserKey(metadata.User)
	inboundID = FormatVirtualInboundID(baseInb, vtag)
	if t.policy != nil {
		userID = t.policy.knownUserID(metadata.User)
	}
	if userID == "" {
		userID, _ = SplitVirtualUserKey(metadata.User)
	}
	rawDomain := strings.TrimSpace(metadata.Domain)
	if rawDomain == "" {
		rawDomain = strings.TrimSpace(metadata.Destination.Fqdn)
	}
	domain = normalizeRootDomain(rawDomain)
	return inboundID, userID, domain, true
}

type flushOnCloseConn struct {
	net.Conn
	flush func()
}

func (c *flushOnCloseConn) Close() error {
	if c.flush != nil {
		c.flush()
	}
	return c.Conn.Close()
}

type flushOnClosePacketConn struct {
	N.PacketConn
	flush func()
}

func (c *flushOnClosePacketConn) Close() error {
	if c.flush != nil {
		c.flush()
	}
	return c.PacketConn.Close()
}

func (t *statsTracker) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	if conn == nil {
		return conn
	}
	inboundID, userID, domain, ok := t.extractMeta(metadata)
	if !ok {
		return conn
	}
	// In sing-box Router.RoutedConnection, conn is the inbound client connection:
	// Read receives client upload bytes; Write sends target download bytes back to client.
	readCount, writeCount, flush := t.collector.newConnCallbacks(inboundID, userID, domain)
	return &flushOnCloseConn{
		Conn:  bufio.NewCounterConn(conn, []N.CountFunc{readCount}, []N.CountFunc{writeCount}),
		flush: flush,
	}
}

func (t *statsTracker) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) N.PacketConn {
	if conn == nil {
		return conn
	}
	inboundID, userID, domain, ok := t.extractMeta(metadata)
	if !ok {
		return conn
	}
	// In sing-box Router.RoutedConnection, conn is the inbound client connection:
	// Read receives client upload bytes; Write sends target download bytes back to client.
	readCount, writeCount, flush := t.collector.newConnCallbacks(inboundID, userID, domain)
	return &flushOnClosePacketConn{
		PacketConn: bufio.NewCounterPacketConn(conn, []N.CountFunc{readCount}, []N.CountFunc{writeCount}),
		flush:      flush,
	}
}

func (t *statsTracker) RoutedFlow(ctx context.Context, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) tun.FlowTracker {
	return nil
}
