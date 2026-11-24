package coreadapter

import (
	"context"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

const (
	statsDefaultTopN   = 15
	statsMaxDomainKeys = 2048
)

type InboundUsageDelta struct {
	InboundID string `json:"inbound_id"`
	UserID    string `json:"user_id"`
	UpBytes   int64  `json:"up_bytes"`
	DownBytes int64  `json:"down_bytes"`
}

type DomainUsageDelta struct {
	InboundID string `json:"inbound_id"`
	Domain    string `json:"domain"`
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

type inbDomainKey struct {
	inboundID string
	domain    string
}

// statsCollector aggregates per-(inbound, user) and per-(inbound, root-domain)
// byte counters in memory. When disabled, Enabled() returns false via a single
// atomic load so connections incur zero lock or wrapper overhead.
type statsCollector struct {
	enabled      atomic.Bool
	mu           sync.Mutex
	tagToInbound map[string]string
	inboundUsage map[inbUserKey]*inbBytes
	domainUsage  map[inbDomainKey]int64
}

func newStatsCollector() *statsCollector {
	return &statsCollector{
		tagToInbound: map[string]string{},
		inboundUsage: map[inbUserKey]*inbBytes{},
		domainUsage:  map[inbDomainKey]int64{},
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
		s.domainUsage = map[inbDomainKey]int64{}
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

	if domain != "" {
		dk := inbDomainKey{inboundID: inboundID, domain: domain}
		if _, exists := s.domainUsage[dk]; exists || len(s.domainUsage) < statsMaxDomainKeys {
			s.domainUsage[dk] += up + down
		}
	}
}

// Drain swaps out the accumulated counters and returns a StatsBatch with at most
// topN domains per inboundID.
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
	s.domainUsage = map[inbDomainKey]int64{}
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
		byInb := map[string][]DomainUsageDelta{}
		for k, total := range domMap {
			if total <= 0 {
				continue
			}
			byInb[k.inboundID] = append(byInb[k.inboundID], DomainUsageDelta{
				InboundID: k.inboundID,
				Domain:    k.domain,
				Bytes:     total,
			})
		}
		for _, list := range byInb {
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

func (t *statsTracker) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	if conn == nil {
		return conn
	}
	inboundID, userID, domain, ok := t.extractMeta(metadata)
	if !ok {
		return conn
	}
	// In sing-box Router.RoutedConnection, conn is the outbound connection:
	// Write sends client upload bytes to target; Read receives target download bytes.
	readCount := func(n int64) {
		t.collector.record(inboundID, userID, domain, 0, n)
	}
	writeCount := func(n int64) {
		t.collector.record(inboundID, userID, domain, n, 0)
	}
	return bufio.NewCounterConn(conn, []N.CountFunc{readCount}, []N.CountFunc{writeCount})
}

func (t *statsTracker) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) N.PacketConn {
	if conn == nil {
		return conn
	}
	inboundID, userID, domain, ok := t.extractMeta(metadata)
	if !ok {
		return conn
	}
	// In sing-box Router.RoutedConnection, conn is the outbound connection:
	// Write sends client upload bytes to target; Read receives target download bytes.
	readCount := func(n int64) {
		t.collector.record(inboundID, userID, domain, 0, n)
	}
	writeCount := func(n int64) {
		t.collector.record(inboundID, userID, domain, n, 0)
	}
	return bufio.NewCounterPacketConn(conn, []N.CountFunc{readCount}, []N.CountFunc{writeCount})
}

func (t *statsTracker) RoutedFlow(ctx context.Context, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) tun.FlowTracker {
	return nil
}
