package coreadapter

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestVirtualInboundAuthAndRouting(t *testing.T) {
	in := InboundSpec{
		ID:           "inb-1",
		Core:         "sing-box",
		Protocol:     "anytls",
		Port:         443,
		SettingsJSON: `{"virtual_tags":["home"]}`,
	}
	alice := UserSpec{
		ID:         "u-alice",
		Username:   "alice",
		UUID:       "11111111-1111-4111-8111-111111111111",
		Password:   "alice-pass",
		InboundIDs: []string{"inb-1", "inb-1#home"},
	}
	bob := UserSpec{
		ID:         "u-bob",
		Username:   "bob",
		UUID:       "22222222-2222-4222-8222-222222222222",
		Password:   "bob-pass",
		InboundIDs: []string{"inb-1"},
	}
	users := []UserSpec{alice, bob}

	entries := userEntriesForInbound(users, in)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries (alice, alice@home, bob), got %d", len(entries))
	}
	if entries[0].ID != "u-alice" || entries[0].Password != "alice-pass" {
		t.Fatalf("unexpected entry[0]: %+v", entries[0])
	}
	if entries[1].ID != "u-alice@home" || entries[1].Password == "alice-pass" || entries[1].Password == "" {
		t.Fatalf("unexpected virtual entry[1]: %+v", entries[1])
	}
	if entries[2].ID != "u-bob" {
		t.Fatalf("unexpected entry[2]: %+v", entries[2])
	}

	// Policy engine should map virtual auth_user "u-alice@home" back to base "u-alice"
	pe := newPolicyEngineWithRole("sing-box")
	pe.sync(users, nil)
	if got := pe.knownUserID("u-alice@home"); got != "u-alice" {
		t.Fatalf("expected knownUserID(u-alice@home)=u-alice, got %q", got)
	}

	// Route rules: virtual inbound route must restrict auth_user to u-alice@home only,
	// and primary inbound route must restrict auth_user to u-alice & u-bob (excluding u-alice@home).
	inbounds := []InboundSpec{in}
	outbounds := []OutboundSpec{
		{ID: "out-home", Name: "home-residential", Protocol: "socks", Enabled: true},
	}
	routes := []RouteSpec{
		{ID: "r1", Priority: 10, Enabled: true, RuleJSON: `{"inbound_id":"inb-1#home","outbound_id":"out-home"}`},
		{ID: "r2", Priority: 20, Enabled: true, RuleJSON: `{"inbound_id":"inb-1","outbound_id":"direct"}`},
	}
	listenTags := map[string][]string{"inb-1": {"inb-1"}}

	sbRules := singBoxRouteRules(routes, outbounds, inbounds, users, listenTags)
	if len(sbRules) != 2 {
		t.Fatalf("expected 2 sing-box rules, got %d", len(sbRules))
	}
	raw, _ := json.Marshal(sbRules)
	gotHome, _ := sbRules[0]["auth_user"].([]string)
	if len(gotHome) != 1 || gotHome[0] != "u-alice@home" {
		t.Fatalf("expected home rule auth_user=[u-alice@home], got %v (all=%s)", gotHome, string(raw))
	}
	gotPrimary, _ := sbRules[1]["auth_user"].([]string)
	if len(gotPrimary) != 2 || gotPrimary[0] != "u-alice" || gotPrimary[1] != "u-bob" {
		t.Fatalf("expected primary rule auth_user=[u-alice u-bob], got %v", gotPrimary)
	}

	// Xray route rules should emit "user" similarly
	xrRules := xrayRouteRules(routes, outbounds, inbounds, users, listenTags)
	if len(xrRules) != 2 {
		t.Fatalf("expected 2 xray rules, got %d", len(xrRules))
	}
	xrHome, _ := xrRules[0]["user"].([]string)
	if len(xrHome) != 1 || xrHome[0] != "u-alice@home" {
		t.Fatalf("expected xray home rule user=[u-alice@home], got %v", xrHome)
	}
}

func TestDomainNormalizationAndStatsCollector(t *testing.T) {
	cases := map[string]string{
		"www.youtube.com":       "youtube.com",
		"r3---sn.googlevideo.com.": "googlevideo.com",
		"sub.api.bbc.co.uk":     "bbc.co.uk",
		"a.b.com.cn":            "b.com.cn",
		"1.1.1.1":               "",
		"[2001:4860:4860::8888]": "",
		"localhost":             "",
		"example.com:443":       "example.com",
	}
	for in, want := range cases {
		if got := normalizeRootDomain(in); got != want {
			t.Fatalf("normalizeRootDomain(%q) = %q, want %q", in, got, want)
		}
	}

	col := newStatsCollector()
	// Disabled by default: records must be ignored
	col.record("inb-1", "u1", "youtube.com", 100, 200)
	if !col.Drain(15).Empty() {
		t.Fatalf("expected empty batch when stats disabled")
	}

	col.SetEnabled(true)
	for i := 1; i <= 25; i++ {
		col.record("inb-1#home", "u1", fmt.Sprintf("site%02d.com", i), int64(i*10), int64(i*100))
	}
	// Separate user should have independent top-N bucket and up/down split
	upFn, downFn, flush := col.newConnCallbacks("inb-1", "u2", "youtube.com")
	upFn(120)
	downFn(880)
	flush()

	batch := col.Drain(20)
	if len(batch.InboundUsage) != 2 {
		t.Fatalf("expected 2 inbound usage rows, got %d", len(batch.InboundUsage))
	}
	if len(batch.DomainTop) != 21 {
		t.Fatalf("expected 21 domain rows (20 for u1 + 1 for u2), got %d", len(batch.DomainTop))
	}
	var u1Domains []DomainUsageDelta
	var u2Domain *DomainUsageDelta
	for i := range batch.DomainTop {
		d := batch.DomainTop[i]
		if d.UserID == "u1" {
			u1Domains = append(u1Domains, d)
		} else if d.UserID == "u2" {
			cp := d
			u2Domain = &cp
		}
	}
	if len(u1Domains) != 20 || u1Domains[0].Domain != "site25.com" || u1Domains[19].Domain != "site06.com" {
		t.Fatalf("unexpected u1 top domain ordering: len=%d first=%+v", len(u1Domains), u1Domains[0])
	}
	if u2Domain == nil || u2Domain.Domain != "youtube.com" || u2Domain.UpBytes != 120 || u2Domain.DownBytes != 880 || u2Domain.Bytes != 1000 {
		t.Fatalf("unexpected u2 domain delta: %+v", u2Domain)
	}
	// Second drain should be empty
	if !col.Drain(20).Empty() {
		t.Fatalf("expected empty batch after drain")
	}
}
