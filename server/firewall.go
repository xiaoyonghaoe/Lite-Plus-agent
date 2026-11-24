package server

import (
	"log"
	"time"

	"github.com/nuomiiiii/lite-agent/firewall"
	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

func RestorePersistedFirewall() {
	if err := firewall.RestorePersisted(); err != nil {
		log.Printf("firewall restore: %v", err)
	}
}

func WatchPersistedFirewall() {
	go flushProtectionReportsLoop()
	firewall.WatchOwned()
}

func flushProtectionReportsLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		FlushProtectionReports()
	}
}

func firewallMethodKind(method string) (string, bool) {
	switch method {
	case v2.MethodAgentFirewallSnapshot:
		return v2.FirewallKindSnapshot, true
	case v2.MethodAgentFirewallApply:
		return v2.FirewallKindApply, true
	case v2.MethodAgentFirewallAdopt:
		return v2.FirewallKindAdopt, true
	default:
		return "", false
	}
}

func processFirewallEvent(method string, params interface{}) bool {
	if _, ok := firewallMethodKind(method); !ok {
		return false
	}
	switch method {
	case v2.MethodAgentFirewallSnapshot:
		var p v2.FirewallSnapshotParams
		if err := v2.BindParams(params, &p); err != nil {
			log.Printf("bad firewall snapshot params: %v", err)
			return true
		}
		go reportFirewallResult(withRequest(firewall.Snapshot(), p.RequestID, v2.FirewallKindSnapshot))
		return true
	case v2.MethodAgentFirewallApply:
		var p v2.FirewallApplyParams
		if err := v2.BindParams(params, &p); err != nil {
			log.Printf("bad firewall apply params: %v", err)
			return true
		}
		go reportFirewallResult(withRequest(firewall.Apply(p.Intent, p.ListenHoles), p.RequestID, v2.FirewallKindApply))
		return true
	case v2.MethodAgentFirewallAdopt:
		var p v2.FirewallAdoptParams
		if err := v2.BindParams(params, &p); err != nil {
			log.Printf("bad firewall adopt params: %v", err)
			return true
		}
		go reportFirewallResult(withRequest(firewall.Adopt(p.Keys), p.RequestID, v2.FirewallKindAdopt))
		return true
	default:
		return false
	}
}

func withRequest(result v2.FirewallResultParams, requestID, kind string) v2.FirewallResultParams {
	result.RequestID = requestID
	if result.Kind == "" {
		result.Kind = kind
	}
	return result
}

func reportFirewallResult(result v2.FirewallResultParams) {
	payload := v2.Request{JSONRPC: v2.Version, Method: v2.MethodAgentFirewallResult, Params: result}
	reportV2Result(payload, "failed to upload firewall result")
}
