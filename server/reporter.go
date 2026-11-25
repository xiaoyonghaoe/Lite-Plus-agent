package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/nuomiiiii/lite-agent/monitoring"
	nodemgtruntime "github.com/nuomiiiii/lite-agent/nodemgt/runtime"
	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
	"github.com/nuomiiiii/lite-agent/runtimeconfig"
)

var (
	v2AckMu        sync.Mutex
	v2AckEventIDs  []string
	v2SeenEvents   = make(map[string]struct{})
	v2SeenEventIDs []string
)

const (
	v2SeenEventLimit         = 512
	v2HasMoreDelay           = 200 * time.Millisecond
	v2MinAdaptiveInterval    = 500 * time.Millisecond
	v2MaxAdaptiveInterval    = 5 * time.Minute
	defaultHTTPReportTimeout = 35 * time.Second
)

var (
	generateReportFn = monitoring.GenerateReport
	postV2RequestFn  = postV2RequestContext
)

// RunHTTPReporter runs the pure HTTP Keep-Alive reporting loop.
// Every POST carries monitoring metrics and pending event ACKs, and receives
// piggybacked control events along with the server's adaptive next_interval_ms.
func RunHTTPReporter(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-runtimeconfig.Changes():
			resetTimer(timer, reportIntervalDuration())
		case <-timer.C:
			nextDelay := reportOnce(ctx)
			if ctx.Err() != nil {
				return
			}
			resetTimer(timer, nextDelay)
		}
	}
}

func resetTimer(timer *time.Timer, d time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	if d <= 0 {
		d = time.Second
	}
	timer.Reset(d)
}

func reportOnce(ctx context.Context) time.Duration {
	reportID := fmt.Sprintf("report-%d", time.Now().UnixNano())
	ackIDs := snapshotV2AckEventIDs()
	resp, err := postV2RequestFn(ctx, v2.BuildReportRequest(reportID, generateReportFn(), ackIDs))
	if err != nil {
		if ctx.Err() == nil {
			log.Println("Failed to POST v2 report:", err)
		}
		return reporterErrorBackoff()
	}
	clearV2AckEventIDs(ackIDs)
	return processV2ResponseEvents(resp)
}

func reporterErrorBackoff() time.Duration {
	if flags != nil && flags.ReconnectInterval > 0 {
		return time.Duration(flags.ReconnectInterval) * time.Second
	}
	return 5 * time.Second
}

func reportIntervalDuration() time.Duration {
	d := time.Duration(runtimeconfig.ReportInterval() * float64(time.Second))
	if d <= 0 {
		return 3 * time.Second
	}
	return d
}

func computeNextReportInterval(result v2.EventResult) time.Duration {
	if result.HasMore {
		return v2HasMoreDelay
	}
	if result.NextIntervalMS > 0 {
		d := time.Duration(result.NextIntervalMS) * time.Millisecond
		if d < v2MinAdaptiveInterval {
			return v2MinAdaptiveInterval
		}
		if d > v2MaxAdaptiveInterval {
			return v2MaxAdaptiveInterval
		}
		return d
	}
	return reportIntervalDuration()
}

func postV2Request(payload []byte) (*v2.Response, error) {
	return postV2RequestContext(context.Background(), payload)
}

func postV2RequestContext(ctx context.Context, payload []byte) (*v2.Response, error) {
	status, bytesBody, err := postV2JSONRPC(ctx, payload, defaultHTTPReportTimeout)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, &httpStatusError{StatusCode: status, Status: http.StatusText(status), Body: string(bytesBody)}
	}
	rpcResp, err := parseV2Response(bytesBody)
	if err != nil {
		return nil, err
	}
	return rpcResp, nil
}

func processV2ResponseEvents(resp *v2.Response) time.Duration {
	if resp == nil || resp.Result == nil {
		return reportIntervalDuration()
	}
	var result v2.EventResult
	if err := v2.BindResult(resp.Result, &result); err != nil {
		log.Println("Failed to bind v2 event result:", err)
		return reportIntervalDuration()
	}
	if result.StatsIntervalMS > 0 {
		if rt := nodemgtruntime.Current(); rt != nil {
			rt.SetStatsInterval(time.Duration(result.StatsIntervalMS) * time.Millisecond)
		}
	}
	for _, event := range result.Events {
		if processV2Event(event.Method, event.Params, event.ID) {
			addV2AckEventID(event.ID)
		}
	}
	return computeNextReportInterval(result)
}

func snapshotV2AckEventIDs() []string {
	v2AckMu.Lock()
	defer v2AckMu.Unlock()
	return append([]string{}, v2AckEventIDs...)
}

func clearV2AckEventIDs(sent []string) {
	if len(sent) == 0 {
		return
	}
	sentSet := make(map[string]struct{}, len(sent))
	for _, id := range sent {
		sentSet[id] = struct{}{}
	}
	v2AckMu.Lock()
	defer v2AckMu.Unlock()
	remaining := v2AckEventIDs[:0]
	for _, id := range v2AckEventIDs {
		if _, ok := sentSet[id]; !ok {
			remaining = append(remaining, id)
		}
	}
	v2AckEventIDs = remaining
}

func addV2AckEventID(id string) {
	if id == "" {
		return
	}
	v2AckMu.Lock()
	defer v2AckMu.Unlock()
	v2AckEventIDs = append(v2AckEventIDs, id)
}

func markV2EventSeen(id string) bool {
	if id == "" {
		return true
	}
	v2AckMu.Lock()
	defer v2AckMu.Unlock()
	if _, ok := v2SeenEvents[id]; ok {
		return false
	}
	v2SeenEvents[id] = struct{}{}
	v2SeenEventIDs = append(v2SeenEventIDs, id)
	if len(v2SeenEventIDs) > v2SeenEventLimit {
		oldest := v2SeenEventIDs[0]
		v2SeenEventIDs = v2SeenEventIDs[1:]
		delete(v2SeenEvents, oldest)
	}
	return true
}

func forgetV2Event(id string) {
	if id == "" {
		return
	}
	v2AckMu.Lock()
	defer v2AckMu.Unlock()
	delete(v2SeenEvents, id)
	for i, seenID := range v2SeenEventIDs {
		if seenID == id {
			v2SeenEventIDs = append(v2SeenEventIDs[:i], v2SeenEventIDs[i+1:]...)
			break
		}
	}
}

func processV2Event(method string, params interface{}, eventID string) bool {
	if !markV2EventSeen(eventID) {
		return true
	}
	switch method {
	case v2.MethodAgentPing:
		var p struct {
			TaskID uint   `json:"ping_task_id"`
			Type   string `json:"ping_type"`
			Target string `json:"ping_target"`
		}
		if err := v2.BindParams(params, &p); err == nil {
			go NewPingTask(p.TaskID, p.Type, p.Target)
			return true
		} else {
			log.Printf("bad v2 ping params: %v", err)
		}
	case v2.MethodAgentRoute:
		var p v2.RouteParams
		if err := v2.BindParams(params, &p); err == nil {
			go NewRouteTask(p)
			return true
		} else {
			log.Printf("bad v2 route params: %v", err)
		}
	case v2.MethodAgentConfig:
		var p v2.ConfigParams
		if err := v2.BindParams(params, &p); err != nil {
			forgetV2Event(eventID)
			log.Printf("bad v2 config params: %v", err)
			return false
		}
		return processRuntimeConfig(p, eventID)
	case v2.MethodNodemgtControl:
		if nodemgtrt := nodemgtRuntimeHandle(); nodemgtrt != nil {
			return nodemgtrt(params, eventID)
		}
	case v2.MethodNodemgtRealityProbe:
		var p v2.RealityProbeParams
		if err := v2.BindParams(params, &p); err == nil {
			go NewRealityProbeTask(p)
			return true
		} else {
			log.Printf("bad v2 reality probe params: %v", err)
		}
		forgetV2Event(eventID)
		log.Printf("nodemgt.control received before runtime start")
		return false
	case v2.MethodAgentFirewallSnapshot, v2.MethodAgentFirewallApply, v2.MethodAgentFirewallAdopt:
		return processFirewallEvent(method, params)
	case v2.MethodAgentProtectionPrecheck, v2.MethodAgentProtectionUpgrade, v2.MethodAgentProtectionApplyConfig, v2.MethodAgentProtectionBan, v2.MethodAgentProtectionUnban, v2.MethodAgentProtectionGroupSnapshot, v2.MethodAgentProtectionPreview:
		return processProtectionEvent(method, params)
	case v2.MethodAgentMessage, v2.MethodAgentEvent:
		log.Printf("received v2 %s: %+v", method, params)
		return true
	default:
		log.Printf("ignored unsupported v2 event method %s", method)
	}
	return false
}
