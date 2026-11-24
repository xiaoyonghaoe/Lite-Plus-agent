package server

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
	"github.com/nuomiiiii/lite-agent/runtimeconfig"
)

func TestComputeNextReportInterval(t *testing.T) {
	runtimeconfig.Initialize(runtimeconfig.State{Interval: 3.0})

	if got := computeNextReportInterval(v2.EventResult{HasMore: true, NextIntervalMS: 15000}); got != v2HasMoreDelay {
		t.Fatalf("HasMore delay = %v, want %v", got, v2HasMoreDelay)
	}
	if got := computeNextReportInterval(v2.EventResult{NextIntervalMS: 15000}); got != 15*time.Second {
		t.Fatalf("NextIntervalMS(15000) = %v, want 15s", got)
	}
	if got := computeNextReportInterval(v2.EventResult{NextIntervalMS: 100}); got != v2MinAdaptiveInterval {
		t.Fatalf("NextIntervalMS(100) = %v, want min %v", got, v2MinAdaptiveInterval)
	}
	if got := computeNextReportInterval(v2.EventResult{NextIntervalMS: int64((10 * time.Minute) / time.Millisecond)}); got != v2MaxAdaptiveInterval {
		t.Fatalf("NextIntervalMS(10m) = %v, want max %v", got, v2MaxAdaptiveInterval)
	}
	if got := computeNextReportInterval(v2.EventResult{}); got != 3*time.Second {
		t.Fatalf("default fallback = %v, want 3s", got)
	}
}

func TestProcessV2EventRejectsRemovedRemoteControlMethods(t *testing.T) {
	resetSeenEventsForTest(t)

	for _, method := range []string{
		v2.MethodAgentExec,
		v2.MethodAgentRemote,
		v2.MethodAgentMCPExec,
		v2.MethodAgentMCPFile,
		v2.MethodAgentFirewallInstall,
	} {
		if processV2Event(method, map[string]any{}, "evt-"+method) {
			t.Fatalf("method %s should not be accepted", method)
		}
	}
}

func TestReportOnceSendsAcksAndAdaptsInterval(t *testing.T) {
	resetSeenEventsForTest(t)
	v2AckMu.Lock()
	oldAcks := v2AckEventIDs
	v2AckEventIDs = nil
	v2AckMu.Unlock()
	t.Cleanup(func() {
		v2AckMu.Lock()
		v2AckEventIDs = oldAcks
		v2AckMu.Unlock()
	})

	origGen := generateReportFn
	origPost := postV2RequestFn
	t.Cleanup(func() {
		generateReportFn = origGen
		postV2RequestFn = origPost
	})

	generateReportFn = func() []byte { return []byte(`{"cpu":{"usage":1}}`) }

	var mu sync.Mutex
	var receivedAcks [][]string
	call := 0
	postV2RequestFn = func(ctx context.Context, payload []byte) (*v2.Response, error) {
		var req v2.Request
		if err := json.Unmarshal(payload, &req); err != nil {
			t.Fatalf("unmarshal request: %v", err)
		}
		var params struct {
			AckEventIDs []string `json:"ack_event_ids"`
		}
		if err := v2.BindParams(req.Params, &params); err != nil {
			t.Fatalf("bind params: %v", err)
		}
		mu.Lock()
		receivedAcks = append(receivedAcks, params.AckEventIDs)
		call++
		currentCall := call
		mu.Unlock()

		if currentCall == 1 {
			return &v2.Response{
				JSONRPC: v2.Version,
				ID:      req.ID,
				Result: v2.EventResult{
					Status: "success",
					Events: []v2.Event{
						{ID: "msg-1", Method: v2.MethodAgentMessage, Params: map[string]any{"text": "hi"}},
					},
					NextIntervalMS: 2000,
					HasMore:        true,
				},
			}, nil
		}
		return &v2.Response{
			JSONRPC: v2.Version,
			ID:      req.ID,
			Result: v2.EventResult{
				Status:         "success",
				NextIntervalMS: 15000,
				HasMore:        false,
			},
		}, nil
	}

	delay1 := reportOnce(context.Background())
	if delay1 != v2HasMoreDelay {
		t.Fatalf("first delay = %v, want %v", delay1, v2HasMoreDelay)
	}
	delay2 := reportOnce(context.Background())
	if delay2 != 15*time.Second {
		t.Fatalf("second delay = %v, want 15s", delay2)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(receivedAcks) != 2 {
		t.Fatalf("call count = %d, want 2", len(receivedAcks))
	}
	if len(receivedAcks[0]) != 0 {
		t.Fatalf("first acks = %v, want empty", receivedAcks[0])
	}
	if len(receivedAcks[1]) != 1 || receivedAcks[1][0] != "msg-1" {
		t.Fatalf("second acks = %v, want [msg-1]", receivedAcks[1])
	}
}
