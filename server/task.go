package server

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
	ping "github.com/prometheus-community/pro-bing"
)

// resolveIP 解析域名到 IP 地址，排除 DNS 查询时间
func resolveIP(target string) (string, error) {
	if ip := net.ParseIP(target); ip != nil {
		return target, nil
	}
	addrs, err := net.LookupHost(target)
	if err != nil || len(addrs) == 0 {
		return "", errors.New("failed to resolve target")
	}
	return addrs[0], nil
}

func latencyMilliseconds(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

func icmpPing(target string, timeout time.Duration) (float64, error) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	host = strings.Trim(host, "[]")

	ip, err := resolveIP(host)
	if err != nil {
		return -1, err
	}

	pinger, err := ping.NewPinger(ip)
	if err != nil {
		return -1, err
	}
	pinger.Count = 1
	pinger.Timeout = timeout
	pinger.SetPrivileged(true)
	err = pinger.Run()
	if err != nil {
		return -1, err
	}
	stats := pinger.Statistics()
	if stats.PacketsRecv == 0 {
		return -1, errors.New("no packets received")
	}
	return latencyMilliseconds(stats.AvgRtt), nil
}

func tcpPing(target string, timeout time.Duration) (float64, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		port = "80"
	}

	host = strings.Trim(host, "[]")

	ip, err := resolveIP(host)
	if err != nil {
		return -1, err
	}

	targetAddr := net.JoinHostPort(ip, port)
	start := time.Now()
	conn, err := net.DialTimeout("tcp", targetAddr, timeout)
	if err != nil {
		return -1, err
	}
	defer conn.Close()
	return latencyMilliseconds(time.Since(start)), nil
}

// httpPingUserAgent 用常见浏览器标识，避免站点把 Go 默认 UA 直接拦成 403。
const httpPingUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

func httpPing(target string, timeout time.Duration) (float64, error) {
	if strings.Contains(target, ":") && !strings.Contains(target, "[") {
		if ip := net.ParseIP(target); ip != nil && ip.To4() == nil {
			target = "[" + target + "]"
		}
	}

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return -1, err
	}
	req.Header.Set("User-Agent", httpPingUserAgent)
	req.Header.Set("Accept", "*/*")

	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ip, err := resolveIP(host)
			if err != nil {
				return nil, err
			}
			return net.DialTimeout(network, net.JoinHostPort(ip, port), timeout)
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
	start := time.Now()
	resp, err := client.Do(req)
	latency := latencyMilliseconds(time.Since(start))
	if err != nil {
		return -1, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return latency, nil
	}
	return latency, errors.New("http status not ok")
}

func NewPingTask(taskID uint, pingType, pingTarget string) {
	if taskID == 0 {
		log.Printf("Invalid task ID: %d", taskID)
		return
	}
	var err error
	var latency float64
	pingResult := -1.0
	timeout := 3 * time.Second
	const highLatencyThreshold = 1000.0
	const retryDropThresholdTcping = 800.0

	measure := func() (float64, error) {
		switch pingType {
		case "icmp":
			return icmpPing(pingTarget, timeout)
		case "tcp":
			return tcpPing(pingTarget, timeout)
		case "http":
			return httpPing(pingTarget, timeout)
		default:
			return -1, errors.New("unsupported ping type")
		}
	}
	PingHighLatencyRetries := 3
	if latency, err = measure(); err == nil {
		firstLatency := latency
		if latency > highLatencyThreshold && PingHighLatencyRetries > 0 {
			attempts := PingHighLatencyRetries
			for i := 0; i < attempts; i++ {
				if second, err2 := measure(); err2 == nil {
					if second <= highLatencyThreshold {
						if pingType == "tcp" && firstLatency-second > retryDropThresholdTcping {
							err = errors.New("suspicious retransmission detected in tcp handshake")
							break
						}
						latency = second
						break
					}
					if i == attempts-1 {
						err = errors.New("latency remains high after retries")
					}
				} else {
					err = err2
					break
				}
			}
		}
	}

	if err != nil {
		log.Printf("Ping task %d failed: %v", taskID, err)
		pingResult = -1
	} else {
		pingResult = latency
	}
	finishedAt := time.Now()
	payload := v2.BuildPingResultPayload(taskID, pingType, pingResult, finishedAt)
	reportV2Result(payload, "Failed to upload ping result")
}

func reportV2Result(payload interface{}, failLog string) {
	if err := postV2RPC(payload); err != nil {
		log.Printf("%s: %v", failLog, err)
	}
}

func postV2RPC(payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	status, respBody, err := postV2JSONRPC(context.Background(), body, 30*time.Second)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return &httpStatusError{StatusCode: status, Status: http.StatusText(status), Body: string(respBody)}
	}
	return nil
}
