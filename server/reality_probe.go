package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	v2 "github.com/nuomiiiii/lite-agent/protocol/v2"
)

func NewRealityProbeTask(p v2.RealityProbeParams) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	res := ProbeRealityTarget(ctx, p.Dest, p.ServerName)
	res.RequestID = p.RequestID
	payload := v2.Request{
		JSONRPC: v2.Version,
		Method:  v2.MethodNodemgtRealityProbeResult,
		Params:  res,
		ID:      fmt.Sprintf("reality-probe-%d", time.Now().UnixNano()),
	}
	reportV2Result(payload, "Failed to upload Reality probe result")
}

func isLoopbackDest(host string) bool {
	h := strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))
	if h == "localhost" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

func tlsVersionName(ver uint16) string {
	switch ver {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		if ver == 0 {
			return ""
		}
		return fmt.Sprintf("0x%04x", ver)
	}
}

// ProbeRealityTarget connects to dest over TCP+TLS with the given SNI and
// checks whether the endpoint satisfies Reality requirements (TLS 1.3, H2 ALPN,
// and certificate validity). Supports both remote targets and local fallback
// services (e.g. 127.0.0.1:8443).
func ProbeRealityTarget(ctx context.Context, rawDest, rawSNI string) v2.RealityProbeResultParams {
	dest := strings.TrimSpace(rawDest)
	sni := strings.TrimSpace(rawSNI)
	out := v2.RealityProbeResultParams{
		Dest:       dest,
		ServerName: sni,
	}
	if dest == "" {
		out.Error = "目标地址不能为空"
		return out
	}

	host, port, err := net.SplitHostPort(dest)
	if err != nil {
		// No port provided; default to 443.
		host = strings.Trim(dest, "[]")
		port = "443"
		dest = net.JoinHostPort(host, port)
		out.Dest = dest
	}
	out.Local = isLoopbackDest(host)

	if sni == "" {
		sni = strings.Trim(host, "[]")
		out.ServerName = sni
	}

	start := time.Now()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", dest)
	if err != nil {
		out.Error = fmt.Sprintf("TCP 连接失败: %v", err)
		return out
	}
	defer rawConn.Close()
	out.Reachable = true
	out.RTTMs = time.Since(start).Milliseconds()

	tlsCfg := &tls.Config{
		ServerName:         sni,
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS10,
		InsecureSkipVerify: true, // verified separately below so we can still inspect cert details
	}
	tlsConn := tls.Client(rawConn, tlsCfg)
	if deadline, ok := ctx.Deadline(); ok {
		_ = tlsConn.SetDeadline(deadline)
	} else {
		_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		out.Error = fmt.Sprintf("TLS 握手失败: %v", err)
		return out
	}

	state := tlsConn.ConnectionState()
	out.TLSVersion = tlsVersionName(state.Version)
	out.TLS13 = state.Version == tls.VersionTLS13
	out.ALPN = state.NegotiatedProtocol
	out.H2 = state.NegotiatedProtocol == "h2"

	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		out.CertSubject = leaf.Subject.CommonName
		out.CertIssuer = leaf.Issuer.CommonName
		if !leaf.NotAfter.IsZero() {
			out.CertNotAfter = leaf.NotAfter.UTC().Format("2006-01-02")
		}
		if len(leaf.DNSNames) > 0 {
			limit := len(leaf.DNSNames)
			if limit > 6 {
				limit = 6
			}
			out.CertSANs = append([]string(nil), leaf.DNSNames[:limit]...)
		}

		intermediates := x509.NewCertPool()
		for _, c := range state.PeerCertificates[1:] {
			intermediates.AddCert(c)
		}
		verifyOpts := x509.VerifyOptions{
			DNSName:       sni,
			Intermediates: intermediates,
		}
		if _, vErr := leaf.Verify(verifyOpts); vErr != nil {
			out.CertValid = false
			out.CertError = vErr.Error()
		} else {
			out.CertValid = true
		}
	}

	if !out.TLS13 {
		out.Error = fmt.Sprintf("目标仅支持 %s，Reality 强制要求 TLS 1.3", out.TLSVersion)
		out.OK = false
		return out
	}

	out.OK = true
	if !out.H2 {
		out.Warnings = append(out.Warnings, "未协商 HTTP/2 (h2)，建议目标服务开启 h2 以获得最佳伪装效果")
	}
	if !out.CertValid {
		if out.Local {
			out.Warnings = append(out.Warnings, "本地回落证书未通过系统信任或与 SNI 不匹配（若已配置正式域名证书请检查 SNI 是否一致）")
		} else {
			out.Warnings = append(out.Warnings, "目标证书未通过验证或与 SNI 不匹配，请确认 Server Names 填写正确")
		}
	}
	if out.Local && isLoopbackDest(sni) {
		out.Warnings = append(out.Warnings, "Server Names 当前为本地地址，建议改为本地服务证书对应的真实域名")
	}
	return out
}
