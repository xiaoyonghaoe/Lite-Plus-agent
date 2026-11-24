package coreadapter

import (
	"net"
	"strings"
)

// multiPartTLDs covers common public suffixes with two labels so subdomains
// like "a.b.co.uk" normalize to "b.co.uk" instead of "co.uk".
var multiPartTLDs = map[string]struct{}{
	"co.uk": {}, "org.uk": {}, "ac.uk": {}, "gov.uk": {}, "net.uk": {},
	"com.cn": {}, "net.cn": {}, "org.cn": {}, "gov.cn": {}, "edu.cn": {},
	"com.hk": {}, "org.hk": {}, "net.hk": {}, "edu.hk": {},
	"com.tw": {}, "org.tw": {}, "net.tw": {}, "edu.tw": {}, "idv.tw": {},
	"co.jp": {}, "ne.jp": {}, "or.jp": {}, "go.jp": {}, "ac.jp": {},
	"com.au": {}, "net.au": {}, "org.au": {}, "edu.au": {},
	"com.sg": {}, "org.sg": {}, "edu.sg": {},
	"com.my": {}, "net.my": {}, "org.my": {},
	"com.vn": {}, "net.vn": {}, "org.vn": {},
	"com.ph": {}, "co.id": {}, "or.id": {},
	"co.kr": {}, "or.kr": {}, "go.kr": {},
	"com.br": {}, "net.br": {}, "org.br": {},
	"com.mx": {}, "com.ar": {}, "com.tr": {}, "co.in": {}, "co.nz": {}, "co.za": {},
	"com.ua": {}, "com.pl": {}, "com.ru": {}, "eu.org": {},
}

// normalizeRootDomain extracts a normalized registrable root domain (eTLD+1).
// Returns "" for empty strings, raw IP addresses, or invalid hostnames.
func normalizeRootDomain(raw string) string {
	host := strings.ToLower(strings.TrimSpace(raw))
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 {
		return ""
	}
	if strings.Contains(host, ":") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = strings.Trim(h, "[]")
		}
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return ""
	}
	for _, p := range parts {
		if p == "" {
			return ""
		}
	}
	n := len(parts)
	if n >= 3 {
		lastTwo := parts[n-2] + "." + parts[n-1]
		if _, ok := multiPartTLDs[lastTwo]; ok {
			return parts[n-3] + "." + lastTwo
		}
	}
	return parts[n-2] + "." + parts[n-1]
}
