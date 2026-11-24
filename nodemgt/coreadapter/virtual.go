package coreadapter

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	virtualInboundSep = "#"
	virtualUserSep    = "@"
)

// NormalizeVirtualTag validates and normalizes a single virtual inbound tag.
// Only ASCII letters, digits, '-' and '_' (1..24 chars) are allowed.
func NormalizeVirtualTag(raw string) string {
	tag := strings.TrimSpace(raw)
	if len(tag) == 0 || len(tag) > 24 {
		return ""
	}
	for i := 0; i < len(tag); i++ {
		c := tag[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			continue
		}
		return ""
	}
	return tag
}

// SplitVirtualInboundID splits "inbID#tag" into ("inbID", "tag").
func SplitVirtualInboundID(id string) (baseID, tag string) {
	id = strings.TrimSpace(id)
	base, rest, ok := strings.Cut(id, virtualInboundSep)
	if !ok {
		return id, ""
	}
	return strings.TrimSpace(base), NormalizeVirtualTag(rest)
}

// FormatVirtualInboundID builds "baseID#tag" when tag is valid, or returns baseID.
func FormatVirtualInboundID(baseID, tag string) string {
	baseID = strings.TrimSpace(baseID)
	tag = NormalizeVirtualTag(tag)
	if baseID == "" || tag == "" {
		return baseID
	}
	return baseID + virtualInboundSep + tag
}

// VirtualUserKey returns "userID@tag" when tag is non-empty, else userID.
func VirtualUserKey(userID, tag string) string {
	userID = strings.TrimSpace(userID)
	tag = NormalizeVirtualTag(tag)
	if userID == "" || tag == "" {
		return userID
	}
	return userID + virtualUserSep + tag
}

// SplitVirtualUserKey splits "userID@tag" into ("userID", "tag").
func SplitVirtualUserKey(key string) (userID, tag string) {
	key = strings.TrimSpace(key)
	idx := strings.LastIndex(key, virtualUserSep)
	if idx <= 0 || idx == len(key)-1 {
		return key, ""
	}
	t := NormalizeVirtualTag(key[idx+1:])
	if t == "" {
		return key, ""
	}
	return strings.TrimSpace(key[:idx]), t
}

// DeriveVirtualPassword derives a deterministic, URL-safe 24-char password
// salted with inboundID and tag (identical to Lite-Plus/nodemgt/inboundcfg).
func DeriveVirtualPassword(baseSecret, inboundID, tag string) string {
	baseSecret = strings.TrimSpace(baseSecret)
	inboundID = strings.TrimSpace(inboundID)
	tag = NormalizeVirtualTag(tag)
	if baseSecret == "" || tag == "" {
		return baseSecret
	}
	mac := hmac.New(sha256.New, []byte("liteplus:vinb:v1:"+inboundID+":"+tag))
	_, _ = mac.Write([]byte(baseSecret))
	sum := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum[:18])
}

// DeriveVirtualUUID derives a deterministic RFC 4122 UUIDv5 (identical to Lite-Plus/nodemgt/inboundcfg).
func DeriveVirtualUUID(baseUUID, inboundID, tag string) string {
	baseUUID = strings.TrimSpace(baseUUID)
	inboundID = strings.TrimSpace(inboundID)
	tag = NormalizeVirtualTag(tag)
	if baseUUID == "" || tag == "" {
		return baseUUID
	}
	h := sha1.New()
	_, _ = h.Write([]byte("liteplus:vinb:uuid:v1:"))
	_, _ = h.Write([]byte(inboundID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(tag))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(baseUUID))
	sum := h.Sum(nil)
	var u [16]byte
	copy(u[:], sum[:16])
	u[6] = (u[6] & 0x0f) | 0x50 // Version 5
	u[8] = (u[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// DeriveVirtualUsername derives an HTTP/SOCKS username for a virtual tag.
func DeriveVirtualUsername(baseUser, tag string) string {
	baseUser = strings.TrimSpace(baseUser)
	tag = NormalizeVirtualTag(tag)
	if baseUser == "" || tag == "" {
		return baseUser
	}
	return baseUser + "-" + tag
}


// NormalizeVirtualTags deduplicates and validates a list of virtual tags.
func NormalizeVirtualTags(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		tag := NormalizeVirtualTag(item)
		if tag == "" {
			continue
		}
		lower := strings.ToLower(tag)
		if _, ok := seen[lower]; ok {
			continue
		}
		seen[lower] = struct{}{}
		out = append(out, tag)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func inboundVirtualTags(in InboundSpec) []string {
	if strings.TrimSpace(in.SettingsJSON) == "" {
		return nil
	}
	var s struct {
		VirtualTags []string `json:"virtual_tags"`
	}
	if err := json.Unmarshal([]byte(in.SettingsJSON), &s); err != nil {
		return nil
	}
	return NormalizeVirtualTags(s.VirtualTags)
}

func grantedExplicit(u UserSpec, inboundID string) bool {
	if len(u.InboundIDs) == 0 {
		return false
	}
	for _, id := range u.InboundIDs {
		if id == inboundID {
			return true
		}
	}
	return false
}

func deriveVirtualUserSpec(u UserSpec, inboundID, tag string) UserSpec {
	vu := u
	vu.ID = VirtualUserKey(u.ID, tag)
	if strings.TrimSpace(u.UUID) != "" {
		vu.UUID = DeriveVirtualUUID(u.UUID, inboundID, tag)
	}
	baseSecret := strings.TrimSpace(u.Password)
	if baseSecret == "" {
		baseSecret = strings.TrimSpace(u.UUID)
	}
	if baseSecret != "" {
		vu.Password = DeriveVirtualPassword(baseSecret, inboundID, tag)
	}
	if strings.TrimSpace(u.Username) != "" {
		vu.Username = DeriveVirtualUsername(u.Username, tag)
	}
	return vu
}

// userEntriesForInbound returns all live UserSpec entries (both primary and
// explicitly granted virtual tag entries) for a physical inbound.
func userEntriesForInbound(users []UserSpec, in InboundSpec) []UserSpec {
	vtags := inboundVirtualTags(in)
	out := make([]UserSpec, 0, len(users))
	for _, u := range users {
		if !userLive(u) {
			continue
		}
		if grantedOn(u, in.ID) {
			out = append(out, u)
		}
		for _, tag := range vtags {
			virtID := FormatVirtualInboundID(in.ID, tag)
			if grantedExplicit(u, virtID) {
				out = append(out, deriveVirtualUserSpec(u, in.ID, tag))
			}
		}
	}
	return out
}

// routeAuthUsersForInbound resolves the auth_user / user list for a route rule
// targeting ruleInboundID (which may be "inbID" or "inbID#tag").
// When restrict is true and authUsers is empty, the caller should omit the rule.
func routeAuthUsersForInbound(ruleInboundID string, inbounds []InboundSpec, users []UserSpec) (authUsers []string, restrict bool) {
	ruleInboundID = strings.TrimSpace(ruleInboundID)
	if ruleInboundID == "" {
		return nil, false
	}
	baseID, vtag := SplitVirtualInboundID(ruleInboundID)
	var target *InboundSpec
	for i := range inbounds {
		if inbounds[i].ID == baseID {
			target = &inbounds[i]
			break
		}
	}
	if target == nil {
		if vtag != "" {
			return nil, true
		}
		return nil, false
	}
	vtags := inboundVirtualTags(*target)
	if vtag == "" && len(vtags) == 0 {
		return nil, false
	}
	proto := strings.ToLower(strings.TrimSpace(target.Protocol))
	isProxyAuth := proto == "http" || proto == "socks" || proto == "mixed"
	seen := map[string]struct{}{}
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		authUsers = append(authUsers, name)
	}
	for _, u := range users {
		if !userLive(u) {
			continue
		}
		if vtag != "" {
			if !grantedExplicit(u, FormatVirtualInboundID(baseID, vtag)) {
				continue
			}
			vu := deriveVirtualUserSpec(u, baseID, vtag)
			if isProxyAuth {
				for _, acct := range proxyAccounts(vu) {
					add(acct["user"])
				}
			} else {
				add(vu.ID)
			}
		} else {
			if !grantedOn(u, baseID) {
				continue
			}
			if isProxyAuth {
				for _, acct := range proxyAccounts(u) {
					add(acct["user"])
				}
			} else {
				add(u.ID)
			}
		}
	}
	return authUsers, true
}
