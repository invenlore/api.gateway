package ratelimit

import (
	"net"
	"net/http"
	"strings"
)

type IPResolver struct {
	TrustProxy        bool
	TrustedProxyCIDRs []*net.IPNet
}

func (r IPResolver) Resolve(req *http.Request) (string, bool) {
	if req == nil {
		return "", false
	}

	remoteIP := parseRemoteIP(req.RemoteAddr)
	if remoteIP == nil {
		return "", false
	}

	if !r.TrustProxy || !ipAllowed(remoteIP, r.TrustedProxyCIDRs) {
		return remoteIP.String(), true
	}

	if forwarded := extractForwardedIP(req.Header.Get("X-Forwarded-For")); forwarded != nil {
		return forwarded.String(), true
	}

	if realIP := net.ParseIP(strings.TrimSpace(req.Header.Get("X-Real-Ip"))); realIP != nil {
		return realIP.String(), true
	}

	return remoteIP.String(), true
}

func ParseCIDRs(raw string) ([]*net.IPNet, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}

	parts := strings.Split(raw, ",")
	result := make([]*net.IPNet, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		_, cidr, err := net.ParseCIDR(trimmed)
		if err != nil {
			return nil, err
		}
		result = append(result, cidr)
	}

	return result, nil
}

func parseRemoteIP(remoteAddr string) net.IP {
	if remoteAddr == "" {
		return nil
	}

	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return net.ParseIP(host)
	}

	return net.ParseIP(remoteAddr)
}

func extractForwardedIP(value string) net.IP {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	parts := strings.SplitSeq(value, ",")
	for part := range parts {
		ip := net.ParseIP(strings.TrimSpace(part))
		if ip != nil {
			return ip
		}
	}

	return nil
}

func ipAllowed(ip net.IP, networks []*net.IPNet) bool {
	if ip == nil {
		return false
	}

	if len(networks) == 0 {
		return false
	}

	for _, network := range networks {
		if network != nil && network.Contains(ip) {
			return true
		}
	}

	return false
}
