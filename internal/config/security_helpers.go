package config

import (
	"net"
	"net/url"
	"strings"
)

func dsnHost(dsn string) string {
	u, err := url.Parse(strings.TrimSpace(dsn))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(u.Hostname())
}

func dsnUsesInsecureSSL(dsn string) bool {
	u, err := url.Parse(strings.TrimSpace(dsn))
	if err != nil {
		return false
	}
	q := strings.TrimSpace(strings.ToLower(u.Query().Get("sslmode")))
	return q == "disable" || q == "allow" || q == "prefer"
}

func isLoopbackHost(host string) bool {
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

func isHTTPSURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Scheme, "https")
}
