// Package proxy parses free-tier proxy URIs (ss://, vmess://, vless://,
// trojan://) into structured outbound configs that the sing-box runner can
// consume. These are the URI schemes used by the free-config aggregator
// repos on GitHub.
package proxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Outbound is the protocol-agnostic representation of a single proxy server.
// The fields it carries are the union of what every supported protocol
// needs; the sing-box config generator picks the relevant subset.
type Outbound struct {
	Protocol string // "shadowsocks" | "vmess" | "vless" | "trojan" | "tuic" | "hysteria2"
	Tag      string // human label from the URI fragment

	// Common
	Server     string
	ServerPort int

	// Shadowsocks
	Method   string
	Password string

	// VMess / VLESS / Trojan
	UUID            string
	AlterID         int    // VMess only
	Security        string // VMess: "auto" | "aes-128-gcm" | "chacha20-poly1305" | "none"
	Flow            string // VLESS only
	Network         string // "tcp" | "ws" | "grpc" | "http"
	WSPath          string
	WSHost          string
	GRPCServiceName string
	TLS             bool
	SNI             string
	ALPN            []string
	SkipCertVerify  bool

	// TUIC v5
	CongestionControl string // "bbr" | "cubic" | "new_reno"
	UDPRelayMode      string // "native" | "quic"

	// Hysteria 2
	ObfsType     string // typically "salamander"
	ObfsPassword string
}

// Parse picks the right scheme parser. Returns an error for unsupported
// schemes so the caller can count yield per source.
func Parse(uri string) (*Outbound, error) {
	uri = strings.TrimSpace(uri)
	switch {
	case strings.HasPrefix(uri, "ss://"):
		return parseShadowsocks(uri)
	case strings.HasPrefix(uri, "vmess://"):
		return parseVMess(uri)
	case strings.HasPrefix(uri, "vless://"):
		return parseVLESS(uri)
	case strings.HasPrefix(uri, "trojan://"):
		return parseTrojan(uri)
	case strings.HasPrefix(uri, "tuic://"):
		return parseTUIC(uri)
	case strings.HasPrefix(uri, "hysteria2://"), strings.HasPrefix(uri, "hy2://"):
		return parseHysteria2(uri)
	case strings.HasPrefix(uri, "hysteria://"):
		// Hysteria v1 uses a fundamentally different config shape (separate
		// up/down bandwidth mandated, no user@host userinfo); not worth a
		// full parser for a mostly-deprecated protocol.
		return nil, fmt.Errorf("hysteria v1 unsupported (use hysteria2)")
	}
	return nil, fmt.Errorf("unsupported scheme: %q", firstChars(uri, 12))
}

// parseShadowsocks handles the SIP002 form (ss://base64(method:pwd)@host:port#tag)
// and the legacy form (ss://base64(method:pwd@host:port)#tag). Both appear in
// the free-config wild.
func parseShadowsocks(uri string) (*Outbound, error) {
	rest := strings.TrimPrefix(uri, "ss://")
	frag := ""
	if i := strings.Index(rest, "#"); i >= 0 {
		frag = rest[i+1:]
		rest = rest[:i]
	}
	tag, _ := url.QueryUnescape(frag)

	// SIP002: <userinfo>@<host>:<port>?<plugin>
	if at := strings.LastIndex(rest, "@"); at > 0 {
		userinfo := rest[:at]
		hostport := rest[at+1:]
		// userinfo may be base64 (with or without padding) or plain "method:pwd"
		method, pwd, err := decodeMethodPwd(userinfo)
		if err != nil {
			return nil, fmt.Errorf("ss userinfo: %w", err)
		}
		host, port, err := splitHostPort(hostport)
		if err != nil {
			return nil, err
		}
		return &Outbound{
			Protocol: "shadowsocks", Tag: tag,
			Server: host, ServerPort: port,
			Method: method, Password: pwd,
		}, nil
	}

	// Legacy form: base64(method:pwd@host:port)
	dec, err := tryB64(rest)
	if err != nil {
		return nil, fmt.Errorf("ss legacy decode: %w", err)
	}
	at := strings.LastIndex(dec, "@")
	if at < 0 {
		return nil, fmt.Errorf("ss legacy: missing @")
	}
	method, pwd, err := splitMethodPwd(dec[:at])
	if err != nil {
		return nil, err
	}
	host, port, err := splitHostPort(dec[at+1:])
	if err != nil {
		return nil, err
	}
	return &Outbound{
		Protocol: "shadowsocks", Tag: tag,
		Server: host, ServerPort: port,
		Method: method, Password: pwd,
	}, nil
}

// vmessJSON is the JSON body inside vmess:// URIs. Fields are documented at
// https://github.com/v2ray/v2ray-core/issues/1139 — some are strings or ints
// depending on the generator, so we accept both via json.Number.
type vmessJSON struct {
	V    string      `json:"v"`
	Ps   string      `json:"ps"`
	Add  string      `json:"add"`
	Port json.Number `json:"port"`
	ID   string      `json:"id"`
	Aid  json.Number `json:"aid"`
	Scy  string      `json:"scy"`
	Net  string      `json:"net"`
	Type string      `json:"type"`
	Host string      `json:"host"`
	Path string      `json:"path"`
	TLS  string      `json:"tls"`
	SNI  string      `json:"sni"`
	ALPN string      `json:"alpn"`
}

func parseVMess(uri string) (*Outbound, error) {
	body := strings.TrimPrefix(uri, "vmess://")
	// May contain query/fragment in some variants; strip after first '#'/'?'
	if i := strings.IndexAny(body, "?#"); i >= 0 {
		body = body[:i]
	}
	dec, err := tryB64(body)
	if err != nil {
		return nil, fmt.Errorf("vmess decode: %w", err)
	}
	var v vmessJSON
	d := json.NewDecoder(strings.NewReader(dec))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		return nil, fmt.Errorf("vmess json: %w", err)
	}
	port, _ := strconv.Atoi(v.Port.String())
	aid, _ := strconv.Atoi(v.Aid.String())
	if port == 0 || v.Add == "" || v.ID == "" {
		return nil, fmt.Errorf("vmess: missing add/port/id")
	}
	sec := v.Scy
	if sec == "" {
		sec = "auto"
	}
	o := &Outbound{
		Protocol: "vmess", Tag: v.Ps,
		Server: v.Add, ServerPort: port,
		UUID: v.ID, AlterID: aid, Security: sec,
		Network: strings.ToLower(v.Net), WSPath: v.Path, WSHost: v.Host,
		TLS: strings.EqualFold(v.TLS, "tls"), SNI: v.SNI,
		SkipCertVerify: true, // free configs are usually self-signed
	}
	if v.ALPN != "" {
		o.ALPN = strings.Split(v.ALPN, ",")
	}
	if o.Network == "" {
		o.Network = "tcp"
	}
	return o, nil
}

// parseVLESS handles the standard VLESS URI:
//
//	vless://<uuid>@<host>:<port>?encryption=none&type=ws&host=...&path=...&security=tls&sni=...#tag
func parseVLESS(uri string) (*Outbound, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("vless parse: %w", err)
	}
	uuid := u.User.Username()
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	if uuid == "" || host == "" || port == 0 {
		return nil, fmt.Errorf("vless: missing uuid/host/port")
	}
	q := u.Query()
	// sing-box only implements the canonical `xtls-rprx-vision` flow.
	// Variants like `xtls-rprx-vision-udp443` (Xray-only UDP-443 forwarding)
	// cause "unsupported flow" at config-init time. Reject them at parse so
	// they never enter the candidate pool.
	flow := q.Get("flow")
	switch flow {
	case "", "xtls-rprx-vision":
		// supported
	default:
		return nil, fmt.Errorf("vless: unsupported flow %q", flow)
	}
	o := &Outbound{
		Protocol: "vless", Tag: u.Fragment,
		Server: host, ServerPort: port, UUID: uuid,
		Network: firstNonEmpty(q.Get("type"), "tcp"),
		WSPath:  q.Get("path"), WSHost: q.Get("host"),
		Flow: flow, SNI: q.Get("sni"),
		TLS: q.Get("security") == "tls" || q.Get("security") == "reality",
		GRPCServiceName: q.Get("serviceName"),
		SkipCertVerify:  true,
	}
	if alpn := q.Get("alpn"); alpn != "" {
		o.ALPN = strings.Split(alpn, ",")
	}
	return o, nil
}

// parseTUIC: tuic://<uuid>:<password>@<host>:<port>?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=...&allow_insecure=1#<tag>
//
// The userinfo is always uuid:password (TUIC v5 — no other versions are in
// the free-config wild). We default to bbr / native because that's what
// every observed config uses and what sing-box assumes when unset.
func parseTUIC(uri string) (*Outbound, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("tuic parse: %w", err)
	}
	uuid := u.User.Username()
	pwd, _ := u.User.Password()
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	if uuid == "" || host == "" || port == 0 {
		return nil, fmt.Errorf("tuic: missing uuid/host/port")
	}
	q := u.Query()
	allowInsecure := q.Get("allow_insecure") == "1" || q.Get("allowInsecure") == "1" || q.Get("insecure") == "1"
	o := &Outbound{
		Protocol:          "tuic", Tag: u.Fragment,
		Server:            host, ServerPort: port,
		UUID:              uuid, Password: pwd,
		CongestionControl: firstNonEmpty(q.Get("congestion_control"), "bbr"),
		UDPRelayMode:      firstNonEmpty(q.Get("udp_relay_mode"), "native"),
		TLS:               true, // TUIC is always TLS (QUIC handshake)
		SNI:               q.Get("sni"),
		SkipCertVerify:    allowInsecure,
	}
	if alpn := q.Get("alpn"); alpn != "" {
		o.ALPN = strings.Split(alpn, ",")
	}
	return o, nil
}

// parseHysteria2: hysteria2://<password>@<host>:<port>?sni=...&insecure=0&alpn=h3&obfs=salamander&obfs-password=...#<tag>
// Accepts hy2:// as a common alias.
func parseHysteria2(uri string) (*Outbound, error) {
	uri = strings.Replace(uri, "hy2://", "hysteria2://", 1)
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("hysteria2 parse: %w", err)
	}
	pwd := u.User.Username()
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	if pwd == "" || host == "" || port == 0 {
		return nil, fmt.Errorf("hysteria2: missing password/host/port")
	}
	q := u.Query()
	o := &Outbound{
		Protocol:       "hysteria2", Tag: u.Fragment,
		Server:         host, ServerPort: port,
		Password:       pwd,
		TLS:            true, // hysteria2 is always TLS (QUIC handshake)
		SNI:            q.Get("sni"),
		SkipCertVerify: q.Get("insecure") == "1",
		ObfsType:       q.Get("obfs"),
		ObfsPassword:   firstNonEmpty(q.Get("obfs-password"), q.Get("obfs_password")),
	}
	if alpn := q.Get("alpn"); alpn != "" {
		o.ALPN = strings.Split(alpn, ",")
	}
	return o, nil
}

// parseTrojan: trojan://<password>@<host>:<port>?sni=...&type=...#tag
func parseTrojan(uri string) (*Outbound, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("trojan parse: %w", err)
	}
	pwd := u.User.Username()
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())
	if pwd == "" || host == "" || port == 0 {
		return nil, fmt.Errorf("trojan: missing password/host/port")
	}
	q := u.Query()
	return &Outbound{
		Protocol: "trojan", Tag: u.Fragment,
		Server: host, ServerPort: port, Password: pwd,
		Network: firstNonEmpty(q.Get("type"), "tcp"),
		WSPath:  q.Get("path"), WSHost: q.Get("host"),
		TLS:     true, // trojan is always TLS
		SNI:     q.Get("sni"), SkipCertVerify: true,
	}, nil
}

// ---- helpers ------------------------------------------------------------

func tryB64(s string) (string, error) {
	// Free-config repos use both standard and URL-safe b64, with and without
	// padding. Try them in order.
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if d, err := enc.DecodeString(s); err == nil {
			return string(d), nil
		}
	}
	return "", fmt.Errorf("invalid base64")
}

func decodeMethodPwd(userinfo string) (method, pwd string, err error) {
	// Try base64 first; fall back to plain "method:pwd".
	if dec, dErr := tryB64(userinfo); dErr == nil {
		return splitMethodPwd(dec)
	}
	if unescaped, uErr := url.QueryUnescape(userinfo); uErr == nil {
		return splitMethodPwd(unescaped)
	}
	return splitMethodPwd(userinfo)
}

func splitMethodPwd(s string) (method, pwd string, err error) {
	c := strings.Index(s, ":")
	if c <= 0 {
		return "", "", fmt.Errorf("missing method:password separator")
	}
	return s[:c], s[c+1:], nil
}

func splitHostPort(s string) (host string, port int, err error) {
	// strip trailing query (?plugin=...)
	if i := strings.Index(s, "?"); i >= 0 {
		s = s[:i]
	}
	c := strings.LastIndex(s, ":")
	if c <= 0 {
		return "", 0, fmt.Errorf("missing host:port separator")
	}
	host = s[:c]
	port, err = strconv.Atoi(s[c+1:])
	if err != nil {
		return "", 0, fmt.Errorf("invalid port: %w", err)
	}
	return host, port, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func firstChars(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
