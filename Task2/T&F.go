package main

import (
	"bufio"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// =============================================================
// ===================== RESULT STRUCT =========================
// =============================================================

type DeepScanResult struct {
	TargetURL     string                 `json:"target_url"`
	IPs           []string               `json:"ips"`
	Server        string                 `json:"server"`
	ContentType   string                 `json:"content_type"`
	Technologies  map[string][]string    `json:"technologies"`
	FaviconMD5    string                 `json:"favicon_md5"`
	TLSInfo       map[string]interface{} `json:"tls_info"`
	Secrets       []string               `json:"secrets"`
	Endpoints     []string               `json:"endpoints"`
	OpenPorts     map[int]string         `json:"open_ports"`
	CDNHosting    []string               `json:"cdn_hosting"`
	MergedFromJS  map[string]interface{} `json:"merged_from_js"`
	ScanTimestamp string                 `json:"scan_timestamp"`
}

// =============================================================
// ========================= ENTRY =============================
// =============================================================

func RunInfoGathering() {
	target := promptTarget()
	fmt.Println("[+] Starting deep scan...\n")

	res := RunDeepScan(target)

	saveJSON(res)
	printPrettyJSON(res)
}

// =============================================================
// ====================== INPUT HANDLING =======================
// =============================================================

func promptTarget() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter target URL: ")
	t, _ := reader.ReadString('\n')
	t = strings.TrimSpace(t)

	if !strings.HasPrefix(t, "http://") && !strings.HasPrefix(t, "https://") {
		t = "https://" + t
	}
	return t
}

// =============================================================
// ====================== MAIN SCAN LOGIC ======================
// =============================================================

func RunDeepScan(target string) DeepScanResult {
	u, _ := url.Parse(target)

	result := DeepScanResult{
		TargetURL:     u.String(),
		Technologies:  map[string][]string{},
		TLSInfo:       map[string]interface{}{},
		OpenPorts:     map[int]string{},
		MergedFromJS:  loadJSReport(),
		ScanTimestamp: time.Now().Format(time.RFC3339),
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// -------------------------------------------------------------
	// 1. HTTP Request (Headers + Body)
	// -------------------------------------------------------------
	resp, body := httpFetch(client, u.String())
	if resp != nil {
		result.Server = resp.Header.Get("Server")
		result.ContentType = resp.Header.Get("Content-Type")
	}

	// -------------------------------------------------------------
	// 2. DNS → All IPs
	// -------------------------------------------------------------
	result.IPs = resolveIPs(u.Host)

	// -------------------------------------------------------------
	// 3. Technology Detection (Frontend + Backend + DB)
	// -------------------------------------------------------------
	result.Technologies = detectTechnologies(resp, body)

	// -------------------------------------------------------------
	// 4. Favicon MD5 Fingerprint
	// -------------------------------------------------------------
	result.FaviconMD5 = getFaviconMD5(client, u)

	// -------------------------------------------------------------
	// 5. TLS Deep Scan
	// -------------------------------------------------------------
	if u.Scheme == "https" {
		result.TLSInfo = scanTLS(u.Host)
	}

	// -------------------------------------------------------------
	// 6. Secret String Detection
	// -------------------------------------------------------------
	result.Secrets = detectSecrets(body)

	// -------------------------------------------------------------
	// 7. JS / API Endpoint Extraction
	// -------------------------------------------------------------
	result.Endpoints = extractEndpoints(body)

	// -------------------------------------------------------------
	// 8. Port Scan (Common Web Ports)
	// -------------------------------------------------------------
	result.OpenPorts = scanPorts(u.Host)

	// -------------------------------------------------------------
	// 9. CDN / Hosting Provider Fingerprinting
	// -------------------------------------------------------------
	result.CDNHosting = detectCDN(resp)

	return result
}

// =============================================================
// ====================== HTTP FETCH ===========================
// =============================================================

func httpFetch(client *http.Client, u string) (*http.Response, []byte) {
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "AdvancedDeepScanner/3.1")

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	return resp, body
}

// =============================================================
// ====================== IP RESOLUTION ========================
// =============================================================

func resolveIPs(host string) []string {
	if strings.Contains(host, ":") {
		host, _, _ = strings.Cut(host, ":")
	}
	ips, _ := net.LookupHost(host)
	return ips
}

// =============================================================
// =================== TECHNOLOGY DETECTION ====================
// =============================================================

func detectTechnologies(resp *http.Response, body []byte) map[string][]string {
	res := map[string][]string{
		"frontend": {},
		"backend":  {},
		"server":   {},
		"database": {},
	}

	b := strings.ToLower(string(body))

	// ---------------- SERVER -----------------
	if resp != nil {
		if s := resp.Header.Get("Server"); s != "" {
			res["server"] = appendIfMissing(res["server"], s)
		}
	}

	// ---------------- FRONTEND ----------------
	frontendRules := map[string]string{
		"React":     "react",
		"Vue.js":    "vue",
		"Angular":   "angular",
		"jQuery":    "jquery",
		"Svelte":    "svelte",
		"Next.js":   "next",
		"Nuxt":      "nuxt",
		"Bootstrap": "bootstrap",
	}

	for name, key := range frontendRules {
		if strings.Contains(b, key) {
			res["frontend"] = appendIfMissing(res["frontend"], name)
		}
	}

	// ---------------- BACKEND ----------------
	backendRules := map[string]string{
		"Node.js":       "node",
		"Express.js":    "express",
		"NestJS":        "nest",
		"Django":        "django",
		"Flask":         "flask",
		"Laravel":       "laravel",
		"Ruby on Rails": "rails",
		"ASP.NET":       "asp.net",
		"WordPress":     "wordpress",
		"Joomla":        "joomla",
		"Drupal":        "drupal",
	}

	for name, key := range backendRules {
		if strings.Contains(b, key) {
			res["backend"] = appendIfMissing(res["backend"], name)
		}
	}

	// ---------------- DATABASE ----------------
	dbRules := map[string][]string{
		"MySQL":      {"mysql", "mysqld", "maria", "innodb", "phpmyadmin"},
		"PostgreSQL": {"postgres", "pgsql", "postgis", "psql"},
		"MongoDB":    {"mongodb", "mongo", "mongod"},
		"SQLite":     {"sqlite", ".db", "sqlite3"},
		"Redis":      {"redis", "redis.io"},
		"OracleDB":   {"oracle", "oracledb", "pl/sql"},
		"MSSQL":      {"mssql", "sql server", "mssqlserver"},
	}

	// LEVEL 1: HTML body + headers
	for dbName, keys := range dbRules {
		for _, k := range keys {
			if strings.Contains(b, k) {
				res["database"] = appendIfMissing(res["database"], dbName)
			}
			if resp != nil {
				for _, v := range resp.Header {
					h := strings.ToLower(strings.Join(v, " "))
					if strings.Contains(h, k) {
						res["database"] = appendIfMissing(res["database"], dbName)
					}
				}
			}
		}
	}

	// LEVEL 2: JS variables
	dbVarRegex := regexp.MustCompile(`(?i)(db|database|engine)["'\s:={]+\s*["']?([A-Za-z0-9_\-\.]+)`)
	dbVars := dbVarRegex.FindAllStringSubmatch(b, -1)
	for _, v := range dbVars {
		val := strings.ToLower(v[2])
		for name, keys := range dbRules {
			for _, k := range keys {
				if strings.Contains(val, k) {
					res["database"] = appendIfMissing(res["database"], name)
				}
			}
		}
	}

	// LEVEL 3: API endpoint hints
	apiDBHints := map[string]string{
		"/wp-json/":      "MySQL",
		"/graphql":       "PostgreSQL",
		"/mongo/":        "MongoDB",
		"/_next/":        "MySQL",
		"/api/db/":       "SQLite",
		"/api/sql/":      "MySQL",
		"/adminer.php":   "MySQL",
		"/phpmyadmin":    "MySQL",
		"/pgadmin":       "PostgreSQL",
		"/mongo-express": "MongoDB",
	}

	for needle, db := range apiDBHints {
		if strings.Contains(b, needle) {
			res["database"] = appendIfMissing(res["database"], db)
		}
	}

	// LEVEL 4: Merge from JS report.json
	if js, ok := loadJSReport()["database"]; ok {
		if arr, ok := js.([]interface{}); ok {
			for _, raw := range arr {
				name := fmt.Sprintf("%v", raw)
				res["database"] = appendIfMissing(res["database"], name)
			}
		}
	}

	return res
}

// =============================================================
// ====================== FAVICON MD5 ==========================
// =============================================================

func getFaviconMD5(client *http.Client, base *url.URL) string {
	u := *base
	u.Path = "/favicon.ico"

	resp, err := client.Get(u.String())
	if err != nil {
		return ""
	}

	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	sum := md5.Sum(data)
	return hex.EncodeToString(sum[:])
}

// =============================================================
// ========================= TLS SCAN ===========================
// =============================================================

func scanTLS(host string) map[string]interface{} {
	info := map[string]interface{}{}

	conn, err := tls.Dial("tcp", host+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return info
	}
	defer conn.Close()

	state := conn.ConnectionState()

	cert := state.PeerCertificates[0]

	info["issuer"] = cert.Issuer.CommonName
	info["expiry"] = cert.NotAfter.String()
	info["protocol"] = tlsVersionName(state.Version)
	info["cipher_suite"] = tls.CipherSuiteName(state.CipherSuite)

	var chain []string
	for _, c := range state.PeerCertificates {
		chain = append(chain, c.Subject.CommonName)
	}
	info["certificate_chain"] = chain

	return info
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (%d)", v)
	}
}

// =============================================================
// ====================== SECRET DETECTION ======================
// =============================================================

func detectSecrets(body []byte) []string {
	regex := regexp.MustCompile(`(?i)(api[_-]?key|token|secret|firebase|aws)[^"'=]{0,10}["'=:]{1,3}[ ]*["']?([A-Za-z0-9_\-]{12,})`)
	matches := regex.FindAllString(string(body), -1)
	return matches
}

// =============================================================
// ====================== ENDPOINT DISCOVERY ===================
// =============================================================

func extractEndpoints(body []byte) []string {
	regex := regexp.MustCompile(`(\/[A-Za-z0-9_\-\/]+\.js)|(\/api\/[A-Za-z0-9_\-\/]+)`)
	matches := regex.FindAllString(string(body), -1)
	return unique(matches)
}

// =============================================================
// ======================= PORT SCAN ===========================
// =============================================================

func scanPorts(host string) map[int]string {
	if strings.Contains(host, ":") {
		host, _, _ = strings.Cut(host, ":")
	}

	ports := []int{80, 443, 8080, 8443, 22, 21, 3000, 5000, 3306, 5432}
	out := map[int]string{}

	for _, p := range ports {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, p), 1*time.Second)
		if err == nil {
			out[p] = "open"
			conn.Close()
		} else {
			out[p] = "closed"
		}
	}

	return out
}

// =============================================================
// ====================== CDN DETECTION ========================
// =============================================================

func detectCDN(resp *http.Response) []string {
	if resp == nil {
		return []string{}
	}
	cdns := []string{}

	h := resp.Header

	if strings.Contains(strings.ToLower(h.Get("Server")), "cloudflare") {
		cdns = append(cdns, "Cloudflare")
	}
	if strings.Contains(strings.ToLower(h.Get("Via")), "cloudfront") {
		cdns = append(cdns, "AWS CloudFront")
	}
	if strings.Contains(strings.ToLower(h.Get("Server")), "akamai") {
		cdns = append(cdns, "Akamai")
	}
	if strings.Contains(strings.ToLower(h.Get("Server")), "vercel") {
		cdns = append(cdns, "Vercel")
	}
	if strings.Contains(strings.ToLower(h.Get("Server")), "netlify") {
		cdns = append(cdns, "Netlify")
	}

	return unique(cdns)
}

// =============================================================
// ===================== MERGE JS REPORT =======================
// =============================================================

func loadJSReport() map[string]interface{} {
	data, err := os.ReadFile("report.json")
	if err != nil {
		return map[string]interface{}{}
	}
	var parsed map[string]interface{}
	json.Unmarshal(data, &parsed)
	return parsed
}

// =============================================================
// ======================= UTIL FUNCTIONS =======================
// =============================================================

func unique(arr []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range arr {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func appendIfMissing(arr []string, val string) []string {
	for _, v := range arr {
		if v == val {
			return arr
		}
	}
	return append(arr, val)
}

func saveJSON(data DeepScanResult) {
	f, _ := os.Create("scan_output.json")
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.Encode(data)
}

func printPrettyJSON(data DeepScanResult) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(data)
}
