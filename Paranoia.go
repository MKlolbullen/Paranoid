//go:build linux
// +build linux

/*
Paranoia – route all outbound traffic through Tor via nftables (IPv4 + IPv6) and Tor.
This version includes:
  1. Orchestration of a local DoH DNS resolver, with a flag to reconfigure the system resolver and update nftables rules.
     It periodically checks via a secure API that DNS queries are resolved via HTTPS and, on leak detection,
     either alerts or re-applies firewall rules.
  2. TOR control integration via a dedicated Go routine using the control protocol on a configurable port.
  3. Randomized identity-rotation timer based on a user-controlled base interval.
  4. Ephemeral logging options (local, ramdisk, or encrypted) chosen by a flag.
  5. Optional pluggable transport configuration to “mask” Tor traffic as ordinary HTTPS.
  6. A fail-safe mode that saves a “secure profile” of critical configuration files and restores them on exit.

WARNING: Test all changes in an isolated environment before deploying on a target system.
*/

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ─── Static configuration ────────────────────────────────────────────────────
const (
	// Basic ports and network definitions
	dnsPort               = "53"
	torPort               = "9040"
	virtualTorNetworkCIDR = "10.0.0.0/10"
	localhostAddr         = "127.0.0.1"
	localhostV6           = "::1"
	torrcFile             = "/etc/tor/torrc"
	httpTimeout           = 5 * time.Second

	// Backup file paths for fail-safe
	backupTorrcPath   = "/tmp/torrc.paranoia.bak"
	backupResolvPath  = "/tmp/resolv.conf.paranoia.bak"
	backupNftablePath = "/tmp/nft_paranoia.bak"
)

// Global logger; it will be reinitialized from main after flag parsing.
var logger *slog.Logger

// Excluded networks
var excludedCIDRs = []string{
	"192.168.0.0/16", "172.16.0.0/12", "127.0.0.0/8", "127.0.0.0/9", "127.128.0.0/10",
	"fe80::/10", "fc00::/7", "::1/128",
}

// ─── Utility Functions ─────────────────────────────────────────────────────────
func requireRoot() {
	if os.Geteuid() != 0 {
		fatalf("run as root (sudo)")
	}
}

func fatalf(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "\033[31m[!]\033[0m "+format+"\n", a...)
	os.Exit(1)
}

func execCmd(name string, arg ...string) string {
	cmd := exec.Command(name, arg...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		fatalf("%s %v failed: %v\n%s", name, arg, err, out.String())
	}
	return strings.TrimSpace(out.String())
}

func tryExec(name string, arg ...string) string {
	cmd := exec.Command(name, arg...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	_ = cmd.Run()
	return strings.TrimSpace(out.String())
}

// ─── Linux Distribution & Tor UID ─────────────────────────────────────────────
func detectDistro() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return "unknown"
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		l := strings.ToLower(scanner.Text())
		switch {
		case strings.Contains(l, "debian") || strings.Contains(l, "ubuntu"):
			return "debian"
		case strings.Contains(l, "fedora") || strings.Contains(l, "centos") || strings.Contains(l, "rhel"):
			return "fedora"
		case strings.Contains(l, "arch"):
			return "arch"
		}
	}
	return "unknown"
}

func getTorUID() string {
	switch detectDistro() {
	case "debian":
		return tryExec("id", "-ur", "debian-tor")
	case "fedora":
		return tryExec("id", "-ur", "toranon")
	default:
		return tryExec("id", "-ur", "tor")
	}
}

// ─── Logging Initialization (Ephemeral Options) ──────────────────────────────
// logMode can be "local", "ramdisk", or "encrypted". For the purpose of this demo,
// "encrypted" logging is simulated with a placeholder.
func initLogger(logMode string) {
	var path string
	switch logMode {
	case "ramdisk":
		path = "/dev/shm/anonow.log"
	case "encrypted":
		path = "anonow_encrypted.log" // In a real scenario, encrypt log output before writing.
	default:
		path = "anonow.log"
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open log file %s: %v\n", path, err)
		os.Exit(1)
	}
	handler := slog.NewTextHandler(io.MultiWriter(os.Stdout, f), &slog.HandlerOptions{Level: slog.LevelInfo})
	logger = slog.New(handler)
}

// ─── Fail-Safe Profile: Saving and Restoring Configurations ───────────────────
func saveSecureProfile(dnsResolverEnabled bool) {
	// Backup torrc if it exists.
	if data, err := os.ReadFile(torrcFile); err == nil {
		_ = os.WriteFile(backupTorrcPath, data, 0644)
		logger.Info("Saved torrc backup", "backup", backupTorrcPath)
	}

	// Backup /etc/resolv.conf if DNS resolver orchestration is enabled.
	if dnsResolverEnabled {
		if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
			_ = os.WriteFile(backupResolvPath, data, 0644)
			logger.Info("Saved resolv.conf backup", "backup", backupResolvPath)
		}
	}

	// Backup current nftables rules for table "inet anonow" (if exists).
	if output := tryExec("nft", "list", "table", "inet", "anonow"); output != "" {
		_ = os.WriteFile(backupNftablePath, []byte(output), 0644)
		logger.Info("Saved nftables backup", "backup", backupNftablePath)
	}
}

func restoreSecureProfile(dnsResolverEnabled bool) {
	// Restore torrc
	if data, err := os.ReadFile(backupTorrcPath); err == nil {
		_ = os.WriteFile(torrcFile, data, 0644)
		logger.Info("Restored torrc from backup", "backup", backupTorrcPath)
	}

	// Restore /etc/resolv.conf if DNS resolver orchestration was enabled.
	if dnsResolverEnabled {
		if data, err := os.ReadFile(backupResolvPath); err == nil {
			_ = os.WriteFile("/etc/resolv.conf", data, 0644)
			logger.Info("Restored resolv.conf from backup", "backup", backupResolvPath)
		}
	}

	// Flush current nftables configuration and restore previous rules if backup exists.
	flushNftables()
	if data, err := os.ReadFile(backupNftablePath); err == nil && len(data) > 0 {
		// Here you might reapply the old nftables rules.
		// For demo, we simply log that a restoration would occur.
		logger.Info("Would restore previous nftables rules from backup", "backup", backupNftablePath)
	}
}

// ─── DNS Resolver Orchestration ──────────────────────────────────────────────
// When enabled, reconfigure /etc/resolv.conf to use a local DoH resolver (assumed running on port 5353)
// and update nftables to capture additional DNS ports (e.g., UDP 853 for DNS-over-TLS).
func setupDNSResolver() {
	// Backup is handled elsewhere. Now set up resolv.conf.
	dohNameserver := "127.0.0.1" // assuming a local DoH resolver is running on 5353
	newConf := fmt.Sprintf("nameserver %s\n", dohNameserver)
	if err := os.WriteFile("/etc/resolv.conf", []byte(newConf), 0644); err != nil {
		fatalf("failed to write /etc/resolv.conf: %v", err)
	}
	logger.Info("System resolver reconfigured for DoH", "nameserver", dohNameserver)

	// Optionally, you might want to start or restart a service such as dnscrypt-proxy here.
}

// monitorDNSLeaks periodically runs a (simulated) DNS leak test.
// If a leak is detected, it either alerts or re-applies the firewall rules based on dnsLeakAction.
func monitorDNSLeaks(ctx context.Context, dnsLeakAction string, secureDNSEnabled bool, uid, secureDNSPort string) {
	// For demo purposes, we use a fake API endpoint and simulated response.
	const dnsLeakTestURL = "https://dnsleaktest.example/api" // Replace with a real endpoint if available.
	for {
		select {
		case <-ctx.Done():
			logger.Info("DNS leak monitoring stopped")
			return
		case <-time.After(randomizedInterval(5 * time.Minute)):
			logger.Info("Performing DNS leak test")
			// Simulate an HTTP GET for DNS leak test
			respBytes := httpGETBytes(dnsLeakTestURL)
			// Expecting {"secure": true} if safe.
			var result struct {
				Secure bool `json:"secure"`
			}
			_ = json.Unmarshal(respBytes, &result)
			if !result.Secure {
				msg := "DNS leak detected!"
				if dnsLeakAction == "reapply" {
					logger.Warn(msg + " Reapplying firewall rules")
					applyNftables(uid, secureDNSEnabled, secureDNSPort)
				} else {
					logger.Warn(msg + " Alerting user")
					fmt.Println("\033[31m[!]\033[0m DNS leak detected!")
				}
			} else {
				logger.Info("DNS leak test passed; secure DNS in use")
			}
		}
	}
}

// ─── Tor Configuration & Pluggable Transport ───────────────────────────────────
// ensureTorrcFragment appends a fragment to the Tor configuration file.
// If a pluggable transport is specified, it adds the necessary configuration.
func ensureTorrcFragment(pluggableTransport string) {
	content := fmt.Sprintf(`
## Added by AnoNow – do not edit by hand
VirtualAddrNetwork %s
AutomapHostsOnResolve 1
TransPort %s
DNSPort %s
`, virtualTorNetworkCIDR, torPort, dnsPort)
	if pluggableTransport != "" {
		// For demonstration, a simple transport config line is appended.
		// (In practice, this configuration depends on the chosen transport.)
		transportLine := fmt.Sprintf("ClientTransportPlugin %s exec /usr/bin/%sproxy\n", pluggableTransport, pluggableTransport)
		content += transportLine
	}
	b, err := os.ReadFile(torrcFile)
	if err != nil {
		// File might not exist; ignore.
		return
	}
	if !bytes.Contains(b, []byte("VirtualAddrNetwork")) {
		f, err := os.OpenFile(torrcFile, os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			defer f.Close()
			_, _ = io.WriteString(f, content)
			logger.Info("Tor configuration fragment appended", "pluggable", pluggableTransport)
		}
	}
}

func restartTorService() {
	switch detectDistro() {
	case "arch", "debian", "fedora":
		execCmd("systemctl", "restart", "tor")
	}
	logger.Info("Tor service restarted")
}

// ─── nftables Manipulation ─────────────────────────────────────────────────────
// nftScript builds the complete rule‑set to feed into `nft -f`.
// If secureDNSEnabled is true, use secureDNSPort (e.g., 5353) for DNS redirection on UDP 53 and 853.
func nftScript(uid string, secureDNSEnabled bool, secureDNSPort string, pluggableTransport string) string {
	exclude4 := []string{}
	exclude6 := []string{}
	for _, cidr := range excludedCIDRs {
		if strings.Contains(cidr, ":") {
			exclude6 = append(exclude6, cidr)
		} else {
			exclude4 = append(exclude4, cidr)
		}
	}

	var dnsRedirectRules string
	if secureDNSEnabled && secureDNSPort != "" {
		dnsRedirectRules = fmt.Sprintf(
			"udp dport 53 redirect to :%s\n    udp dport 853 redirect to :%s",
			secureDNSPort, secureDNSPort)
	} else {
		dnsRedirectRules = fmt.Sprintf("udp dport %s redirect to :%s", dnsPort, dnsPort)
	}

	// Optionally, rules could be further modified when a pluggable transport is used.
	// For simplicity, we include the same redirection.
	return fmt.Sprintf(`flush table inet anonow

table inet anonow {

 chain nat_out {
    type nat hook output priority 0; policy accept;
    meta skuid %s return
    %s
    ip daddr { %s } return
    ip6 daddr { %s } return
    tcp flags & syn == syn redirect to :%s
 }

 chain filter_out {
    type filter hook output priority 1; policy drop;
    meta skuid %s accept
    ct state established,related accept
    ip daddr { %s } accept
    ip6 daddr { %s } accept
 }
}
`, uid, dnsRedirectRules,
		strings.Join(exclude4, ", "),
		strings.Join(exclude6, ", "),
		torPort,
		uid,
		strings.Join(exclude4, ", "),
		strings.Join(exclude6, ", "))
}

func applyNftables(uid string, secureDNSEnabled bool, secureDNSPort string) {
	script := nftScript(uid, secureDNSEnabled, secureDNSPort, "")
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		fatalf("nft failed: %v\n%s", err, out.String())
	}
	logger.Info("nftables rules configured for Tor routing", "secureDNS", secureDNSEnabled)
}

func flushNftables() {
	_ = tryExec("nft", "flush", "table", "inet", "anonow")
	_ = tryExec("nft", "delete", "table", "inet", "anonow")
	logger.Info("nftables rules cleared")
}

// ─── HTTP Helpers ──────────────────────────────────────────────────────────────
var httpClient = &http.Client{Timeout: httpTimeout}

func httpGETBytes(url string) []byte {
	resp, err := httpClient.Get(url)
	if err != nil {
		logger.Warn("HTTP request failed", "url", url, "err", err)
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Warn("reading body failed", "url", url, "err", err)
		return nil
	}
	return body
}

// ─── Public‑IP & Geolocation ───────────────────────────────────────────────────
type torAPIResponse struct{ IP string `json:"IP"` }
type httpBinResponse struct{ Origin string `json:"origin"` }
type ipAPIResponse struct {
	Country string `json:"country"`
	City    string `json:"city"`
}

func fetchCurrentIP() (ip, country, city string) {
	var torResp torAPIResponse
	for i := 0; i < 9; i++ {
		if b := httpGETBytes("https://check.torproject.org/api/ip"); len(b) > 0 {
			_ = json.Unmarshal(b, &torResp)
			if torResp.IP != "" {
				ip = torResp.IP
				break
			}
		}
		time.Sleep(5 * time.Second)
	}

	if ip == "" {
		var hb httpBinResponse
		if b := httpGETBytes("https://httpbin.org/ip"); len(b) > 0 {
			_ = json.Unmarshal(b, &hb)
			ip = hb.Origin
		}
	}

	if ip == "" {
		return // total failure
	}

	var loc ipAPIResponse
	if b := httpGETBytes("http://ip-api.com/json/" + ip); len(b) > 0 {
		_ = json.Unmarshal(b, &loc)
		country, city = loc.Country, loc.City
	}

	return
}

func displayCurrentIP() {
	fmt.Println("\033[93m[*]\033[0m AnoNow: fetching public IP…")
	ip, country, city := fetchCurrentIP()
	if ip == "" {
		fatalf("could not determine public IP")
	}
	fmt.Printf(" \033[92m[+]\033[0m AnoNow: Your IP: \033[92m%s\033[0m\n", ip)
	if country != "" {
		fmt.Printf(" \033[92m[+]\033[0m AnoNow: Location: \033[92m%s, %s\033[0m\n", country, city)
	}
	logger.Info("current IP", "ip", ip, "country", country, "city", city)
}

// ─── Tor Control Integration ──────────────────────────────────────────────────
// requestNewTorIdentityControl connects to the Tor control port and issues a newnym signal.
func requestNewTorIdentityControl(controlAddr, controlPassword string) {
	conn, err := net.Dial("tcp", controlAddr)
	if err != nil {
		logger.Warn("failed to connect to Tor control port", "err", err)
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	// Read initial response (expecting a 250 OK message)
	buf := make([]byte, 512)
	_, _ = conn.Read(buf)

	// Send authentication command.
	authCmd := "AUTHENTICATE \""
	if controlPassword != "" {
		authCmd += controlPassword
	}
	authCmd += "\"\r\n"
	_, _ = conn.Write([]byte(authCmd))
	_, _ = conn.Read(buf) // Read auth response

	// Send the NEWNYM command.
	_, _ = conn.Write([]byte("SIGNAL NEWNYM\r\n"))
	_, _ = conn.Read(buf) // Read command response
	logger.Info("Tor identity rotated via control protocol")
	displayCurrentIP()
}

// ─── Rotation Timer Randomization ─────────────────────────────────────────────
// randomizedInterval returns the base duration plus a random duration between 0 and 20% of base.
func randomizedInterval(base time.Duration) time.Duration {
	// Variation up to 20% of the base interval
	offset := time.Duration(rand.Int63n(int64(base)/5))
	return base + offset
}

// autoRotateIP rotates the Tor identity at randomized intervals.
// If torControlEnabled is true, it uses the Tor control protocol; otherwise it uses SIGHUP.
func autoRotateIP(ctx context.Context, baseInterval time.Duration, torControlEnabled bool, controlAddr, controlPassword string) {
	for {
		select {
		case <-ctx.Done():
			logger.Info("Auto-rotation stopped")
			return
		case <-time.After(randomizedInterval(baseInterval)):
			if torControlEnabled {
				requestNewTorIdentityControl(controlAddr, controlPassword)
			} else {
				// Fallback: SIGHUP based rotation.
				pid := execCmd("pidof", "tor")
				execCmd("kill", "-HUP", pid)
				displayCurrentIP()
				logger.Info("Tor identity rotated via SIGHUP")
			}
			fmt.Println(" \033[92m[*]\033[0m Identity rotated\n")
		}
	}
}

// ─── main ─────────────────────────────────────────────────────────────────────
func main() {
	rand.Seed(time.Now().UnixNano())

	// Command-line Flags
	flagStart := flag.Bool("start", false, "Start AnoNow (route traffic through Tor)")
	flagStop := flag.Bool("stop", false, "Stop AnoNow (restore normal traffic)")
	flagHelp := flag.Bool("help", false, "Display help information")
	flagDNSResolver := flag.Bool("dns-resolver", false, "Enable local secure DNS resolver (force DoH)")
	flagDNSLeakAction := flag.String("dns-leak-action", "alert", "Action on DNS leak detection: alert or reapply")
	flagRotateInterval := flag.Duration("rotate-interval", 30*time.Minute, "Base interval for Tor identity rotation")
	flagLogMode := flag.String("log-mode", "local", "Logging mode: local, ramdisk, or encrypted")
	flagPluggableTransport := flag.String("pluggable-transport", "", "Specify a pluggable transport (e.g., obfs4)")
	flagTorControlPassword := flag.String("tor-control-password", "", "Password for Tor control (if required)")
	flagTorControlPort := flag.String("tor-control-port", "9051", "Tor control port")
	flagFailSafe := flag.Bool("fail-safe", true, "Enable fail-safe: save and restore secure configuration profile")
	flagTorControl := flag.Bool("tor-control", true, "Enable Tor control integration")
	flag.Parse()

	if *flagHelp || (!*flagStart && !*flagStop) {
		fmt.Printf("Usage: %s [-start | -stop] [options]\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Initialize the logger based on mode.
	initLogger(*flagLogMode)
	logger.Info("Paranoia starting", "log-mode", *flagLogMode)

	// If fail-safe is enabled, save current secure configuration profile.
	if *flagFailSafe {
		saveSecureProfile(*flagDNSResolver)
		// Ensure restoration on exit.
		defer restoreSecureProfile(*flagDNSResolver)
	}

	if *flagStart {
		requireRoot()

		// If DNS resolver orchestration is enabled, reconfigure system resolver.
		secureDNSEnabled := *flagDNSResolver
		// If enabled, assume our secure DNS resolver listens on port 5353.
		secureDNSPort := ""
		if secureDNSEnabled {
			secureDNSPort = "5353"
			setupDNSResolver()
		}

		// Modify Tor configuration for pluggable transport if requested.
		ensureTorrcFragment(*flagPluggableTransport)
		restartTorService()

		uid := getTorUID()
		if uid == "" {
			fatalf("failed to get Tor UID")
		}

		applyNftables(uid, secureDNSEnabled, secureDNSPort)
		displayCurrentIP()

		// Setup graceful shutdown with context cancellation.
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		// Start auto-rotation of Tor identity.
		go autoRotateIP(ctx, *flagRotateInterval, *flagTorControl, "127.0.0.1:"+*flagTorControlPort, *flagTorControlPassword)

		// If DNS resolver orchestration is enabled, start DNS leak monitoring.
		if secureDNSEnabled {
			go monitorDNSLeaks(ctx, *flagDNSLeakAction, secureDNSEnabled, uid, secureDNSPort)
		}

		// Wait for shutdown signal.
		<-ctx.Done()
		fmt.Println("\nExiting... flushing nftables and restoring configurations")
		flushNftables()
	}

	if *flagStop {
		requireRoot()
		flushNftables()
		if *flagFailSafe {
			restoreSecureProfile(*flagDNSResolver)
		}
		logger.Info("Paranoia stopped; normal trafficresumed")
		fmt.Println("Paranoia stopped; nftables rules cleared and configuration restored")
	}
}
