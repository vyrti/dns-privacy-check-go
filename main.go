package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/miekg/dns"
)

const (
	queryDomainDefault    = "example.com."
	defaultTimeoutSeconds = 5
	maxConcurrentChecks   = 10
)

type dnsProtocol int

const (
	protocolPlainUDP dnsProtocol = iota
	protocolPlainTCP
	protocolDoT
	protocolDoH
)

func (p dnsProtocol) String() string {
	switch p {
	case protocolPlainUDP:
		return "UDP/53"
	case protocolPlainTCP:
		return "TCP/53"
	case protocolDoT:
		return "DoT/853"
	case protocolDoH:
		return "DoH/443"
	default:
		return "Unknown"
	}
}

type dnsServer struct {
	Name        string
	IP          string
	DoTHostname string
	DoHURL      string
}

type checkConfig struct {
	ServerName     string
	Protocol       dnsProtocol
	Target         string
	SNIHostname    string
	QueryDomain    string
	Timeout        time.Duration
	ValidateCerts  bool
	IsSystemServer bool
}

type checkResult struct {
	ServerName     string
	Protocol       dnsProtocol
	Success        bool
	Duration       time.Duration
	IPCount        int
	Error          string
	CertsValidated bool
	IsSystemServer bool
}

func (cr checkResult) FormatOutput() string {
	statusMark := color.RedString("✗")
	if cr.Success {
		statusMark = color.GreenString("✓")
	}

	certInfo := ""
	if cr.Protocol == protocolDoT || cr.Protocol == protocolDoH {
		if cr.CertsValidated {
			if cr.Success {
				certInfo = color.GreenString(" (Certs Validated)")
			} else {
				certInfo = color.YellowString(" (Certs Validation Enabled)")
			}
		} else {
			certInfo = color.BlueString(" (Certs Unchecked)")
		}
	}

	if cr.Success {
		ipInfo := ""
		if cr.IPCount == 0 {
			ipInfo = " - NXDOMAIN or No A/AAAA"
		} else {
			ipInfo = fmt.Sprintf(" - %d IPs", cr.IPCount)
		}
		return fmt.Sprintf("  %s %-25s %-12s %-5dms%s%s",
			statusMark, cr.ServerName, cr.Protocol.String(), cr.Duration.Milliseconds(), ipInfo, certInfo)
	}
	return fmt.Sprintf("  %s %-25s %-12s %-5dms%s - %s",
		statusMark, cr.ServerName, cr.Protocol.String(), cr.Duration.Milliseconds(), certInfo, cr.Error)
}

var (
	resolvConfNameserverRegex = regexp.MustCompile(`^\s*nameserver\s+([0-9a-fA-F:.]+)`)
)

func getSystemDNSServers() ([]dnsServer, error) {
	servers := []dnsServer{}
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		log.Printf("Warning: Could not open /etc/resolv.conf: %v. System DNS server IP detection may be incomplete.", err)
		return servers, nil
	}
	defer file.Close()

	seenIPs := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		matches := resolvConfNameserverRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			ipStr := matches[1]
			if net.ParseIP(ipStr) != nil && !seenIPs[ipStr] {
				servers = append(servers, dnsServer{
					Name: fmt.Sprintf("System (%s)", ipStr),
					IP:   ipStr,
				})
				seenIPs[ipStr] = true
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Warning: Error reading /etc/resolv.conf: %v", err)
	}

	if len(servers) == 0 {
		log.Println("No system DNS servers found via /etc/resolv.conf.")
	}
	return servers, nil
}

func getPublicDNSServers() []dnsServer {
	return []dnsServer{
		{Name: "Cloudflare", IP: "1.1.1.1", DoTHostname: "cloudflare-dns.com", DoHURL: "https://cloudflare-dns.com/dns-query"},
		{Name: "Cloudflare (IPv6)", IP: "2606:4700:4700::1111", DoTHostname: "cloudflare-dns.com", DoHURL: "https://cloudflare-dns.com/dns-query"},
		{Name: "Google", IP: "8.8.8.8", DoTHostname: "dns.google", DoHURL: "https://dns.google/dns-query"},
		{Name: "Google (IPv6)", IP: "2001:4860:4860::8888", DoTHostname: "dns.google", DoHURL: "https://dns.google/dns-query"},
		{Name: "Quad9", IP: "9.9.9.9", DoTHostname: "dns.quad9.net", DoHURL: "https://dns.quad9.net/dns-query"},
		{Name: "Quad9 (IPv6)", IP: "2620:fe::fe", DoTHostname: "dns.quad9.net", DoHURL: "https://dns.quad9.net/dns-query"},
		{Name: "OpenDNS", IP: "208.67.222.222", DoTHostname: "dns.opendns.com", DoHURL: "https://doh.opendns.com/dns-query"},
	}
}

func performLookup(ctx context.Context, cc checkConfig) checkResult {
	startTime := time.Now()
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(cc.QueryDomain), dns.TypeA)
	msg.RecursionDesired = true

	var response *dns.Msg
	var err error
	var clientIPCount int

	client := dns.Client{}
	client.Timeout = cc.Timeout

	opCtx, cancel := context.WithTimeout(ctx, cc.Timeout+time.Second*2)
	defer cancel()

	switch cc.Protocol {
	case protocolPlainUDP:
		client.Net = "udp"
		response, _, err = client.ExchangeContext(opCtx, msg, cc.Target)
	case protocolPlainTCP:
		client.Net = "tcp"
		response, _, err = client.ExchangeContext(opCtx, msg, cc.Target)
	case protocolDoT:
		client.Net = "tcp-tls"
		tlsConfig := &tls.Config{
			ServerName:         cc.SNIHostname,
			InsecureSkipVerify: !cc.ValidateCerts,
		}
		client.TLSConfig = tlsConfig
		response, _, err = client.ExchangeContext(opCtx, msg, cc.Target)
	case protocolDoH:
		packedMsg, packErr := msg.Pack()
		if packErr != nil {
			err = fmt.Errorf("packing DNS message for DoH: %w", packErr)
			break
		}

		httpClient := &http.Client{
			Timeout: cc.Timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: !cc.ValidateCerts,
				},
				DialContext: (&net.Dialer{
					Timeout:   cc.Timeout,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          10,
				IdleConnTimeout:       30 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		}

		req, reqErr := http.NewRequestWithContext(opCtx, "POST", cc.Target, bytes.NewReader(packedMsg))
		if reqErr != nil {
			err = fmt.Errorf("creating DoH request: %w", reqErr)
			break
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")

		httpResp, httpErr := httpClient.Do(req)
		if httpErr != nil {
			err = fmt.Errorf("DoH HTTP request: %w", httpErr)
			break
		}
		defer httpResp.Body.Close()

		if httpResp.StatusCode != http.StatusOK {
			err = fmt.Errorf("DoH HTTP error: %s", httpResp.Status)
			break
		}

		body, readErr := io.ReadAll(httpResp.Body)
		if readErr != nil {
			err = fmt.Errorf("reading DoH response body: %w", readErr)
			break
		}

		response = new(dns.Msg)
		unpackErr := response.Unpack(body)
		if unpackErr != nil {
			err = fmt.Errorf("unpacking DoH DNS message: %w", unpackErr)
		}
	}

	duration := time.Since(startTime)
	res := checkResult{
		ServerName:     cc.ServerName,
		Protocol:       cc.Protocol,
		Duration:       duration,
		CertsValidated: cc.ValidateCerts,
		IsSystemServer: cc.IsSystemServer,
	}

	if opCtx.Err() == context.DeadlineExceeded {
		res.Success = false
		res.Error = "Timeout (overall operation)"
		return res
	}

	if err != nil {
		res.Success = false
		res.Error = err.Error()
	} else if response == nil {
		res.Success = false
		res.Error = "No response received"
	} else if response.Rcode != dns.RcodeSuccess {
		res.Success = false
		res.Error = fmt.Sprintf("DNS error: %s", dns.RcodeToString[response.Rcode])
	} else {
		res.Success = true
		for _, ans := range response.Answer {
			if _, okA := ans.(*dns.A); okA {
				clientIPCount++
			}
			if _, okAAAA := ans.(*dns.AAAA); okAAAA {
				clientIPCount++
			}
		}
		res.IPCount = clientIPCount
	}
	return res
}

func main() {
	log.SetFlags(0)

	queryTimeout := time.Duration(defaultTimeoutSeconds) * time.Second

	fmt.Println("🔍 DNS Capability Checker (Go Version)")
	fmt.Printf("Query Domain: %s\n", queryDomainDefault)
	fmt.Printf("Timeout: %s\n", queryTimeout)
	fmt.Println(strings.Repeat("=", 80))

	var checks []checkConfig

	// 1. System DNS Servers
	fmt.Println("\n📋 System DNS Servers (from /etc/resolv.conf, Unix-like only)")
	systemServers, _ := getSystemDNSServers()
	systemChecksCount := 0
	if len(systemServers) > 0 {
		for _, s := range systemServers {
			if s.IP != "" {
				checks = append(checks, checkConfig{
					ServerName: s.Name, Protocol: protocolPlainUDP, Target: net.JoinHostPort(s.IP, "53"),
					QueryDomain: queryDomainDefault, Timeout: queryTimeout, ValidateCerts: true, IsSystemServer: true,
				})
				systemChecksCount++
				checks = append(checks, checkConfig{
					ServerName: s.Name, Protocol: protocolPlainTCP, Target: net.JoinHostPort(s.IP, "53"),
					QueryDomain: queryDomainDefault, Timeout: queryTimeout, ValidateCerts: true, IsSystemServer: true,
				})
				systemChecksCount++
				checks = append(checks, checkConfig{
					ServerName:     fmt.Sprintf("%s (opp.)", s.Name),
					Protocol:       protocolDoT,
					Target:         net.JoinHostPort(s.IP, "853"),
					SNIHostname:    s.IP,
					QueryDomain:    queryDomainDefault,
					Timeout:        queryTimeout,
					ValidateCerts:  false,
					IsSystemServer: true,
				})
				systemChecksCount++
			}
		}
		fmt.Printf("  Scheduled %d checks for system DNS servers.\n", systemChecksCount)
	} else {
		fmt.Println("  No system DNS server IPs found to schedule specific checks. For Windows, this requires manual configuration or different methods.")
	}

	// 2. Public DNS Servers
	fmt.Println("\n🌐 Public DNS Servers")
	publicServers := getPublicDNSServers()
	publicServerChecksCount := 0
	for _, s := range publicServers {
		if s.IP != "" {
			targetPlain := net.JoinHostPort(s.IP, "53")
			checks = append(checks, checkConfig{ServerName: s.Name, Protocol: protocolPlainUDP, Target: targetPlain, QueryDomain: queryDomainDefault, Timeout: queryTimeout, ValidateCerts: true})
			publicServerChecksCount++
			checks = append(checks, checkConfig{ServerName: s.Name, Protocol: protocolPlainTCP, Target: targetPlain, QueryDomain: queryDomainDefault, Timeout: queryTimeout, ValidateCerts: true})
			publicServerChecksCount++

			if s.DoTHostname != "" {
				targetDoT := net.JoinHostPort(s.IP, "853")
				checks = append(checks, checkConfig{
					ServerName: s.Name, Protocol: protocolDoT, Target: targetDoT, SNIHostname: s.DoTHostname,
					QueryDomain: queryDomainDefault, Timeout: queryTimeout, ValidateCerts: true,
				})
				publicServerChecksCount++
			}
		}
		if s.DoHURL != "" {
			checks = append(checks, checkConfig{
				ServerName: s.Name, Protocol: protocolDoH, Target: s.DoHURL,
				QueryDomain: queryDomainDefault, Timeout: queryTimeout, ValidateCerts: true,
			})
			publicServerChecksCount++
		}
	}
	fmt.Printf("  Scheduled %d checks for public DNS servers.\n", publicServerChecksCount)

	// Execute checks with concurrency limit
	results := make(chan checkResult, len(checks))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, maxConcurrentChecks)

	for _, chk := range checks {
		wg.Add(1)
		go func(c checkConfig) {
			defer wg.Done()
			semaphore <- struct{}{}
			results <- performLookup(context.Background(), c)
			<-semaphore
		}(chk)
	}

	wg.Wait()
	close(results)

	allResults := []checkResult{}
	for res := range results {
		allResults = append(allResults, res)
	}

	displayResultsGrouped(allResults)
}

func displayResultsGrouped(results []checkResult) {
	fmt.Println("\n📊 Results Summary")
	fmt.Println(strings.Repeat("=", 80))

	if len(results) == 0 {
		fmt.Println("  No checks were executed or all results were filtered.")
		fmt.Println(strings.Repeat("=", 80))
		fmt.Println("📈 Summary: 0/0 checks successful (0.0%)")
		return
	}

	grouped := make(map[string][]checkResult)
	for _, r := range results {
		grouped[r.ServerName] = append(grouped[r.ServerName], r)
	}

	serverNames := make([]string, 0, len(grouped))
	for name := range grouped {
		serverNames = append(serverNames, name)
	}
	sort.SliceStable(serverNames, func(i, j int) bool {
		isSystemI := false
		isSystemJ := false
		for _, res := range results { // More robust way to check if a server group is "system"
			if res.ServerName == serverNames[i] {
				isSystemI = res.IsSystemServer
				break
			}
		}
		for _, res := range results {
			if res.ServerName == serverNames[j] {
				isSystemJ = res.IsSystemServer
				break
			}
		}

		if isSystemI && !isSystemJ {
			return true
		}
		if !isSystemI && isSystemJ {
			return false
		}
		return serverNames[i] < serverNames[j]
	})

	totalChecks := 0
	successfulChecks := 0

	for _, serverName := range serverNames {
		fmt.Printf("\n🖥️  %s\n", serverName)
		serverResults := grouped[serverName]
		sort.Slice(serverResults, func(i, j int) bool {
			return serverResults[i].Protocol < serverResults[j].Protocol
		})
		for _, r := range serverResults {
			fmt.Println(r.FormatOutput())
			totalChecks++
			if r.Success {
				successfulChecks++
			}
		}
	}

	fmt.Printf("\n%s\n", strings.Repeat("=", 80))
	successRate := 0.0
	if totalChecks > 0 {
		successRate = (float64(successfulChecks) / float64(totalChecks)) * 100.0
	}
	fmt.Printf("📈 Summary: %d/%d checks successful (%.1f%%)\n", successfulChecks, totalChecks, successRate)
}
