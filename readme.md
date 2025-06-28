# DNS Capability Checker (Go Version)

## Overview

DNS Capability Checker is a command-line tool written in Go that tests the capability and performance of various DNS servers and protocols. It checks your system's configured DNS servers (from `/etc/resolv.conf` on Unix-like systems) and a predefined list of popular public DNS providers across different protocols:

- Plain DNS (UDP/53)
- Plain DNS (TCP/53)
- DNS-over-TLS (DoT/853)
- DNS-over-HTTPS (DoH/443)

The tool reports whether queries are successful, the time taken, the number of IP addresses returned for `example.com.`, and certificate validation status for DoT/DoH.

## Features

- **Multiple Protocol Testing**: Checks UDP, TCP, DoT, and DoH.
- **System DNS Integration**: Automatically attempts to detect and test system DNS servers (from `/etc/resolv.conf` on Unix-like systems).
- **Public DNS Server Checks**: Includes a built-in list of common public DNS resolvers (Cloudflare, Google, Quad9, OpenDNS).
- **Performance Metrics**: Measures query duration.
- **Certificate Validation Info**: For DoT and DoH, indicates if TLS certificate validation was enabled and if it contributed to success.
- **Concurrent Checks**: Performs checks concurrently (up to 10 by default) for faster results.
- **Colorized Output**: Uses colors for better readability of results (success/failure).
- **Configurable Defaults**: Uses `example.com.` as the query domain and a 5-second timeout by default.

## Prerequisites

- Go version 1.18 or higher (developed with Go 1.24.3 as per `go.mod`).
- Access to the internet for DNS queries.
- On Unix-like systems, read access to `/etc/resolv.conf` for system DNS server detection.

## Getting Started

### 1. Clone the Repository (If you don't have the files locally)

If you obtained the code as a set of files, you can skip this step. Otherwise:

```bash
git clone <repository_url>
cd dns-capability-checker
```

### 2. Build the Executable

Navigate to the project's root directory (where main.go and go.mod are located) and run:

```bash
go build
```

This will create an executable file named `dns-capability-checker` (or `dns-capability-checker.exe` on Windows) in the current directory.

### 3. Run the Tool

Execute the compiled binary:

```bash
./dns-capability-checker
```

(On Windows, use `.\dns-capability-checker.exe`)

## Output Explanation

The tool will first print a header with the query domain and timeout. Then, it will list the scheduled checks. Finally, it will display the results grouped by server name.

Example output snippet:

```
🔍 DNS Capability Checker (Go Version)
Query Domain: example.com.
Timeout: 5s
================================================================================

📋 System DNS Servers (from /etc/resolv.conf, Unix-like only)
  Scheduled 6 checks for system DNS servers.

🌐 Public DNS Servers
  Scheduled 15 checks for public DNS servers.

📊 Results Summary
================================================================================

🖥️  Cloudflare
  ✓ Cloudflare                 UDP/53       25ms  - 2 IPs
  ✓ Cloudflare                 TCP/53       30ms  - 2 IPs
  ✓ Cloudflare                 DoT/853      45ms  - 2 IPs (Certs Validated)
  ✓ Cloudflare                 DoH/443      60ms  - 2 IPs (Certs Validated)

🖥️  Google
  ✓ Google                     UDP/53       18ms  - 2 IPs
  ...

🖥️  System (192.168.1.1)
  ✓ System (192.168.1.1)     UDP/53       8ms   - 2 IPs
  ✓ System (192.168.1.1)     TCP/53       12ms  - 2 IPs

🖥️  System (192.168.1.1) (opp.)
  ✓ System (192.168.1.1) (opp.) DoT/853      22ms  - 2 IPs (Certs Unchecked)

🖥️  Some Failing Server
  ✗ Some Failing Server        UDP/53       5005ms (Certs Unchecked) - Timeout (overall operation)
```

### Legend

- **✓ / ✗**: Indicates success (green checkmark) or failure (red X) of the check.

- **Server Name**: The name of the DNS server being tested.
  - System DNS servers derived from `/etc/resolv.conf` are named like `System (IP_ADDRESS)`.
  - Opportunistic DoT checks against system IPs will have `(opp.)` appended to the server name, e.g., `System (IP_ADDRESS) (opp.)`.

- **Protocol**: The DNS protocol used (e.g., UDP/53, DoT/853).

- **Duration**: The time taken for the query in milliseconds (ms).

- **IPs Info**:
  - `X IPs`: The number of A or AAAA records returned for the query domain (example.com.).
  - `NXDOMAIN` or `No A/AAAA`: Indicates the domain was resolved as non-existent or no A/AAAA records were found in the answer.

- **Certificate Info (for DoT/DoH)**:
  - `(Certs Validated)`: (Green) TLS certificate validation was enabled, and the DNS query was successful.
  - `(Certs Validation Enabled)`: (Yellow) TLS certificate validation was enabled, but the DNS query itself failed for other reasons (e.g., timeout, DNS error).
  - `(Certs Unchecked)`: (Blue) TLS certificate validation was not performed for this check (e.g., for opportunistic DoT against an IP where the hostname is unknown, or if the protocol is not DoT/DoH).

- **Error Message**: If a check fails, a brief error message is provided (e.g., Timeout, DNS error: SERVFAIL).

A summary at the end shows the total number of successful checks and the success rate.

## How it Works

### System DNS Servers Discovery

The tool attempts to read `/etc/resolv.conf` (on Unix-like systems) to find system-configured DNS server IP addresses.

For each IP found, it schedules checks for:
- Plain DNS over UDP/53.
- Plain DNS over TCP/53.
- Opportunistic DNS-over-TLS (DoT) on port 853. For these, certificate validation is typically disabled as the true DoT hostname is unknown, and the IP address itself is used for the SNI. These are marked with `(opp.)` in the server name.

### Public DNS Servers

A predefined list of public DNS servers (Cloudflare, Google, Quad9, OpenDNS) and their known DoT hostnames and DoH URLs is used.

For each public server, checks are scheduled for UDP/53, TCP/53.
- If a DoT hostname is defined, a DoT/853 check is scheduled with proper SNI and TLS certificate validation enabled.
- If a DoH URL is defined, a DoH/443 check is scheduled with TLS certificate validation enabled.

### Query Execution

- All DNS checks are performed by querying for A records of `example.com.` (by default).
- Checks are run concurrently, up to a maximum limit (`maxConcurrentChecks`, default 10), to speed up the process.
- Each check has a timeout (`defaultTimeoutSeconds`, default 5 seconds).

### Results Display

- Results are grouped by server name.
- System DNS servers are typically listed first, followed by public DNS servers.
- Within each server group, results are sorted by protocol.

## Limitations

- **System DNS Detection**: System DNS server detection via `/etc/resolv.conf` is specific to Unix-like systems. It will not work or may provide incomplete information on Windows or other operating systems. For Windows, users would need to manually identify their DNS servers and potentially modify the code or use other tools to test them with this script's logic.

- **Opportunistic DoT for System IPs**: When testing DoT for system DNS server IPs, the tool uses the IP address as the SNI for TLS, and certificate validation is disabled (`ValidateCerts: false`). This is an "opportunistic" check to see if the server responds on port 853 with anything resembling DoT, not a full validation of a known DoT service.

- **Fixed Query Domain & Type**: The query domain (`example.com.`) and query type (A record) are currently hardcoded in `main.go`.

- **Firewall/Network Restrictions**: Local firewalls, network policies, or ISP interference (e.g., transparent DNS proxies) can block certain DNS protocols or servers, leading to failed checks that might not reflect the server's actual capability if accessed from a different network.

- **DoH Path Specificity**: The DoH checks assume the standard `/dns-query` path or a fully specified URL. Some DoH servers might use different paths.

## Dependencies

The project uses the following Go modules (managed by `go.mod`):

- `github.com/fatih/color`: For colorized console output.
- `github.com/miekg/dns`: A comprehensive DNS library for Go.

## To-Do / Potential Enhancements

- Allow specifying custom DNS servers (IPs, DoT hostnames, DoH URLs) via command-line arguments or a configuration file.
- Allow changing the query domain and query type via command-line arguments.
- Add support for testing more DNS record types (e.g., AAAA, MX, TXT).
- Implement more robust system DNS detection for different operating systems (e.g., Windows).
- Option to export results to structured formats (e.g., JSON, CSV).
- More detailed error reporting or debugging options.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.