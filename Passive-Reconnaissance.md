# Passive Recon Cheat Sheet

> No direct interaction with the target. Very low detection risk.  
> Start wide — narrow down — then move to active enumeration.  
> **Scope first.** Validate all targets against your scoping document before acting.

---

## Table of Contents

- [Key Data Points](#key-data-points)
- [Domain Information](#domain-information)
  - [WHOIS](#whois)
  - [DNS Records](#dns-records)
  - [DNS Zone Transfers](#dns-zone-transfers)
  - [Certificate Transparency (CT Logs)](#certificate-transparency-ct-logs)
- [ASN / IP Space](#asn--ip-space)
- [Search Engine Dorking](#search-engine-dorking)
- [Web Fingerprinting](#web-fingerprinting)
- [robots.txt & Well-Known URIs](#robotstxt--well-known-uris)
- [Web Archives](#web-archives)
- [Cloud Resources](#cloud-resources)
- [Social Media & Staff OSINT](#social-media--staff-osint)
- [Breach / Credential Data](#breach--credential-data)
- [Automated Passive Recon](#automated-passive-recon)
- [DNS Record Types Reference](#dns-record-types-reference)
- [Notetaking Structure](#notetaking-structure)

---

## Key Data Points

| Data Point | What to Look For |
|---|---|
| **IP Space** | ASN, netblocks, cloud providers, DNS records |
| **Domain Info** | Subdomains, mail servers, VPN portals, defenses (SIEM/IDS/AV hints) |
| **Schema / Format** | Email naming format, AD username conventions, password policies |
| **Data Disclosures** | Public files (`.pdf`, `.docx`, `.xlsx`), metadata, intranet links, GitHub leaks |
| **Breach Data** | Leaked usernames, cleartext passwords, hashes |

---

## Domain Information

Domain information is the **first thing to gather** on any engagement. Before hunting for IPs or breach data, you need to understand who owns the domain, what DNS infrastructure is in place, what subdomains exist, and what third-party services are in use. This is done entirely passively using public records and third-party services.

Start with the company's main website — read the content carefully to understand their services, technologies, and structure. Then move into formal domain lookups.

---

## WHOIS

```bash
# Install
sudo apt update && sudo apt install whois -y

# Basic lookup
whois example.com

# Key fields to capture:
#   Registrar
#   Creation Date / Expiry Date
#   Name Servers        → reveals hosting provider
#   Registrant Contact  → social engineering target
#   Admin / Tech Contact
```

**Signal analysis:**

| Signal | Meaning |
|---|---|
| Very recent registration | Possible phishing / malicious domain |
| Privacy-protected registrant | Harder to attribute — investigate further |
| Bulletproof hosting provider | Likely malicious infrastructure |
| Shared name servers across domains | Linked infrastructure / campaign |
| Distant expiry date | Established, long-running domain |

Historical WHOIS records: **https://whoisfreaks.com**

---

## DNS Records

```bash
# All records (may be restricted by server)
dig any example.com

# Specific record types
dig example.com A        # IPv4 address
dig example.com AAAA     # IPv6 address
dig example.com MX       # mail servers
dig example.com NS       # nameservers
dig example.com TXT      # text records (SPF, DKIM, third-party verification)
dig example.com CNAME    # aliases
dig example.com SOA      # zone authority info

# Query a specific nameserver
dig @8.8.8.8 example.com A

# Short output only
dig +short example.com

# Full resolution trace
dig +trace example.com

# Answer section only (clean output)
dig +noall +answer example.com

# Reverse lookup (IP → hostname)
dig -x 192.168.1.1

# nslookup alternative
nslookup example.com
nslookup ns1.example.com
```

**TXT Record Intel — third-party services in use:**

| TXT Value | Indicates |
|---|---|
| `MS=ms...` | Microsoft / Office 365 tenant |
| `atlassian-domain-verification=...` | Jira / Confluence → look for misconfigs |
| `google-site-verification=...` | Google Workspace / GDrive → check open shares |
| `logmein-verification-code=...` | LogMeIn remote access → high-value if compromised |
| `v=spf1 include:mailgun.org ...` | Mailgun email API → test IDOR/SSRF on API endpoints |
| `v=spf1 include:_spf.google.com ...` | Gmail for email → check for open GDrive links |
| `_1password=...` | 1Password in use → social engineering / phishing target |

---

## DNS Zone Transfers

> Misconfigured name servers may return a full zone dump — a complete list of all subdomains, IPs, and service records.

```bash
# Step 1 — identify nameservers
dig example.com NS

# Step 2 — attempt zone transfer (AXFR) against each nameserver
dig axfr @ns1.example.com example.com
dig axfr @ns2.example.com example.com

# General syntax
dig axfr @<nameserver> <domain>

# Practice on intentionally vulnerable domain
dig axfr @nsztm1.digi.ninja zonetransfer.me
```

A successful zone transfer reveals: all subdomains, associated IPs, mail servers, service records, and internal naming conventions.  
Most modern servers block this — but it's always worth attempting.

---

## Certificate Transparency (CT Logs)

```bash
# Browse manually
# https://crt.sh/?q=example.com

# API — JSON output
curl -s "https://crt.sh/?q=example.com&output=json" | jq .

# Extract unique subdomains from CT logs
curl -s "https://crt.sh/?q=example.com&output=json" \
  | jq . | grep name | cut -d":" -f2 \
  | grep -v "CN=" | cut -d'"' -f2 \
  | awk '{gsub(/\\n/,"\n");}1;' | sort -u | tee subdomainlist

# Filter for a specific pattern (e.g. dev subdomains)
curl -s "https://crt.sh/?q=example.com&output=json" \
  | jq -r '.[] | select(.name_value | contains("dev")) | .name_value' \
  | sort -u
```

| Tool | URL |
|---|---|
| crt.sh | https://crt.sh |
| Censys | https://search.censys.io |

**Why CT logs beat brute-forcing:** They reveal historically issued certificates — including expired or decommissioned subdomains that may still host vulnerable software.

---

## ASN / IP Space

| Resource | URL |
|---|---|
| BGP Toolkit (Hurricane Electric) | https://bgp.he.net |
| IANA | https://www.iana.org |
| ARIN (Americas) | https://search.arin.net |
| RIPE NCC (Europe) | https://apps.db.ripe.net |
| ViewDNS.info | https://viewdns.info |
| Shodan | https://www.shodan.io |

```bash
# Validate IP found from BGP against viewdns.info
# Browse: https://bgp.he.net → enter domain or IP
# Browse: https://viewdns.info → confirm IP / reverse IP lookup

# Identify company-hosted vs cloud-hosted subdomains
for i in $(cat subdomainlist); do
  host $i | grep "has address" | grep example.com | cut -d" " -f1,4
done

# Extract IPs only into a file
for i in $(cat subdomainlist); do
  host $i | grep "has address" | grep example.com | cut -d" " -f4 >> ip-addresses
done

# Run discovered IPs through Shodan
for i in $(cat ip-addresses); do shodan host $i >> shodan-iplist; done
```

> Large corporations often have their own ASN. Smaller orgs typically host on Cloudflare, AWS, Azure, or GCP.  
> Confirm that any discovered IPs are **in-scope** before proceeding — get written approval for third-party infrastructure.

---

## Search Engine Dorking

### Core Operators

| Operator | Description | Example |
|---|---|---|
| `site:` | Limit results to a domain | `site:example.com` |
| `inurl:` | Term in the URL | `inurl:admin` |
| `filetype:` | Specific file extension | `filetype:pdf` |
| `intitle:` | Term in the page title | `intitle:"index of"` |
| `intext:` | Term in the body text | `intext:"password reset"` |
| `cache:` | Cached version of a page | `cache:example.com` |
| `link:` | Pages linking to a URL | `link:example.com` |
| `related:` | Similar websites | `related:example.com` |
| `"..."` | Exact phrase match | `"internal use only"` |
| `-` | Exclude a term | `site:example.com -inurl:login` |
| `*` | Wildcard | `filetype:pdf user* manual` |
| `OR` | Either term | `"linux" OR "ubuntu"` |
| `AND` | Both terms required | `site:example.com AND inurl:admin` |
| `..` | Numerical range | `site:example.com numrange:1000-2000` |

### Common Google Dorks

```
# Login / Admin pages
site:example.com inurl:login
site:example.com (inurl:login OR inurl:admin)
site:example.com inurl:dashboard
site:example.com inurl:portal

# Exposed sensitive files
site:example.com filetype:pdf
site:example.com (filetype:xls OR filetype:docx)
site:example.com filetype:sql
site:example.com ext:bak
site:example.com (ext:conf OR ext:cnf)
site:example.com ext:log
site:example.com filetype:env

# Backup files
site:example.com inurl:backup
site:example.com (inurl:backup OR inurl:bak OR inurl:old)

# Email address harvesting
intext:"@example.com" inurl:example.com

# Directory listing
site:example.com intitle:"index of"
intitle:"index of" inurl:example.com

# Sensitive strings in pages
site:example.com "internal use only"
site:example.com "confidential"
site:example.com intext:"DB_PASSWORD"
site:example.com intext:"api_key"

# Cloud storage
site:s3.amazonaws.com "companyname"
site:blob.core.windows.net "companyname"
site:storage.googleapis.com "companyname"
```

> Full dork database: **Google Hacking Database (GHDB)** — https://www.exploit-db.com/google-hacking-database

---

## Web Fingerprinting

Passive fingerprinting only — no active scanning of the target.

### Header Analysis

```bash
# Fetch HTTP headers only (no body)
curl -I http://example.com
curl -I https://example.com

# Follow each redirect to capture all headers in the chain
curl -I http://example.com           # may reveal redirect
curl -I https://example.com          # may expose CMS (X-Redirect-By: WordPress)
curl -I https://www.example.com      # final destination headers
```

**Headers to look for:**

| Header | What It Reveals |
|---|---|
| `Server:` | Web server software + version (e.g. `Apache/2.4.41 (Ubuntu)`) |
| `X-Powered-By:` | Backend tech (PHP version, ASP.NET, etc.) |
| `X-Redirect-By:` | CMS handling redirect (e.g. `WordPress`) |
| `Link:` | API endpoints, CMS paths (e.g. `/wp-json/`) |
| `Set-Cookie:` | Session framework clues (`PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId`) |
| `X-Generator:` | CMS or framework name |
| `Strict-Transport-Security:` | Absence = missing HSTS (misconfiguration) |

### Passive Tech Fingerprinting Tools

| Tool | How to Use |
|---|---|
| Wappalyzer | Browser extension — passive tech stack detection while browsing |
| BuiltWith | https://builtwith.com — detailed tech stack reports |
| Netcraft | https://sitereport.netcraft.com — hosting, tech, security posture |

---

## robots.txt & Well-Known URIs

```bash
# Disallowed paths often point to admin panels, private dirs, backup locations
curl https://example.com/robots.txt

# Security contact info for the organization
curl https://example.com/.well-known/security.txt

# OpenID Connect configuration → reveals auth/OAuth endpoints
curl https://example.com/.well-known/openid-configuration

# Standard password reset URL endpoint
curl https://example.com/.well-known/change-password

# Email MTA-STS policy
curl https://example.com/.well-known/mta-sts.txt
```

**robots.txt — what to look for:**

| Directive | Meaning |
|---|---|
| `Disallow: /admin/` | Admin panel exists at this path |
| `Disallow: /private/` | Private content — investigate |
| `Disallow: /backup/` | Backup files potentially accessible |
| `Sitemap:` | Full site structure URL |
| Honeypot paths | Reveals defensive awareness |

**openid-configuration — key fields:**

| Field | What It Gives You |
|---|---|
| `authorization_endpoint` | OAuth login URL |
| `token_endpoint` | Where tokens are issued |
| `userinfo_endpoint` | User data retrieval endpoint |
| `jwks_uri` | Cryptographic keys in use |
| `scopes_supported` | Available OAuth permission scopes |

---

## Web Archives

```bash
# Browse historical snapshots manually
# https://web.archive.org/web/*/example.com

# Pull all historical URLs with waybackurls (Go tool)
go install github.com/tomnomnom/waybackurls@latest
waybackurls example.com | tee wayback-urls.txt
```

**What to look for in archives:**
- Old admin panels or endpoints removed from the current site
- Historical configuration files or exposed credentials
- Past directory structures revealing hidden paths
- Software version info from outdated pages
- Infrastructure changes — when new subdomains appeared
- Previous breach disclosures or incident notices

---

## Cloud Resources

```bash
# Check which subdomains resolve to cloud provider infrastructure
for i in $(cat subdomainlist); do
  host $i | grep "has address" | grep example.com | cut -d" " -f1,4
done
# Look for: s3-website-us-west-2.amazonaws.com, blob.core.windows.net, etc.

# Google Dorks for open cloud buckets
# inurl:s3.amazonaws.com "companyname"
# site:blob.core.windows.net "companyname"
# site:storage.googleapis.com "companyname"
```

| Resource | Purpose |
|---|---|
| GrayHatWarfare | https://buckets.grayhatwarfare.com — find open S3/Azure/GCP buckets |
| domain.glass | https://domain.glass — infrastructure overview + Cloudflare classification |
| Shodan | https://shodan.io — internet-connected device search |

**Bucket naming patterns to check:**
`companyname`, `company-backup`, `company-dev`, `company-prod`, `company-data`, `COMP` (abbreviation), `company-assets`, `company-logs`

---

## Social Media & Staff OSINT

| Platform | What to Look For |
|---|---|
| LinkedIn | Job postings (tech stack clues), employee profiles, org structure |
| GitHub / GitLab | Leaked creds, API keys, hardcoded tokens, internal paths in commits |
| Twitter / X | Tech discussions, tool mentions, outage or incident responses |
| Job boards (Indeed, Glassdoor) | Software/DB/framework versions in job descriptions |
| Company website | Staff emails, org charts, embedded documents, intranet links |

```bash
# Harvest LinkedIn usernames → generate username wordlist
# https://github.com/initstring/linkedin2username
python3 linkedin2username.py -u <your_linkedin_user> -c <company_name>
# Output formats: flast, first.last, f.last, firstl, etc.

# Search GitHub for company domain references
# https://github.com/search?q=example.com&type=code

# TruffleHog — scan repos for secrets (API keys, tokens, passwords)
trufflehog github --repo https://github.com/example/repo

# theHarvester — OSINT aggregation from multiple sources
theHarvester -d example.com -b all
theHarvester -d example.com -b linkedin,google,bing
```

**Job posting intel — look for:**
- Programming languages and web frameworks (Flask, Django, Spring, .NET)
- Database technologies (MSSQL, PostgreSQL, Oracle, MongoDB)
- Specific software versions ("SharePoint 2013/2016 experience required")
- Security tools in use → know what defenses to expect (SIEM, EDR, IDS/IPS names)

---

## Breach / Credential Data

```bash
# HaveIBeenPwned — check corporate email domains in breach data
# https://haveibeenpwned.com

# Dehashed — search for cleartext passwords / hashes by domain
# https://dehashed.com
sudo python3 dehashed.py -q example.com -p

# Example output:
#   email    : roger.grimes@example.local
#   username : rgrimes
#   password : Ilovefishing!
#   database : ModBSolutions
```

**Test found credentials against exposed portals:**

| Portal Type | Examples |
|---|---|
| Remote access | Citrix, RDS, VPN endpoints, VMware Horizon |
| Email | Outlook Web Access (OWA), Office 365 |
| Cloud | Azure Portal, AWS Console |
| Custom | Any AD-authenticated web app |

---

## Automated Passive Recon

```bash
# FinalRecon — all-in-one passive recon framework
git clone https://github.com/thewhiteh4t/FinalRecon.git
cd FinalRecon
pip3 install -r requirements.txt
chmod +x ./finalrecon.py

# Headers + WHOIS
./finalrecon.py --headers --whois --url http://example.com

# SSL certificate info
./finalrecon.py --sslinfo --url https://example.com

# DNS enumeration (40+ record types including DMARC)
./finalrecon.py --dns --url http://example.com

# Subdomain enumeration (crt.sh, VirusTotal, Shodan, BeVigil, etc.)
./finalrecon.py --sub --url http://example.com

# Web crawling (internal/external links, JS files, robots.txt, Wayback)
./finalrecon.py --crawl --url http://example.com

# Wayback Machine — last 5 years of URLs
./finalrecon.py --wayback --url http://example.com

# Full recon (all modules)
./finalrecon.py --full --url http://example.com
```

---

## DNS Record Types Reference

| Record | Full Name | Purpose | Example |
|---|---|---|---|
| `A` | Address Record | Hostname → IPv4 | `www.example.com. IN A 192.0.2.1` |
| `AAAA` | IPv6 Address Record | Hostname → IPv6 | `www.example.com. IN AAAA 2001:db8::1` |
| `CNAME` | Canonical Name | Alias → hostname | `blog.example.com. IN CNAME webserver.example.net.` |
| `MX` | Mail Exchange | Mail server for domain | `example.com. IN MX 10 mail.example.com.` |
| `NS` | Name Server | Authoritative nameserver | `example.com. IN NS ns1.example.com.` |
| `TXT` | Text Record | SPF, DKIM, third-party verification | `example.com. IN TXT "v=spf1 mx -all"` |
| `SOA` | Start of Authority | Zone admin info | Primary NS, serial number, refresh/retry/expire |
| `SRV` | Service Record | Hostname + port for a service | `_sip._udp.example.com. IN SRV 10 5 5060 sip.example.com.` |
| `PTR` | Pointer Record | IP → hostname (reverse DNS) | `1.2.0.192.in-addr.arpa. IN PTR www.example.com.` |

---

*Passive recon only — no direct target interaction.*  
*Feed findings into the Active Recon phase.*
