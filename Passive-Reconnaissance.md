# 🟢 Passive Reconnaissance Cheat Sheet
> No direct interaction with the target — public sources only.
> *HTB Penetration Tester Job Role Path | 🔗 [github.com/0xB0oMa](https://github.com/0xB0oMa)*

---

## ⚙️ Set Variables
```bash
TARGET="example.com"
TARGET_IP="10.10.10.10"
OUTPUT_DIR="./recon-$TARGET"
mkdir -p $OUTPUT_DIR
```

---

## 1. WHOIS
```bash
whois $TARGET
```

**What to look for:**
| Field | Why It Matters |
|-------|----------------|
| Registration Date | Recent = suspicious |
| Registrant | Hidden = privacy protection |
| Name Servers | Reveals hosting provider |
| Domain Status | Protected domain indicators |

---

## 2. ASN / IP Space
```bash
# BGP Toolkit — ASN, netblocks, IP ranges
# https://bgp.he.net

# Validate IP
# https://viewdns.info

# Nameservers lookup
nslookup ns1.$TARGET
nslookup ns2.$TARGET
```

**What to look for:**
- Valid ASN + netblocks in scope
- Hosting provider (AWS, Azure, Cloudflare...)
- Mail servers, nameservers
- Self-hosted vs 3rd party infrastructure

---

## 3. DNS Records
```bash
dig $TARGET
dig $TARGET A        # IPv4
dig $TARGET AAAA     # IPv6
dig $TARGET MX       # Mail servers
dig $TARGET NS       # Name servers
dig $TARGET TXT      # SPF, DMARC, third-party keys
dig $TARGET SOA      # Zone authority
dig $TARGET CNAME    # Aliases
dig +short $TARGET
dig +trace $TARGET
dig -x $TARGET_IP    # Reverse lookup
```

**TXT Records — what they reveal:**
```
MS=ms92346782        → Microsoft/O365 tenant
atlassian-domain     → Uses Jira/Confluence
google-site-verif    → Uses Google Workspace
logmein-verif        → Remote access platform
v=spf1 include:mailgun.org → Uses Mailgun API
```

---

## 4. Zone Transfer
```bash
# Attempt zone transfer
dig axfr @$(dig $TARGET NS +short | head -1) $TARGET

# fierce
fierce --domain $TARGET
```

> ⚠️ If successful = Critical misconfiguration → reveals ALL subdomains + IPs

---

## 5. Subdomain Enumeration
```bash
# HackerTarget
curl -s "https://api.hackertarget.com/hostsearch/?q=$TARGET" \
  | cut -d, -f1 | tee $OUTPUT_DIR/subdomainlist

# Certificate Transparency (crt.sh)
curl -s "https://crt.sh/?q=$TARGET&output=json" \
  | jq -r '.[].name_value' | tr '\n' ',' | tr ',' '\n' \
  | sed 's/\*\.//g' | grep -E "\.$TARGET$" \
  | sort -u | anew $OUTPUT_DIR/subdomainlist

# Shodan
shodan search "ssl.cert.subject.CN:\"$TARGET\"" \
  --fields hostnames | tr ';' '\n' \
  | grep -E "\.$TARGET(\.|$)" \
  | anew $OUTPUT_DIR/subdomainlist

# Subfinder
subfinder -d $TARGET | anew $OUTPUT_DIR/subdomainlist

# PureDNS
puredns bruteforce ~/SecLists/Discovery/DNS/subdomains-top1million-110000.txt $TARGET \
  | anew $OUTPUT_DIR/subdomainlist
```

**Online Sources:**
- [crt.sh](https://crt.sh) — Certificate Transparency logs
- [censys.io](https://search.censys.io) — Advanced filtering
- [dnsdumpster.com](https://dnsdumpster.com) — DNS map
- [shodan.io](https://shodan.io) — Internet-connected devices

---

## 6. Cloud Resources Discovery
```bash
# Resolve subdomains → identify cloud providers
for i in $(cat $OUTPUT_DIR/subdomainlist); do
  host $i | grep "has address" | grep $TARGET \
  | cut -d" " -f1,4
done

# Google Dorks
# intext:company_name inurl:amazonaws.com
# intext:company_name inurl:blob.core.windows.net

# Online
# https://buckets.grayhatwarfare.com
# https://domain.glass
```

---

## 7. OSINT — Staff & Social Media
```bash
# LinkedIn username harvesting
linkedin2username -c COMPANY_NAME

# Email format discovery
# https://hunter.io
# https://phonebook.cz

# Email dork
intext:"@$TARGET" inurl:$TARGET

# Document hunting
filetype:pdf inurl:$TARGET
filetype:docx inurl:$TARGET
filetype:xlsx inurl:$TARGET

# GitHub leaked secrets
trufflehog https://github.com/TARGET/repo
site:github.com "$TARGET" password
site:github.com "$TARGET" api_key
site:github.com "$TARGET" secret
```

**What to look for:**
```
✅ Email naming convention (first.last, f.last...)
✅ Employee roles → tech stack
✅ Job postings → frameworks, databases, security tools
✅ Embedded docs → intranet links, internal paths
✅ GitHub repos → leaked credentials, JWT tokens
```

---

## 8. Breach Data
```bash
# Check breached emails
# https://haveibeenpwned.com

# Search cleartext credentials
# https://dehashed.com
sudo python3 dehashed.py -q $TARGET -p
```

> 💡 Found credentials → try on: OWA, VPN, Citrix, RDS, O365, VMware Horizon

---

## 9. Web Archives
```bash
# Wayback Machine
# https://web.archive.org/web/*/$TARGET

# robots.txt
curl -s https://$TARGET/robots.txt

# sitemap.xml
curl -s https://$TARGET/sitemap.xml

# .well-known
curl -s https://$TARGET/.well-known/security.txt
curl -s https://$TARGET/.well-known/openid-configuration
```

---

## 10. Google Dorks

### Login Pages
```
site:example.com (inurl:login OR intitle:login)
site:example.com (inurl:signin OR intitle:"sign in")
site:example.com (inurl:logon OR intitle:logon)
site:example.com (inurl:auth OR intitle:authentication)
site:example.com (inurl:account/login OR intitle:account)
site:example.com (inurl:user/login OR intitle:user)
site:example.com (inurl:session/login OR intitle:session)
```

### Admin Panels
```
site:example.com (inurl:admin OR intitle:admin)
site:example.com (inurl:administrator OR intitle:administrator)
site:example.com (inurl:admin/login OR intitle:"admin login")
site:example.com (inurl:dashboard OR intitle:dashboard)
site:example.com (inurl:controlpanel OR intitle:"control panel")
```

### Cpanels / Hosting Panels
```
site:example.com (inurl:cpanel OR intitle:cpanel)
site:example.com (inurl:whm OR intitle:whm)
site:example.com (inurl:webmail OR intitle:webmail)
site:example.com (inurl:2082 OR inurl:2083)
site:example.com (inurl:2086 OR inurl:2087)
```

### Config Files
```
site:example.com (filetype:env OR inurl:.env)
site:example.com (filetype:cfg OR inurl:.cfg)
site:example.com (filetype:config OR inurl:.config)
site:example.com (filetype:conf OR inurl:.conf)
site:example.com (filetype:ini OR inurl:.ini)
site:example.com (filetype:json OR inurl:.json)
site:example.com (filetype:yaml OR inurl:.yaml)
site:example.com (filetype:yml OR inurl:.yml)
site:example.com (filetype:xml OR inurl:.xml)
```

### Backup Files
```
site:example.com (filetype:bak OR inurl:.bak)
site:example.com (filetype:backup OR inurl:.backup)
site:example.com (filetype:zip OR inurl:.zip)
site:example.com (filetype:tar OR inurl:.tar)
site:example.com (filetype:gz OR inurl:.gz)
site:example.com (filetype:7z OR inurl:.7z)
site:example.com (filetype:rar OR inurl:.rar)
site:example.com (filetype:xlsx OR inurl:.xlsx)
site:example.com (filetype:pptx OR inurl:.pptx)
```

### Database Files
```
site:example.com (filetype:sql OR inurl:.sql)
site:example.com (filetype:db OR inurl:.db)
site:example.com (filetype:sqlite OR inurl:.sqlite)
site:example.com (filetype:csv OR inurl:.csv)
site:example.com (filetype:mdb OR inurl:.mdb)
site:example.com (filetype:accdb OR inurl:.accdb)
```

---

## ✅ Passive Recon Checklist
- [ ] WHOIS lookup
- [ ] ASN / IP space (bgp.he.net, viewdns.info)
- [ ] DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME)
- [ ] Zone Transfer attempt
- [ ] Subdomain enum (crt.sh, subfinder, shodan, hackertarget, puredns)
- [ ] Cloud storage discovery (GrayHatWarfare, Google Dorks)
- [ ] OSINT staff (LinkedIn, GitHub, job postings)
- [ ] Breach data (HaveIBeenPwned, Dehashed)
- [ ] Web Archives (Wayback Machine)
- [ ] robots.txt + sitemap.xml + .well-known
- [ ] Google Dorks (login, admin, config, backup, database)
