<h1 align="center">
  <br>
  <a href="https://github.com/aashay4123/bug_hunter"><img src="https://github.com/aashay4123/bug_hunter/blob/master/tools/resources/bunny.jpg" alt="bug_hunter"></a>
  <br>
  Bunny
  <br>
</h1>

<h3 align="center">Summary</h3>
 
**Bunny** automates the entire process of reconnaisance for you. It outperforms the work of subdomain enumeration along with various vulnerability checks and obtaining maximum information about your target.       
 
Bunny uses lot of techniques (passive, bruteforce, permutations, certificate transparency, source code scraping, analytics, DNS records...) for subdomain enumeration which helps you getting the maximum and the most interesting subdomains so that you be ahead of the competition.   
  
It also performs various vulnerability checks like XSS, Open Redirects, SSRF, CRLF, LFI, SQLi, SSL tests, SSTI, DNS zone transfers, and much more. Along with these, it performs OSINT techniques, directory fuzzing, dorking, ports scanning, screenshots, nuclei scan on your target.
 
So, what are you waiting for Go! Go! Go! :boom:

## 📔 Table of Contents

- [💿 Installation:](#-installation)
- [Usage:](#usage)
- [Example Usage:](#example-usage)
- [Mindmap/Workflow](#mindmapworkflow)

---

# 💿 Installation:

```bash
git clone https://github.com/aashay4123/bug_hunter
cd bug_hunter/
./install.sh
./bunny.sh -d target.com -a

```

# Usage:

**TARGET OPTIONS**

| Flag | Description                              |
| ---- | ---------------------------------------- | ---- | ----- | --------- |
| -d   | Single Target domain _(example.com)_     |
| -l   | List of targets \*(one per line          | name | email | domain)\* |
| -n   | Single Target name                       |
| -e   | Single Target email                      |
| -x   | Exclude subdomains list _(Out Of Scope)_ |
| -i   | Include subdomains list _(In Scope)_     |

**MODE OPTIONS**

| Flag | Description                                                                   |
| ---- | ----------------------------------------------------------------------------- |
| -r   | Recon - Full recon process (without attacks like sqli,ssrf,xss,ssti,lfi etc.) |
| -a   | All - Perform osint, recon and all active attacks                             |
| -P   | OSINT - Performs an OSINT scan (no subdomain enumeration and attacks)         |
| -h   | Help - Show this help menu                                                    |

**GENERAL OPTIONS**

| Flag | Description                 |
| ---- | --------------------------- |
| -x   | exclude subdomain from file |
| -i   | include subdomain from file |
| -o   | Output directory            |
| -N   | turn off notification       |

# Example Usage:

**To perform a full recon on single target**

```bash
./reconftw.sh -d target.com -r
```

**To perform a full recon on a list of targets**

```bash
./reconftw.sh -l sites.txt -r -o /output/directory/
```

**Perform all steps (whole recon + all attacks)**

```bash
./reconftw.sh -d target.com -a
```

**Perform almost all steps (whole recon without subdomain discovery + all attacks)**

**_if http?:// exist scipt skips subdomain enumeration_**

```bash
./reconftw.sh -d http://target.com -a
```

**Perform OSINT for email Name Domains**

```bash
./reconftw.sh -l jumbled_content.txt -osint -o /output/directory/
```

# Bunny Features :

- Domain information parser ([domainbigdata](https://domainbigdata.com/))
- Emails addresses and users ([emailfinder](https://github.com/Josue87/EmailFinder))
- Metadata finder ([MetaFinder](https://github.com/Josue87/MetaFinder))
- Google Dorks ([degoogle_hunter](https://github.com/six2dez/degoogle_hunter))
- Github Dorks ([GitDorker](https://github.com/obheda12/GitDorker))
- Multiple subdomain enumeration techniques (passive, bruteforce, permutations, DNS records, scraping)
  - Passive ([subfinder](https://github.com/projectdiscovery/subfinder), [assetfinder](https://github.com/tomnomnom/assetfinder), [amass](https://github.com/OWASP/Amass), [findomain](https://github.com/Findomain/Findomain), [crobat](https://github.com/cgboal/sonarsearch), [waybackurls](https://github.com/tomnomnom/waybackurls), [github-subdomains](https://github.com/gwen001/github-subdomains), [Anubis](https://jldc.me), [gauplus](https://github.com/bp0lr/gauplus) and [mildew](https://github.com/daehee/mildew))
  - Certificate transparency ([ctfr](https://github.com/UnaPibaGeek/ctfr), [tls.bufferover](tls.bufferover.run) and [dns.bufferover](dns.bufferover.run)))
  - Bruteforce ([puredns](https://github.com/d3mondev/puredns))
  - Permutations ([DNScewl](https://github.com/codingo/DNSCewl))
  - JS files & Source Code Scraping ([gospider](https://github.com/jaeles-project/gospider), [analyticsRelationship](https://github.com/Josue87/analyticsRelationship))
  - DNS Records ([dnsx](https://github.com/projectdiscovery/dnsx))
- Nuclei Sub TKO templates ([nuclei](https://github.com/projectdiscovery/nuclei))
- Web Prober ([httpx](https://github.com/projectdiscovery/httpx) and [unimap](https://github.com/Edu4rdSHL/unimap))
- Web screenshot ([webscreenshot](https://github.com/maaaaz/webscreenshot))
- Web templates scanner ([nuclei](https://github.com/projectdiscovery/nuclei) and [nuclei geeknik](https://github.com/geeknik/the-nuclei-templates.git))
- IP and subdomains WAF checker ([cf-check](https://github.com/dwisiswant0/cf-check) and [wafw00f](https://github.com/EnableSecurity/wafw00f))
- Port Scanner (Active with [nmap](https://github.com/nmap/nmap) and passive with [shodan-cli](https://cli.shodan.io/), Subdomains IP resolution with[resolveDomains](https://github.com/Josue87/resolveDomains))
- Url extraction ([waybackurls](https://github.com/tomnomnom/waybackurls), [gauplus](https://github.com/bp0lr/gauplus), [gospider](https://github.com/jaeles-project/gospider), [github-endpoints](https://gist.github.com/six2dez/d1d516b606557526e9a78d7dd49cacd3) and [JSA](https://github.com/w9w/JSA))
- Pattern Search ([gf](https://github.com/tomnomnom/gf) and [gf-patterns](https://github.com/1ndianl33t/Gf-Patterns))
- Param discovery ([paramspider](https://github.com/devanshbatham/ParamSpider) and [arjun](https://github.com/s0md3v/Arjun))
- XSS ([dalfox](https://github.com/hahwul/dalfox))
- Open redirect ([Openredirex](https://github.com/devanshbatham/OpenRedireX))
- SSRF (headers [interactsh](https://github.com/projectdiscovery/interactsh) and param values with [ffuf](https://github.com/ffuf/ffuf))
- CRLF ([crlfuzz](https://github.com/dwisiswant0/crlfuzz))
- Favicon Real IP ([fav-up](https://github.com/pielco11/fav-up))
- Javascript analysis ([LinkFinder](https://github.com/GerbenJavado/LinkFinder), scripts from [JSFScan](https://github.com/KathanP19/JSFScan.sh))
- Fuzzing ([ffuf](https://github.com/ffuf/ffuf))
- Cors ([Corsy](https://github.com/s0md3v/Corsy))
- LFI Checks ([ffuf](https://github.com/ffuf/ffuf))
- SQLi Check ([SQLMap](https://github.com/sqlmapproject/sqlmap))
- SSTI ([ffuf](https://github.com/ffuf/ffuf))
- CMS Scanner ([CMSeeK](https://github.com/Tuhinshubhra/CMSeeK))
- SSL tests ([testssl](https://github.com/drwetter/testssl.sh))
- Multithread in some steps ([Interlace](https://github.com/codingo/Interlace))
- Broken Links Checker ([gospider](https://github.com/jaeles-project/gospider))
- S3 bucket finder ([S3Scanner](https://github.com/sa7mon/S3Scanner))
- Password spraying ([brutespray](https://github.com/x90skysn3k/brutespray))
- 4xx bypasser ([DirDar](https://github.com/M4DM0e/DirDar))
- Custom resolvers generated list ([dnsvalidator](https://github.com/vortexau/dnsvalidator))
- DNS Zone Transfer ([dnsrecon](https://github.com/darkoperator/dnsrecon))
- Docker container included and [DockerHub](https://hub.docker.com/r/six2dez/reconftw) integration
- Cloud providers check ([ip2provider](https://github.com/oldrho/ip2provider))
- URL sorting by extension
- Wordlist generation
- Allows IP/CIDR as target
- Resume the scan from last performed step
- Custom output folder option
- All in one installer/updater script compatible with most distros
- Diff support for continuous running (cron mode)
- Support for targets with multiple domains
- Raspberry Pi/ARM support
- Send scan results zipped over Slack, Discord and Telegram
- 6 modes (recon, passive, subdomains, web, osint and all)
- Out of Scope Support
- Notification support for Slack, Discord and Telegram ([notify](https://github.com/projectdiscovery/notify))

## Manual workflow

- Emails addresses and users ([theHarvester](https://github.com/techgaun/theHarvester))
- Password leaks ([pwndb](http://xjypo5vzgmo7jca6b322dnqbsdnp3amd24ybx26x5nxbusccjkm4pwid.onion/) and [H8mail](https://github.com/khast3x/h8mail))

# Mindmap/Workflow

![Mindmap](images/mindmap.png)

### Main commands:

- Upload changes to your personal repo: `git add . && git commit -m "Data upload" && git push origin master`
- Update tool anytime: `git fetch upstream && git rebase upstream/main master`

#### Install required tools

`chmod +x install.sh`

`./install.sh`

1. In the main directory you should have `/root` directory and `/usr/local/bin`
2. In the `/root` directory you must have `/go/bin` directory
3. In the tool's directory you will find `tools` directory after install tools_script

#### Running tool

`./bug_hunter.sh --domain avito.ru /opt/target/avito.ru -full`


## workflow

1. Collect all Acquisitions and ASN
2. Collect Live subdomains
3. Collect Live sub-subdomains
4. Spider & wayback subdomains
5. Extract JS files
6. Content Discovery
7. Port Scan
8. GitHub Secrets
9. GitHub dork links
10. Extract possible vulnerable links
11. Scan for Subdomain vulnerabilities Takeover & S3buckets
12. Scan Links for CVE's
13. Scan Security Headers
14. Scan Misconfiguration
15. Scan Vulnerabilities
16. Scan for website technologies and services

## Initial Setup

1. add credentials for CloudUnflare
2. add burpcollaborator for jaeles

