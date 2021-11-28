#!/bin/bash

# DEPENDENCIES:
# iceweasel or xdg-utils (apt-get install xdg-utils)


TARGET="$1"
BROWSER="firefox" # CHANGE TO DEFAULT BROWSER - FOR OSX, USE "open".
VER="1.9"
OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
OKORANGE='\033[93m'
DELAY=5
RESET='\e[0m'

  google_dorks(){
    if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] && [ "$GOOGLE_DORKS" = true ] && [ "$OSINT" = true ]; then
      start_func "Google Dorks in process"
      eval sed -i "s/^cookies=\"c_user=HEREYOUCOOKIE; xs=HEREYOUCOOKIE;\"/cookies=\"${UDORK_COOKIE}\"/" $TOOL_PATH/uDork/uDork.sh 2>>"$LOGFILE" &>/dev/null
      cd "$TOOL_PATH/uDork" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
      ./uDork.sh $DOMAIN -f $TOOL_PATH/custom_udork.txt -o $dir/osint/dorks.txt &> /dev/null
      [ -s "$dir/osint/dorks.txt" ] && sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" $dir/osint/dorks.txt 2>>"$LOGFILE" &>/dev/null
      cd "$dir" || { echo "Failed to cd to $dir in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
      end_func "Results are saved in $DOMAIN/osint/dorks.txt" ${FUNCNAME[0]}
    else
      if [ "$GOOGLE_DORKS" = false ] || [ "$OSINT" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} are already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }
# Google Dorks Cli
  https://github.com/adnane-X-tebbaa/GRecon
  https://github.com/six2dez/degoogle_hunter
  degoogle_hunter.sh company.com
  uDork.sh

if [ -z $TARGET ]; then
	echo -e "$OKORANGE + -- --=[Usage: goohak <domain>$RESET"
	exit
fi

# LOAD WEBSITE IN A WEB BROSER
$BROWSER http://$TARGET 2> /dev/null
$BROWSER https://$TARGET 2> /dev/null
# TCPUTILS
$BROWSER http://www.tcpiputils.com/browse/domain/$TARGET 2> /dev/null
# NETCRAFT
$BROWSER http://toolbar.netcraft.com/site_report?url=$TARGET 2> /dev/null
# SHOWDAN
$BROWSER https://www.shodan.io/search?query=$TARGET 2> /dev/null
# CENSYS
$BROWSER https://www.censys.io/ipv4?q=$TARGET 2> /dev/null
# CRT.SH
$BROWSER https://crt.sh/?q=%25.$TARGET 2> /dev/null
# ZONE-H
$BROWSER "https://www.google.ca/search?q=site:zone-h.org+$TARGET" 2> /dev/null
# XSSPOSED
$BROWSER "https://www.xssposed.org/search/?search=$TARGET&type=host" 2> /dev/null
# SECURITYHEADERS
$BROWSER "https://securityheaders.io/?q=$TARGET" 2> /dev/null
# SSLLABS
$BROWSER https://www.ssllabs.com/ssltest/analyze.html?d=$TARGET 2> /dev/null
# HEADER CHECK
$BROWSER https://securityheaders.io/?q=$TARGET 2> /dev/null
# THREATCROWD
$BROWSER https://www.threatcrowd.org/domain.php?domain=$TARGET 2> /dev/null
# ZOOMEYE
$BROWSER https://www.zoomeye.org/searchResult/bugs?q=$TARGET 2> /dev/null
# DOMAIN INFO SEARCH
$BROWSER https://securitytrails.com/search/domain/$TARGET 2> /dev/null
# WAYBACKMACHINE
$BROWSER https://web.archive.org/web/*/$TARGET 2> /dev/null
# REVERSEDNS
$BROWSER http://viewdns.info/reversewhois/?q=$TARGET 2> /dev/null
# PUNKSPIDER
$BROWSER "https://www.punkspider.org/#searchkey=url&searchvalue=$TARGET&pagenumber=1&filterType=or" 2> /dev/null

sleep $DELAY
# FIND SUBDOMAINS
$BROWSER "https://www.google.ca/search?q=site:*.$TARGET" 2> /dev/null
$BROWSER "https://www.google.ca/search?q=site:*.*.$TARGET" 2> /dev/null

sleep $DELAY
# FIND LOGIN PAGES:
$BROWSER "https://www.google.ca/search?q=site:$TARGET+username+OR+password+OR+login+OR+root+OR+admin" 2> /dev/null
# SEARCH FOR BACKDOORS:
$BROWSER "https://www.google.ca/search?q=site:$TARGET+inurl:shell+OR+inurl:backdoor+OR+inurl:wso+OR+inurl:cmd+OR+shadow+OR+passwd+OR+boot.ini+OR+inurl:backdoor" 2> /dev/null
# FIND SETUP OR INSTALL FILES:
$BROWSER "https://www.google.ca/search?q=site:$TARGET+inurl:readme+OR+inurl:license+OR+inurl:install+OR+inurl:setup+OR+inurl:config" 2> /dev/null
# FIND WORDPRESS PLUGINS/UPLOADS/DOWNLOADS:
$BROWSER "https://www.google.ca/search?q=site:$TARGET+inurl:wp-+OR+inurl:plugin+OR+inurl:upload+OR+inurl:download" 2> /dev/null
# FIND OPEN REDIRECTS:
$BROWSER "https://www.google.ca/search?q=site:$TARGET+inurl:redir+OR+inurl:url+OR+inurl:redirect+OR+inurl:return+OR+inurl:src=http+OR+inurl:r=http" 2> /dev/null

sleep $DELAY
# FIND FILES BY EXTENSION:
$BROWSER "https://www.google.ca/search?q=site:$TARGET+ext:cgi+OR+ext:php+OR+ext:asp+OR+ext:aspx+OR+ext:jsp+OR+ext:jspx+OR+ext:swf+OR+ext:fla+OR+ext:xml" 2> /dev/null
# FIND DOCUMENTS BY EXTENSION:
$BROWSER "https://www.google.ca/search?q=site:$TARGET+ext:doc+OR+ext:docx+OR+ext:csv+OR+ext:pdf+OR+ext:txt+OR+ext:log+OR+ext:bak" 2> /dev/null
# FIND APACHE STRUTS RCE's:
$BROWSER "https://www.google.ca/search?q=site:$TARGET+ext:action+OR+struts" 2> /dev/null
# FIND PASTEBIN POSTS FOR DOMAIN:
$BROWSER "https://www.google.ca/search?q=site:pastebin.com+$TARGET" 2> /dev/null
# FIND EMPLOYEES ON LINKEDIN:
$BROWSER "https://www.google.ca/search?q=site:linkedin.com+employees+$TARGET" 2> /dev/null


```
Integrate me Fast

# Code share sites
site:http://ideone.com | site:http://codebeautify.org | site:http://codeshare.io | site:http://codepen.io | site:http://repl.it | site:http://jsfiddle.net "company"
# GitLab/GitHub/Bitbucket
site:github.com | site:gitlab.com | site:bitbucket.org "company"
# Stackoverflow
site:stackoverflow.com "target.com"
# Project management sites
site:http://trello.com | site:*.atlassian.net "company"
# Pastebin-like sites
site:http://justpaste.it | site:http://pastebin.com "company"
# Config files
site:target.com ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:env | ext:ini
# Database files
site:target.com ext:sql | ext:dbf | ext:mdb
# Backup files
site:target.com ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup
# .git folder
inurl:"/.git" target.com -github
# Exposed documents
site:target.com ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv
# Other files
site:target.com intitle:index.of | ext:log | ext:php intitle:phpinfo "published by the PHP Group" | inurl:shell | inurl:backdoor | inurl:wso | inurl:cmd | shadow | passwd | boot.ini | inurl:backdoor | inurl:readme | inurl:license | inurl:install | inurl:setup | inurl:config | inurl:"/phpinfo.php" | inurl:".htaccess" | ext:swf
# SQL errors
site:target.com intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()"
# PHP errors
site:target.com "PHP Parse error" | "PHP Warning" | "PHP Error"
# Login pages
site:target.com inurl:signup | inurl:register | intitle:Signup
# Open redirects
site:target.com inurl:redir | inurl:url | inurl:redirect | inurl:return | inurl:src=http | inurl:r=http
# Apache Struts RCE
site:target.com ext:action | ext:struts | ext:do
# Search in pastebin
site:pastebin.com target.com
# Linkedin employees
site:linkedin.com employees target.com
# Wordpress files
site:target.com inurl:wp-content | inurl:wp-includes
# Subdomains
site:*.target.com
# Sub-subdomains
site:*.*.target.com
#Find S3 Buckets
site:.s3.amazonaws.com | site:http://storage.googleapis.com | site:http://amazonaws.com "target"
# Traefik
intitle:traefik inurl:8080/dashboard "target"
# Jenkins
intitle:"Dashboard [Jenkins]"
  site:<Third Party Vendor> <Company Name>
  site:pastebin.com “Company Name”
  site:*.atlassian.net “Company Name”
  site:bitbucket.org “Company Name”
  Inurl:gitlab “Company Name”

```
