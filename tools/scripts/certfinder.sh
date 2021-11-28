
 #!/bin/bash

if [ ! -x "$(command -v jq)" ]; then
	echo "[-] This script requires jq. Exiting."
	exit 1
fi


curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$1/passive_dns"|jq '.passive_dns[].hostname' 2>/dev/null |grep -o "\w.*$1"|sort -u >> tcert
echo "[+] Alienvault(otx) Over => $(wc -l tcert )"
curl -s "https://urlscan.io/api/v1/search/?q=domain:$1"|jq '.results[].page.domain' 2>/dev/null |grep -o "\w.*$1"|sort -u >> tcert
echo "[+] Entrust.com Over => $(wc -l tcert )"
curl -s "https://api.threatminer.org/v2/domain.php?q=$1&rt=5" | jq -r '.results[]' 2>/dev/null |grep -o "\w.*$1"|sort -u >> tcert
echo "[+] Threatminer Over => $(wc -l tcert )"
curl -s "https://riddler.io/search/exportcsv?q=pld:$1" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" >> tcert
echo "[+] Riddler.io Over => $(wc -l tcert )"
curl -s "https://certspotter.com/api/v0/certs?domain=$1" | jq -r '.[].dns_names[]' 2>/dev/null | grep -o "\w.*$1" | sort -u >> tcert			
curl -s "https://crt.sh/?q=$1&output=json" | jq . | grep 'name_value' | awk '{print $2}' | sed -e 's/"//g'| sed -e 's/,//g' |  awk '{gsub(/\\n/,"\n")}1' | grep -iv '*' |grep -iv '@' | grep -iv '\--'|sort -u >> tcert 
echo "[+] Cert data => $(wc -l tcert )"
curl -s "https://dns.bufferover.run/dns?q=.$1" | jq '.FDNS_A[]' | sed 's/^\".*.,//g' | sed 's/\"$//g'  >> tcert
curl -s "https://dns.bufferover.run/dns?q=.$1" | jq -r .RDNS[] 2>/dev/null | cut -d ',' -f2 | grep -o "\w.*$1" >> tcert
curl -s "https://tls.bufferover.run/dns?q=.$1" | jq -r .Results 2>/dev/null | cut -d ',' -f3 |grep -o "\w.*$1"| sort -u >> tcert
echo "[+] bufferover data => $(wc -l tcert )"
curl -s "https://rapiddns.io/subdomain/$1#result" | grep "<td><a" | cut -d '"' -f 2 | grep http | cut -d '/' -f3 | sed 's/#results//g' >> tcert
echo "[+] rapiddns data => $(wc -l tcert )"
curl -s "http://web.archive.org/cdx/search/cdx?url=*.$1/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" |sort -u >> tcert
echo "[+] web archive data => $(wc -l tcert )"
curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$1" |jq .subdomains |grep -o \w.*$1 |sort -u >> tcert
echo "[+] threatcrowd data => $(wc -l tcert )"
curl -s "https://api.hackertarget.com/hostsearch/?q=$1" | grep -o \w.*$1 |sort -u  >> tcert
echo "[+] hackertarget data => $(wc -l tcert )"

curl -s "https://subbuster.cyberxplore.com/api/find?domain=$1" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u >> tcert
echo "[+] cyberxplore data => $(wc -l tcert )"
curl -s "https://jldc.me/anubis/subdomains/$1" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u  >> tcert
echo "[+] jldc anubis data => $(wc -l tcert )"
curl --silent https://sonar.omnisint.io/subdomains/$1 | grep -oE "[a-zA-Z0-9._-]+\.$1" | sort -u >> tcert
echo "[+] sonar data => $(wc -l tcert )"
curl --silent -X POST https://synapsint.com/report.php -d "name=https%3A%2F%$1" | grep -oE "[a-zA-Z0-9._-]+\.$1" | sort -u >> tcert
echo "[+] synapsint data => $(wc -l tcert )"


cmdtoken=$(curl -ILs https://dnsdumpster.com | grep csrftoken | cut -d " " -f2 | cut -d "=" -f2 | tr -d ";")
curl -s --header "Host:dnsdumpster.com" --referer https://dnsdumpster.com --user-agent "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" --data "csrfmiddlewaretoken=$cmdtoken&targetip=$1" --cookie "csrftoken=$cmdtoken; _ga=GA1.2.1737013576.1458811829; _gat=1" https://dnsdumpster.com > dnsdumpster.html
cat dnsdumpster.html|grep "https://api.hackertarget.com/httpheaders"|grep -o "\w.*$1"|cut -d "/" -f7|sort -u >> tcert
rm dnsdumpster.html
echo "[+] Dnsdumpster Over => $(wc -l tcert )"
cat tcert  | sort -u >> $2
rm tcert


