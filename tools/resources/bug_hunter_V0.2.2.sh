#!/bin/bash

VERSION="1.0"

PROJECT=""
TARGET=""

NOW=$(date +'%Y-%m-%d_%H-%M-%S')
TOOLS_DIR="$HOME/tools"

RED="\033[1;31m"
GREEN="\033[1;32m"
BLUE="\033[1;36m"
YELLOW="\033[1;33m"
RESET="\033[0m"

DOMAINS_FILE="domains-$NOW.txt"
FINAL_DOMAINS="final-domains.txt"

# set tool path
set_tool_paths() {
		# If tool paths have not been set, set them
		if [[ "$TOOL_PATH_SET" -eq 0 ]]; then
				TOOL_PATH_SET=1;
				SUBFINDER=$(which subfinder);
				SUBJACK=$(which subjack);
				FFUF=$(which ffuf);
				WHATWEB=$(which whatweb);
				WAFW00F=$(which wafw00f);
				GOBUSTER=$(which gobuster);
				CHROMIUM=$(which chromium);
				NMAP=$(which nmap);
				MASSCAN=$(which masscan);
				NIKTO=$(which nikto);
				INCEPTION=$(which inception);
				WAYBACKURLS=$(which waybackurls);
				GOALTDNS=$(which goaltdns);
				RESCOPE=$(which rescope);
				KNOCK=$(which knockpy);
				HTTPROBE=$(which httprobe);
				SUBLIST3R=$TOOL_PATH/Sublist3r/sublist3r.py;
				DNSCAN=$TOOL_PATH/dnscan/dnscan.py;
				MASSDNS_BIN=$TOOL_PATH/massdns/bin/massdns;
				MASSDNS_RESOLVERS=resolvers.txt;
				AQUATONE=$TOOL_PATH/aquatone/aquatone;
				BFAC=$TOOL_PATH/bfac/bfac;
				DIRSEARCH=$TOOL_PATH/dirsearch/dirsearch.py;
				SNALLY=$TOOL_PATH/snallygaster/snallygaster;
				CORSTEST=$TOOL_PATH/CORStest/corstest.py;
				S3SCANNER=$TOOL_PATH/S3Scanner/s3scanner.py;
				AMASS=$TOOL_PATH/amass/amass;
		else
				return;
		fi
}
# Check that a file path exists and is not empty
exists() {
		if [[ -e "$1" ]]; then
				if [[ -s "$1" ]]; then
						return 1;
				else
						return 0;
				fi
		else
				return 0;
		fi
}
check_paths() {
		# Check if paths haven't been set and set them
		set_tool_paths;

		# Check that all paths are set
		if [[ "$SUBFINDER" == "" ]] || [[ ! -f "$SUBFINDER" ]]; then
				echo -e "$RED""[!] The path or the file specified by the path for subfinder does not exit.";
				exit 1;
		fi
		if [[ "$SUBLIST3R" == "" ]] || [[ ! -f "$SUBLIST3R" ]]; then
				grep 'Kali' /etc/issue 1>/dev/null; 
				KALI=$?;
				if [[ "$KALI" -eq 0 ]]; then
						SUBLIST3R=$(command -v sublist3r);
				else
						echo -e "$RED""[!] The path or the file specified by the path for sublist3r does not exit.";
						exit 1;
				fi
		fi
}
runBanner(){
    name=$1
    echo -e "${GREEN}\n[+] Running $name...${RESET}"
}

subdomainDiscovery() {
    runBanner "Subdomain Discovery Passively"
    mkdir $DOMAIN 
    cd $DOMAIN
    python2 domain_analyzer.py -d $DOMAIN -o -e
    cd ..
    /opt/tools/spoofcheck/./spoofcheck.py $DOMAIN >> attack/spoofcheck
    amass enum -passive -norecursive -noalts -config ../amass/config.ini -d $DOMAIN -o tmp.txt
    subfinder -d $DOMAIN -silent >> tmp.txt
    assetfinder --subs-only $DOMAIN  >> tmp.txt
    findomain -t $DOMAIN -c ../amass/bin/config.json --quiet >> tmp.txt
    echo "amass data $(cat tmp.txt|sort -u | wc -l)"  
    python /opt/bug_hunter/tools/github-subdomains.py -t 6c5ed8ab7b7c4b9232fcaea5c051b8977a624012 -d $DOMAIN >> tmp.txt
    /opt/bug_hunter/tools/./certfinder.sh $DOMAIN tmp.txt 
    echo "cert data $(cat tmp.txt | sort -u |wc -l)"
    shuffledns -d $DOMAIN -w ../../wordlist/top_subdomains.txt -r ../../wordlist/resolvers.txt -list tmp.txt -silent | sort -u |grep ".$DOMAIN"  >> $DOMAIN/subdomains.txt 
    echo "shuffledns data $(cat $DOMAIN/subdomains.txt | wc -l)"

  # Collect Live subdomains
    mkdir $DOMAIN/subdomain  
    cat $DOMAIN/subdomains.txt | httpx -silent -threads 200 -status-code -ip -follow-redirects > all.txt
    cat subdomains.txt | httpx -threads 200 -status-code -ports 3000 ,8443 ,8443 ,8080 ,8080 ,8008 ,8008 ,591 ,591 ,593 ,593 ,981 ,981 ,2480 ,2480 ,4567 ,4567 ,5000 ,5000 ,5800 ,5800 ,7001 ,7001 ,7002 ,7002 ,9080 ,9080 ,9090 ,9090 ,9443 ,18091 ,18092 | awk '{print $1}' > $DOMAIN/subdomain/3xxsub.txt
    cat all.txt | sort -u | grep 2m20[0-9] | awk '{print $1}' > $DOMAIN/subdomain/200sub.txt 
    cat all.txt | sort -u | grep 1m40[1-3] | awk '{print $1}' > $DOMAIN/subdomain/401sub.txt 
    cat all.txt | sort -u | grep 3m5.. | awk '{print $1}' > $DOMAIN/subdomain/5xxsub.txt
    cat all.txt | sort -u | awk '{print $1}' > $DOMAIN/subdomain/allsubdmain
    # cat all.txt | sort -u | grep 3m3.. | awk '{print $1}' > $DOMAIN/subdomain/3xxsub.txt
    cat all.txt | sort -u | grep -v [1-3]m...| awk '{print $1}'  > $DOMAIN/subdomain/apisub.txt
    cat all.txt | awk '{print $1}' | sort -u | grep api >> $DOMAIN/subdomain/apisub.txt
}

contentDiscovery(){
    mkdir $DOMAIN/urls
    runBanner "Wayback urls"
    echo "$DOMAIN" | waybackurls >> wayback.txt
    runBanner "Gau urls"
    echo "$DOMAIN" | gau >> wayback.txt
    runBanner "github-endpoints urls"
    python3 /opt/bug_hunter/tools/github-endpoints.py -t 6c5ed8ab7b7c4b9232fcaea5c051b8977a624012 -d $DOMAIN  >> wayback.txt
    
    cat wayback.txt | sort -u > $DOMAIN/waybackurls.txt 
    cat all.txt | sort -u | awk '{print $1}' > tmp
    runBanner "gospider"
    gospider -S tmp -c 10 -d 1 -t 20 --other-source --sitemap > gospider.txt

    runBanner "url cleaning and sorting"
    cat gospider.txt |grep linkfinder\] | awk '{print $3}' | sort -u  >> $DOMAIN/waybackurls.txt
    cat gospider.txt |grep robots\] | awk '{print $3}' | sort -u >> $DOMAIN/waybackurls.txt
    cat gospider.txt |grep  sitemap\] | awk '{print $3}' | sort -u >> $DOMAIN/waybackurls.txt
    cat gospider.txt | grep "url\]" | grep "\[code-2"  | awk '{print $5}'  | egrep -vi ".(htm|zip|jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|xml|json|yaml|pdf|svg|txt|asp|net|js|php|html)" | sort -u >  $DOMAIN/urls/2xx.txt
    cat gospider.txt | grep "url\]" | grep "\[code-4" | grep -v "code-404" | awk '{print $5}' | sort -u >  $DOMAIN/urls/4xx.txt
    cat gospider.txt | grep "url\]" | grep "\[code-5" | awk '{print $5}' | sort -u >  $DOMAIN/urls/5xx.txt
    cat gospider.txt | grep "form\]" | sort -u >  $DOMAIN/urls/form	
    cat gospider.txt | grep "aws-s3\]" | sort -u | tee  $DOMAIN/urls/aws_s3
    cat gospider.txt | grep "url\]"| grep "\[code-2"  | awk '{print $5}'| grep "\.html" >>  $DOMAIN/urls/html.txt
    cat gospider.txt | grep "url\]"| grep "\[code-2"  | awk '{print $5}'| grep "\.php" >>  $DOMAIN/urls/php.txt
    cat gospider.txt | grep "url\]"| grep "\[code-2"  | awk '{print $5}'  | grep -v "\.js" >>  $DOMAIN/urls/js.txt
    cat gospider.txt | grep "javascript\]" | awk '{print $3}'|sort -u >>  $DOMAIN/urls/js.txt
    cat gospider.txt | grep -v "form\]" | grep -v "javascript\]" | grep -v "linkfinder\]" | grep -v "robots\]" | grep -v "sitemap\]" | grep -v subdomains | grep -v url | grep -v "aws\-s3" |sort -u | tee  $DOMAIN/urls/checkurl

    cat $DOMAIN/waybackurls.txt | grep "\.html" | sort -u >>  $DOMAIN/urls/html.txt
    cat $DOMAIN/waybackurls.txt | grep -v "\.json" | grep "\.js" >>  $DOMAIN/urls/js.txt
    cat $DOMAIN/waybackurls.txt | grep "\.php" >>  $DOMAIN/urls/php.txt
    cat $DOMAIN/waybackurls.txt  | egrep -vi ".(htm|zip|jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|xml|json|yaml|pdf|svg|txt|asp|net|js|php|html)" | sort -u > tmp
    cat tmp | httpx -threads 200 -status-code -silent -follow-redirects -ports 3000 ,8443 ,8443 ,8080 ,8080 ,8008 ,8008 ,591 ,591 ,593 ,593 ,981 ,981 ,2480 ,2480 ,4567 ,4567 ,5000 ,5000 ,5800 ,5800 ,7001 ,7001 ,7002 ,7002 ,9080 ,9080 ,9090 ,9090 ,9443 ,18091 ,18092 > allurls.txt
    cat allurls.txt | grep 2m20[0-9] | awk '{print $1}' >> $DOMAIN/urls/2xx.txt 
    cat allurls.txt | grep 1m40[1-3] | awk '{print $1}' >> $DOMAIN/urls/4xx.txt 
    cat allurls.txt | grep 3m5.. | awk '{print $1}' >> $DOMAIN/urls/5xx.txt
    cat allurls.txt | awk '{print $1}' > $DOMAIN/urls/allurls  

  # sorting and deleting old files
    cat $DOMAIN/urls/2xx.txt | sort -u > $DOMAIN/urls/2xx 
    cat $DOMAIN/urls/4xx.txt | sort -u > $DOMAIN/urls/4xx 
    cat $DOMAIN/urls/5xx.txt | sort -u > $DOMAIN/urls/5xx 
    cat $DOMAIN/urls/html.txt | sort -u > $DOMAIN/urls/html 
    cat $DOMAIN/urls/php.txt | sort -u  > $DOMAIN/urls/php 
    cat $DOMAIN/waybackurls.txt| sort -u > $DOMAIN/waybackurls  
    cat $DOMAIN/urls/js.txt |sort -u| subjs -c 140 >  $DOMAIN/urls/javascript
    cat $DOMAIN/urls/javascript | sort -u >  $DOMAIN/urls/js 
    cat $DOMAIN/urls/2xx  | egrep  "\?|\=" | qsreplace   >  $DOMAIN/urls/params
  #cleaning the output folder
    rm $DOMAIN/urls/php.txt $DOMAIN/urls/html.txt $DOMAIN/waybackurls.txt $DOMAIN/urls/4xx.txt $DOMAIN/urls/2xx.txt  $DOMAIN/urls/5xx.txt  $DOMAIN/urls/javascript
    rm  tmp.txt all.txt allurls.txt wayback.txt gospider.txt tmp

    runBanner "Sort vulnerable_files"
    mkdir $DOMAIN/vulnerable_files
	cat  $DOMAIN/urls/2xx | gf ssrf | qsreplace > $DOMAIN/vulnerable_files/ssrf
	cat  $DOMAIN/urls/2xx | gf sqli | qsreplace > $DOMAIN/vulnerable_files/sqli
	cat  $DOMAIN/urls/2xx | gf ssti | qsreplace > $DOMAIN/vulnerable_files/ssti
	cat  $DOMAIN/urls/2xx | gf xss  | qsreplace > $DOMAIN/vulnerable_files/xss
	cat  $DOMAIN/urls/2xx | qsreplace | kxss  > $DOMAIN/vulnerable_files/xss1
	cat  $DOMAIN/urls/2xx | gf lfi | qsreplace > $DOMAIN/vulnerable_files/lfi
	cat  $DOMAIN/urls/2xx | gf idor | qsreplace > $DOMAIN/vulnerable_files/idor
	cat  $DOMAIN/urls/2xx | gf redirect | qsreplace > $DOMAIN/vulnerable_files/redirect
	cat  $DOMAIN/urls/2xx | gf rce | qsreplace > $DOMAIN/vulnerable_files/rce
	cat  $DOMAIN/urls/2xx | gf debug_logic | qsreplace > $DOMAIN/vulnerable_files/debug_logic
	cat  $DOMAIN/urls/2xx | gf interestingEXT | qsreplace > $DOMAIN/vulnerable_files/interestingEXT
	cat  $DOMAIN/urls/2xx | gf interestingparams | qsreplace > $DOMAIN/vulnerable_files/interestingparams
	cat  $DOMAIN/urls/2xx | gf interestingsubs | qsreplace > $DOMAIN/vulnerable_files/interestingsubs
	cat  $DOMAIN/urls/2xx | gf jsvar | qsreplace > $DOMAIN/vulnerable_files/jsvar 

    runBanner "GetJS"
    cat alive.txt | getJS -complete -output alive-js-files.txt
    sort -u alive-js-files.txt -o alive-js-files.txt

    runBanner "Extracting paths from js files"
    domainExtract

    ## meg
    # find a good wordlist to use for brutforcing with meg

}

networkDiscovery(){

    # Find IP-addresses
    runBanner "Massdns"
    cat $FINAL_DOMAINS | massdns --output S -q -r $TOOLS_DIR/resolvers.txt > massdns-$NOW.txt
    cat massdns-$NOW.txt | grep -w -E A | cut -d " " -f3 > ips-$NOW.txt

    if [ -s ips-$NOW.txt ]
    then
        runBanner "Masscan"
        # Find open-ports on ip list
        sudo masscan -iL ips.txt --rate 10000 -p10000,10243,1025,1026,1029,1030,1033,1034,1036,1038,110,1100,111,1111,113,119,123,135,137,139,143,1433,1434,1521,15567,161,1748,1754,1808,1809,199,20048,2030,2049,21,2100,22,22000,2222,23,25,25565,27900,2869,3128,3268,3269,32768,32843,32844,32846,3306,3339,3366,3372,3389,3573,35826,3632,36581,389,4190,43862,43871,44048,443,4443,4445,445,45295,4555,4559,464,47001,49152,49153,49154,49155,49156,49157,49158,49159,49160,49165,49171,49182,49327,49664,49665,49666,49667,49668,49669,49670,5000,5038,53,5353,5357,54987,55030,55035,55066,55067,55097,55104,55114,55116,55121,55138,55146,55167,55184,5722,5800,58633,587,5900,59010,59195,593,5985,6001,6002,6003,6004,6005,6006,6007,6008,6010,6011,6019,6144,631,636,64327,64337,6532,7411,745,7778,80,82,83,84,85,86,87,8000,8014,808,8080,81,8192,8228,88,8443,8008,8888,9389,9505,993,995 -oX masscan-$NOW.xml

        open_ports=$(cat masscan-$NOW.xml | grep portid | cut -d "\"" -f 10 | sort -n | uniq | paste -sd,)
        sudo nmap -sVC -p$open_ports --open -v -T4 -Pn -iL $FINAL_DOMAINS -oG nmap-$NOW.txt
    else
        echo -e "${RED}[-] Skipping Masscan, ips-$NOW.txt was empty or does not exist${RESET}"
    fi

}

visualDiscovery(){
    # Get Screenshots from online domains
    runBanner "Aquatone"
    cat alive.txt | aquatone -out aquatone
}

vulnerabilityDiscovery(){
    runBanner "Subdomain takeover checks"
    subzy -targets $FINAL_DOMAINS | grep -i -v -E "not vulnerable|ERROR" | tee -a subtakeovers-$NOW.txt

    # CRLF scanner here
        https://github.com/BountyStrike/Injectus.git
    # open redirerct scanner here
        https://github.com/BountyStrike/Injectus.git
    # RetireJS here

    # Nuclei
    mkdir $DOMAIN/nuclei_op   
    nuclei -l $DOMAIN/subdomain/200sub.txt -t /root/nuclei-templates/cves/ -v  -timeout 7 -c 75 -o $DOMAIN/nuclei_op/cves
    nuclei -l $DOMAIN/subdomain/200sub.txt -t /root/nuclei-templates/default-credentials/ -v  -timeout 7 -c 75 -o $DOMAIN/nuclei_op/default-credentials
    nuclei -l $DOMAIN/subdomain/200sub.txt -t /root/nuclei-templates/dns/ -v  -timeout 7 -c 75 -o $DOMAIN/nuclei_op/dns
    nuclei -l $DOMAIN/subdomain/200sub.txt -t /root/nuclei-templates/files/ -v  -timeout 7 -c 75 -o $DOMAIN/nuclei_op/files
    nuclei -l $DOMAIN/subdomain/200sub.txt -t /root/nuclei-templates/gener  ic-detections/ -v  -timeout 7 -c 75 -o $DOMAIN/nuclei_op/generic-detections
    nuclei -l $DOMAIN/subdomain/200sub.txt -t /root/nuclei-templates/misc/ -v  -timeout 7 -c 75 -o $DOMAIN/nuclei_op/misc
    nuclei -l $DOMAIN/subdomain/200sub.txt -t /root/nuclei-templates/panels/ -v  -timeout 7 -c 75 -o $DOMAIN/nuclei_op/panels
    nuclei -l $DOMAIN/subdomain/200sub.txt -t /root/nuclei-templates/security-misconfiguration/ -v  -timeout 7 -c 75 -o $DOMAIN/nuclei_op/security-misconfiguration
    nuclei -l $DOMAIN/subdomain/200sub.txt -t /root/nuclei-templates/subdomain-takeover/ -v  -timeout 7 -c 75 -o $DOMAIN/nuclei_op/subdomain-takeover
    nuclei -l $DOMAIN/subdomain/200sub.txt -t /root/nuclei-templates/technologies/ -v  -timeout 7 -c 75 -o $DOMAIN/nuclei_op/technologies
    nuclei -l $DOMAIN/subdomain/200sub.txt -t /root/nuclei-templates/tokens/ -v  -timeout 7 -c 75 -o $DOMAIN/nuclei_op/tokens
    nuclei -l $DOMAIN/subdomain/200sub.txt -t /root/nuclei-templates/vulnerabilities/ -v  -timeout 7 -c 75 -o $DOMAIN/nuclei_op/vulnerabilities

    # jaeles 
    
    # notification
    #   1. https://github.com/BountyStrike/Emissary
    #   2. send notification after the scan completes
    #   3. send all vulnerability     
}


# ------------------------------------------------------------------------- #

help() {

	echo -e """
${YELLOW}== Info${RESET}
 Bountystrike-sh is a simple bash pipeline script
 containing a bunch tools piping data between each other.
 No need for any fancy setup 
 
${YELLOW}== Usage${RESET}:
	bstrike.sh <action> [project] [domain]
	    bstrike.sh install                       (Install tooling)
	    bstrike.sh run fra fra.se                (Run pipeline)
	    bstrike.sh [assetdiscovery|ad]   fra.se  (Run only asset discovery)
	    bstrike.sh [contentdiscovery|cd] fra.se  (Run only content discovery)
	    bstrike.sh [networkdiscovery|nd] fra.se  (Run only network discovery)
	    bstrike.sh [visualdiscovery|vd]  fra.se  (Run only visual discovery)
	    bstrike.sh [vulndiscovery|vvd]   fra.se  (Run only vulnerability discovery)
	"""
	exit 1
}



if [[ $1 == "" ]] || [[ $1 == "-h" ]] || [[ $1 == "--help" ]]; then
	help
elif [[ $1 == "install" ]]; then

    bash install.sh

elif [[ $1 == "run" ]]; then

	if [[ ! $2 == "" ]]; then
        PROJECT=$2
        if [ ! -d "$PROJECT" ]; then
            mkdir $PROJECT
            cd $PROJECT
        else
            cd $PROJECT
        fi

        if [[ $3 == "" ]]; then
            echo "[-] Please specify a domain..."
            help
        fi

        TARGET=$3
        check_paths;
        SCAN_START=$(date +%s);
        subdomainDiscovery
        contentDiscovery
        networkDiscovery
        vulnerabilityDiscovery
        visualDiscovery

	else
		help
	fi
elif [[ $1 == "assetdiscovery" ]] || [[ $1 == "ad" ]]; then
        if [[ ! $2 == "" ]]; then
            echo -e "\n${GREEN}[+] Running asset discovery on $2...${RESET}"
            echo -e "${GREEN}==============================================================${RESET}"
            TARGET=$2
            check_paths;
            SCAN_START=$(date +%s);
            subdomainDiscovery
        else
            help
        fi
elif [[ $1 == "contentdiscovery" ]] || [[ $1 == "cd" ]]; then
        if [[ ! $2 == "" ]]; then
            echo -e "\n${GREEN}[+] Running content discovery on $2...${RESET}"
            echo -e "${GREEN}==============================================================${RESET}"
            TARGET=$2
            check_paths;
            SCAN_START=$(date +%s);
            contentDiscovery
        else
            help
        fi
elif [[ $1 == "networkdiscovery" ]] || [[ $1 == "nd" ]]; then
        if [[ ! $2 == "" ]]; then
            echo -e "\n${GREEN}[+] Running network discovery on $2...${RESET}"
            echo -e "${GREEN}==============================================================${RESET}"
            TARGET=$2
            check_paths;
            SCAN_START=$(date +%s);
            networkDiscovery
        else
            help
        fi
elif [[ $1 == "vulndiscovery" ]] || [[ $1 == "vvd" ]]; then
        if [[ ! $2 == "" ]]; then
            echo -e "\n${GREEN}[+] Running vulnerability discovery on $2...${RESET}"
            echo -e "${GREEN}==============================================================${RESET}"
            TARGET=$2
            check_paths;
            SCAN_START=$(date +%s);
            vulnerabilityDiscovery
        else
            help
        fi
elif [[ $1 == "visualdiscovery" ]] || [[ $1 == "vd" ]]; then
        if [[ ! $2 == "" ]]; then
            echo -e "\n${GREEN}[+] Running visual discovery on $2...${RESET}"
            echo -e "${GREEN}==============================================================${RESET}"
            TARGET=$2
            check_paths;
            SCAN_START=$(date +%s);
            visualDiscovery
        else
            help
        fi
else
    help
fi


# Calculate scan runtime
SCAN_END=$(date +%s);
SCAN_DIFF=$(( SCAN_END - SCAN_START ));

if [[ "$NOTICA" != "" ]]; then
		run_notica "$DOMAIN";
fi

echo -e "$BLUE""[i] Total script run time: $SCAN_DIFF seconds.""$NC";
echo -e "${GREEN}\n==== BountyStrike surface scan complete ====${RESET}"
