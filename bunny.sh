#!/bin/bash
  # TODO: integrate whole script using interlace 
  # TODO: Replace ffuf with meg for content discovery as meg is server friendly 
  # https://github.com/tomnomnom/meg  

########################################################################################################
######################################## CONFIG_FILES ##################################################
########################################################################################################

  VERSION="bunny_V2"
  # TERM COLORS
    RED="\033[1;31m"
    GREEN="\033[1;32m"
    BLUE="\033[1;36m"
    YELLOW="\033[1;33m"
    RESET="\033[0m"

    NORMAL='\[\033[00m\]'
    BGREEN='\[\033[1;32m\]'
    BLUE='\[\033[1;34m\]'
    GREEN='\[\033[0;32m\]'
    bred='\033[1;31m'
    bblue='\033[1;34m'
    bgreen='\033[1;32m'
    yellow='\033[0;33m'
    red='\033[0;31m'
    blue='\033[0;34m'
    green='\033[0;32m'
    reset='\033[0m'


  # General values
    tools="~/Tools"
    TOOL_PATH="/opt/tools"
    PROJECT="/opt/target"
    TOOL_PATH_SET=0;
    CONFIG_FILES="$(pwd)/config_files"
    called_fn_dir="$PROJECT/.called_fn"
    WORDLIST="${pwd}/wordlist"
    REPO_TOOLS="${pwd}/tools"
    proxy_url="http://127.0.0.1:8080/"

  # Wordlists
    fuzz_wordlist=${WORDLIST}/fuzz_wordlist.txt
    lfi_wordlist=${WORDLIST}/lfi_wordlist.txt
    ssti_wordlist=${WORDLIST}/ssti_wordlist.txt
    subs_wordlist=${WORDLIST}/subdomains.txt
    resolvers=${WORDLIST}/resolvers.txt
    resolvers_trusted=${WORDLIST}/resolvers_trusted.txt

  # Tools config files
    AMASS_CONFIG=$CONFIG_FILES/config.ini
    GITHUB_TOKENS=${tools}/.github_tokens

  # File descriptors
    DEBUG_STD="&>/dev/null"
    DEBUG_ERROR="2>/dev/null"
    NOTIFY="notify -silent -bulk"

  # Osint
    GOOGLE_DORKS=false
    GITHUB_DORKS=false
    TLDA=true
    IP_INFO=true
    META=true
    EMAILS=true
  # Subdomains
    SUBDOMAINS_GENERAL=true
    SUBPASSIVE=true
    SUBCRT=true
    SUBANALYTICS=true
    SUBBRUTE=true
    SUBSCRAPING=true
    SUBPERMUTE=true
    SUBTAKEOVER=true
    SUBRECURSIVE=true
    SUB_RECURSIVE_PASSIVE=false # Uses a lot of API keys queries
    ZONETRANSFER=true
    S3BUCKETS=true
    REVERSE_IP=false
    WEBSCREENSHOT=true
    UNCOMMON_PORTS_WEB="81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9092,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55440,55672"
  # Host
    FAVICON=true
    PORTSCANNER=true
    PORTSCAN_PASSIVE=true
    PORTSCAN_ACTIVE=true
    CLOUD_IP=true

  # Web analysis
    WAF_DETECTION=true
    NUCLEICHECK=true
    URL_CHECK=true
    URL_GF=true
    URL_EXT=true
    JSCHECKS=true
    FUZZ=true
    CMS_SCANNER=true
    WORDLIST=true
    ROBOTSWORDLIST=true

  # Vulns
    XSS=true
    CORS=true
    TEST_SSL=false
    OPEN_REDIRECT=true
    SSRF_CHECKS=true
    CRLF_CHECKS=true
    LFI=true
    SSTI=true
    SQLI=true
    BROKENLINKS=true
    SPRAY=false
    COMM_INJ=true
    PROTO_POLLUTION=true

  # Extra features
    NOTIFICATION=false # Notification for every function
    SOFT_NOTIFICATION=false # Only for start/end on cli
    REMOVETMP=false
    REMOVELOG=false
    PROXY=false
    SENDZIPNOTIFY=false
    PRESERVE=true      # Yet to add set to true to avoid deleting the .called_fn files on really large scans

  # HTTP options
    HEADER="User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0"

  # Threads
    FFUF_THREADS=40
    HTTPX_THREADS=50
    HTTPX_UNCOMMONPORTS_THREADS=100
    GOSPIDER_THREADS=50
    GITDORKER_THREADS=5
    BRUTESPRAY_THREADS=20
    BRUTESPRAY_CONCURRENCE=10
    ARJUN_THREADS=20
    GAUPLUS_THREADS=10
    DALFOX_THREADS=200
    PUREDNS_PUBLIC_LIMIT=1000 # Set between 2000 - 10000 if your router blows up, 0 is unlimited
    PUREDNS_TRUSTED_LIMIT=400
    WEBSCREENSHOT_THREADS=200
    RESOLVE_DOMAINS_THREADS=150
    PPFUZZ_THREADS=30

  # Timeouts in Seconds
    CMSSCAN_TIMEOUT=3600            
    SUBJS_TIMEOUT=108000  
    GOSPIDER_TIMEOUT=108000  

########################################################################################################
######################################### INITIAL SETUP ################################################
########################################################################################################

  initial_banner(){
    echo """                                                             
      @@@@@@@   @@@  @@@  @@@  @@@  @@@  @@@  @@@ @@@     @@@  @@@   @@@@@@   
      @@@@@@@@  @@@  @@@  @@@@ @@@  @@@@ @@@  @@@ @@@     @@@  @@@  @@@@@@@@  
      @@!  @@@  @@!  @@@  @@!@!@@@  @@!@!@@@  @@! !@@     @@!  @@@       @@@  
      !@   @!@  !@!  @!@  !@!!@!@!  !@!!@!@!  !@! @!!     !@!  @!@      @!@   
      @!@!@!@   @!@  !@!  @!@ !!@!  @!@ !!@!   !@!@!      @!@  !@!     !!@    
      !!!@!!!!  !@!  !!!  !@!  !!!  !@!  !!!    @!!!      !@!  !!!    !!:     
      !!:  !!!  !!:  !!!  !!:  !!!  !!:  !!!    !!:       :!:  !!:   !:!      
      :!:  !:!  :!:  !:!  :!:  !:!  :!:  !:!    :!:        ::!!:!   :!:       
      :: ::::  ::::: ::   ::   ::   ::   ::     ::         ::::    :: :::::  
      :: : ::    : :  :   ::    :   ::    :      :           :      :: : :::                                                                           
    """
  }

  check_version(){
    timeout 10 git fetch &>/dev/null
    exit_status=$?
    if [ $exit_status -eq 0 ]; then
      BRANCH=$(git rev-parse --abbrev-ref HEAD)
      HEADHASH=$(git rev-parse HEAD)
      UPSTREAMHASH=$(git rev-parse ${BRANCH}@{upstream})
      if [ "$HEADHASH" != "$UPSTREAMHASH" ]; then
        printf "\n${yellow} There is a new version, run ./install.sh to get latest version${reset}\n\n"
      fi
    else
      printf "\n${bred} Unable to check updates ${reset}\n\n"
    fi
  }

  set_tool_paths() {
    if [[ "$TOOL_PATH_SET" -eq 0 ]]; then
      TOOL_PATH_SET=1;
      DOMAIN_ANALYZER=$TOOL_PATH/domain_analyzer/domain_analyzer.py
      SPOOFCHECK=$TOOL_PATH/spoofcheck/spoofcheck.py
      S3SCANNER=$TOOL_PATH/S3Scanner/s3scanner.py;
      CORSTEST=$TOOL_PATH/CORStest/corstest.py;
      CORSY=$TOOL_PATH/Corsy/corsy.py;
      UDORK=$TOOL_PATH/uDork/./uDork.sh
      DNSRECON=$TOOL_PATH/dnsrecon/dnsrecon.py
      BRUTESPRAY=$TOOL_PATH/brutespray/brutespray.py
      BYPASS_403=$TOOL_PATH/bypass-403/./Bypass-403.sh
      FAVFREAK=$TOOL_PATH/FavFreak/favfreak.py
      TESTSSL=$TOOL_PATH/testssl.sh/testssl.sh
      CMSEEK=$TOOL_PATH/CMSeeK/cmseek.py
      CLOUD_ENUM=$TOOL_PATH/cloud_enum/cloud_enum.py
      JSA=$TOOL_PATH/JSA/jsa.py
      PWNDB=$TOOL_PATH/pwndb/pwndb.py
      GETJSWORDS=$TOOL_PATH/getjswords.py
      CTRF=$TOOL_PATH/ctfr/ctfr.py
      LINKFINDER=$TOOL_PATH/LinkFinder/linkfinder.py
      GITDORKDER=$TOOL_PATH/GitDorker/GitDorker.py
      COMMIX=$TOOL_PATH/commix/commix.py
      HOST_HUNTER=$TOOL_PATH/HostHunter/hosthunter.py
      HOSTPANIC=$TOOL_PATH/HostPanic/main.py 
      SMUGGLER=$TOOL_PATH/smuggler/smuggler.py
      CERTFINDER=$REPO_TOOLS/./certfinder.sh
      BYPASS4xx=$REPO_TOOLS/./4xxbypass.sh
      DOMXSS=$REPO_TOOLS/./findomxss.sh
      SHODANFY=$REPO_TOOLS/shodanfy.py
    else
      return;
    fi
  }

  check_connection() {
    wget -q --spider http://google.com
    if [ $? -ne 0 ];then
        echo "Connect to internet!!"
        exit 1
    fi
    local prompt
    prompt=$(sudo -nv 2>&1)
    if [ $? -eq 0 ]; then
      echo "All Done"
     elif echo $prompt | grep -q '^sudo:'; then
      echo "try again after sudo -s"
      exit 1
     else
      echo "no_sudo"
      exit 1
    fi
  }

  notification(){
    if [ -n "$1" ] && [ -n "$2" ]; then
      case $2 in
        info)
          text="\n${bblue} ${1} ${reset}"
          printf "${text}\n" && printf "${text} - ${DOMAIN}\n" | $NOTIFY
        ;;
        warn)
          text="\n${yellow} ${1} ${reset}"
          printf "${text}\n" && printf "${text} - ${DOMAIN}\n" | $NOTIFY
        ;;
        error)
          text="\n${bred} ${1} ${reset}"
          printf "${text}\n" && printf "${text} - ${DOMAIN}\n" | $NOTIFY
        ;;
        good)
          text="\n${bgreen} ${1} ${reset}"
          printf "${text}\n" && printf "${text} - ${DOMAIN}\n" | $NOTIFY
        ;;
      esac
    fi
  }

########################################################################################################
########################################## MISC Functions ##############################################
########################################################################################################

  deleteOutScoped(){
    # deleteOutScoped $outOfScope_file subdomains/subdomains.txt
    if [ -z "$1" ]; then
      cat $1 | while read outscoped
      do
        if  grep -q  "^[*]" <<< $outscoped
        then
          outscoped="${outscoped:1}"
          sed -i /"$outscoped$"/d  $2
        else
        sed -i /$outscoped/d  $2
        fi
      done
    fi
  }

  getElapsedTime() {
    runtime=""
    local T=$2-$1
    local D=$((T/60/60/24))
    local H=$((T/60/60%24))
    local M=$((T/60%60))
    local S=$((T%60))
    (( $D > 0 )) && runtime="$runtime$D days, "
    (( $H > 0 )) && runtime="$runtime$H hours, "
    (( $M > 0 )) && runtime="$runtime$M minutes, "
    runtime="$runtime$S seconds."
  }

  resolvers_update(){
    if [[ $(find "$resolvers" -mtime +1 -print) ]]; then
      notification "Resolvers seem older than 1 day\n Generating custom resolvers..." warn
      eval rm -f $resolvers 2>>"$LOGFILE"
      dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 100 -o $resolvers &>/dev/null
      notification "Updated\n" good
    fi
  }

  sendToNotify() {
    if [[ -z "$1" ]]; then
      printf "\n${yellow} no file provided to send ${reset}\n"
    else
      if [[ -z "$NOTIFY_CONFIG" ]]; then
        NOTIFY_CONFIG=~/.config/notify/notify.conf
      fi
      if grep -q '^ discord\|^discord' $NOTIFY_CONFIG ; then
        notification "Sending ${DOMAIN} data over Discord" info
        discord_url=$(cat ${NOTIFY_CONFIG} | grep '^ discord_webhook_url\|^discord_webhook_url' | xargs | cut -d' ' -f2)
        curl -v -i -H "Accept: application/json" -H "Content-Type: multipart/form-data" -X POST -F file1=@${1} $discord_url &>/dev/null
      fi
    fi
  }

  zipSnedOutputFolder ()  {
    zip_name=`date +"%Y_%m_%d-%H.%M.%S"`
    zip_name="$zip_name"_"$DOMAIN.zip"
    cd $SCRIPTPATH && zip -r $zip_name $dir &>/dev/null
    if [ -s "$SCRIPTPATH/$zip_name" ]; then
      sendToNotify "$SCRIPTPATH/$zip_name"
      rm -f "$SCRIPTPATH/$zip_name"
    else
      notification "No Zip file to send" warn
    fi
  }

  isAsciiText() {
    IS_ASCII="False";
    if [[ $(file $1 | grep -o 'ASCII text$') == "ASCII text" ]]; then
      IS_ASCII="True";
    else
      IS_ASCII="False";
    fi
  }

  remove_big_files(){
    rm -rf .tmp/gotator*.txt 2>>"$LOGFILE"
    rm -rf .tmp/brute_recursive_wordlist.txt 2>>"$LOGFILE"
    rm -rf .tmp/subs_dns_tko.txt  2>>"$LOGFILE"
    rm -rf .tmp/subs_no_resolved.txt .tmp/subdomains_dns.txt .tmp/brute_dns_tko.txt .tmp/scrap_subs.txt .tmp/analytics_subs_clean.txt .tmp/gotator1.txt .tmp/gotator2.txt .tmp/passive_recursive.txt .tmp/brute_recursive_wordlist.txt .tmp/gotator1_recursive.txt .tmp/gotator2_recursive.txt 2>>"$LOGFILE"
    find .tmp -type f -size +200M -exec rm -f {} + 2>>"$LOGFILE"
  }

########################################################################################################
############################################# OSINT ####################################################
########################################################################################################

  emails(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$EMAILS" = true ] && [ "$OSINT" = true ] && ! [[ $DOMAIN =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
      start_func "Searching emails/users/passwords leaks"
      emailfinder -d $DOMAIN 2>>"$LOGFILE" | anew -q .tmp/emailfinder.txt
      python3 crosslinked.py -f `{first}.{last}@$DOMAIN` $DOMAIN | anew -q .tmp/emailfinder.txt
      [ -s ".tmp/emailfinder.txt" ] && cat .tmp/emailfinder.txt | awk 'matched; /^-----------------$/ { matched = 1 }' | anew -q osint/emails.txt
      python3 crosslinked.py -f `$DOMAIN\{f}{last}` -t 45 -j 1 $DOMAIN | anew -q osint/users.txt
      python3 crosslinked.py -f `$DOMAIN\{first}/{last}` -t 45 -j 1 $DOMAIN   | anew -q osint/users.txt
      cd "$TOOL_PATH/theHarvester" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
      # python3 $TOOL_PATH/theHarvester/theHarvester.py -d $DOMAIN -b all 2>>"$LOGFILE" | anew -q .tmp/harvester.txt
	  	python3 $TOOL_PATH/theHarvester/theHarvester.py -d $DOMAIN -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, netcraft, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye" 2>>"$LOGFILE" | anew -q .tmp/harvester.txt
      if [ -s ".tmp/harvester.txt" ]; then
        cat .tmp/harvester.txt | awk '/Emails/,/Hosts/' | sed -e '1,2d' | head -n -2 | sed -e '/Searching /d' -e '/exception has occurred/d' -e '/found:/Q' | anew -q osint/emails.txt
        cat .tmp/harvester.txt | awk '/Users/,/IPs/' | sed -e '1,2d' | head -n -2 | sed -e '/Searching /d' -e '/exception has occurred/d' -e '/found:/Q' | anew -q osint/users.txt
        cat .tmp/harvester.txt | awk '/Links/,/Users/' | sed -e '1,2d' | head -n -2 | sed -e '/Searching /d' -e '/exception has occurred/d' -e '/found:/Q' | anew -q osint/linkedin.txt
      fi
      end_func "Results are saved in $DOMAIN/osint/[emails/users/passwords].txt" ${FUNCNAME[0]}
    else
      if [ "$EMAILS" = false ] || [ "$OSINT" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi

    fi
  }

  metadata(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$META" = true ]; then
      start_subfunc "Running : pymeta "
      pymeta -d $DOMAIN -o $PROJECT/$DOMAIN -f pymeta.csv

      NUMOFLINES=$(cat $PROJECT/$DOMAIN/pymeta.csv | wc -l)
      end_subfunc "${NUMOFLINES} new resources (pdf,png)" ${FUNCNAME[0]}
      start_func ${FUNCNAME[0]} "Scanning metadata in public files"
      metafinder -d "$domain" -l $METAFINDER_LIMIT -o osint -go -bi -ba 2>>"$LOGFILE" &>/dev/null
      mv "osint/${domain}/"*".txt" "osint/" 2>>"$LOGFILE"
      rm -rf "osint/${domain}" 2>>"$LOGFILE"
      end_func "Results are saved in $domain/osint/[software/authors/metadata_results].txt" ${FUNCNAME[0]}
    else
      if [ "$META" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  google_dorks(){
    if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] && [ "$GOOGLE_DORKS" = true ] && [ "$OSINT" = true ]; then
      start_func ${FUNCNAME[0]} "Google Dorks in process"
      eval sed -i "s/^cookies=\"c_user=HEREYOUCOOKIE; xs=HEREYOUCOOKIE;\"/cookies=\"${UDORK_COOKIE}\"/" $tools/uDork/uDork.sh 2>>"$LOGFILE" &>/dev/null
      cd "$tools/uDork" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
      ./uDork.sh $domain -f $tools/custom_udork.txt -o $dir/osint/dorks.txt &> /dev/null
      [ -s "$dir/osint/dorks.txt" ] && sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" $dir/osint/dorks.txt 2>>"$LOGFILE" &>/dev/null
      cd "$dir" || { echo "Failed to cd to $dir in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
      end_func "Results are saved in $domain/osint/dorks.txt" ${FUNCNAME[0]}
    else
      if [ "$GOOGLE_DORKS" = false ] || [ "$OSINT" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} are already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  domain_info(){
    if  [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] && [ "$DOMAIN_INFO" = true ] && [ "$OSINT" = true ]; then
      start_func "Searching domain info (whois, registrant name/email domains)"
      lynx -dump "https://domainbigdata.com/${DOMAIN}" | tail -n +19 > osint/domain_info_general.txt
      if [ -s "osint/domain_info_general.txt" ]; then
        cat osint/domain_info_general.txt | grep '/nj/' | tr -s ' ' ',' | cut -d ',' -f3 > .tmp/domain_registrant_name.txt
        cat osint/domain_info_general.txt | grep '/mj/' | tr -s ' ' ',' | cut -d ',' -f3 > .tmp/domain_registrant_email.txt
        cat osint/domain_info_general.txt | grep -E "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | grep "https://domainbigdata.com" | tr -s ' ' ',' | cut -d ',' -f3 > .tmp/domain_registrant_ip.txt
      fi
      sed -i -n '/Copyright/q;p' osint/domain_info_general.txt

      if [ -s ".tmp/domain_registrant_name.txt" ]; then
        for line in $(cat .tmp/domain_registrant_name.txt); do
          lynx -dump $line | tail -n +18 | sed -n '/]domainbigdata.com/q;p' >> osint/domain_info_name.txt && echo -e "\n\n#######################################################################\n\n" >> osint/domain_info_name.txt
        done
      fi

      if [ -s ".tmp/domain_registrant_email.txt" ]; then
        for line in $(cat .tmp/domain_registrant_email.txt); do
          lynx -dump $line | tail -n +18 | sed -n '/]domainbigdata.com/q;p'  >> osint/domain_info_email.txt && echo -e "\n\n#######################################################################\n\n" >> osint/domain_info_email.txt
        done
      fi

      if [ -s ".tmp/domain_registrant_ip.txt" ]; then
        for line in $(cat .tmp/domain_registrant_ip.txt); do
          lynx -dump $line | tail -n +18 | sed -n '/]domainbigdata.com/q;p'  >> osint/domain_info_ip.txt && echo -e "\n\n#######################################################################\n\n" >> osint/domain_info_ip.txt
        done
      fi
      end_func "Results are saved in $DOMAIN/osint/domain_info_[general/name/email/ip].txt" ${FUNCNAME[0]}
    else
      if [ "$DOMAIN_INFO" = false ] || [ "$OSINT" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  github_dorks(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$GITHUB_DORKS" = true ] && [ "$OSINT" = true ]; then
      start_func ${FUNCNAME[0]} "Github Dorks in process"
      if [ -s "${GITHUB_TOKENS}" ]; then
        python3 "$GITDORKDER" -tf "${GITHUB_TOKENS}" -e "$GITDORKER_THREADS" -q "$domain" -p -ri -d "$tools/GitDorker/Dorks/alldorksv3" 2>>"$LOGFILE" | grep "\[+\]" | grep "git" | anew -q osint/gitdorks.txt
        sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" osint/gitdorks.txt
      else
        printf "\n${bred} Required file ${GITHUB_TOKENS} not exists or empty${reset}\n"
      fi
      end_func "Results are saved in $domain/osint/gitdorks.txt" ${FUNCNAME[0]}
    else
      if [ "$GITHUB_DORKS" = false ] || [ "$OSINT" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  ip_info(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$IP_INFO" = true ] && [ "$OSINT" = true ] && [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
      start_func ${FUNCNAME[0]} "Searching ip info"
      if [ -n "$WHOISXML_API" ]; then
        curl "https://reverse-ip.whoisxmlapi.com/api/v1?apiKey=${WHOISXML_API}&ip=${domain}" 2>/dev/null | jq -r '.result[].name' 2>>"$LOGFILE" | sed -e "s/$/ ${ip}/" | anew -q osint/ip_${domain}_relations.txt
        curl "https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${WHOISXML_API}&domainName=${domain}&outputFormat=json&da=2&registryRawText=1&registrarRawText=1&ignoreRawTexts=1" 2>/dev/null | jq 2>>"$LOGFILE" | anew -q osint/ip_${domain}_whois.txt
        curl "https://ip-geolocation.whoisxmlapi.com/api/v1?apiKey=${WHOISXML_API}&ipAddress=${domain}" 2>/dev/null | jq -r '.ip,.location' 2>>"$LOGFILE" | anew -q osint/ip_${domain}_location.txt
        end_func "Results are saved in $domain/osint/ip_[domain_relations|whois|location].txt" ${FUNCNAME[0]}
      else
        printf "\n${yellow} No WHOISXML_API var defined, skipping function ${reset}\n"
      fi
    else
      if [ "$IP_INFO" = false ] || [ "$OSINT" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
      elif [[ ! $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
        return
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

########################################################################################################
############################################ SUBDOMAINS ################################################
########################################################################################################

  subdomains_full(){
    NUMOFLINES_subs="0"
    NUMOFLINES_probed="0"
    printf "${bgreen}#######################################################################\n\n"
    ! [[ $DOMAIN =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]] && printf "${bblue} Subdomain Enumeration $DOMAIN\n\n"
    [[ $DOMAIN =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]] && printf "${bblue} Scanning IP $DOMAIN\n\n"
    [ -s "subdomains/subdomains.txt" ] && cp subdomains/subdomains.txt .tmp/subdomains_old.txt
    [ -s "webs/webs.txt" ] && cp webs/webs.txt .tmp/probed_old.txt

    resolvers_update

    [ -s "${inScope_file}" ] && cat ${inScope_file} | anew -q subdomains/subdomains.txt
    # TODO: skip subdomainDiscovery for https:// & http:// in urls
    if ! [[ $DOMAIN =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
      sub_passive
      sub_crt
      sub_active
      sub_brute
      sub_recursive
      sub_dns
      sub_scraping
      sub_analytics
      # cat urls.txt | python3 favfreak.py | grep "sixt.com" | grep -v "\["   >> subdomains/subdomains.txt

      # deleteOutScoped $outOfScope_file .tmp/subs_no_resolved.txt
    else 
      notification "IP/CIDR detected, subdomains search skipped" info
    fi

    if [ -s "subdomains/subdomains.txt" ]; then
      deleteOutScoped $outOfScope_file subdomains/subdomains.txt
      NUMOFLINES_subs=$(cat subdomains/subdomains.txt 2>>"$LOGFILE" | anew .tmp/subdomains_old.txt | wc -l)
    fi
    checkDomains

    printf "${bblue}\n Total subdomains: ${reset}\n\n"
    notification "- ${NUMOFLINES_subs} alive" good
    [ -s "subdomains/subdomains.txt" ] && cat subdomains/subdomains.txt | sort
    notification "Subdomain Enumeration Finished" good
    printf "${bblue} Results are saved in $PROJECT/$DOMAIN/subdomains/subdomains.txt${reset}\n"
    printf "${bgreen}#######################################################################\n\n"
  }

  sub_passive(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBPASSIVE" = true ]; then
      start_subfunc "Running : Passive Subdomain Enumeration"
        subfinder -d $DOMAIN -all -o .tmp/subfinder_psub.txt 2>>"$LOGFILE" &>/dev/null
        assetfinder --subs-only $DOMAIN 2>>"$LOGFILE" | anew -q .tmp/assetfinder_psub.txt
        amass enum -passive -d $DOMAIN -config $AMASS_CONFIG -o .tmp/amass_psub.txt 2>>"$LOGFILE" &>/dev/null
        findomain --quiet -t $DOMAIN -u .tmp/findomain_psub.txt 2>>"$LOGFILE" &>/dev/null
        crobat -s $DOMAIN -u -r
        timeout 10m waybackurls $DOMAIN | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/waybackurls_psub.txt
        timeout 10m gauplus -t $GAUPLUS_THREADS -random-agent -subs $DOMAIN | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/gau_psub.txt
        crobat -s $DOMAIN 2>>"$LOGFILE" | anew -q .tmp/crobat_psub.txt
        if [ -s "${GITHUB_TOKENS}" ]; then
          github-subdomains -d $DOMAIN -t $GITHUB_TOKENS -o .tmp/github_subdomains_psub.txt 2>>"$LOGFILE" &>/dev/null
        fi
      NUMOFLINES=$(cat .tmp/*_psub.txt 2>>"$LOGFILE" | sed "s/*.//" | anew .tmp/passive_subs.txt | wc -l)
      end_subfunc "${NUMOFLINES} new subs (passive)" ${FUNCNAME[0]}
    else
      if [ "$SUBPASSIVE" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  sub_crt(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBCRT" = true ]; then
      start_subfunc "Running : Crtsh Subdomain Enumeration"
        $CERTFINDER $DOMAIN subdomains/subdomains.txt 

      end_subfunc "new subs (cert transparency)" ${FUNCNAME[0]}
    else
      if [ "$SUBCRT" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  sub_dns(){
    if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; then
      start_subfunc "Running : DNS Subdomain Enumeration"
        [ -s "subdomains/subdomains.txt" ] && dnsx -retry 3 -a -aaaa -cname -ns -ptr -mx -soa -resp -silent -l subdomains/subdomains.txt -o subdomains/subdomains_dnsregs.txt -r $resolvers_trusted 2>>"$LOGFILE" &>/dev/null
        [ -s "subdomains/subdomains_dnsregs.txt" ] && cat subdomains/subdomains_dnsregs.txt | cut -d '[' -f2 | sed 's/.$//' | grep ".$DOMAIN$" | anew -q .tmp/subdomains_dns.txt
        [ -s ".tmp/subdomains_dns.txt" ] && puredns resolve .tmp/subdomains_dns.txt -w .tmp/subdomains_dns_resolved.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT 2>>"$LOGFILE" &>/dev/null

      NUMOFLINES=$(cat .tmp/subdomains_dns_resolved.txt 2>>"$LOGFILE" | grep "\.$DOMAIN$\|^$DOMAIN$" | anew subdomains/subdomains.txt | wc -l)
      end_subfunc "${NUMOFLINES} new subs (dns resolution)" ${FUNCNAME[0]}
    else
      printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
    fi
  }

  sub_brute(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBBRUTE" = true ]; then
      start_subfunc "Running : Bruteforce Subdomain Enumeration"
          puredns bruteforce $subs_wordlist_big $DOMAIN -w .tmp/subs_brute.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT 2>>"$LOGFILE" &>/dev/null
          # puredns bruteforce names.txt sixt.com --resolvers trusted.txt --rate-limit 450
        [ -s ".tmp/subs_brute.txt" ] && puredns resolve .tmp/subs_brute.txt -w .tmp/subs_brute_valid.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT 2>>"$LOGFILE" &>/dev/null

      NUMOFLINES=$(cat .tmp/subs_brute_valid.txt 2>>"$LOGFILE" | sed "s/*.//" | grep ".$DOMAIN$" | anew subdomains/subdomains.txt | wc -l)
      end_subfunc "${NUMOFLINES} new subs (bruteforce)" ${FUNCNAME[0]}
    else
      if [ "$SUBBRUTE" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  sub_scraping(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBSCRAPING" = true ]; then
      start_subfunc "Running : Source code scraping subdomain search"
      touch .tmp/scrap_subs.txt
      if [ -s "$dir/subdomains/subdomains.txt" ]; then
          cat subdomains/subdomains.txt | httpx -follow-host-redirects -random-agent -status-code -threads $HTTPX_THREADS -timeout $HTTPX_TIMEOUT -silent -retries 2 -ip -no-color | anew .tmp/web_full_info.txt | cut -d ' ' -f1 | grep ".$DOMAIN$" | anew -q .tmp/probed_tmp_scrap.txt
          [ -s ".tmp/probed_tmp_scrap.txt" ] && cat .tmp/probed_tmp_scrap.txt | httpx -csp-probe -random-agent -status-code -threads $HTTPX_THREADS -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color | anew .tmp/web_full_info.txt | cut -d ' ' -f1 | grep ".$DOMAIN$" | anew .tmp/probed_tmp_scrap.txt | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/scrap_subs.txt
          [ -s ".tmp/probed_tmp_scrap.txt" ] && cat .tmp/probed_tmp_scrap.txt | httpx -tls-probe -random-agent -status-code -threads $HTTPX_THREADS -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color | anew .tmp/web_full_info.txt | cut -d ' ' -f1 | grep ".$DOMAIN$" | anew .tmp/probed_tmp_scrap.txt | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/scrap_subs.txt
          [ -s ".tmp/probed_tmp_scrap.txt" ] && gospider -S .tmp/probed_tmp_scrap.txt --js -t $GOSPIDER_THREADS -d 2 --sitemap --robots -w -r > .tmp/gospider.txt
          sed -i '/^.\{2048\}./d' .tmp/gospider.txt
          [ -s ".tmp/gospider.txt" ] && cat .tmp/gospider.txt | grep -Eo 'https?://[^ ]+' | sed 's/]$//' | unfurl -u domains 2>>"$LOGFILE" | grep ".$DOMAIN$" | anew -q .tmp/scrap_subs.txt
          [ -s ".tmp/scrap_subs.txt" ] && puredns resolve .tmp/scrap_subs.txt -w .tmp/scrap_subs_resolved.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT 2>>"$LOGFILE" &>/dev/null
          NUMOFLINES=$(cat .tmp/scrap_subs_resolved.txt 2>>"$LOGFILE" | grep "\.$DOMAIN$\|^$DOMAIN$" | anew subdomains/subdomains.txt | tee .tmp/diff_scrap.txt | wc -l)
          [ -s ".tmp/diff_scrap.txt" ] && cat .tmp/diff_scrap.txt | httpx -follow-host-redirects -random-agent -status-code -threads $HTTPX_THREADS -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color | anew .tmp/web_full_info.txt | cut -d ' ' -f1 | grep ".$DOMAIN$" | anew -q .tmp/probed_tmp_scrap.txt
  
        end_subfunc "${NUMOFLINES} new subs (code scraping)" ${FUNCNAME[0]}
      else
        end_subfunc "No subdomains to search (code scraping)" ${FUNCNAME[0]}
      fi
    else
      if [ "$SUBSCRAPING" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  sub_analytics(){
    if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]; then
      start_subfunc "Running : Analytics Subdomain Enumeration related domains mostly out of scope"
      if [ -s ".tmp/probed_tmp_scrap.txt" ]; then
        mkdir -p .tmp/output_analytics/
        cat .tmp/probed_tmp_scrap.txt | analyticsrelationships >> .tmp/analytics_subs_tmp.txt 2>>"$LOGFILE" &>/dev/null
        [ -s ".tmp/analytics_subs_tmp.txt" ] && cat .tmp/analytics_subs_tmp.txt | grep "\.$DOMAIN$\|^$DOMAIN$" | sed "s/|__ //" | awk '{print $4}'| anew -q .tmp/analytics_subs_clean.txt
        
      fi
      NUMOFLINES=$(cat .tmp/analytics_subs_resolved.txt 2>>"$LOGFILE" | anew osint/subdomains.txt |  wc -l)
      end_subfunc "${NUMOFLINES} new subs (analytics relationship)" ${FUNCNAME[0]}
    else
      if [ "$SUBANALYTICS" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  sub_recursive(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBRECURSIVE" = true ] && [ -s "subdomains/subdomains.txt" ]; then
      start_subfunc "Running : Subdomains recursive search"
      if [ "$SUB_RECURSIVE_PASSIVE" = true ]; then
          for sub in $( ( cat subdomains/subdomains.txt | rev | cut -d '.' -f 3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 && cat subdomains/subdomains.txt | rev | cut -d '.' -f 4,3,2,1 | rev | sort | uniq -c | sort -nr | grep -v '1 ' | head -n 10 ) | sed -e 's/^[[:space:]]*//' | cut -d ' ' -f 2);do 
            subfinder -d $sub -all -silent 2>>"$LOGFILE" | anew -q .tmp/passive_recursive.txt
            assetfinder --subs-only $sub 2>>"$LOGFILE" | anew -q .tmp/passive_recursive.txt
            amass enum -passive -d $sub -config $AMASS_CONFIG 2>>"$LOGFILE" | anew -q .tmp/passive_recursive.txt
            findomain --quiet -t $sub 2>>"$LOGFILE" | anew -q .tmp/passive_recursive.txt
          done
          [ -s ".tmp/passive_recurs_tmp.txt" ] && cat .tmp/passive_recurs_tmp.txt | anew -q subdomains/subdomains.txt
      fi
    
    else
      if [ "$SUBRECURSIVE" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  checkDomains() {
      # Filtering outofscope domains
      if [ -f "$exclude" ]; then
        cat temporary/*.txt | grep -v "*" | grep -vf $exclude | sort -u | sed '/@\|<BR>\|\_\|*/d' | dnsx -retry 2 -r ~/wordlists/resolvers.txt -t 100 -silent | anew -q domains/subdomains.txt
      else
        cat temporary/*.txt | grep -v "*" | sort -u | sed '/@\|<BR>\|\_\|*/d' | dnsx -retry 2 -r ~/wordlists/resolvers.txt -t 100 -silent | anew -q domains/subdomains.txt
      fi
      cat $DOMAIN/subdomains.txt | httpx -silent -threads 200 -status-code -ip -follow-redirects  -ports 80 ,443 ,3000 ,8443 ,8443 ,8080 ,8080 ,8008 ,8008 ,5000 ,5800 ,5800 ,7001 ,7000 ,9080 ,9443 > all.txt
      [ ! -d domains/aquatone ] && xargs -a domains/liveurls.txt -P 50 -I % bash -c "echo % | aquatone -chrome-path /snap/bin/chromium -out domains/aquatone/ -threads 10 -silent" 2> /dev/null &> /dev/null
        # Collect Live subdomains
      mkdir $DOMAIN/subdomain  
      echo "Collecting Live subdomains $(pwd)/all.txt"
      cat all.txt | sort -u | grep 2m20[0-9] | awk '{print $1}' > $DOMAIN/subdomain/200sub.txt 
      cat all.txt | sort -u | grep 1m40[1-3] | awk '{print $1}' > $DOMAIN/subdomain/401sub.txt 
      cat all.txt | sort -u | grep 3m5.. | awk '{print $1}' > $DOMAIN/subdomain/5xxsub.txt
      cat $DOMAIN/subdomain/*.txt| sort -u >> $DOMAIN/subdomain/allsubdmain
      cat all.txt | sort -u | awk '{print $3}' | sed "s/\[//g"| sed "s/\]//g" > $DOMAIN/ip_list
      cat all.txt | sort -u | grep -v [1-3]m...| awk '{print $1}'  > $DOMAIN/subdomain/apisub.txt
      cat all.txt | awk '{print $1}' | sort -u | grep api >> $DOMAIN/subdomain/apisub.txt
  }

  webprobe_full(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$WEBPROBEFULL" = true ]; then
      start_func ${FUNCNAME[0]} "Http probing non standard ports"
      if [ -s "subdomains/subdomains.txt" ]; then
          sudo nmap -iL subdomains/subdomains.txt -p $UNCOMMON_PORTS_WEB -oG .tmp/uncommon_nmap.gnmap 2>>"$LOGFILE" &>/dev/null
          cat .tmp/uncommon_nmap.gnmap | egrep -v "^#|Status: Up" | cut -d' ' -f2,4- | grep "open" | sed -e 's/\/.*$//g' | sed -e "s/ /:/g" | sort -u | anew -q .tmp/nmap_uncommonweb.txt
          cat .tmp/nmap_uncommonweb.txt | httpx -follow-host-redirects -random-agent -status-code -threads $HTTPX_UNCOMMONPORTS_THREADS -timeout $HTTPX_UNCOMMONPORTS_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color | anew .tmp/web_full_info_uncommon.txt | cut -d ' ' -f1 | anew -q .tmp/probed_uncommon_ports_tmp.txt
        
        [ -s ".tmp/web_full_info_uncommon.txt" ] && cat .tmp/web_full_info_uncommon.txt | anew -q webs/web_full_info_uncommon.txt

        [ -s ".tmp/web_full_info_uncommon.txt" ] && cat .tmp/web_full_info_uncommon.txt 2>>"$LOGFILE" | anew -q webs/web_full_info_uncommon.txt
      fi
      NUMOFLINES=$(cat .tmp/probed_uncommon_ports_tmp.txt 2>>"$LOGFILE" | anew webs/webs_uncommon_ports.txt | wc -l)
      notification "Uncommon web ports: ${NUMOFLINES} new websites" good
      [ -s "webs/webs_uncommon_ports.txt" ] && cat webs/webs_uncommon_ports.txt
      rm -rf "unimap_logs" 2>>"$LOGFILE"
      end_func "Results are saved in $domain/webs/webs_uncommon_ports.txt" ${FUNCNAME[0]}
      if [ "$PROXY" = true ] && [ -n "$proxy_url" ] && [[ $(cat webs/webs_uncommon_ports.txt| wc -l) -le $DEEP_LIMIT2 ]]; then
        notification "Sending websites uncommon ports to proxy" info
        ffuf -mc all -fc 404 -w webs/webs_uncommon_ports.txt -u FUZZ -replay-proxy $proxy_url 2>>"$LOGFILE" &>/dev/null
      fi
    fi
  }

  screenshot(){
    if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] ; then
      start_func "Web Screenshots"
      cat webs/webs.txt webs/webs_uncommon_ports.txt 2>>"$LOGFILE" | anew -q .tmp/webs_screenshots.txt
      [ -s ".tmp/webs_screenshots.txt" ] && aquatone -chrome-path ~/chrome-linux/chrome -out $PROJECT/aquatone 2>>"$LOGFILE" &>/dev/
      end_func "Results are saved in $DOMAIN/screenshots folder" ${FUNCNAME[0]}
    else
      if [ "$WEBSCREENSHOT" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

########################################################################################################
######################################### Cloud Detection ##############################################
########################################################################################################

  s3buckets(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$S3BUCKETS" = true ] && ! [[ $DOMAIN =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
      start_func "AWS S3 buckets search"

      # S3Scanner
        [ -s "subdomains/subdomains.txt" ] && s3scanner scan -f subdomains/subdomains.txt | grep -iv "not_exist" | grep -iv "Warning:" | grep -iv "ERROR" | grep -v "NoSuchBucket"| anew -q .tmp/s3buckets.txt
    
      # Cloudenum
      keyword=${DOMAIN%%.*}
      python3 ~/Tools/cloud_enum/cloud_enum.py -k $keyword -qs -l .tmp/output_cloud.txt 2>>"$LOGFILE" &>/dev/null
      # python3 $CLOUD_ENUM_PATH -m $CLOUD_ENUM_WORDLIST_PATH -kf "$1/subdomains.txt" -l "$1/cloud_enum.txt"
      # TODO: add cloud brute https://github.com/gdraperi/slurp-1
      # https://github.com/RhinoSecurityLabs/GCPBucketBrute
      # https://github.com/appsecco/spaces-finder   digital ocean
      # slurp domain -t sixt.com
      NUMOFLINES1=$(cat .tmp/output_cloud.txt 2>>"$LOGFILE" | sed '/^#/d' | sed '/^$/d' | anew subdomains/cloud_assets.txt | wc -l)
      if [ "$NUMOFLINES1" -gt 0 ]; then
        notification "${NUMOFLINES} new cloud assets found" info
      fi
      NUMOFLINES2=$(cat .tmp/s3buckets.txt 2>>"$LOGFILE" | anew subdomains/s3buckets.txt | wc -l)
      if [ "$NUMOFLINES2" -gt 0 ]; then
        notification "${NUMOFLINES} new S3 buckets found" info
      fi      

      end_func "Results are saved in subdomains/s3buckets.txt and subdomains/cloud_assets.txt" ${FUNCNAME[0]}
    else
      if [ "$S3BUCKETS" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  cloudprovider(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$CLOUD_IP" = true ]; then
      start_func "Cloud provider check"
      # change this file ip
      if [ -s "$dir/hosts/ips.txt" ]; then
        for ip in $( cat "$dir/hosts/ips.txt" ); do 
          echo "$( echo -n ${ip} && echo -n " " && clouddetect -ip=${ip} )" | grep -iv "Error" | anew -q $dir/hosts/cloud_providers.txt
            # git clone https://github.com/m0rtem/CloudFail.git
            # cd CloudFail
            # pip3 install -r requirements.txt
            python3 cloudfail.py --target fireeye.com 
        done
      fi
      end_func "Results are saved in hosts/cloud_providers.txt" ${FUNCNAME[0]}
    else
      if [ "$CLOUD_IP" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

########################################################################################################
########################################## HOST DETECTION ##############################################
########################################################################################################

  portscan(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$PORTSCANNER" = true ]; then
      start_func "Port scan"
      interlace -tL subdomains/subdomains.txt -threads 50 -c 'echo "_target_ $(dig +short a _target_ | tail -n1)" | anew -q _output_' -o .tmp/subs_ips.txt
      [ -s ".tmp/subs_ips.txt" ] && awk '{ print $2 " " $1}' .tmp/subs_ips.txt | sort -k2 -n | anew -q hosts/subs_ips_vhosts.txt
      [ -s "hosts/subs_ips_vhosts.txt" ] && cat hosts/subs_ips_vhosts.txt | cut -d ' ' -f1 | grep -Eiv "^(127|10|169\.154|172\.1[6789]|172\.2[0-9]|172\.3[01]|192\.168)\." | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | anew -q hosts/ips.txt
  
      [ -s "hosts/ips.txt" ] && cat hosts/ips.txt | cf-check | grep -Eiv "^(127|10|169\.154|172\.1[6789]|172\.2[0-9]|172\.3[01]|192\.168)\." | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | anew -q .tmp/ips_nowaf.txt	

      printf "${bblue}\n Resolved IP addresses (No WAF) ${reset}\n\n";
      [ -s ".tmp/ips_nowaf.txt" ] && cat .tmp/ips_nowaf.txt | sort -u
      printf "${bblue}\n Scanning ports... ${reset}\n\n";
      if [ ! -f "hosts/portscan_passive.txt" ] && [ -s "hosts/ips.txt" ] ; then
        for sub in $(cat hosts/ips.txt); do
          shodan host $sub 2>/dev/null >> hosts/portscan_passive.txt && echo -e "\n\n#######################################################################\n\n" >> hosts/portscan_passive.txt
        done
      fi
      [ -s ".tmp/ips_nowaf.txt" ] && sudo nmap --top-ports 200 -sV -n --max-retries 2 -Pn --open -iL .tmp/ips_nowaf.txt -oA hosts/portscan_active 2>>"$LOGFILE" &>/dev/null
      # TODO: Check results of diff output types not great o/p for automated testing 
      [ -s "hosts/portscan_active.xml" ] && searchsploit --nmap hosts/portscan_active.xml 2>>"$LOGFILE" > hosts/searchsploit.txt
      # https://github.com/1N3/Findsploit
      end_func "Results are saved in hosts/portscan_[passive|active].txt" ${FUNCNAME[0]}
    else
      if [ "$PORTSCANNER" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  nmaps_scan(){
    # git clone https://github.com/scipag/vulscan scipag_vulscan
    # https://github.com/chinarulezzz/nmap-extra-scripts 
    rustscan -r 1-65535 -a 104.18.22.208 --ulimit 8000 -- -A -Pn -sV -V -n -O -oG -sS -sU -sn -oA full -T3 --script=vulscan
  }

  spraying(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SPRAY" = true ]; then
      start_func "Password spraying"
      cd "$TOOL_PATH/brutespray" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
      python3 $BRUTESPRAY --file $PROJECT/hosts/portscan_active.gnmap  --threads $BRUTESPRAY_THREADS --hosts $BRUTESPRAY_CONCURRENCE -o $PROJECT/hosts/brutespray 2>>"$LOGFILE" &>/dev/null
      cd "$PROJECT" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
      end_func "Results are saved in hosts/brutespray folder" ${FUNCNAME[0]}
    else
      if [ "$SPRAY" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

########################################################################################################
####################################### CONTENT DISCOVERY ##############################################
########################################################################################################

  waf_checks(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$WAF_DETECTION" = true ]; then
      start_func "Website's WAF detection"
      if [ -s "./webs/webs.txt" ]; then
          wafw00f -i webs/webs.txt -o .tmp/wafs.txt 2>>"$LOGFILE" &>/dev/null
          gotestwaf --url=https://movie-portal.sixt.com --reportPath /home/work/Desktop   
        if [ -s ".tmp/wafs.txt" ]; then
          cat .tmp/wafs.txt | sed -e 's/^[ \t]*//' -e 's/ \+ /\t/g' -e '/(None)/d' | tr -s "\t" ";" > webs/webs_wafs.txt
          NUMOFLINES=$(cat webs/webs_wafs.txt 2>>"$LOGFILE" | wc -l)
          notification "${NUMOFLINES} websites protected by waf" info
          end_func "Results are saved in $DOMAIN/webs/webs_wafs.txt" ${FUNCNAME[0]}
        else
          end_func "No results found" ${FUNCNAME[0]}
        fi
      else
        end_func "No websites to scan" ${FUNCNAME[0]}
      fi
    else
      if [ "$WAF" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  cms_scanner(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$CMS_SCANNER" = true ]; then
      start_func "CMS Scanner"
      if [ -s "./webs/webs.txt" ]; then
        tr '\n' ',' < webs/webs.txt > .tmp/cms.txt
        timeout -k 20m python3 $CMSEEK -l .tmp/cms.txt --batch -r 2>>"$LOGFILE" &>/dev/null
        exit_status=$?
        if [[ $exit_status -eq 125 ]]; then
          echo "TIMEOUT cmseek.py - investigate manually for $dir" &>>"$LOGFILE"
          end_func "TIMEOUT cmseek.py - investigate manually for $dir" ${FUNCNAME[0]}
          return
        elif [[ $exit_status -ne 0 ]]; then
          echo "ERROR cmseek.py - investigate manually for $dir" &>>"$LOGFILE"
          end_func "ERROR cmseek.py - investigate manually for $dir" ${FUNCNAME[0]}
          return
        fi	# otherwise Assume we have a successfully exited cmseek
        for sub in $(cat webs/webs.txt); do
          sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||')
          cms_id=$(cat $TOOL_PATH/CMSeeK/Result/${sub_out}/cms.json 2>>"$LOGFILE" | jq -r '.cms_id')
          if [ -z "$cms_id" ]; then
            rm -rf $TOOL_PATH/CMSeeK/Result/${sub_out}
          else
            mv -f $TOOL_PATH/CMSeeK/Result/${sub_out} $dir/cms/
          fi
        done
        end_func "Results are saved in $DOMAIN/cms/*subdomain* folder" ${FUNCNAME[0]}
      else
        end_func "No $DOMAIN/web/webs.txts file found, cms scanner skipped" ${FUNCNAME[0]}
      fi
    else
      if [ "$CMS_SCANNER" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  fuzz(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$FUZZ" = true ]; then
      start_func "Web directory fuzzing"
      if [ -s "webs/webs.txt" ]; then
        mkdir -p $dir/fuzzing
        interlace -tL webs/webs.txt -threads 10 -c "ffuf -mc all -fc 404 -ac -t ${FFUF_THREADS} -sf -s -H \"${HEADER}\" -w ${fuzz_wordlist} -maxtime ${FFUF_MAXTIME} -u  _target_/FUZZ -of csv -o _output_/_cleantarget_.csv" -o fuzzing 2>>"$LOGFILE" &>/dev/null
        for sub in $(cat webs/webs.txt); do
          sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||')
          [ -s "$dir/fuzzing/${sub_out}.csv" ] && cat $dir/fuzzing/${sub_out}.csv | cut -d ',' -f2,5,6 | tr ',' ' ' | awk '{ print $2 " " $3 " " $1}' | tail -n +2 | sort -k1 | anew -q $dir/fuzzing/${sub_out}.txt
          rm -f $dir/fuzzing/${sub_out}.csv 2>>"$LOGFILE"
        done
        find $dir/fuzzing/ -type f -iname "*.txt" -exec cat {} + 2>>"$LOGFILE" | anew -q $dir/fuzzing/fuzzing_full.txt
        end_func "Results are saved in $DOMAIN/fuzzing/*subdomain*.txt" ${FUNCNAME[0]}
      else
        end_func "No $DOMAIN/web/webs.txts file found, fuzzing skipped " ${FUNCNAME[0]}
      fi
    else
      if [ "$FUZZ" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  urlchecks(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$URL_CHECK" = true ]; then
      start_func "URL Extraction"
      mkdir -p js
      if [ -s "webs/webs.txt" ]; then
        # cat webs/webs.txt | nuclei -t ~/nuclei-templates/headless/extract-urls.yaml -headless -silent -no-color | grep "^http" | anew -q .tmp/url_extract_tmp.txt
        [ ! -f temporary/dirhunt.txt ] && xargs -a domains/liveurls.txt -P 5 -I % bash -c "torsocks dirhunt %" 2> /dev/null | anew -q .tmp/url_extract_tmp.txt
        cat subdomains/subdomains.txt | hakrawler -subs -u -d 5 | anew -q .tmp/url_extract_tmp.txt
        cat subdomains/subdomains.txt | gauplus --random-agent -t 10 --subs| anew -q .tmp/url_extract_tmp.txt
        cat subdomains/subdomains.txt | waybackurls | anew -q .tmp/url_extract_tmp.txt
        [ -s "${GITHUB_TOKENS}" ] && github-endpoints -q -k -s -r -d $DOMAIN -t $(cat ~/tools/.tokens) -o .tmp/github-endpoints.txt 2>>"$LOGFILE" &>/dev/null
        # https://github.com/shahid1996/igoturls.git
        # python3 igoturls.py yourdomain.com
        #  https://github.com/IAmStoxe/urlgrab
        # git clone https://github.com/1N3/BlackWidow.git
        # cd BlackWidow
        # docker build -t blackwidow .
        # docker run -it blackwidow -d sixt.com -l 5 -s y -v y
        [ -s ".tmp/github-endpoints.txt" ] && cat .tmp/github-endpoints.txt | anew -q .tmp/url_extract_tmp.txt
        [ ! -f temporary/gospider.txt ] && timeout $GOSPIDER_TIMEOUT gospider -S sites.txt -t $GOSPIDER_THREADS --js -d 5 -a -w -r -c 20 -K 3 --blacklist ".(eot|css|tif|tiff|ttf|otf|woff|woff2|ico)" -o temporary/gospider 2> /dev/null | anew -q temporary/gospider.txt
      
        diff_webs=$(diff <(sort -u .tmp/probed_tmp.txt 2>>"$LOGFILE") <(sort -u webs/webs.txt 2>>"$LOGFILE") | wc -l)
        sed -i '/^.\{2048\}./d' .tmp/gospider.txt
        [ -s ".tmp/gospider.txt" ] && cat .tmp/gospider.txt | grep -Eo 'http?://[^ ]+' | sed 's/]$//' | grep "$DOMAIN" | anew -q .tmp/url_extract_tmp.txt
        cat temporary/gauplus.txt temporary/waybackurls.txt | sed '/\[/d' | grep $domain | sort -u | urldedupe -s | anew -q domains/endpoints.txt

        [ -s ".tmp/url_extract_tmp.txt" ] && cat .tmp/url_extract_tmp.txt | grep "${DOMAIN}" | grep -Ei "\.(js)" | anew -q js/url_extract_js.txt
        [ -s ".tmp/url_extract_tmp.txt" ] &&  cat .tmp/url_extract_tmp.txt | grep "${DOMAIN}" | grep "=" | qsreplace -a 2>>"$LOGFILE" | grep -Eiv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg|txt|js)$" | anew -q .tmp/url_extract_tmp2.txt
        [ -s ".tmp/url_extract_tmp2.txt" ] && cat .tmp/url_extract_tmp2.txt | urldedupe -s -qs | uro | anew -q .tmp/url_extract_uddup.txt 2>>"$LOGFILE" &>/dev/null
        NUMOFLINES=$(cat .tmp/url_extract_uddup.txt 2>>"$LOGFILE" | anew webs/url_extract.txt | wc -l)
        notification "${NUMOFLINES} new urls with params" info
        end_func "Results are saved in $DOMAIN/webs/url_extract.txt" ${FUNCNAME[0]}
        if [ "$PROXY" = true ] && [ -n "$proxy_url" ] && [[ $(cat webs/url_extract.txt | wc -l) -le 1500 ]]; then
          notification "Sending urls to proxy" info
          ffuf -mc all -fc 404 -w webs/url_extract.txt -u FUZZ -replay-proxy $proxy_url 2>>"$LOGFILE" &>/dev/null
        fi
      fi
    else
      printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
    fi
  }

  url_gf(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$URL_GF" = true ]; then
      start_func "Vulnerable Pattern Search"
      mkdir -p gf
      if [ -s "webs/url_extract.txt" ]; then
        for gf_pattern in $(ls ~/.gf);do
          gf $gf_pattern webs/url_extract.txt > $DOMAIN/vulnerable_files/$gf_pattern 
          if [ ! -f "$DOMAIN/vulnerable_files/$gf_pattern" ]; then
              notification "vulnerable files found with $gf_pattern"
          fi
        done
        cat domains/endpoints.txt | gf xss | sed "s/'\|(\|)//g" | qsreplace "FUZZ" 2> /dev/null | anew -q domains/patterns/xss.txt
        cat ~/tools/payloads/lfipayloads.txt | while read -r line; do cat domains/patterns/lfi.txt | qsreplace "$line" 2> /dev/null | anew -q temporary/lfi.txt;done
        gf xss webs/url_extract.txt | anew -q gf/xss.txt
        gf ssti webs/url_extract.txt | anew -q gf/ssti.txt
        gf ssrf webs/url_extract.txt | anew -q gf/ssrf.txt
        gf sqli webs/url_extract.txt | anew -q gf/sqli.txt
        gf redirect webs/url_extract.txt | anew -q gf/redirect.txt
        [ -s "gf/ssrf.txt" ] && cat gf/ssrf.txt | anew -q gf/redirect.txt
        gf rce webs/url_extract.txt | anew -q gf/rce.txt
        gf potential webs/url_extract.txt | cut -d ':' -f3-5 |anew -q gf/potential.txt
        [ -s ".tmp/url_extract_tmp.txt" ] && cat .tmp/url_extract_tmp.txt | grep -Eiv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg|txt|js)$" | unfurl -u format %s://%d%p 2>>"$LOGFILE" | anew -q gf/endpoints.txt
        gf lfi webs/url_extract.txt | anew -q gf/lfi.txt
        
      fi
      end_func "Results are saved in $DOMAIN/gf folder" ${FUNCNAME[0]}
    else
      if [ "$URL_GF" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  url_ext(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$URL_EXT" = true ]; then
      if [ -s ".tmp/url_extract_tmp.txt" ]; then
        start_func "Urls by extension"
        ext=("7z" "achee" "action" "adr" "apk" "arj" "ascx" "asmx" "asp" "aspx" "axd" "backup" "bak" "bat" "bin" "bkf" "bkp" "bok" "cab" "cer" "cfg" "cfm" "cfml" "cgi" "cnf" "conf" "config" "cpl" "crt" "csr" "csv" "dat" "db" "dbf" "deb" "dmg" "dmp" "doc" "docx" "drv" "email" "eml" "emlx" "env" "exe" "gadget" "gz" "html" "ica" "inf" "ini" "iso" "jar" "java" "jhtml" "json" "jsp" "key" "log" "lst" "mai" "mbox" "mbx" "md" "mdb" "msg" "msi" "nsf" "ods" "oft" "old" "ora" "ost" "pac" "passwd" "pcf" "pdf" "pem" "pgp" "php" "php3" "php4" "php5" "phtm" "phtml" "pkg" "pl" "plist" "pst" "pwd" "py" "rar" "rb" "rdp" "reg" "rpm" "rtf" "sav" "sh" "shtm" "shtml" "skr" "sql" "swf" "sys" "tar" "tar.gz" "tmp" "toast" "tpl" "txt" "url" "vcd" "vcf" "wml" "wpd" "wsdl" "wsf" "xls" "xlsm" "xlsx" "xml" "xsd" "yaml" "yml" "z" "zip")
        for t in "${ext[@]}"; do
          NUMOFLINES=$(cat .tmp/url_extract_tmp.txt | grep -Ei "\.(${t})($|\/|\?)" | sort -u | wc -l)
          if [[ ${NUMOFLINES} -gt 0 ]]; then
            echo -e "\n############################\n + ${t} + \n############################\n" >> webs/urls_by_ext.txt
            cat .tmp/url_extract_tmp.txt | grep -Ei "\.(${t})($|\/|\?)" >> webs/urls_by_ext.txt
          fi
        done
        runBanner "url cleaning and sorting"
          cat gospider.txt |grep linkfinder\] | awk '{print $3}' | sort -u  >> waybackurls.txt
          cat gospider.txt |grep robots\] | awk '{print $3}' | sort -u >> waybackurls.txt
          cat gospider.txt |grep  sitemap\] | awk '{print $3}' | sort -u >> waybackurls.txt
          cat gospider.txt | grep "url\]" | grep "\[code-2"  | awk '{print $5}'  | egrep -vi ".(htm|zip|jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|xml|json|yaml|pdf|svg|txt|asp|net|js|php|html)" | sort -u >  $DOMAIN/urls/2xx.txt
          cat gospider.txt | grep "url\]" | grep "\[code-4" | grep -v "code-404" | awk '{print $5}' | sort -u > 4xx.txt
          cat gospider.txt | grep "url\]" | grep "\[code-5" | awk '{print $5}' | sort -u > 5xx.txt
          cat gospider.txt | grep "form\]" | sort -u >  $DOMAIN/urls/form	
          cat gospider.txt | grep "aws-s3\]" | sort -u | tee  $DOMAIN/urls/aws_s3
          cat gospider.txt | grep "url\]"| grep "\[code-2"  | awk '{print $5}'| grep "\.html" >> html.txt
          cat gospider.txt | grep "url\]"| grep "\[code-2"  | awk '{print $5}'| grep "\.php" >> php.txt
          cat gospider.txt | grep "url\]"| grep "\[code-2"  | awk '{print $5}'  | grep -v "\.js" >> js.txt
          cat gospider.txt | grep "javascript\]" | awk '{print $3}'|sort -u >> js.txt
          cat gospider.txt | grep -v "form\]" | grep -v "javascript\]" | grep -v "linkfinder\]" | grep -v "robots\]" | grep -v "sitemap\]" | grep -v subdomains | grep -v url | grep -v "aws\-s3" |sort -u | tee  $DOMAIN/urls/checkurl

          cat waybackurls.txt | grep "\.html" | sort -u >>  html.txt
          cat waybackurls.txt | grep -v "\.json" | grep "\.js" >>  js.txt
          cat waybackurls.txt | grep "\.php" >>  php.txt
          cat waybackurls.txt  | egrep -vi ".(htm|zip|jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|xml|json|yaml|pdf|svg|txt|asp|net|js|php|html)" | sort -u > tmp
          cat tmp | httpx -threads 200 -status-code -silent -follow-redirects -ports 80 ,443 ,3000 ,8443 ,8443 ,8080 ,8080 ,8008 ,8008 ,5000 ,5800 ,5800 ,7001 ,7000 ,9080 ,9443 > allurls.txt
          cat allurls.txt | grep 2m20[0-9] | awk '{print $1}' >> 2xx.txt 
          cat allurls.txt | grep 1m40[1-3] | awk '{print $1}' >> 4xx.txt 
          cat allurls.txt | grep 3m5.. | awk '{print $1}' >> 5xx.txt
          cat allurls.txt | awk '{print $1}' > $DOMAIN/urls/allurls  

        # sorting and deleting old files
          cat 2xx.txt | sort -u > $DOMAIN/urls/2xx 
          cat 4xx.txt | sort -u > $DOMAIN/urls/4xx 
          cat 5xx.txt | sort -u > $DOMAIN/urls/5xx 
          cat html.txt | sort -u > $DOMAIN/urls/html 
          cat php.txt | sort -u  > $DOMAIN/urls/php 
          cat waybackurls.txt| sort -u > $DOMAIN/waybackurls  
          cat js.txt |sort -u| subjs -c 140 >  $DOMAIN/urls/javascript
          cat javascript | sort -u >  $DOMAIN/urls/js 
          cat 2xx  | egrep  "\?|\=" | qsreplace   >  $DOMAIN/urls/params
        #cleaning the output folder
          rm php.txt html.txt waybackurls.txt 4xx.txt 2xx.txt  5xx.txt  javascript js.txt
          rm tmp.txt all.txt allurls.txt wayback.txt gospider.txt tmp
          
        end_func "Results are saved in $DOMAIN/webs/urls_by_ext.txt" ${FUNCNAME[0]}
      fi
    else
      if [ "$URL_EXT" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  jschecks(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$JSCHECKS" = true ]; then
      start_func "Javascript Scan"
      if [ -s "js/url_extract_js.txt" ]; then

        printf "${yellow} Running : Fetching Urls 1/5${reset}\n"
          cat $DOMAIN/urls/2xx  | getJS -complete -output alive-js-files.txt
          cat js/url_extract_js.txt | subjs -c 40 | grep "$DOMAIN" | anew -q .tmp/subjslinks.txt
          [ -s .tmp/subjslinks.txt ] && cat .tmp/subjslinks.txt | egrep -iv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg|txt|js)" | anew -q js/nojs_links.txt
          [ -s .tmp/subjslinks.txt ] && cat .tmp/subjslinks.txt | grep -iE "\.js" | anew -q js/url_extract_js.txt
        printf "${yellow} Running : Resolving JS Urls 2/5${reset}\n"
          [ -s "js/url_extract_js.txt" ] && cat js/url_extract_js.txt | httpx -follow-redirects -random-agent -silent -timeout $HTTPX_TIMEOUT -threads $HTTPX_THREADS -status-code -retries 2 -no-color | grep "[200]" | cut -d ' ' -f1 | anew -q js/js_livelinks.txt
      
        printf "${yellow} Running : Gathering endpoints 3/5${reset}\n"
          if [ -s "js/js_livelinks.txt" ]; then
            interlace -tL js/js_livelinks.txt -threads 10 -c "python3 $TOOL_PATH/LinkFinder/linkfinder.py -d -i _target_ -o cli >> .tmp/js_endpoints.txt" &>/dev/null
          fi
          python3 sourcewolf.py -t 15 -l subdomains/subdomains.txt -o sourcewolf.txt -c sourcewolf_Crawler.txt
          cat $target/urls/allurls | cariddi -intensive  -s  -e -c 200 -ext 1 
          interlace -tL live_jsfile_links.txt -threads 5 -c "bash ./tools/getjsbeautify.sh _target_" -v
          if [ -s ".tmp/js_endpoints.txt" ]; then
            sed -i '/^\//!d' .tmp/js_endpoints.txt
            cat .tmp/js_endpoints.txt | anew -q js/js_endpoints.txt
          fi
        printf "${yellow} Running : Gathering secrets 4/5${reset}\n"

          interlace -tL temporary/jslinks.txt -threads 5 -c "bash $DOMXSS _target_" -v
          interlace -tL live_jsfile_links.txt -threads 5 -c "python3 ./tools/SecretFinder/SecretFinder.py -i _target_ -o cli >> jslinksecret.txt" -v
          [ -s "js/js_livelinks.txt" ] && cat js/js_livelinks.txt | nuclei -silent -t ~/nuclei-templates/ -tags exposure,token -r $resolvers_trusted -o js/js_secrets.txt 2>>"$LOGFILE" &>/dev/null
        
        printf "${yellow} Running : Building wordlist 5/5${reset}\n"
          [ -s "js/js_livelinks.txt" ] && cat js/js_livelinks.txt | python3 $TOOL_PATH/getjswords.py 2>>"$LOGFILE" | anew -q webs/dict_words.txt
          if [ -s "webs/webs.txt" ]; then
          wordlist_gen
            cat webs/webs.txt | roboxtractor -m 1 -wb 2>>"$LOGFILE" | anew -q webs/robots_wordlist.txt
          fi
        end_func "Results are saved in $DOMAIN/js folder" ${FUNCNAME[0]}
      else
        end_func "No JS urls found for $DOMAIN, skipped" ${FUNCNAME[0]}
      fi
    else
      if [ "$JSCHECKS" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  hidden_parameters(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$HIDDEN_PARAMETERS" = true ]; then
      start_func "Website's hidden parameters"
      if [ -s "./webs/webs.txt" ]; then
        interlace -tL .subdomains/allsubdomains.txt -threads 10 -c "ParamSpider --level high --domain _target_ -o temporary/params " 2>>"$LOGFILE"  &>/dev/null
        Parameth [https://github.com/maK-/parameth]
        Arjun -i targets.txt -t 12 -T 10 -oT temporary/params.txt
        # https://github.com/s0md3v/Parth
        NUMOFLINES=$(cat webs/webs_wafs.txt 2>>"$LOGFILE" | wc -l)
        notification "${NUMOFLINES} websites protected by waf" info
        end_func "No results found" ${FUNCNAME[0]}
      fi
     else
        end_func "No websites to scan" ${FUNCNAME[0]}
    fi
  }

  wordlist_gen(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$WORDLIST" = true ];	then
      start_func "Wordlist generation"
      if [ -s ".tmp/url_extract_tmp.txt" ]; then
        cat .tmp/url_extract_tmp.txt | unfurl -u keys 2>>"$LOGFILE" | sed 's/[][]//g' | sed 's/[#]//g' | sed 's/[}{]//g' | anew -q webs/dict_params.txt
        cat .tmp/url_extract_tmp.txt | unfurl -u values 2>>"$LOGFILE" | sed 's/[][]//g' | sed 's/[#]//g' | sed 's/[}{]//g' | anew -q webs/dict_values.txt
        cat .tmp/url_extract_tmp.txt | tr "[:punct:]" "\n" | anew -q webs/dict_words.txt
      fi
      [ -s ".tmp/js_endpoints.txt" ] && cat .tmp/js_endpoints.txt | unfurl -u format %s://%d%p 2>>"$LOGFILE" | anew -q webs/all_paths.txt
      [ -s ".tmp/url_extract_tmp.txt" ] && cat .tmp/url_extract_tmp.txt | unfurl -u format %s://%d%p 2>>"$LOGFILE" | anew -q webs/all_paths.txt
      end_func "Results are saved in $DOMAIN/webs/dict_[words|paths].txt" ${FUNCNAME[0]}
      if [ "$PROXY" = true ] && [ -n "$proxy_url" ] && [[ $(cat webs/all_paths.txt | wc -l) -le 1500 ]]; then
        notification "Sending urls to proxy" info
        ffuf -mc all -fc 404 -w webs/all_paths.txt -u FUZZ -replay-proxy $proxy_url 2>>"$LOGFILE" &>/dev/null
      fi
    else
      if [ "$WORDLIST" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

########################################################################################################
###################################### VULNERABILITIES SCANNER #########################################
########################################################################################################

  jaeles_check(){
    if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ] && [ "$JAELESCHECK" = true ]; then
      start_func "Templates based web scanner"
      mkdir -p jaeles_output
        jaeles config update --repo https://github.com/ghsec/ghsec-jaeles-signatures 
        cat $DOMAIN/subdomain/200sub.txt | jaeles scan -c 100 -L2 p 'dest=xxx.burpcollaborator.net' -f 'noti_slack "{{.vulnInfo}}"' -o $DOMAIN/jaeles 
        printf "${yellow}\n Running : jaeles Info${reset}\n\n"
        cat subdomains/subdomains.txt webs/webs.txt 2>/dev/null | jaeles -silent -t ~/jaeles-templates/ -severity info -r $resolvers_trusted -o jaeles_output/info.txt
        printf "${yellow}\n\n Running : jaeles Low${reset}\n\n"
        cat subdomains/subdomains.txt webs/webs.txt 2>/dev/null | jaeles -silent -t ~/jaeles-templates/ -severity low -r $resolvers_trusted -o jaeles_output/low.txt
        printf "${yellow}\n\n Running : jaeles Medium${reset}\n\n"
        cat subdomains/subdomains.txt webs/webs.txt 2>/dev/null | jaeles -silent -t ~/jaeles-templates/ -severity medium -r $resolvers_trusted -o jaeles_output/medium.txt
        printf "${yellow}\n\n Running : jaeles High${reset}\n\n"
        cat subdomains/subdomains.txt webs/webs.txt 2>/dev/null | jaeles -silent -t ~/jaeles-templates/ -severity high -r $resolvers_trusted -o jaeles_output/high.txt
        printf "${yellow}\n\n Running : jaeles Critical${reset}\n\n"
        cat subdomains/subdomains.txt webs/webs.txt 2>/dev/null | jaeles -silent -t ~/jaeles-templates/ -severity critical -r $resolvers_trusted -o jaeles_output/critical.txt

        printf "\n\n"

      end_func "Results are saved in $DOMAIN/jaeles_output folder" ${FUNCNAME[0]}
    else
      if [ "$JAELESCHECK" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  nuclei_check(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$NUCLEICHECK" = true ]; then
      start_func "Templates based web scanner"
      nuclei -update-templates 2>>"$LOGFILE" &>/dev/null
      mkdir -p nuclei_output
        [ ! -f nuclei/info.txt ] && xargs -a domains/liveurls.txt -P 5 -I % bash -c "nuclei -target % -t ~/nuclei-templates/ -r $resolvers_trusted -severity info -c 50 -silent" 2> /dev/null | anew nuclei/info.txt |$NOTIFY -id vuln 
        [ ! -f nuclei/low.txt ] && xargs -a domains/liveurls.txt -P 5 -I % bash -c "nuclei -target % -t ~/nuclei-templates/ -r $resolvers_trusted -severity low -c 50 -silent" 2> /dev/null | anew nuclei/low.txt | $NOTIFY -id vuln &> /dev/null
        [ ! -f nuclei/medium.txt ] && xargs -a domains/liveurls.txt -P 5 -I % bash -c "nuclei -target % -t ~/nuclei-templates/ -r $resolvers_trusted -severity medium -c 50 -silent" 2> /dev/null | anew nuclei/medium.txt | $NOTIFY -id vuln &> /dev/null
        [ ! -f nuclei/high.txt ] && xargs -a domains/liveurls.txt -P 5 -I % bash -c "nuclei -target % -t ~/nuclei-templates/ -r $resolvers_trusted -severity high -c 50 -silent" 2> /dev/null | anew nuclei/high.txt | $NOTIFY -id vuln &> /dev/null
        [ ! -f nuclei/critical.txt] && xargs -a domains/liveurls.txt -P 5 -I % bash -c "nuclei -target % -t ~/nuclei-templates/ -r $resolvers_trusted -severity critical -c 50 -silent" 2> /dev/null | anew nuclei/critical.txt | $NOTIFY -id vuln &> /dev/null
        printf "\n\n"

      end_func "Results are saved in $DOMAIN/nuclei_output folder" ${FUNCNAME[0]}
    else
      if [ "$NUCLEICHECK" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

########################################################################################################
################################### DOMAIN LEVEL VULNERABILITIES #######################################
########################################################################################################
  test_ssl(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$TEST_SSL" = true ]; then
      start_func "SSL Test"
      $TESTSSL --quiet --color 0 -U -iL hosts/ips.txt 2>>"$LOGFILE" > hosts/testssl.txt
      end_func "Results are saved in hosts/testssl.txt" ${FUNCNAME[0]}
    else
      if [ "$TEST_SSL" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  subtakeover(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBTAKEOVER" = true ]; then
      start_func "Looking for possible subdomain and DNS takeover"
      touch .tmp/tko.txt
      cat subdomains/subdomains.txt webs/webs.txt 2>/dev/null | nuclei -silent -t ~/nuclei-templates/takeovers/ -r $resolvers_trusted -o .tmp/tko.txt
      tko-subs -domains=$DOMAIN/subdomains.txt -data=../config/providers-data.csv  -threads 50 -output=op.csv &> /dev/null
      cat op.csv | grep -v elb.amazon | grep true |tee -a $DOMAIN/attack/STKO 
      rm op.csv tmp;
      cat subdomains/subdomains.txt | dnstake -c 20 -s 2>>"$LOGFILE" | anew -q .tmp/tko.txt      
      NUMOFLINES=$(cat .tmp/tko.txt 2>>"$LOGFILE" | anew webs/takeover.txt | wc -l)
      if [ "$NUMOFLINES" -gt 0 ]; then
        notification "${NUMOFLINES} new possible takeovers found" info
      fi
      
      end_func "Results are saved in $DOMAIN/webs/takeover.txt" ${FUNCNAME[0]}
    else
      if [ "$SUBTAKEOVER" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  submisconfig(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBMISCONFIG" = true ]; then
      start_func "Zone transfer check"
      python3 $DNSRECON -d $DOMAIN -a -j subdomains/zonetransfer.json 2>>"$LOGFILE" &>/dev/null
      $CORSTEST -p 75 $DOMAIN/subdomains.txt > tmp
      cat tmp | grep -v "Error:" | grep -v "Not vulnerable:" >> $DOMAIN/attack/cors
      python3 $CORSY -i webs/webs.txt > webs/cors.txt 2>>"$LOGFILE" &>/dev/null
      $SPOOFCHECK $DOMAIN >> $DOMAIN/attack/spoofcheck 
      [ -s "webs/cors.txt" ] && cat webs/cors.txt
      if [ -s "subdomains/zonetransfer.json" ]; then
        if grep -q "\"zone_transfer\"\: \"success\"" subdomains/zonetransfer.json ; then notification "Zone transfer found on ${DOMAIN}!" info; fi
      fi
      if [ -s "subdomains/spoofcheck" ]; then
        if grep -q "\"zone_transfer\"\: \"success\"" subdomains/zonetransfer.json ; then notification "Zone transfer found on ${DOMAIN}!" info; fi
      fi
      if [ -s "subdomains/cors" ]; then
        if grep -q "\"zone_transfer\"\: \"success\"" subdomains/zonetransfer.json ; then notification "Zone transfer found on ${DOMAIN}!" info; fi
      fi
      end_func "Results are saved in $DOMAIN/subdomains/zonetransfer.txt" ${FUNCNAME[0]}
    else
      if [ "$SUBMISCONFIG" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

########################################################################################################
################################# APPLICATION LEVEL VULNERABILITIES ####################################
########################################################################################################

  host_Header(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$HOST_HEADER" = true ]; then
      start_func "Host Header Injection"
      interlace -tL .subdomains/allsubdomains.txt -threads 10 -c " python3 $HOSTPANIC -r -u _target_ " -o  hosts/hostheader.txt 2>>"$LOGFILE"  &>/dev/null
      https://github.com/mlcsec/headi
      end_func "Results are saved in hosts/hostheader.txt" ${FUNCNAME[0]}
    else
      if [ "$HOST_HEADER" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  Request_Smuggling(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$REQ_SMUGGING" = true ]; then
      start_func "Request Smuggling"
      interlace -tL .subdomains/allsubdomains.txt -threads 10 -c "request_smuggler --full -u _target_ " -o  hosts/reqsmugging.txt 2>>"$LOGFILE"  &>/dev/null
      cat subdomains/subdomains.txt | python3 $SMUGGLER 2>>"$LOGFILE" > hosts/reqsmugging.txt
      end_func "Results are saved in hosts/reqsmugging.txt" ${FUNCNAME[0]}
    else
      if [ "$REQ_SMUGGING" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  brokenLinks(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$BROKENLINKS" = true ] ; then
      start_func "Broken links checks"
        if [ ! -s ".tmp/gospider.txt" ]; then
            # https://github.com/stevenvachon/broken-link-checker
            # https://github.com/mhmdiaa/second-order
            [ -s "webs/webs.txt" ] && blc -rfoi --exclude linkedin.com --filter-level 3 -r -f https://example.com/
          fi
        [ -s ".tmp/gospider.txt" ] && sed -i '/^.\{2048\}./d' .tmp/gospider.txt

      NUMOFLINES=$(cat .tmp/brokenLinks_total.txt 2>>"$LOGFILE" | anew webs/brokenLinks.txt | wc -l)
      notification "${NUMOFLINES} new broken links found" info
      end_func "Results are saved in webs/brokenLinks.txt" ${FUNCNAME[0]}
    else
      if [ "$BROKENLINKS" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  bfac(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$BFAC" = true ] ; then
      start_func "Backup File Artifacts Checker"
        if [ ! -s ".tmp/gospider.txt" ]; then
            # https://github.com/mazen160/bfac
            [ -s "webs/webs.txt" ] && bfac --detection-technique all --list webs/webs.txt
          fi
        [ -s ".tmp/gospider.txt" ] && sed -i '/^.\{2048\}./d' .tmp/gospider.txt

      NUMOFLINES=$(cat .tmp/BFAC_total.txt 2>>"$LOGFILE" | anew webs/BFAC.txt | wc -l)
      notification "${NUMOFLINES} new Backup File Artifacts Checker found" info
      end_func "Results are saved in webs/BFAC.txt" ${FUNCNAME[0]}
    else
      if [ "$BFAC" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi

  }

  403_bypasses(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$BYPASS_403" = true ] ; then
      start_func "Checking for 403 bypass"
        if [ ! -s "web/4xx" ]; then
          # https://github.com/Raywando/4xxbypass 
          # https://github.com/iamj0ker/bypass-403
          $BYPASS_403 URL PATH
            base=$(echo "$(echo "$url" | cut -d/ -f1,2,3)")
            path=$(echo "/$(echo "$url" | cut -d/ -f4-)") #| sed 's/\/$//g')
          cat urls.txt | $BYPASS4xx
        fi

      NUMOFLINES=$(cat .tmp/403_bypass.txt 2>>"$LOGFILE" | anew vuln/403_bypass.txt | wc -l)
      notification "${NUMOFLINES} new 403 bypass found" info
      end_func "Results are saved in vuln/403_bypass.txt" ${FUNCNAME[0]}
    else
      if [ "$BYPASS_403" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi

  }

  xss(){
    if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ] && [ "$XSS" = true ] && [ -s "gf/xss.txt" ]; then
      start_func "XSS Analysis"
      [ -s "gf/xss.txt" ] && cat gf/xss.txt | qsreplace FUZZ | Gxss -c 100 -p Xss | qsreplace FUZZ | anew -q .tmp/xss_reflected.txt
        if [ -n "$XSS_SERVER" ]; then
          [ -s ".tmp/xss_reflected.txt" ] && cat .tmp/xss_reflected.txt | dalfox pipe --silence --no-color --no-spinner --mass --mass-worker 100 --multicast --skip-bav -b ${XSS_SERVER} -w $DALFOX_THREADS 2>>"$LOGFILE" | anew -q vulns/xss.txt
          cat urls/2xx | qsreplace -a | dalfox pipe -blind https://dash.xss.ht
          dalfox file urls_file --custom-payload ./mypayloads.txt
          python3 $XSSTRIKE_PATH --crawl --blind --params --skip --file-log-level VULN --log-file $logfile -u $site
        fi
      end_func "Results are saved in vulns/xss.txt" ${FUNCNAME[0]}
    else
      if [ "$XSS" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
        elif [ ! -s "gf/xss.txt" ]; then
            printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to XSS ${reset}\n\n"
        else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n";
      fi
    fi
  }

  open_redirect(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$OPEN_REDIRECT" = true ] && [ -s "gf/redirect.txt" ]; then
      start_func "Open redirects checks"
      if [ "$DEEP" = true ] || [[ $(cat gf/redirect.txt | wc -l) -le $DEEP_LIMIT ]]; then
        cat gf/redirect.txt | qsreplace FUZZ | anew -q .tmp/tmp_redirect.txt
        python3 $TOOL_PATH/Oralyzer/oralyzer.py -l .tmp/tmp_redirect.txt -p $TOOL_PATH/Oralyzer/payloads.txt > vulns/redirect.txt
        python3 ~/tools/OpenRedireX/openredirex.py -l $DOMAIN/vulnerabilities/openredirect/fuzzredirect.txt -p ~/tools/OpenRedireX/payloads.txt --keyword FUZZ | tee $DOMAIN/vulnerabilities/openredirect/confrimopenred.txt
        
        sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" vulns/redirect.txt
        end_func "Results are saved in vulns/redirect.txt" ${FUNCNAME[0]}
      else
        end_func "Skipping Open redirects: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
        printf "${bgreen}##############################################################${reset}\n"
      fi
    else
      if [ "$OPEN_REDIRECT" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      elif [ ! -s "gf/redirect.txt" ]; then
        printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to Open Redirect ${reset}\n\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  ssrf_checks(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SSRF_CHECKS" = true ] && [ -s "gf/ssrf.txt" ]; then
      start_func "SSRF checks"
      if [ -z "$COLLAB_SERVER" ]; then
        interactsh-client &>.tmp/ssrf_callback.txt &
        sleep 2
        COLLAB_SERVER_FIX=$(cat .tmp/ssrf_callback.txt | tail -n1 | cut -c 16-)
        COLLAB_SERVER_URL="http://$COLLAB_SERVER_FIX"
        INTERACT=true
      else
        COLLAB_SERVER_FIX=$(echo ${COLLAB_SERVER} | sed -r "s/https?:\/\///")
        INTERACT=false
      fi
        cat gf/ssrf.txt | qsreplace ${COLLAB_SERVER_FIX} | anew -q .tmp/tmp_ssrf.txt
        cat gf/ssrf.txt | qsreplace ${COLLAB_SERVER_URL} | anew -q .tmp/tmp_ssrf.txt
        ffuf -v -H "${HEADER}" -t $FFUF_THREADS -w .tmp/tmp_ssrf.txt -u FUZZ 2>>"$LOGFILE" | grep "URL" | sed 's/| URL | //' | anew -q vulns/ssrf_requests_url.txt
        ffuf -v -w .tmp/tmp_ssrf.txt:W1,$TOOL_PATH/headers_inject.txt:W2 -H "${HEADER}" -H "W2: ${COLLAB_SERVER_FIX}" -t $FFUF_THREADS -u W1 2>>"$LOGFILE" | anew -q vulns/ssrf_requests_headers.txt
        ffuf -v -w .tmp/tmp_ssrf.txt:W1,$TOOL_PATH/headers_inject.txt:W2 -H "${HEADER}" -H "W2: ${COLLAB_SERVER_URL}" -t $FFUF_THREADS -u W1 2>>"$LOGFILE" | anew -q vulns/ssrf_requests_headers.txt
        sleep 5
        [ -s ".tmp/ssrf_callback.txt" ] && cat .tmp/ssrf_callback.txt | tail -n+11 | anew -q vulns/ssrf_callback.txt && NUMOFLINES=$(cat .tmp/ssrf_callback.txt | tail -n+12 | wc -l)
        [ "$INTERACT" = true ] && notification "SSRF: ${NUMOFLINES} callbacks received" info
        end_func "Results are saved in vulns/ssrf_*" ${FUNCNAME[0]}
      pkill -f interactsh-client
    else
      if [ "$SSRF_CHECKS" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      elif [ ! -s "gf/ssrf.txt" ]; then
          printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to SSRF ${reset}\n\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  crlf_checks(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$CRLF_CHECKS" = true ]; then
      start_func "CRLF checks"
      if [ "$DEEP" = true ] || [[ $(cat webs/webs.txt | wc -l) -le $DEEP_LIMIT ]]; then
        crlfuzz -c 20 -l webs/webs.txt -o vulns/crlf.txt 2>>"$LOGFILE" &>/dev/null
        end_func "Results are saved in vulns/crlf.txt" ${FUNCNAME[0]}
      else
        end_func "Skipping CRLF: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
      fi
    else
      if [ "$CRLF_CHECKS" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  lfi(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$LFI" = true ] && [ -s "gf/lfi.txt" ]; then
      start_func "LFI checks"
      if [ -s "gf/lfi.txt" ]; then
        cat gf/lfi.txt | qsreplace FUZZ | anew -q .tmp/tmp_lfi.txt
        if [ "$DEEP" = true ] || [[ $(cat .tmp/tmp_lfi.txt | wc -l) -le $DEEP_LIMIT ]]; then
          interlace -tL .tmp/tmp_lfi.txt -threads 10 -c "ffuf -v -r -t ${FFUF_THREADS} -H \"${HEADER}\" -w ${lfi_wordlist} -u \"_target_\" -mr \"root:\" " 2>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q vulns/lfi.txt
          end_func "Results are saved in vulns/lfi.txt" ${FUNCNAME[0]}
        else
          end_func "Skipping LFI: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
        fi
      fi
    else
      if [ "$LFI" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      elif [ ! -s "gf/lfi.txt" ]; then
        printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to LFI ${reset}\n\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  ssti(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SSTI" = true ] && [ -s "gf/ssti.txt" ]; then
      start_func "SSTI checks"
      if [ -s "gf/ssti.txt" ]; then
        cat gf/ssti.txt | qsreplace FUZZ | anew -q .tmp/tmp_ssti.txt
        if [ "$DEEP" = true ] || [[ $(cat .tmp/tmp_ssti.txt | wc -l) -le $DEEP_LIMIT ]]; then
          interlace -tL .tmp/tmp_ssti.txt -threads 10 -c "ffuf -v -r -t ${FFUF_THREADS} -H \"${HEADER}\" -w ${ssti_wordlist} -u \"_target_\" -mr \"ssti49\" " 2>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q vulns/ssti.txt
          # git clone https://github.com/epinna/tplmap.git
          # ./tplmap.py -u 'http://www.target.com/page?name=John'
          end_func "Results are saved in vulns/ssti.txt" ${FUNCNAME[0]}
        else
          end_func "Skipping SSTI: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
        fi
      fi
    else
      if [ "$SSTI" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      elif [ ! -s "gf/ssti.txt" ]; then
        printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to SSTI ${reset}\n\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  sqli(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SQLI" = true ] && [ -s "gf/sqli.txt" ]; then
      start_func "SQLi checks"

      cat gf/sqli.txt | qsreplace FUZZ | anew -q .tmp/tmp_sqli.txt
      if [ "$DEEP" = true ] || [[ $(cat .tmp/tmp_sqli.txt | wc -l) -le $DEEP_LIMIT ]]; then
        interlace -tL .tmp/tmp_sqli.txt -threads 10 -c "python3 $TOOL_PATH/sqlmap/sqlmap.py -u _target_ -b --batch --disable-coloring --random-agent --level 2 --output-dir=_output_" -o vulns/sqlmap &>/dev/null

        end_func "Results are saved in vulns/sqlmap folder" ${FUNCNAME[0]}
      else
        end_func "Skipping SQLi: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
      fi
    else
      if [ "$SQLI" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      elif [ ! -s "gf/sqli.txt" ]; then
        printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to SQLi ${reset}\n\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  command_injection(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$COMM_INJ" = true ] && [ -s "gf/rce.txt" ]; then
      start_func "Command Injection checks"
      [ -s "gf/rce.txt" ] && cat gf/rce.txt | qsreplace FUZZ | anew -q .tmp/tmp_rce.txt
      if [ "$DEEP" = true ] || [[ $(cat .tmp/tmp_rce.txt | wc -l) -le $DEEP_LIMIT ]]; then
        [ -s ".tmp/tmp_rce.txt" ] && python3 $TOOL_PATH/commix/commix.py --batch -m .tmp/tmp_rce.txt --output-dir vulns/command_injection.txt 2>>"$LOGFILE" &>/dev/null
        end_func "Results are saved in vulns/command_injection folder" ${FUNCNAME[0]}
      else
        end_func "Skipping Command injection: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
      fi
    else
      if [ "$COMM_INJ" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      elif [ ! -s "gf/rce.txt" ]; then
        printf "\n${yellow} ${FUNCNAME[0]} No URLs potentially vulnerables to Command Injection ${reset}\n\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

  prototype_pollution(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$PROTO_POLLUTION" = true ] ; then
      start_func "Prototype Pollution checks"
      if [ "$DEEP" = true ] || [[ $(cat webs/url_extract.txt | wc -l) -le $DEEP_LIMIT ]]; then
        [ -s "webs/url_extract.txt" ] && ppfuzz -l webs/url_extract.txt -c $PPFUZZ_THREADS > anew -q .tmp/prototype_pollution.txt
        [ -s ".tmp/prototype_pollution.txt" ] && cat .tmp/prototype_pollution.txt | sed -e '1,8d' | sed '/^\[ERR/d' | anew -q vulns/prototype_pollution.txt
        end_func "Results are saved in vulns/prototype_pollution.txt" ${FUNCNAME[0]}
      else
        end_func "Skipping Prototype Pollution: Too many URLs to test, try with --deep flag" ${FUNCNAME[0]}
      fi
    else
      if [ "$PROTO_POLLUTION" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in bunny.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }

########################################################################################################
###################################### MAIN FUNCTIONS ##################################################
########################################################################################################

  osint(){
    emails
    metadata
    domain_info
    google_dorks
    github_dorks
    tlda
  }

  subdomainDiscovery(){
    subdomains_full
    s3buckets
    cloudprovider
  }

  contentDiscovery(){

  }

  networkDiscovery(){
    portscan
    nmaps_scan
    spraying
  }

  vulnDiscovery(){
    ###################################### VULNERABILITIES SCANNER #############################################
      jaeles_check
      nuclei_check
    ################################### DOMAIN LEVEL VULNERABILITIES ###########################################
      dead_records
      test_ssl
      subtakeover
      submisconfig
      cors
    ################################### APPLICATION LEVEL VULNERABILITIES ######################################
      brokenLinks
      bfac 
      403_bypasses
      xss
      open_redirect
      ssti
      ssrf_checks
      crlf_checks
      lfi
      sqli
      command_injection
      prototype_pollution
    ################################### NETWORK LEVEL VULNERABILITIES ##########################################
  }

  recon(){
    osint                 
    subdomainDiscovery    
    contentDiscovery      
    networkDiscovery      
  }

  help(){
    printf "\n Usage: $0 [-d domain.tld] [-l list.txt] [-x oos.txt] [-osint]"
    printf "\n           	 [-r] [-a] [-h] [-oD OUT_DIR]\n\n"
    printf " ${bblue}TARGET OPTIONS${reset}\n"
    printf "   -d/--domain domain.tld     Target domain\n"
    printf "   -l/--list list.txt       Targets list, one per line\n"
    printf "   -x/--exclude oos.txt        Exclude subdomains list (Out Of Scope)\n"
    printf "   -osint, emai/name OSINT - Just checks public intel info\n"
    printf " \n"
    printf " ${bblue}MODE OPTIONS${reset}\n"
    printf "   -r, --recon       Recon - Full recon process (only recon without attacks)\n"
    printf "   -a, --all         All (Default) - Perform all checks and exploitations\n"
    printf "   -h                Help - Show this help\n"
    printf " \n"
    printf " ${bblue}GENERAL OPTIONS${reset}\n"
    printf "   -f/--config confile_file   Alternate bunny.cfg file\n"
    printf "   -oD/--out output/path    Define output folder\n"
    printf " \n"
    printf " ${bblue}USAGE EXAMPLES${reset}\n"
    printf " Recon:\n"
    printf " ./bunny.sh -d example.com -r\n"
    printf " \n"
    printf " OSINT Email or Name \n"
    printf " ./bunny.sh -osint aashay (default)/opt/target/osint/aashay.txt \n"
    printf " \n"
    printf " Full recon with custom output and excluded subdomains list:\n"
    printf " ./bunny.sh -d example.com -x out.txt -oD custom/path\n"
    exit 1
  }

########################################################################################################
######################################## START/STOP WRAPPER ############################################
########################################################################################################

  start(){  
    # Intial Validation
      if [[ -z $CONFIG_FILES ]]; then
          echo -e "\n${red}ERROR${normal} - config not supplied. $DOMAIN $LIST \n${normal}"
          exit 1
      fi
      if [[ ! -z "config_files/Provider-config-notify.yaml" ]]; then
          cp config_files/Provider-config-notify.yaml /root/.config/notify/provider-config.yaml
        else
          echo -e "\n${red}ERROR${normal} - notify config Not added. $DOMAIN $LIST \n${normal}"
      fi
          if [[ ! -z "config_files/Provider-config-notify.yaml" ]]; then
          cp config_files/Provider-config-notify.yaml /root/.config/notify/provider-config.yaml
        else
          echo -e "\n${red}ERROR${normal} - notify config Not added. $DOMAIN $LIST \n${normal}"
      fi
      if [[ ! -z $LIST ]] && [ ! -f "$LIST" ]; then
        isAsciiText $LIST
        if [ "False" = "$IS_ASCII" ]; then
            printf "\n\n${bred} LIST file is not a text file${reset}\n\n"
            exit
        fi
      fi
      if [[ -z $DOMAIN ]] && [[ -z $LIST ]] && [[ -z $NAME ]] && [[ -z $EMAIL ]] ; then
        echo -e "\n${red}ERROR${normal} - Target not supplied.\n${normal}"
        exit 1
      fi
      if [[ ! -z $DOMAIN ]] && [[ ! -z $LIST ]]; then
        echo -e "\n${red}ERROR${normal} - only add -d or -l \n${normal}"
        exit 1
      fi
      if [[ -z $PROJECT ]]; then
        echo "[-] Please specify the output Location..."
        help
      fi
      if [ -n "$outOfScope_file" ]; then
        isAsciiText $outOfScope_file
        if [ "False" = "$IS_ASCII" ]; then
            printf "\n\n${bred} Out of Scope file is not a text file${reset}\n\n"
            exit
        fi
      fi
      if [ -n "$inScope_file" ]; then
        isAsciiText $inScope_file
        if [ "False" = "$IS_ASCII" ]; then
            printf "\n\n${bred} In Scope file is not a text file${reset}\n\n"
            exit
        fi
      fi
      if [ ! -d "$PROJECT/$DOMAIN" ]; then
          sudo mkdir -p $PROJECT/$DOMAIN
          cd $PROJECT/$DOMAIN
          sudo mkdir .tmp .log osint subdomains webs hosts vulns
        else
          cd $PROJECT/$DOMAIN
          sudo mkdir .tmp .log osint subdomains webs hosts vulns

      fi
    # Mode for scanning
      case $opt_mode in
        'osint')
          if [ -n "$LIST" ]; then
            printf "\n${bgreen}##############################################################${reset}"
            notification "osint succesfully started on ${LIST}" good
            echo "osint succesfully started on $(cat $LIST)" | $NOTIFY -id gen
            printf "${bgreen}##############################################################${reset}\n"
            NOW=$(date +"%F")
            NOWT=$(date +"%T")
            LOGFILE="${PROJECT}/.log/${DOMAIN}_${NOW}_${NOWT}.txt"
            touch LOGFILE

            for DOMAIN in $(cat $LIST); do
              if [[$DOMAIN =~ ^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4} ]]; then
                email=$DOMAIN
                else
                name=$DOMAIN
              fi
              echo "osint data file $DOMAIN $email $name"
              osint
            done
          else
            printf "\n${bgreen}##############################################################${reset}"
            notification "osint succesfully started on $DOMAIN $EMAIL $NAME" good
            echo "osint succesfully started on $DOMAIN $EMAIL $NAME " | $NOTIFY
            printf "${bgreen}##############################################################${reset}\n"
            NOW=$(date +"%F")
            NOWT=$(date +"%T")
            LOGFILE="${PROJECT}/.log/${DOMAIN}_${NOW}_${NOWT}.txt"
            touch LOGFILE
            echo "osint data for $DOMAIN $EMAIL $NAME"
            osint
          fi
            ;;
        'recon')
          if [ -n "$LIST" ]; then
            printf "\n${bgreen}##############################################################${reset}"
            notification "RECON succesfully started on ${LIST}" good
            pwd
            echo "recon succesfully started on $(cat $LIST)" | $NOTIFY -id gen
            printf "${bgreen}##############################################################${reset}\n"
            NOW=$(date +"%F")
            NOWT=$(date +"%T")
            LOGFILE="${PROJECT}/.log/${DOMAIN}_${NOW}_${NOWT}.txt"
            touch LOGFILE
            # sed -i 's/\r$//' $LIST
            for DOMAIN in $(cat $LIST); do
              echo " file $DOMAIN"
              recon
            done
          else
            printf "\n${bgreen}##############################################################${reset}"
            notification "RECON succesfully started on ${DOMAIN}" good
            echo "recon succesfully started on ${DOMAIN}" | $NOTIFY -id gen
            printf "${bgreen}##############################################################${reset}\n"
            NOW=$(date +"%F")
            NOWT=$(date +"%T")
            LOGFILE="${PROJECT}/.log/${DOMAIN}_${NOW}_${NOWT}.txt"
            touch LOGFILE
            echo " DOMAIN $DOMAIN"
            recon
          fi
            ;;
        'tlda')
          if [ -n "$LIST" ]; then
            printf "\n${bgreen}##############################################################${reset}"
            notification "RECON succesfully started on ${LIST}" good
            echo "recon succesfully started on $(cat $LIST)" | $NOTIFY -id gen
            printf "${bgreen}##############################################################${reset}\n"
            NOW=$(date +"%F")
            NOWT=$(date +"%T")
            LOGFILE="${PROJECT}/.log/${DOMAIN}_${NOW}_${NOWT}.txt"
            touch LOGFILE
            # sed -i 's/\r$//' $LIST
            for DOMAIN in $(cat $LIST); do
              echo " file $DOMAIN"
              tlda
            done
          else
            printf "\n${bgreen}##############################################################${reset}"
            notification "RECON succesfully started on ${DOMAIN}" good
            echo "recon succesfully started on ${DOMAIN}" | $NOTIFY -id gen
            printf "${bgreen}##############################################################${reset}\n"
            NOW=$(date +"%F")
            NOWT=$(date +"%T")
            LOGFILE="${PROJECT}/.log/${DOMAIN}_${NOW}_${NOWT}.txt"
            touch LOGFILE
            echo " DOMAIN $DOMAIN"
            tlda
          fi
          ;;  
        'all')
          if [ -n "$LIST" ]; then
            printf "\n${bgreen}##############################################################${reset}"
            notification "Complete scan succesfully started on ${LIST}" good
            echo "complete scan succesfully started on $(cat $LIST)" | $NOTIFY -id gen
            printf "${bgreen}##############################################################${reset}\n"
            NOW=$(date +"%F")
            NOWT=$(date +"%T")
            LOGFILE="${PROJECT}/.log/${DOMAIN}_${NOW}_${NOWT}.txt"
            touch LOGFILE
            for DOMAIN in $(cat $LIST); do
              echo "a data file $DOMAIN"
              # osint
              # recon
              # vulnDiscovery
            done
          else
              printf "\n${bgreen}##############################################################${reset}"
              notification "Complete succesfully started on ${DOMAIN}" good
              echo "Complete succesfully started on ${DOMAIN}" | $NOTIFY -id gen
              printf "${bgreen}##############################################################${reset}\n"
              NOW=$(date +"%F")
              NOWT=$(date +"%T")
              LOGFILE="${PROJECT}/.log/${DOMAIN}_${NOW}_${NOWT}.txt"
              touch LOGFILE
              echo "a data DOMAIN $DOMAIN"
              osint
              # recon
              # vulnDiscovery
            fi
            ;;
        *)
            help
            # tools_installed
            exit 1
            ;;
      esac
  }

  end_notification(){

    notification "############################# Total data ############################" info
    NUMOFLINES_users_total=$(find . -type f -name 'users.txt' -exec cat {} + | anew osint/users.txt | wc -l)
    NUMOFLINES_pwndb_total=$(find . -type f -name 'passwords.txt' -exec cat {} + | anew osint/passwords.txt | wc -l)
    NUMOFLINES_software_total=$(find . -type f -name 'software.txt' -exec cat {} + | anew osint/software.txt | wc -l)
    NUMOFLINES_authors_total=$(find . -type f -name 'authors.txt' -exec cat {} + | anew osint/authors.txt | wc -l)
    NUMOFLINES_subs_total=$(find . -type f -name 'subdomains.txt' -exec cat {} + | anew subdomains/subdomains.txt | wc -l)
    NUMOFLINES_subtko_total=$(find . -type f -name 'takeover.txt' -exec cat {} + | anew webs/takeover.txt | wc -l)
    NUMOFLINES_webs_total=$(find . -type f -name 'webs.txt' -exec cat {} + | anew webs/webs.txt | wc -l)
    NUMOFLINES_webs_total=$(find . -type f -name 'webs_uncommon_ports.txt' -exec cat {} + | anew webs/webs_uncommon_ports.txt | wc -l)
    NUMOFLINES_ips_total=$(find . -type f -name 'ips.txt' -exec cat {} + | anew hosts/ips.txt | wc -l)
    NUMOFLINES_cloudsprov_total=$(find . -type f -name 'cloud_providers.txt' -exec cat {} + | anew hosts/cloud_providers.txt | wc -l)

    notification "- ${NUMOFLINES_users_total} total users found" good
    notification "- ${NUMOFLINES_pwndb_total} total creds leaked" good
    notification "- ${NUMOFLINES_software_total} total software found" good
    notification "- ${NUMOFLINES_authors_total} total authors found" good
    notification "- ${NUMOFLINES_subs_total} total subdomains" good
    notification "- ${NUMOFLINES_subtko_total} total probably subdomain takeovers" good
    notification "- ${NUMOFLINES_webs_total} total websites" good
    notification "- ${NUMOFLINES_ips_total} total ips" good
    notification "- ${NUMOFLINES_cloudsprov_total} total IPs belongs to cloud" good

  }

  stop(){
    find $PROJECT -type f -empty | grep -v "called_fn" | xargs rm -f &>/dev/null
    find $PROJECT -type d -empty | grep -v "called_fn" | xargs rm -rf &>/dev/null

    if [ "$REMOVETMP" = true ]; then
      rm -rf $PROJECT/.tmp
    fi

    if [ "$REMOVELOG" = true ]; then
      rm -rf $PROJECT/.log
    fi 

    if [ "$SENDZIPNOTIFY" = true ]; then
      zipSnedOutputFolder
    fi
    end_notification
    global_end=$(date +%s)
    getElapsedTime $global_start $global_end
    printf "${bgreen}##############################################################${reset}\n"
    notification "Finished Recon on: ${DOMAIN} under ${finaldir} in: ${runtime}" good
    echo "Finished Recon on: ${DOMAIN} under ${finaldir} in: ${runtime}" | $NOTIFY
    printf "${bgreen}##############################################################${reset}\n"
    echo "******  Stay safe 🦠 and secure 🔐  ******" | $NOTIFY
  }

  start_func(){
    printf "${bgreen}#######################################################################"
    notification "${1}" info
    start=$(date +%s)
  }

  end_func(){
    touch $called_fn_dir/.${2}
    end=$(date +%s)
    getElapsedTime $start $end
    notification "${2} Finished in ${runtime}" info
    printf "${bblue} ${1} ${reset}\n"
    printf "${bgreen}##############################################################${reset}\n"
  }

  start_subfunc(){
    notification "${1}" warn
    start_sub=$(date +%s)
  }

  end_subfunc(){
    touch $called_fn_dir/.${2}
    end_sub=$(date +%s)
    getElapsedTime $start_sub $end_sub
    notification "${1} in ${runtime}" good
  }

########################################################################################################
########################################### STARTS HERE ################################################
########################################################################################################
  
global_start=$(date +%s)
initial_banner
check_connection
# check_version

if [ ! -d "$called_fn_dir" ]; then
  mkdir -p "$called_fn_dir"
fi

PARSED_ARGUMENTS=$(getopt -n alphabet -o l:PNrae:n:x:i:o:d: --long list:,osint,Nonotify,recon,all,email:,name:,exclude:,include:,output:,domain: -- "$@")
VALID_ARGUMENTS=$?

if [ "$VALID_ARGUMENTS" != "0" ]; then
  help
fi

eval set -- "$PARSED_ARGUMENTS"
while :
  do
    case "$1" in
    -d | --domain)   DOMAIN=$2      ; shift 2  ;;
    -l | --list)   
      if [[ "$2" != /* ]]; then
          LIST=$PWD/$2
        else
          LIST=$2
      fi ; shift 2 ;;
    -x | --exclude)   outOfScope_file=$2  ; shift 2 ;;
    -i | --include)   inScope_file=$2  ; shift 2 ;;
    -n | --name)   NAME=$2  ; shift 2 ;;
    -e | --email)   EMAIL=$2  ; shift 2 ;;
    -o | --output)   
      if [[ "$2" != /* ]]; then
          PROJECT=$PWD/$2
        else
          PROJECT=$2
      fi ; shift 2 ;;
    -P | --osint)   opt_mode="osint"   ; shift  ;;
    -r | --recon)   opt_mode="recon"   ; shift  ;;
    -t | --tlda)   opt_mode="tlda"   ; shift  ;;
    -N | --Nonotify) NOTIFICATION=0 ; shift  ;;
    -a | --all)   opt_mode="all"   ; shift  ;;
    --) shift; break ;;
    *) echo "Unexpected option: $1 - this should not happen."
    help ;;
  esac
done

start
stop 

echo """   

  ███████╗███╗   ██╗██████╗ 
  ██╔════╝████╗  ██║██╔══██╗
  █████╗  ██╔██╗ ██║██║  ██║
  ██╔══╝  ██║╚██╗██║██║  ██║
  ███████╗██║ ╚████║██████╔╝
  ╚══════╝╚═╝  ╚═══╝╚═════╝ 
                            
  """
