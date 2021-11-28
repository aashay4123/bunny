#!/bin/bash

contentDiscovery(){
    mkdir -p $DOMAIN/urls
    runBanner "Wayback urls"
    echo "$DOMAIN" | waybackurls >> wayback.txt
    runBanner "Gau urls"
    echo "$DOMAIN" | gau >> wayback.txt
    runBanner "github-endpoints urls"
    python3 $REPO_TOOLS/github-endpoints.py -t 6c5ed8ab7b7c4b9232fcaea5c051b8977a624012 -d $DOMAIN  >> wayback.txt
    
    cat wayback.txt | sort -u > waybackurls.txt 
    runBanner "gospider"
    gospider -S $DOMAIN/subdomain/allsubdmain -c 10 -d 1 -t 20 --other-source --sitemap > gospider.txt

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

  runBanner "Sort vulnerable_files"
    mkdir -p $DOMAIN/vulnerable_files
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
    cat $DOMAIN/urls/2xx  | getJS -complete -output alive-js-files.txt
    sort -u alive-js-files.txt -o alive-js-files
    rm alive-js-files.txt
  runBanner "Extracting paths from js files"
    # domainExtract
}
