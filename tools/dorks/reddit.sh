#!/bin/bash

# Variables
BOLD='\033[1m'
END='\033[0m'

# Queries
site_results=$(curl -Ls "https://www.reddit.com/search?q=site%3A$1" -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0" | tidy -q  2> /dev/null | grep "search-link")
url_results=$(curl -Ls "https://www.reddit.com/search?q=url%3A$1" -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0" | tidy -q  2> /dev/null | grep "search-link")
self_results=$(curl -Ls "https://www.reddit.com/search?q=selftext%3A$1" -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0" | grep "search-title")

# Output
echo
echo -e "${BOLD}Hosts:${END}"
echo "========================"
echo $site_results | grep -Po '.*?//\K.*?(?=/)' | sort | uniq

echo
echo -e "${BOLD}Links:${END}"
echo "========================"
echo $site_results | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | sort | uniq
echo $url_results | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | sort | uniq

echo
echo -e "${BOLD}Self-posts:${END}"
echo "========================"
echo $self_results | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | grep "comments" | sort | uniq