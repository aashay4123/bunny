https://github.com/hisxo/gitGraber
https://github.com/anshumanbh/git-all-secrets
https://github.com/internetwache/GitTools

# GitGot

https://github.com/BishopFox/GitGot
./gitgot.py --gist -q CompanyName./gitgot.py -q '"example.com"'./gitgot.py -q "org:github cats"

# GitRob https://github.com/michenriksen/gitrob

gitrob website.com

# GitHound https://github.com/tillson/git-hound

git-hound --dig-files --dig-commits --many-results --threads 100 --subdomain-file "$1/subdomains.txt" | tee "$1/githound.txt"
echo "domain.com" | githound --dig --many-results --languages common-languages.txt --threads 100


# If you have public .git Manual
If we have access to .git folder:
./gitdumper.sh http://example.com/.git/ /home/user/dump/
git cat-file --batch-check --batch-all-objects | grep blob git cat-file -p HASH
# GitLeaks   
curl -s "https://raw.githubusercontent.com/liamg/gitjacker/master/scripts/install.sh" | bash
gitjacker url.com

# tools

# https://github.com/obheda12/GitDorker  

python3 GitDorker.py -tf TOKENSFILE -q tesla.com -d dorks/DORKFILE -o target


  github_dorks(){
    if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$GITHUB_DORKS" = true ] && [ "$OSINT" = true ]; then
      start_func "Github Dorks in process"
      if [ -s "${GITHUB_TOKENS}" ]; then
        if [ "$DEEP" = true ]; then
          python3 "$TOOL_PATH/GitDorker/GitDorker.py" -tf "${GITHUB_TOKENS}" -e "$GITDORKER_THREADS" -q "$DOMAIN" -p -ri -d "$TOOL_PATH/GitDorker/Dorks/alldorksv3" 2>>"$LOGFILE" | grep "\[+\]" | grep "git" | anew -q osint/gitdorks.txt
        else
          python3 "$TOOL_PATH/GitDorker/GitDorker.py" -tf "${GITHUB_TOKENS}" -e "$GITDORKER_THREADS" -q "$DOMAIN" -p -ri -d "$TOOL_PATH/GitDorker/Dorks/medium_dorks.txt" 2>>"$LOGFILE" | grep "\[+\]" | grep "git" | anew -q osint/gitdorks.txt
        fi
        sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" osint/gitdorks.txt
      else
        printf "\n${bred} Required file ${GITHUB_TOKENS} not exists or empty${reset}\n"
      fi
      end_func "Results are saved in $DOMAIN/osint/gitdorks.txt" ${FUNCNAME[0]}
    else
      if [ "$GITHUB_DORKS" = false ] || [ "$OSINT" = false ]; then
        printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
      else
        printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
      fi
    fi
  }
