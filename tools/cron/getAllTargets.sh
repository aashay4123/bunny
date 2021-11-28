# Edit this file to introduce tasks to be run by cron.
# crontab -e / -l
# m h  dom mon dow   command
# 0 */12 * * * /home/kodachi/.kbase/tmpmon >/dev/null 2>&1

if [[ !  -f newTargets.txt ]]; then
    # Assets from chaos-bugbounty-list
    curl -sL https://github.com/projectdiscovery/public-bugbounty-programs/raw/master/chaos-bugbounty-list.json | jq -r '.programs[].domains | to_entries | .[].value' >> allTargets
    # HackerOne Programs
    curl -sL https://github.com/arkadiyt/bounty-targets-data/blob/master/data/hackerone_data.json?raw=true | jq -r '.[].targets.in_scope[] | [.asset_identifier, .asset_type] | @tsv' | grep URL | awk '{print $1}' >> allTargets
    # BugCrowd Programs
    curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/bugcrowd_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv' | grep website | awk '{print $1}' >> allTargets
    # Intigriti Programs
    curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/intigriti_data.json | jq -r '.[].targets.in_scope[] | [.endpoint, .type] | @tsv' | grep url | awk '{print $1}' >> allTargets
    # YesWeHack Programs
    curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/yeswehack_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'| grep web | awk '{print $1}' >> allTargets
    # HackenProof Programs
    curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/hackenproof_data.json | jq -r '.[].targets.in_scope[] | [.target, .type, .instruction] | @tsv'| grep Web  | awk '{print $1}' >> allTargets
    # Federacy Programs
    curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/federacy_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'| grep website  | awk '{print $1}' >> allTargets
    cat allTargets | sort -u > alltarget
    cat alltarget | anew oldallTargets | tee  newTargets.txt
    mv alltarget oldallTargets
    # notify -data newTargets.txt -id newt -bulk
    # ~/Documents/bug_hunter/./bunny.sh -l newTargets -all
    rm allTargets
    else 
      echo "previous command in progress" | notify -id newt 
fi
