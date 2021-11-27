#!/bin/bash

# Colors
BLINK='\e[5m'
BOLD='\e[1m'
LIGHT_GREEN='\e[92m'
LIGHT_YELLOW='\e[93m'
LIGHT_CYAN='\e[96m'
NORMAL='\e[0m'
RED='\e[31m'
UNDERLINE='\e[4m'

UBUNTU=;
DEBIAN=;
KALI=;
TOOLS="/opt/tools";

testcmd () {
  command -v "$1" 
}

install_ubuntu() {
	echo -e "$LIGHT_GREEN[+] Installing for Ubuntu.$NORMAL";
	install_library;
	install_envlib;
	install_tools;
	if ! testcmd urldedupe; then
 	 sudo snap install cmake --classic
	fi
}

install_library(){
	sudo apt update 
	sudo apt -y upgrade 
	sudo apt dist-upgrade -y
	gem install parallel
	sudo apt install -y lynx python3-openpyxl libxml2 libxml2-dev libxslt1-dev libgmp-dev zlib1g-dev libgdbm-dev libncurses5-dev automake libtool bison jq
	sudo apt install -y libffi-dev software-properties-common  python-dev libcurl4-openssl-dev apt-transport-https libssl-dev jq  whois python-setuptools libldns-dev libpcap-dev
	sudo apt install -y npm exiftool golang-go gem perl parallel libxml2-utils psmisc host dnsutils  snapd git gcc make python3-pip libgeoip-dev 
	sudo apt install -y git wget curl medusa nmap masscan whatweb gobuster nikto wafw00f openssl libnet-ssleay-perl p7zip-full build-essential unzip 
}

install_envlib() {	
  if ! testcmd code; then
    wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
    sudo install -o root -g root -m 644 packages.microsoft.gpg /etc/apt/trusted.gpg.d/
    sudo sh -c 'echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/trusted.gpg.d/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list'
    rm -f packages.microsoft.gpg
    curl -sSL https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
    sudo apt install apt-transport-https
    sudo apt update
    sudo apt install code

	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing vs-code ...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
  if ! testcmd go ;then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing go ...${NORMAL}"
		sudo wget -nv https://golang.org/dl/go1.17.2.linux-amd64.tar.gz
		sudo tar -C /usr/local -xzf go1.17.2.linux-amd64.tar.gz;
		sudo rm go1.17.2.linux-amd64.tar.gz;
		sudo echo 'export GOROOT=/usr/local/go' >> /root/.zshrc
		sudo echo 'export GOPATH=/root/go'   >> /root/.zshrc
		sudo echo 'export PATH=$GOPATH/bin:$GOROOT/bin:$PATH' >> /root/.zshrc
		source /root/.zshrc
	 else 
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing go ...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi

  if ! testcmd rustc ;then
    echo -e "${BOLD}${LIGHT_GREEN}[+] Installing rustc ...${NORMAL}"
    curl https://sh.rustup.rs -sSf | sh
    sudo apt install cargo -y
    # curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
	  source $HOME/.cargo/env
	else 
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing rustc ...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi

	if ! testcmd pip3; then 
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing pip3 ...${NORMAL}"
		sudo apt-get purge python3-pip
		sudo apt-get install python3-pip -y
	 else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing pip3 ...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd docker ;then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing docker ...${NORMAL}"
		curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add -
		echo 'deb [arch=amd64] https://download.docker.com/linux/debian buster stable' | sudo tee /etc/apt/sources.list.d/docker.list
		sudo apt-get update
		sudo apt-get install docker-ce -y
	 else 
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing docker ...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd ruby ; then 
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing ruby ...${NORMAL}"
		gpg --keyserver hkp://pool.sks-keyservers.net --recv-keys 409B6B1796C275462A1703113804BB82D39DC0E3 7D2BAF1CF37B13E2069D6956105BD0E739499BDB
		curl -sSL https://get.rvm.io | bash -s stable
		source /etc/profile.d/rvm.sh
		type rvm | head -n 1
		rvm install "ruby-2.7.1"
		rvm use "ruby-2.7.1" --default
		ruby -v
	 else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing ruby ...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"

	fi
	echo -e "${BOLD}${LIGHT_GREEN}[+] Installing requirements for Python 2 and Python 3.${NORMAL}"
	sudo pip3 install -r tools/requirements.txt > /dev/null
	install_go_tools;
} 

install_tools	() {
	sudo mkdir "$TOOLS"/manual
	if [[ -d "$TOOLS"/manual/CloudUnflare ]]; then
			echo -e "$LIGHT_GREEN[+] Updating CloudUnflare.""$NORMAL";
			cd "$TOOLS"/manual/CloudUnflare;
			sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing CloudUnflare from Github.""$NORMAL";
		sudo git clone https://github.com/greycatz/CloudUnflare.git "$TOOLS"/manual/CloudUnflare;
	fi
	if [[ -d "$TOOLS"/manual/ReconT ]]; then
			echo -e "$LIGHT_GREEN[+] Updating ReconT.""$NORMAL";
			cd "$TOOLS"/manual/ReconT;
			sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing ReconT from Github.""$NORMAL";
		sudo git clone https://github.com/dock3rX/ReconT.git "$TOOLS"/manual/ReconT;
		cd "$TOOLS"/manual/ReconT;
		sudo pip3 install -r requirements.txt
	fi
	if [[ -d "$TOOLS"/manual/CloudFail ]]; then
			echo -e "$LIGHT_GREEN[+] Updating CloudFail.""$NORMAL";
			cd "$TOOLS"/manual/CloudFail;
			sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing CloudFail from Github.""$NORMAL";
		sudo git clone https://github.com/m0rtem/CloudFail.git "$TOOLS"/manual/CloudFail;
		cd "$TOOLS"/manual/CloudFail
		sudo pip3 install -r requirements.txt
	fi

	if [[ -d "$TOOLS"/manual/wig ]]; then
			echo -e "$LIGHT_GREEN[+] Updating wig.""$NORMAL";
			cd "$TOOLS"/manual/wig;
			sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing wig from Github.""$NORMAL";
		sudo git clone https://github.com/jekyc/wig.git "$TOOLS"/manual/wig;
		cd "$TOOLS"/manual/wig;
		sudo python3 setup.py install > /dev/null
	fi
	if [[ -d "$TOOLS"/testssl.sh ]]; then
			echo -e "$LIGHT_GREEN[+] Updating testssl.sh.""$NORMAL";
			cd "$TOOLS"/testssl.sh;
			sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing testssl.sh from Github.""$NORMAL";
		sudo git clone https://github.com/drwetter/testssl.sh.git "$TOOLS"/testssl.sh;
	fi
	if [[ -d "$TOOLS"/manual/git-hound ]]; then
			echo -e "$LIGHT_GREEN[+] Updating git-hound.""$NORMAL";
			cd "$TOOLS"/manual/git-hound;
			sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing git-hound from Github.""$NORMAL";
		sudo git clone https://github.com/tillson/git-hound.git "$TOOLS"/manual/git-hound 
		cd "$TOOLS"/manual/git-hound;
		sudo go build main.go && sudo mv main githound
	fi
  if [[ -d "$TOOLS"/dnsvalidator ]]; then
			echo -e "$LIGHT_GREEN[+] Updating CloudUnflare.""$NORMAL";
			cd "$TOOLS"/dnsvalidator;
			sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing CloudUnflare from Github.""$NORMAL";
		sudo git clone https://github.com/vortexau/dnsvalidator.git "$TOOLS"/dnsvalidator;
		cd "$TOOLS"/dnsvalidator;
		sudo python3 setup.py install 2> /dev/null
	fi
	if [[ -d "$TOOLS"/domain_analyzer ]]; then
			echo -e "$LIGHT_GREEN[+] Updating domain_analyzer.""$NORMAL";
			cd "$TOOLS"/domain_analyzer;
			sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing domain_analyzer from Github.""$NORMAL";
		sudo git clone https://github.com/eldraco/domain_analyzer.git "$TOOLS"/domain_analyzer;
	fi
 	if [[ -d "$TOOLS"/FavFreak ]]; then
			echo -e "$LIGHT_GREEN[+] Updating FavFreak.""$NORMAL";
			cd "$TOOLS"/FavFreak;
			sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing FavFreak from Github.""$NORMAL";
      git clone https://github.com/devanshbatham/FavFreak "$TOOLS"/FavFreak;
      cd FavFreak
      python3 -m pip install mmh3
	fi

	if [[ -d "$TOOLS"/spoofcheck ]]; then
			echo -e "$LIGHT_GREEN[+] Updating spoofcheck.""$NORMAL";
			cd "$TOOLS"/spoofcheck;
			sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing spoofcheck from Github.""$NORMAL";
		sudo git clone https://github.com/BishopFox/spoofcheck.git "$TOOLS"/spoofcheck;
		cd "$TOOLS"/spoofcheck;
		sudo pip install -r requirements.txt
	fi
  if [[ -d "$TOOLS"/HostPanic ]]; then
			echo -e "$LIGHT_GREEN[+] Updating HostPanic.""$NORMAL";
			cd "$TOOLS"/HostPanic;
			sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing HostPanic from Github.""$NORMAL"
    git clone https://github.com/mr-medi/HostPanic.git "$TOOLS"/HostPanic;
	fi
  if [[ -d "$TOOLS"/smuggler ]]; then
			echo -e "$LIGHT_GREEN[+] Updating smuggler.""$NORMAL";
			cd "$TOOLS"/smuggler;
			sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing smuggler from Github.""$NORMAL"
    git clone https://github.com/defparam/smuggler.git "$TOOLS"/smuggler;
	fi

	if [[ -d "$TOOLS"/github-dorks ]]; then
			echo -e "$LIGHT_GREEN[+] Updating github-dorks.""$NORMAL";
			cd "$TOOLS"/github-dorks;
			sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing github-dorks from Github.""$NORMAL";
		sudo git clone https://github.com/techgaun/github-dorks.git "$TOOLS"/github-dorks;
		cd "$TOOLS"/github-dorks;
		sudo pip install -r requirements.txt > /dev/null
	fi
  if [[ -d "$TOOLS"/theHarvester ]]; then
    echo -e "$LIGHT_GREEN[+] Updating theHarvester.""$NORMAL";
    cd "$TOOLS"/theHarvester;
    sudo git pull;
	 else
		echo -e "$LIGHT_GREEN[+] Installing theHarvester from Github.""$NORMAL";
		sudo git clone https://github.com/techgaun/theHarvester.git "$TOOLS"/theHarvester;
		cd "$TOOLS"/theHarvester;
		sudo pip install -r requirements.txt > /dev/null
	fi
  if [[ -d "$TOOLS"/sqlmap ]]; then
    echo -e "$LIGHT_GREEN[+] Updating sqlmap.""$NORMAL";
    cd "$TOOLS"/sqlmap;
    sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing sqlmap from Github.""$NORMAL";
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git   "$TOOLS"/sqlmap;
		cd "$TOOLS"/sqlmap;
		sudo pip install -r requirements.txt > /dev/null
	fi

  if [[ -d "$TOOLS"/uDork ]]; then
			echo -e "$LIGHT_GREEN[+] Updating uDork.""$NORMAL";
			cd "$TOOLS"/uDork;
			sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing uDork from Github.""$NORMAL";
		sudo git clone https://github.com/m3n0sd0n4ld/uDork "$TOOLS"/uDork;
		cd "$TOOLS"/uDork;
    chmod +x uDork.sh
	fi
  	if [[ -d "$TOOLS"/pymeta ]]; then
			echo -e "$LIGHT_GREEN[+] Updating pymeta.""$NORMAL";
			cd "$TOOLS"/pymeta;
			sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing pymeta from Github.""$NORMAL";
		sudo git clone https://github.com/m8r0wn/pymeta "$TOOLS"/pymeta;
		cd "$TOOLS"/pymeta;
    python3 setup.py install
	fi
  if [[ -d "$TOOLS"/http-request-smuggling ]]; then
			echo -e "$LIGHT_GREEN[+] Updating http-request-smuggling.""$NORMAL";
			cd "$TOOLS"/http-request-smuggling;
			sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing http-request-smuggling from Github.""$NORMAL"
    git clone https://github.com/anshumanpattnaik/http-request-smuggling.git "$TOOLS"/http-request-smuggling;
	fi
	if [[ -d "$TOOLS"/lazys3 ]]; then
			echo -e "$LIGHT_GREEN[+] Updating lazys3.""$NORMAL";
			cd "$TOOLS"/lazys3;
			sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing lazys3 from Github.""$NORMAL";
		sudo git clone https://github.com/nahamsec/lazys3.git "$TOOLS"/lazys3;
	fi
	if [[ -d "$TOOLS"/SourceWolf ]]; then
			echo -e "$LIGHT_GREEN[+] Updating SourceWolf.""$NORMAL";
			cd "$TOOLS"/SourceWolf;
			sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing SourceWolf from Github.""$NORMAL";
    git clone https://github.com/ksharinarayanan/SourceWolf "$TOOLS"/SourceWolf;
	fi
  if [[ -d "$TOOLS"/JSA ]]; then
			echo -e "$LIGHT_GREEN[+] Updating JSA.""$NORMAL";
			cd "$TOOLS"/JSA;
			sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing JSA from Github.""$NORMAL";
  		git clone https://github.com/w9w/JSA.git  "$TOOLS"/JSA/ 2> /dev/null
	fi
	if [[ -d "$TOOLS"/S3Scanner ]]; then
			echo -e "$LIGHT_GREEN[+] Updating S3Scanner.""$NORMAL";
			cd "$TOOLS"/S3Scanner;
			sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing S3Scanner from Github.""$NORMAL";
		sudo git clone https://github.com/sa7mon/S3Scanner.git "$TOOLS"/S3Scanner;
		cd "$TOOLS"/S3Scanner;
		sudo pip3 install -r requirements.txt 
	fi
	if [[ -d "$TOOLS"/DumpsterDiver ]]; then
			echo -e "$LIGHT_GREEN[+] Updating DumpsterDiver.""$NORMAL";
			cd "$TOOLS"/DumpsterDiver;
			sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing DumpsterDiver from Github.""$NORMAL";
		sudo git clone https://github.com/securing/DumpsterDiver.git "$TOOLS"/DumpsterDiver;
		cd "$TOOLS"/DumpsterDiver;
		chmod +x DumpsterDiver.py
		sudo pip3 install -r requirements.txt
	fi
  
	if [[ -d "$TOOLS"/JSFScan.sh ]]; then
		echo -e "$LIGHT_GREEN[+] Updating JSFScan.sh.""$NORMAL";
		cd "$TOOLS"/JSFScan.sh;
		sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing JSFScan.sh from Github.""$NORMAL";
 		sudo git clone https://github.com/KathanP19/JSFScan.sh.git "$TOOLS"/JSFScan.sh;
		cd "$TOOLS"/JSFScan.sh;
		chmod +x JSFScan.sh install.sh
	  	./install.sh
	fi
  if [[ -d "$TOOLS"/ParamSpider ]]; then
		echo -e "$LIGHT_GREEN[+] Updating ParamSpider.""$NORMAL";
		cd "$TOOLS"/ParamSpider;
		sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing ParamSpider from Github.""$NORMAL";
 		sudo git clone https://github.com/devanshbatham/ParamSpider "$TOOLS"/ParamSpider;
		cd "$TOOLS"/ParamSpider;
		sudo pip3 install -r requirements.txt
	fi
  if [[ -d "$TOOLS"/crosslinked ]]; then
		echo -e "$LIGHT_GREEN[+] Updating crosslinked.""$NORMAL";
		cd "$TOOLS"/crosslinked;
		sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing crosslinked from Github.""$NORMAL";
 		sudo git clone https://github.com/m8r0wn/crosslinked "$TOOLS"/crosslinked;
		cd "$TOOLS"/crosslinked;
		sudo pip3 install -r requirements.txt
	fi
	if [[ -d "$TOOLS"/Corsy ]]; then
		echo -e "$LIGHT_GREEN[+] Updating Corsy.""$NORMAL";
		cd "$TOOLS"/Corsy;
		sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing Corsy from Github.""$NORMAL";
		sudo git clone https://github.com/s0md3v/Corsy.git "$TOOLS"/Corsy;
	fi
	if [[ -d "$TOOLS"/CORStest ]]; then
		echo -e "$LIGHT_GREEN[+] Updating CORStest.""$NORMAL";
		cd "$TOOLS"/CORStest;
		sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing CORStest from Github.""$NORMAL";
		sudo git clone https://github.com/RUB-NDS/CORStest.git "$TOOLS"/CORStest;
	fi
	if [[ -d "$TOOLS"/pwndb ]]; then
		echo -e "$LIGHT_GREEN[+] Updating pwndb.""$NORMAL";
		cd "$TOOLS"/pwndb;
		sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing pwndb from Github.""$NORMAL";
		sudo git clone https://github.com/davidtavarez/pwndb.git "$TOOLS"/pwndb;
	fi
	if [[ -d "$TOOLS"/bypass-403 ]]; then
		echo -e "$LIGHT_GREEN[+] Updating bypass-403.""$NORMAL";
		cd "$TOOLS"/bypass-403;
		sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing bypass-403 from Github.""$NORMAL";
		sudo git clone https://github.com/iamj0ker/bypass-403 "$TOOLS"/bypass-403;
		cd "$TOOLS"/bypass-403
		chmod +x bypass-403.sh
	fi
	
	if [[ -d "$TOOLS"/bypass-403 ]]; then
		echo -e "$LIGHT_GREEN[+] O-MY-ZSH installed.""$NORMAL";
	  else
		echo -e "$LIGHT_GREEN[+] Installing O-my-zsh from Github.""$NORMAL";
		sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
	fi
	
	if [[ -d "$TOOLS"/HostHunter ]]; then
			echo -e "$LIGHT_GREEN[+] Updating HostHunter.""$NORMAL";
			cd "$TOOLS"/HostHunter;
			sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing HostHunter from Github.""$NORMAL";
		sudo git clone https://github.com/SpiderLabs/HostHunter  "$TOOLS"/HostHunter;
	fi
	if [[ -d "$TOOLS"/CloudBrute ]]; then
			echo -e "$LIGHT_GREEN[+] Updating CloudBrute.""$NORMAL";
			cd "$TOOLS"/CloudBrute;
			sudo git pull;
	  else
		echo -e "$LIGHT_GREEN[+] Installing CloudBrute from Github.""$NORMAL";
		sudo git clone https://github.com/0xsha/CloudBrute "$TOOLS"/CloudBrute;
		cd "$TOOLS"/CloudBrute
		chmod +x CloudBrute.sh
	fi
}

install_go_tools() {
	echo -e "${BOLD}${LIGHT_GREEN}[+] Installing Go tools from Github.${NORMAL}";
	sleep 1;
  export GO111MODULE=on
	if ! testcmd gitleaks; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing gitleaks...${NORMAL}"
		wget https://github.com/zricethezav/gitleaks/releases/download/v7.0.2/gitleaks-linux-amd64 -O gitleaks 
		chmod +x gitleaks
		sudo mv gitleaks /usr/bin/
      else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing gitleaks...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd findomain; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing findomain...${NORMAL}"
		wget https://github.com/Findomain/Findomain/releases/download/2.1.5/findomain-linux -O findomain
		chmod +x findomain
		sudo mv findomain /usr/bin/
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing findomain...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi

	if ! testcmd wapiti; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing wapiti...${NORMAL}"
		git clone git@github.com:wapiti-scanner/wapiti.git
		cd  wapiti
		python setup.py install
    cd ..
    rm -rf wapiti
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing wapiti...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd massdns; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing massdns...${NORMAL}"
		git clone https://github.com/blechschmidt/massdns.git
		cd massdns
		make
		sudo cp bin/massdns /usr/bin/
		cd ..
		rm -rf massdns
	 else
 		echo -e "${BOLD}${LIGHT_GREEN}[+] massdns...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi  
	if ! testcmd slurp; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing slurp...${NORMAL}"
		git clone https://github.com/gdraperi/slurp-1.git "$TOOLS"/slurp
		cd slurp
		go build
		cp slurp /usr/bin/
		cd ..
		rm -rf slurp
	 else
 		echo -e "${BOLD}${LIGHT_GREEN}[+] slurp...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi  

	if ! testcmd request_smuggler; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing request_smuggler...${NORMAL}"
		git clone https://github.com/Sh1Yo/request_smuggler
		cd request_smuggler
		sudo cargo build --release
		sudo cargo install request_smuggler --version 0.1.0-alpha.1
		cd ..
		cp ~/.cargo/bin/request_smuggler  /usr/bin
		rm -rf request_smuggler
	 else
 		echo -e "${BOLD}${LIGHT_GREEN}[+] request_smuggler...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	
  if ! testcmd pymeta; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing pymeta...${NORMAL}"
		git clone https://github.com/m8r0wn/pymeta
		cd pymeta
		sudo python3 setup.py install > /dev/null
		cd ..
		rm -rf pymeta
	 else
 		echo -e "${BOLD}${LIGHT_GREEN}[+] pymeta...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
  if ! testcmd gotestwaf; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing gotestwaf...${NORMAL}"
		git clone https://github.com/wallarm/gotestwaf.git
    cd gotestwaf
    go build -mod vendor -o gotestwaf ./cmd/main.go
    mv gotestwaf /usr/bin
		cd ..
		rm -rf gotestwaf
	 else
 		echo -e "${BOLD}${LIGHT_GREEN}[+] gotestwaf...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
  if ! testcmd subfinder; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing subfinder...${NORMAL}"
		go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
	 else
 		echo -e "${BOLD}${LIGHT_GREEN}[+] subfinder...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
  if ! testcmd analyticsrelationships; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing analyticsrelationships...${NORMAL}"
    git clone https://github.com/Josue87/AnalyticsRelationships.git
    cd AnalyticsRelationships/  
    go build
    mv analyticsrelationships /usr/bin
    cd ../ && rm -rf AnalyticsRelationships
	 else
 		echo -e "${BOLD}${LIGHT_GREEN}[+] subfinder...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi

  if ! testcmd github-endpoints; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing github-endpoints...${NORMAL}"
    go install github.com/gwen001/github-endpoints@latest
	 else
 		echo -e "${BOLD}${LIGHT_GREEN}[+] github-endpoints...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi

  if ! testcmd github-subdomains; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing github-subdomains...${NORMAL}"
    go install github.com/gwen001/github-subdomains@latest 
	 else
 		echo -e "${BOLD}${LIGHT_GREEN}[+] github-subdomains...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
  
  if ! testcmd dnstake; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing dnstake...${NORMAL}"
     go install github.com/pwnesia/dnstake/cmd/dnstake@latest 
	 else
 		echo -e "${BOLD}${LIGHT_GREEN}[+] dnstake...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi

	if ! testcmd crobat; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing crobat...${NORMAL}"
	  	go install github.com/cgboal/sonarsearch/cmd/crobat 2> /dev/null
	 else
 		echo -e "${BOLD}${LIGHT_GREEN}[+] crobat...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd assetfinder; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing assetfinder...${NORMAL}"
		go install  github.com/tomnomnom/assetfinder@latest
	 else
		echo -e "${BOLD}${LIGHT_GREEN}[+] assetfinder...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd ffuf; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing ffuf...${NORMAL}"
		go install github.com/ffuf/ffuf@latest
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] ffuf...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd gobuster; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing gobuster...${NORMAL}"
		go install  github.com/OJ/gobuster@latest
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] gobuster...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi

	if ! testcmd waybackurls; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing waybackurls...${NORMAL}"
		go install  github.com/tomnomnom/waybackurls@latest
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] waybackurls...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd goaltdns; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing goaltdns...${NORMAL}"
		go install  github.com/subfinder/goaltdns@latest 
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] goaltdns...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd aquatone; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing aquatone...${NORMAL}"
    wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
    unzip aquatone*
    rm LICENSE.txt README.md 
    chmod +x aquatone
    sudo mv aquatone /usr/bin/
    wget https://download-chromium.appspot.com/dl/Linux_x64?type=snapshots
    unzip Linux_x64*
    mv chrome-linux ~/
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] aquatone...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi

	if ! testcmd rescope; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing rescope...${NORMAL}"
		go install  github.com/root4loot/rescope@latest 
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] rescope...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd httpx; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing httpx...${NORMAL}"
		go install  github.com/projectdiscovery/httpx/cmd/httpx@latest 
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] httpx...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd httprobe; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing httprobe...${NORMAL}"
		go install  github.com/tomnomnom/httprobe@latest
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] httprobe...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd metabigor; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing metabigor...${NORMAL}"
		go install  github.com/j3ssie/metabigor@latest
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] metabigor...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd Gxxx; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing Gxxx...${NORMAL}"
    go install github.com/KathanP19/Gxss@latest
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Gxxx...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi

  if ! testcmd getJS; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing getJS...${NORMAL}"
		  go install github.com/003random/getJS@latest > /dev/null
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+]  getJS...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
  if ! testcmd notify; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing notify...${NORMAL}"
      GO111MODULE=on go install -v github.com/projectdiscovery/notify/cmd/notify@latest > /dev/null 
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+]  notify...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
    if ! testcmd jaeles; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing jaeles...${NORMAL}"
       GO111MODULE=on go install github.com/jaeles-project/jaeles@latest > /dev/null 

	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+]  jaeles...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
 	if ! testcmd rustscan; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing rustscan...${NORMAL}"
      wget https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb >/dev/null
      dpkg -i rustscan*.deb 
      rm rustscan*.deb
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+]  rustscan...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd nuclei; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing nuclei...${NORMAL}"
		go install  github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest 
    	git clone https://github.com/geeknik/the-nuclei-templates.git ~/nuclei-templates/extra_templates
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing nuclei...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd qsreplace; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing qsreplace...${NORMAL}"
		go install  github.com/tomnomnom/qsreplace@latest 
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing qsreplace...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd subzy; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing subzy...${NORMAL}"
		go install  github.com/lukasikic/subzy@latest > /dev/null
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing subzy...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd tko-subs; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing tko-subs...${NORMAL}"
		go install github.com/anshumanbh/tko-subs@latest > /dev/null
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing tko-subs...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd shuffledns; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing shuffledns...${NORMAL}"
      wget https://github.com/projectdiscovery/shuffledns/releases/download/v1.0.4/shuffledns_1.0.4_linux_amd64.tar.gz  2>&1
      tar -xvzf shuffledns*.gz 
      sudo mv shuffledns /usr/local/bin
      rm -R shuffledns*.gz
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing shuffledns...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd gospider; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing gospider...${NORMAL}"
		go install  github.com/jaeles-project/gospider@latest 
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+]  gospider...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd gauplus; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing gauplus...${NORMAL}"
    GO111MODULE=on go install -v github.com/bp0lr/gauplus@latest > /dev/null 
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] gauplus...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
  
	if ! testcmd unfurl; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing unfurl...${NORMAL}"
		go install  github.com/tomnomnom/unfurl@latest > /dev/null 
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] unfurl...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
  if ! testcmd anew; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing anew...${NORMAL}"
		go install github.com/tomnomnom/anew@latest  
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+]  anew...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd subjs; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing subjs...${NORMAL}"
		go install  github.com/lc/subjs@latest 
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] subjs...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd gf; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing gf...${NORMAL}"
		go install  github.com/tomnomnom/gf@latest 
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing gf...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd github-subdomains; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing github-subdomains...${NORMAL}"
		go install  github.com/gwen001/github-subdomains@latest 
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] github-subdomains...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi	
	if [ ! -d /root/Gf-Patterns ]; then
		sudo mkdir /root/.gf
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing GF patterns...${NORMAL}"
		sudo git clone https://github.com/1ndianl33t/Gf-Patterns /root/Gf-Patterns
		sudo mv /root/Gf-Patterns/*.json /root/.gf
		# sudo echo 'source $GOPATH/src/github.com/tomnomnom/gf/gf-completion.bash' >> /root/.bashrc
		sudo cp -r /root/go/src/github.com/tomnomnom/gf/examples /root/.gf
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] GF patterns...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	cp -r /root/go/bin/* /usr/bin/
}

Checks(){
  wget -q --spider http://google.com
  if [ $? -ne 0 ];then
    echo "Connect to internet before running bunny!"
    exit 1
  fi
	prompt=$(sudo -nv 2>&1)
	if [ $? -eq 0 ]; then
	  echo "proper"
	elif echo $prompt | grep -q '^sudo:'; then
    echo "try again after sudo -s"
    exit 1;
	else
    echo "no_sudo"
    exit 1;
	fi
}

printf "${bblue} Running: Performing last configurations ${reset}\n\n"
# Last steps
if [ ! -s "resolvers.txt" ] || [ $(find "resolvers.txt" -mtime +1 -print) ]; then
    printf "${yellow} Resolvers seem older than 1 day\n Generating custom resolvers... ${reset}\n\n"
    rm -f resolvers.txt &>/dev/null
    dnsvalidator -tL https://public-dns.info/nameservers.txt -threads $DNSVALIDATOR_THREADS -o resolvers.txt $DEBUG_STD
	dnsvalidator -tL https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt -threads $DNSVALIDATOR_THREADS -o tmp_resolvers $DEBUG_STD
	cat tmp_resolvers $DEBUG_ERROR | anew -q resolvers.txt
	rm -f tmp_resolvers $DEBUG_STD
    [ ! -s "$resolvers" ] && wget -O $resolvers https://raw.githubusercontent.com/proabiral/Fresh-Resolvers/master/resolvers.txt &>/dev/null
fi
# BBRF Setup
# if [ ! -d "$HOME/.bbrf/" ] ; then
#     mkdir $HOME/.bbrf/
# fi
# if  [ -d "$HOME/.bbrf/" ] && [ ! -s "$HOME/.bbrf/config.json" ]; then
#     cat > $HOME/.bbrf/config.json << EOF
# {
#     "username": "$BBRF_USERNAME",
#     "password": "$BBRF_PASSWORD",
#     "couchdb": "https://$BBRF_SERVER/bbrf",
#     "slack_token": "<a slack token to receive notifications>",
#     "discord_webhook": "<your discord webhook if you want one>",
#     "ignore_ssl_errors": false
# }
# EOF
# fi

Checks

# Check for custom path
  CUSTOM_PATH=$1;
  if [[ "$CUSTOM_PATH" != "" ]]; then
    if [[ -e "$1" ]]; then
        TOOLS="$CUSTOM_PATH";
      else
        echo -e "$RED""The path provided does not exist or can't be opened""$NORMAL";
        exit 1;
    fi
  fi

# Create install directory
sudo mkdir -pv $TOOLS;

install_ubuntu;
## Stripping all Go binaries
sudo chmod -R 777 $HOME/go/bin/*
sudo cp $HOME/go/bin/* /usr/bin/ 
echo -e "$ORANGE""[i] Note: In order to use S3Scanner, you must configure your personal AWS credentials in the aws CLI tool.""$NORMAL";
echo "${BLUE} Create a ./config.yml or /root/.githound/config.yml "${NORMAL}""
printf "${yellow} Remember set your api keys:\n - amass (~/.config/amass/config.ini)\n - subfinder (~/.config/subfinder/config.yaml)\n - GitHub (~/Tools/.github_tokens)\n - SHODAN (SHODAN_API_KEY in reconftw.cfg)\n - SSRF Server (COLLAB_SERVER in reconftw.cfg) \n - Blind XSS Server (XSS_SERVER in reconftw.cfg) \n - notify (~/.config/notify/notify.conf) \n - theHarvester (~/Tools/theHarvester/api-keys.yml)\n - H8mail (~/Tools/h8mail_config.ini)\n\n${reset}"
