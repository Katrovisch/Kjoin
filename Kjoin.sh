#!/bin/bash

# Environment Variables:
ID_LINUX=$(awk -F "=" '/^ID=/ {print $2}' /etc/os-release | sed 's/^"\(.*\)".*/\1/')
MACHINE=$(hostname)

# CONFs:
hosts="/etc/hosts"
krb5conf="/etc/krb5.conf"
smbconf="/etc/samba/smb.conf"
nsswitchconf="/etc/nsswitch.conf"
pamconf_deb="/etc/pam.d/common-session"
pamconf_rhel="/etc/pam.d/password-auth"
lightdmconf="/etc/lightdm/lightdm.conf.d/99-login-ad.conf"
sudoers="/etc/sudoers.d/admins"
chrony="/etc/chrony.conf"
hosts="/etc/hosts"

# LOGs:
LOGGING="/var/log/kjoin"

if ! which dialog &> /dev/null; then
    dialog=1; echo "[x] Required dependencies: dialog: not installed"
fi

if ! which whiptail &> /dev/null; then
    whiptail=1; echo "[x] Required dependencies: whiptail not installed"
fi

if [ $ID_LINUX = "linuxmint" ] || [ $ID_LINUX = "debian" ] || [ $ID_LINUX = "ubuntu" ]; then
    if ! which nslookup &> /dev/null; then
        dnsutils=1; echo "[x] Required dependencies: dnsutils not installed"
    fi
elif [ $ID_LINUX = "centos" ] || [ $ID_LINUX = "fedora" ]
then
    if ! which nslookup &> /dev/null; then
        bind_utils=1; echo "[x] Required dependencies: bind-utils not installed"
    fi
fi

if [ "$dialog" = "1" ] || [ "$whiptail" = "1" ] || [ "$dnsutils" = "1" ] || [ "$bind_utils" = "1" ]; then exit; fi

export DEBIAN_FRONTEND=noninteractive

main() {

auth=$(dialog --stdout \
--ok-label 'OK' \
--cancel-label 'CANCEL' \
--title 'KJoin' \
--backtitle 'KJoin - Integration Assistant' \
--menu '' \
0 0 0 \
1 'Domain Join' \
2 'Leave Domain' \
3 'Exit')

case $auth in

1) domain_join ;;
2) leave_domain ;;
3) exit ;;
esac

}

credentiais_authentication() {

    domain=""
    admindc=""

    # open fd
    exec 3>&1

    form=$(dialog --ok-label "OK" \
          --cancel-label 'CANCEL' \
	      --backtitle "KJoin - Integration Assistant" \
          --title "Credentials" \
	      --form "" 0 50 0 \
	    "Domain Name:"    1 1    "$domain"  1 17 26 0 \
	    "Administrators:" 2 1    "$admindc"   2 17 26 0 \
    2>&1 1>&3)

    if [ $? -eq 1 ]; then main; fi

    # close fd
    exec 3>&-

    array=($form)

    passwd_ad=$( dialog --stdout --backtitle 'KJoin - Integration Assistant' --title 'Password Administrators' --passwordbox '' 7 35 )
    
    if [ $? -eq 1 ]; then credentiais_authentication; fi

    check_domain

    networking_settings

    kerberos_auth

    # ${array[0]}
}

credentiais_leave() {

    admindc=""

    exec 3>&1

    form2=$(dialog --ok-label "OK" \
          --cancel-label 'CANCEL' \
	      --backtitle "KJoin - Integration Assistant" \
          --title "Credentials" \
	      --form "" 0 50 0 \
	    "Administrator:"  1 1    "$admindc"  1 17 26 0 2>&1 1>&3)

    if [ $? -eq 1 ]; then main; fi

    exec 3>&-

    array_leave=($form2)
    passwd_ad=$( dialog --stdout --backtitle 'KJoin - Integration Assistant' --passwordbox 'Password Administrator:' 0 0 )

    if [ $? -eq 1 ]; then credentiais_leave; fi
}

check_domain(){

OUTPUT=$(host ${array[0]} 2>&1)
if [ $? -gt 0 ]
then
   dialog --backtitle 'KJoin - Integration Assistant' --title 'ERROR:' --infobox '\nDomain not found\n\n' 0 0
   DATE=$(date +"[%D %T]:"); echo "$DATE $OUTPUT" >> $LOGGING
   sleep 3
   credentiais_authentication
else
    IP=$(host ${array[0]} | awk -F "address " '{print $2}')
    hostname=$(nslookup $IP | grep "name" |cut -d' ' -f3 | cut -d. -f1)
fi

}

kerberos_auth() {

dialog --backtitle 'KJoin - Integration Assistant' --infobox 'Authenticating To The Active Directory' 3 42

if [ $ID_LINUX = "linuxmint" ] || [ $ID_LINUX = "debian" ] || [ $ID_LINUX = "ubuntu" ]
then
    apt install -y krb5-user &> /dev/null

    if ! dpkg -s krb5-user &> /dev/null; then dialog --title "Kerberos failed authentication" --yesno 'krb5-workstation not installed\nwant abort' 0 0; if [ $? = 0 ]; then exit; fi; fi

elif [ $ID_LINUX = "centos" ]
then
    yum install -y krb5-workstation &> /dev/null

    if ! rpm -q krb5-workstation &> /dev/null; then dialog --title "Kerberos failed authentication" --yesno 'krb5-workstation not installed\nwant abort' 0 0; if [ $? = 0 ]; then exit; fi; fi

elif [ $ID_LINUX = "fedora" ]
then
    dnf install -y krb5-workstation &> /dev/null

    if ! rpm -q krb5-workstation &> /dev/null; then dialog --title "Kerberos failed authentication" --yesno 'krb5-workstation not installed\nwant abort' 0 0; if [ $? = 0 ]; then exit; fi; fi
fi

if [ -f $krb5conf.backup ]; then
    rm $krb5conf; cp $krb5conf.backup $krb5conf
else
    cp $krb5conf $krb5conf.backup
fi

DOMAIN=$(echo ${array[0]} | tr '[:lower:]' '[:upper:]')

cat << EOF > $krb5conf

[logging]
        default = FILE:/var/log/krb5.log

[libdefaults]
        default_realm = $DOMAIN

[realms]
        $DOMAIN = {
        kdc = $hostname.${array[0]}
        default_domain = ${array[0]}
        admin_server = $hostname.${array[0]}
}

[domain_realm]
        .${array[0]} = $DOMAIN
        ${array[0]} = $DOMAIN
EOF

OUTPUT=$(echo "$passwd_ad" | kinit ${array[1]} 2>&1)

if [ $? -eq 1 ]; then
   DATE=$(date +"[%D %T]:"); echo "$DATE $OUTPUT" >> $LOGGING
   dialog --backtitle 'KJoin - Integration Assistant' --infobox 'Invalid Credentials' 3 24
   sleep 3
   credentiais_authentication
fi

}

networking_settings(){

if [ $ID_LINUX = "linuxmint" ] || [ $ID_LINUX = "ubuntu" ]
then
    if [ $(echo ${array[0]} |grep --count .local) -eq 1 ]
    then

    if [ -f $nsswitchconf.backup ]; then
        rm $nsswitchconf; cp $nsswitchconf.backup $nsswitchconf
    else
        cp $nsswitchconf $nsswitchconf.backup
    fi

        sed -i '/^hosts:/ s/^/#/' $nsswitchconf
        echo -e "\n# ADD\nhosts:\t\tfiles dns" >> $nsswitchconf
    fi
fi

}

samba() {

# Samba
workgroup=$(echo ${array[0]} | sed 's/.[^.]*$//')

cat << EOF > $smbconf

[global]
        workgroup = $workgroup
        realm = $DOMAIN
        security = ads
        winbind uid = 10000-20000
        winbind gid = 10000-20000
        winbind enum users = yes
        winbind enum groups = yes
        winbind use default domain = yes
        template shell = /bin/bash
        template homedir = /home/%D/%U
        winbind refresh tickets = yes
EOF

}

backup_restore() {

if [ -f $smbconf.backup ]; then rm $smbconf; mv $smbconf.backup $smbconf; fi
if [ -f $krb5conf.backup ]; then rm $krb5conf; mv $krb5conf.backup $krb5conf; fi
if [ -f $nsswitchconf.backup ]; then rm $nsswitchconf; mv $nsswitchconf.backup $nsswitchconf; fi
if [ -f $hosts.backup ]; then rm $hosts; mv $hosts.backup $hosts; fi
if [ -f $sudoers ]; then rm $sudoers; fi

if [ $ID_LINUX = "linuxmint" ] || [ $ID_LINUX = "debian" ] || [ $ID_LINUX = "ubuntu" ]
then
    if [ -f $pamconf_deb.backup ]; then rm $pamconf_deb; mv $pamconf_deb.backup $pamconf_deb; fi

   elif [ $ID_LINUX = "centos" ] || [ $ID_LINUX = "fedora" ]
then
    if [ -f $pamconf_rhel.backup ]; then rm $pamconf_rhel; mv $pamconf_rhel.backup $pamconf_rhel; fi
    if [ -f $chrony.backup ]; then rm $chrony; mv $chrony.backup $chrony; fi
fi

}

backup() {

cp $smbconf $smbconf.backup

if [ $ID_LINUX = "linuxmint" ] || [ $ID_LINUX = "debian" ] || [ $ID_LINUX = "ubuntu" ]
then
    cp $pamconf_deb $pamconf_deb.backup

   elif [ $ID_LINUX = "centos" ] || [ $ID_LINUX = "fedora" ]
then
    cp $pamconf_rhel $pamconf_rhel.backup
    cp $chrony $chrony.backup
fi

}

lightdm() {
  echo -e "[SeatDefaults]\n\tallow-guest=false\n\tgreeter-show-manual-login=true" > $lightdmconf  
}

install_dependencies_winbind(){

if [ $ID_LINUX = "linuxmint" ] || [ $ID_LINUX = "debian" ] || [ $ID_LINUX = "ubuntu" ]
then
    PACKAGES=("samba" "winbind" "libpam-winbind" "libnss-winbind" "libpam-krb5" "ntpdate" "sudo")
    package=$[${#PACKAGES[@]}-1]
    progress=$[100/${#PACKAGES[@]}]

    for n in $(seq 0 $package)
    do
      apt install -y ${PACKAGES[$n]} &> /dev/null | dialog --backtitle 'Installation Dependencies' --gauge "\nInstalling: ${PACKAGES[$n]}" 0 0 $progress

      if ! dpkg -s ${PACKAGES[$n]} &> /dev/null
      then
          dialog --backtitle 'KJoin - Integration Assistant' --title 'Want Abort ?' --yesno "\nPackage ${PACKAGES[$n]} not installed\n\n" 0 0 
          if [ $? = 0 ]
          then 
            DATE=$(date +"[%D %T]:"); echo "$DATE Package ${PACKAGES[$n]} Not Installed" >> $LOGGING; exit
          fi
      fi
    progress=$(( progress+$[100/${#PACKAGES[@]}] ))
    done
elif [ $ID_LINUX = "centos" ]
then

    PACKAGES=("samba-winbind" "chrony" "bind-utils" "oddjob-mkhomedir" "samba-winbind-clients" "authselect" "authselect-compat" "sudo")
    package=$[${#PACKAGES[@]}-1]
    progress=$[100/${#PACKAGES[@]}]

    for n in $(seq 0 $package)
    do
      yum install -y ${PACKAGES[$n]} &> /dev/null | dialog --backtitle 'Installation Dependencies' --gauge "\nInstalling: ${PACKAGES[$n]}" 0 0 $progress

      if ! rpm -q ${PACKAGES[$n]} &> /dev/null
      then
         dialog --backtitle 'KJoin - Integration Assistant' --title 'Want Abort ?' --yesno "\nPackage ${PACKAGES[$n]} not installed\n\n" 0 0
         if [ $? = 0 ]
         then
            DATE=$(date +"[%D %T]:"); echo "$DATE Package ${PACKAGES[$n]} Not Installed" >> $LOGGING; exit
       fi
    fi
    progress=$(( progress+$[100/${#PACKAGES[@]}] ))
    done

elif [ $ID_LINUX = "fedora" ]
then

    PACKAGES=("samba-winbind" "chrony" "bind-utils" "oddjob-mkhomedir" "samba-winbind-clients" "authselect" "authselect-compat" "sudo")
    package=$[${#PACKAGES[@]}-1]
    progress=$[100/${#PACKAGES[@]}]

    for n in $(seq 0 $package)
    do
      dnf install -y ${PACKAGES[$n]} &> /dev/null | dialog --backtitle 'Installation Dependencies' --gauge "\nInstalling: ${PACKAGES[$n]}" 0 0 $progress

      if ! rpm -q ${PACKAGES[$n]} &> /dev/null
      then
         dialog --backtitle 'KJoin - Integration Assistant' --title 'Want Abort ?' --yesno "\nPackage ${PACKAGES[$n]} not installed\n\n" 0 0
         if [ $? = 0 ]
         then
            DATE=$(date +"[%D %T]:"); echo "$DATE Package ${PACKAGES[$n]} Not Installed" >> $LOGGING; exit
         fi
      fi
    progress=$(( progress+$[100/${#PACKAGES[@]}] ))
    done
fi

}

domain_join() {

credentiais_authentication

install_dependencies_winbind
dialog --backtitle 'KJoin - Integration Assistant' --title 'Authentication Winbind' --infobox '\n    Satisfied dependencies' 5 34
sleep 2
dialog --backtitle 'KJoin - Integration Assistant' --infobox "Joining the domain ${array[0]}" 3 22

# BACKUP FILES (.conf):
backup
sleep 2

##### SAMBA #####
samba

##### JOIN #####
OUTPUT=$(net ads join -U ${array[1]}%$passwd_ad 2>&1)
if [ $(echo $OUTPUT | grep -c NT_STATUS_ACCESS_DENIED) -eq 1 ]
then
    whiptail --backtitle 'KJoin - Integration Assistant' --title 'Error' --msgbox "\nUser ${array[1]} without privileges to join the domain" --fb 0 0
    DATE=$(date +"[%D %T]:"); echo "$DATE $OUTPUT" >> $LOGGING
    domain_join
fi
sleep 2

# Name Service Switch (NSS)
if [ $ID_LINUX = "linuxmint" ] || [ $ID_LINUX = "debian" ] || [ $ID_LINUX = "ubuntu" ]
then
    sed -i '/^passwd:/  s/$/ winbind/' $nsswitchconf
    sed -i '/^group:/  s/$/ winbind/' $nsswitchconf
    sed -i '/^shadow:/  s/$/ winbind/' $nsswitchconf

elif [ $ID_LINUX = "centos" ] || [ $ID_LINUX = "fedora" ]
then
    authselect select winbind --force &> /dev/null
fi
sleep 2

# Pluggable Authentication Modules (PAM)
if [ $ID_LINUX = "linuxmint" ] || [ $ID_LINUX = "debian" ] || [ $ID_LINUX = "ubuntu" ]
then
    echo -e "session required\tpam_mkhomedir.so umask=0022 skel=/etc/skel" >> $pamconf_deb

elif [ $ID_LINUX = "centos" ] || [ $ID_LINUX = "fedora" ]
then
    authconfig --enablemkhomedir --update &> /dev/null
fi
sleep 2

# LightDM
if [ $(systemctl show -p SubState lightdm.service | cut -d= -f2) = "running" ]
then
  lightdm
fi

# WINBIND SERVICES
systemctl restart winbind.service

if [ $(systemctl is-enabled winbind) = "disabled" ]; then
    systemctl enable winbind.service &> /dev/null
fi

DATE=$(date +"[%D %T]:"); echo "$DATE $MACHINE Successfully joined to the domain" >> $LOGGING

#  REBOOT
whiptail --backtitle 'KJoin - Integration Assistant' --title 'Reboot Required' \
--msgbox '  Machine Successfully Joined To The Domain' --fb 10 50
reboot
}

leave_domain() {

if [ $(systemctl show -p LoadState winbind.service | cut -d= -f2 | grep -c loaded) -eq 1 ]
then
    credentiais_leave
    OUTPUT=$(echo "$passwd_ad" | net ads testjoin -U ${array_leave[0]} 2>&1)
    if [ "$OUTPUT" = "Join is OK" ]; then
        net_adsinfo=$(net ads info | head -n -4)
            dialog --title 'Want To Leave The Domain ?' --yesno "$net_adsinfo" 0 0
            if [ $? -eq 0 ]; then
                OUTPUT=$(net ads leave -U ${array_leave[0]}%$passwd_ad 2>&1)
                if [ $? -gt 0 ]; then
                    if [ $(echo $OUTPUT | grep -c -o -i 'insufficient access') -eq 1 ]
                    then
                        DATE=$(date +"[%D %T]:"); echo "$DATE $OUTPUT" >> $LOGGING
                        dialog --infobox 'User with insufficient privileges' 3 38
                        sleep 3
                        leave
                    else
                        DATE=$(date +"[%D %T]:"); echo "$DATE $OUTPUT" >> $LOGGING
                        dialog --infobox 'Invalid Credentials' 3 24
                        sleep 3
                        leave
                    fi
                fi
            dialog --backtitle 'KJoin - Integration Assistant' --title 'Leave Domain' --infobox "\n\nRemoving $MACHINE from Domain\n\n\n" 0 0
            sleep 2
                backup_restore
                systemctl stop winbind.service && systemctl disable winbind.service &> /dev/null
                DATE=$(date +"[%D %T]:"); echo "$DATE Removing $MACHINE from Domain..." >> $LOGGING
                DATE=$(date +"[%D %T]:"); echo "$DATE Leave domain successfully" >> $LOGGING
            dialog --infobox 'Leave Domain Successfully' 3 30
        else
            main
        fi
    else
        dialog --infobox 'This Machine Is Not In The Domain' 3 38
    fi
else
    dialog --infobox 'This machine is not performing winbind authentication' 3 58
fi
}

main
