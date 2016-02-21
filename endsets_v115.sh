#! /bin/bash
##################################################################
# Program: endsets.sh
# Type: bash shell script
# Current Version: 1.15
# Date: February 20 2016
# Stable Version: 1.14
# Date: February 17 2016
# Author: Endwall Development Team 
#
# Description: Loads ipsets, blacklists and whitelists into iptables
#              
# Notes:  This script does not save it's rules and is ephemeral on reboot
#         !!DO NOT ATTEMPT TO MAKE THIS SAVE THE RULES YET!!
#         - I am looking into fixing this
#
# Change Log: - Fixed the Logging problem (reverse order of log and drop due to insert)
#             - Use && to execute log and drop rules in parallel (multiprocess)
#             - Fixed ip error in ipv6 blacklist 
#             - Fixed a typo in dns_blacklist
#             - Added instructions for banning on fly
#             - Moved string matching blacklists into endsets
#             - Fixed log flags to match spamalertz.sh
#             - Added IPv6 blacklist to sets and blacklist
#             - Moved the ephemeral portion of endwall into endset
#             
###################################################################
#                   INSTRUCTIONS
###################################################################
# STEP 1) INSTALL ipset
# $ su
# # pacman -S ipset 
#
# STEP 2) make directory and save file, make blacklists and whitelists
# $ 
# $ mkdir ~/endwall
# $ cp vdyvuh.sh ~/endwall/endwall.sh
# $ cp rshrwh.sh ~/endwall/endset.sh
# $ cd ~/endwall
# $ echo " " >> smtp_whitelist.txt  # whitelist (hotmail,gmail,etc)
# $ echo " " >> http_whitelist.txt  # users of your website  
# $ echo " " >> http_blacklist.txt  # ipv4 addresses to restrict http/https
# $ echo " " >> smtp_blacklist.txt  # ipv4 addresses to restrict smtp access
# $ echo " " >> dns_blacklist.txt   # ipv4 addresses to restrict dns access/ bad dns actors
# $ echo " " >> attackers.txt       # ipv4 blacklist for hack attackers 
# $ echo " " >> blacklist.txt       # ipv4 blacklist of DOD subnets and others 
# $ echo " " >> email_blacklist.txt # strings of email addresses and keywords to block from smtp
# $ echo " " >> html_blacklist.txt  # strings of attack html calls (cgi,php) to block from http 
# $ echo " " >> ipv6_blacklist.txt  # ipv6 blacklist for subnets
# $ ls                              # list the files you just made
# 
# STEP 3) edit endwall.sh and endset.sh to suite your needs
# $ nano endwall.sh   # go to the section below labeled GLOBAL VARIABLES
#                       edit the variables client1_ip,client1_mac,client1_ip,client2_mac 
#                       so that they match your needs and save. ^X  
#                       uncomment the macchanger lines to use machanger
#
# STEP 4) Make files executable and run them
# $ chmod u+rwx endset.sh         # changer permisions to allow script execution
# $ chmod u+rwx endwall.sh        # change permisions to allow script execution 
# $ su                            # become root
# #./endwall.sh                   # First execute endwall to set your firewall and save it 
# #./endsets.sh                   # Next execute/run the file endset.sh to setup blacklists and whitelists
###############################################################################################
#                       ADDING TO BAN LIST EXAMPLES
##############################################################################################
# Next add ip addresses to the whitelists and blacklists
# Example: adding an ip to attackers.txt
# $ echo "116.58.45.115" >> attackers.txt
# Example: banning a subnet from accessing smtp
# $ echo "116.58.0.0/16" >> smtp_blacklist.txt
# Example: banning a larger subnet from accessing http
# $ echo "117.0.0.0/8" >> http_blacklist.txt
# Example: banning a large subnet from accessing anything on your server
# $ echo "6.0.0.0/8" >> blacklist.txt
# Example: banning a spammer 
# $ echo "retard_lamer@website.com" >> email_blacklist.txt (read the postfix log for examples)
# Example: banning a hacker diving for files on your webserver (read your httpd log for examples)
# $ echo "/configuration.php" >> html_blacklist.txt
# $ echo "/wordpress/xmlrpc.php" >> html_blacklist.txt
# $ chmod u+wrx endwall.sh
# $ su                     
# # ./endwall.sh   # run the firewall script with the new blacklisted ipv4 addresses
###############################################################################################
#                      BANNING ON THE FLY WITH IPSETS
###############################################################################################
# # ipset add http_blacklist 113.205.0.0/16
# # ipset add smtp_blacklist 113.205.0.0/16 
# # ipset add blacklist 6.0.0.0/8
# # ipset add dns_blacklist 114.50.150.58
# # ipset add attackers 114.58.29.158
#
#  Whitelisting should only be done to singleton ip addresses or at most a  /24 block
#
# # ipset add http_whitelist 198.252.153.0/24
# # ipset add smtp_whitelist 198.252.153.0/24
#
######################################################################################################
#                           GLOBAL VARIABLES
#######################################################################################################
iptables=/sbin/iptables
ip6tables=/sbin/ip6tables

#systemctl enable iptables
#systemctl enable ip6tables
#systemctl enable iptables.service
#systemctl enable ip6tables.service
#systemctl restart iptablees
#systemctl restart ip6tables

# Grab interface name from ip link and parse 
int_if1=$(ip link | grep -a "state " | gawk -F: '{ if (FNR==2) print $2}')
int_if2=$(ip link | grep -a "state " | gawk -F: '{ if (FNR==3) print $2}')

# Grab Gateway Information
gateway_ip=$(ip route | gawk '/via/ {print $3}')
#gateway_mac=$( arp | gawk '/gateway/ {print $3}')
gateway_mac=$( nmap -sS $gateway_ip -p 53| grep -a "MAC Address:" | gawk '{print $3}')

# RUN MAC CHANGER on INTERFACES
#macchanger -A $int_if
#macchanger -A $int_if2

# grab host mac addresses from ip link  
host_mac1=$(ip link | grep -a "ether" | gawk ' {if (FNR==1) print $2}')
host_mac2=$(ip link | grep -a "ether" | gawk ' {if (FNR==2) print $2}')

# grab the ip addresses from the interfaces
host_ip1=$(ip addr | grep -a "scope global"|gawk 'BEGIN  {FS="/"} {if (FNR==1) print $1}'| gawk '{print $2}')
host_ip2=$(ip addr | grep -a "scope global"|gawk 'BEGIN  {FS="/"} {if (FNR==2) print $1}'| gawk '{print $2}')

host_ip1v6=$(ip addr | grep -a "scope link"|gawk 'BEGIN  {FS="/"} {if (FNR==1) print $1}'| gawk '{print $2}')
host_ip2v6=$(ip addr | grep -a "scope link"|gawk 'BEGIN  {FS="/"} {if (FNR==2) print $1}'| gawk '{print $2}')

##################### INTERNAL VARIABLES

int_mac1=$host_mac1
int_ip1=$host_ip1   # set the ip of the machine
int_ip1v6=$host_ip1v6

int_mac2=$host_mac2
int_ip2=$host_ip2
int_ip2v6=$host_ip2v6

############################################################################################################

###################################################################################################################################
#                              LINUX SECURITY BOOLEANS
###################################################################################################################################
# Disable Source Routed Packets
for f in /proc/sys/net/ipv4/conf/*/accept_source_route; do
       echo 0 > $f
done

# Disable ICMP Redirect Acceptance
for f in /proc/sys/net/ipv4/conf/*/accept_redirects; do
      echo 0 > $f
done

# Don't send Redirect Messages
for f in /proc/sys/net/ipv4/conf/*/send_redirects; do
     echo 0 > $f
done

# Drop Spoofed Packets coming in on an interface, which if replied to,
# would result in the reply going out a different interface.
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
     echo 1 > $f
done

# Log packets with impossible addresses.
for f in /proc/sys/net/ipv4/conf/*/log_martians; do
     echo 1 > $f
done

echo 1 > /proc/sys/net/ipv4/tcp_syncookies                              # enable tcp syn cookies (prevent against the common 'syn flood attack')
echo 0 > /proc/sys/net/ipv4/ip_forward                                  # disable Packet forwarding between interfaces
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts                 # ignore all ICMP ECHO and TIMESTAMP requests sent to it via broadcast/multicast
echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses           # disable logging of bogus responses to broadcast frames
echo 1 > /proc/sys/net/ipv4/conf/all/log_martians                       # log packets with impossible addresses to kernel log
echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter                          # do source validation by reversed path (Recommended option for single homed hosts)
echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route                # Disable source routed packets redirects
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects                   # don't accept redirects
echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects                     # don't send redirects
echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route                # don't accept packets with SRR option

echo 0 > /proc/sys/net/ipv6/conf/all/accept_redirects                   # don't accept redirects
echo 0 > /proc/sys/net/ipv6/conf/all/accept_source_route                # don't accept packets with SRR option

#echo 1 > /proc/sys/net/ipv4/conf/all/disable_ipv6                      # disable ipv6
#setsebool httpd_can_network_connect on   #needed for squirelmail if you are on selinux
#setsebool httpd_can_sendmail on          #needed for squirelmail send if you are selinux

###################################################################################################
#                       IP SET CREATION 
###################################################################################################
ipset flush
ipset destroy

ipset destroy ipv6_blacklist

ipset create blacklist hash:net hashsize 65536 
ipset create http_blacklist hash:net hashsize 65536   
ipset create smtp_blacklist hash:net hashsize 65536 
ipset create dns_blacklist hash:net hashsize 65536  
ipset create attackers hash:net hashsize 65536
ipset create http_whitelist hash:net hashsize 65536
ipset create smtp_whitelist hash:net hashsize 65536 

ipset create ipv6_blacklist hash:net family inet6 hashsize 65536

ipset flush

####################################################################################
#                    IP FILTER BLACK LISTS
####################################################################################

echo HTTP/HTTPS BLACKLIST LOADING

iptables -I OUTPUT  -p tcp -s $int_ip1 -m set --match-set http_blacklist dst -m multiport --sports 80,443 -j DROP && iptables -I OUTPUT  -p tcp -s $int_ip1 -m set --match-set http_blacklist dst -m multiport --dports 80,443 -j DROP;

iptables -I OUTPUT  -p tcp -s $int_ip1 -m set --match-set http_blacklist dst -m multiport --sports 80,443 -j LOG --log-prefix "[HTTP-BL OUT] "  --log-level=info && iptables -I OUTPUT  -p tcp -s $int_ip1 -m set --match-set http_blacklist dst -m multiport --dports 80,443 -j LOG --log-prefix "[HTTP-BL OUT] "  --log-level=info 

iptables -I INPUT  27 -p tcp -d $int_ip1 -m set --match-set http_blacklist src -m multiport --dports 80,443 -j DROP && iptables -I INPUT  27 -p tcp -d $int_ip1 -m set --match-set http_blacklist src -m multiport --sports 80,443 -j DROP;

iptables -I INPUT  27 -p tcp -d $int_ip1 -m set --match-set http_blacklist src -m multiport --dports 80,443 -j LOG --log-prefix "[HTTP-BL IN] " --log-level=info && iptables -I INPUT  27 -p tcp -d $int_ip1 -m set --match-set http_blacklist src -m multiport --sports 80,443 -j LOG --log-prefix "[HTTP-BL IN] " --log-level=info;

#iptables -I FORWARD  -p tcp -m set --match-set http_blacklist src -m multiport --dports 80,443 -j DROP;
#iptables -I FORWARD  -p tcp -m set --match-set http_blacklist src -m multiport --sports 80,443 -j DROP;
#iptables -I FORWARD  -p tcp -m set --match-set http_blacklist dst -m multiport --sports 80,443 -j DROP;
#iptables -I FORWARD  -p tcp -m set --match-set http_blacklist dst -m multiport --dports 80,443 -j DROP;

#iptables -I FORWARD  -p tcp -m set --match-set http_blacklist src -m multiport --dports 80,443 -j LOG --log-prefix "[HTTP-BL FORWARD IN] "  --log-level=info 
#iptables -I FORWARD  -p tcp -m set --match-set http_blacklist src -m multiport --sports 80,443 -j LOG --log-prefix "[HTTP-BL FORWARD IN] "  --log-level=info 
#iptables -I FORWARD  -p tcp -m set --match-set http_blacklist dst -m multiport --sports 80,443 -j LOG --log-prefix "[HTTP-BL FORWARD OUT] " --log-level=info 
#iptables -I FORWARD  -p tcp -m set --match-set http_blacklist dst -m multiport --dports 80,443 -j LOG --log-prefix "[HTTP-BL FORWARD OUT] " --log-level=info 

echo HTTP BLACKLIST LOADED

echo SMTP BLACKLIST LOADING

iptables -I OUTPUT  -p tcp -s $int_ip1 -m set --match-set smtp_blacklist dst -m multiport --sports 25,587 -j DROP && iptables -I OUTPUT  -p tcp -s $int_ip1 -m set --match-set smtp_blacklist dst -m multiport --dports 25,587 -j DROP;
iptables -I OUTPUT  -p tcp -s $int_ip1 -m set --match-set smtp_blacklist dst -m multiport --sports 25,587 -j LOG --log-prefix "[SMTP-BL OUT] " --log-level=info && iptables -I OUTPUT  -p tcp -s $int_ip1 -m set --match-set smtp_blacklist dst -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-BL OUT] " --log-level=info; 

iptables -I INPUT  27 -p tcp -d $int_ip1 -m set --match-set smtp_blacklist src -m multiport --dports 25,587 -j DROP && iptables -I INPUT  27 -p tcp -d $int_ip1 -m set --match-set smtp_blacklist src -m multiport --sports 25,587 -j DROP;
iptables -I INPUT  27 -p tcp -d $int_ip1 -m set --match-set smtp_blacklist src -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-BL IN] " --log-level=info && iptables -I INPUT  27 -p tcp -d $int_ip1 -m set --match-set smtp_blacklist src -m multiport --sports 25,587 -j LOG --log-prefix "[SMTP-BL IN] " --log-level=info 

#iptables -I FORWARD  -p tcp -d $int_ip1 -m set --match-set smtp_blacklist src -m multiport --dports 25,587 -j DROP;
#iptables -I FORWARD  -p tcp -d $int_ip1 -m set --match-set smtp_blacklist src -m multiport --sports 25,587 -j DROP;
#iptables -I FORWARD  -p tcp -d $int_ip1 -m set --match-set smtp_blacklist dst -m multiport --sports 25,587 -j DROP;
#iptables -I FORWARD  -p tcp -d $int_ip1 -m set --match-set smtp_blacklist dst -m multiport --dports 25,587 -j DROP;

#iptables -I FORWARD  -p tcp -d $int_ip1 -m set --match-set smtp_blacklist src -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-BL FORWARD IN] " --log-level=info 
#iptables -I FORWARD  -p tcp -d $int_ip1 -m set --match-set smtp_blacklist src -m multiport --sports 25,587 -j LOG --log-prefix "[SMTP-BL FORWARD IN] " --log-level=info 
#iptables -I FORWARD  -p tcp -s $int_ip1 -m set --match-set smtp_blacklist dst -m multiport --sports 25,587 -j LOG --log-prefix "[SMTP-BL FORWARD OUT] " --log-level=info 
#iptables -I FORWARD  -p tcp -s $int_ip1 -m set --match-set smtp_blacklist dst -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-BL FORWARD OUT] " --log-level=info 

echo SMTP BLACKLIST LOADED

echo DNS BLACKLIST LOADING

iptables -I OUTPUT  -p udp -s $int_ip1 -m set --match-set dns_blacklist dst --dport 53 -j DROP && iptables -I OUTPUT  -p udp -s $int_ip1 -m set --match-set dns_blacklist dst --sport 53 -j DROP;
iptables -I INPUT  27 -p udp -d $int_ip1 -m set --match-set dns_blacklist src --dport 53 -j DROP && iptables -I INPUT  27 -p udp -d $int_ip1 -m set --match-set dns_blacklist src --sport 53 -j DROP;


iptables -I OUTPUT  -p udp -s $int_ip1 -m set --match-set dns_blacklist dst --dport 53 -j LOG --log-prefix "[DNS-BL UDP OUT] " --log-level=info && iptables -I OUTPUT  -p udp -s $int_ip1 -m set --match-set dns_blacklist dst --sport 53 -j LOG --log-prefix "[DNS-BL UDP OUT] " --log-level=info; 

iptables -I INPUT  27 -p udp -d $int_ip1 -m set --match-set dns_blacklist src --dport 53 -j LOG --log-prefix "[DNS-BL UDP IN] " --log-level=info && iptables -I INPUT  27 -p udp -d $int_ip1 -m set --match-set dns_blacklist src --sport 53 -j LOG --log-prefix "[DNS-BL UDP IN] " --log-level=info; 

#iptables -I FORWARD  -p udp -d $int_ip1 -m set --match-set dns_blacklist src --dport 53 -j DROP;
#iptables -I FORWARD  -p udp -d $int_ip1 -m set --match-set dns_blacklist src --sport 53 -j DROP;
#iptables -I FORWARD  -p udp -s $int_ip1 -m set --match-set dns_blacklist dst --dport 53 -j DROP;
#iptables -I FORWARD  -p udp -s $int_ip1 -m set --match-set dns_blacklist dst --sport 53 -j DROP;

#iptables -I FORWARD  -p udp -d $int_ip1 -m set --match-set dns_blacklist src --dport 53 -j LOG --log-prefix "[DNS-BL UDP FORWARD IN] " --log-level=info 
#iptables -I FORWARD  -p udp -d $int_ip1 -m set --match-set dns_blacklist src --sport 53 -j LOG --log-prefix "[DNS-BL UDP FORWARD IN] " --log-level=info 
#iptables -I FORWARD  -p udp -s $int_ip1 -m set --match-set dns_blacklist dst --dport 53 -j LOG --log-prefix "[DNS-BL UDP FORWARD OUT] " --log-level=info 
#iptables -I FORWARD  -p udp -s $int_ip1 -m set --match-set dns_blacklist dst --sport 53 -j LOG --log-prefix "[DNS-BL UDP FORWARD OUT] " --log-level=info 

iptables -I OUTPUT -p tcp -s $int_ip1 -m set --match-set dns_blacklist dst --dport 53 -j DROP && iptables -I OUTPUT -p tcp -s $int_ip1 -m set --match-set dns_blacklist dst --sport 53 -j DROP;
iptables -I OUTPUT -p tcp -s $int_ip1 -m set --match-set dns_blacklist dst --dport 53 -j LOG --log-prefix "[DNS-BL TCP OUT] " --log-level=info && iptables -I OUTPUT -p tcp -s $int_ip1 -m set --match-set dns_blacklist dst --sport 53 -j LOG --log-prefix "[DNS-BL TCP OUT] " --log-level=info ;

iptables -I INPUT 27 -p tcp -d $int_ip1 -m set --match-set dns_blacklist src --dport 53 -j DROP && iptables -I INPUT 27 -p tcp -d $int_ip1 -m set --match-set dns_blacklist src --sport 53 -j DROP;
iptables -I INPUT 27 -p tcp -d $int_ip1 -m set --match-set dns_blacklist src --dport 53 -j LOG --log-prefix "[DNS-BL TCP IN] " --log-level=info && iptables -I INPUT 27 -p tcp -d $int_ip1 -m set --match-set dns_blacklist src --sport 53 -j LOG --log-prefix "[DNS-BL TCP IN] " --log-level=info ;

#iptables -I FORWARD  -p tcp -d $int_ip1 -m set --match-set dns_blacklist src --dport 53 -j DROP;
#iptables -I FORWARD  -p tcp -d $int_ip1 -m set --match-set dns_blacklist src --sport 53 -j DROP;
#iptables -I FORWARD  -p tcp -s $int_ip1 -m set --match-set dns_blacklist dst --dport 53 -j DROP;
#iptables -I FORWARD  -p tcp -s $int_ip1 -m set --match-set dns_blacklist dst --sport 53 -j DROP;

#iptables -I FORWARD  -p tcp -d $int_ip1 -m set --match-set dns_blacklist src --dport 53 -j LOG --log-prefix "[DNS-BL TCP FORWARD IN] " --log-level=info 
#iptables -I FORWARD  -p tcp -d $int_ip1 -m set --match-set dns_blacklist src --sport 53 -j LOG --log-prefix "[DNS-BL TCP FORWARD IN] " --log-level=info 
#iptables -I FORWARD  -p tcp -s $int_ip1 -m set --match-set dns_blacklist dst --dport 53 -j LOG --log-prefix "[DNS-BL TCP FORWARD OUT] " --log-level=info 
#iptables -I FORWARD  -p tcp -s $int_ip1 -m set --match-set dns_blacklist dst --sport 53 -j LOG --log-prefix "[DNS-BL TCP FORWARD OUT] " --log-level=info 

echo DNS BLACKLIST LOADED

echo ATTACKER BLACKLIST LOADING

iptables -I OUTPUT   -p all -s $int_ip1 -m set --match-set attackers dst -j DROP && iptables -I INPUT 27 -p all -d $int_ip1 -m set --match-set attackers src -j DROP;
iptables -I OUTPUT   -p all -s $int_ip1 -m set --match-set attackers dst -j LOG --log-prefix "[ATTACKER OUT] " --log-level=info && iptables -I INPUT 27 -p all -d $int_ip1 -m set --match-set attackers src -j LOG --log-prefix "[ATTACKER IN] "  --log-level=info; 

#iptables -I FORWARD  -p all -d $int_ip1 -m set --match-set attackers src -j LOG --log-prefix "[ATTACKER FORWARD IN] "  --log-level=info && iptables -I FORWARD  -p all -d $int_ip1 -m set --match-set attackers src -j DROP;
#iptables -I FORWARD  -p all -s $int_ip1 -m set --match-set attackers dst -j LOG --log-prefix "[ATTACKER FORWARD OUT] "  --log-level=info && iptables -I FORWARD  -p all -s $int_ip1 -m set --match-set attackers dst -j DROP;

echo ATTACKER BLACKLIST LOADED

echo LOADING BLACKLIST 
iptables -I OUTPUT   -p all -m set --match-set blacklist dst -j DROP && iptables -I INPUT 27 -p all -m set --match-set blacklist src -j DROP;
iptables -I OUTPUT   -p all -m set --match-set blacklist dst -j LOG --log-prefix "[BLACKLIST OUT] "  --log-level=info && iptables -I INPUT 27 -p all -m set --match-set blacklist src -j LOG --log-prefix "[BLACKLIST IN] "  --log-level=info;

#iptables -I FORWARD  -p all -m set --match-set blacklist src -j DROP;
#iptables -I FORWARD  -p all -m set --match-set blacklist dst -j DROP;

#iptables -I FORWARD  -p all -m set --match-set blacklist src -j LOG --log-prefix "[BLACKLIST FORWARD IN] " --log-level=info 
#iptables -I FORWARD  -p all -m set --match-set blacklist dst -j LOG --log-prefix "[BLACKLIST FORWARD OUT] "  --log-level=info 

echo BLACKLIST LOADED


echo LOADING IPv6 BLACKLIST 

ip6tables -I OUTPUT   -p all -m set --match-set ipv6_blacklist dst -j DROP && ip6tables -I INPUT 27 -p all -m set --match-set ipv6_blacklist src -j DROP;
ip6tables -I OUTPUT   -p all -m set --match-set ipv6_blacklist dst -j LOG --log-prefix "[IPv6-BLACKLIST OUT] " --log-level=info && ip6tables -I INPUT 27 -p all -m set --match-set ipv6_blacklist src -j LOG --log-prefix "[IPv6-BLACKLIST IN] "  --log-level=info; 

#ip6tables -I FORWARD  -p all -m set --match-set ipv6_blacklist src -j DROP && ip6tables -I FORWARD  -p all -m set --match-set ipv6_blacklist dst -j DROP;
#ip6tables -I FORWARD  -p all -m set --match-set ipv6_blacklist src -j LOG --log-prefix "[IPv6-BLACKLIST FORWARD IN] "  --log-level=info 
#ip6tables -I FORWARD  -p all -m set --match-set ipv6_blacklist dst -j LOG --log-prefix "[IPv6-BLACKLIST FORWARD OUT] "  --log-level=info 

echo IPv6 BLACKLIST LOADED


####################################################################################
#                    IP FILTER WHITE LISTS
####################################################################################

echo SMTP WHITELIST LOADING

iptables -I OUTPUT  -p tcp -s $int_ip1 -m set --match-set smtp_whitelist dst -m multiport --dports 25,587 -j ACCEPT && iptables -I INPUT 27  -p tcp -d $int_ip1 -m set --match-set smtp_whitelist src -m multiport --dports 25,587 -j ACCEPT; 
iptables -I OUTPUT  -p tcp -s $int_ip1 -m set --match-set smtp_whitelist dst -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-WL OUT] " --log-level=info && iptables -I INPUT 27  -p tcp -d $int_ip1 -m set --match-set smtp_whitelist src -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-WL IN] " --log-level=info 

echo SMTP WHITELIST LOADED

echo HTTP/HTTPS WHITELIST LOADING

iptables -I OUTPUT  -p tcp -s $int_ip1 -m set --match-set http_whitelist dst -m multiport --dports 80,443 -j ACCEPT && iptables -I INPUT 27  -p tcp -d $int_ip1 -m set --match-set http_whitelist src -m multiport --dports 80,443 -j ACCEPT;
iptables -I OUTPUT  -p tcp -s $int_ip1 -m set --match-set http_whitelist dst -m multiport --dports 80,443 -j LOG --log-prefix "[HTTPS-WL OUT] " --log-level=info && iptables -I INPUT 27  -p tcp -d $int_ip1 -m set --match-set http_whitelist src -m multiport --dports 80,443 -j LOG --log-prefix "[HTTPS-WL IN] " --log-level=info 

echo HTTP/HTTPS WHITELIST LOADED

#######################################################################################
#                  STRING MATCHING BLACKLISTS
######################################################################################
echo EMAIL BLACKLIST LOADING
for blackout in $(cat email_blacklist.txt);
do 
(

iptables -I INPUT 27  -p tcp --dport 25 -m string --string "$blackout" --algo bm -j DROP && iptables -I OUTPUT  -p tcp --dport 25 -m string --string "$blackout" --algo bm -j DROP; 
iptables -I INPUT 27  -p tcp --dport 25 -m string --string "$blackout" --algo bm -j LOG --log-prefix "[EMAIL SPAM] "--log-level=info && iptables -I OUTPUT -p tcp --dport 25 -m string --string "$blackout" --algo bm -j LOG --log-prefix "[EMAIL SPAM] " --log-level=info ;

#iptables -I FORWARD -p tcp --dport 25 -m string --string "$blackout" --algo bm -j DROP 
#iptables -I FORWARD -p tcp --dport 25 -m string --string "$blackout" --algo bm -j LOG --log-prefix "[EMAIL SPAM] " --log-level=info 
)
echo $blackout ; 
done 
echo EMAIL BLACKLIST LOADED

echo HTML BLACKLIST LOADING
for blackout in $(cat html_blacklist.txt);
do 
(

iptables -I INPUT 27  -p tcp -m multiport --dports 80,443 -m string --string "$blackout" --algo bm -j DROP && iptables -I OUTPUT  -p tcp -m multiport --dports 80,443 -m string --string "$blackout" --algo bm -j DROP; 
iptables -I INPUT 27  -p tcp -m multiport --dports 80,443 -m string --string "$blackout" --algo bm -j LOG --log-prefix "[HTTP SPAM] " --log-level=info && iptables -I OUTPUT  -p tcp -m multiport --dports 80,443 -m string --string "$blackout" --algo bm -j LOG --log-prefix "[HTTP SPAM] " --log-level=info ;

#iptables -I FORWARD -p tcp -m multiport --dports 80,443 -m string --string "$blackout" --algo bm -j DROP 
#iptables -I FORWARD -p tcp -m multiport --dports 80,443 -m string --string "$blackout" --algo bm -j LOG --log-prefix "[HTTP SPAM] " --log-level=info  
)
echo $blackout ; 
done 
echo HTML BLACKLIST LOADED


#########################################
#         POPULATE WHITELISTS
#######################################
echo LOADING HTTP WHITELIST 
for whiteout in $(cat http_whitelist.txt);
do 
(
ipset add http_whitelist $whiteout 
)
echo $whiteout ; 
done
echo HTTP WHITELIST LOADED

echo LOADING SMTP WHITELIST 
for whiteout in $(cat smtp_whitelist.txt);
do 
(
ipset add smtp_whitelist $whiteout 
)
echo $whiteout ; 
done
echo SMTP WHITELIST LOADED

##################################################
#       POPULATE BLACKLISTS
###################################################
echo LOADING BLACKLIST 
for blackout in $(cat blacklist.txt);
do 
(
ipset add blacklist $blackout 
)
echo $blackout ; 
done
echo BLACKLIST LOADED

echo LOADING IPv6 BLACKLIST 
for blackout in $(cat ipv6_blacklist.txt);
do 
(
ipset add ipv6_blacklist $blackout 
)
echo $blackout ; 
done
echo IPv6 BLACKLIST LOADED

echo LOADING HTTP BLACKLIST 
for blackout in $(cat http_blacklist.txt);
do 
(
ipset add http_blacklist $blackout 
)
echo $blackout ; 
done
echo HTTP BLACKLIST LOADED

echo LOADING SMTP BLACKLIST 
for blackout in $(cat smtp_blacklist.txt);
do 
(
ipset add smtp_blacklist $blackout 
)
echo $blackout ; 
done
echo SMTP BLACKLIST LOADED

echo LOADING ATTACKER BLACKLIST 
for blackout in $(cat attackers.txt);
do 
(
ipset add attackers $blackout 
)
echo $blackout ; 
done
echo ATTACKER BLACKLIST LOADED

echo LOADING DNS BLACKLIST 
for blackout in $(cat dns_blacklist.txt);
do 
(
ipset add dns_blacklist $blackout 
)
echo $blackout ; 
done
echo DNS BLACKLIST LOADED
#########################################

echo "ENDSETS LOADED"
################################  PRINT RULES   ###############################################################
#list the rules
#iptables -L -v
#ip6tables -L -v

#############################   PRINT ADDRESSES  ############################################################
echo GATEWAY  :          MAC:$gateway_mac  IP:$gateway_ip  
echo INTERFACE_1: $int_if1  MAC:$int_mac1  IPv4:$int_ip1 IPv6:$int_ip1v6
echo INTERFACE_2: $int_if2 MAC:$int_mac2 IPv4:$int_ip2 IPv6:$int_ip2v6
# print the time the script finishes
date











