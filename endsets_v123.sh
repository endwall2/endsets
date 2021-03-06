#!/bin/sh
##################################################################
# Program: endsets.sh
# Type: Bourne shell script
# Creation Date: February 12, 2016
# Current Version: 1.24
# Revision Date: June 2 2016
# Stable Version: 1.22
# Stable Version Date: May 05 2016
# Author: The Endware Development Team 
# Copyright: The Endware Development Team, 2016
#
# Description: Loads ipsets, blacklists and whitelists into iptables
#              
# Notes:  This script can be modified to not save it's rules 
#         and be ephemeral on reboot by commenting out lines 513-522
#         do not attempt to save the iptables ruleset unless you have enabled
#         the ipset daemon, as this may cause your firewall to fail and reset in 
#         an open policy state (no firewall).
#        
# Change Log: - Annotated Beginning and End of Program
#             - Fixed insertion numbers
#             - Added tor exit node grabber
#             - Updated EULA
#             - Added EULA
#             - moved booleans to endwall using syctl (removed from script)
#             - Added save persistence
#             - Fixed some style issues
#             - Fixed the Logging problem (reverse order of log and drop due to insert)
#             - Use && to execute log and drop rules in parallel (multiprocess)
#             - Fixed ip error in ipv6 blacklist 
#             - Fixed a typo in dns_blacklist
#             - Added instructions for banning on fly
#             - Moved string matching blacklists into endsets
#             - Fixed log flags to match spamalertz.sh
#             - Added IPv6 blacklist to sets and blacklist
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
# $ chmod u+rwx endset.sh          # changer permisions to allow script execution
# $ chmod u+rwx endwall.sh         # change permisions to allow script execution 
# $ su                             # become root
# #./endwall.sh                    # First execute endwall to set your firewall and save it 
# # systemctl enable ipset.service # Enable ipset to run as a daemon on reboot
# # systemctl start ipset          # Start the ipset daemon
# #./endsets.sh                    # Next execute/run the file endset.sh to setup blacklists and whitelists
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
# # ./endlists.sh  # (optional) configure this for /8 bans with big_bans.txt
# # ./endsets.sh   # run endsets
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
################################################################################################
#                          ENABLE IPTABLES/IP6TABLES 
#################################################################################################
# systemd commands:
# systemctl enable iptables
# systemctl enable ip6tables
# systemctl enable iptables.service
# systemctl enable ip6tables.service
# systemctl restart iptables
# systemctl restart ip6tables
####################################################################################################
#                          ENABLE IPSET 
##################################################################################################
# systemctl enable ipset.service
# systemctl start ipset
# systemctl restart ipset
##############################################################################################################################################################################
#                                         ACKNOWLEDGEMENTS
##############################################################################################################################################################################
#  The Endware Development Team would like to acknowledge the work and efforts
#  of OdiliTime, who graciously hosted and promoted this firewall project.
#  Without his efforts and his wonderful website www.endchan.xyz , the Endware Suite including Endwall would not
#  exist in the public domain at all in any form. So thanks to OdiliTime for inspiring this work
#  and for hosting and promoting it. 
#  
#  The Endware Suite including Endwall,Endsets,Endlists,Endtools, Endloads and Endtube are named in honor of Endchan.
#
#  Thank you also to early beta testers including a@a, and to other contributors 
#  as well as to the detractors who helped to critique this work and to ultimately improve it.  
#  
#  We also acknowledge paste.debian.net, ix.io and gitweb for their hosting services, 
#  without which distribution would be limited, so thank you.
#
#  https://www.endchan.xyz, http://paste.debian.net, http://gitweb2zl5eh7tp3.onion , http://ix.io  
#
#  We salute you! 
#  
#  In the end, may it all end well.
#
#  The Endware Development Team
###############################################################################################################################################################################
##############################################################################################################################################################################
#                               LICENSE AGREEMENT  
##############################################################################################################################################################################
#  BEGINNING OF LICENSE AGREMENT
#  TITLE:  THE ENDWARE END USER LICENSE AGREEMENT (EULA) 
#  CREATION DATE: MARCH 19, 2016
#  VERSION: 1.08 
#  VERSION DATE: MAY 12, 2016
#  COPYRIGHT: THE ENDWARE DEVELOPMENT TEAM, 2016
#      
#  WHAT CONSTITUES "USE"? WHAT IS A "USER"?
#  0) a) Use of this program means the ability to study, posses, run, copy, modify, publish, distribute and sell the code as included in all lines of this file,
#        in text format or as a binary file consituting this particular program or its compiled binary machine code form, as well as the the performance 
#        of these aforementioned actions and activities. 
#  0) b) A user of this program is any individual who has been granted use as defined in section 0) a) of the LICENSE AGREEMENT, and is granted to those individuals listed in section 1.
#  WHO MAY USE THIS PROGRAM ?
#  1) a) This program may be used by any living human being, any person, any corporation, any company, and by any sentient individual with the willingness and ability to do so.
#  1) b) This program may be used by any citizen or resident of any country, and by any human being without citizenship or residency.
#  1) c) This program may be used by any civilian, military officer, government agent, private citizen, public official, soveriegn, monarch, head of state,
#        dignitary, ambassdor, noble, commoner, clergy, layity, and generally all classes and ranks of people, persons, and human beings mentioned and those not mentioned.
#  1) d) This program may be used by any human being of any gender, including men, women, and any other gender not mentioned.       
#  1) e) This program may be used by anyone of any afiliation, political viewpoint, political affiliation, religious belief, religious affiliation, and by those of non-belief or non affiliation.
#  1) f) This program may be used by any person of any race, ethnicity, identity, origin, genetic makeup, physical apperance, mental ability, and by those of any other physical 
#        or non physical characteristics of differentiation.
#  1) g) This program may be used by any human being of any sexual orientation, including heterosexual, homosexual, bisexual, asexual, or any other sexual orientation not mentioned.
#  1) h) This program may be used by anyone. 
#  WHERE MAY A USER USE THIS PROGRAM ?
#  2) a) This program may be used in any country, in any geographic location of the planet Earth, in any marine or maritime environment, at sea, subsea, in a submarine, underground,
#        in the air, in an airplane, dirigible, blimp, or balloon, and at any distance from the surface of the planet Earth, including in orbit about the Earth or the Moon,
#        on a satellite orbiting about the Earth or about any planet, on any space transport vehicle, and anywhere in the solar system including the Moon, Mars, and all other solar system planets not listed.  
#  2) b) This program may be used in any residential, commercial, business, and governmental property or location and in all public and private spaces. 
#  2) c) This program may be used anywhere.
#  IN WHAT CONTEXT OR CIRCUMSTANCES MAY A USER USE THIS PROGRAM?
#  3)  This program may be used by any person, human being or sentient individual for any purpose and in any context and in any setting including for personal use, academic use,
#      business use, commercial use, government use, non-governmental organization use, non-profit organization use, military use, civilian use, and generally any other use 
#      not specifically mentioned.
#  WHAT MAY A "USER" DO WITH THIS PROGRAM ?
#  4) Any user of this program is granted the freedom to study the code.
#  5) a) Any user of this program is granted the freedom to distribute, publish, and share the code with any neighbor of their choice electronically or by any other method of transmission. 
#  5) b) The LICENCSE AGREEMENT, ACKNOWLEDGEMENTS, Header and Instructions must remain attached to the code in their entirety when re-distributed.
#  5) c) Any user of this program is granted the freedom to sell this software as distributed or to bundle it with other software or saleable goods.
#  6) a) Any user of this program is granted the freedom to modify and improve the code.
#  6) b) When modified or improved, any user of this program is granted the freedom of re-distribution of their modified code if and only if the user attatchs the LICENSE AGREEMENT
#        in its entirety to their modified code before re-distribution.
#  6) c) Any user of this software is granted the freedom to sell their modified copy of this software or to bundle their modified copy with other software or saleable goods.
#  7) a) Any user of this program is granted the freedom to run this code on any computer of their choice.
#  7) b) Any user of this program is granted the freedom to run as many simultaneous instances of this code, on as many computers as they are able to and desire, and for as long as they desire and are
#        able to do so with any degree of simultaneity in use. 
#  WHAT MUST A "USER" NOT DO WITH THIS PROGRAM ?
#  8) Any user of this program is not granted the freedom to procur a patent for the methods presented in this software, and agrees not to do so.
#  9) Any user of this program is not granted the freedom to arbitrarily procur a copyright on this software as presented, and agrees not to do so.
#  10) Any user of this program is not granted the freedom to obtain or retain intelectual property rights on this software as presented and agrees not to do so.
#  11) a) Any user of this program may use this software as part of a patented process, as a substitutable input into the process; however the user agrees not to attempt to patent this software as part of their patented process. 
#      b) This software is a tool, like a hammer, and may be used in a process which applies for and gains a patent, as a substitutable input into the process;
#         however the software tool itself may not be included in the patent or covered in the patent as a novel invention, and the user agrees not to do this and not to attempt to do this.
#  WHO GRANTS THESE FREEDOMS ?
#  10) The creators of this software are the original developer,"Endwall", and anyone listed as being a member of "The Endware Development Team", as well as ancillary contributors, and user modifiers and developers of the software. 
#  11) The aformentioned freedoms of use listed in sections 4),5),6),and 7) are granted by the creators of this software and the Endware Development Team to any qualifying user listed in section 1) and 
#      comporting with any restrictions and qualifications mentioned in sections 2), 3), 8), 9), 10) and 11) of this LICENSE AGREEMENT.
#  WHAT RELATIONSHIP DO THE USERS HAVE WITH THE CREATORS OF THE SOFTWARE ?
#  12)  This software is distributed without any warranty and without any guaranty and the creators do not imply anything about its usefulness or efficacy.
#  13)  If the user suffers or sustains financial loss, informational loss, material loss, physical loss or data loss as a result of using, running, or modifying this software 
#       the user agrees that they will hold the creators of this software, "The Endware Development Team", "Endwall", and the programers involved in its creation, free from prosecution, 
#       free from indemnity, and free from liability, and will not attempt to seek restitution or renumeration for any such loss real or imagined.
#  END OF LICENSE AGREEMENT
##################################################################################################################################################################################
#  ADITIONAL NOTES:
#  14)  If a user finds a significant flaw or makes a significant improvement to this software, please feel free to notify the original developers so that we may also
#       include your user improvement in the next release; users are not obligated to do this, but we would enjoy this courtesy tremendously.
#
#  15)  Sections 0) a) 0) b) and 1) a) are sufficient for use; however sections 1) b) through 1) h) are presented to clarify 1 a) and to enforce non-discrimination and non-exlusion of use.  
#       For example some people may choose to redefine the meaning of the words "person" "human being" or "sentient individual" to exclude certain types of people.
#       This would be deemed unacceptable and is specifically rejected by the enumeration presented.  If the wording presented is problematic please contact us and suggest a change,
#       and it will be taken into consideration.  
#################################################################################################################################################################################

#############################################################   BEGINNING OF PROGRAM  ##############################################################################

######################################################################################################
#                           GLOBAL VARIABLES
#######################################################################################################
iptables=/sbin/iptables
ip6tables=/sbin/ip6tables

# Grab interface name from ip link and parse 
int_if1=$(ip link | grep -a "state " | awk -F: '{ if (FNR==2) print $2}')
int_if2=$(ip link | grep -a "state " | awk -F: '{ if (FNR==3) print $2}')

# Grab Gateway Information
gateway_ip=$(ip route | awk '/via/ {print $3}')
#gateway_mac=$( arp | awk '/gateway/ {print $3}')
gateway_mac=$( nmap -sS $gateway_ip -p 53| grep -a "MAC Address:" | awk '{print $3}')

# RUN MAC CHANGER on INTERFACES
#macchanger -A "$int_if"
#macchanger -A "$int_if2"

# grab host mac addresses from ip link  
host_mac1=$(ip link | grep -a "ether" | awk ' {if (FNR==1) print $2}')
host_mac2=$(ip link | grep -a "ether" | awk ' {if (FNR==2) print $2}')

# grab the ip addresses from the interfaces
host_ip1=$(ip addr | grep -a "scope global"|awk 'BEGIN  {FS="/"} {if (FNR==1) print $1}'| awk '{print $2}')
host_ip2=$(ip addr | grep -a "scope global"|awk 'BEGIN  {FS="/"} {if (FNR==2) print $1}'| awk '{print $2}')

host_ip1v6=$(ip addr | grep -a "scope link"|awk 'BEGIN  {FS="/"} {if (FNR==1) print $1}'| awk '{print $2}')
host_ip2v6=$(ip addr | grep -a "scope link"|awk 'BEGIN  {FS="/"} {if (FNR==2) print $1}'| awk '{print $2}')

#####################    INTERNAL VARIABLES  #########################################################

int_mac1="$host_mac1"
int_ip1="$host_ip1"   # set the ip of the machine
int_ip1v6="$host_ip1v6"

int_mac2="$host_mac2"
int_ip2="$host_ip2"
int_ip2v6="$host_ip2v6"

############################################################################################################

###################################################################################################
#                       IP SET CREATION 
###################################################################################################
ipset flush
ipset destroy

ipset create -exist blacklist hash:net hashsize 65536 
ipset create -exist http_blacklist hash:net hashsize 65536   
ipset create -exist smtp_blacklist hash:net hashsize 65536 
ipset create -exist dns_blacklist hash:net hashsize 65536  
ipset create -exist attackers hash:net hashsize 65536
ipset create -exist http_whitelist hash:net hashsize 65536
ipset create -exist smtp_whitelist hash:net hashsize 65536 
ipset create -exist tor_list hash:net hashsize 65536 

ipset create ipv6_blacklist hash:net family inet6 hashsize 65536

ipset flush

####################################################################################
#                    IP FILTER BLACK LISTS
####################################################################################

echo HTTP/HTTPS BLACKLIST LOADING

iptables -I OUTPUT 51 -p tcp -s "$int_ip1" -m set --match-set http_blacklist dst -m multiport --sports 80,443 -j DROP && iptables -I OUTPUT 51 -p tcp -s "$int_ip1" -m set --match-set http_blacklist dst -m multiport --dports 80,443 -j DROP;
iptables -I OUTPUT 51 -p tcp -s $int_ip1 -m set --match-set http_blacklist dst -m multiport --sports 80,443 -j LOG --log-prefix "[HTTP-BL OUT] "  --log-level=info && iptables -I OUTPUT 51 -p tcp -s "$int_ip1" -m set --match-set http_blacklist dst -m multiport --dports 80,443 -j LOG --log-prefix "[HTTP-BL OUT] "  --log-level=info 
iptables -I INPUT  51 -p tcp -d "$int_ip1" -m set --match-set http_blacklist src -m multiport --dports 80,443 -j DROP && iptables -I INPUT 51 -p tcp -d "$int_ip1" -m set --match-set http_blacklist src -m multiport --sports 80,443 -j DROP;
iptables -I INPUT  51 -p tcp -d "$int_ip1" -m set --match-set http_blacklist src -m multiport --dports 80,443 -j LOG --log-prefix "[HTTP-BL IN] " --log-level=info && iptables -I INPUT 51 -p tcp -d "$int_ip1" -m set --match-set http_blacklist src -m multiport --sports 80,443 -j LOG --log-prefix "[HTTP-BL IN] " --log-level=info;

#iptables -I FORWARD 51 -p tcp -m set --match-set http_blacklist src -m multiport --dports 80,443 -j DROP;
#iptables -I FORWARD 51 -p tcp -m set --match-set http_blacklist src -m multiport --sports 80,443 -j DROP;
#iptables -I FORWARD 51 -p tcp -m set --match-set http_blacklist dst -m multiport --sports 80,443 -j DROP;
#iptables -I FORWARD 51 -p tcp -m set --match-set http_blacklist dst -m multiport --dports 80,443 -j DROP;

#iptables -I FORWARD 51 -p tcp -m set --match-set http_blacklist src -m multiport --dports 80,443 -j LOG --log-prefix "[HTTP-BL FORWARD IN] "  --log-level=info 
#iptables -I FORWARD 51 -p tcp -m set --match-set http_blacklist src -m multiport --sports 80,443 -j LOG --log-prefix "[HTTP-BL FORWARD IN] "  --log-level=info 
#iptables -I FORWARD 51 -p tcp -m set --match-set http_blacklist dst -m multiport --sports 80,443 -j LOG --log-prefix "[HTTP-BL FORWARD OUT] " --log-level=info 
#iptables -I FORWARD 51 -p tcp -m set --match-set http_blacklist dst -m multiport --dports 80,443 -j LOG --log-prefix "[HTTP-BL FORWARD OUT] " --log-level=info 

echo HTTP BLACKLIST LOADED

echo SMTP BLACKLIST LOADING

iptables -I OUTPUT 51 -p tcp -s "$int_ip1" -m set --match-set smtp_blacklist dst -m multiport --sports 25,587 -j DROP && iptables -I OUTPUT 51 -p tcp -s "$int_ip1" -m set --match-set smtp_blacklist dst -m multiport --dports 25,587 -j DROP;
iptables -I OUTPUT 51 -p tcp -s "$int_ip1" -m set --match-set smtp_blacklist dst -m multiport --sports 25,587 -j LOG --log-prefix "[SMTP-BL OUT] " --log-level=info && iptables -I OUTPUT 51 -p tcp -s "$int_ip1" -m set --match-set smtp_blacklist dst -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-BL OUT] " --log-level=info; 
iptables -I INPUT  51 -p tcp -d "$int_ip1" -m set --match-set smtp_blacklist src -m multiport --dports 25,587 -j DROP && iptables -I INPUT  51 -p tcp -d "$int_ip1" -m set --match-set smtp_blacklist src -m multiport --sports 25,587 -j DROP;
iptables -I INPUT  51 -p tcp -d "$int_ip1" -m set --match-set smtp_blacklist src -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-BL IN] " --log-level=info && iptables -I INPUT  51 -p tcp -d "$int_ip1" -m set --match-set smtp_blacklist src -m multiport --sports 25,587 -j LOG --log-prefix "[SMTP-BL IN] " --log-level=info 

#iptables -I FORWARD 51 -p tcp -d "$int_ip1" -m set --match-set smtp_blacklist src -m multiport --dports 25,587 -j DROP;
#iptables -I FORWARD 51 -p tcp -d "$int_ip1" -m set --match-set smtp_blacklist src -m multiport --sports 25,587 -j DROP;
#iptables -I FORWARD 51 -p tcp -d "$int_ip1" -m set --match-set smtp_blacklist dst -m multiport --sports 25,587 -j DROP;
#iptables -I FORWARD 51 -p tcp -d "$int_ip1" -m set --match-set smtp_blacklist dst -m multiport --dports 25,587 -j DROP;

#iptables -I FORWARD 51 -p tcp -d "$int_ip1" -m set --match-set smtp_blacklist src -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-BL FORWARD IN] " --log-level=info 
#iptables -I FORWARD 51 -p tcp -d "$int_ip1" -m set --match-set smtp_blacklist src -m multiport --sports 25,587 -j LOG --log-prefix "[SMTP-BL FORWARD IN] " --log-level=info 
#iptables -I FORWARD 51 -p tcp -s "$int_ip1" -m set --match-set smtp_blacklist dst -m multiport --sports 25,587 -j LOG --log-prefix "[SMTP-BL FORWARD OUT] " --log-level=info 
#iptables -I FORWARD 51 -p tcp -s "$int_ip1" -m set --match-set smtp_blacklist dst -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-BL FORWARD OUT] " --log-level=info 

echo SMTP BLACKLIST LOADED

echo DNS BLACKLIST LOADING

iptables -I OUTPUT 51 -p udp -s "$int_ip1" -m set --match-set dns_blacklist dst --dport 53 -j DROP && iptables -I OUTPUT 51 -p udp -s "$int_ip1" -m set --match-set dns_blacklist dst --sport 53 -j DROP;
iptables -I INPUT  51 -p udp -d "$int_ip1" -m set --match-set dns_blacklist src --dport 53 -j DROP && iptables -I INPUT  51 -p udp -d "$int_ip1" -m set --match-set dns_blacklist src --sport 53 -j DROP;
iptables -I OUTPUT 51 -p udp -s "$int_ip1" -m set --match-set dns_blacklist dst --dport 53 -j LOG --log-prefix "[DNS-BL UDP OUT] " --log-level=info && iptables -I OUTPUT 51 -p udp -s "$int_ip1" -m set --match-set dns_blacklist dst --sport 53 -j LOG --log-prefix "[DNS-BL UDP OUT] " --log-level=info; 
iptables -I INPUT  51 -p udp -d "$int_ip1" -m set --match-set dns_blacklist src --dport 53 -j LOG --log-prefix "[DNS-BL UDP IN] " --log-level=info && iptables -I INPUT 51 -p udp -d "$int_ip1" -m set --match-set dns_blacklist src --sport 53 -j LOG --log-prefix "[DNS-BL UDP IN] " --log-level=info; 

#iptables -I FORWARD 51 -p udp -d "$int_ip1" -m set --match-set dns_blacklist src --dport 53 -j DROP;
#iptables -I FORWARD 51 -p udp -d "$int_ip1" -m set --match-set dns_blacklist src --sport 53 -j DROP;
#iptables -I FORWARD 51 -p udp -s "$int_ip1" -m set --match-set dns_blacklist dst --dport 53 -j DROP;
#iptables -I FORWARD 51 -p udp -s "$int_ip1" -m set --match-set dns_blacklist dst --sport 53 -j DROP;

#iptables -I FORWARD 51 -p udp -d "$int_ip1" -m set --match-set dns_blacklist src --dport 53 -j LOG --log-prefix "[DNS-BL UDP FORWARD IN] " --log-level=info 
#iptables -I FORWARD 51 -p udp -d "$int_ip1" -m set --match-set dns_blacklist src --sport 53 -j LOG --log-prefix "[DNS-BL UDP FORWARD IN] " --log-level=info 
#iptables -I FORWARD 51 -p udp -s "$int_ip1" -m set --match-set dns_blacklist dst --dport 53 -j LOG --log-prefix "[DNS-BL UDP FORWARD OUT] " --log-level=info 
#iptables -I FORWARD 51 -p udp -s "$int_ip1" -m set --match-set dns_blacklist dst --sport 53 -j LOG --log-prefix "[DNS-BL UDP FORWARD OUT] " --log-level=info 

iptables -I OUTPUT 51 -p tcp -s "$int_ip1" -m set --match-set dns_blacklist dst --dport 53 -j DROP && iptables -I OUTPUT 51 -p tcp -s $int_ip1 -m set --match-set dns_blacklist dst --sport 53 -j DROP;
iptables -I OUTPUT 51 -p tcp -s "$int_ip1" -m set --match-set dns_blacklist dst --dport 53 -j LOG --log-prefix "[DNS-BL TCP OUT] " --log-level=info && iptables -I OUTPUT 51 -p tcp -s "$int_ip1" -m set --match-set dns_blacklist dst --sport 53 -j LOG --log-prefix "[DNS-BL TCP OUT] " --log-level=info ;
iptables -I INPUT 51 -p tcp -d "$int_ip1" -m set --match-set dns_blacklist src --dport 53 -j DROP && iptables -I INPUT 51 -p tcp -d "$int_ip1" -m set --match-set dns_blacklist src --sport 53 -j DROP;
iptables -I INPUT 51 -p tcp -d "$int_ip1" -m set --match-set dns_blacklist src --dport 53 -j LOG --log-prefix "[DNS-BL TCP IN] " --log-level=info && iptables -I INPUT 51 -p tcp -d "$int_ip1" -m set --match-set dns_blacklist src --sport 53 -j LOG --log-prefix "[DNS-BL TCP IN] " --log-level=info ;

#iptables -I FORWARD 51 -p tcp -d "$int_ip1" -m set --match-set dns_blacklist src --dport 53 -j DROP;
#iptables -I FORWARD 51 -p tcp -d "$int_ip1" -m set --match-set dns_blacklist src --sport 53 -j DROP;
#iptables -I FORWARD 51 -p tcp -s "$int_ip1" -m set --match-set dns_blacklist dst --dport 53 -j DROP;
#iptables -I FORWARD 51 -p tcp -s "$int_ip1" -m set --match-set dns_blacklist dst --sport 53 -j DROP;

#iptables -I FORWARD 51 -p tcp -d "$int_ip1" -m set --match-set dns_blacklist src --dport 53 -j LOG --log-prefix "[DNS-BL TCP FORWARD IN] " --log-level=info 
#iptables -I FORWARD 51 -p tcp -d "$int_ip1" -m set --match-set dns_blacklist src --sport 53 -j LOG --log-prefix "[DNS-BL TCP FORWARD IN] " --log-level=info 
#iptables -I FORWARD 51 -p tcp -s "$int_ip1" -m set --match-set dns_blacklist dst --dport 53 -j LOG --log-prefix "[DNS-BL TCP FORWARD OUT] " --log-level=info 
#iptables -I FORWARD 51 -p tcp -s "$int_ip1" -m set --match-set dns_blacklist dst --sport 53 -j LOG --log-prefix "[DNS-BL TCP FORWARD OUT] " --log-level=info 

echo DNS BLACKLIST LOADED

echo ATTACKER BLACKLIST LOADING

iptables -I OUTPUT 51 -p all -s "$int_ip1" -m set --match-set attackers dst -j DROP && iptables -I INPUT 51 -p all -d $int_ip1 -m set --match-set attackers src -j DROP;
iptables -I OUTPUT 51  -p all -s "$int_ip1" -m set --match-set attackers dst -j LOG --log-prefix "[ATTACKER OUT] " --log-level=info && iptables -I INPUT 51 -p all -d "$int_ip1" -m set --match-set attackers src -j LOG --log-prefix "[ATTACKER IN] "  --log-level=info; 

#iptables -I FORWARD 51 -p all -d "$int_ip1" -m set --match-set attackers src -j LOG --log-prefix "[ATTACKER FORWARD IN] " --log-level=info && iptables -I FORWARD 51 -p all -d "$int_ip1" -m set --match-set attackers src -j DROP;
#iptables -I FORWARD 51 -p all -s "$int_ip1" -m set --match-set attackers dst -j LOG --log-prefix "[ATTACKER FORWARD OUT] " --log-level=info && iptables -I FORWARD 51 -p all -s "$int_ip1" -m set --match-set attackers dst -j DROP;

echo ATTACKER BLACKLIST LOADED

echo LOADING BLACKLIST 
iptables -I OUTPUT 51 -p all -m set --match-set blacklist dst -j DROP && iptables -I INPUT 51 -p all -m set --match-set blacklist src -j DROP;
iptables -I OUTPUT 51 -p all -m set --match-set blacklist dst -j LOG --log-prefix "[BLACKLIST OUT] " --log-level=info && iptables -I INPUT 51 -p all -m set --match-set blacklist src -j LOG --log-prefix "[BLACKLIST IN] " --log-level=info;

#iptables -I FORWARD 51 -p all -m set --match-set blacklist src -j DROP;
#iptables -I FORWARD 51 -p all -m set --match-set blacklist dst -j DROP;

#iptables -I FORWARD 51 -p all -m set --match-set blacklist src -j LOG --log-prefix "[BLACKLIST FORWARD IN] " --log-level=info 
#iptables -I FORWARD 51 -p all -m set --match-set blacklist dst -j LOG --log-prefix "[BLACKLIST FORWARD OUT] "  --log-level=info 

echo BLACKLIST LOADED


echo LOADING IPv6 BLACKLIST 

ip6tables -I OUTPUT 34 -p all -m set --match-set ipv6_blacklist dst -j DROP && ip6tables -I INPUT 34 -p all -m set --match-set ipv6_blacklist src -j DROP;
ip6tables -I OUTPUT 34  -p all -m set --match-set ipv6_blacklist dst -j LOG --log-prefix "[IPv6-BLACKLIST OUT] " --log-level=info && ip6tables -I INPUT 34 -p all -m set --match-set ipv6_blacklist src -j LOG --log-prefix "[IPv6-BLACKLIST IN] "  --log-level=info; 

#ip6tables -I FORWARD 34 -p all -m set --match-set ipv6_blacklist src -j DROP && ip6tables -I FORWARD 34 -p all -m set --match-set ipv6_blacklist dst -j DROP;
#ip6tables -I FORWARD 34 -p all -m set --match-set ipv6_blacklist src -j LOG --log-prefix "[IPv6-BLACKLIST FORWARD IN] "  --log-level=info 
#ip6tables -I FORWARD 34 -p all -m set --match-set ipv6_blacklist dst -j LOG --log-prefix "[IPv6-BLACKLIST FORWARD OUT] "  --log-level=info 

echo IPv6 BLACKLIST LOADED

echo TOR BLACKLIST LOADING

iptables -I OUTPUT 51 -p tcp -s "$int_ip1" -m set --match-set tor_list dst -m multiport --sports 25,80,443 -j DROP && iptables -I OUTPUT 51 -p tcp -s "$int_ip1" -m set  --match-set tor_list dst -m multiport --dports 25,80,443 -j DROP;
iptables -I OUTPUT 51 -p tcp -s $int_ip1 -m set --match-set tor_list dst -m multiport --sports 25,80,443 -j LOG --log-prefix "[TOR-BL OUT] "  --log-level=info && iptables -I OUTPUT 51 -p tcp -s "$int_ip1" -m set --match-set tor_list dst -m multiport --dports 25,80,443 -j LOG --log-prefix "[TOR-BL OUT] "  --log-level=info 
iptables -I INPUT  51 -p tcp -d "$int_ip1" -m set --match-set tor_list src -m multiport --dports 80,443 -j DROP && iptables -I INPUT  51 -p tcp -d "$int_ip1" -m set --match-set tor_list src -m multiport --sports 25,80,443 -j DROP;
iptables -I INPUT  51 -p tcp -d "$int_ip1" -m set --match-set tor_list src -m multiport --dports 25,80,443 -j LOG --log-prefix "[TOR-BL IN] " --log-level=info && iptables -I INPUT  51 -p tcp -d "$int_ip1" -m set --match-set tor_list src -m multiport --sports 25,80,443 -j LOG --log-prefix "[TOR-BL IN] " --log-level=info;

echo TOR BLACKLIST LOADED

####################################################################################
#                    IP FILTER WHITE LISTS
####################################################################################

echo SMTP WHITELIST LOADING

iptables -I OUTPUT 51 -p tcp -s "$int_ip1" -m set --match-set smtp_whitelist dst -m multiport --dports 25,587 -j ACCEPT && iptables -I INPUT 51 -p tcp -d "$int_ip1" -m set --match-set smtp_whitelist src -m multiport --dports 25,587 -j ACCEPT; 
iptables -I OUTPUT 51 -p tcp -s "$int_ip1" -m set --match-set smtp_whitelist dst -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-WL OUT] " --log-level=info && iptables -I INPUT 51 -p tcp -d "$int_ip1" -m set --match-set smtp_whitelist src -m multiport --dports 25,587 -j LOG --log-prefix "[SMTP-WL IN] " --log-level=info 

echo SMTP WHITELIST LOADED

echo HTTP/HTTPS WHITELIST LOADING

iptables -I OUTPUT 51 -p tcp -s "$int_ip1" -m set --match-set http_whitelist dst -m multiport --dports 80,443 -j ACCEPT && iptables -I INPUT 51 -p tcp -d "$int_ip1" -m set --match-set http_whitelist src -m multiport --dports 80,443 -j ACCEPT;
iptables -I OUTPUT 51 -p tcp -s "$int_ip1" -m set --match-set http_whitelist dst -m multiport --dports 80,443 -j LOG --log-prefix "[HTTPS-WL OUT] " --log-level=info && iptables -I INPUT 51  -p tcp -d "$int_ip1" -m set --match-set http_whitelist src -m multiport --dports 80,443 -j LOG --log-prefix "[HTTPS-WL IN] " --log-level=info 

echo HTTP/HTTPS WHITELIST LOADED

#######################################################################################
#                  STRING MATCHING BLACKLISTS
######################################################################################
echo EMAIL BLACKLIST LOADING
for blackout in $(cat email_blacklist.txt);
do 
iptables -I INPUT 51  -p tcp --dport 25 -m string --string "$blackout" --algo bm -j DROP && iptables -I OUTPUT 51 -p tcp --dport 25 -m string --string "$blackout" --algo bm -j DROP; 
iptables -I INPUT 51  -p tcp --dport 25 -m string --string "$blackout" --algo bm -j LOG --log-prefix "[EMAIL SPAM] "--log-level=info && iptables -I OUTPUT 51 -p tcp --dport 25 -m string --string "$blackout" --algo bm -j LOG --log-prefix "[EMAIL SPAM] " --log-level=info ;

#iptables -I FORWARD 51 -p tcp --dport 25 -m string --string "$blackout" --algo bm -j DROP 
#iptables -I FORWARD 51 -p tcp --dport 25 -m string --string "$blackout" --algo bm -j LOG --log-prefix "[EMAIL SPAM] " --log-level=info 
echo "$blackout" ; 
done 
echo EMAIL BLACKLIST LOADED

echo HTML BLACKLIST LOADING
for blackout in $(cat html_blacklist.txt);
do 

iptables -I INPUT 51 -p tcp -m multiport --dports 80,443 -m string --string "$blackout" --algo bm -j DROP && iptables -I OUTPUT 51 -p tcp -m multiport --dports 80,443 -m string --string "$blackout" --algo bm -j DROP; 
iptables -I INPUT 51 -p tcp -m multiport --dports 80,443 -m string --string "$blackout" --algo bm -j LOG --log-prefix "[HTTP SPAM] " --log-level=info && iptables -I OUTPUT 51 -p tcp -m multiport --dports 80,443 -m string --string "$blackout" --algo bm -j LOG --log-prefix "[HTTP SPAM] " --log-level=info ;

#iptables -I FORWARD 51 -p tcp -m multiport --dports 80,443 -m string --string "$blackout" --algo bm -j DROP 
#iptables -I FORWARD 51 -p tcp -m multiport --dports 80,443 -m string --string "$blackout" --algo bm -j LOG --log-prefix "[HTTP SPAM] " --log-level=info  
echo "$blackout" ; 
done 
echo HTML BLACKLIST LOADED

########################################
#          TOR EXIT NODES
#########################################
curl https://check.torproject.org/exit-addresses | grep -ah "ExitAddresses" | awk '{print $2}' > tor_exit.txt

# format for cidr
for tor_ip in $( cat tor_exit.txt )
do 
echo "Tor Exit Node:" "$tor_ip"
ipset add tor_list "$tor_ip"/32
done
echo TOR LIST LOADED
rm tor_exit.txt

#########################################
#         POPULATE WHITELISTS
#######################################
echo LOADING HTTP WHITELIST 
for whiteout in $(cat http_whitelist.txt);
do 
ipset add http_whitelist "$whiteout" 
echo "$whiteout" ; 
done
echo HTTP WHITELIST LOADED

echo LOADING SMTP WHITELIST 
for whiteout in $(cat smtp_whitelist.txt);
do 
ipset add smtp_whitelist "$whiteout" 
echo "$whiteout" ; 
done
echo SMTP WHITELIST LOADED

##################################################
#       POPULATE BLACKLISTS
###################################################
echo LOADING BLACKLIST 
for blackout in $(cat blacklist.txt);
do 
ipset add blacklist "$blackout" 
echo "$blackout" ; 
done
echo BLACKLIST LOADED

echo LOADING IPv6 BLACKLIST 
for blackout in $(cat ipv6_blacklist.txt);
do 
ipset add ipv6_blacklist "$blackout" 
echo "$blackout" ; 
done
echo IPv6 BLACKLIST LOADED

echo LOADING HTTP BLACKLIST 
for blackout in $(cat http_blacklist.txt);
do 
ipset add http_blacklist "$blackout" 
echo "$blackout" ; 
done
echo HTTP BLACKLIST LOADED

echo LOADING SMTP BLACKLIST 
for blackout in $(cat smtp_blacklist.txt);
do 
ipset add smtp_blacklist "$blackout" 
echo "$blackout" ; 
done
echo SMTP BLACKLIST LOADED

echo LOADING ATTACKER BLACKLIST 
for blackout in $(cat attackers.txt);
do 
ipset add attackers "$blackout" 
echo "$blackout" ; 
done
echo ATTACKER BLACKLIST LOADED

echo LOADING DNS BLACKLIST 
for blackout in $(cat dns_blacklist.txt);
do 
ipset add dns_blacklist "$blackout" 
echo "$blackout" ; 
done
echo "DNS BLACKLIST LOADED"
#########################################

echo "ENDSETS LOADED"
################################  SAVE RULES    ##############################################################

ipset save > /etc/ipset.conf


iptables-save > /etc/iptables/iptables.rules
ip6tables-save > /etc/iptables/ip6tables.rules

iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6

iptables-save > /etc/iptables/iptables
ip6tables-save > /etc/iptables/ip6tables

################################  PRINT RULES   ###############################################################
#list the rules
#iptables -L -v
#ip6tables -L -v

#############################   PRINT ADDRESSES  ############################################################
echo "GATEWAY  :          MAC:$gateway_mac  IP:$gateway_ip  "
echo "INTERFACE_1: "$int_if1"  MAC:"$int_mac1"  IPv4:"$int_ip1" IPv6:"$int_ip1v6" "
echo "INTERFACE_2: "$int_if2" MAC:"$int_mac2" IPv4:"$int_ip2" IPv6:"$int_ip2v6" "
# print the time the script finishes
date
#############################################################   END OF PROGRAM  ##############################################################################
