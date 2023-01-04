#
go build
# asn2pf
# -> generate asn based network tables for pf firewall use
#
# adapt and modify before use
#
# setup asn db source directory
# export ASN2PF_SRC=/usr/store/doc/asn
#
# setup pf table out file
export ASN2PF_FILE=/tmp/pf.asn-tables
#
# we do not need the ipv6 rules yet
# export NO_IPV4=true
# export NO_IPV6=true
# export ASN2PF_SKIP="10.0.0.0/8#192.168.8.0/21"
#
# This command will define the following tables!
# Please remember: This will *NOT* filter or block this tables !
# You need to specify the the glue code to pf.conf your self!
./asn2pf update
#
# Your can filter, log, detect, redirect, throttle, packet-loss, whitelist, ...
# any of this tables inividually for any device, ip or other condition! GET CREATIVE!
#
# simplest case, add to /etc/pf.conf
#
# anchor asn
# load anchor asn from "/etc/pf.asn-tables"
# block quick from <owner_facebook_ip4> to any
# block quick from <owner_dod_ip4> to any
# block quick from <country_none_ip4> to any
#
#
# drop       -> add "block drop" filter rule for all tables
# log        -> add "log" option
# facebook   -> filter owner:facebook table for anyting owned by facebook
# dod        -> filter owner:dod table for the not [offially] not connected, but often abused, reseved US DoD ip ranges !
# bogus      -> filter owner:None table for all networks that are officially not connected [rfc1918, martians, bougus, private]
# country:RU -> filter country:RU table to filter all networks from russia
./asn2pf drop log asn:0 dod facebook cloudflare amazon microsoft country:CN country:RU
