# Overview

Dynamicly generate optimized firewall tables based on the full internet bgp prefix & asn tables.
Process data from Source: iptoasn.com 

## Need
- Your Amazon dot should be able to communicate with the <amazon_aws>, but no other internet [network|server|service]?
- Your iPhone should be able to communicate with the <apple> cloud, but not with any of the <facebook> [networks|server]?
- Non of your devices should communicate with:
	- declard but usually not connected, but often abused  <dod>  (US Department of Defense) network ranges?
	- china great firewall <country_cn> networks?
	- rfc1918 <notconnected> networks [private|martians|bogon] [asn:0] via your ISP uplink?
- you want to [silently] [log|limit|stat] all your traffic with a specific full asn for pcap [analysis|decrypt|proof]?
- your chatty TV should only allowed to communicate with <netflix_ipv6>, via a specific [ISP|route|limit]?
- your smtp mail server takes no interest in offerings from <country_ru> <country_in> [unasked] inbound connects?

## You already tried [< random dns blocker >] ?
- Industrie already adapted to this via 'securing' the DNS service (DoT/DoH/...). 

## Keypoints 
- Supports any pf based firwall: macos, openbsd, freebsd, netbsd, pfsense, opensense, network focused linux distros.
- Fast (parses more than One Million prefixes in millisecons).
- Produces optimized tables for building with pf an optimal radix tree.
- 100 % pure golang, simple, easy to review code

# Showtime 

```Shell 
asn2pf block drop log facebook amazon rfc1918 dod country:cn country:ru asn:13335
[...]

```

# TODO: 
- split and migrate prefix and asn table sources from all original authoritative creator sources (arin, ...)
- use the asn radix tree package also for serialized/compresses/storage/publish
