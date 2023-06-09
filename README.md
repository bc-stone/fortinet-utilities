# fortinet-utilities
### A series of utility scripts for Fortigate firewalls
All scripts use Hashicorp Vault along with a set of environment variables that must be present on the local system for storage and retrieval of secrets such as usernames, API keys, URLs, etc.

This repo contains a helper script entitled 'get_secrets.py' that should help to streamline the auth process somewhat.  Details will need to be modified on a per-site basis.

1. <b>fortigate-backup</b> : back up the Fortigate config to a file (with or without a password)
2. <b>get-active-routes</b> : retrieve a list of all active routing table entries (IPv4 by default, in tabular format)
3. <b>get-ssl-vpn-connections</b> : outputs a table of active SSL VPN connections with username, login time, remote and tunnel addresses and total bytes
4. <b>list-botnet-ips</b> : outputs a csv file of all IP-based botnet entries in the FortiGuard botnet database
5. <b>list-botnet-domains</b> : outputs a csv file of all domain-based botnet entries in the FortiGuard botnet database
6. <b>get-rate-based-sigs</b> : outputs a csv file of rate-based IPS signatures, their triggers and thresholds
7. <b>get-ip-objects</b> : outputs a csv file of all the IP address objects on a Fortigate firewall
8. <b>get-license-info</b> : gets the current license and registration status
9. <b>delete-ssl-vpn-session</b> : terminates the provided SSL VPN session