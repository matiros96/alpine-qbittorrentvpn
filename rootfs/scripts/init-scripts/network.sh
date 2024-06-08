#!/bin/bash

# shellcheck disable=SC1091
source /scripts/helper/functions.sh
##########
# Skip - Only needed if VPN is enabled

if [[ $VPN_ENABLED == "no" ]]; then
    exit 0
fi

##########
# nft rules

# Mark outgoing packets belonging to a WebUI connection (for routing and firewall)
iptables -t mangle -N QBT-MARK-PREROUTING
iptables -t mangle -N QBT-MARK-OUTPUT
iptables -t mangle -A PREROUTING -j QBT-MARK-PREROUTING
iptables -t mangle -A OUTPUT -j QBT-MARK-OUTPUT
iptables -t mangle -A QBT-MARK-PREROUTING -p tcp --dport 8080 -m conntrack --ctstate NEW -j CONNMARK --set-mark 9090 -m comment --comment "Track new WebUI connections"
iptables -t mangle -A QBT-MARK-PREROUTING -p tcp --dport 8080 -j MARK --set-mark 8080 -m comment --comment "Mark packets to pass rp_filter reverse path route lookup"
iptables -t mangle -A QBT-MARK-OUTPUT -m connmark --mark 9090 -j MARK --set-mark 8080 -m comment --comment "Add mark to outgoing packets belonging to a WebUI connection"

ip6tables -t mangle -N QBT-MARK-PREROUTING
ip6tables -t mangle -N QBT-MARK-OUTPUT
ip6tables -t mangle -A PREROUTING -j QBT-MARK-PREROUTING
ip6tables -t mangle -A OUTPUT -j QBT-MARK-OUTPUT
ip6tables -t mangle -A QBT-MARK-PREROUTING -p tcp --dport 8080 -m conntrack --ctstate NEW -j CONNMARK --set-mark 9090 -m comment --comment "Track new WebUI connections"
ip6tables -t mangle -A QBT-MARK-PREROUTING -p tcp --dport 8080 -j MARK --set-mark 8080 -m comment --comment "Mark packets to pass rp_filter reverse path route lookup"
ip6tables -t mangle -A QBT-MARK-OUTPUT -m connmark --mark 9090 -j MARK --set-mark 8080 -m comment --comment "Add mark to outgoing packets belonging to a WebUI connection"

# Route WebUI traffic over "$DEFAULT_IPV4_GATEWAY"
mkdir -p /etc/iproute2/
echo "8080 webui" >> /etc/iproute2/rt_tables
if [ -n "$DEFAULT_IPV4_GATEWAY" ]; then
	# Default
	ip rule add fwmark 8080 table webui 
	ip route add default via "$DEFAULT_IPV4_GATEWAY" table webui
	# Look for local networks first
	ip rule add fwmark 8080 table main suppress_prefixlength 1
fi
if [ -n "$DEFAULT_IPV6_GATEWAY" ]; then
	# Default
	ip -6 rule add fwmark 8080 table webui 
	ip -6 route add default via "$DEFAULT_IPV6_GATEWAY" table webui
	# Look for local networks first
	ip -6 rule add fwmark 8080 table main suppress_prefixlength 1
fi

# Create IP sets for IPv4 and IPv6 addresses
ipset create vpn_ipv4 hash:ip family inet
ipset create vpn_ipv6 hash:ip family inet6

## VPN_REMOTE IP

VPN_REMOTE_IPv4_ADDRESSES=()
VPN_REMOTE_IPv6_ADDRESSES=()

# VPN_REMOTE is already an IPv4 address
if (ipcalc -c -4 "$VPN_REMOTE" > /dev/null 2>&1); then
	VPN_REMOTE_IPv4_ADDRESSES+=("$VPN_REMOTE")
# VPN_REMOTE is already an IPv6 address
elif (ipcalc -c -6 "$VPN_REMOTE" > /dev/null 2>&1); then
	VPN_REMOTE_IPv6_ADDRESSES+=("$VPN_REMOTE")
# VPN_REMOTE is a hostname
else
	if [[ "${VPN_TYPE}" == "openvpn" ]]; then
		while ! VPN_REMOTE_IP=$(grep -o -m 1 -P 'Peer Connection Initiated with [^\d]+\K(\d+(\.\d+){3})(?=:\d+)' < /var/log/openvpn.log); do sleep 0.1; done
	else
		VPN_REMOTE_IP="$(wg show | grep -o -m 1 -P '((?<=endpoint:\s\[)[0-9a-f:]+(?=\]:\d+$))|((?<=endpoint:\s)[0-9.]+(?=:\d+$))')"
	fi

	if (ipcalc -c -4 "$VPN_REMOTE_IP" > /dev/null 2>&1); then
		VPN_REMOTE_IPv4_ADDRESSES+=("$VPN_REMOTE_IP")
	elif (ipcalc -c -6 "$VPN_REMOTE_IP" > /dev/null 2>&1); then
		VPN_REMOTE_IPv6_ADDRESSES+=("$VPN_REMOTE_IP")
	else
		echo "$(date +'%Y-%m-%d %H:%M:%S') [ERROR] neither $VPN_REMOTE (VPN_REMOTE) nor \"$VPN_REMOTE_IP\" (obtained from the VPN client) is a valid IP"
		stop_container
	fi
fi

if [[ "$DEBUG" == "yes" ]]; then
	# shellcheck disable=SC2154
	echo "$(date +'%Y-%m-%d %H:%M:%S') [DEBUG] VPN_REMOTE_IPv4_ADDRESSES defined as (${VPN_REMOTE_IPv4_ADDRESSES[*]})"
	# shellcheck disable=SC2154
	echo "$(date +'%Y-%m-%d %H:%M:%S') [DEBUG] VPN_REMOTE_IPv6_ADDRESSES defined as (${VPN_REMOTE_IPv6_ADDRESSES[*]})"
fi

# Add each IP address to its respective set
for address in "${VPN_REMOTE_IPv4_ADDRESSES[@]}"; do
	ipset add vpn_ipv4 "$address"
done

for address in "${VPN_REMOTE_IPv6_ADDRESSES[@]}"; do
	ipset add vpn_ipv6 "$address"
done

## Input

iptables -P INPUT DROP
iptables -A INPUT -i "$VPN_DEVICE_TYPE" -j ACCEPT -m comment --comment "Accept input from VPN tunnel"
iptables -A INPUT -p "$VPN_PROTOCOL" --sport "$VPN_PORT" -m set --match-set vpn_ipv4 src -j ACCEPT -m comment --comment "Accept input from VPN server (IPv4)"
ip6tables -A INPUT -p "$VPN_PROTOCOL" --sport "$VPN_PORT" -m set --match-set vpn_ipv6 src -j ACCEPT -m comment --comment "Accept input from VPN server (IPv6)"
iptables -A INPUT -i lo -j ACCEPT -m comment --comment "Accept input from internal loopback"
ip6tables -A INPUT -p icmpv6 --icmpv6-type 135 -j ACCEPT -m comment --comment "Basic ICMPv6 NDP (Neighbor Solicitation)"
ip6tables -A INPUT -p icmpv6 --icmpv6-type 136 -j ACCEPT -m comment --comment "Basic ICMPv6 NDP (Neighbor Advertisement)"
ip6tables -A INPUT -p icmpv6 --icmpv6-type 133 -j ACCEPT -m comment --comment "Basic ICMPv6 NDP (Router Solicitation)"
ip6tables -A INPUT -p icmpv6 --icmpv6-type 134 -j ACCEPT -m comment --comment "Basic ICMPv6 NDP (Router Advertisement)"
ip6tables -A INPUT -p icmpv6 --icmpv6-type 1 -j ACCEPT -m comment --comment "Basic ICMPv6 errors (Destination Unreachable)"
ip6tables -A INPUT -p icmpv6 --icmpv6-type 2 -j ACCEPT -m comment --comment "Basic ICMPv6 errors (Packet Too Big)"
ip6tables -A INPUT -p icmpv6 --icmpv6-type 3 -j ACCEPT -m comment --comment "Basic ICMPv6 errors (Time Exceeded)"
iptables -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT -m comment --comment "Basic ICMP errors (optional)"
iptables -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT -m comment --comment "Basic ICMP errors (optional)"
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT -m comment --comment "Respond to IPv4 pings (optional)"
ip6tables -A INPUT -p icmpv6 --icmpv6-type 128 -j ACCEPT -m comment --comment "Respond to IPv6 pings (Echo Request)"

## Output

iptables -P OUTPUT DROP
iptables -A OUTPUT -o "$VPN_DEVICE_TYPE" -j ACCEPT -m comment --comment "Accept output to VPN tunnel"
iptables -A OUTPUT -p "$VPN_PROTOCOL" --dport "$VPN_PORT" -m set --match-set vpn_ipv4 dst -j ACCEPT -m comment --comment "Accept output to VPN server (IPv4)"
ip6tables -A OUTPUT -p "$VPN_PROTOCOL" --dport "$VPN_PORT" -m set --match-set vpn_ipv6 dst -j ACCEPT -m comment --comment "Accept output to VPN server (IPv6)"
iptables -A OUTPUT -p tcp --sport 8080 -m mark --mark 8080 -j ACCEPT -m comment --comment "Accept outgoing packets belonging to a WebUI connection"
iptables -A OUTPUT -o lo -j ACCEPT -m comment --comment "Accept output to internal loopback"
ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 135 -j ACCEPT -m comment --comment "Basic ICMPv6 NDP (Neighbor Solicitation)"
ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 136 -j ACCEPT -m comment --comment "Basic ICMPv6 NDP (Neighbor Advertisement)"
ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 133 -j ACCEPT -m comment --comment "Basic ICMPv6 NDP (Router Solicitation)"
ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 134 -j ACCEPT -m comment --comment "Basic ICMPv6 NDP (Router Advertisement)"
ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 1 -j ACCEPT -m comment --comment "ICMPv6 errors (Destination Unreachable)"
ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 2 -j ACCEPT -m comment --comment "ICMPv6 errors (Packet Too Big)"
ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 3 -j ACCEPT -m comment --comment "ICMPv6 errors (Time Exceeded)"
iptables -A OUTPUT -p icmp --icmp-type destination-unreachable -j ACCEPT -m comment --comment "ICMP errors (optional)"
iptables -A OUTPUT -p icmp --icmp-type time-exceeded -j ACCEPT -m comment --comment "ICMP errors (optional)"
iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT -m comment --comment "Respond to IPv4 pings (optional)"
ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 129 -j ACCEPT -m comment --comment "Respond to IPv6 pings (Echo Reply)"

# Input to WebUI
if [ -z "$WEBUI_ALLOWED_NETWORKS" ]; then
	iptables -A INPUT -p tcp --dport 8080 -j ACCEPT -m comment --comment "Accept input to the qBt WebUI"
else
	ipset create webui_allowed_networks_ipv4 hash:net family inet
	ipset create webui_allowed_networks_ipv6 hash:net family inet6

	# Split comma separated string into list from WEBUI_ALLOWED_NETWORKS env variable
	IFS=',' read -ra allowed_networks_array <<< "$WEBUI_ALLOWED_NETWORKS"

	for address in "${allowed_networks_array[@]}"; do
		# Remove whitepaces (for ipcalc)
		address="$(sed -e 's/\s//g' <<< "$address")"

		if ipcalc -c -4 "$address"; then
			ipset add webui_allowed_networks_ipv4 "$address"
		elif ipcalc -c -6 "$address"; then
			ipset add webui_allowed_networks_ipv6 "$address"
		fi
	done

	iptables -A INPUT -p tcp --dport 8080 -m set --match-set webui_allowed_networks_ipv4 src -j ACCEPT -m comment --comment "Accept input to the qBt WebUI (IPv4)"
	ip6tables -A INPUT -p tcp --dport 8080 -m set --match-set webui_allowed_networks_ipv6 src -j ACCEPT -m comment --comment "Accept input to the qBt WebUI (IPv6)"
fi

# Additional port list for scripts or container linking
if [[ -n "$ADDITIONAL_PORTS" ]]; then
	IFS=',' read -ra additional_port_list <<< "$ADDITIONAL_PORTS"

	for additional_port_item in "${additional_port_list[@]}"; do
		additional_port_item=$(echo "$additional_port_item" | sed -e 's~^[ \t]*~~;s~[ \t]*$~~')
		echo "$(date +'%Y-%m-%d %H:%M:%S') [INFO] Adding additional outgoing port $additional_port_item for $DOCKER_INTERFACE"
		iptables -A INPUT -p tcp --dport "$additional_port_item" -j ACCEPT -m comment --comment "Accept input to additional port"
		iptables -A OUTPUT -o "$DOCKER_INTERFACE" -p tcp --sport "$additional_port_item" -j ACCEPT -m comment --comment "Accept output from additional port"
	done
fi

if [[ "$DEBUG" == "yes" ]]; then
	echo "$(date +'%Y-%m-%d %H:%M:%S') [DEBUG] 'main' routing table defined as follows..."
	echo "--------------------"
	ip route show table main
	echo "--------------------"
	echo "$(date +'%Y-%m-%d %H:%M:%S') [DEBUG] ip rules defined as follows..."
	echo "--------------------"
	ip rule
	echo "--------------------"
	echo "$(date +'%Y-%m-%d %H:%M:%S') [DEBUG] iptables filter defined as follows..."
	echo "--------------------"
	iptables -t filter -S
	echo "--------------------"
	echo "$(date +'%Y-%m-%d %H:%M:%S') [DEBUG] iptables mangle defined as follows..."
	echo "--------------------"
	iptables -t mangle -S
	echo "--------------------"
	echo "$(date +'%Y-%m-%d %H:%M:%S') [DEBUG] ip6tables filter defined as follows..."
	echo "--------------------"
	ip6tables -t filter -S
	echo "--------------------"
	echo "$(date +'%Y-%m-%d %H:%M:%S') [DEBUG] ip6tables mangle defined as follows..."
	echo "--------------------"
	ip6tables -t mangle -S
	echo "--------------------"
    test_connection
fi

##########
# Save envirnonment variables

CONT_INIT_ENV="/var/run/s6/container_environment"
mkdir -p $CONT_INIT_ENV
export_vars=("DOCKER_INTERFACE")

for name in "${export_vars[@]}"; do
	echo -n "${!name}" > "$CONT_INIT_ENV/$name"
done
