#!/usr/bin/env bash
set -u
if [ "$(id -u)" -ne 0 ]; then echo "run as root:  sudo ./lab-up.sh"; exit 1; fi

BR=br-securehome
SUBNET=24
declare -A IPS=( [attacker]=192.168.50.100 [iot]=192.168.50.30 [c2]=192.168.50.200 )
declare -A CODE=( [attacker]=atk [iot]=iot [c2]=c2 )

echo "[*] cleaning any previous lab…"
for ns in attacker iot c2; do ip netns del "$ns" 2>/dev/null; done
for c in atk iot c2; do ip link del "veth-$c-br" 2>/dev/null; done
ip link del "$BR" 2>/dev/null
pkill -f "http.server 80" 2>/dev/null
sleep 1

echo "[*] creating bridge $BR (192.168.50.1/$SUBNET)…"
ip link add "$BR" type bridge
ip addr add 192.168.50.1/$SUBNET dev "$BR"
ip link set "$BR" up

add_ns() {
  local ns=$1 ip=$2 c="${CODE[$1]}"
  local v="veth-$c" vb="veth-$c-br"
  ip netns add "$ns"
  ip link add "$v" type veth peer name "$vb"
  ip link set "$v" netns "$ns"
  ip link set "$vb" master "$BR"; ip link set "$vb" up
  ip netns exec "$ns" ip addr add "$ip/$SUBNET" dev "$v"
  ip netns exec "$ns" ip link set "$v" up
  ip netns exec "$ns" ip link set lo up
  echo "    + $ns -> $ip  ($v)"
}
echo "[*] creating namespaces…"
for ns in attacker iot c2; do add_ns "$ns" "${IPS[$ns]}"; done

echo "[*] starting listeners (iot:80, c2:80)…"
ip netns exec iot nohup python3 -m http.server 80 --bind 192.168.50.30  >/tmp/iot.log 2>&1 &
ip netns exec c2  nohup python3 -m http.server 80 --bind 192.168.50.200 >/tmp/c2.log  2>&1 &
sleep 1

echo "[*] enabling bridge netfilter…"
modprobe br_netfilter 2>/dev/null
sysctl -w net.bridge.bridge-nf-call-iptables=1 >/dev/null 2>&1 || true

echo "[*] verifying…"
ip netns exec attacker ping -c1 -W1 192.168.50.30  >/dev/null 2>&1 && echo "    attacker -> iot  : OK" || echo "    attacker -> iot  : FAIL"
ip netns exec iot curl -s -m2 http://192.168.50.200/ >/dev/null 2>&1 && echo "    iot -> c2 (HTTP) : OK" || echo "    iot -> c2 (HTTP) : FAIL"

echo ""
echo "[✓] Lab is UP.  attacker .100 | iot .30 | c2 .200 | bridge $BR"
