#!/usr/bin/env bash
# hardlock.sh <TRUSTED_IP> [SSH_PORT]
# Instantly drop all inbound traffic except the trusted IP and kill
# every established SSH session whose peer is not the trusted IP.
set -euo pipefail

TRUSTED_IP="${1:?usage: $0 <trusted-ip> [ssh-port]}"
SSH_PORT="${2:-22}"
TRUSTED_IP6="${TRUSTED_IP6:-}"   # optional, export before running

[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }

# ---------- backends ----------
apply_ufw() {
    ufw --force reset >/dev/null
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow in on lo
    ufw allow from "$TRUSTED_IP" to any port "$SSH_PORT" proto tcp
    ufw allow from "$TRUSTED_IP"
    if [[ -n "$TRUSTED_IP6" ]]; then
        ufw allow from "$TRUSTED_IP6" to any port "$SSH_PORT" proto tcp
        ufw allow from "$TRUSTED_IP6"
    fi
    ufw --force enable
}

apply_iptables() {
    iptables -F; iptables -X; iptables -P INPUT DROP; iptables -P FORWARD DROP; iptables -P OUTPUT ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -s "$TRUSTED_IP" -j ACCEPT
    iptables -A INPUT -s "$TRUSTED_IP" -j ACCEPT
    if [[ -n "$TRUSTED_IP6" ]]; then
        ip6tables -F; ip6tables -X; ip6tables -P INPUT DROP; ip6tables -P FORWARD DROP; ip6tables -P OUTPUT ACCEPT
        ip6tables -A INPUT -i lo -j ACCEPT
        ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        ip6tables -A INPUT -p tcp --dport "$SSH_PORT" -s "$TRUSTED_IP6" -j ACCEPT
        ip6tables -A INPUT -s "$TRUSTED_IP6" -j ACCEPT
    fi
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save
    else
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
        [[ -n "$TRUSTED_IP6" ]] && ip6tables-save > /etc/iptables/rules.v6
    fi
}

apply_nftables() {
    local v6_set="" v6_ssh="" v6_all=""
    if [[ -n "$TRUSTED_IP6" ]]; then
        v6_set="
        set trusted6 { type ipv6_addr; elements = { $TRUSTED_IP6 } }"
        v6_ssh="ip6 saddr @trusted6 tcp dport $SSH_PORT accept"
        v6_all="ip6 saddr @trusted6 accept"
    fi
    cat >/etc/nftables.conf <<EOF
flush ruleset
table inet filter {
    set trusted4 { type ipv4_addr; elements = { $TRUSTED_IP } }$v6_set
    chain input {
        type filter hook input priority 0; policy drop;
        iif lo accept
        ct state established,related accept
        ip saddr @trusted4 tcp dport $SSH_PORT accept
        ip saddr @trusted4 accept
        $v6_ssh
        $v6_all
    }
    chain forward { type filter hook forward priority 0; policy drop; }
    chain output  { type filter hook output  priority 0; policy accept; }
}
EOF
    nft -f /etc/nftables.conf
}

apply_firewalld() {
    systemctl start firewalld 2>/dev/null || true
    firewall-cmd --permanent --zone=trusted --add-source="$TRUSTED_IP" >/dev/null
    [[ -n "$TRUSTED_IP6" ]] && firewall-cmd --permanent --zone=trusted --add-source="$TRUSTED_IP6" >/dev/null
    firewall-cmd --reload
    firewall-cmd --permanent --set-default-zone=drop
    firewall-cmd --reload
}

# ---------- detection ----------
detect() {
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then echo ufw; return; fi
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then echo firewalld; return; fi
    if command -v nft >/dev/null 2>&1 && [[ -s /etc/nftables.conf ]]; then echo nftables; return; fi
    command -v iptables >/dev/null 2>&1 && echo iptables || echo none
}

# ---------- kill non-trusted SSH sessions ----------
kick_intruders() {
    local peer
    ss -Htn state established "( sport = :$SSH_PORT )" 2>/dev/null \
        | awk '{print $5}' | sed 's/:[0-9]*$//' | sort -u \
        | while read -r peer; do
            [[ -z "$peer" ]] && continue
            [[ "$peer" == "$TRUSTED_IP"  ]] && continue
            [[ -n "$TRUSTED_IP6" && "$peer" == "$TRUSTED_IP6" ]] && continue
            echo "killing session from $peer"
            ss -K dst "$peer" 2>/dev/null || true
        done
}

# ---------- go ----------
backend="$(detect)"
echo "backend: $backend | trusted: $TRUSTED_IP | ssh: $SSH_PORT"

case "$backend" in
    ufw)       apply_ufw ;;
    iptables)  apply_iptables ;;
    nftables)  apply_nftables ;;
    firewalld) apply_firewalld ;;
    *) echo "no supported firewall found" >&2; exit 1 ;;
esac

kick_intruders
echo "done."
