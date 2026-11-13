#!/bin/bash
# smb + ldap enum script for the comp
# runs a bunch of nxc/smbclient/ldapsearch stuff so i dont have to type it every time
# only reads stuff, doesnt change anything
# usage: ./enum-smb-ldap.sh <ip>  (add -u user -p pass -d domain if you have creds)

# ---- grab the args ----
target=$1
shift
user=""
pass=""
domain=""

while [ $# -gt 0 ]; do
    if [ "$1" == "-u" ]; then
        user=$2
        shift 2
    elif [ "$1" == "-p" ]; then
        pass=$2
        shift 2
    elif [ "$1" == "-d" ]; then
        domain=$2
        shift 2
    else
        echo "idk what this arg is: $1"
        exit 1
    fi
done

if [ -z "$target" ]; then
    echo "you gotta give me a target ip"
    echo "example: ./enum-smb-ldap.sh 192.168.1.100 -u Administrator -p 'password' -d pvp.swift"
    exit 1
fi

# ---- dont scan stuff we're not allowed to (routers are .1, kali is .2) ----
# if the ip ends in .1 or .2 just bail so we dont get DQd
last=$(echo $target | awk -F. '{print $4}')
if [ "$last" == "1" ] || [ "$last" == "2" ]; then
    echo "nope, $target is a router or kali box, not touching that"
    exit 1
fi

# make a folder to dump everything in
outdir="enum_${target}_$(date +%H%M%S)"
mkdir -p $outdir
echo "saving everything to $outdir"
echo ""

# figure out the auth part for nxc
# if we have a user use it, otherwise just do empty (null session) to see whats open
if [ -n "$user" ]; then
    echo "using creds: $user"
else
    echo "no creds, trying anonymous/null session"
fi
echo ""

# ================= SMB STUFF =================
echo "========== SMB =========="

# first just hit it and look at the banner (tells you signing + smbv1)
echo "[*] checking smb..."
if [ -n "$user" ]; then
    nxc smb $target -u "$user" -p "$pass" | tee $outdir/smb_banner.txt
else
    nxc smb $target -u '' -p '' | tee $outdir/smb_banner.txt
fi

# check the banner for bad stuff
if grep -q "SMBv1:True" $outdir/smb_banner.txt; then
    echo "[!!] FOUND: smbv1 is on, thats the eternalblue thing, turn it off"
fi
if grep -q "signing:False" $outdir/smb_banner.txt; then
    echo "[!!] FOUND: smb signing is off, bad (relay attacks), turn it on"
fi

# list shares + users + password policy
echo "[*] getting shares and users..."
if [ -n "$user" ]; then
    nxc smb $target -u "$user" -p "$pass" --shares --users --pass-pol | tee $outdir/smb_enum.txt
    # rid brute gets you the user list by number
    nxc smb $target -u "$user" -p "$pass" --rid-brute | tee $outdir/smb_rid.txt
else
    # try listing shares with no creds, if it works thats a finding
    smbclient -N -L //$target | tee $outdir/smb_shares.txt
    if grep -q "Sharename" $outdir/smb_shares.txt; then
        echo "[!!] FOUND: can list shares with no login (null session), lock that down"
    fi
fi

echo ""

# ================= LDAP STUFF =================
echo "========== LDAP =========="

# anonymous rootdse query, this usually works and gives you the domain name (DC=whatever)
echo "[*] getting the base DN..."
ldapsearch -x -H ldap://$target -s base namingContexts | tee $outdir/ldap_root.txt

# the roasting checks only work if you have creds
if [ -n "$user" ]; then
    echo "[*] getting ldap users..."
    nxc ldap $target -u "$user" -p "$pass" --users | tee $outdir/ldap_users.txt

    echo "[*] checking for kerberoast / asrep (this is the DC fix list)..."
    nxc ldap $target -u "$user" -p "$pass" --kerberoasting $outdir/kerberoast.txt
    nxc ldap $target -u "$user" -p "$pass" --asreproast $outdir/asrep.txt
    nxc ldap $target -u "$user" -p "$pass" --password-not-required | tee $outdir/ldap_weak.txt

    # if those files got stuff in them its a finding
    if [ -s "$outdir/kerberoast.txt" ]; then
        echo "[!!] FOUND: kerberoastable accounts (check kerberoast.txt) -> make the service passwords long"
    fi
    if [ -s "$outdir/asrep.txt" ]; then
        echo "[!!] FOUND: asrep roastable accounts (check asrep.txt) -> turn on pre-auth"
    fi
else
    echo "no creds so skipping the ldap user/roast stuff, rerun with -u and -p"
fi

echo ""
echo "========== DONE =========="
echo "everything saved in $outdir"
echo "remember: only your own boxes or in scope ones, and DONT touch the flags"
