#!/bin/bash

# scans the 5 comp boxes (.50 through .54) with nmap
# give it your pod subnet (first 3 octets) and it does one scan per box
# usage: ./scan5.sh 172.16.13      <- scans 172.16.13.50 ... .54

base=$1

if [ -z "$base:" ]; then
	echo "give me the subnet like 172.16.92 (or a full ip)"
	echo "example: ./nmap.sh 172.16.92"
	exit 1
fi

 
# if they handed me a whole ip (172.16.13.50) just take the first 3 parts
base=$(echo $base | cut -d. -f1-3)

# make a scan folder
mkdir -p scans-$base

# loop through the last octet 50..54
for i in 50 51 52 53 54; do
	ip="$base.$i"
	echo "============================"
	echo "[*] scanning $ip"
	echo "==========================="

    # -sCV = default scripts + version detection
    # -T5  = go fast
    # -Pn  = dont ping first (boxes might block ping and get skipped otherwise)
	nmap -sCV -T5 -Pn $ip -oN scans-$base/$i.txt
	echo "[*] done with $ip -> saved to scans/$ip.txt"
	echo ""
done

echo "Finished"
