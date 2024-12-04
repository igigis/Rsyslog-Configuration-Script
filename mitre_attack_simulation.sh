#!/bin/bash

# MITRE ATT&CK Simulation Script
# Simulating different log messages based on MITRE ATT&CK techniques
# Ensure to run this script in a test environment.

# Function to simulate failed password attempts (T1078 - Valid Accounts)
simulate_t1078() {
    echo "Simulating T1078 (Valid Accounts) - Failed password"
    sudo logger "Failed password for invalid user john from 192.168.1.100 port 22 ssh2"
    sudo logger "authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.1.100 user=john"
}

# Function to simulate account discovery (T1087 - Account Discovery)
simulate_t1087() {
    echo "Simulating T1087 (Account Discovery) - Accessing /etc/passwd"
    sudo logger "cat /etc/passwd"
    sudo logger "getent passwd"
    sudo logger "compgen -u"
}

# Function to simulate account manipulation (T1098 - Account Manipulation)
simulate_t1098() {
    echo "Simulating T1098 (Account Manipulation) - usermod, chmod, chown"
    sudo logger "usermod -aG sudo john"
    sudo logger "chmod 755 /home/john"
    sudo logger "chown root:root /etc/sudoers"
}

# Function to simulate system process modification (T1543 - Create or Modify System Process)
simulate_t1543() {
    echo "Simulating T1543 (Create or Modify System Process) - systemctl start"
    sudo logger "systemctl start apache2.service"
    sudo logger "service ssh restart"
    sudo logger "/etc/init.d/mysql start"
}

# Function to simulate certificate modification (T1553 - Subvert Trust Controls)
simulate_t1553() {
    echo "Simulating T1553 (Subvert Trust Controls) - Adding certificates"
    sudo logger "certutil -addstore -enterprise -f -v root newcert.cer"
    sudo logger "update-ca-certificates"
}

# Function to simulate indicator removal (T1070 - Indicator Removal on Host)
simulate_t1070() {
    echo "Simulating T1070 (Indicator Removal on Host) - Clearing bash history"
    sudo logger "history -c"
    sudo logger "rm .bash_history"
    sudo logger "truncate -s 0 /var/log/syslog"
}

# Menu for selecting a simulation
echo "Select a MITRE ATT&CK technique to simulate:"
echo "1. T1078 - Valid Accounts"
echo "2. T1087 - Account Discovery"
echo "3. T1098 - Account Manipulation"
echo "4. T1543 - Create or Modify System Process"
echo "5. T1553 - Subvert Trust Controls"
echo "6. T1070 - Indicator Removal on Host"
echo "7. Run all simulations"
echo "8. Exit"

read -p "Enter your choice [1-8]: " choice

case $choice in
    1)
        simulate_t1078
        ;;
    2)
        simulate_t1087
        ;;
    3)
        simulate_t1098
        ;;
    4)
        simulate_t1543
        ;;
    5)
        simulate_t1553
        ;;
    6)
        simulate_t1070
        ;;
    7)
        simulate_t1078
        simulate_t1087
        simulate_t1098
        simulate_t1543
        simulate_t1553
        simulate_t1070
        ;;
    8)
        echo "Exiting..."
        ;;
    *)
        echo "Invalid choice. Exiting."
        ;;
esac
