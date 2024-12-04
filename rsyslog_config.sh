#!/bin/bash

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root or with sudo"
    exit 1
fi

# Function to validate IP address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a ip_parts <<< "$ip"
        for part in "${ip_parts[@]}"; do
            if [ "$part" -gt 255 ] || [ "$part" -lt 0 ]; then
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}

# Prompt for syslog server IP
while true; do
    read -p "Enter the syslog server IP address: " syslog_ip
    if validate_ip "$syslog_ip"; then
        break
    else
        echo "Invalid IP address. Please try again."
    fi
done

echo "Installing rsyslog..."
apt-get update
apt-get install -y rsyslog

# Stop rsyslog service before making changes
systemctl stop rsyslog

# Create log file if it doesn't exist
touch /var/log/mitre_mapped.log

# Set appropriate permissions
chown syslog:adm /var/log/mitre_mapped.log
chmod 640 /var/log/mitre_mapped.log

# Backup original rsyslog.conf
cp /etc/rsyslog.conf /etc/rsyslog.conf.backup

# Create new rsyslog configuration
cat > /etc/rsyslog.conf << 'EOL'
# rsyslog configuration for MITRE ATT&CK mapping with remote forwarding

# Global directives
global(workDirectory="/var/lib/rsyslog")

# Load base modules
module(load="imuxsock")    # Local system logging support
module(load="imklog")      # Kernel logging support

# Define template for RFC5424
template(name="RFC5424-MITRE" type="string" 
    string="<%PRI%>1 %TIMESTAMP:::date-rfc3339% %HOSTNAME% %APP-NAME% %PROCID% %MSGID% [technique=\"%$!mitre_technique%\" tactic=\"%$!mitre_tactic%\"] %msg%\n"
)

# Rule set for MITRE ATT&CK mapping
ruleset(name="mitre_mapping") {
    # T1046 - Network Service Scanning
    if re_match($msg, '^.*nmap.*$') or re_match($msg, '^.*netcat.*$') or re_match($msg, '^.*nc -.*$') or re_match($msg, '^.*port.*scan.*$') then {
        set $!mitre_technique = "T1046";
        set $!mitre_tactic = "Discovery";
    }
	
    # T1059 - Command and Scripting Interpreter
    else if re_match($msg, '^.*python.*$') or re_match($msg, '^.*perl.*$') or re_match($msg, '^.*bash -c.*$') then {
        set $!mitre_technique = "T1059";
        set $!mitre_tactic = "Execution";
    }
	
    # T1082 - System Information Discovery
    else if re_match($msg, '^.*uname -a.*$') or re_match($msg, '^.*systeminfo.*$') or re_match($msg, '^.*hostnamectl.*$') or re_match($msg, '^.*lscpu.*$') then {
        set $!mitre_technique = "T1082";
        set $!mitre_tactic = "Discovery";
    }
	
    # T1078 - Valid Accounts
    else if re_match($msg, '^.*Failed password.*$') or re_match($msg, '^.*authentication failure.*$') or re_match($msg, '^.*invalid user.*$') then {
        set $!mitre_technique = "T1078";
        set $!mitre_tactic = "Initial Access";
    }
    
    # T1087 - Account Discovery
    else if re_match($msg, '^.*/etc/passwd$') or re_match($msg, '^.*getent.*$') or re_match($msg, '^.*printenv.*$') or re_match($msg, '^.*compgen -u.*$') then {
        set $!mitre_technique = "T1087";
        set $!mitre_tactic = "Discovery";
    }
    
    # T1098 - Account Manipulation
    else if re_match($msg, '^.*usermod.*$') or re_match($msg, '^.*adduser.*$') or re_match($msg, '^.*groupadd.*$') or re_match($msg, '^.*chmod.*$') or re_match($msg, '^.*chown.*$') then {
        set $!mitre_technique = "T1098";
        set $!mitre_tactic = "Persistence";
    }
	
    # T1105 - Ingress Tool Transfer
    else if re_match($msg, '^.*wget.*$') or re_match($msg, '^.*curl.*$') or re_match($msg, '^.*scp.*$') or re_match($msg, '^.*sftp.*$') then {
        set $!mitre_technique = "T1105";
        set $!mitre_tactic = "Command and Control";
    }
	
    # T1136 - Create Account
    else if re_match($msg, '^.*adduser.*$') or re_match($msg, '^.*net user /add.*$') or re_match($msg, '^.*useradd.*$') then {
        set $!mitre_technique = "T1136";
        set $!mitre_tactic = "Persistence";
    }
	
    # T1543 - Create or Modify System Process
    else if re_match($msg, '^.*systemctl.*start.*$') or re_match($msg, '^.*service.*start.*$') or re_match($msg, '^.*/etc/init.d/.*$') then {
        set $!mitre_technique = "T1543";
        set $!mitre_tactic = "Persistence,Privilege Escalation";
    }
    
    # T1553 - Subvert Trust Controls
    else if re_match($msg, '^.*cert.*add.*$') or re_match($msg, '^.*trust.*anchor.*$') or re_match($msg, '^.*update-ca-certificates.*$') then {
        set $!mitre_technique = "T1553";
        set $!mitre_tactic = "Defense Evasion";
    }
    
    # T1070 - Indicator Removal on Host
    else if re_match($msg, '^.*history -c.*$') or re_match($msg, '^.*rm.*bash_history.*$') or re_match($msg, '^.*truncate.*log.*$') then {
        set $!mitre_technique = "T1070";
        set $!mitre_tactic = "Defense Evasion";
    }
	
    # T1561.001 - Disk Wipe: Disk Structure Wipe
    else if re_match($msg, '^.*dd.*if=/dev/zero.*$') or re_match($msg, '^.*shred.*$') or re_match($msg, '^.*fdisk.*delete.*$') or re_match($msg, '^.*mkfs.*$') then {
        set $!mitre_technique = "T1561.001";
        set $!mitre_tactic = "Impact";
    }
	
    # T1562 - Impair Defenses
    else if re_match($msg, '^.*setenforce 0.*$') or re_match($msg, '^.*systemctl stop firewalld.*$') or re_match($msg, '^.*ufw disable.*$') then {
        set $!mitre_technique = "T1562";
        set $!mitre_tactic = "Defense Evasion";
    }
	
    # T1569 - System Services
    else if re_match($msg, '^.*sc.*create.*$') or re_match($msg, '^.*new-service.*$') or re_match($msg, '^.*systemctl.*enable.*$') then {
        set $!mitre_technique = "T1569";
        set $!mitre_tactic = "Execution";
    }
	
    # Default case - if no matches
    else {
        set $!mitre_technique = " ";
        set $!mitre_tactic = " ";
    }
}

# Apply MITRE mapping ruleset
*.* call mitre_mapping

# Forward to remote syslog using built-in forward action
action(
    type="omfwd"
    target="${syslog_ip}"
    port="514"
    protocol="udp"
    template="RFC5424-MITRE"
)

# Local logging with MITRE mapping
action(
    type="omfile"
    file="/var/log/mitre_mapped.log"
    template="RFC5424-MITRE"
)

# Standard system logging with corrected syntax
if ($syslogfacility-text == 'auth' or $syslogfacility-text == 'authpriv') then {
    action(type="omfile" file="/var/log/secure")
}
if ($syslogfacility-text == 'mail') then {
    action(type="omfile" file="/var/log/maillog")
}
if ($syslogfacility-text == 'cron') then {
    action(type="omfile" file="/var/log/cron")
}
if ($syslogfacility-text == 'kern' or $syslogfacility-text == 'user' or $syslogfacility-text == 'daemon') then {
    action(type="omfile" file="/var/log/messages")
}
if ($syslogseverity == '0') then {
    action(type="omusrmsg" users="*")
}
EOL

# Set permissions for rsyslog.conf
chmod 644 /etc/rsyslog.conf

# Create rsyslog directory if it doesn't exist
mkdir -p /var/lib/rsyslog
chown syslog:adm /var/lib/rsyslog

# Restart rsyslog service
systemctl restart rsyslog

# Enable rsyslog to start on boot
systemctl enable rsyslog

echo "Installation and configuration completed successfully!"
echo "Syslog server IP configured as: $syslog_ip"
echo "Log file location: /var/log/mitre_mapped.log"
echo "Original configuration backed up at: /etc/rsyslog.conf.backup"

# Check if rsyslog is running
if systemctl is-active --quiet rsyslog; then
    echo "Rsyslog service is running"
else
    echo "Warning: Rsyslog service is not running. Please check the logs with 'journalctl -xe'"
fi
