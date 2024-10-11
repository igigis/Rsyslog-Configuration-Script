#!/bin/bash

# Prompt for syslog server IP address
read -p "Enter the syslog server IP address: " SYSLOG_SERVER_IP

# Validate IP address format
if [[ ! $SYSLOG_SERVER_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Invalid IP address format. Please run the script again with a valid IP."
    exit 1
fi

# Backup the original rsyslog.conf file
sudo cp /etc/rsyslog.conf /etc/rsyslog.conf.bak

# Create custom log files
sudo touch /var/log/custom_apache.log /var/log/custom_nginx.log /var/log/custom_mysql.log \
    /var/log/custom_postgresql.log /var/log/custom_tomcat.log /var/log/custom_ids.log \
    /var/log/custom_ssh.log /var/log/custom_changes.log /var/log/custom_performance.log \
    /var/log/custom_network_devices.log /var/log/custom_vpn.log /var/log/custom_ldap.log \
    /var/log/custom_docker.log /var/log/custom_dns.log /var/log/custom_email.log \
    /var/log/custom_proxy.log /var/log/custom_ntp.log

# Set ownership and permissions for custom log files
sudo chown syslog:adm /var/log/custom_*
sudo chmod 640 /var/log/custom_*

# Create a new rsyslog.conf file
cat << EOF | sudo tee /etc/rsyslog.conf
# /etc/rsyslog.conf configuration file for rsyslog
#
# For more information install rsyslog-doc and see
# /usr/share/doc/rsyslog-doc/html/configuration/index.html

#################
#### MODULES ####
#################
module(load="imuxsock") # provides support for local system logging
module(load="imklog")   # provides kernel logging support
#module(load="immark")  # provides --MARK-- message capability

# provides UDP syslog reception
#module(load="imudp")
#input(type="imudp" port="514")

# provides TCP syslog reception
#module(load="imtcp")
#input(type="imtcp" port="514")

###########################
#### GLOBAL DIRECTIVES ####
###########################

# Set the default permissions for all log files.
\$FileOwner root
\$FileGroup adm
\$FileCreateMode 0640
\$DirCreateMode 0755
\$Umask 0022

# Where to place spool and state files
\$WorkDirectory /var/spool/rsyslog

# Include all config files in /etc/rsyslog.d/
\$IncludeConfig /etc/rsyslog.d/*.conf

# Define the RFC5424 template
template(name="RFC5424" type="string"
    string="<%pri%>1 %timestamp:::date-rfc3339% %hostname% %app-name% %procid% %msgid% %structured-data% %msg%\n"
)

###############
#### RULES ####
###############

# Log anything besides private authentication messages to a single log file
*.*;auth,authpriv.none          -/var/log/syslog

# Log commonly used facilities to their own log file
auth,authpriv.*                 /var/log/auth.log
cron.*                          -/var/log/cron.log
kern.*                          -/var/log/kern.log
mail.*                          -/var/log/mail.log
user.*                          -/var/log/user.log

# Emergencies are sent to everybody logged in.
*.emerg                         :omusrmsg:*

# --- Custom rsyslog configuration for security events ---
# Authentication and Privilege Escalation (auth logs)
auth,authpriv.* /var/log/custom_auth.log
auth,authpriv.* @${SYSLOG_SERVER_IP}:514;RFC5424

# Process monitoring (audit logs)
if \$msg contains "/var/log/audit/audit.log" then /var/log/custom_audit.log
if \$msg contains "/var/log/audit/audit.log" then @${SYSLOG_SERVER_IP}:514;RFC5424

# Network and firewall events (UFW and kernel)
:msg, contains, "[UFW" /var/log/custom_ufw.log
:msg, contains, "[UFW" @${SYSLOG_SERVER_IP}:514;RFC5424
kern.* /var/log/custom_kern.log
kern.* @${SYSLOG_SERVER_IP}:514;RFC5424

# System and Kernel security events (AppArmor, critical events)
:msg, contains, "apparmor=\"DENIED\"" /var/log/custom_security.log
:msg, contains, "apparmor=\"DENIED\"" @${SYSLOG_SERVER_IP}:514;RFC5424
kern.crit /var/log/custom_critical_security.log
kern.crit @${SYSLOG_SERVER_IP}:514;RFC5424

# --- Additional log types ---
# Web server logs (Apache and Nginx)
:programname, isequal, "apache2" /var/log/custom_apache.log
:programname, isequal, "apache2" @${SYSLOG_SERVER_IP}:514;RFC5424
:programname, isequal, "nginx" /var/log/custom_nginx.log
:programname, isequal, "nginx" @${SYSLOG_SERVER_IP}:514;RFC5424

# Database logs (MySQL and PostgreSQL)
:programname, isequal, "mysql" /var/log/custom_mysql.log
:programname, isequal, "mysql" @${SYSLOG_SERVER_IP}:514;RFC5424
:programname, isequal, "postgresql" /var/log/custom_postgresql.log
:programname, isequal, "postgresql" @${SYSLOG_SERVER_IP}:514;RFC5424

# Application server logs (Tomcat)
:programname, isequal, "tomcat" /var/log/custom_tomcat.log
:programname, isequal, "tomcat" @${SYSLOG_SERVER_IP}:514;RFC5424

# Intrusion Detection/Prevention System logs (assuming Snort)
:programname, isequal, "snort" /var/log/custom_ids.log
:programname, isequal, "snort" @${SYSLOG_SERVER_IP}:514;RFC5424

# SSH access logs
:msg, contains, "sshd" /var/log/custom_ssh.log
:msg, contains, "sshd" @${SYSLOG_SERVER_IP}:514;RFC5424

# Configuration changes
:msg, contains, "changed" /var/log/custom_changes.log
:msg, contains, "changed" @${SYSLOG_SERVER_IP}:514;RFC5424

# Performance logs (CPU, memory, disk)
:msg, contains, "CPU usage" /var/log/custom_performance.log
:msg, contains, "CPU usage" @${SYSLOG_SERVER_IP}:514;RFC5424
:msg, contains, "memory usage" /var/log/custom_performance.log
:msg, contains, "memory usage" @${SYSLOG_SERVER_IP}:514;RFC5424
:msg, contains, "disk usage" /var/log/custom_performance.log
:msg, contains, "disk usage" @${SYSLOG_SERVER_IP}:514;RFC5424

# Network device logs (assuming syslog messages from network devices)
:msg, contains, "router" /var/log/custom_network_devices.log
:msg, contains, "router" @${SYSLOG_SERVER_IP}:514;RFC5424
:msg, contains, "switch" /var/log/custom_network_devices.log
:msg, contains, "switch" @${SYSLOG_SERVER_IP}:514;RFC5424

# VPN logs
:programname, isequal, "openvpn" /var/log/custom_vpn.log
:programname, isequal, "openvpn" @${SYSLOG_SERVER_IP}:514;RFC5424

# LDAP/Active Directory logs (assuming syslog messages from LDAP server)
:msg, contains, "LDAP" /var/log/custom_ldap.log
:msg, contains, "LDAP" @${SYSLOG_SERVER_IP}:514;RFC5424

# Container logs (Docker)
:programname, isequal, "docker" /var/log/custom_docker.log
:programname, isequal, "docker" @${SYSLOG_SERVER_IP}:514;RFC5424

# DNS Server logs
:programname, isequal, "named" /var/log/custom_dns.log
:programname, isequal, "named" @${SYSLOG_SERVER_IP}:514;RFC5424

# Email server logs (assuming Postfix)
:programname, isequal, "postfix" /var/log/custom_email.log
:programname, isequal, "postfix" @${SYSLOG_SERVER_IP}:514;RFC5424

# Proxy server logs (assuming Squid)
:programname, isequal, "squid" /var/log/custom_proxy.log
:programname, isequal, "squid" @${SYSLOG_SERVER_IP}:514;RFC5424

# Time synchronization logs (NTP)
:programname, isequal, "ntpd" /var/log/custom_ntp.log
:programname, isequal, "ntpd" @${SYSLOG_SERVER_IP}:514;RFC5424

# --- End of custom rsyslog configuration ---
EOF

# Restart rsyslog service
sudo systemctl restart rsyslog

echo "rsyslog configuration updated with syslog server IP ${SYSLOG_SERVER_IP} and service restarted."
