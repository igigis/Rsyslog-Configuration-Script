# Rsyslog MITRE ATT&CK Mapping Setup

This script automates the installation and configuration of rsyslog with MITRE ATT&CK framework mapping for enhanced security logging and monitoring capabilities on Ubuntu systems.

## Features

- Automated rsyslog installation
- MITRE ATT&CK framework integration
- Remote syslog forwarding
- Secure default permissions
- Backup of original configuration
- Interactive IP address validation
- Comprehensive error checking

## MITRE ATT&CK Techniques Covered

The configuration includes mapping for the following MITRE ATT&CK techniques:

- T1046 - Network Service Scanning
- T1059 - Command and Scripting Interpreter
- T1082 - System Information Discovery
- T1078 - Valid Accounts
- T1087 - Account Discovery
- T1098 - Account Manipulation
- T1105 - Ingress Tool Transfer
- T1136 - Create Account
- T1543 - Create or Modify System Process
- T1553 - Subvert Trust Controls
- T1070 - Indicator Removal on Host
- T1561.001 - Disk Wipe: Disk Structure Wipe
- T1562 - Impair Defenses
- T1569 - System Services

## Prerequisites

- Ubuntu Linux system
- Root or sudo privileges
- Network connectivity to the target syslog server

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/igigis/rsyslog-mitre-setup.git
   cd rsyslog-mitre-setup
   ```

2. Make the script executable:
   ```bash
   chmod +x rsyslog_config.sh
   ```

3. Run the script with sudo:
   ```bash
   sudo ./rsyslog_config.sh
   ```

4. When prompted, enter the IP address of your syslog server.

## Configuration Details

The script sets up the following:

- Creates `/var/log/mitre_mapped.log` for MITRE-mapped events
- Configures remote forwarding to your specified syslog server
- Sets appropriate file permissions (640 for logs, 644 for config)
- Enables standard system logging
- Configures MITRE ATT&CK mapping rules
- Enables and starts the rsyslog service

### Log Files

- `/var/log/mitre_mapped.log` - MITRE ATT&CK mapped events
- `/var/log/secure` - Authentication and authorization logs
- `/var/log/maillog` - Mail server logs
- `/var/log/cron` - Cron job logs
- `/var/log/messages` - General system messages

## Troubleshooting

### Common Issues and Solutions

1. **Rsyslog Service Won't Start**
   ```bash
   # Check service status
   systemctl status rsyslog
   
   # Check logs for errors
   journalctl -xe | grep rsyslog
   
   # Verify configuration syntax
   rsyslogd -N1
   ```

2. **Logs Not Being Generated**
   - Check file permissions:
     ```bash
     ls -l /var/log/mitre_mapped.log
     ```
   - Verify syslog user has write permissions:
     ```bash
     sudo chown syslog:adm /var/log/mitre_mapped.log
     sudo chmod 640 /var/log/mitre_mapped.log
     ```

3. **Remote Forwarding Not Working**
   - Verify network connectivity:
     ```bash
     nc -vz <syslog_server_ip> 514
     ```
   - Check firewall rules:
     ```bash
     sudo ufw status
     # If needed, allow UDP 514:
     sudo ufw allow 514/udp
     ```
   - Verify remote server configuration:
     ```bash
     # On remote server
     netstat -ulnp | grep 514
     ```

4. **Performance Issues**
   - Check system resources:
     ```bash
     top
     df -h /var/log
     ```
   - Monitor rsyslog queue:
     ```bash
     watch -n 1 'ls -l /var/lib/rsyslog'
     ```

### Logging Verification

To test the MITRE ATT&CK mapping:

1. Generate test events:
   ```bash
   # Test network scanning detection
   nmap localhost
   
   # Test account manipulation detection
   sudo useradd testuser
   ```

2. Check the mapped log:
   ```bash
   sudo tail -f /var/log/mitre_mapped.log
   ```

### Configuration Recovery

If you need to restore the original configuration:

```bash
sudo cp /etc/rsyslog.conf.backup /etc/rsyslog.conf
sudo systemctl restart rsyslog
```

## Security Considerations

- The script sets restrictive file permissions by default
- Logs are only accessible by the syslog user and admin group
- Remote forwarding uses UDP port 514 (consider using TCP and TLS in production)
- Configuration file permissions are set to 644
- Backup of original configuration is preserved

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and feature requests, please create an issue in the GitHub repository.
