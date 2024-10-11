# Rsyslog Configuration Script

This repository contains a bash script that automates the configuration of rsyslog on Ubuntu systems. The script sets up custom log files and forwards logs to a remote syslog server.

## Prerequisites

Before running the script, ensure you have the following installed on your Ubuntu system:

1. rsyslog
2. auditd

### Installing rsyslog and auditd

To install rsyslog and auditd on Ubuntu, run the following commands:

```bash
sudo apt update
sudo apt install rsyslog auditd audispd-plugins -y
```

After installation, start and enable the services:

```bash
sudo systemctl start rsyslog
sudo systemctl enable rsyslog
sudo systemctl start auditd
sudo systemctl enable auditd
```

## Usage

1. Clone this repository or download the script file.

2. Make the script executable:
   ```bash
   chmod +x rsyslog_config.sh
   ```

3. Run the script with sudo privileges:
   ```bash
   sudo ./rsyslog_config.sh
   ```

4. When prompted, enter the IP address of your syslog server.

5. The script will perform the following actions:
   - Backup the original rsyslog configuration
   - Create custom log files
   - Generate a new rsyslog configuration with custom rules
   - Restart the rsyslog service

## Features

- Configures rsyslog to forward logs to a remote syslog server
- Creates custom log files for various services and events
- Sets up log forwarding for security-related events
- Configures logging for common services like Apache, Nginx, MySQL, and more
- Implements best practices for log management and security event monitoring

## Customization

You can modify the script to add or remove custom log files and rules according to your specific requirements. Edit the script before running it to make any necessary changes.

## Troubleshooting

If you encounter any issues:

1. Check the rsyslog status:
   ```bash
   sudo systemctl status rsyslog
   ```

2. View the rsyslog log for any error messages:
   ```bash
   sudo tail -f /var/log/syslog
   ```

3. Verify the configuration file for any syntax errors:
   ```bash
   sudo rsyslogd -N1
   ```

## Contributing

Contributions to improve the script or documentation are welcome. Please submit a pull request or open an issue to discuss proposed changes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
