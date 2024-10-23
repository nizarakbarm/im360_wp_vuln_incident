# Im360 WP Vuln Incident

## Project Goal
The goal of the **Im360 WP Vuln Incident** project is to detect vulnerabilities in WordPress by analyzing incident logs and scanning the site for known vulnerabilities to determine if any match the attacks recorded.

## Target Audience
- System Administrators of WHM Servers

is

## Key Features
- **Vulnerability Scanning**: Scans WordPress Core, themes, and plugins for vulnerabilities.
- **Integration with Imunify360**: Utilizes Imunify360 Incident Data to trigger vulnerability scans.
- **Detailed Vulnerability Reports**: Provides severity levels (CVSS v3.0) and informed fixed versions.
- **Customizable Slack Notifications**: Allows customization of Slack Webhooks URL and channel.
- **Notification Delta Time**: Customizable settings to prevent alert fatigue.
- **Customizable Logging**: Configure logging settings to suit user preferences.

## Installation and Setup

### Requirements
- WHM/cPanel
- CloudLinux + Imunify360
- ModSecurity Imunify360 Vendor
- Python 3.11 installed

### Dependencies
```plaintext
aiohttp==3.9.1
aiosqlite==0.20.0
PyYAML==6.0.2
```

### Installation Step

### 1. Clone and Install:

```
git clone https://github.com/nizarakbarm/im60_wp_vuln_incident.git
rsync -Paz im360_wp_vuln_incident /opt/imunify360_wp_vuln_incident
cd /opt/imunify360_wp_vuln_incident
python3.11 -m venv /opt/imunify360_wp_vuln_incident
source /opt/imunify360_wp_vuln_incident/bin/activate
python install --upgrade pip
python install -r requirements.txt
# run to create the json rule list
python ruleid_cve.py 
```
### 2. Configuration

Create a configuration file at /opt/imunify360_wp_vuln_incident/.config.yaml with the following content:
```
config:
  task:
    scan_concurrent: true
  notification:
    SLACK_WEBHOOKS_URL: [ SLACK_WEBHOOKS_URL ]
    SLACK_CHANNEL: [ SLACK_CHANNEL ]
    SHOW_VERSION: true
    SHOW_STATUS: true
  logging:
    version: 1
    disable_existing_loggers: False
    formatters:
      simple:
        format: '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
      detailed:
        format: '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
    handlers:
      rotating_file_handler:
        class: logging.handlers.RotatingFileHandler
        level: INFO
        formatter: detailed
        filename: /var/log/imunify360_wp_vuln_incident.log
        maxBytes: 524288000  # 500MB
        backupCount: 2
        mode: 'a'
    loggers:
      root:
        level: INFO
        handlers: [rotating_file_handler]
        propagate: no
```

### Configuration Details

#### Task Configuration:

- `scan_concurrent` : Defines whether to run scanning tasks concurrently

#### Notification Setup:

- `SLACK_WEBHOOKS_URL`: Define your Slack webhooks URL
- `SLACK_CHANNEL`: Define your Slack channel URL
- `SHOW_VERSION`: Enable/disable showing versions of plugins, themes, and WordPress Core
- `SHOW_STATUS`: Enable/disable showing detailed vulnerability information

#### Logging Configuration

- Follows Python dictionary logging format, see more info in [Logging Config DictSchema](https://docs.python.org/3/library/logging.config.html#logging-config-dictschema)
- Includes rotating file handler with 500MB max file size (can be customized).
- Maintains detailed formatting for log entries

### 3. Linux Service Setup:

```
cat <<EOF>/etc/systemd/system/imunify360_wp_vuln_incident.service
[Unit]
Description=imunify360 wp vuln incident
After=network.target

[Service]
WorkingDirectory=/opt/imunify360_wp_vuln_incident
ExecStart=/opt/imunify360_wp_vuln_incident/bin/python3 /opt/imunify360_wp_vuln_incident/im360_wp_vuln_incident.py -s "5 minutes"
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable imunify360_wp_vuln_incident.service
systemctl start imunify360_wp_vuln_incident.service
```

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/nizarakb/im360_wp_vuln_incident/LICENSE) file for details.

## Contact

Nizar Akbar Meilani - Telegarm @nizarakbarm

## Acknowledgments

I would like to extend our heartfelt thanks to the PyCon APAC 2024 organizers for accepting my topic on the Im360 WP Vuln Incident project.
