# Security Audit and Hardening Automation Suite

A modular Bash-based security auditing and system hardening tool designed for Linux environments. It identifies common security misconfigurations, generates detailed audit reports, and supports controlled automatic remediation with backup and rollback mechanisms.

## Features

- Automated Linux security auditing
- Eight modular security checks
- Customizable scan profiles
- Configurable security policies
- Severity-based security logging
- Timestamped audit reports
- Automatic remediation for supported issues
- Configuration backups
- Controlled rollback mechanism
- Root privilege validation
- Automated testing

## Technologies Used

- Bash Shell Scripting
- Linux / Ubuntu
- Windows Subsystem for Linux (WSL2)
- ShellCheck
- Git and GitHub
- Visual Studio Code

## Security Modules

| Module | Description |
|---|---|
| SSH | Checks SSH security configuration |
| Password | Audits password aging and password quality policies |
| Network | Identifies listening ports and unexpected services |
| Permissions | Checks sensitive file permissions and world-writable files |
| Accounts | Detects insecure user account configurations |
| Firewall | Checks supported firewall configurations |
| Updates | Identifies pending package updates |
| Services | Detects configured unnecessary services |

## Project Structure

    security-audit-suite/
    ├── audit.sh
    ├── rollback.sh
    ├── config/
    │   └── policy.conf
    ├── modules/
    │   ├── common.sh
    │   ├── ssh.sh
    │   ├── password.sh
    │   ├── network.sh
    │   ├── permissions.sh
    │   ├── accounts.sh
    │   ├── firewall.sh
    │   ├── updates.sh
    │   ├── services.sh
    │   └── remediation.sh
    ├── tests/
    │   └── test_audit.sh
    ├── logs/
    ├── reports/
    ├── backups/
    ├── .gitignore
    └── README.md

Runtime directories may be absent from the Git repository because generated files are excluded.

## System Requirements

- Linux operating system
- Bash
- Standard Linux command-line utilities
- iproute2
- ShellCheck for development testing
- Root privileges for protected operations

## Installation

Install the required packages on Ubuntu:

    sudo apt update
    sudo apt install -y git curl shellcheck iproute2

Open the downloaded or cloned project directory.

Set executable permissions:

    chmod +x audit.sh rollback.sh tests/test_audit.sh

## Usage

Display available options:

    ./audit.sh --help

Run a full security audit:

    ./audit.sh --profile full

Run a quick security audit:

    ./audit.sh --profile quick

Run a network security audit:

    ./audit.sh --profile network

Run a filesystem security audit:

    ./audit.sh --profile filesystem

Run selected security checks:

    ./audit.sh --checks password,permissions

## Scan Profiles

| Profile | Purpose |
|---|---|
| Quick | Essential security checks |
| Full | Comprehensive security audit |
| Network | Network-related security checks |
| Filesystem | File permissions and account checks |
| Custom | User-selected security modules |

## Configuration

Security policies can be customized through:

    config/policy.conf

Configurable settings include:

- Minimum password length
- Password expiration policy
- Allowed network ports
- SSH security requirements
- Sensitive file permissions
- Firewall requirements
- Unnecessary services
- Remediation preferences

## Protected Installation

Review the source code and configuration before installing the suite for privileged operations.

    sudo install -d -o root -g root -m 700 /opt/security-audit-suite
    sudo install -d -o root -g root -m 700 /opt/security-audit-suite/{config,modules,logs,reports,backups}
    sudo install -o root -g root -m 700 audit.sh rollback.sh /opt/security-audit-suite/
    sudo install -o root -g root -m 600 modules/*.sh /opt/security-audit-suite/modules/
    sudo install -o root -g root -m 600 config/policy.conf /opt/security-audit-suite/config/

The installation must be root-owned and protected from unauthorized modification.

## Automatic Remediation

Supported remediation operations include:

- SSH root login configuration
- Password aging defaults
- Sensitive file permission hardening

Automatic remediation is disabled by default.

After reviewing audit findings and testing in an isolated environment, remediation can be explicitly enabled:

    sudo /bin/bash /opt/security-audit-suite/audit.sh --profile full --remediate

## Backup and Rollback

Configuration backups are stored in:

    /var/backups/security-audit-suite/

List available backup sessions:

    sudo /bin/bash /opt/security-audit-suite/rollback.sh --list

Restore a selected backup session:

    sudo /bin/bash /opt/security-audit-suite/rollback.sh --restore SESSION_NAME

The rollback mechanism includes:

- Root privilege verification
- Backup validation
- User confirmation
- Pre-restoration backups
- Restoration logging
- Restrictions on unsafe permission restoration

## Logging and Reporting

The application generates timestamped logs and summary reports containing:

- Security findings
- Severity levels
- Recommended corrective actions
- Remediation results
- Passed and failed checks
- Warnings and skipped checks

Generated logs, reports and sensitive backups are excluded from Git version control.

## Testing

Run automated tests:

    ./tests/test_audit.sh

Perform static code analysis:

    shellcheck --severity=error audit.sh rollback.sh modules/*.sh tests/test_audit.sh

The development test suite previously achieved 24 out of 24 passing tests.

Password policy remediation and backup integrity were verified in an isolated Ubuntu WSL2 environment.

## Limitations

- Some checks depend on installed Linux services and utilities.
- WSL2 does not fully represent a production Linux server.
- Windows host firewall settings are not verified.
- Password aging changes apply to account creation defaults rather than automatically updating existing accounts.
- SSH configuration changes require a separately reviewed service reload.
- Pending package updates are not necessarily security-specific updates.
- Rollback intentionally refuses unsafe original file permissions.
- Full privileged remediation and rollback coverage has not been independently verified.

## Security Precautions

- Review audit findings before applying remediation.
- Test configuration changes in an isolated environment.
- Maintain backups of important system files.
- Never publish sensitive logs, credentials or system backups.
- Avoid running unreviewed scripts with root privileges.

## Future Enhancements

- HTML-based security reports
- Scheduled security audits
- Email notifications
- CIS benchmark integration
- Expanded Linux distribution support
- Additional automated security tests

## Author

Kajal Pandey

B.Sc. Information Technology Student

## Disclaimer

This project is developed for educational purposes and authorized Linux security auditing. Users should review all configuration changes before applying them to production systems.
