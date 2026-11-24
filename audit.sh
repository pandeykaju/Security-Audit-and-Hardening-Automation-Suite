#!/usr/bin/env bash

# ==================================================
# Security Audit and Hardening Automation Suite
# Main Controller Script
# Version: 1.0
# ==================================================

set -uo pipefail
umask 077


# Use trusted system commands
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"

# Protect privileged execution
if (( EUID == 0 )); then

    SCRIPT_PATH=$(/usr/bin/realpath -e -- "${BASH_SOURCE[0]}") ||
        exit 1

    if [[ "$SCRIPT_PATH" != "/opt/security-audit-suite/audit.sh" ]]; then

        echo "Error: Unsafe privileged execution location."
        echo "Use the protected installation directory."
        exit 1

    fi

    # Verify protected project files and directories
    for trusted_path in \
        /opt \
        /opt/security-audit-suite \
        /opt/security-audit-suite/audit.sh \
        /opt/security-audit-suite/config \
        /opt/security-audit-suite/modules \
        /opt/security-audit-suite/logs \
        /opt/security-audit-suite/reports \
        /opt/security-audit-suite/backups \
        /opt/security-audit-suite/config/policy.conf \
        /opt/security-audit-suite/modules/*.sh; do

        if [[ ! -e "$trusted_path" || -L "$trusted_path" ]]; then

            echo "Error: Missing or unsafe path: $trusted_path"
            exit 1

        fi

        FILE_OWNER=$(/usr/bin/stat -c '%u' -- "$trusted_path") ||
            exit 1

        FILE_MODE=$(/usr/bin/stat -c '%a' -- "$trusted_path") ||
            exit 1

        if [[ "$FILE_OWNER" != 0 ]] ||
           (( (8#$FILE_MODE & 0022) != 0 )); then

            echo "Error: Untrusted ownership or permissions."
            echo "Unsafe path: $trusted_path"
            exit 1

        fi

    done

fi


# Project directories
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$BASE_DIR/config/policy.conf"
MODULE_DIR="$BASE_DIR/modules"
LOG_DIR="$BASE_DIR/logs"
REPORT_DIR="$BASE_DIR/reports"
BACKUP_DIR="$BASE_DIR/backups"

# Load common functions
source "$MODULE_DIR/common.sh"

# Default options
PROFILE=""
CUSTOM_CHECKS=""
REMEDIATE=false

# Display help
show_help() {
    cat <<EOF
Security Audit and Hardening Automation Suite

Usage:
  bash audit.sh [OPTIONS]

Options:
  -p, --profile NAME     Select scan profile
  -c, --checks LIST      Custom comma-separated checks
  -r, --remediate        Enable approved automatic fixes
  -h, --help             Display help
  -v, --version          Display version

Available profiles:
  quick
  full
  network
  filesystem
  custom

Available checks:
  ssh, password, network, permissions,
  accounts, firewall, updates, services

Examples:
  bash audit.sh
  bash audit.sh --profile quick
  bash audit.sh --profile network
  bash audit.sh --profile custom --checks ssh,network
  sudo /bin/bash /opt/security-audit-suite/audit.sh --profile full --remediate

EOF
}

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--profile)
            if [[ $# -lt 2 || "$2" == -* ]]; then
                echo "Error: Profile name required."
                exit 1
            fi
            PROFILE="$2"
            shift 2
            ;;

        -c|--checks)
            if [[ $# -lt 2 || "$2" == -* ]]; then
                echo "Error: Custom checks required."
                exit 1
            fi
            CUSTOM_CHECKS="$2"
            PROFILE="custom"
            shift 2
            ;;

        -r|--remediate)
            REMEDIATE=true
            shift
            ;;

        -h|--help)
            show_help
            exit 0
            ;;

        -v|--version)
            echo "Security Audit Suite Version 1.0"
            exit 0
            ;;

        *)
            echo "Error: Unknown option $1"
            show_help
            exit 1
            ;;
    esac
done

# Load security configuration
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: Configuration file not found."
    exit 1
fi

source "$CONFIG_FILE"

PROFILE="${PROFILE:-$DEFAULT_PROFILE}"

# Select security checks
case "$PROFILE" in
    quick)
        SELECTED_CHECKS="$PROFILE_QUICK"
        ;;

    full)
        SELECTED_CHECKS="$PROFILE_FULL"
        ;;

    network)
        SELECTED_CHECKS="$PROFILE_NETWORK"
        ;;

    filesystem)
        SELECTED_CHECKS="$PROFILE_FILESYSTEM"
        ;;

    custom)
        SELECTED_CHECKS="${CUSTOM_CHECKS//,/ }"
        SELECTED_CHECKS="${SELECTED_CHECKS:-$PROFILE_CUSTOM}"

        if [[ -z "$SELECTED_CHECKS" ]]; then
            echo "Error: No custom checks selected."
            exit 1
        fi
        ;;

    *)
        echo "Error: Invalid profile: $PROFILE"
        exit 1
        ;;
esac

# Convert selected checks into an array
read -r -a CHECKS <<< "$SELECTED_CHECKS"

# Validate selected checks
for check in "${CHECKS[@]}"; do
    case "$check" in
        ssh|password|network|permissions|accounts|firewall|updates|services)
            ;;
        *)
            echo "Error: Invalid security check: $check"
            exit 1
            ;;
    esac
done

# Validate remediation permissions
if [[ "$REMEDIATE" == true ]]; then
    if ! is_root; then
        echo "Error: Remediation requires root privileges."
        exit 1
    fi

    if [[ "$BACKUP_ENABLED" != true ]]; then
        echo "Error: Backups must be enabled for remediation."
        exit 1
    fi
fi

# Create required directories
mkdir -p "$LOG_DIR" "$REPORT_DIR" "$BACKUP_DIR" || exit 1

# Create unique log and report files
TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"

LOG_FILE=$(mktemp "$LOG_DIR/audit_${TIMESTAMP}_XXXXXX.log") || exit 1

REPORT_FILE=$(mktemp "$REPORT_DIR/report_${TIMESTAMP}_XXXXXX.txt") || exit 1

# Display project banner
print_banner

printf 'Scan Profile : %s\n' "$PROFILE"
printf 'Checks       : %s\n' "$SELECTED_CHECKS"

if [[ "$REMEDIATE" == true ]]; then
    printf 'Mode         : Remediation\n'
else
    printf 'Mode         : Audit Only\n'
fi

printf '\n'

log_message "INFO" "Security audit started" "Profile: $PROFILE"

# Warn if running without root privileges
if ! is_root; then
    warn_check "Running without root privileges" \
        "Some security checks may be skipped"
fi

# Load remediation functions
if [[ -s "$MODULE_DIR/remediation.sh" ]]; then
    source "$MODULE_DIR/remediation.sh"
elif [[ "$REMEDIATE" == true ]]; then
    log_message "ERROR" "Remediation module not implemented"
    exit 1
fi


    
# Execute selected security modules
for check in "${CHECKS[@]}"; do

    MODULE_FILE="$MODULE_DIR/$check.sh"
    FUNCTION_NAME="check_$check"

    print_section "Running ${check^^} Security Checks"

    if [[ ! -s "$MODULE_FILE" ]]; then
        skip_check "$check module not implemented" \
            "Complete the security module"
        continue
    fi

    source "$MODULE_FILE" || {
        warn_check "Unable to load $check module"
        continue
    }

    if declare -F "$FUNCTION_NAME" >/dev/null; then

        if ! "$FUNCTION_NAME"; then
            warn_check "$check module returned an error" \
                "Review module execution"
            continue
        fi

    else

        skip_check "Function $FUNCTION_NAME not found" \
            "Review module implementation"
        continue

    fi

    # Execute automatic remediation when requested
    if [[ "$REMEDIATE" == true ]]; then

        if ! run_remediation "$check"; then

            warn_check \
                "Remediation incomplete for module: $check" \
                "Review detailed audit logs"

        fi

    fi

done


# Generate final summary
print_summary | tee -a "$REPORT_FILE"

log_message "INFO" "Security audit completed" \
    "Review generated report"

# Include detailed findings in report
{
    printf '\nDETAILED AUDIT LOG\n'
    printf '%s\n' "=================================================="
    cat "$LOG_FILE"
} >> "$REPORT_FILE"

printf '\nAudit completed successfully.\n'
printf 'Log saved to: %s\n' "$LOG_FILE"
printf 'Report saved to: %s\n' "$REPORT_FILE"
