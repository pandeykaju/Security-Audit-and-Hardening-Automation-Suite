#!/usr/bin/env bash

# ==================================================
# Common Functions - Security Audit Suite
# ==================================================

# Terminal colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Audit counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNING_COUNT=0
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
FIXED_COUNT=0
SKIPPED_COUNT=0

# Generate timestamp
get_timestamp() {
    date '+%Y-%m-%d %H:%M:%S %z'
}

# Write log entry
log_message() {
    local severity="$1"
    local message="$2"
    local action="${3:-None}"
    local timestamp
    local entry
    local color

    timestamp=$(get_timestamp)

    # Prevent multiline log entries
    message=${message//$'\n'/\\n}
    action=${action//$'\n'/\\n}

    entry="[$timestamp] [$severity] $message | Action: $action"

    case "$severity" in
        CRITICAL|HIGH|ERROR)
            color="$RED"
            ;;
        MEDIUM|WARNING)
            color="$YELLOW"
            ;;
        PASS|FIXED)
            color="$GREEN"
            ;;
        *)
            color="$BLUE"
            ;;
    esac

    if [[ -t 1 ]]; then
        printf '%b%s%b\n' "$color" "$entry" "$NC"
    else
        printf '%s\n' "$entry"
    fi

    if [[ -n "${LOG_FILE:-}" ]]; then
        printf '%s\n' "$entry" >> "$LOG_FILE" || return 1
    fi
}

# Register a successful check
pass_check() {
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    PASSED_CHECKS=$((PASSED_CHECKS + 1))

    log_message "PASS" "$1" "No remediation required"
}

# Register a security finding
fail_check() {
    local severity="$1"
    local message="$2"
    local action="$3"

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    FAILED_CHECKS=$((FAILED_CHECKS + 1))

    case "$severity" in
        CRITICAL)
            CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
            ;;
        HIGH)
            HIGH_COUNT=$((HIGH_COUNT + 1))
            ;;
        MEDIUM)
            MEDIUM_COUNT=$((MEDIUM_COUNT + 1))
            ;;
        LOW)
            LOW_COUNT=$((LOW_COUNT + 1))
            ;;
    esac

    log_message "$severity" "$message" "$action"
}

# Register a warning
warn_check() {
    WARNING_COUNT=$((WARNING_COUNT + 1))

    log_message "WARNING" "$1" "${2:-Review manually}"
}

# Register a skipped check
skip_check() {
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    SKIPPED_COUNT=$((SKIPPED_COUNT + 1))

    log_message "SKIPPED" "$1" "${2:-Review manually}"
}

# Register successful remediation
record_fix() {
    FIXED_COUNT=$((FIXED_COUNT + 1))

    log_message "FIXED" "$1" "${2:-Remediation applied}"
}

# Check whether a command is available
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check root privileges
is_root() {
    [[ "$EUID" -eq 0 ]]
}

# Display section heading
print_section() {
    printf '\n'
    printf '%s\n' "=================================================="
    printf ' %s\n' "$1"
    printf '%s\n' "=================================================="
}

# Display application banner
print_banner() {
    printf '\n'
    printf '%s\n' "=================================================="
    printf '%s\n' "   SECURITY AUDIT AND HARDENING AUTOMATION SUITE"
    printf '%s\n' "                  Version 1.0"
    printf '%s\n' "=================================================="
    printf '\n'
    printf 'Hostname : %s\n' "$(hostname)"
    printf 'Date     : %s\n' "$(get_timestamp)"
    printf 'User     : %s\n' "$(id -un)"
    printf '\n'
}

# Generate final audit summary
print_summary() {
    print_section "SECURITY AUDIT SUMMARY"

    printf 'Total Checks     : %s\n' "$TOTAL_CHECKS"
    printf 'Passed Checks    : %s\n' "$PASSED_CHECKS"
    printf 'Failed Checks    : %s\n' "$FAILED_CHECKS"
    printf 'Skipped Checks   : %s\n' "$SKIPPED_COUNT"
    printf 'Warnings         : %s\n' "$WARNING_COUNT"
    printf 'Critical Issues  : %s\n' "$CRITICAL_COUNT"
    printf 'High Issues      : %s\n' "$HIGH_COUNT"
    printf 'Medium Issues    : %s\n' "$MEDIUM_COUNT"
    printf 'Low Issues       : %s\n' "$LOW_COUNT"
    printf 'Issues Fixed     : %s\n' "$FIXED_COUNT"
    printf 'Log File         : %s\n' "${LOG_FILE:-Not configured}"

    printf '%s\n' "=================================================="
}
