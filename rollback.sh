#!/usr/bin/env bash

# ==================================================
# Security Audit and Hardening Automation Suite
# Backup Restoration and Rollback
# Version: 1.0
# ==================================================

set -uo pipefail
umask 077

export PATH="/usr/sbin:/usr/bin:/sbin:/bin"

BACKUP_ROOT="/var/backups/security-audit-suite"

# Display rollback help
show_help() {
    cat <<EOF
Security Audit Suite - Rollback Utility

Usage:
  rollback.sh --list
  rollback.sh --restore SESSION_NAME
  rollback.sh --help

Options:
  --list       List available backup sessions
  --restore    Restore a selected backup session
  --help       Display help information

EOF
}

# Verify administrator privileges
check_root() {

    if (( EUID != 0 )); then
        echo "Error: Rollback requires root privileges."
        return 1
    fi

    return 0
}

# Validate trusted files and directories
validate_trusted_path() {

    local path="$1"
    local owner mode

    if [[ ! -e "$path" || -L "$path" ]]; then
        echo "Error: Missing or unsafe path: $path"
        return 1
    fi

    owner=$(stat -c '%u' -- "$path") || return 1
    mode=$(stat -c '%a' -- "$path") || return 1

    if [[ "$owner" != 0 ]] ||
       (( (8#$mode & 0022) != 0 )); then

        echo "Error: Unsafe ownership or permissions."
        return 1

    fi

    return 0
}

# Validate backup directory
validate_backup_root() {

    local path

    for path in /var /var/backups "$BACKUP_ROOT"; do

        validate_trusted_path "$path" || return 1

        if [[ ! -d "$path" ]]; then
            echo "Error: Invalid backup directory."
            return 1
        fi

    done

    return 0
}

# Validate backup session
validate_session() {

    local session="$1"
    local session_path

    if [[ ! "$session" =~ ^session_[0-9]{8}_[0-9]{6}_[a-zA-Z0-9]{6}$ ]]; then

        echo "Error: Invalid backup session name."
        return 1

    fi

    validate_backup_root || return 1

    session_path="$BACKUP_ROOT/$session"

    validate_trusted_path "$session_path" || return 1

    if [[ ! -d "$session_path" ]]; then
        echo "Error: Backup session not found."
        return 1
    fi

    return 0
}

# List available backup sessions
list_backup_sessions() {

    local session_path
    local session_name
    local count=0

    check_root || return 1

    if [[ ! -e "$BACKUP_ROOT" && ! -L "$BACKUP_ROOT" ]]; then
        echo "No backup sessions available."
        return 0
    fi

    validate_backup_root || return 1

    echo "=================================================="
    echo "           AVAILABLE BACKUP SESSIONS"
    echo "=================================================="

    for session_path in "$BACKUP_ROOT"/session_*; do

        [[ -d "$session_path" ]] || continue

        session_name="${session_path##*/}"

        if ! validate_session "$session_name"; then
            continue
        fi

        count=$((count + 1))

        printf '%s. %s\n' "$count" "$session_name"

        printf '   Created: %s\n' \
            "$(stat -c '%y' -- "$session_path")"

        printf '\n'

    done

    if [[ "$count" -eq 0 ]]; then
        echo "No valid backup sessions found."
    fi

    echo "=================================================="
    printf 'Total backup sessions: %s\n' "$count"
    echo "=================================================="

    return 0
}

# Restore an approved configuration file
restore_config_file() {

    local session="$1"
    local target="$2"
    local backup_file
    local temp_file
    local parent
    local confirmation

    check_root || return 1
    validate_session "$session" || return 1

    # Allow only approved configuration files
    case "$target" in

        /etc/login.defs|/etc/ssh/sshd_config)
            ;;

        *)
            echo "Error: Configuration file not approved."
            return 1
            ;;

    esac

    backup_file="$BACKUP_ROOT/$session$target"

    # Check backup parent directories
    validate_trusted_path "$BACKUP_ROOT/$session/etc" ||
        return 1

    if [[ "$target" == "/etc/ssh/sshd_config" ]]; then

        validate_trusted_path "$BACKUP_ROOT/$session/etc/ssh" ||
            return 1

    fi

    # Validate backup file
    validate_trusted_path "$backup_file" || return 1

    if [[ ! -f "$backup_file" ]]; then
        echo "Error: Invalid backup file."
        return 1
    fi

    # Validate destination
    validate_trusted_path /etc || return 1

    parent="$(dirname -- "$target")"

    validate_trusted_path "$parent" || return 1
    validate_trusted_path "$target" || return 1

    if [[ ! -f "$target" ]]; then
        echo "Error: Invalid destination file."
        return 1
    fi

    # Skip unchanged configuration files
    if cmp -s -- "$backup_file" "$target"; then
        echo "No restoration required: $target"
        return 0
    fi

    # Require administrator confirmation
    echo "Warning: Restoration may overwrite later changes."
    echo "Target: $target"
    echo "Backup session: $session"

    read -r -p "Type RESTORE to continue: " confirmation ||
        return 1

    if [[ "$confirmation" != "RESTORE" ]]; then
        echo "Restoration cancelled."
        return 1
    fi
    # Back up the current configuration before restoration
    create_pre_restore_backup "$target" || return 1
    # Create temporary restoration file
    temp_file=$(mktemp "$parent/.rollback_XXXXXX") ||
        return 1

    if ! cp -a -- "$backup_file" "$temp_file"; then

        rm -f -- "$temp_file"
        echo "Error: Unable to prepare restoration."
        return 1

    fi

    # Validate SSH configuration
    if [[ "$target" == "/etc/ssh/sshd_config" ]]; then

        if ! command -v sshd >/dev/null 2>&1 ||
           ! sshd -t -f "$temp_file"; then

            rm -f -- "$temp_file"
            echo "Error: SSH configuration validation failed."
            return 1

        fi

    fi

    # Restore configuration file
    if ! mv -fT -- "$temp_file" "$target"; then

        rm -f -- "$temp_file"
        echo "Error: Configuration restoration failed."
        return 1

    fi

    # Verify restored content
    if cmp -s -- "$backup_file" "$target"; then

        echo "SUCCESS: Configuration restored: $target"

        if [[ "$target" == "/etc/ssh/sshd_config" ]]; then
            echo "Review SSH configuration before reloading SSH."
        fi

        return 0

    fi

    echo "Error: Restoration verification failed."
    return 1
}


# Restore original permissions of sensitive files
restore_file_permissions() {

    local session="$1"
    local target="$2"
    local backup_file
    local original_mode
    local current_mode
    local confirmation

    check_root || return 1
    validate_session "$session" || return 1

    # Allow only approved sensitive files
    case "$target" in

        /etc/passwd|/etc/shadow|/etc/group)
            ;;

        *)
            echo "Error: File not approved for permission restoration."
            return 1
            ;;

    esac

    backup_file="$BACKUP_ROOT/$session$target"

    # Validate backup directory and file
    validate_trusted_path "$BACKUP_ROOT/$session/etc" ||
        return 1

    validate_trusted_path "$backup_file" ||
        return 1

    if [[ ! -f "$backup_file" ]]; then
        echo "Error: Invalid backup file."
        return 1
    fi

    # Validate destination file
    validate_trusted_path /etc || return 1
    validate_trusted_path "$target" || return 1

    if [[ ! -f "$target" ]]; then
        echo "Error: Invalid destination file."
        return 1
    fi

    # Validate shadow file group ownership
    if [[ "$target" == "/etc/shadow" ]]; then

        local current_group
        local backup_group

        current_group=$(stat -c '%G' -- "$target") ||
            return 1

        backup_group=$(stat -c '%G' -- "$backup_file") ||
            return 1

        case "$current_group" in
            root|shadow)
                ;;
            *)
                echo "Error: Unsafe shadow group ownership."
                return 1
                ;;
        esac

        if [[ "$current_group" != "$backup_group" ]]; then
            echo "Error: Shadow group ownership has changed."
            return 1
        fi

    fi

    # Read original and current permissions
    original_mode=$(stat -c '%a' -- "$backup_file") ||
        return 1

    current_mode=$(stat -c '%a' -- "$target") ||
        return 1

    # Reject unsafe permission modes
    case "$target" in

        /etc/passwd|/etc/group)
            case "$original_mode" in
                644|640|600|444|440|400)
                    ;;
                *)
                    echo "Error: Unsafe backup permissions."
                    return 1
                    ;;
            esac
            ;;

        /etc/shadow)
            case "$original_mode" in
                640|600|440|400|0)
                    ;;
                *)
                    echo "Error: Unsafe shadow permissions."
                    return 1
                    ;;
            esac
            ;;

    esac

    if [[ "$current_mode" == "$original_mode" ]]; then

        echo "No permission restoration required: $target"
        return 0

    fi

    echo "Target: $target"
    echo "Current permissions: $current_mode"
    echo "Original permissions: $original_mode"

    read -r -p "Type RESTORE to continue: " confirmation ||
        return 1

    if [[ "$confirmation" != "RESTORE" ]]; then

        echo "Permission restoration cancelled."
        return 1

    fi
    # Back up current permissions before restoration
    create_pre_restore_backup "$target" || return 1
    # Restore permissions without changing file contents
    if ! chmod -- "$original_mode" "$target"; then

        echo "Error: Unable to restore permissions."
        return 1

    fi

    # Verify restored permissions
    if [[ "$(stat -c '%a' -- "$target")" == "$original_mode" ]]; then

        echo "SUCCESS: Permissions restored: $target"
        return 0

    fi

    # Attempt to recover previous permissions
    chmod -- "$current_mode" "$target" ||
        echo "Warning: Manual recovery required."

    echo "Error: Permission restoration verification failed."
    return 1
}


# Validate protected rollback installation
validate_installation() {

    local script_path
    local path

    check_root || return 1

    script_path=$(realpath -e -- "${BASH_SOURCE[0]}") ||
        return 1

    if [[ "$script_path" != "/opt/security-audit-suite/rollback.sh" ]]; then

        echo "Error: Unsafe rollback execution location."
        return 1

    fi

    for path in \
        /opt \
        /opt/security-audit-suite \
        /opt/security-audit-suite/rollback.sh \
        /opt/security-audit-suite/logs; do

        validate_trusted_path "$path" || return 1

    done

    return 0
}

# Initialize rollback logging
initialize_rollback_log() {

    ROLLBACK_LOG=$(mktemp \
        "/opt/security-audit-suite/logs/rollback_$(date '+%Y%m%d_%H%M%S')_XXXXXX.log") ||
        return 1

    return 0
}

# Record rollback activity
rollback_log() {

    local severity="$1"
    local message="$2"
    local timestamp

    timestamp=$(date '+%Y-%m-%d %H:%M:%S %z')

    printf '[%s] [%s] %s\n' \
        "$timestamp" "$severity" "$message" |
        tee -a "$ROLLBACK_LOG"
}


# Create a backup before restoring a file
create_pre_restore_backup() {

    local target="$1"
    local backup_session
    local destination
    local directory_mode

    check_root || return 1
    validate_installation || return 1
    validate_backup_root || return 1

    # Require a private backup directory
    directory_mode=$(stat -c '%a' -- "$BACKUP_ROOT") ||
        return 1

    if [[ "$directory_mode" != "700" ]]; then
        echo "Error: Backup directory must have mode 700."
        return 1
    fi

    # Allow only approved system files
    case "$target" in

        /etc/passwd|/etc/shadow|/etc/group|\
        /etc/login.defs|/etc/ssh/sshd_config)
            ;;

        *)
            echo "Error: File not approved for backup."
            return 1
            ;;

    esac

    # Validate the source file
    validate_trusted_path /etc || return 1

    if [[ "$target" == "/etc/ssh/sshd_config" ]]; then
        validate_trusted_path /etc/ssh || return 1
    fi

    validate_trusted_path "$target" || return 1

    if [[ ! -f "$target" ]]; then
        echo "Error: Invalid source file."
        return 1
    fi

    # Create a private backup session
    backup_session=$(mktemp -d \
        "$BACKUP_ROOT/session_$(date +%Y%m%d_%H%M%S)_XXXXXX") ||
        return 1

    destination="$backup_session$target"

    mkdir -p -- "$(dirname -- "$destination")" ||
        return 1

    # Preserve current content and permissions
    if ! cp -a -- "$target" "$destination"; then

        echo "Error: Pre-restoration backup failed."
        return 1

    fi

    # Verify backup content and permissions
    if ! cmp -s -- "$target" "$destination"; then
        echo "Error: Backup content verification failed."
        return 1
    fi

    if [[ "$(stat -c '%a' -- "$target")" != \
          "$(stat -c '%a' -- "$destination")" ]]; then

        echo "Error: Backup permission verification failed."
        return 1

    fi

    rollback_log "INFO" \
        "Pre-restoration backup created: $destination" ||
        return 1

    return 0
}

# Restore approved files from a backup session
restore_session() {

    local session="$1"
    local target
    local backup_file
    local found=0
    local restored=0
    local failed=0

    validate_installation || return 1
    validate_session "$session" || return 1

    if [[ "$(stat -c '%a' -- "$BACKUP_ROOT")" != "700" ||
          "$(stat -c '%a' -- "$BACKUP_ROOT/$session")" != "700" ]]; then

        rollback_log "ERROR" "Backup directories are not private."
        return 1

    fi

    for target in \
        /etc/login.defs \
        /etc/ssh/sshd_config \
        /etc/passwd \
        /etc/shadow \
        /etc/group; do

        backup_file="$BACKUP_ROOT/$session$target"

        if [[ ! -e "$backup_file" && ! -L "$backup_file" ]]; then
            continue
        fi

        found=$((found + 1))

        rollback_log "INFO" "Processing: $target" ||
            return 1

        case "$target" in

            /etc/login.defs|/etc/ssh/sshd_config)

                if restore_config_file "$session" "$target"; then
                    restored=$((restored + 1))
                else
                    failed=$((failed + 1))
                    rollback_log "ERROR" "Restoration failed: $target"
                fi
                ;;

            /etc/passwd|/etc/shadow|/etc/group)

                if restore_file_permissions "$session" "$target"; then
                    restored=$((restored + 1))
                else
                    failed=$((failed + 1))
                    rollback_log "ERROR" "Permission restoration failed: $target"
                fi
                ;;

        esac

    done

    echo "=========================================="
    echo "           ROLLBACK SUMMARY"
    echo "=========================================="
    echo "Backup files found : $found"
    echo "Successful checks  : $restored"
    echo "Failed or cancelled: $failed"
    echo "Log file           : $ROLLBACK_LOG"
    echo "=========================================="

    rollback_log "INFO" \
        "Summary: found=$found successful=$restored failed=$failed"

    if (( found == 0 || failed > 0 )); then
        return 1
    fi

    return 0
}

# Main rollback controller
main() {

    case "${1:---help}" in

        --help|-h)

            show_help
            ;;

        --list)

            if [[ $# -ne 1 ]]; then
                echo "Error: Invalid arguments."
                return 1
            fi

            validate_installation || return 1

            list_backup_sessions
            ;;

        --restore)

            if [[ $# -ne 2 ]]; then
                echo "Error: Backup session name required."
                return 1
            fi

            validate_installation || return 1
            validate_session "$2" || return 1

            initialize_rollback_log || return 1

            rollback_log "INFO" "Restore requested for session: $2" || return 1

            # Execute backup restoration
            restore_session "$2"
            ;;

        *)

            echo "Error: Unknown option: $1"
            show_help
            return 1
            ;;

    esac
}

# Execute rollback controller
main "$@"
