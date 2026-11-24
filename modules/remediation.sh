#!/usr/bin/env bash

# ==================================================
# Automatic Remediation and Backup Module
# ==================================================

# Check whether remediation is permitted
remediation_allowed() {

    [[ "${REMEDIATE:-false}" == true ]] &&
    [[ "${BACKUP_ENABLED:-false}" == true ]] &&
    is_root
}

# Initialize secure backup directory
initialize_backup() {

    if ! remediation_allowed; then
        return 1
    fi

    if [[ -n "${BACKUP_SESSION:-}" ]]; then
        return 0
    fi

    local backup_root="/var/backups/security-audit-suite"

    if [[ -L "$backup_root" ]]; then
        log_message "ERROR" "Unsafe backup directory"
        return 1
    fi

    if ! install -d -m 700 -o root -g root "$backup_root"; then

        log_message "ERROR" \
            "Unable to initialize backup directory"

        return 1

    fi

    BACKUP_SESSION=$(mktemp -d \
        "$backup_root/session_$(date +%Y%m%d_%H%M%S)_XXXXXX") ||
        return 1

    log_message "INFO" \
        "Backup session created: $BACKUP_SESSION"

    return 0
}

# Create a backup before modifying a system file
backup_file() {

    local file="$1"
    local destination

    if ! remediation_allowed; then
        return 1
    fi

    # Only approved system files can be backed up
    case "$file" in
        /etc/passwd|/etc/shadow|/etc/group|\
        /etc/login.defs|/etc/ssh/sshd_config)
            ;;
        *)
            log_message "ERROR" \
                "File not approved for automatic remediation: $file"
            return 1
            ;;
    esac

    if [[ ! -f "$file" || -L "$file" ]]; then

        log_message "ERROR" \
            "Invalid or unsafe backup source: $file"

        return 1

    fi

    initialize_backup || return 1

    destination="$BACKUP_SESSION$file"

    mkdir -p -- "$(dirname "$destination")" ||
        return 1

    # Preserve the original backup
    if [[ -f "$destination" ]]; then
        return 0
    fi

    if cp -a -- "$file" "$destination"; then

        log_message "INFO" \
            "Backup created for $file"

        return 0

    fi

    log_message "ERROR" \
        "Backup failed for $file" \
        "Remediation cancelled"

    return 1
}

# Correct approved sensitive file permissions
fix_file_permission() {

    local file="$1"
    local expected="$2"
    local actual
    local verified
    local owner

    if ! remediation_allowed; then
        return 1
    fi

    if [[ "${FIX_FILE_PERMISSIONS:-false}" != true ]]; then
        return 1
    fi

    # Restrict changes to approved files and modes
    case "$file:$expected" in
        /etc/passwd:644|/etc/group:644|\
        /etc/shadow:640|/etc/shadow:600|\
        /etc/shadow:400|/etc/shadow:000)
            ;;
        *)
            log_message "ERROR" \
                "Unapproved permission remediation: $file"
            return 1
            ;;
    esac

    if [[ ! -f "$file" || -L "$file" ]]; then
        return 1
    fi

    actual=$(stat -c '%a' -- "$file") || return 1
    owner=$(stat -c '%u' -- "$file") || return 1

    if [[ "$owner" != 0 ]]; then
        log_message "ERROR" \
            "Unexpected file ownership: $file" \
            "Review manually"
        return 1
    fi

    # Do not broaden existing permissions
    if (( (8#$expected & 8#$actual) != 8#$expected )); then

        log_message "WARNING" \
            "Requested permissions would broaden access: $file" \
            "Manual review required"

        return 1

    fi

    if (( 8#$actual == 8#$expected )); then
        return 0
    fi

    backup_file "$file" || return 1

    if chmod -- "$expected" "$file"; then

        verified=$(stat -c '%a' -- "$file") || return 1

        if (( 8#$verified == 8#$expected )); then

            record_fix \
                "Corrected permissions for $file" \
                "Changed from $actual to $expected"

            return 0

        fi

    fi

    log_message "ERROR" \
        "Permission remediation failed: $file" \
        "Attempting to restore original permissions"

    if ! chmod -- "$actual" "$file"; then
        log_message "ERROR" \
            "Unable to restore permissions: $file" \
            "Administrator intervention required"
    fi

    return 1
}


# ==================================================
# Password Policy Remediation
# ==================================================

fix_password_policy() {

    local file="/etc/login.defs"
    local temp_file
    local key
    local expected
    local actual
    local owner

    if ! remediation_allowed; then
        return 1
    fi

    if [[ "${FIX_PASSWORD_POLICY:-false}" != true ]]; then
        return 1
    fi

    # Validate policy values
    for expected in "$PASS_MAX_DAYS" \
                    "$PASS_MIN_DAYS" \
                    "$PASS_WARN_AGE"; do

        if [[ ! "$expected" =~ ^(0|[1-9][0-9]{0,3})$ ]]; then

            log_message "ERROR" \
                "Invalid password policy value"

            return 1

        fi

    done

    if (( PASS_MAX_DAYS <= 0 ||
          PASS_MIN_DAYS > PASS_MAX_DAYS ||
          PASS_WARN_AGE > PASS_MAX_DAYS )); then

        log_message "ERROR" \
            "Inconsistent password aging policy"

        return 1

    fi

    # Validate target file
    if [[ ! -f "$file" || -L "$file" ]]; then

        log_message "ERROR" \
            "Unsafe password configuration file"

        return 1

    fi

    owner=$(stat -c '%u' -- "$file") || return 1

    if [[ "$owner" != 0 ]]; then

        log_message "ERROR" \
            "Unexpected password configuration ownership"

        return 1

    fi

    # Create backup before modification
    backup_file "$file" || return 1

    # Create temporary file in the same directory
    temp_file=$(mktemp /etc/.login.defs.XXXXXX) ||
        return 1

    if ! cp -a -- "$file" "$temp_file"; then
        rm -f -- "$temp_file"
        return 1
    fi

    # Update password policy values
    if ! awk \
        -v max="$PASS_MAX_DAYS" \
        -v min="$PASS_MIN_DAYS" \
        -v warn="$PASS_WARN_AGE" '

        $1 == "PASS_MAX_DAYS" {
            if (!seen_max++) print "PASS_MAX_DAYS\t" max
            next
        }

        $1 == "PASS_MIN_DAYS" {
            if (!seen_min++) print "PASS_MIN_DAYS\t" min
            next
        }

        $1 == "PASS_WARN_AGE" {
            if (!seen_warn++) print "PASS_WARN_AGE\t" warn
            next
        }

        {print}

        END {
            if (!seen_max) print "PASS_MAX_DAYS\t" max
            if (!seen_min) print "PASS_MIN_DAYS\t" min
            if (!seen_warn) print "PASS_WARN_AGE\t" warn
        }

    ' "$file" > "$temp_file"; then

        rm -f -- "$temp_file"

        log_message "ERROR" \
            "Unable to prepare password policy"

        return 1

    fi

    # Verify temporary configuration
    for key in PASS_MAX_DAYS PASS_MIN_DAYS PASS_WARN_AGE; do

        expected="${!key}"

        actual=$(awk -v key="$key" '
            $1 == key {print $2}
        ' "$temp_file")

        if [[ "$actual" != "$expected" ]]; then

            rm -f -- "$temp_file"

            log_message "ERROR" \
                "Password policy verification failed: $key"

            return 1

        fi

    done

    # Avoid unnecessary changes
    if cmp -s "$file" "$temp_file"; then

        rm -f -- "$temp_file"

        log_message "INFO" \
            "Password aging policy already compliant"

        return 0

    fi

    # Apply validated configuration
    if ! mv -fT -- "$temp_file" "$file"; then

        rm -f -- "$temp_file"

        log_message "ERROR" \
            "Unable to apply password policy"

        return 1

    fi

    # Verify installed configuration
    for key in PASS_MAX_DAYS PASS_MIN_DAYS PASS_WARN_AGE; do

        expected="${!key}"

        actual=$(awk -v key="$key" '
            $1 == key {print $2}
        ' "$file")

        if [[ "$actual" != "$expected" ]]; then

            log_message "ERROR" \
                "Installed password policy verification failed" \
                "Restore configuration from secure backup"

            return 1

        fi

    done

    record_fix \
        "Password aging policy updated successfully" \
        "Maximum=$PASS_MAX_DAYS Minimum=$PASS_MIN_DAYS Warning=$PASS_WARN_AGE"

    return 0
}


# ==================================================
# SSH Security Remediation
# ==================================================

fix_ssh_root_login() {

    local file="/etc/ssh/sshd_config"
    local temp_file
    local sshd_binary
    local effective_config
    local owner

    # Check remediation authorization
    if ! remediation_allowed; then
        return 1
    fi

    if [[ "${FIX_ROOT_SSH:-false}" != true ]]; then
        return 1
    fi

    # Validate configured policy
    if [[ "$PERMIT_ROOT_LOGIN" != "no" ]]; then

        log_message "ERROR" \
            "Unsupported SSH remediation policy"

        return 1

    fi

    # Check SSH configuration availability
    if [[ ! -f "$file" || -L "$file" ]]; then

        skip_check "SSH configuration unavailable or unsafe"

        return 1

    fi

    # Verify SSH server availability
    sshd_binary=$(command -v sshd) || {

        skip_check "SSH server is not installed"

        return 1

    }

    # Validate file ownership
    owner=$(stat -c '%u' -- "$file") || return 1

    if [[ "$owner" != 0 ]]; then

        log_message "ERROR" \
            "Unexpected SSH configuration ownership"

        return 1

    fi

    # Validate existing configuration
    if ! "$sshd_binary" -t -f "$file"; then

        log_message "ERROR" \
            "Existing SSH configuration is invalid"

        return 1

    fi

    # Check current effective configuration
    effective_config=$("$sshd_binary" -T -f "$file") ||
        return 1

    if grep -qx 'permitrootlogin no' <<< "$effective_config"; then

        log_message "INFO" \
            "Global SSH root login policy already compliant"

        return 0

    fi

    # Create backup before modification
    backup_file "$file" || return 1

    # Prepare temporary configuration
    temp_file=$(mktemp /etc/ssh/.sshd_config.XXXXXX) ||
        return 1

    if ! cp -a -- "$file" "$temp_file"; then

        rm -f -- "$temp_file"

        return 1

    fi

    # Add global root login restriction
    if ! {
        printf '%s\n' "# Security Audit Suite Hardening"
        printf '%s\n' "PermitRootLogin no"
        cat -- "$file"
    } > "$temp_file"; then

        rm -f -- "$temp_file"

        return 1

    fi

    # Validate proposed SSH configuration
    if ! "$sshd_binary" -t -f "$temp_file"; then

        rm -f -- "$temp_file"

        log_message "ERROR" \
            "Proposed SSH configuration failed validation"

        return 1

    fi

    # Verify effective root login policy
    if ! effective_config=$(
        "$sshd_binary" -T -f "$temp_file"
    ); then

        rm -f -- "$temp_file"

        return 1

    fi

    if ! grep -qx 'permitrootlogin no' <<< "$effective_config"; then

        rm -f -- "$temp_file"

        log_message "ERROR" \
            "SSH root login policy verification failed"

        return 1

    fi

    # Apply validated configuration
    if ! mv -fT -- "$temp_file" "$file"; then

        rm -f -- "$temp_file"

        log_message "ERROR" \
            "Unable to apply SSH configuration"

        return 1

    fi

    record_fix \
        "Global SSH root login configuration disabled" \
        "PermitRootLogin set to no"

    warn_check "SSH service reload required" \
        "Verify alternative administrator access before reloading SSH"

    warn_check "SSH Match rules require manual review" \
        "Verify connection-specific root login restrictions"

    return 0
}


# ==================================================
# Automatic Remediation Controller
# ==================================================

run_remediation() {

    local check="$1"
    local remediation_failed=false

    if [[ "${REMEDIATE:-false}" != true ]]; then
        return 0
    fi

    if ! remediation_allowed; then

        log_message "ERROR" \
            "Remediation authorization failed"

        return 1

    fi

    print_section "Automatic Remediation: $check"

    case "$check" in

        ssh)

            if [[ "${FIX_ROOT_SSH:-false}" == true ]]; then

                fix_ssh_root_login ||
                    remediation_failed=true

            fi

            ;;

        password)

            if [[ "${FIX_PASSWORD_POLICY:-false}" == true ]]; then

                fix_password_policy ||
                    remediation_failed=true

            fi

            ;;

        permissions)

            if [[ "${FIX_FILE_PERMISSIONS:-false}" == true ]]; then

                fix_file_permission \
                    "/etc/passwd" "$PASSWD_PERMISSION" ||
                    remediation_failed=true

                fix_file_permission \
                    "/etc/shadow" "$SHADOW_PERMISSION" ||
                    remediation_failed=true

                fix_file_permission \
                    "/etc/group" "$GROUP_PERMISSION" ||
                    remediation_failed=true

            fi

            ;;

        network|accounts|firewall|updates|services)

            log_message "INFO" \
                "Automatic remediation not supported for $check" \
                "Review audit recommendations manually"

            ;;

        *)

            log_message "WARNING" \
                "Unknown remediation module: $check"

            return 1

            ;;

    esac

    if [[ "$remediation_failed" == true ]]; then

        log_message "WARNING" \
            "One or more remediation actions were unsuccessful" \
            "Review audit logs and backup files"

        return 1

    fi

    return 0
}
