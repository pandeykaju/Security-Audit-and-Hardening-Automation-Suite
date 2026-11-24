#!/usr/bin/env bash

# ==================================================
# Password Policy Security Module
# ==================================================

check_password() {

    local login_defs="/etc/login.defs"
    local pwquality_config="/etc/security/pwquality.conf"
    local max_days
    local min_days
    local warn_age
    local min_length

    # Check configuration availability
    if [[ ! -r "$login_defs" ]]; then
        skip_check "Cannot read password policy configuration" \
            "Verify /etc/login.defs"
        return 0
    fi

    # Read password policy settings
    max_days=$(awk '$1 == "PASS_MAX_DAYS" {print $2}' "$login_defs" | tail -n 1)

    min_days=$(awk '$1 == "PASS_MIN_DAYS" {print $2}' "$login_defs" | tail -n 1)

    warn_age=$(awk '$1 == "PASS_WARN_AGE" {print $2}' "$login_defs" | tail -n 1)

    # ------------------------------------------
    # Check maximum password age
    # ------------------------------------------

    if [[ "$max_days" =~ ^[0-9]+$ ]] &&
       (( max_days > 0 && max_days <= PASS_MAX_DAYS )); then

        pass_check "Maximum password age: $max_days days"

    else

        fail_check "HIGH" \
            "Maximum password age: ${max_days:-Not configured}" \
            "Set PASS_MAX_DAYS to $PASS_MAX_DAYS"

    fi

    # ------------------------------------------
    # Check minimum password age
    # ------------------------------------------

    if [[ "$min_days" =~ ^[0-9]+$ ]] &&
       (( min_days >= PASS_MIN_DAYS )); then

        pass_check "Minimum password age: $min_days days"

    else

        fail_check "MEDIUM" \
            "Minimum password age: ${min_days:-Not configured}" \
            "Set PASS_MIN_DAYS to $PASS_MIN_DAYS"

    fi

    # ------------------------------------------
    # Check password expiration warning
    # ------------------------------------------

    if [[ "$warn_age" =~ ^[0-9]+$ ]] &&
       (( warn_age >= PASS_WARN_AGE )); then

        pass_check "Password warning period: $warn_age days"

    else

        fail_check "MEDIUM" \
            "Password warning period: ${warn_age:-Not configured}" \
            "Set PASS_WARN_AGE to $PASS_WARN_AGE"

    fi

    # ------------------------------------------
    # Check password quality configuration
    # ------------------------------------------

    if [[ ! -r "$pwquality_config" ]]; then

        skip_check "Password quality configuration not available" \
            "Review libpam-pwquality installation"

        return 0

    fi

    min_length=$(awk -F= '
        /^[[:space:]]*minlen[[:space:]]*=/ {
            sub(/#.*/, "", $2)
            gsub(/[[:space:]]/, "", $2)
            print $2
        }
    ' "$pwquality_config" | tail -n 1)

    # ------------------------------------------
    # Check minimum password length
    # ------------------------------------------

    if [[ "$min_length" =~ ^[0-9]+$ ]] &&
       (( min_length >= PASS_MIN_LEN )); then

        pass_check "Configured password minimum length: $min_length"

    else

        fail_check "HIGH" \
            "Password minimum length: ${min_length:-Not explicitly configured}" \
            "Configure minlen = $PASS_MIN_LEN"

    fi

    warn_check "Password quality enforcement requires PAM verification" \
        "Review PAM settings and pwquality configuration overrides"

    return 0
}
