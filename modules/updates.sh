#!/usr/bin/env bash

# ==================================================
# System Update Security Module
# ==================================================

check_updates() {

    local update_output
    local update_count=0
    local package_manager
    local status

    # Check whether update auditing is enabled
    if [[ "$CHECK_UPDATES" != true ]]; then

        skip_check "System update check disabled by policy"
        return 0

    fi

    # ------------------------------------------
    # Ubuntu / Debian
    # ------------------------------------------

    if command_exists apt; then

        package_manager="APT"

        log_message "INFO" "APT package manager detected"

        if ! update_output=$(LC_ALL=C apt list --upgradable 2>/dev/null); then

            skip_check "Unable to retrieve available updates" \
                "Review APT package manager"

            return 0

        fi

        update_count=$(awk '
            /\[upgradable from:/ {count++}
            END {print count+0}
        ' <<< "$update_output")

    # ------------------------------------------
    # CentOS / RHEL / Fedora
    # ------------------------------------------

    elif command_exists dnf || command_exists yum; then

        if command_exists dnf; then
            package_manager="dnf"
        else
            package_manager="yum"
        fi

        log_message "INFO" "$package_manager package manager detected"

        status=0

        update_output=$(LC_ALL=C "$package_manager" -q check-update 2>/dev/null) ||
            status=$?

        # Exit code 100 indicates updates are available
        if [[ "$status" -ne 0 && "$status" -ne 100 ]]; then

            skip_check "Unable to retrieve available updates" \
                "Review package manager configuration"

            return 0

        fi

        update_count=$(awk '
            NF == 3 && $1 ~ /\.(x86_64|noarch|aarch64|i686|i386|ppc64le|s390x)$/ {
                count++
            }
            END {print count+0}
        ' <<< "$update_output")

        if [[ "$status" -eq 100 && "$update_count" -eq 0 ]]; then

            skip_check "Updates available but package count could not be determined" \
                "Review package manager output manually"

            return 0

        fi

    else

        skip_check "No supported package manager detected" \
            "Review system update status manually"

        return 0

    fi

    # ------------------------------------------
    # Evaluate update security policy
    # ------------------------------------------

    log_message "INFO" \
        "Pending package updates: $update_count"

    if (( update_count == 0 )); then

        pass_check "No pending package updates detected"

    elif (( update_count > MAX_PENDING_UPDATES )); then

        fail_check "MEDIUM" \
            "$update_count pending updates exceed policy threshold of $MAX_PENDING_UPDATES" \
            "Review and install approved package updates"

    else

        fail_check "LOW" \
            "$update_count pending package updates detected" \
            "Schedule package updates during maintenance"

    fi

    warn_check "Update results depend on package repository metadata" \
        "Refresh package information and review security advisories"

    return 0
}
