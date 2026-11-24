#!/usr/bin/env bash

# ==================================================
# User Account Security Module
# ==================================================

check_accounts() {

    local empty_accounts
    local uid_zero_accounts
    local duplicate_uids
    local account
    local uid

    # ------------------------------------------
    # Check 1: Empty Password Accounts
    # ------------------------------------------

    print_section "Empty Password Accounts"

    if [[ ! -r /etc/shadow ]]; then

        skip_check "Cannot read /etc/shadow" \
            "Administrator privileges required"

    elif ! empty_accounts=$(awk -F: '$2 == "" {print $1}' /etc/shadow); then

        skip_check "Unable to inspect password records" \
            "Review account database manually"

    elif [[ -z "$empty_accounts" ]]; then

        pass_check "No empty password accounts detected"

    else

        while IFS= read -r account; do

            [[ -z "$account" ]] && continue

            fail_check "CRITICAL" \
                "Empty password detected for account: $account" \
                "Review account and configure a secure password or lock it"

        done <<< "$empty_accounts"

    fi

    # ------------------------------------------
    # Check 2: Unauthorized UID 0 Accounts
    # ------------------------------------------

    print_section "Root Privilege Accounts"

    if [[ ! -r /etc/passwd ]]; then

        skip_check "Cannot read /etc/passwd" \
            "Review account database permissions"

        return 0

    fi

    if ! uid_zero_accounts=$(awk -F: '
        $3 == 0 && $1 != "root" {print $1}
    ' /etc/passwd); then

        skip_check "Unable to inspect UID 0 accounts" \
            "Review account database manually"

    elif [[ -z "$uid_zero_accounts" ]]; then

        pass_check "No additional UID 0 accounts detected"

    else

        while IFS= read -r account; do

            [[ -z "$account" ]] && continue

            fail_check "CRITICAL" \
                "Additional root privilege account: $account" \
                "Investigate account and remove unauthorized root privileges"

        done <<< "$uid_zero_accounts"

    fi

    # ------------------------------------------
    # Check 3: Duplicate User IDs
    # ------------------------------------------

    print_section "Duplicate User IDs"

    if ! duplicate_uids=$(cut -d: -f3 /etc/passwd |
        sort | uniq -d); then

        skip_check "Unable to inspect duplicate user IDs" \
            "Review account database manually"

    elif [[ -z "$duplicate_uids" ]]; then

        pass_check "No duplicate user IDs detected"

    else

        while IFS= read -r uid; do

            [[ -z "$uid" ]] && continue

            fail_check "HIGH" \
                "Duplicate user ID detected: $uid" \
                "Review accounts sharing this UID"

        done <<< "$duplicate_uids"

    fi

    return 0
}
