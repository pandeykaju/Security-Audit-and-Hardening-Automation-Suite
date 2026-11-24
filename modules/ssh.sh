#!/usr/bin/env bash

# ==================================================
# SSH Security Audit Module
# ==================================================

check_ssh() {

    local ssh_config="/etc/ssh/sshd_config"
    local effective_config
    local root_login
    local password_auth

    # Check whether SSH server is installed
    if [[ ! -f "$ssh_config" ]]; then
        skip_check "SSH server configuration not found" \
            "SSH server may not be installed"
        return 0
    fi

    # Check SSH command availability
    if ! command_exists sshd; then
        skip_check "SSH server command not available" \
            "Verify OpenSSH server installation"
        return 0
    fi

    # Read effective SSH configuration
    if ! effective_config=$(sshd -T 2>/dev/null); then
        skip_check "Unable to read effective SSH configuration" \
            "Administrator review required"
        return 0
    fi

    # ------------------------------------------
    # Check 1: Root SSH Login
    # ------------------------------------------

    root_login=$(awk '$1 == "permitrootlogin" {print $2; exit}' \
        <<< "$effective_config")

    if [[ -z "$root_login" ]]; then

        skip_check "Unable to determine root SSH login policy" \
            "Review SSH configuration manually"

    elif [[ "$root_login" == "$PERMIT_ROOT_LOGIN" ]]; then

        pass_check "Root SSH login matches security policy"

    else

        fail_check "HIGH" \
            "Root SSH login policy is insecure: $root_login" \
            "Set PermitRootLogin to $PERMIT_ROOT_LOGIN"

    fi

    # ------------------------------------------
    # Check 2: SSH Password Authentication
    # ------------------------------------------

    password_auth=$(awk '$1 == "passwordauthentication" {print $2; exit}' \
        <<< "$effective_config")

    if [[ -z "$password_auth" ]]; then

        skip_check "Unable to determine SSH authentication policy" \
            "Review SSH configuration manually"

    elif [[ "$password_auth" == "$PASSWORD_AUTHENTICATION" ]]; then

        pass_check "SSH password authentication matches security policy"

    else

        fail_check "HIGH" \
            "SSH password authentication policy: $password_auth" \
            "Verify SSH key access before disabling password authentication"

    fi

    return 0
}
