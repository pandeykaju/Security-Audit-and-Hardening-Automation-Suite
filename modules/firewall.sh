#!/usr/bin/env bash

# ==================================================
# Firewall Security Audit Module
# ==================================================

check_firewall() {

    local firewall_status
    local firewall_detected=false
    local firewall_active=false
    local status_unknown=false

    # Check whether firewall auditing is required
    if [[ "$FIREWALL_REQUIRED" != true ]]; then
        skip_check "Firewall check disabled by policy"
        return 0
    fi

    # ------------------------------------------
    # Check UFW Firewall
    # ------------------------------------------

    if command_exists ufw; then

        firewall_detected=true

        log_message "INFO" "UFW firewall detected"

        if firewall_status=$(LC_ALL=C ufw status 2>/dev/null); then

            if grep -q '^Status: active' <<< "$firewall_status"; then

                firewall_active=true
                pass_check "UFW firewall is active"

            else

                log_message "INFO" "UFW firewall is inactive"

            fi

        else

            status_unknown=true

            warn_check "Unable to determine UFW status" \
                "Administrator privileges may be required"

        fi

    fi

    # ------------------------------------------
    # Check Firewalld
    # ------------------------------------------

    if command_exists firewall-cmd; then

        firewall_detected=true

        log_message "INFO" "Firewalld detected"

        if firewall_status=$(firewall-cmd --state 2>/dev/null); then

            if [[ "$firewall_status" == "running" ]]; then

                firewall_active=true
                pass_check "Firewalld is running"

            else

                log_message "INFO" "Firewalld is not running"

            fi

        else

            status_unknown=true

            warn_check "Unable to confirm Firewalld status" \
                "Review firewall service manually"

        fi

    fi

    # ------------------------------------------
    # Check nftables
    # ------------------------------------------

    if command_exists nft && [[ "$firewall_active" == false ]]; then

        firewall_detected=true

        log_message "INFO" "nftables detected"

        if firewall_status=$(nft list ruleset 2>/dev/null); then

            if [[ -n "$firewall_status" ]]; then

                status_unknown=true

                warn_check "nftables rules are present" \
                    "Review filtering chains and default policies"

            else

                log_message "INFO" "nftables ruleset is empty"

            fi

        else

            status_unknown=true

            warn_check "Unable to inspect nftables rules" \
                "Administrator privileges may be required"

        fi

    fi

    # ------------------------------------------
    # Evaluate overall firewall status
    # ------------------------------------------

    if [[ "$firewall_active" == true ]]; then

        log_message "INFO" \
            "An active firewall manager was detected"

    elif [[ "$status_unknown" == true ]]; then

        skip_check "Firewall protection could not be confirmed" \
            "Verify firewall status and filtering rules manually"

    elif [[ "$firewall_detected" == false ]]; then

        fail_check "HIGH" \
            "No supported firewall management tool detected" \
            "Review host firewall protection and install an appropriate firewall if required"

    else

        fail_check "HIGH" \
            "No active firewall detected by supported tools" \
            "Configure and enable an appropriate firewall"

    fi

    return 0
}
