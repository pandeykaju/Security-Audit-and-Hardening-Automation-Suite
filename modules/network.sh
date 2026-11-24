#!/usr/bin/env bash

# ==================================================
# Network Security Audit Module
# ==================================================

check_network() {

    local listening_ports
    local protocol
    local address
    local port
    local allowed
    local found=0
    local -a allowed_ports

    # Check command availability
    if ! command_exists ss; then
        skip_check "Network scanning command unavailable" \
            "Install iproute2"
        return 0
    fi

    # Load allowed ports from configuration
    IFS=',' read -r -a allowed_ports <<< "$ALLOWED_PORTS"

    log_message "INFO" \
        "Allowed network ports: $ALLOWED_PORTS"

    # Detect listening TCP and UDP sockets
    if ! listening_ports=$(ss -H -lntu 2>/dev/null); then
        skip_check "Unable to scan listening ports" \
            "Review network permissions"
        return 0
    fi

    if [[ -z "$listening_ports" ]]; then
        pass_check "No listening TCP or UDP ports detected"
        return 0
    fi

    # Analyze listening sockets
    while read -r protocol address; do

        [[ -z "$address" ]] && continue

        port="${address##*:}"

        if [[ ! "$port" =~ ^[0-9]+$ ]]; then
            continue
        fi

        found=$((found + 1))
        allowed=false

        # Compare against approved ports
        for approved_port in "${allowed_ports[@]}"; do

            if [[ "$port" == "$approved_port" ]]; then
                allowed=true
                break
            fi

        done

        # Evaluate port security
        if [[ "$allowed" == true ]]; then

            pass_check \
                "Approved port: $port ($protocol) Address: $address"

        elif [[ "$address" == 127.* ||
                "$address" == "[::1]:"* ]]; then

            fail_check "LOW" \
                "Unapproved local port: $port ($protocol) Address: $address" \
                "Review the local service using this port"

        else

            fail_check "MEDIUM" \
                "Unapproved listening port: $port ($protocol) Address: $address" \
                "Identify the service and restrict access if unnecessary"

        fi

    done < <(
        awk '{print $1, $5}' <<< "$listening_ports" |
            sort -u
    )

    log_message "INFO" \
        "Total listening endpoints analyzed: $found"

    if (( found == 0 )); then
        warn_check "No valid listening endpoints parsed" \
            "Review ss command output manually"
    fi

    return 0
}
