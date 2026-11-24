#!/usr/bin/env bash

# ==================================================
# Unnecessary Service Detection Module
# ==================================================

check_services() {

    local service
    local active_status
    local enabled_status
    local load_status
    local -a services

    # Check systemctl availability
    if ! command_exists systemctl; then

        skip_check "systemctl command unavailable" \
            "Review running services manually"

        return 0

    fi

    # Verify systemd availability
    if [[ ! -d /run/systemd/system ]]; then

        skip_check "Systemd is not running" \
            "Review service management environment"

        return 0

    fi

    # Verify communication with systemd
    if ! systemctl list-units --no-pager >/dev/null 2>&1; then

        skip_check "Unable to communicate with systemd" \
            "Review system service manager"

        return 0

    fi

    # Load unnecessary services from policy
    read -r -a services <<< "$UNNECESSARY_SERVICES"

    if (( ${#services[@]} == 0 )); then

        skip_check "No unnecessary services defined" \
            "Configure UNNECESSARY_SERVICES in policy.conf"

        return 0

    fi

    log_message "INFO" \
        "Services selected for auditing: $UNNECESSARY_SERVICES"

    # Inspect each configured service
    for service in "${services[@]}"; do

        if [[ ! "$service" =~ ^[a-zA-Z0-9_.@-]+$ ||
              "$service" == -* ]]; then

            warn_check "Invalid service name: $service" \
                "Review service policy configuration"

            continue

        fi

        if ! load_status=$(systemctl show \
            --property=LoadState --value \
            "$service.service" 2>/dev/null); then

            skip_check "Unable to inspect service: $service" \
                "Review service status manually"

            continue

        fi

        # Check whether service is installed
        if [[ "$load_status" == "not-found" ]]; then

            pass_check "Unnecessary service not installed: $service"

            continue

        elif [[ "$load_status" != "loaded" &&
                "$load_status" != "masked" ]]; then

            skip_check "Unknown load state for $service: $load_status" \
                "Inspect service configuration manually"

            continue

        fi

        # Check running and startup status
        active_status=$(systemctl is-active \
            "$service.service" 2>/dev/null) || true

        enabled_status=$(systemctl is-enabled \
            "$service.service" 2>/dev/null) || true

        # Evaluate running service
        if [[ "$active_status" == "active" ||
              "$active_status" == "activating" ||
              "$active_status" == "reloading" ]]; then

            fail_check "HIGH" \
                "Unnecessary service is running: $service" \
                "Review service requirements before stopping it"

        elif [[ "$enabled_status" == "enabled" ||
                "$enabled_status" == "enabled-runtime" ]]; then

            fail_check "MEDIUM" \
                "Unnecessary service enabled at startup: $service" \
                "Review and disable service if unnecessary"

        elif [[ "$active_status" == "inactive" ||
                "$active_status" == "failed" ]]; then

            pass_check "Service not running or explicitly enabled: $service"

        else

            skip_check "Unable to confirm service status: $service" \
                "Inspect service manually"

        fi

    done

    warn_check "Service audit covers configured service units only" \
        "Review socket activation and other installed services"

    return 0
}
