#!/usr/bin/env bash

# ==================================================
# File Permission Security Module
# ==================================================

# Check permissions of a sensitive file
check_sensitive_file() {

    local file="$1"
    local expected="$2"
    local actual

    if [[ ! -f "$file" ]]; then
        skip_check "Sensitive file not found: $file" \
            "Verify file availability"
        return 0
    fi

    if ! actual=$(stat -c '%a' -- "$file" 2>/dev/null); then
        skip_check "Cannot read permissions: $file" \
            "Review access permissions"
        return 0
    fi

    if [[ "$actual" == "$expected" ]]; then

        pass_check "$file has correct permissions: $actual"

    else

        fail_check "HIGH" \
            "$file permissions are $actual; policy requires $expected" \
            "Review and set approved permissions to $expected"

    fi

    return 0
}

# Main permission security check
check_permissions() {

    local scan_path
    local file
    local count=0
    local scan_status=0
    local scan_file
    local -a scan_paths

    # ------------------------------------------
    # Check 1: Sensitive System Files
    # ------------------------------------------

    print_section "Sensitive File Permissions"

    check_sensitive_file "/etc/passwd" "$PASSWD_PERMISSION"

    check_sensitive_file "/etc/shadow" "$SHADOW_PERMISSION"

    check_sensitive_file "/etc/group" "$GROUP_PERMISSION"

    # ------------------------------------------
    # Check 2: World-Writable Files
    # ------------------------------------------

    print_section "World-Writable File Detection"

    read -r -a scan_paths <<< "$WORLD_WRITABLE_SCAN_PATHS"

    if [[ ! "$MAX_WORLD_WRITABLE_RESULTS" =~ ^[1-9][0-9]*$ ]]; then
        skip_check "Invalid world-writable result limit" \
            "Correct MAX_WORLD_WRITABLE_RESULTS"
        return 0
    fi

    scan_file=$(mktemp) || return 1

    for scan_path in "${scan_paths[@]}"; do

        if [[ ! -d "$scan_path" ]]; then
            log_message "INFO" \
                "Scan directory not found: $scan_path"
            continue
        fi

        log_message "INFO" \
            "Scanning directory: $scan_path"

        # Scan regular files without crossing filesystems
        if ! find "$scan_path" -xdev -type f \
            -perm -0002 -print0 >> "$scan_file" 2>/dev/null; then

            scan_status=1

            warn_check "Incomplete scan of $scan_path" \
                "Some files or directories could not be accessed"

        fi

    done

    # Process detected files safely
    while IFS= read -r -d '' file; do

        count=$((count + 1))

        if (( count <= MAX_WORLD_WRITABLE_RESULTS )); then

            fail_check "HIGH" \
                "World-writable file detected: $file" \
                "Review file ownership and remove unnecessary other-write permission"

        fi

    done < "$scan_file"

    rm -f -- "$scan_file"

    # Display scan results
    if (( count == 0 && scan_status == 0 )); then

        pass_check "No world-writable files found in scanned directories"

    elif (( count == 0 )); then

        skip_check "World-writable scan incomplete" \
            "Repeat with appropriate access permissions"

    else

        log_message "INFO" \
            "Total world-writable files detected: $count"

    fi

    if (( count > MAX_WORLD_WRITABLE_RESULTS )); then

        warn_check "World-writable result limit exceeded" \
            "Increase MAX_WORLD_WRITABLE_RESULTS for detailed reporting"

    fi

    return 0
}
