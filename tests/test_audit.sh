#!/usr/bin/env bash

# ==================================================
# Security Audit Suite - Automated Tests
# ==================================================

set -uo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$BASE_DIR" || exit 1

TOTAL=0
PASSED=0
FAILED=0

# Test result functions
pass_test() {
    PASSED=$((PASSED + 1))
    echo "[PASS] $1"
}

fail_test() {
    FAILED=$((FAILED + 1))
    echo "[FAIL] $1"
}

run_test() {

    local name="$1"
    shift

    TOTAL=$((TOTAL + 1))

    if "$@" >/dev/null 2>&1; then
        pass_test "$name"
    else
        fail_test "$name"
    fi
}

# Prevent privileged execution
if (( EUID == 0 )); then
    echo "Error: Run these tests without sudo."
    exit 1
fi

echo "=========================================="
echo "     SECURITY AUDIT AUTOMATED TESTS"
echo "=========================================="

# Test Bash syntax
for file in audit.sh rollback.sh modules/*.sh; do

    run_test "Syntax: $file" bash -n "$file"

done

# Test required files
run_test "Policy configuration exists" \
    test -f config/policy.conf

run_test "README exists" \
    test -f README.md

# Test command-line options
run_test "Audit help command" \
    bash audit.sh --help

run_test "Rollback help command" \
    bash rollback.sh --help

# Test scan profiles
run_test "Quick profile" \
    bash audit.sh --profile quick

run_test "Full profile" \
    bash audit.sh --profile full

run_test "Network profile" \
    bash audit.sh --profile network

run_test "Filesystem profile" \
    bash audit.sh --profile filesystem

run_test "Custom profile" \
    bash audit.sh --checks password,permissions

# Test invalid profile rejection
TOTAL=$((TOTAL + 1))

if bash audit.sh --profile invalid >/dev/null 2>&1; then
    fail_test "Invalid profile rejection"
else
    pass_test "Invalid profile rejection"
fi

# Test unauthorized remediation rejection
TOTAL=$((TOTAL + 1))

if bash audit.sh --profile quick --remediate \
    >/dev/null 2>&1; then

    fail_test "Unauthorized remediation rejection"

else

    pass_test "Unauthorized remediation rejection"

fi

# Test unauthorized rollback rejection
TOTAL=$((TOTAL + 1))

if bash rollback.sh --list >/dev/null 2>&1; then
    fail_test "Unauthorized rollback rejection"
else
    pass_test "Unauthorized rollback rejection"
fi

# Display final summary
echo "=========================================="
echo "             TEST SUMMARY"
echo "=========================================="
echo "Total Tests  : $TOTAL"
echo "Passed Tests : $PASSED"
echo "Failed Tests : $FAILED"
echo "=========================================="

if (( FAILED > 0 )); then
    exit 1
fi

echo "All automated tests passed successfully."
exit 0
