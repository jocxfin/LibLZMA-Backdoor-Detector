#!/bin/bash

set -uo pipefail

# Define compromised versions and conditions
COMPROMISED_VERSIONS=("5.6.0" "5.6.1")
UNUSUAL_ENV_VARS=("LD_DEBUG" "LD_PROFILE")
REQUIRED_ENV_VARS=("LANG")

# Array to keep track of test results
declare -A TEST_RESULTS=(
    ["version_check"]="not run"
    ["ssh_delay"]="not run"
    ["env_conditions"]="not run"
    ["function_signature"]="not run"
)

# Function to update test result and print detailed explanation
update_result() {
    TEST_RESULTS[$1]=$2
    echo "$1: $2"

    # Print a detailed explanation based on the test
    case $1 in
        version_check)
            echo "Checking if the installed liblzma version is known to be compromised."
            ;;
        ssh_delay)
            echo "Detecting if there is an unusual delay in SSH response, which might indicate a vulnerability."
            ;;
        env_conditions)
            echo "Verifying environment conditions that might be exploited by the backdoor."
            ;;
        function_signature)
            echo "Searching for specific function signatures in liblzma that indicate a compromise."
            ;;
    esac

    # Print the result explanation
    case $2 in
        compromised|vulnerable)
            echo "Warning: Your system might be vulnerable."
            ;;
        "not compromised"|"not vulnerable"|"conditions met")
            echo "Your system appears to be safe from this specific vulnerability."
            ;;
        "unusual variable detected"|"required variable missing")
            echo "Potential security risk detected in the environment setup."
            ;;
        *)
            echo "Test result: $2"
            ;;
    esac
    echo "" # For better readability
}

# Check if liblzma version is compromised
is_compromised_version() {
    local version
    version=$(xz --version | head -n1 | awk '{print $4}' 2>/dev/null || echo "not found")
    if [[ " ${COMPROMISED_VERSIONS[*]} " =~ " ${version} " ]]; then
        update_result "version_check" "compromised version detected: $version"
    else
        update_result "version_check" "liblzma version $version is not known to be compromised or xz is not installed"
    fi
}

# Detect unusual ssh response delays
detect_ssh_delays() {
    local start=$(date +%s%N)
    echo -e "QUIT" | nc -w 2 localhost 22 > /dev/null 2>&1
    local end=$(date +%s%N)
    local delay=$(( (end - start) / 1000000 ))
    if [ "$delay" -gt 500 ]; then
        update_result "ssh_delay" "detected"
    else
        update_result "ssh_delay" "not detected"
    fi
}

# Check for specific environment conditions
check_env_conditions() {
    for var in "${UNUSUAL_ENV_VARS[@]}"; do
        if [ -n "${!var-}" ]; then
            update_result "env_conditions" "unusual variable detected"
            return
        fi
    done

    for var in "${REQUIRED_ENV_VARS[@]}"; do
        if [ -z "${!var-}" ]; then
            update_result "env_conditions" "required variable missing"
            return
        fi
    done

    update_result "env_conditions" "conditions met"
}

# Check for function signature
check_function_signature() {
    local sshd_path
    sshd_path=$(which sshd 2>/dev/null)
    if [ -z "$sshd_path" ]; then
        update_result "function_signature" "liblzma not used by sshd or sshd not found"
        return
    fi

    local liblzma_path
    liblzma_path="$(ldd $sshd_path | grep liblzma | grep -o '/[^ ]*' || echo "")"
    if [ -z "$liblzma_path" ]; then
        update_result "function_signature" "liblzma not used by sshd or sshd not found"
    else
        if hexdump -ve '1/1 "%.2x"' "$liblzma_path" | grep -q f30f1efa554889f54c89ce5389fb81e7000000804883ec28488954241848894c2410; then
            update_result "function_signature" "vulnerable"
        else
            update_result "function_signature" "not vulnerable"
        fi
    fi
}

# Main logic
echo "Starting detection of xz/liblzma backdoor vulnerability..."
echo ""

is_compromised_version
detect_ssh_delays
check_env_conditions
check_function_signature

# Display results
echo "Detection results:"
for test in "${!TEST_RESULTS[@]}"; do
    echo "$test: ${TEST_RESULTS[$test]}"
done
