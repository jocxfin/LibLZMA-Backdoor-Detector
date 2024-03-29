#!/bin/bash

set -uo pipefail

# compromised versions and conditions
COMPROMISED_VERSIONS=("5.6.0" "5.6.1")
TARGET_ARCH="x86_64-linux-gnu"
DEBIAN_RULES_PATH="debian/rules"
RPM_ARCH="x86_64"
UNUSUAL_ENV_VARS=("LD_DEBUG" "LD_PROFILE")
REQUIRED_ENV_VARS=("LANG")

# keep track of test results
declare -A TEST_RESULTS=(
    ["version_check"]="not run"
    ["ssh_delay"]="not run"
    ["env_conditions"]="not run"
    ["function_signature"]="not run"
)

# update test result and print detailed explanation
update_result() {
    TEST_RESULTS[$1]=$2
    echo "$1: $2"

    # explanation based on the test
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

    # result explanation
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
    echo "" 
}

# check if liblzma version is compromised
is_compromised_version() {
    local version=$1
    for v in "${COMPROMISED_VERSIONS[@]}"; do
        if [[ "$version" == "$v" ]]; then
            update_result "version_check" "compromised"
            return 0
        fi
    done
    update_result "version_check" "not compromised"
    return 1
}

# detect unusual ssh response delays
detect_ssh_delays() {
    local start=$(date +%s%N)

    echo -e "QUIT" | nc -w 2 localhost 22 > /dev/null 2>&1
    local end=$(date +%s%N)
    local delay=$(( (end - start) / 1000000 )) 
    if [ "$delay" -gt 500 ]; then 
        update_result "ssh_delay" "detected"
        return 0
    else
        update_result "ssh_delay" "not detected"
        return 1
    fi
}


# check for specific environment conditions
check_env_conditions() {
    for var in "${UNUSUAL_ENV_VARS[@]}"; do
        if [ -n "${!var-}" ]; then
            update_result "env_conditions" "unusual variable detected"
            return 1
        fi
    done

    for var in "${REQUIRED_ENV_VARS[@]}"; do
        if [ -z "${!var-}" ]; then
            update_result "env_conditions" "required variable missing"
            return 1
        fi
    done

    update_result "env_conditions" "conditions met"
    return 0
}

# check for function signature
check_function_signature() {
    local path
    path="$(ldd $(which sshd) | grep liblzma | grep -o '/[^ ]*')"
    if [ -z "$path" ]; then
        update_result "function_signature" "liblzma not used by sshd"
        return 1
    fi

    if hexdump -ve '1/1 "%.2x"' "$path" | grep -q f30f1efa554889f54c89ce5389fb81e7000000804883ec28488954241848894c2410; then
        update_result "function_signature" "vulnerable"
        return 0
    else
        update_result "function_signature" "not vulnerable"
        return 1
    fi
}

# main logic
echo "Starting detection of xz/liblzma backdoor vulnerability..."
echo ""

xz_version=$(xz --version | head -n1 | awk '{print $4}')
is_compromised_version "$xz_version"
detect_ssh_delays
check_env_conditions
check_function_signature

# display results
echo "Detection results:"
for test in "${!TEST_RESULTS[@]}"; do
    echo "$test: ${TEST_RESULTS[$test]}"
done
