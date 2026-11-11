#!/bin/bash

# CS4254 Project: DNS Client Testing Script
# This script compares your client's packet construction and parsed output
# against the pre-compiled reference solution.

SERVER_IP="172.21.222.45"
PORT="53"
CLIENT="./simplednsClient"
REF_CLIENT="/home/courses/cs4254/share-bin/ref_simplednsClient"

make clean > /dev/null
make > /dev/null

if [ ! -f "$CLIENT" ]; then
    echo "Compilation failed. $CLIENT not found."
    exit 1
fi

if [ ! -x "$REF_CLIENT" ]; then
    echo "Error: Reference binary $REF_CLIENT not found or not executable."
    echo "Please ensure the reference solution is accessible."
    exit 1
fi

run_test() {
    local query=$1
    local test_name=$2

    echo "Testing $test_name ($query) ... "
    
    # Capture the full output
    expected_full=$(timeout 8s $REF_CLIENT @$SERVER_IP:$PORT $query 2>/dev/null)
    actual_full=$(timeout 8s $CLIENT @$SERVER_IP:$PORT $query 2>/dev/null)
    client_status=$?

    if [ $client_status -eq 124 ]; then
        echo "  [FAIL] Program forcefully killed after 8 seconds (Timeout/Infinite loop)."
        return
    fi

    # 1. Isolate and Compare the Hex Dump (Lines starting with '[')
    expected_dump=$(echo "$expected_full" | grep "^\[")
    actual_dump=$(echo "$actual_full" | grep "^\[")
    
    dump_pass=1
    if [ "$expected_dump" != "$actual_dump" ]; then
        echo "  [FAIL - Query Packet (dump_packet) Mismatch]"
        echo "    Expected Query Dump:"
        echo "$expected_dump"
        echo "    Actual Query Dump:"
        echo "$actual_dump"
        dump_pass=0
    fi

    # 2. Isolate, SORT, and Compare the Parsed Answers (Lines NOT starting with '[')
    # Sorting neutralizes DNS round-robin ordering issues
    expected_ans=$(echo "$expected_full" | grep -v "^\[" | sed '/^\s*$/d' | sort)
    actual_ans=$(echo "$actual_full" | grep -v "^\[" | sed '/^\s*$/d' | sort)

    ans_pass=1
    
    # Flexible Error String Checking:
    # If the expected output contains an ERROR line, we just check if the actual output also threw an ERROR.
    if echo "$expected_ans" | grep -q "^ERROR"; then
        if ! echo "$actual_ans" | grep -q "^ERROR"; then
            ans_pass=0
            echo "  [FAIL - Parsed Output Mismatch]"
            echo "    Expected an ERROR message."
            echo "    Actual Output:"
            echo "$actual_ans"
        fi
    elif [ "$expected_ans" != "$actual_ans" ]; then
        ans_pass=0
        echo "  [FAIL - Parsed Output Mismatch]"
        echo "    Expected Output:"
        echo "$expected_ans"
        echo "    Actual Output:"
        echo "$actual_ans"
    fi

    if [ $dump_pass -eq 1 ] && [ $ans_pass -eq 1 ]; then
        echo "  [PASS]"
    fi
    echo ""
}

echo "--- Running CS4254 DNS Tests ---"
echo ""

# --- Standard Resolutions ---
run_test "google.com" "Standard External Resolution (Google)"
run_test "www.cnn.com" "Standard External Resolution (CNN)"
run_test "vt.edu" "Standard External Resolution (VT)"
run_test "amazon.com" "Standard External Resolution (Amazon)"

# --- Edge Cases & Protocol Specs ---
run_test "missing.cs4254" "NXDOMAIN Handling (Missing Record)"
run_test "multi.cs4254" "Multiple Answers Handling"
run_test "alias.cs4254" "CNAME Identification & Extraction"
run_test "error.cs4254" "Server Error Handling (e.g., SERVFAIL/REFUSED)"

# --- Timeout Enforcement ---
echo -n "Testing 5-Second Timeout (Blackhole IP) ... "

expected_full=$(timeout 8s $REF_CLIENT @192.0.2.1:$PORT google.com 2>/dev/null)
expected_ans=$(echo "$expected_full" | grep -v "^\[" | sed '/^\s*$/d' | sort)

time_start=$(date +%s)
actual_full=$(timeout 8s $CLIENT @192.0.2.1:$PORT google.com 2>/dev/null)
client_status=$?
time_end=$(date +%s)
time_diff=$((time_end - time_start))

actual_ans=$(echo "$actual_full" | grep -v "^\[" | sed '/^\s*$/d' | sort)

if [ $client_status -eq 124 ]; then
    echo "[FAIL - Program forcefully killed. Did not honor 5-second socket timeout.]"
elif [ "$actual_ans" == "$expected_ans" ]; then
    if [ $time_diff -ge 4 ] && [ $time_diff -le 6 ]; then
        echo "[PASS]"
    else
        echo "[FAIL - Output matched, but wrong timeout duration: $time_diff seconds]"
    fi
else
    echo "[FAIL]"
    echo "  Expected output:"
    echo "$expected_ans"
    echo "  Actual output:"
    echo "$actual_ans"
fi