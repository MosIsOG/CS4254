#!/bin/bash

cd "$(dirname "$0")/.." || exit 1
make > /dev/null || exit 1

CLIENT=${CLIENT:-./simplednsClient}
SERVER=tests/fake_dns_server.py
pass=0
fail=0

run_case() {
    local mode=$1
    local expected=$2
    local fifo
    fifo=$(mktemp -u)
    mkfifo "$fifo"
    python3 "$SERVER" "$mode" > "$fifo" &
    local server_pid=$!
    local port
    read -r port < "$fifo"
    rm -f "$fifo"

    local actual
    actual=$(timeout 8s "$CLIENT" "@127.0.0.1:$port" www.example.com | grep -v '^\[' | sort)
    wait "$server_pid" 2> /dev/null

    if echo "$actual" | grep -Eq "$expected"; then
        echo "[PASS] $mode"
        pass=$((pass + 1))
    else
        echo "[FAIL] $mode: expected /$expected/, got:"
        echo "$actual"
        fail=$((fail + 1))
    fi
}

run_case nodata '^NOTFOUND$'
run_case short '^ERROR'
run_case tc '^ERROR'
run_case wrongid $'^IP\t1\\.2\\.3\\.4\tnonauth$'
run_case notresponse $'^IP\t1\\.2\\.3\\.4\tnonauth$'
run_case loop '^ERROR'
run_case forwardptr '^ERROR'
run_case badalen '^ERROR'
run_case overrun '^ERROR'
run_case trailing '^ERROR'
run_case mismatch '^ERROR'
run_case noquestion '^ERROR'
run_case refused '^ERROR'
run_case formerr '^ERROR'
run_case rcode9 '^ERROR'
run_case chain $'CNAME\talias\\.example\tnonauth'
run_case otherport $'^IP\t1\\.2\\.3\\.4\tnonauth$'
run_case mixed $'^IP\t5\\.6\\.7\\.8\tnonauth$'
run_case auth $'^IP\t10\\.0\\.0\\.1\tauth$'
run_case many $'IP\t10\\.1\\.0\\.39\tnonauth'
run_case escaped $'^CNAME\ta\\\\\\.b\\.\\\\009\\.example\tnonauth$'
run_case upper $'^IP\t1\\.2\\.3\\.4\tnonauth$'
run_case authority '^NOTFOUND$'
run_case badclass '^ERROR'
run_case silent '^NORESPONSE$'

echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
