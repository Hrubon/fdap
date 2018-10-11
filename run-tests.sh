#!/usr/bin/env sh

prog=$(basename $0)

function usage() {
    echo "Usage: $prog BINARIES"
}

if [ $# -lt 1 -o "$1" = "-h" ]; then
    usage
    exit 1
fi

num_ok=0
num_failed=0
for test_file in $@; do
	./$test_file
	if [ $? -eq 0 ]; then
		echo "OK       $test_file"
		num_ok=$(($num_ok + 1))
	else
		echo "FAIL     $test_file"
		num_failed=$(($num_failed + 1))
	fi
done

echo
echo "$num_ok OK, $num_failed FAILED"
if [ $num_failed -gt 0 ]; then
	exit 1
fi
