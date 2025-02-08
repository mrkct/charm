#!/bin/bash

set -e

rm -f tests/*.{elf, actual, expected}
echo "Running tests..."

for f in tests/*.S; do
    echo "Running test $f"
    arm-none-eabi-as $f -o $f.elf && arm-none-eabi-objcopy -O binary $f.elf $f.expected
    ./charm $f $f.actual
    diff $f.actual $f.expected && echo "❎ Test $f passed" || >&2 echo "❌ Test $f failed"
done
