#!/bin/bash

set -e

rm -f tests/*.{elf,actual,expected}
echo "Running tests..."

for f in tests/*.S; do
    echo "Running test $f"
    arm-none-eabi-as $f -o $f.elf && arm-none-eabi-objcopy -O binary $f.elf $f.expected.bin
    ./charm $f $f.actual.bin || echo "❌ Test $f failed: Charm returned status code $?"
    diff $f.actual.bin $f.expected.bin && echo "✅ Test $f passed" || >&2 echo "❌ Test $f failed"
done

rm -f samples/*.{elf,o,txt}
echo "Running samples..."
for f in samples/*.S; do
    echo "Running sample $f"
    arm-none-eabi-as $f -o $f.o && arm-none-eabi-ld $f.o -o $f.gnuc.elf
    ./charm $f $f.charmc.elf || echo "❌ Sample $f failed: Charm returned status code $?"
    qemu-arm $f.gnuc.elf > $f.expected.txt 2>&1 || >&2 echo "❌ Sample $f failed (GNU compiled version exited with status code $?)"
    qemu-arm $f.charmc.elf > $f.actual.txt 2>&1 || >&2 echo "❌ Sample $f failed (Charm compiled version exited with status code $?)"
    diff $f.actual.txt $f.expected.txt && echo "✅ Sample $f passed" || >&2 echo "❌ Sample $f failed (output mismatch)"
done
