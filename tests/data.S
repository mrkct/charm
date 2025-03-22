.section .text, "ax"
_start:
fizz:
    .asciz "Fizz"
fizzbuzz:
    .asciz "FizzBuzz"
fizzbuzz_addr:
    .word fizzbuzz
fizz_addr:
    .word fizz
