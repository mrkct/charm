.global _start

.section .data, "aw"
fizz:
    .asciz "Fizz"
buzz:
    .asciz "Buzz"
fizzbuzz:
    .asciz "FizzBuzz"
newline:
    .asciz "\n"
buffer:
    .space 13

.section .text, "ax"
_start:
    mov r4, #1         // i = 1
loop:
    cmp r4, #101       // while (i <= 100)
    beq exit

    // Check divisibility by 3
    mov r0, r4
    mov r1, #3
    bl modulo         // r0 = r4 % 3
    cmp r0, #0
    moveq r5, #1      // r5 = 1 if divisible by 3
    movne r5, #0

    // Check divisibility by 5
    mov r0, r4
    mov r1, #5
    bl modulo         // r0 = r4 % 5
    cmp r0, #0
    moveq r6, #1      // r6 = 1 if divisible by 5
    movne r6, #0

    cmp r5, #1
    bne not_div3
    cmp r6, #1
    beq print_fizzbuzz_label  // if divisible by both 3 and 5
    b print_fizz_label
not_div3:
    cmp r6, #1
    beq print_buzz_label
    b print_number_label

print_fizzbuzz_label:
    ldr r0, fizzbuzz_addr
    bl print_string
    b print_newline_label

print_fizz_label:
    ldr r0, fizz_addr
    bl print_string
    b print_newline_label

print_buzz_label:
    ldr r0, buzz_addr
    bl print_string
    b print_newline_label

print_number_label:
    mov r0, r4              // number to print
    ldr r1, buffer_addr     // pointer to conversion buffer
    bl itoa                 // convert number; returns pointer in r0
    bl print_string
    b print_newline_label

print_newline_label:
    ldr r0, newline_addr
    bl print_string

    add r4, r4, #1
    b loop

exit:
    mov r7, #1         // syscall: exit
    mov r0, #0
    svc #0
fizzbuzz_addr:
    .word fizzbuzz
fizz_addr:
    .word fizz
buzz_addr:
    .word buzz
newline_addr:
    .word newline
buffer_addr:
    .word buffer


// print_string:
//   Expects r0 = pointer to a null-terminated string.
//   Uses syscall write (syscall number 4) to print to stdout.
print_string:
    push {r1, r2, r3, lr}
    mov r1, r0         // r1 = string pointer
    mov r2, #0         // r2 = length counter
strlen_loop:
    ldrb r3, [r1, r2]
    cmp r3, #0
    beq strlen_done
    add r2, r2, #1
    b strlen_loop
strlen_done:
    mov r7, #4         // syscall: write
    mov r0, #1         // stdout
    svc #0
    pop {r1, r2, r3, pc}


// itoa:
//   Converts the unsigned number in r0 to an ASCII string.
//   Expects r1 to point to a buffer of at least 13 bytes.
//   Returns in r0 a pointer to the beginning of the generated string.
itoa:
    push {r2, r3, r4, lr}
    mov r2, r1           // r2 = start of buffer
    add r4, r1, #12      // r4 = pointer to the end of buffer
    mov r3, r0           // r3 = current number
    cmp r3, #0
    bne itoa_loop
    mov r0, #'0'
    strb r0, [r4, #-1]!  // store '0'
    b itoa_done
itoa_loop:
    mov r0, r3           // pass current number in r0 to div10
    bl div10             // returns quotient in r0, remainder in r1
    add r1, r1, #'0'     // convert remainder to ASCII digit
    strb r1, [r4, #-1]!  // store digit in buffer (pre-decrement r4)
    mov r3, r0           // update current number with quotient
    cmp r3, #0
    bne itoa_loop
itoa_done:
    mov r0, r4           // r4 now points to the beginning of the string
    pop {r2, r3, r4, lr}
    bx lr


// --------------------------------------------------------------------
//  modulo:
//    Computes r0 % r1 using repeated subtraction.
//    Expects: dividend in r0, divisor in r1.
//    Returns: remainder in r0.
// --------------------------------------------------------------------
modulo:
    push {r2, lr}
mod_loop:
    cmp r0, r1       // while (dividend >= divisor)
    blt mod_done
    sub r0, r0, r1
    b mod_loop
mod_done:
    pop {r2, pc}


// --------------------------------------------------------------------
//  div10:
//    Divides r0 by 10 using repeated subtraction.
//    Expects: dividend in r0.
//    Returns: quotient in r0, remainder in r1.
// --------------------------------------------------------------------
div10:
    push {r2, lr}
    mov r2, #0       // quotient = 0
div10_loop:
    cmp r0, #10
    blt div10_done
    sub r0, r0, #10
    add r2, r2, #1
    b div10_loop
div10_done:
    mov r1, r0       // remainder in r1
    mov r0, r2       // quotient in r0
    pop {r2, pc}
