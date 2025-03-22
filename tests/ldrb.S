.section .text, "ax"
_start:
    mov r0, r0
before:
    mov r0, r0
    mov r0, r0
    mov r0, r0
    ldrb r0, [r1]
    ldrb r0, [r1, #8]
    ldrb r0, [r1, #16]!
    ldrb r0, [r1], #24
    ldrb r0, [r1, r2]
    ldrb r0, [r1, r2]!
    ldrb r0, [r1], r2
    mov r0, r0
    mov r0, r0
    mov r0, r0
after:
    mov r0, r0
