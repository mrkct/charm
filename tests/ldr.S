.section .text, "ax"
_start:
    mov r0, r0
before:
    mov r0, r0
    mov r0, r0
    mov r0, r0
    ldr r0, [r1]
    ldr r0, [r1, #8]
    ldr r0, [r1, #16]!
    ldr r0, [r1], #24
    ldr r0, [r1, r2]
    ldr r0, [r1, r2]!
    ldr r0, [r1], r2
    mov r0, r0
    mov r0, r0
    mov r0, r0
after:
    mov r0, r0
