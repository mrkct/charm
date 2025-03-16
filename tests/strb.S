.section .text, "ax"
_start:
    mov r0, r0
before:
    mov r0, r0
    mov r0, r0
    mov r0, r0
    strb r0, [r1]
    strb r0, [r1, #8]
    strb r0, [r1, #16]!
    strb r0, [r1], #24
    mov r0, r0
    mov r0, r0
    mov r0, r0
after:
    mov r0, r0
