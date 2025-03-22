.section .text, "ax"
_start:
    mov r0, r0
before:
    mov r0, r0
    mov r0, r0
    mov r0, r0
    str r0, [r1]
    str r0, [r1, #8]
    str r0, [r1, #16]!
    str r0, [r1], #24
    str r0, [r1, r2]
    str r0, [r1, r2]!
    str r0, [r1], r2
    mov r0, r0
    mov r0, r0
    mov r0, r0
after:
    mov r0, r0
