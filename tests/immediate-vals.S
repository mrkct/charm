.section .text, "ax"
_start:
    add r0, r0, #1
    add r0, r0, #+1
    add r0, r0, #'A'
    ldr r0, [r1, #+4]
    ldr r0, [r1, #-4]
    ldr r0, [r1, #'A']
    ldr r0, [r1, #4]

