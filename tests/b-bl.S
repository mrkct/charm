.section .text, "ax"
_start:
    b _start
    b ahead
    add r0, r0, r0
    add r0, r0, r0
    add r0, r0, r0
    add r0, r0, r0
    add r0, r0, r0
    add r0, r0, r0
    add r0, r0, r0
    b _start
ahead:
    b ahead
    b _start
_start2:
    bl _start
    bl ahead
    add r0, r0, r0
    add r0, r0, r0
    add r0, r0, r0
    add r0, r0, r0
    add r0, r0, r0
    add r0, r0, r0
    add r0, r0, r0
    bl _start
ahead2:
    bl ahead
    bl _start
