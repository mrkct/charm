.global _start
.section .text, "ax"
_start:
    mov r7, #4
    mov r0, #1
    add r1, pc, #16  // ldr r1, msg_addr
    mov r2, #13
    svc #0

    mov r7, #1
    mov r0, #0
    svc #0

message:
    .asciz "Hello World!\n"
