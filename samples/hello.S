.global _start
.section .text, "ax"
_start:
    mov r7, #4
    mov r0, #1
    ldr r1, message_addr
    mov r2, #13
    svc #0

    mov r7, #1
    mov r0, #0
    svc #0

message_addr:
    .word message
message:
    .asciz "Hello World!\n"
