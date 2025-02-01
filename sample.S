.section .bss, "aw"
label:
    .asciiz "Hello World"

.section .text, "ax"
_start:
    mov r0, #1      # SYS_Write
    mov r1, #1      # STDOUT
    ldr r0, =label  # data
    mov r2, #12     # length
    swi #0x0

    mov r0, #0      # SYS_Exit
    swi #0x0
