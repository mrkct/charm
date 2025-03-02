.section .text, "ax"
_start:
    ldr r0, some_value_addr
    ldr r0, some_value
    str r0, some_value_addr
    str r0, some_value
some_value:
    .word 0x12345678
some_value_addr:
    .word some_value
