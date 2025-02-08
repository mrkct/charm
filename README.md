# Charm: a tiny assembler for 32-bit ARM

Charm is a toy assembler that aims to generate ARMv7-A assembly code.
It implements a very tiny subset of the ARMv7-A instruction set
and can either generate a flat binary or a static ELF executable.

Charm is implemented entirely in a single C file, without any
dependencies other than the standard C library.

Compiling charm is easy:

    cc charm.c -o charm

Using charm is easy too:

    # Compile into a static ELF executable
    ./charm hello.S hello

    # Compile into a flat binary
    ./charm hello.S hello.bin

