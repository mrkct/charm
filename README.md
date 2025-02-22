# Charm: a tiny assembler for 32-bit ARM

Charm is a toy assembler that aims to generate ARMv7-A assembly code.
It implements a very tiny subset of the ARMv7-A instruction set
and can either generate a flat binary or a static ELF executable.

Charm is implemented entirely in a single C file, without any
dependencies other than the standard C library.

## Usage

The following commands will assemble the `hello.S` into a static ELF
executable that can run on an ARM Linux machine:

    ./charm hello.S hello
    ./hello
    Hello, world!

> [!TIP]
> If you're not on an ARM machine, you can use `qemu-arm` to run the generated executable.

Charm will use `_start` as the entry point of the program.

If the output file ends with `.bin` or `.obj`, the output will be
a flat binary.

## Compiling

Compiling charm only requires a C compiler.
To compile by yourself, run:

    cc charm.c -o charm

If you want to develop charm, you should also get `make`, a POSIX shell
and the GNU tools in `arm-none-eabi-gcc` as the tools 
`as` and `objdump` are used validation.

There is also a Makefile with a few targets that you might
be interested in; it's probably easiest to just see what's
there by yourself.

## Limitations

As the first line of this README says, Charm is a toy assembler and
therefore has many limitations compared to established assemblers
like GNU's `as`.

Here's a non-exhaustive list, you can either look at this to see if
charm is suitable for you use case or you can treat this as a potential
list of improvements you could contribute.

**Very few instructions are implemented**:
Charm implements less than 20 instructions, and some of them are not
even fully implemented.

**Not all invalid instructions are rejected**:
Charm doesn't implement all verification checks for all instructions,
and therefore it might allow you to assemble code that can generate
unpredictable results.

As an example, `mul pc, pc, pc` is marked as UNPREDICTABLE by the
ARMv7-A architecture, but charm will happily assemble that for you.

**No support for auto-generating literal pools**:
Charm doesn't implement any support for literal pools, so you'll
have to write them by hand.
