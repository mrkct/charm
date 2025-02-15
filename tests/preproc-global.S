// This test only cares about parsing '.global', but gnu AS will fail with only that line.
.global _start
_start:
    add r0, r0, r0
