arm7-dasm
=========

android kernel disassembler based on MAME emulator code

Compile:

	$ gcc -o arm7-dasm arm7-dasm.c

Disassemble:

	$ ./arm7-dasm [kernel image filename] [image base address] [disassemble address or symbol name] [symbol table file]

    Or

	$ ./arm7-dasm [kernel image filename] [image base address] [disassemble address]

Example:

	$ kallsymsprint kernel.Image > kallsyms.txt
	[+]mmap
	  mem=f6a0b000 length=00bcff4c offset=c95fd000
	[+]kallsyms_addresses=c076dc90
	  count=0000d90e
	[+]kallsyms_num_syms=0000d90e
	[+]kallsyms_names=c07a40e0
	[+]kallsyms_markers=c08415b0
	[+]kallsyms_token_table=c0841920
	[+]kallsyms_token_index=c0841cd0
	[+]kallsyms_lookup_name

	$ ./arm7-dasm kernel.Image c0008000 vmalloc_exec kallsyms.txt > vmalloc_exec.dasm
	55417 symbols are loaded.

	$ cat vmalloc_exec.dasm
	Disassemble 0xc0143354 - 0xc0143374
	c0143354: e5 9f 30 1c     LDR     R3, =$c0bd8318 [$c0143378]
	c0143358: e9 2d 40 07     STMPW   [SP], { R0-R2, LR }
	c014335c: e3 e0 20 00     MVN     R2, #$0
	c0143360: e5 93 30 00     LDR     R3, [R3]
	c0143364: e3 a0 10 01     MOV     R1, #$1
	c0143368: e8 8d 40 04     STMU    [SP], { R2, LR }
	c014336c: e3 a0 20 d2     MOV     R2, #$d2
	c0143370: eb ff ff 85     BL      $c014318c <__vmalloc_node>
	c0143374: e8 bd 80 0e     LDMUW   [SP], { R1-R3, PC }
