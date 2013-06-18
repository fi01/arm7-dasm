arm7-dasm
=========

android kernel disassembler based on MAME emulator code

Compile:

	$ gcc -o arm7-dasm arm7-dasm.c

Disassemble:

	$ ./arm7-dasm [kernel image filename] [image base address] [start address]

Disassemble with symbol table:

	$ ./arm7-dasm [kernel image filename] [image base address] [start address or symbol name] [symbol table file]

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

Example 2:
How to find ptms_fops address

Generate kallsyms table

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

Disassemble pty_init with kallsyms table

	$ arm7-dasm kernel.Image c0008000 pty_init kallsyms.txt > pty_init.dasm
	55417 symbols are loaded.

Search where tty_default_fops is called

	$ grep tty_default_fops pty_init.dasm
	c0a1d188: eb e3 e6 c7     BL      $c0316cac <tty_default_fops>

Check more a few lines

	$ grep ^c0a1d1[8-9] pty_init.dasm
	c0a1d180: 1a ff ff 5f     BNE     $c0a1cf04
	c0a1d184: e2 85 00 08     ADD     R0, R5, #$8
	c0a1d188: eb e3 e6 c7     BL      $c0316cac <tty_default_fops>
	c0a1d18c: e5 9f 30 c0     LDR     R3, =$c031ea48 <ptmx_open> [$c0a1d254]
	c0a1d190: e2 85 00 70     ADD     R0, R5, #$70
	c0a1d194: e2 85 10 08     ADD     R1, R5, #$8
	c0a1d198: e5 85 30 34     STR     R3, [R5, #$34]
	c0a1d19c: eb dc e0 f0     BL      $c0155564 <cdev_init>

Now we know "ptms_fops = R5 + $8", check R5 value

	$ grep -n ^c0a1d184 pty_init.dasm
	188:c0a1d184: e2 85 00 08     ADD     R0, R5, #$8

	$ head -n 188 pty_init.dasm | grep 'R5.*=' | tail -1
	c0a1d02c: e5 9f 51 fc     LDR     R5, =$c0cc37e0 [$c0a1d230]

Finally we found "ptms_fops = $c0cc37e0 + $8 = $c0cc37e8"
