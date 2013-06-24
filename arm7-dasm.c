#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define INT8	signed char
#define INT16	signed short
#define INT32	signed int
#define UINT8	unsigned char
#define UINT16	unsigned short
#define UINT32	unsigned int

#define endianness_t	int
#define device_irq_callback void *
#define legacy_cpu_device void *
#define address_space void *
#define direct_read_data void *

#define write32_device_func void *
#define read32_device_func void *

#define DASMFLAG_STEP_OVER	1
#define DASMFLAG_STEP_OUT	2
#define DASMFLAG_SUPPORTED	4

#define CPU_DISASSEMBLE(x)	int x(char *buffer, UINT32 pc, const UINT8 *oprom)

#define KSYM_NAME_LEN 128

UINT8 *image_data;
UINT32 image_base;
UINT32 image_size;

int dasm_process_pass;

struct _coderef_t;
typedef struct _coderef_t coderef_t;

struct _coderef_t
{
	UINT32 from;
	struct _coderef_t *next;
};

coderef_t **coderef;

void register_coderef(UINT32 from, UINT32 to)
{
	coderef_t *p, **q;

	if (dasm_process_pass)
		return;

	if (to < image_base)
		return;

	to -= image_base;
	if (to >= image_size)
		return;

	to /= 4;

	p = malloc(sizeof *p);
	if (!p)
	{
		fprintf(stderr, "Out fo memory\n");
		exit(1);
	}

	p->from = from;
	p->next = NULL;

	for (q = &coderef[to]; *q; q = &(*q)->next);
		*q = p;
}

typedef struct
{
	char name[KSYM_NAME_LEN];
	UINT32 addr;
} symbol_t;

symbol_t *symbols;
size_t symbol_len;
size_t symbol_size;

static int search_symbol(UINT32 addr)
{
	int s = 0;
	int e = symbol_len - 1;

	while (e >= s)
	{
		int i = (s + e) / 2;
		if (symbols[i].addr == addr)
			return i;

		if (symbols[i].addr > addr)
			e = i - 1;
		else
			s = i + 1;
	}

	return s;
}

int have_symbol(UINT32 addr)
{
	int i;

	if (symbols == NULL)
		return 0;

	i = search_symbol(addr);
	return symbols[i].addr == addr;
}

const char *get_symbol_name(UINT32 addr)
{
	static char buf[KSYM_NAME_LEN + 16];

	if (symbols)
	{
		int i;

		i = search_symbol(addr);
		if (symbols[i].addr == addr)
		{
			snprintf(buf, sizeof (buf) - 1, "$%x <%s>", addr, symbols[i].name);
			buf[sizeof (buf) - 1] = '\0';
			return buf;
		}
	}

	sprintf(buf, "$%x", addr);
	return buf;
}

const UINT32 get_symbol_address(const char *name)
{
	int i;

	if (symbols == NULL)
		return 0;

	for (i = 0; i < symbol_len; i++)
		if (strcmp(symbols[i].name, name) == 0)
			return symbols[i].addr;

	return 0;
}

UINT32 rnv_requested;

void check_rnv(UINT32 addr)
{
	if (rnv_requested != 0 && rnv_requested < addr)
		return;

	if (addr & 3)
	{
#ifdef DEBUG
		fprintf(stderr, "skip: check_rnv(0x%08x)\n", addr);
#endif /* DEBUG */
		return;
	}

#ifdef DEBUG
	if (!dasm_process_pass)
		fprintf(stderr, "check_rnv(0x%08x)\n", addr);
#endif /* DEBUG */

	rnv_requested = addr;
}

#include "arm7dasm.c"

static void insert_symbol(int pos, const char *name, UINT32 addr)
{
	int i;

	for (i = symbol_len - 1; i >= pos; i--)
		symbols[i + 1] = symbols[i];

	symbols[pos].addr = addr;

	strncpy(symbols[pos].name, name, sizeof (symbols[0].name) - 1);
	symbols[pos].name[sizeof (symbols[0].name) - 1] = '\0';

	symbol_len++;
}

static void register_symbol(const char *name, UINT32 addr)
{
	int i;

	if (symbols == NULL)
	{
		symbol_size = 1024;
		symbols = malloc(sizeof (*symbols) * symbol_size);
		if (symbols == NULL)
			return;

		symbol_len = 0;
	}

	i = search_symbol(addr);
	if (symbols[i].addr == addr)
		return;

	if (symbol_len == symbol_size)
	{
		symbol_size += 1024;
		symbols = realloc(symbols, sizeof (*symbols) * symbol_size);
		if (symbols == NULL)
			return;
	}

	insert_symbol(i, name, addr);
}

static void read_kallsyms(const char *filename)
{
	FILE *fp = fopen(filename, "rt");

	if (!fp)
	{
		fprintf(stderr, "cannot open file: %s\n", filename);
		return;
	}

	while (!feof(fp))
	{
		char buf[1024];
		UINT32 addr;
		char name[KSYM_NAME_LEN];
		char *s;
		char *p;

		if (fgets(buf, sizeof buf, fp) == NULL)
			break;

		s = strtok_r(buf, " \r\n", &p);
		if (s == NULL)
			break;

		if (sscanf(s, "%x", &addr) != 1)
			break;

		s = strtok_r(NULL, " \r\n", &p);
		if (s == NULL)
			break;

		strncpy(name, s, KSYM_NAME_LEN - 1);
		name[KSYM_NAME_LEN - 1] = '\0';

		if ((s = strtok_r(NULL, " \r\n", &p)) != NULL)
		{
			strncpy(name, s, KSYM_NAME_LEN - 1);
			name[KSYM_NAME_LEN - 1] = '\0';
		}

		register_symbol(name, addr);
	}

	fclose(fp);

	fprintf(stderr, "%d symbols are loaded.\n", symbol_len);
}

enum
{
	STAT_START = 0,
	STAT_HAS_STACKFRAME,
	STAT_END_STACKFRAME,
	STAT_END_FUNCTION,
	STAT_PROCESS_WHOLE,
	STAT_UNKNOWN
};

int load_image(const char *name)
{
	FILE *fp;

	fp = fopen(name, "rb");
	if (!fp)
		return 1;

	fseek(fp, 0, SEEK_END);

	image_size = ftell(fp);
	if (image_size < 4)
	{
		fprintf(stderr, "image file is too small\n");
		goto error_exit;
	}

	fseek(fp, 0, SEEK_SET);

	image_data = malloc(image_size);
	if (!image_data)
	{
		fprintf(stderr, "out of memory for rom image\n");
		goto error_exit;
	}

	memset(image_data, 0, image_size);

	if (fread(image_data, image_size, 1, fp) != 1)
	{
		fprintf(stderr, "file read error\n");
		goto error_exit;
	}

	fclose(fp);

	return 0;

error_exit:
	fclose(fp);
	return 1;
}

static UINT32 start;
static UINT32 end;
static int status;

static void check_stackframe(UINT32 pc, UINT32 op, UINT32 *frameregs)
{
	switch (status)
	{
	case STAT_START:
		// BX LR
		if (op == 0xe12fff1e)
		{
			status = STAT_END_FUNCTION;
			return;
		}

		// e92d4xxx: STMPW [SP], { ..., LR }
		// e92ddxxx: STMPW [SP], { , LR, PC }
		if (((op & 0xfffff000) == 0xe92d4000)
		 || ((op & 0xfffff000) == 0xe92dd000))
		{
			status = STAT_HAS_STACKFRAME;
			// R4-R12
			*frameregs = op & 0x00000ff0;

#ifdef DEBUG
			fprintf(stderr, "found: STMPW: pc = 0x%08x, frameregs = 0x%08x\n", pc, *frameregs);
#endif /* DEBUG */
		}

		if (pc - start >= 32)
		{
			status = STAT_PROCESS_WHOLE;
			fprintf(stderr, "Disassemble whole image.\n");
		}

		return;

	case STAT_HAS_STACKFRAME:
		// e8bd8xxx: LDMUW [SP], { ..., PC }
		// e89daxxx: LDMU  [SP], { ..., SP, PC }
		if (((op & 0xfffffff0) == (0xe8bd8000 | *frameregs))
		 || ((op & 0xfffffff0) == (0xe89da000 | *frameregs)))
		{
#if 0
			if (end <= pc)
#else
			if (1)
#endif
			{
				if (end > pc)
					status = STAT_END_STACKFRAME;
				else
					status = STAT_END_FUNCTION;
#ifdef DEBUG
				fprintf(stderr, "found: LDMUW (PC): pc = 0x%08x, frameregs = 0x%08x\n", pc, *frameregs);
			}
			else
			{
				fprintf(stderr, "skip: LDMUW (PC): pc = 0x%08x, end = 0x%08x, frameregs = 0x%08x\n", pc, end, *frameregs);
#endif /* DEBUG */
			}

			return;
		}
	}
}

static int check_branch(UINT32 pc, UINT32 op)
{
	// Bxx $xxxxxxxx
	if ((op & 0x0f000000) == 0x0a000000)
	{
		int b = pc + (op & 0x00ffffff) * 4 + 8;

		if (op & 0x00800000)
			b += 0xff000000 * 4; /* sign-extend */

		// B $xxxxxxxx
		if ((op & 0xff000000) == 0xea000000)
			if (b < pc && pc > end)
				return 1;

		if (b > image_base + image_size)
			return 0;

		if (status == STAT_END_STACKFRAME)
		{
			if (b > end)
				return 1;
		}
		else if (!have_symbol(b))
		{
			if (end < b)
				end = b;
		}
#if 0
		else if (status != STAT_HAS_STACKFRAME)
		{
			fprintf(stderr, "end due to branch to symbol\n");
			return 1;
		}
#endif
	}

	return 0;
}

static void write_result(UINT32 pc, const char *asm7)
{
	coderef_t *ref;
	UINT32 off;
	int i;

	off = pc - image_base;
	ref = coderef[off / 4];

	if (ref)
	{
		printf("%08x: %*s; from %08x\n", pc, 44, "", ref->from);

		for (ref = ref->next; ref; ref = ref->next)
			printf("%08x: %*s;      %08x\n", pc, 44, "", ref->from);
	}

	if (have_symbol(pc))
	{
		i = search_symbol(pc);
		printf("%08x: %12s<%s>\n", pc, "", symbols[i].name);
	}

	printf("%08x: ", pc);

	for (i = 0; i < 4; i++)
		printf("%02x ", image_data[off + 3 - i]);

	printf("    %s\n", asm7);
}

static int do_disassemble(void)
{
	UINT32 pc;

	rnv_requested = 0;
	end = 0;

	status = STAT_START;

	for (dasm_process_pass = 0; dasm_process_pass < 2; dasm_process_pass++)
	{
		UINT32 frameregs = 0;

		if (dasm_process_pass == 1)
			printf("Disassemble 0x%08x - 0x%08x\n", start, end);

		for (pc = start; pc < image_base + image_size; pc += 4)
		{
			UINT32 off;
			UINT32 op;
			char buf[1024];
			int i;
			int n;

			off = pc - image_base;

			for (i = 0; i < 4; i++)
			{
				op <<= 8;
				op += image_data[off + 3 - i];
			}

			if (!dasm_process_pass)
			{
				if (end < pc)
					end = pc;

				check_stackframe(pc, op, &frameregs);
			}

			n = arm7arm(buf, pc, &image_data[off]);

			if (dasm_process_pass)
			{
				write_result(pc, buf);

				if (pc >= end)
					break;

				continue;
			}

			if (status == STAT_PROCESS_WHOLE)
				continue;

			if (status == STAT_END_FUNCTION)
				if (pc >= end)
					break;

			if (check_branch(pc, op))
			{
#ifdef DEBUG
				fprintf(stderr, "end by branch\n");
				break;
#endif /* DEBUG */
			}

			if (status != STAT_HAS_STACKFRAME && status != STAT_UNKNOWN)
				if (rnv_requested != 0 && pc >= rnv_requested)
				{
					fprintf(stderr, "end at 0x%08x by rnv requested\n", pc);

					end = pc - 4;
					break;
				}
		}
	}

#ifdef DEBUG
	fprintf(stderr, "done at 0x%08x (end = 0x%08x, rnv requested: 0x%08x)\n", pc, end, rnv_requested);
#endif /* DEBUG */
}

int main(int argc, const char *argv[])
{
	if (argc != 4 && argc != 5)
		return 1;

	if (sscanf(argv[2], "%x", &image_base) != 1)
		return 1;

	if (load_image(argv[1]))
		return 1;

	coderef = malloc(image_size / 4 * sizeof *coderef);
	if (!coderef)
	{
		fprintf(stderr, "out of memory for coderef\n");
		return 1;
	}

	memset(coderef, 0, image_size / 4 * sizeof *coderef);

	if (argv[4])
		read_kallsyms(argv[4]);

	start = get_symbol_address(argv[3]);
	if (start == 0)
		if (sscanf(argv[3], "%x", &start) != 1)
			return 1;

	if (start < image_base || start >= image_base + image_size)
		return 1;

	do_disassemble();

	return 0;
}

/*
vi:ts=2:nowrap:ai:noexpandtab:sw=2
*/
