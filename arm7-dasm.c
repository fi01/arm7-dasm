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

	//printf("register coderef: %08x to %08x\n", from, to);

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
  char name[KSYM_NAME_LEN + 16];
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

  i = search_symbol(addr);
  return symbols[i].addr == addr;
}

const char *get_symbol_name(UINT32 addr)
{
  static char buf[16];
  int i;

  i = search_symbol(addr);
  if (symbols[i].addr == addr)
    return symbols[i].name;

  sprintf(buf, "$%x", addr);
  return buf;
}

#include "arm7dasm.c"

static void register_symbol(const char *name, UINT32 addr)
{
  symbol_t target;
  int i;

  snprintf(target.name, sizeof (target.name) - 1, "$%x <%s>", addr, name);
  target.name[sizeof (target.name) - 1] = '\0';
  target.addr = addr;

  if (symbols == NULL)
  {
    symbol_size = 1024;
    symbols = malloc(sizeof (*symbols) * symbol_size);
    if (symbols == NULL)
      return;

    symbol_len = 0;
    //fprintf(stderr, "\r%d symbols", symbol_len);
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

    //fprintf(stderr, "\r%d symbols", symbol_len);
  }

  memmove(&symbols[i], &symbols[i + 1], sizeof (*symbols) * (symbol_len - i));
  symbols[i] = target;
  symbol_len++;
}

static void read_kallsyms(const char *filename)
{
  FILE *fp = fopen(filename, "rt");

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
	STAT_ENDFUNC,
	STAT_UNKNOWN
};

int main(int argc, const char *argv[])
{
	FILE *fp;
	UINT32 start;
	UINT32 end;
	int status;
	UINT32 frameregs;
	UINT32 i;

	if (argc != 4 && argc != 5)
		return 1;

	if (sscanf(argv[2], "%x", &image_base) != 1)
		return 1;

	if (sscanf(argv[3], "%x", &start) != 1)
		return 1;

	fp = fopen(argv[1], "rb");
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

	if (start < image_base || start >= image_base + image_size)
		goto error_exit;

	image_data = malloc(image_size);
	if (!image_data)
	{
		fprintf(stderr, "out of memory for rom image\n");
		goto error_exit;
	}

	memset(image_data, 0, image_size);

	coderef = malloc(image_size / 4 * sizeof *coderef);
	if (!coderef)
	{
		fprintf(stderr, "out of memory for coderef\n");
		goto error_exit;
	}

	memset(coderef, 0, image_size / 4 * sizeof *coderef);

	if (fread(image_data, image_size, 1, fp) != 1)
	{
		fprintf(stderr, "file read error\n");
		goto error_exit;
	}

	fclose(fp);

  if (argv[4])
    read_kallsyms(argv[4]);

  end = 0;

	for (dasm_process_pass = 0; dasm_process_pass < 2; dasm_process_pass++)
	{
		status = STAT_START;
		frameregs = 0;
		i = 0;

    if (dasm_process_pass == 1)
      printf("Disassemble 0x%08x - 0x%08x\n", start, start + end);

		while (1)
		{
			UINT32 pc;
			UINT32 off;
			UINT32 op;
			coderef_t *ref;
			char buf[1024];
			int j;
			int n;

			pc = start + i;

      if (end < i)
      {
        end = i;
      }

			off = pc - image_base;

			if (off >= image_size)
				break;

			for (j = 0; j < 4; j++)
			{
				op <<= 8;
				op += image_data[off + 3 - j];
			}

			switch (status)
			{
			case STAT_START:
        // BX LR
				if (op == 0xe12fff1e)
        {
					status = STAT_ENDFUNC;
          break;
        }

        // STMPW [SP], { ..., LR }
				if ((op & 0x0ffff000) == 0x092d4000)
				{
					status = STAT_HAS_STACKFRAME;
          // R4-R12
					frameregs = op & 0x00000ff0;

#ifdef DEBUG
          if (!dasm_process_pass)
            fprintf(stderr, "found: STMPW: pc = 0x%08x, frameregs = 0x%08x\n", pc, frameregs);
#endif /* DEBUG */
				}

				break;

			case STAT_HAS_STACKFRAME:
        // LDMUW [SP], { R4-R6, PC }
				if ((op & 0x0ffffff0) == (0x08bd8000 | frameregs))
        {
          if (end <= i) {
#ifdef DEBUG
            if (!dasm_process_pass)
              fprintf(stderr, "found: LDMUW: pc = 0x%08x, frameregs = 0x%08x\n", pc, frameregs);
#endif /* DEBUG */

            status = STAT_ENDFUNC;
          }
#ifdef DEBUG
          else {
            if (!dasm_process_pass)
              fprintf(stderr, "skip: LDMUW: pc = 0x%08x, frameregs = 0x%08x\n", pc, frameregs);
          }
#endif /* DEBUG */
        }

				break;
			}

			if (dasm_process_pass)
			{
				ref = coderef[(pc - image_base) / 4];
				if (ref)
				{
					printf("%08x: %*s; from %08x\n", pc, 44, "", ref->from);

					for (ref = ref->next; ref; ref = ref->next)
						printf("%08x: %*s;      %08x\n", pc, 44, "", ref->from);
				}

				printf("%08x: ", pc);
				
				for (j = 0; j < 4; j++)
					printf("%02x ", image_data[off + 3 - j]);
			}

			n = arm7arm(buf, pc, &image_data[off]);

			if (dasm_process_pass)
				printf("    %s\n", buf);

			if (status == STAT_ENDFUNC)
      {
        if (i >= end)
          break;
      }

      // Bxx $xxxxxxxx
      if ((op & 0x0f000000) == 0x0a000000)
      {
        int b = i + (op & 0x00ffffff) * 4 + 8;

        if (op & 0x00800000)
          b += 0xff000000 * 4; /* sign-extend */

        if ((op & 0xff000000) == 0xea000000)
          if (((b - i) & 0x80000000) && i >= end)
            break;

        if (b <= image_size)
          if (!have_symbol(b))
            if (end < b)
              end = b;
      }

			i += 4;
		}
	}

	return 0;

error_exit:
	fclose(fp);
	return 1;
}
