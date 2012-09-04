#include "fout.h"
#include "bufout.h"

#include <string.h>

static char *hexdict = "0123456789ABCDEF";

int bufout_setup(struct bufout *b, struct fout *ff)
{
	memset(b, 0, sizeof(struct bufout));
	b->ff = ff;
	return 1;
}

int bufout_write(struct bufout *b, const void *buffer, int len)
{
	int r;
TOP:
	if ((b->used+len) < sizeof(b->buffer)) {
		memcpy(b->buffer+b->used, buffer, len);
		b->used += len;
		return 1;
	}
	r = sizeof(b->buffer)-b->used;
	memcpy(b->buffer+b->used, buffer, r);
	if (!bufout_flush(b)) return 0;

	buffer = ((const char *)buffer)+r;
	len -= r;

	goto TOP;
}
int bufout_flush(struct bufout *b)
{
	int r;
	r = fout(b->ff, b->buffer, b->used);
	b->used = 0;
	return r;
}


int bufout_putc(struct bufout *b, int ch)
{
	if (b->used == sizeof(b->buffer)) {
		if (!bufout_flush(b)) return 0;
	}
	b->buffer[b->used] = ch;
	b->used++;
	return 1;
}
int bufout_puts(struct bufout *b, const char *s)
{
	while (*s) {
		if (!bufout_putc(b,*s)) return 0;
		s++;
	}
	return 1;
}
int bufout_puthex2(struct bufout *b, unsigned int x)
{
	if (!bufout_putc(b, hexdict[(x >> 4) & 15])) return 0;
	if (!bufout_putc(b, hexdict[x & 15])) return 0;
	return 1;
}
int bufout_puthex8(struct bufout *b, unsigned int x)
{
	if (!bufout_putc(b, hexdict[(x >> 28) & 15])) return 0;
	if (!bufout_putc(b, hexdict[(x >> 24) & 15])) return 0;
	if (!bufout_putc(b, hexdict[(x >> 20) & 15])) return 0;
	if (!bufout_putc(b, hexdict[(x >> 16) & 15])) return 0;
	if (!bufout_putc(b, hexdict[(x >> 12) & 15])) return 0;
	if (!bufout_putc(b, hexdict[(x >> 8) & 15])) return 0;
	if (!bufout_putc(b, hexdict[(x >> 4) & 15])) return 0;
	if (!bufout_putc(b, hexdict[x & 15])) return 0;
	return 1;
}

