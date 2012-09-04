struct fout;

struct bufout {
	struct fout *ff; /* fout_handle */

	unsigned char buffer[65536];
	int used;
};

int bufout_setup(struct bufout *b, struct fout *ff);

int bufout_write(struct bufout *b, const void *buffer, int len);
int bufout_flush(struct bufout *b);


int bufout_putc(struct bufout *b, int ch);
int bufout_puts(struct bufout *b, const char *s);
int bufout_puthex2(struct bufout *b, unsigned int x);
int bufout_puthex8(struct bufout *b, unsigned int x);

