struct fout {
	void *x;

	void *x_a, *x_b, *x_c, *x_d;
	int i_a, i_b, i_c, i_d;

	int (*fun)(struct fout *ff, const void *buf, int len);

	char *fn;

	int aborted;
};

int fout_setup(struct fout *s, const char *root, const char *name);
int fout(struct fout *s, const void *buf, int len);
int fout_close(struct fout *s);
void fout_abort(struct fout *s);

/* protocol-specific */
struct url;
int fout_ftp_setup(struct fout *ff, struct url *uu,
		const char *fn);
int fout_ssh_setup(struct fout *ff, struct url *uu,
				const char *fn, int protocol);
#define FOUT_SSH_SFTP	0
#define FOUT_SSH_SSH1	1
#define FOUT_SSH_SSH2	2
#define FOUT_SSH_ANY	3

