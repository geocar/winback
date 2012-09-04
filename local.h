struct fout;

int set_priv(char *privilege, int on);

int set_backup_privs(int on);

void win32_perror(const char *sa);

char *ensure_directories_exist(
		void (*fun)(void *a, const char *d),
		void *a,
		const char *fn,
		int pathsep);

int backup1(struct fout *ff, const char *f);

void backup_fun(const char *fn,
		void *x,
		int (*fun)(void *x, struct fout *ff));

int backup1_ntfs(struct fout *ff, const char *f);

