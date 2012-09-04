#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <windows.h>
#include <stdio.h>

#include "fout.h"
#include "urlparse.h"
#include "local.h"


static int _win32_write(struct fout *ff, const void *buf, int len)
{
	HANDLE tmp;
	DWORD did;
	int r1, r2;

	tmp = (HANDLE)ff->x;

	if (!buf && len < 1) {
		r1 = FlushFileBuffers(tmp);
		r2 = CloseHandle(tmp);
		if (ff->aborted) (void)unlink(ff->fn);
		if (!r1 || !r2) return 0;
		return 1;
	}

	while (len > 0) {
		did = 0;
		if (!WriteFile(tmp, buf, len, &did, NULL)) {
			win32_perror("WriteFile");
			return 0;
		}
		buf += did;
		len -= did;
	}
	return 1;
}


int fout_setup(struct fout *ff, const char *root, const char *name)
{
	static char *s = NULL;
	static char *q = NULL;
	char *x;

	struct url uu;
	HANDLE tmp;
	int i, flip;

	memset(ff, 0, sizeof(struct fout));

	if (sizeof(HANDLE) > sizeof(void*)) {
		fprintf(stderr, "Critical error: This windows aint\n");
		exit(EXIT_FAILURE);
	}
	if (!url_parse(&uu, root)) {
		/* hope CreateFile can deal with it */
		s = realloc(s, (strlen(root) + strlen(name) + 4));
		if (!s) abort();

		/* ensure directories exist */
		for (i = 0; root[i]; i++) {
			s[i] = root[i];
		}
		if (i > 0 && s[i-1] == '\\') {
			i--;
		}
		s[i] = '\\';i++;
		while (name[0] == '\\') name++;
		if (!*name) {
			/* uh... */
			return 0;
		}
		while (*name) {
			if (*name == '\\') {
				s[i] = '\0';
				(void)CreateDirectory(s, NULL);
				s[i] = '\\';
			} else if (*name == ':') {
				s[i] = '_';
			} else {
				s[i] = *name;
			}
			i++; name++;
		}
		s[i] = '\0';

		/* try to actually create the file */
		tmp = CreateFile(s,
			GENERIC_WRITE,
			FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE,
			NULL,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL);
		if (tmp == INVALID_HANDLE_VALUE) {
			return 0;
		}

		ff->fn = strdup(s);
		if (!ff->fn) abort();
		ff->x = (void*)tmp;
		ff->fun = _win32_write;
		return 1;
	}
	if (strcmp(uu.schema, "file") == 0) {
		/* okay, it's easier if we reverse the \\ chars in path
		 * and restart
		 */
		if (!uu.hostname) uu.hostname = "";
		q = realloc(q, (strlen(uu.hostname) + strlen(uu.path) + 5));
		if (!q) abort();
		if (uu.hostname) {
			q[0] = '\\';
			q[1] = '\\';
			for (i = 0; uu.hostname[i]; i++) {
				q[i+2] = uu.hostname[i];
			}
			q[i+2] = '\\';
			x = q+(i+3);
		} else {
			x = q;
		}
		for (i = 0; uu.path[i] == '/'; i++);
		flip = 1;
		for (; uu.path[i]; i++) {
			if (flip && uu.path[i] == '|') {
				*x = ':';
				flip = 0;
			} else if (uu.path[i] == '/') {
				flip = 0;
				*x = '\\';
			} else {
				*x = uu.path[i];
			}
			x++;
		}
		*x = '\0';
		i = fout_setup(ff, q, name);

	} else if (strcmp(uu.schema, "ftp") == 0) {
		netrc(&uu);
		i = fout_ftp_setup(ff, &uu, name);

	} else if (strcmp(uu.schema, "sftp") == 0) {
		i = fout_ssh_setup(ff, &uu, name, FOUT_SSH_SFTP);

	} else if (strcmp(uu.schema, "ssh1") == 0) {
		i = fout_ssh_setup(ff, &uu, name, FOUT_SSH_SSH1);

	} else if (strcmp(uu.schema, "ssh2") == 0) {
		i = fout_ssh_setup(ff, &uu, name, FOUT_SSH_SSH2);

	} else if (strcmp(uu.schema, "ssh") == 0) {
		i = fout_ssh_setup(ff, &uu, name, FOUT_SSH_ANY);

	} else {
		if (strcmp(uu.schema, "http") == 0) {
		} else if (strcmp(uu.schema, "https") == 0) {
	
	
		} else {
			fprintf(stderr, "Unsupported url-scheme \"%s\"\n", uu.schema);
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "Unimplemented url-scheme \"%s\"\n", uu.schema);
		exit(EXIT_FAILURE);
	}
	url_free(&uu);
	return i;
}

int fout(struct fout *s, const void *buf, int len)
{
	if (s->aborted) return 1;
	return s->fun(s, buf, len);
}
int fout_close(struct fout *s)
{
	int r;
	r = s->fun(s, 0, -1);
	free(s->fn);
	return r;
}
void fout_abort(struct fout *s)
{
	s->aborted = 1;
}
