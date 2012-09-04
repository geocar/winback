#include "urlparse.h"

#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>

static int _hex(int c)
{
	if (c >= '0' && c <= '9') return c-'0';
	if (c >= 'A' && c <= 'F') return 10+(c-'A');
	if (c >= 'a' && c <= 'f') return 10+(c-'a');
	return -1;
}
static void _decode(char *s)
{
	char *d;
	int a,b;
	if (!s) return;

	/* always gets shorter */
	d=s;
	while (*s) {
		if (*s == '%' && s[1] && s[2]) {
			a = _hex(s[1]);
			b = _hex(s[2]);
			if (a > -1 && b > -1) {
				*d = (a << 4) | b;
				d++;
				s += 3;
				continue;
			}
		}
		if (s != d) *d = *s;
		s++;
		d++;
	}
	if (s != d) *d = *s;
}


int url_parse(struct url *dst, const char *src)
{
	int i, j;
	int mp;

	dst->extra_free_me3 = NULL;
	dst->extra_free_me4 = NULL;

	/* special case: mailto urls don't have // */
	if ((src[0] == 'm' || src[0] == 'M')
	&&  (src[1] == 'a' || src[1] == 'A')
	&&  (src[2] == 'i' || src[2] == 'I')
	&&  (src[3] == 'l' || src[3] == 'L')
	&&  (src[4] == 't' || src[4] == 'T')
	&&  (src[5] == 'o' || src[5] == 'O')
	&&  src[6] == ':') {
		if (src[7] == '/' || src[8] == '/') return 0;

		memset(dst,0,sizeof(struct url));
		dst->original_url = strdup(src);
		dst->extra_free_me1 = strdup(src);
		if (!dst->original_url || !dst->extra_free_me1)
			abort(); /* OOM */
		dst->schema = "mailto";
		dst->emailaddr = dst->extra_free_me1+7;
		i = 7;
		goto GOT_PATH; /* for ?-string processing */
	}

	/* TODO special case: news urls might not have // */

	for (i = 0; src[i]; i++) {
		if (src[i] >= 'A' && src[i] <= 'Z') continue;
		if (src[i] >= 'a' && src[i] <= 'z') continue;
		if (src[i] == ':') {
			if (src[i+1] == '/'
			&&  src[i+2] == '/') {
				break;
			}
		}
		return 0; /* fail */
	}
	if (!src[i]) return 0;

	memset(dst,0,sizeof(struct url));
	dst->original_url = strdup(src);
	dst->extra_free_me1 = strdup(src);
	dst->extra_free_me2 = strdup(src);
	if (!dst->original_url || !dst->extra_free_me1 || !dst->extra_free_me2)
		abort(); /* OOM */

	dst->schema = dst->extra_free_me1;
	dst->extra_free_me1[i] = '\0'; /* : from above */
	dst->port = -1;

	i += 3;
	for (j = i; src[j]; j++) {
		if (src[j] == ':') {
			/* okay, that was _probably_ a username */
			dst->username = dst->extra_free_me1+i;
			dst->extra_free_me1[j] = '\0'; /* : from above */
			j++;
			mp = 1;
			for (i = j; src[j]; j++) {
				if (mp) {
					/* maybe port */
					if (src[j] >= '0' && src[j] <= '9') {
						continue;
					} else if (src[j] == '/') {
						/* that was hostname:port! */
						dst->hostname = dst->username;
						dst->username = NULL;
						dst->path = dst->extra_free_me2 + j;
						dst->extra_free_me1[j] = '\0';
						dst->port = atoi(dst->extra_free_me1+i);
						i = j;
						goto GOT_PATH;
					}
					mp = 0;
				}

				if (src[j] == '@') {
					dst->password = dst->extra_free_me1+i;
					dst->extra_free_me1[j] = '\0'; /* : from above */
					j++;
					dst->hostname = dst->extra_free_me1+j;
					i = j;
					goto GOT_HOSTNAME;
				} else if (src[j] == '/' || src[j] == ':') {
					goto FAIL;
				}
			}
			goto FAIL;
		} else if (src[j] == '@') {
			/* okay, that was a username */
			dst->username = dst->extra_free_me1+i;
			dst->extra_free_me1[j] = '\0'; /* : from above */
			j++;
			dst->hostname = dst->extra_free_me1+j;
			i = j;
			goto GOT_HOSTNAME;
		} else if (src[j] == '/') {
			/* hostname */
			dst->hostname = dst->extra_free_me1+i;
			dst->extra_free_me1[j] = '\0'; /* : from above */
			dst->path = dst->extra_free_me2 + j;
			i = j;
			goto GOT_PATH;
		}
	}
	/* hostname _only; no path */
	_decode(dst->username);
	_decode(dst->password);
	_decode(dst->hostname);
	dst->path = "/";
	dst->hostname = dst->extra_free_me1 + i;
	goto FINISH;

GOT_HOSTNAME:
	/* i points to the first word of the hostname */
	for (j = i; src[j]; j++) {
		if (src[j] == ':') {
			/* port */
			dst->extra_free_me1[j] = '\0';
			j++;
			for (i = j; src[j]; j++) {
				if (src[j] >= '0' && src[j] <= '9') continue;
				if (src[j] != '/') goto FAIL;
				dst->extra_free_me1[j] = '\0';
				dst->port = atoi(dst->extra_free_me1+i);
				j++;
				i = j;
				dst->path = dst->extra_free_me2 + j;
				goto GOT_PATH;
			}
			/* hostname:port */
			dst->port = atoi(dst->extra_free_me1+i);
			dst->path = "/";
			goto GOT_PATH;
		} else if (src[j] == '/') {
			dst->extra_free_me1[j] = '\0';
			dst->path = dst->extra_free_me2 + j;
			i = j;
			goto GOT_PATH;
		} else if (src[j] == '@') {
			goto FAIL;
		}
	}
	_decode(dst->username);
	_decode(dst->password);
	_decode(dst->hostname);
	dst->path = "/";
	goto FINISH;

GOT_PATH:
	_decode(dst->username);
	_decode(dst->password);
	_decode(dst->hostname);

	/* i points to the first word of the path */
	for (j = i; src[j]; j++) {
		if (src[j] == '?') { 
			dst->querystr = dst->extra_free_me2+(j+1);
			dst->extra_free_me2[j] = '\0';
			j++;
			for (i = j; src[j]; j++) {
				if (src[j] == '#') {
					dst->fragment = dst->extra_free_me2+(j+1);
					dst->extra_free_me2[j] = '\0';
					_decode(dst->fragment);
					goto FINISH;
				}
			}
			break;

		} else if (src[j] == '#') {
			dst->fragment = dst->extra_free_me2+(j+1);
			dst->extra_free_me2[j] = '\0';
			_decode(dst->fragment);
			goto FINISH;
		}
	}

FINISH:
	for (i = 0; dst->schema[i]; i++)
		dst->schema[i] = tolower(((unsigned)dst->schema[i]));
	if (!strcmp(dst->schema, "file")) {
		if (dst->hostname && !dst->hostname[0])
			dst->hostname = NULL;
	} else if (!dst->hostname || !dst->hostname[0]) {
		if (!strcmp(dst->schema, "news") || !strcmp(dst->schema, "mailto")) {
			/* no valid thing as a hostname */
		} else {
			/* hostname required */
			goto FAIL;
		}
	}

	if (dst->port == -1) {
		if (!strcmp(dst->schema, "http")) {
			dst->port = 80;
		} else if (!strcmp(dst->schema, "https")) {
			dst->port = 443;
		} else if (!strcmp(dst->schema, "ftp")) {
			dst->port = 21;
		} else if (!strcmp(dst->schema, "gopher")) {
			dst->port = 70;
		} else if (!strcmp(dst->schema, "mailto")) {
			/* NA */
		} else if (!strcmp(dst->schema, "news")) {
			/* NA */
		} else if (!strcmp(dst->schema, "file")) {
			/* NA */
		} else if (!strcmp(dst->schema, "nntp")) {
			dst->port = 119;
		} else if (!strcmp(dst->schema, "ssh")) {
			dst->port = 22;
		} else if (!strcmp(dst->schema, "sftp")) {
			dst->port = 22;
		} else if (!strcmp(dst->schema, "ssh1")) {
			dst->port = 22;
		} else if (!strcmp(dst->schema, "ssh2")) {
			dst->port = 22;
		}
	}

	return 1;
FAIL:
	free(dst->original_url);
	free(dst->extra_free_me1);
	free(dst->extra_free_me2);
	free(dst->extra_free_me3);
	free(dst->extra_free_me4);
	memset(dst,0,sizeof(struct url));
	return 0;
}


void url_free(struct url *dst)
{
	free(dst->original_url);
	free(dst->extra_free_me1);
	free(dst->extra_free_me2);
	free(dst->extra_free_me3);
	free(dst->extra_free_me4);
	memset(dst,0,sizeof(struct url));
}

