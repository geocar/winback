#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "urlparse.h"

int netrc(struct url *p)
{
	FILE *fp;
	char *s, *h, *q;
	char buf[1024];
	int inside;

	h = getenv("NETRC");
	if (h) {
		fp = fopen(h, "r");
	} else {
		h = getenv("HOME");
#if defined(WIN32) || defined(_WINDOWS)
		if (!h) h = getenv("APPDATA");
#endif
		if (!h) h = "/";
		s = malloc(strlen(h) + 9);
		if (!s) abort();
		sprintf(s, "%s/.netrc", h);
		fp = fopen(s, "r");
#if defined(WIN32) || defined(_WINDOWS)
		if (!fp) {
			sprintf(s, "%s/netrc", h);
			fp = fopen(s, "r");
		}
#endif
		free(s);
	}
	if (!fp) return 0;
	inside = 0;
	while (fgets(buf, sizeof(buf)-2, fp)) {
		s = buf;
		q = strchr(s, '\r'); if (q) *q = '\0';
		q = strchr(s, '\n'); if (q) *q = '\0';
		while (isspace(((unsigned int)*s))) s++;
		if (*s == '#') continue;
		if (strncasecmp(s, "machine", 7) == 0) {
			if (inside) break;
			inside = 0;
			s += 7;
			while (isspace(((unsigned int)*s))) s++;
			if (strcasecmp(s,  p->hostname) == 0)
				inside = 1;
			continue;
		} else if (strcmp(s, "default") == 0) {
			inside = 1;
			continue;
		}
		if (!inside) continue;
		if (strncasecmp(s, "login", 5) == 0) {
			s += 5;
			while (isspace(((unsigned int)*s))) s++;
			if (!p->username) {
				p->username = strdup(s);
				if (!p->username) abort();
				free(p->extra_free_me4);
				p->extra_free_me4 = p->username;
			}
			continue;
		}
		if (strncasecmp(s, "password", 8) == 0) {
			s += 8;
			while (isspace(((unsigned int)*s))) s++;
			if (!p->password) {
				p->password = strdup(s);
				if (!p->password) abort();
				free(p->extra_free_me3);
				p->extra_free_me3 = p->password;
			}
			continue;
		}
	}
	fclose(fp);
	return 1;
}
