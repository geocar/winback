#include <stdlib.h>
#include <string.h>

char *ensure_directories_exist(
		void (*fun)(void *a, const char *d),
		void *a,
		const char *fn,
		int pathsep)
{
	static char *q = NULL;
	int i;

	q = realloc(q, strlen(fn)+8);
	if (!q) abort();

	for (i = 0; fn[i]; i++) {
		if (fn[i] == '\\') {
			q[i] = '\0';
			fun(a,q);
			q[i] = pathsep;
		} else {
			q[i] = fn[i];
		}
	}
	q[i] = '\0';
	return q;
}
