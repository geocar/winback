#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>

#include "fout.h"
#include "urlparse.h"
#include "local.h"

static void _ftp_mkdir(void *x, const char *fn)
{
	(void)FtpCreateDirectory((HINTERNET)x, fn);
}
static int _ftp_writer(struct fout *ff, const void *buf, int len)
{
	DWORD did;
	int r, r1,r2,r3;

	if (!buf && len < 0) {
		r = GetLastError();
		r1=InternetCloseHandle((HINTERNET)ff->x_c);
		if (!r1) r = GetLastError();

		if (ff->aborted) {
			(void)FtpDeleteFile((HINTERNET)ff->x_b, ff->fn);
		} else {
			if (!FtpRenameFile((HINTERNET)ff->x_b, ff->fn, ff->x_d)) {
				r1=1;
				r = GetLastError();
			}
		}

		free(ff->x_d);

		r2=InternetCloseHandle((HINTERNET)ff->x_b);
		if (!r2) r = GetLastError();
		r3=InternetCloseHandle((HINTERNET)ff->x_a);
		if (!r2) r = GetLastError();

		if (r3 || r2 || r1) SetLastError(r);
		if (!r1 || !r2 || !r3) return 0;
		return 1;
	}
RETRY:	if (!InternetWriteFile((HINTERNET)ff->x_c, buf, len, &did)) return 0;
	if (did < len) {
		buf = ((char*)buf) + did;
		len -= did;
		Sleep(100);
		goto RETRY;
	}
	return 1;
}

int fout_ftp_setup(struct fout *ff, struct url *uu, const char *fn)
{
	HINTERNET h1, h2, h3;
	static int counter = 1234;
	char *tmp, *tmp2;
	FILETIME now;
	int r;

	h1 = InternetOpen("winback/0",
			INTERNET_OPEN_TYPE_PRECONFIG,
			NULL, NULL,
			0);
	if (!h1) return 0;

	h2 = InternetConnect(h1, uu->hostname,
			((uu->port < 1)
				? INTERNET_DEFAULT_FTP_PORT
				: uu->port),
			uu->username,
			uu->password,
			INTERNET_SERVICE_FTP,
			INTERNET_FLAG_PASSIVE,
			0);
	if (!h2) {
		r = GetLastError();
		InternetCloseHandle(h1);
		SetLastError(r);
		return 0;
	}

	if (!FtpSetCurrentDirectory(h2, uu->path)) goto FAIL;
	tmp = ensure_directories_exist(_ftp_mkdir, h2, fn, '/');

	tmp2 = malloc(strlen(tmp) + 128);
	if (!tmp2) abort();
	GetSystemTimeAsFileTime(&now);
	sprintf(tmp2, "%s.%lu.%lu.%d.~tmp", tmp,
			(unsigned long)now.dwLowDateTime,
			(unsigned long)now.dwHighDateTime,
			counter);
	counter++;

	h3 = FtpOpenFile(h2, tmp2,
			GENERIC_WRITE,
			FTP_TRANSFER_TYPE_BINARY,
			0);
	if (!h3) {
		goto FAIL;
	}

	ff->fn = tmp2;
	ff->x = (void*)ff;
	ff->x_a = h1;
	ff->x_b = h2;
	ff->x_c = h3;
	ff->x_d = (void*)strdup(tmp);
	if (!ff->fn || !ff->x_d) abort();
	ff->fun = _ftp_writer;
	return 1;

FAIL:
	win32_perror("FtpOpenFile");
	r = GetLastError();
	(void)InternetCloseHandle(h2);
	(void)InternetCloseHandle(h1);
	SetLastError(r);
	return 0;
}
