#include <windows.h>
#include <winreg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "bufout.h"
#include "local.h"

struct closure {
	HKEY top;
	const char *name;
};



static int doit2(void *x, struct fout *ff)
{
	LONG rc;
	char tmp1[_MAX_FNAME];
	char tmp2[_MAX_FNAME+16];
	int r;

	set_backup_privs(1);

RETRY:	if (GetTempPath((sizeof(tmp1)-1), tmp1) >= (sizeof(tmp1)-1)) abort();
	if (!GetTempFileName(tmp1, "HK", 0, tmp2)) abort();
	(void)unlink(tmp2);

	rc=RegSaveKey(HKEY_CLASSES_ROOT, tmp2, NULL);
	if (rc != ERROR_SUCCESS) {
		if (rc == ERROR_FILE_EXISTS) {
			Sleep(1000);
			goto RETRY;
		}
		set_backup_privs(0);
		SetLastError(rc);
		win32_perror("RegSaveKey");
		return 0;
	}
	r = backup1(ff, tmp2);

	rc=GetLastError();
	(void)unlink(tmp2);
	SetLastError(rc);
	return r;
}

static int doit1(void *x, struct fout *ff)
{
	HKEY rk;
	DWORD disp;
	LONG rc;
	char tmp1[_MAX_FNAME];
	char tmp2[_MAX_FNAME+16];
	int r;

	struct closure *cx = (struct closure *)x;

	set_backup_privs(1);

RETRY:	if (GetTempPath((sizeof(tmp1)-1), tmp1) >= (sizeof(tmp1)-1)) abort();
	if (!GetTempFileName(tmp1, "HK", 0, tmp2)) abort();
	(void)unlink(tmp2);

	rc = RegCreateKeyEx(cx->top, cx->name, 0, NULL,
			REG_OPTION_BACKUP_RESTORE,
			0,
			NULL,
			&rk,
			&disp);

	if (rc != ERROR_SUCCESS) {
		set_backup_privs(0);
		SetLastError(rc);
		win32_perror("RegOpenKeyEx");
		return 0;
	}
	rc=RegSaveKey(rk, tmp2, NULL);
	if (rc != ERROR_SUCCESS) {
		if (rc == ERROR_FILE_EXISTS) {
			Sleep(1000);
			goto RETRY;
		}
		RegCloseKey(rk);
		set_backup_privs(0);
		SetLastError(rc);
		win32_perror("RegSaveKey");
		return 0;
	}
	r = backup1(ff, tmp2);

	rc=GetLastError();
	(void)unlink(tmp2);
	RegCloseKey(rk);
	SetLastError(rc);

	return r;
}
static void doit0(HKEY top, char *basef)
{
	struct closure cx;
	char fn[(_MAX_PATH*2)+2];
	char subk[_MAX_PATH];
	DWORD idx, subklen;
	LONG rc;

	for (idx = 0;; idx++) {
		subklen = sizeof(subk);
		rc = RegEnumKeyEx(top, idx, subk, &subklen,
				NULL, NULL, NULL, NULL);
		if (rc == ERROR_NO_MORE_ITEMS) break;
		if (rc != ERROR_SUCCESS) {
			SetLastError(rc);
			win32_perror("RegSaveKey");
			exit(EXIT_FAILURE);
		}
		cx.top = top;
		cx.name = subk;
		snprintf(fn, sizeof(fn)-1, "%s\\%s", basef, subk);

		backup_fun(fn, (void*)&cx, doit1);
	}
}

void backup_reg(void)
{
	doit0(HKEY_LOCAL_MACHINE, "Registry\\HKLM");
	doit0(HKEY_USERS, "Registry\\HKU");
	backup_fun("Registry\\HKCR", NULL, doit2);
}
