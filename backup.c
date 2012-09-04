#include <windows.h>
#include <winreg.h>
#include <winsock.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>

#include "fout.h"
#include "local.h"
#include "acprint.h"

static FILE *security_vbs = NULL;

int l_flag = 0;
int e_flag = 0;
int o_flag = 0;
int n_flag = 0;
int s_flag = 0;
int v_flag = 0;
int r_flag = 0;
int m_flag = 0;
int c_flag = 0;
int checkpoint_flag = 0;

const char *dst_cf = 0;
static char buffer[65536];

int set_priv(char *privilege, int on)
{
	HANDLE              hToken;
	TOKEN_PRIVILEGES    tp;
	if (!OpenProcessToken(GetCurrentProcess(),
				TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
				&hToken))
		return FALSE;
	if (!LookupPrivilegeValue(NULL, privilege, &tp.Privileges[0].Luid))
	{
		CloseHandle(hToken);
		return FALSE;
	}
	tp.PrivilegeCount = 1;
	if (on)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, 0,
				(PTOKEN_PRIVILEGES)NULL, 0))
	{
		CloseHandle(hToken);
		return FALSE;
	}
	if (!CloseHandle(hToken))
		return FALSE;

	return TRUE;
}
int set_backup_privs(int on)
{
	int r;
	r = set_priv(SE_BACKUP_NAME,on);
	r &= set_priv(SE_RESTORE_NAME,on);
	return r;
}


void win32_perror(const char *sa)
{
	char *s;

	s=NULL;
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM
			| FORMAT_MESSAGE_ALLOCATE_BUFFER,
			NULL,
			GetLastError(),
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR)&s,
			0,
			NULL);
	if (s) {
		fprintf(stderr, "%s: %s\n", sa,s);
	}

	LocalFree(s);

}

int backupsec(HANDLE h, const char *f)
{
	PSECURITY_DESCRIPTOR sec;
	SECURITY_INFORMATION inf;
	DWORD rv;
	int r;

	if (!security_vbs) return 1;

	rv = 0;
#define ALL_SECURITY	DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION \
			| GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION
	inf = ALL_SECURITY;
	if (!GetUserObjectSecurity(h,
				&inf,
				(PSECURITY_DESCRIPTOR)buffer,
				sizeof(buffer),
				&rv)) {
		if (rv >= sizeof(buffer)) {
			sec = malloc(rv+64);
			inf = ALL_SECURITY;
			if (!GetUserObjectSecurity(h, &inf, sec, rv+64, &rv)) {
				win32_perror(f);
				set_backup_privs(0);
				if (s_flag) return 0;
			}
		} else {
			win32_perror(f);
			set_backup_privs(0);
			if (s_flag) return 0;
			return 1;
		}
		r = acprint(security_vbs, sec, f);
		free(sec);
	} else {
		r = acprint(security_vbs, (PSECURITY_DESCRIPTOR)buffer, f);
	}

	return r;
}

int backupsec2(const char *f)
{
	LPVOID lpContext;
	HANDLE h;
	LONG rc;

	lpContext = NULL;
	set_backup_privs(1);
	h = CreateFileA(f,
		STANDARD_RIGHTS_READ | ACCESS_SYSTEM_SECURITY,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN
		| FILE_FLAG_OPEN_REPARSE_POINT,
		NULL);
	if (h == INVALID_HANDLE_VALUE) {
		rc = GetLastError();
		if (rc == ERROR_FILE_NOT_FOUND) {
			set_backup_privs(0);
			return 1;
		}
		win32_perror(f);
		set_backup_privs(0);
		return 0;
	}
	if (!backupsec(h, f)) {
		rc = GetLastError();
		CloseHandle(h);
		set_backup_privs(0);
		SetLastError(rc);
		return 0;
	}
	CloseHandle(h);
	set_backup_privs(0);
	SetLastError(ERROR_SUCCESS);
	return 1;
}


int backup1(struct fout *ff, const char *f)
{
	WIN32_STREAM_ID sid;
	LPVOID lpContext;
	HANDLE h;
	DWORD rv;
	int r, n;

	lpContext = NULL;
	set_backup_privs(1);
	h = CreateFileA(f,
		FILE_READ_DATA | STANDARD_RIGHTS_READ | ACCESS_SYSTEM_SECURITY,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN
		| FILE_FLAG_OPEN_REPARSE_POINT,
		NULL);
	if (h == INVALID_HANDLE_VALUE) {
		r = GetLastError();
		if (r == ERROR_FILE_NOT_FOUND) {
			set_backup_privs(0);
			fout_abort(ff);
			return 1;
		}
		set_backup_privs(0);
		/* try to read it raw */
		if (!backup1_ntfs(ff, f)) {
			return 0;
		}
		/* hooray! it read in- get the security info */
		if (s_flag) return backupsec2(f);
		return 1;
	}

	if (!backupsec(h, f)) {
		r = GetLastError();
		CloseHandle(h);
		set_backup_privs(0);
		SetLastError(r);
		return 0;
	}

NEXT_STREAM:
	rv = 0;
	if (!BackupRead(h,(void*)&sid,20, &rv,FALSE,FALSE,&lpContext)) {
		goto FAIL;
	}
	if (rv < 2) {
		/* SUCCESS */
		(void)BackupRead(h,buffer,sizeof(buffer),&rv,TRUE,FALSE,&lpContext);
		CloseHandle(h);
		set_backup_privs(0);
		SetLastError(ERROR_SUCCESS);
		return 1;
	}

	if (rv != 20) {
		goto FAIL;
	}

	if (sid.dwStreamId != 1 || sid.dwStreamAttributes != 0
	|| sid.dwStreamNameSize > 0) {
		/* skip */
		BackupSeek(h, sid.dwStreamNameSize, 0,
				(void*)buffer, (void*)(buffer+8), &lpContext);
		BackupSeek(h, sid.Size.LowPart, sid.Size.HighPart,
				(void*)buffer, (void*)(buffer+8), &lpContext);
		goto NEXT_STREAM;
	}

	while (sid.Size.QuadPart > 0) {
		rv = 0;
		if (sid.Size.QuadPart < sizeof(buffer)) {
			n = sid.Size.QuadPart;
		} else {
			n = sizeof(buffer);
		}
		if (!BackupRead(h,buffer,n,&rv,FALSE,FALSE,&lpContext)) {
			goto FAIL;
		}
		r=rv;
		if (!r) break;
		if (!fout(ff, buffer, r)) {
			goto FAIL;
		}
	}
	goto NEXT_STREAM;
FAIL:
	r = GetLastError();
	(void)BackupRead(h,buffer,sizeof(buffer),&rv,TRUE,FALSE,&lpContext);
	CloseHandle(h);
	set_backup_privs(0);
	SetLastError(r);
	return 0;
}

static int backupf(const char *fn, const char *sfn)
{
	struct fout ff;
	int r;

	if (!fout_setup(&ff, dst_cf, sfn)) return 0;
	r = backup1(&ff, fn);
	if (!fout_close(&ff)) return 0;

	return r;
}

static void backupf2(const char *fn, const char *sfn)
{
	if (!backupf(fn, sfn)) {
		win32_perror(sfn);
		if (!c_flag) exit(EXIT_FAILURE);
		SetLastError(ERROR_SUCCESS);
	}
}
static int backupf3(FILE *fp, const char *sfn)
{
	struct fout ff;
	int r;

	if (!fout_setup(&ff, dst_cf, sfn)) return 0;
	while (!feof(fp)) {
		r = fread(buffer, 1, sizeof(buffer), fp);
		if (r > 0) {
			if (!fout(&ff, buffer, r)) {
				return 0;
			}
		}
	}
	return fout_close(&ff);
}


static int backupd(const char *s, const char *w, const char *wn)
{
	HANDLE h;
	WIN32_FIND_DATA dd;
	char *subf = NULL;
	char *tubf = NULL;
	char *wubf = NULL;
	DWORD attr;
	int r, lf, nf;

	lf = 0;
	h = FindFirstFile(s, &dd);
	if (h == INVALID_HANDLE_VALUE) {
		attr = GetFileAttributes(w);
		if (attr == INVALID_FILE_ATTRIBUTES) return 0;
		if (attr & FILE_ATTRIBUTE_DIRECTORY) return 0;
		if (attr & (FILE_ATTRIBUTE_DEVICE|FILE_ATTRIBUTE_OFFLINE|FILE_ATTRIBUTE_TEMPORARY)) return 1;

		if (attr & FILE_ATTRIBUTE_ARCHIVE) {
			if (!n_flag) {
				if (s_flag) backupsec2(w);
				return 1;
			}
			/* fall through */

		} else {
			if (!o_flag) {
				if (s_flag) backupsec2(w);
				return 1;
			}
			/* fall through */
		}

		if (v_flag) {
			puts(w);
		}
		if (!backupf(w, wn)) {
			if (c_flag) {
				win32_perror(w);
				SetLastError(ERROR_SUCCESS);
				/* fall through */
			} else {
				r = GetLastError();
				CloseHandle(h);
				SetLastError(r);
				return 0;
			}
		} else {
			SetFileAttributes(w, attr & (~FILE_ATTRIBUTE_ARCHIVE));
		}
		return 1;
	}
	do {
		if (dd.dwFileAttributes
		& (FILE_ATTRIBUTE_DEVICE|FILE_ATTRIBUTE_OFFLINE|FILE_ATTRIBUTE_TEMPORARY)) {
			/* no */
			continue;
		}

		if (strcmp(dd.cFileName,".") == 0) continue;
		if (strcmp(dd.cFileName,"..") == 0) continue;

		nf = (strlen(wn) + strlen(w) + strlen(dd.cFileName)) + 8;
		if (nf > lf) {
			subf = realloc(subf, lf = nf);
			tubf = realloc(tubf, lf = nf);
			wubf = realloc(wubf, lf = nf);
			if (!subf) abort();
			if (!tubf) abort();
			if (!wubf) abort();
		}
		sprintf(subf, "%s\\%s\\*.*", w, dd.cFileName);
		sprintf(tubf, "%s\\%s", w, dd.cFileName);
		sprintf(wubf, "%s\\%s", wn, dd.cFileName);

		if (dd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			if (s == w || w == wn) {
				sprintf(subf, "%s\\*.*", s);
				strcpy(tubf, w);
				strcpy(wubf, wn);
			}

			if (s_flag) backupsec2(tubf);

			if (!backupd(subf, tubf, wubf)) {
				if (c_flag) {
					SetLastError(ERROR_SUCCESS);
					/* fall through */
				} else {
					r = GetLastError();
					free(wubf);
					free(tubf);
					free(subf);
					CloseHandle(h);
					SetLastError(r);
					return 0;
				}
			}
			continue;

		}
		if (s == w || w == wn) {
			strcpy(tubf, w);
			strcpy(wubf, wn);
		}
		
		if (dd.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE) {
			if (!n_flag) {
				if (s_flag) backupsec2(tubf);
				continue;
			}
			/* fall through */

		} else {
			if (!o_flag) {
				if (s_flag) backupsec2(tubf);
				continue;
			}
			/* fall through */
		}
		if (v_flag) {
			puts(wubf);
		}
		if (!backupf(tubf, wubf)) {
			if (c_flag) {
				win32_perror(tubf);
				SetLastError(ERROR_SUCCESS);
				/* fall through */
			} else {
				r = GetLastError();
				free(wubf);
				free(tubf);
				free(subf);
				CloseHandle(h);
				SetLastError(r);
				return 0;
			}
		} else {
			SetFileAttributes(tubf,
				GetFileAttributes(tubf) & (~FILE_ATTRIBUTE_ARCHIVE));
		}

	} while (FindNextFile(h, &dd));
	CloseHandle(h);
	free(wubf);
	free(tubf);
	free(subf);
	SetLastError(ERROR_SUCCESS);
	return 1;
}
static void usage(const char *argv0, int lh)
{
	printf("Usage: %s [options...] files... dest\n", argv0);
	if (lh) {
		printf(
" /LOGO         Display the logo (include /VERBOSE to see license information)\n"
" /ALL          Backup everything\n"
" /NEW          Only backup files with the archive-bit set\n"
" /OLD          Backup old files (without the archive-bit set)\n"
" /EVENTS       Backup the event log\n"
" /REGISTRY     Backup the registry hives\n"
" /METABASE     Backup the IIS metabase\n"
" /SECURITY     Backup security/permission data in a file called SECURITY.VBS\n"
" /CONTINUE     Continue even if there are errors\n"
" /K            Checkpoint the output by uploading a dummy checkpoint.txt last\n"
" /VERBOSE      Print file names as they get backed up\n");
	} else {
		printf(" Use %s /HELP to get a list of options\n", argv0);
	}
}
void backup_fun(const char *fn, void *x, int (*fun)(void *x, struct fout *ff))
{
	struct fout ff;
	int r;

	if (v_flag) {
		puts(fn);
	}
	if (!fout_setup(&ff, dst_cf, fn)) goto FAIL;
	if (fun != NULL) {
		r = fun(x, &ff);
	} else {
		r = 1;
	}
	if (!fout_close(&ff)) goto FAIL;
	if (r) goto SUCCESS;
FAIL:
	if (c_flag) {
		SetLastError(ERROR_SUCCESS);
		goto SUCCESS;
	}

	win32_perror(fn);
	exit(EXIT_FAILURE);
SUCCESS:
	return;
}

int main(int argc, char *argv[])
{
	int i;
	int all_flag = 0;
	int need_exit = 0;
	int dest_argi;
	int last_file;
	WSADATA ignored;
	char *winroot;
	char *sysroot;
	char *fn, *fn2;
	DWORD dw;

	memset(&ignored, 0, sizeof(ignored));
	if (WSAStartup(0x202,&ignored) == SOCKET_ERROR) {
		win32_perror("WSASstartup");
		exit(EXIT_FAILURE);
	}

	winroot = getenv("windir");
	if (!winroot) winroot = "C:\\WINDOWS";
	sysroot = getenv("systemroot");
	if (!sysroot) sysroot=winroot;

	dest_argi = last_file = 0;
	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '/') {
			switch (argv[i][1]) {
			case 'A': case 'a': /* ALL */
				all_flag = o_flag = n_flag = s_flag = r_flag = m_flag = e_flag = 1;
				break;
			case 'L': case 'l': /* LOGO */
				l_flag = 1;
				break;
			case 'C': case 'c': /* CONTINUE */
				c_flag = 1;
				break;
			case 'N': case 'n': /* NEW */
				n_flag = 1;
				break;
			case 'O': case 'o': /* OLD */
				o_flag = 1;
				break;
			case 'R': case 'r': /* REGISTRY */
				r_flag = 1;
				break;
			case 'M': case 'm': /* METABASE */
				m_flag = 1;
				break;
			case 'E': case 'e': /* EVENTS */
				e_flag = 1;
				break;
			case 'S': case 's': /* SECURITY */
				s_flag = 1;
				break;
			case 'V': case 'v': /* verbose */
				v_flag = 1;
				break;
			case 'H': case 'h': case '?': /* help */
				usage(argv[0], 1);
				need_exit |= 1;
				break;
			case 'K': case 'k': /* checkpoint flag */
				checkpoint_flag = 1;
				break;
			default:
				printf("Unknown switch \"%s\", try /HELP\n", argv[i]);
				need_exit |= 2;
				break;
			};
		} else {
			last_file = dest_argi;
			dest_argi = i;
		}
	}
	if (l_flag) {
		printf("WINBACK to simply copy files\n"
"Copyright (C) 2008 Internet Connection, Inc.\n");

		if (v_flag) {
			printf("\n"
"WINBACK is free software; you can redistribute it and/or\n"
"modify it under the terms of the GNU General Public License as published\n"
"by the Free Software Foundation; either version 3 of the License, or\n"
"(at your option) any later version.\n"
"\n"
"This program/include file is distributed in the hope that it will be\n"
"useful, but WITHOUT ANY WARRANTY; without even the implied warranty\n"
"of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
"GNU General Public License for more details.\n"
"\n"
"You should have received a copy of the GNU General Public License\n"
"along with this program (in the main directory of the NTFS-3G\n"
"distribution in the file COPYING); if not, write to the Free Software\n"
"Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA\n"
"\n"
"PuTTY is Copyright (C) 1997-2007 Simon Tatham\n"
"Portions copyright Robert de Bath, Joris van Rantwijk, Delian Delchev,\n"
"Andreas Schultz, Jeroen Massar, Wez Furlong, Nicolas Barry, Justin Bradford,\n"
"Ben Harris, Malcolm Smith, Ahmad Khalifa, Markus Kuhn, and CORE SDI S.A.\n"
"PuTTY is redistributable under terms known as the \"MIT license\", the exact\n"
"text of which follows:\n"
"  Permission is hereby granted, free of charge, to any person obtaining a copy\n"
"  of this software and associated documentation files (the \"Software\"), to\n"
"  deal in the Software without restriction, including without limitation the\n"
"  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or\n"
"  sell copies of the Software, and to permit persons to whom the Software is\n"
"  furnished to do so, subject to the following conditions:\n"
"\n"
"  The above copyright notice and this permission notice shall be included in\n"
"  all copies or substantial portions of the Software.\n"
"\n"
"  THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS\n"
"  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n"
"  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL\n"
"  SIMON TATHAM BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER\n"
"  IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN\n"
"  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.\n"
"\n"
"libntfs-3g is Copyright (c) 2000-2005 Anton Altaparmakov,\n"
"2002-2005 Richard Russon, 2002-2006 Szabolcs Skakacsits,\n"
"and 2004-2006 Yura Pakhuchiy, and is redistributable under the terms\n"
"of the GNU General Public License as published by the Free Software\n"
"Foundation; either version 3 of the License, or (at your option)\n"
"any later version.\n\n");
		}
	}
	if ((!last_file && !r_flag && !m_flag && !e_flag) || !dest_argi) {
		usage(argv[0],0);
		exit(EXIT_FAILURE);
	}
	if (need_exit) {
		if (need_exit & 2) exit(EXIT_FAILURE);
		exit(EXIT_SUCCESS);
	}

	if (s_flag) {
		security_vbs = tmpfile();
		acprint_const(security_vbs);
	}

	dst_cf = argv[dest_argi];

	if (all_flag && !last_file) {
		/* get all drive letters */
		char root[4];
		dw = GetLogicalDrives();
		dw >>= 2; /* shift off a and b */
		root[0] = 'C';
		root[1] = ':';
		root[2] = '\\';
		root[3] = '\0';
		while (dw) {
			if (!backupd(root,root,root)) {
				win32_perror(root);
				if (c_flag) continue;
				exit(EXIT_FAILURE);
			}
			if (root[0] >= 'Z') break;
			root[0]++;
			dw >>= 1;
		}

	} else {
		for (i = 1; i <= last_file; i++) {
			if (argv[i][0] == '/') continue;
			if (!backupd(argv[i],argv[i],argv[i])) {
				win32_perror(argv[i]);
				if (c_flag) continue;
				exit(EXIT_FAILURE);
			}
		}
	}

	if (s_flag) {
		rewind(security_vbs);
		if (v_flag) {
			puts("Security.vbs");
		}
		if (!backupf3(security_vbs, "Security.vbs")) {
			win32_perror(argv[i]);
			if (!c_flag)
				exit(EXIT_FAILURE);
		}
		s_flag = 0;
	}

	if (r_flag) {
		extern void backup_reg(void);
		backup_reg();
	}

	fn = malloc(strlen(sysroot)+65);
	fn2 = malloc(strlen(sysroot)+65);

	if (m_flag) {
		sprintf(fn, "%s\\system32\\inetsrv\\metabase.bin", sysroot);
		if (!o_flag || n_flag) {
			if (v_flag) {
				puts("Metabase\\Current");
			}
			backupf2(fn, "Metabase\\Current");
		}
		if (o_flag) {
			sprintf(fn, "%s\\system32\\inetsrv\\metaback\\*.*",sysroot);
			sprintf(fn2, "%s\\system32\\inetsrv\\metaback",sysroot);
			if (!backupd(fn,fn2,"Metabase\\Backup")) {
				win32_perror("Metabase\\Backup");
				if (!c_flag) exit(EXIT_FAILURE);
			}
		}
	}
	if (e_flag) {
		sprintf(fn, "%s\\system32\\config\\*.evt", sysroot);
		sprintf(fn2, "%s\\system32\\config", sysroot);
		if (!backupd(fn,fn2,"Event Log")) {
			win32_perror("Event Log");
			if (!c_flag) exit(EXIT_FAILURE);
		}
	}
	if (checkpoint_flag) {
		/* windows time has 2-second granularity */
		Sleep(4000);
		backup_fun("checkpoint.txt", NULL, NULL);
	}

	exit(EXIT_SUCCESS);
}
