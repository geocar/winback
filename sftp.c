/*
 * this actually glues putty and winback
 * it is based heavily on winsftp, winplink and psftp from putty
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <limits.h>

#include "local.h"
#include "urlparse.h"
#include "fout.h"

#define PUTTY_DO_GLOBALS
#include "putty.h"
#include "psftp.h"
#include "storage.h"
#include "ssh.h"
#include "sftp.h"
#include "int64.h"


int term_ldisc(Terminal *term, int mode)
{
    return FALSE;
}
void ldisc_update(void *frontend, int echo, int edit)
{
}



static char *pwd;
/*
 * Attempt to canonify a pathname starting from the pwd. If
 * canonification fails, at least fall back to returning a _valid_
 * pathname (though it may be ugly, eg /home/simon/../foobar).
 */
char *canonify(const char *name)
{
    char *fullname, *canonname;
    struct sftp_packet *pktin;
    struct sftp_request *req, *rreq;

    if (name[0] == '/') {
	fullname = dupstr(name);
    } else {
	char *slash;
	if (pwd[strlen(pwd) - 1] == '/')
	    slash = "";
	else
	    slash = "/";
	fullname = dupcat(pwd, slash, name, NULL);
    }

    sftp_register(req = fxp_realpath_send(fullname));
    rreq = sftp_find_request(pktin = sftp_recv());
    assert(rreq == req);
    canonname = fxp_realpath_recv(pktin, rreq);

    if (canonname) {
	sfree(fullname);
	return canonname;
    } else {
	/*
	 * Attempt number 2. Some FXP_REALPATH implementations
	 * (glibc-based ones, in particular) require the _whole_
	 * path to point to something that exists, whereas others
	 * (BSD-based) only require all but the last component to
	 * exist. So if the first call failed, we should strip off
	 * everything from the last slash onwards and try again,
	 * then put the final component back on.
	 * 
	 * Special cases:
	 * 
	 *  - if the last component is "/." or "/..", then we don't
	 *    bother trying this because there's no way it can work.
	 * 
	 *  - if the thing actually ends with a "/", we remove it
	 *    before we start. Except if the string is "/" itself
	 *    (although I can't see why we'd have got here if so,
	 *    because surely "/" would have worked the first
	 *    time?), in which case we don't bother.
	 * 
	 *  - if there's no slash in the string at all, give up in
	 *    confusion (we expect at least one because of the way
	 *    we constructed the string).
	 */

	int i;
	char *returnname;

	i = strlen(fullname);
	if (i > 2 && fullname[i - 1] == '/')
	    fullname[--i] = '\0';      /* strip trailing / unless at pos 0 */
	while (i > 0 && fullname[--i] != '/');

	/*
	 * Give up on special cases.
	 */
	if (fullname[i] != '/' ||      /* no slash at all */
	    !strcmp(fullname + i, "/.") ||	/* ends in /. */
	    !strcmp(fullname + i, "/..") ||	/* ends in /.. */
	    !strcmp(fullname, "/")) {
	    return fullname;
	}

	/*
	 * Now i points at the slash. Deal with the final special
	 * case i==0 (ie the whole path was "/nonexistentfile").
	 */
	fullname[i] = '\0';	       /* separate the string */
	if (i == 0) {
	    sftp_register(req = fxp_realpath_send("/"));
	} else {
	    sftp_register(req = fxp_realpath_send(fullname));
	}
	rreq = sftp_find_request(pktin = sftp_recv());
	assert(rreq == req);
	canonname = fxp_realpath_recv(pktin, rreq);

	if (!canonname) {
	    /* Even that failed. Restore our best guess at the
	     * constructed filename and give up */
	    fullname[i] = '/';	/* restore slash and last component */
	    return fullname;
	}

	/*
	 * We have a canonical name for all but the last path
	 * component. Concatenate the last component and return.
	 */
	returnname = dupcat(canonname,
			    canonname[strlen(canonname) - 1] ==
			    '/' ? "" : "/", fullname + i + 1, NULL);
	sfree(fullname);
	sfree(canonname);
	return returnname;
    }
}

struct backend_list backends[] = {
    {PROT_SSH, "ssh", NULL},
    {PROT_TELNET, "telnet", NULL},
    {PROT_RLOGIN, "rlogin", NULL},
    {PROT_RAW, "raw", NULL},
    {0, NULL}
};

char *get_ttymode(void *frontend, const char *mode) { return NULL; }

static char *password_hack = NULL;

int get_userpass_input(prompts_t *p, unsigned char *in, int inlen)
{
	int i;
	if (password_hack == NULL) return 0;
	for (i = 0; i < p->n_prompts; i++) {
		if (p->prompts[i]->echo) return 0;
		strncpy(p->prompts[i]->result, password_hack, p->prompts[i]->result_len);
	}
	return 1;
}

/* ----------------------------------------------------------------------
 * File access abstraction.
 */

/*
 * Set local current directory. Returns NULL on success, or else an
 * error message which must be freed after printing.
 */
char *psftp_lcd(char *dir)
{
	char *ret = NULL;

	if (!SetCurrentDirectory(dir)) {
		LPVOID message;
		int i;
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
				FORMAT_MESSAGE_FROM_SYSTEM |
				FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL, GetLastError(),
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				(LPTSTR)&message, 0, NULL);
		i = strcspn((char *)message, "\n");
		ret = dupprintf("%.*s", i, (LPCTSTR)message);
		LocalFree(message);
	}

	return ret;
}

/*
 * Get local current directory. Returns a string which must be
 * freed.
 */
char *psftp_getcwd(void)
{
	char *ret = snewn(256, char);
	int len = GetCurrentDirectory(256, ret);
	if (len > 256)
		ret = sresize(ret, len, char);
	GetCurrentDirectory(len, ret);
	return ret;
}

#define TIME_POSIX_TO_WIN(t, ft) (*(LONGLONG*)&(ft) = \
		((LONGLONG) (t) + (LONGLONG) 11644473600) * (LONGLONG) 10000000)
#define TIME_WIN_TO_POSIX(ft, t) ((t) = (unsigned long) \
		((*(LONGLONG*)&(ft)) / (LONGLONG) 10000000 - (LONGLONG) 11644473600))

struct RFile {
	HANDLE h;
};


/* Seek offset bytes through file, from whence, where whence is
   FROM_START, FROM_CURRENT, or FROM_END */
int file_type(char *name)
{
	DWORD attr;
	attr = GetFileAttributes(name);
	/* We know of no `weird' files under Windows. */
	if (attr == (DWORD)-1)
		return FILE_TYPE_NONEXISTENT;
	else if (attr & FILE_ATTRIBUTE_DIRECTORY)
		return FILE_TYPE_DIRECTORY;
	else
		return FILE_TYPE_FILE;
}

struct DirHandle {
	HANDLE h;
	char *name;
};

DirHandle *open_directory(char *name)
{
	HANDLE h;
	WIN32_FIND_DATA fdat;
	char *findfile;
	DirHandle *ret;

	/* Enumerate files in dir `foo'. */
	findfile = dupcat(name, "/*", NULL);
	h = FindFirstFile(findfile, &fdat);
	if (h == INVALID_HANDLE_VALUE)
		return NULL;
	sfree(findfile);

	ret = snew(DirHandle);
	ret->h = h;
	ret->name = dupstr(fdat.cFileName);
	return ret;
}

char *read_filename(DirHandle *dir)
{
	do {

		if (!dir->name) {
			WIN32_FIND_DATA fdat;
			int ok = FindNextFile(dir->h, &fdat);
			if (!ok)
				return NULL;
			else
				dir->name = dupstr(fdat.cFileName);
		}

		assert(dir->name);
		if (dir->name[0] == '.' &&
				(dir->name[1] == '\0' ||
				 (dir->name[1] == '.' && dir->name[2] == '\0'))) {
			sfree(dir->name);
			dir->name = NULL;
		}

	} while (!dir->name);

	if (dir->name) {
		char *ret = dir->name;
		dir->name = NULL;
		return ret;
	} else
		return NULL;
}

void close_directory(DirHandle *dir)
{
	FindClose(dir->h);
	if (dir->name)
		sfree(dir->name);
	sfree(dir);
}

int test_wildcard(char *name, int cmdline)
{
	HANDLE fh;
	WIN32_FIND_DATA fdat;

	/* First see if the exact name exists. */
	if (GetFileAttributes(name) != (DWORD)-1)
		return WCTYPE_FILENAME;

	/* Otherwise see if a wildcard match finds anything. */
	fh = FindFirstFile(name, &fdat);
	if (fh == INVALID_HANDLE_VALUE)
		return WCTYPE_NONEXISTENT;

	FindClose(fh);
	return WCTYPE_WILDCARD;
}

struct WildcardMatcher {
	HANDLE h;
	char *name;
	char *srcpath;
};

/*
 * Return a pointer to the portion of str that comes after the last
 * slash (or backslash or colon, if `local' is TRUE).
 */
static char *stripslashes(char *str, int local)
{
	char *p;

	if (local) {
		p = strchr(str, ':');
		if (p) str = p+1;
	}

	p = strrchr(str, '/');
	if (p) str = p+1;

	if (local) {
		p = strrchr(str, '\\');
		if (p) str = p+1;
	}

	return str;
}

WildcardMatcher *begin_wildcard_matching(char *name)
{
	HANDLE h;
	WIN32_FIND_DATA fdat;
	WildcardMatcher *ret;
	char *last;

	h = FindFirstFile(name, &fdat);
	if (h == INVALID_HANDLE_VALUE)
		return NULL;

	ret = snew(WildcardMatcher);
	ret->h = h;
	ret->srcpath = dupstr(name);
	last = stripslashes(ret->srcpath, 1);
	*last = '\0';
	if (fdat.cFileName[0] == '.' &&
			(fdat.cFileName[1] == '\0' ||
			 (fdat.cFileName[1] == '.' && fdat.cFileName[2] == '\0')))
		ret->name = NULL;
	else
		ret->name = dupcat(ret->srcpath, fdat.cFileName, NULL);

	return ret;
}

char *wildcard_get_filename(WildcardMatcher *dir)
{
	while (!dir->name) {
		WIN32_FIND_DATA fdat;
		int ok = FindNextFile(dir->h, &fdat);

		if (!ok)
			return NULL;

		if (fdat.cFileName[0] == '.' &&
				(fdat.cFileName[1] == '\0' ||
				 (fdat.cFileName[1] == '.' && fdat.cFileName[2] == '\0')))
			dir->name = NULL;
		else
			dir->name = dupcat(dir->srcpath, fdat.cFileName, NULL);
	}

	if (dir->name) {
		char *ret = dir->name;
		dir->name = NULL;
		return ret;
	} else
		return NULL;
}

void finish_wildcard_matching(WildcardMatcher *dir)
{
	FindClose(dir->h);
	if (dir->name)
		sfree(dir->name);
	sfree(dir->srcpath);
	sfree(dir);
}

int vet_filename(char *name)
{
	if (strchr(name, '/') || strchr(name, '\\') || strchr(name, ':'))
		return FALSE;

	if (!name[strspn(name, ".")])      /* entirely composed of dots */
		return FALSE;

	return TRUE;
}

int create_directory(char *name)
{
	return CreateDirectory(name, NULL) != 0;
}

char *dir_file_cat(char *dir, char *file)
{
	return dupcat(dir, "\\", file, NULL);
}


/* ----------------------------------------------------------------------
 * Platform-specific network handling.
 */

/*
 * Be told what socket we're supposed to be using.
 */
static SOCKET sftp_ssh_socket = INVALID_SOCKET;
static HANDLE netevent = INVALID_HANDLE_VALUE;
char *do_select(SOCKET skt, int startup)
{
	int events;
	if (startup)
		sftp_ssh_socket = skt;
	else
		sftp_ssh_socket = INVALID_SOCKET;

	if (p_WSAEventSelect) {
		if (startup) {
			events = (FD_CONNECT | FD_READ | FD_WRITE |
					FD_OOB | FD_CLOSE | FD_ACCEPT);
			netevent = CreateEvent(NULL, FALSE, FALSE, NULL);
		} else {
			events = 0;
		}
		if (p_WSAEventSelect(skt, netevent, events) == SOCKET_ERROR) {
			switch (p_WSAGetLastError()) {
				case WSAENETDOWN:
					return "Network is down";
				default:
					return "WSAEventSelect(): unknown error";
			}
		}
	}
	return NULL;
}
extern int select_result(WPARAM, LPARAM);

int do_eventsel_loop(HANDLE other_event)
{
	int n, nhandles, nallhandles, netindex, otherindex;
	long next, ticks;
	HANDLE *handles;
	SOCKET *sklist;
	int skcount;
	long now = GETTICKCOUNT();

	if (run_timers(now, &next)) {
		ticks = next - GETTICKCOUNT();
		if (ticks < 0) ticks = 0;  /* just in case */
	} else {
		ticks = INFINITE;
	}

	handles = handle_get_events(&nhandles);
	handles = sresize(handles, nhandles+2, HANDLE);
	nallhandles = nhandles;

	if (netevent != INVALID_HANDLE_VALUE)
		handles[netindex = nallhandles++] = netevent;
	else
		netindex = -1;
	if (other_event != INVALID_HANDLE_VALUE)
		handles[otherindex = nallhandles++] = other_event;
	else
		otherindex = -1;

	n = WaitForMultipleObjects(nallhandles, handles, FALSE, ticks);

	if ((unsigned)(n - WAIT_OBJECT_0) < (unsigned)nhandles) {
		handle_got_event(handles[n - WAIT_OBJECT_0]);
	} else if (netindex >= 0 && n == WAIT_OBJECT_0 + netindex) {
		WSANETWORKEVENTS things;
		SOCKET socket;
		extern SOCKET first_socket(int *), next_socket(int *);
		extern int select_result(WPARAM, LPARAM);
		int i, socketstate;

		/*
		 * We must not call select_result() for any socket
		 * until we have finished enumerating within the
		 * tree. This is because select_result() may close
		 * the socket and modify the tree.
		 */
		/* Count the active sockets. */
		i = 0;
		for (socket = first_socket(&socketstate);
				socket != INVALID_SOCKET;
				socket = next_socket(&socketstate)) i++;

		/* Expand the buffer if necessary. */
		sklist = snewn(i, SOCKET);

		/* Retrieve the sockets into sklist. */
		skcount = 0;
		for (socket = first_socket(&socketstate);
				socket != INVALID_SOCKET;
				socket = next_socket(&socketstate)) {
			sklist[skcount++] = socket;
		}

		/* Now we're done enumerating; go through the list. */
		for (i = 0; i < skcount; i++) {
			WPARAM wp;
			socket = sklist[i];
			wp = (WPARAM) socket;
			if (!p_WSAEnumNetworkEvents(socket, NULL, &things)) {
				static const struct { int bit, mask; } eventtypes[] = {
					{FD_CONNECT_BIT, FD_CONNECT},
					{FD_READ_BIT, FD_READ},
					{FD_CLOSE_BIT, FD_CLOSE},
					{FD_OOB_BIT, FD_OOB},
					{FD_WRITE_BIT, FD_WRITE},
					{FD_ACCEPT_BIT, FD_ACCEPT},
				};
				int e;

				noise_ultralight(socket);
				noise_ultralight(things.lNetworkEvents);

				for (e = 0; e < lenof(eventtypes); e++)
					if (things.lNetworkEvents & eventtypes[e].mask) {
						LPARAM lp;
						int err = things.iErrorCode[eventtypes[e].bit];
						lp = WSAMAKESELECTREPLY(eventtypes[e].mask, err);
						select_result(wp, lp);
					}
			}
		}

		sfree(sklist);
	}

	sfree(handles);

	if (n == WAIT_TIMEOUT) {
		now = next;
	} else {
		now = GETTICKCOUNT();
	}

	if (otherindex >= 0 && n == WAIT_OBJECT_0 + otherindex)
		return 1;

	return 0;
}

/*
 * Wait for some network data and process it.
 *
 * We have two variants of this function. One uses select() so that
 * it's compatible with WinSock 1. The other uses WSAEventSelect
 * and MsgWaitForMultipleObjects, so that we can consistently use
 * WSAEventSelect throughout; this enables us to also implement
 * ssh_sftp_get_cmdline() using a parallel mechanism.
 */
int ssh_sftp_loop_iteration(void)
{
	if (p_WSAEventSelect == NULL) {
		fd_set readfds;
		int ret;
		long now = GETTICKCOUNT();

		if (sftp_ssh_socket == INVALID_SOCKET)
			return -1;		       /* doom */

		if (socket_writable(sftp_ssh_socket))
			select_result((WPARAM) sftp_ssh_socket, (LPARAM) FD_WRITE);

		do {
			long next, ticks;
			struct timeval tv, *ptv;

			if (run_timers(now, &next)) {
				ticks = next - GETTICKCOUNT();
				if (ticks <= 0)
					ticks = 1;	       /* just in case */
				tv.tv_sec = ticks / 1000;
				tv.tv_usec = ticks % 1000 * 1000;
				ptv = &tv;
			} else {
				ptv = NULL;
			}

			FD_ZERO(&readfds);
			FD_SET(sftp_ssh_socket, &readfds);
			ret = p_select(1, &readfds, NULL, NULL, ptv);

			if (ret < 0)
				return -1;		       /* doom */
			else if (ret == 0)
				now = next;
			else
				now = GETTICKCOUNT();

		} while (ret == 0);

		select_result((WPARAM) sftp_ssh_socket, (LPARAM) FD_READ);

		return 0;
	} else {
		return do_eventsel_loop(INVALID_HANDLE_VALUE);
	}
}

/*
 * Read a command line from standard input.
 * 
 * In the presence of WinSock 2, we can use WSAEventSelect to
 * mediate between the socket and stdin, meaning we can send
 * keepalives and respond to server events even while waiting at
 * the PSFTP command prompt. Without WS2, we fall back to a simple
 * fgets.
 */
struct command_read_ctx {
	HANDLE event;
	char *line;
};

static DWORD WINAPI command_read_thread(void *param)
{
	struct command_read_ctx *ctx = (struct command_read_ctx *) param;

	ctx->line = fgetline(stdin);

	SetEvent(ctx->event);

	return 0;
}

char *ssh_sftp_get_cmdline(char *prompt, int no_fds_ok)
{
	int ret;
	struct command_read_ctx actx, *ctx = &actx;
	DWORD threadid;

	fputs(prompt, stdout);
	fflush(stdout);

	if ((sftp_ssh_socket == INVALID_SOCKET && no_fds_ok) ||
			p_WSAEventSelect == NULL) {
		return fgetline(stdin);	       /* very simple */
	}

	/*
	 * Create a second thread to read from stdin. Process network
	 * and timing events until it terminates.
	 */
	ctx->event = CreateEvent(NULL, FALSE, FALSE, NULL);
	ctx->line = NULL;

	if (!CreateThread(NULL, 0, command_read_thread,
				ctx, 0, &threadid)) {
		fprintf(stderr, "Unable to create command input thread\n");
		cleanup_exit(1);
	}

	do {
		ret = do_eventsel_loop(ctx->event);

		/* Error return can only occur if netevent==NULL, and it ain't. */
		assert(ret >= 0);
	} while (ret == 0);

	return ctx->line;
}

static Backend *back = NULL;
static void* backhandle = NULL;

static void _sftp_mkdir(void *x, const char *fn)
{
	struct sftp_packet *pktin;
	struct sftp_request *req, *rreq;

	sftp_register(req = fxp_mkdir_send((char*)fn));
	rreq = sftp_find_request(pktin = sftp_recv());
	assert(rreq = req);
	(void)fxp_mkdir_recv(pktin, rreq);
}

static int _sftp_writer(struct fout *ff, const void *buf, int len)
{
	struct fxp_handle *fh;
	struct fxp_xfer *xfer;
	struct sftp_packet *pktin;
	struct sftp_request *req, *rreq;
	int ret;

	xfer = (struct fxp_xfer *)ff->x_a;
	fh = (struct fxp_handle *)ff->x_b;

	if (!buf && len < 0) {
		xfer_cleanup(xfer);

		sftp_register(req = fxp_close_send(fh));
		rreq = sftp_find_request(pktin = sftp_recv());
		assert(rreq == req);
		fxp_close_recv(pktin, rreq);

		/* still here? rename time! */
		if (!ff->aborted) {
			sftp_register(req = fxp_rename_send((char*)ff->x_d, (char*)ff->fn));
			rreq = sftp_find_request(pktin = sftp_recv());
			assert(rreq == req);
			(void)fxp_rename_recv(pktin, rreq);
		} else {
			sftp_register(req = fxp_remove_send((char*)ff->x_d));
			req = sftp_find_request(pktin = sftp_recv());
			assert(rreq == req);
			(void)fxp_remove_recv(pktin, rreq);
		}

		free(ff->x_d);
		sfree(ff->x_c);
		return 1;
	}

	xfer_upload_data(xfer, (void*)buf, len);

	if (!xfer_done(xfer)) {
		pktin = sftp_recv();
		ret = xfer_upload_gotpkt(xfer, pktin);
		if (!ret) {
			ff->aborted = 1;
			return 0;
		}
	}
	return 1;
}


int fout_ssh_setup(struct fout *ff, struct url *uu,
				const char *fn, int protocol)
{
	static int virgin = 1;
	static int counter = 1234;
	FILETIME now;
	static Config cfg;
	struct fxp_handle *fh;
	struct fxp_xfer *xfer;
	struct sftp_packet *pktin;
	struct sftp_request *req, *rreq;
	char *realhost, *homedir;
	char *tmp, *tmp2;
	char *dir;
	void *logctx;

	char *err;
	int tries;

	if (virgin) {
		sk_init();
		virgin = 0;
	}

	if (uu->password) {
		password_hack = strdup(uu->password);
		if (!password_hack) abort();
	} else {
		free(password_hack);
		password_hack = NULL;
	}


	tmp = NULL;
	tmp2 = NULL;
	if (back != NULL) goto READY;

	memset(&cfg, 0, sizeof(cfg));
	do_defaults(NULL, &cfg);
	strcpy(cfg.host, uu->hostname);
	cfg.protocol = PROT_SSH;
	cfg.port = uu->port > 0 ? uu->port : 22;
	switch (protocol) {
	case FOUT_SSH_SFTP:
		cfg.sshprot = 2;
		break;
	case FOUT_SSH_SSH2:
		cfg.sshprot = 2;
		break;
	case FOUT_SSH_SSH1:
		cfg.sshprot = 2;
		break;
	case FOUT_SSH_ANY:
		cfg.sshprot = 3;
		break;
	};
	strcpy(cfg.username, uu->username);
	strcpy(cfg.remote_cmd, "sftp");
	cfg.ssh_subsys = TRUE;
	cfg.nopty = TRUE;
	if (protocol != FOUT_SSH_SFTP) {
		/* try to make sftp work */
		cfg.remote_cmd_ptr2 =
			"test -x /usr/lib/sftp-server && exec /usr/lib/sftp-server\n"
			"test -x /usr/local/lib/sftp-server && exec /usr/local/lib/sftp-server\n"
			"exec sftp-server";
		cfg.ssh_subsys2 = FALSE;
	}
	back = &ssh_backend;
	err = (void*)back->init(NULL, &backhandle, &cfg, cfg.host, cfg.port, &realhost,
			0, cfg.tcp_keepalives);
	if (err != NULL) {
		fprintf(stderr, "ssh_init: %s\n", err);
		goto FAIL;
	}
	logctx = log_init(NULL, &cfg);
	back->provide_logctx(backhandle, logctx);
	console_provide_logctx(logctx);
	while (!back->sendok(backhandle)) {
		if (ssh_sftp_loop_iteration() < 0) {
			fprintf(stderr, "ssh_init: error during SSH connection setup\n");
			goto FAIL;
		}
		if (!back->connected(backhandle)) {
			fprintf(stderr, "ssh_init: unexpectedly disconnected\n");
			goto FAIL;
		}
	}
	if (realhost != NULL) free(realhost);
	sftp_register(req = fxp_realpath_send(uu->path));
	rreq = sftp_find_request(pktin = sftp_recv());
	assert(rreq == req);
	homedir = fxp_realpath_recv(pktin, rreq);
	if (!homedir) {
		fprintf(stderr, "ssh_init: cannot resolve home directory\n");
		goto FAIL;
	}

	pwd = dupstr(homedir);
READY:
	dir = canonify(fn);
	if (!dir) abort();
	tmp = ensure_directories_exist(_sftp_mkdir, NULL, dir, '/');
	tmp2 = malloc(strlen(tmp)+128);
	if (!tmp2) abort();

	for (tries = 0; tries < 100; tries++) {
		GetSystemTimeAsFileTime(&now);
		sprintf(tmp2, "%s.%lu.%lu.%d.~tmp", tmp,
				(unsigned long)now.dwLowDateTime,
				(unsigned long)now.dwHighDateTime,
				counter);
		counter++;
	
		sftp_register(req = fxp_open_send(tmp2, SSH_FXF_WRITE | SSH_FXF_CREAT));
		rreq = sftp_find_request(pktin = sftp_recv());
		assert(rreq == req);
					
		fh = fxp_open_recv(pktin, rreq);
		if (!fh) continue;

		xfer = xfer_upload_init(fh, uint64_make(0,0));
		ff->x_a = (void*)xfer;
		ff->x_b = (void*)fh;
		ff->x_d = (void*)tmp2;
		ff->x_c = (void*)dir;
		ff->fn = (void*)strdup(tmp);
		if (!ff->fn) abort();
		ff->fun = _sftp_writer;
		return 1;
	}
	/* fall through */
	sfree(dir);
FAIL:
	if (back && back->free) back->free(backhandle);
	sftp_cleanup_request();
	back = NULL;
	backhandle = NULL;
	if (tmp) free(tmp);
	if (tmp2) free(tmp2);
	return 0;
}

void fatalbox(char *p, ...)
{
    va_list ap;
    fprintf(stderr, "FATAL ERROR: ");
    va_start(ap, p);
    vfprintf(stderr, p, ap);
    va_end(ap);
    fputc('\n', stderr);
    if (logctx) {
        log_free(logctx);
        logctx = NULL;
    }
    cleanup_exit(1);
}
void modalfatalbox(char *p, ...)
{
    va_list ap;
    fprintf(stderr, "FATAL ERROR: ");
    va_start(ap, p);
    vfprintf(stderr, p, ap);
    va_end(ap);
    fputc('\n', stderr);
    if (logctx) {
        log_free(logctx);
        logctx = NULL;
    }
    cleanup_exit(1);
}
void connection_fatal(void *frontend, char *p, ...)
{
    va_list ap;
    fprintf(stderr, "FATAL ERROR: ");
    va_start(ap, p);
    vfprintf(stderr, p, ap);
    va_end(ap);
    fputc('\n', stderr);
    if (logctx) {
        log_free(logctx);
        logctx = NULL;
    }
    cleanup_exit(1);
}


static unsigned char *outptr;	       /* where to put the data */
static unsigned outlen;		       /* how much data required */
static unsigned char *pending = NULL;  /* any spare data */
static unsigned pendlen = 0, pendsize = 0;	/* length and phys. size of buffer */
int from_backend(void *frontend, int is_stderr, const char *data, int datalen)
{
    unsigned char *p = (unsigned char *) data;
    unsigned len = (unsigned) datalen;

    /*
     * stderr data is just spouted to local stderr and otherwise
     * ignored.
     */
    if (is_stderr) {
	if (len > 0)
	    fwrite(data, 1, len, stderr);
	return 0;
    }

    /*
     * If this is before the real session begins, just return.
     */
    if (!outptr)
	return 0;

    if ((outlen > 0) && (len > 0)) {
	unsigned used = outlen;
	if (used > len)
	    used = len;
	memcpy(outptr, p, used);
	outptr += used;
	outlen -= used;
	p += used;
	len -= used;
    }

    if (len > 0) {
	if (pendsize < pendlen + len) {
	    pendsize = pendlen + len + 4096;
	    pending = sresize(pending, pendsize, unsigned char);
	}
	memcpy(pending + pendlen, p, len);
	pendlen += len;
    }

    return 0;
}
int sftp_recvdata(char *buf, int len)
{
    outptr = (unsigned char *) buf;
    outlen = len;

    /*
     * See if the pending-input block contains some of what we
     * need.
     */
    if (pendlen > 0) {
	unsigned pendused = pendlen;
	if (pendused > outlen)
	    pendused = outlen;
	memcpy(outptr, pending, pendused);
	memmove(pending, pending + pendused, pendlen - pendused);
	outptr += pendused;
	outlen -= pendused;
	pendlen -= pendused;
	if (pendlen == 0) {
	    pendsize = 0;
	    sfree(pending);
	    pending = NULL;
	}
	if (outlen == 0)
	    return 1;
    }

    while (outlen > 0) {
	if (back->exitcode(backhandle) >= 0 || ssh_sftp_loop_iteration() < 0)
	    return 0;		       /* doom */
    }

    return 1;
}
int sftp_senddata(char *buf, int len)
{
    back->send(backhandle, buf, len);
    return 1;
}

int from_backend_untrusted(void *frontend_handle, const char *data, int len)
{
    /*
     * No "untrusted" output should get here (the way the code is
     * currently, it's all diverted by FLAG_STDERR).
     */
    assert(!"Unexpected call to from_backend_untrusted()");
    return 0; /* not reached */
}
void cmdline_error(char *p, ...)
{
    va_list ap;
    fprintf(stderr, "plink: ");
    va_start(ap, p);
    vfprintf(stderr, p, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}
