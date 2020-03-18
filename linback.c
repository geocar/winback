#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <netdb.h>
#include <time.h>
#include <ctype.h>

#include "urlparse.h"

#ifndef PATH_MAX
#define PATH_MAX 65536
#endif

static char *checkpoint_tmp;
static char *checkpoint_file;
static int checkpoint_fd;
static struct stat checkpoint_stat;


static int v_flag = 0;
static int c_flag = 0;
static int z_flag = 0;
static int passive_flag = 0;
static int ftp_socket = -1;
static char out_addr[4];
static int ftpsend_count = 0;

static struct sockaddr_in ftp_sin;

char ftp_response[512];

static int checkpoint_flag = 0;

static int a_flag = 0;

void ftp_check_pasv_response(void)
{
	char *x;
	int h[6];

	x = ftp_response;
	while (*x) {
		if (sscanf(x, "%d,%d,%d,%d,%d,%d",
					&h[0], &h[1], &h[2], &h[3],
					&h[4], &h[5]) == 6) break;
		x++;
	}
	if (!*x) return;
	memset(&ftp_sin, 0, sizeof(ftp_sin));
	ftp_sin.sin_family = AF_INET;
	((unsigned char *)&ftp_sin.sin_addr)[0] = h[0];
	((unsigned char *)&ftp_sin.sin_addr)[1] = h[1];
	((unsigned char *)&ftp_sin.sin_addr)[2] = h[2];
	((unsigned char *)&ftp_sin.sin_addr)[3] = h[3];
	((unsigned char *)&ftp_sin.sin_port)[0] = h[4];
	((unsigned char *)&ftp_sin.sin_port)[1] = h[5];
}

void ftpwrite(const char *buf, int buflen)
{
	int r;
	while (buflen > 0) {
		r = write(ftp_socket, buf, buflen);
		if (r > 0) {
			buf += r;
			buflen -= r;
			continue;
		}
		if (r == -1 && errno == EINTR) continue;
		fprintf(stderr, "Error from FTP server: %s\n",strerror(errno));
		if (c_flag) fprintf(stderr, "Can't continue\n");
		exit(EXIT_FAILURE);
	}
}
int ftpread(char *buf, int buflen)
{
	int r;
	do {
		r = read(ftp_socket, buf, buflen);
	} while (r == -1 && errno == EINTR);
	if (r >= 0) {
		return r;
	}
	fprintf(stderr, "Error from FTP server: %s\n",strerror(errno));
	if (c_flag) fprintf(stderr, "Can't continue\n");
	exit(EXIT_FAILURE);
}

int blast(int in, int out)
{
	static char buffer[65536], *q;
	int r, x;

	for (;;) {
		do {
			r = read(in, buffer, sizeof(buffer));
		} while (r == -1 && errno == EINTR);
		if (r == 0) return 1;
		if (r < 0) return 0;
		q = buffer;
		for (x = r; x > 0;) {
			do {
				r = write(out, q, x);
			} while (r == -1 && errno == EINTR);
			if (r < 1) return 0;
			q += r;
			x -= r;
		}
	}
}

void ftpcmd_send(const char *a, const char *b)
{
	static char buf[4096];
	int i;

	if (!a && !b) return;

	for (i = 0; *a && i < sizeof(buf); i++) {
		buf[i] = *a;
		a++;
	}
	if (i >= (sizeof(buf)-4)) abort();
	if (b) {
		buf[i] = ' ';
		i++;
		while (*b && i < sizeof(buf)) {
			buf[i] = *b;
			b++;
			i++;
		}
		if (i >= (sizeof(buf) - 3)) {
			ftpwrite(buf, i);
			if (*b) {
				ftpwrite(b, strlen(b));
			}
			ftpwrite("\r\n", 2);
		} else {
			buf[i] = '\r'; i++;
			buf[i] = '\n'; i++;
			ftpwrite(buf, i);
		}
	} else {
		buf[i] = '\r'; i++;
		buf[i] = '\n'; i++;
		ftpwrite(buf, i);
	}
	ftpsend_count++;
}
int ftpcmd_recv(void)
{
	static char buf[4096];
	int i, j, r, st, ok;

	st = 0;
	j = 0;
	ok = 0;
	if (ftpsend_count == 0) {
		fprintf(stderr, "AAACK that's not right either\n");
		abort();
	}
	ftpsend_count--;

MORE:	r = ftpread(buf, sizeof(buf));
	for (i = 0; i < r; i++) {
		if (st == 0) {
			if (buf[i] == '1' || buf[i] == '2' || buf[i] == '3') {
				ok = 1;
			} else {
				ok = 0;
			}
			st = 1;
		} else if (st == 1) {
			st = 2; /* x.x[ -].* */
		} else if (st == 2) {
			st = 3; /* xx.[ -].* */
		} else if (st == 3) {
			if (buf[i] == '-') {
				st = 4;
			} else if (buf[i] == ' ') {
				st = 5;
			} else if (buf[i] == '\r') {
				st = 6;
			} else if (buf[i] == '\n') {
				st = 7;
			}
		} else if (st == 4) {
			/* continued */
			if (buf[i] == '\n') st = 0;
		} else if (st == 5) {
			if (buf[i] == '\r') st = 6;
			if (buf[i] == '\n') {
				st = 7;
			} else if (j < (sizeof(ftp_response)-1)) {
				ftp_response[j] = buf[i];
				j++;
			}
		} else if (st == 6) {
			if (buf[i] == '\n') {
				st = 7;
			}
		}
		if (st == 7) {
			if (ftpsend_count > 0) {
				ftp_response[j] = '\0';
				if (passive_flag) ftp_check_pasv_response();
				ftpsend_count--;
				st = j = ok = 0;
			} else if ((i+1) < r) {
				fprintf(stderr, "AAACK, at 7, no more messages, WTF happened!?\n");
				abort();
			}
		}
	}
	if (st != 7) goto MORE;
	st = 0;

	ftp_response[j] = '\0';
	j--;
	if (j > 0 && ftp_response[j] == '\r') ftp_response[j] = '\0';
	if (passive_flag) ftp_check_pasv_response();
	if (ftpsend_count) {
		ftpsend_count--;
		st = j = ok = 0;
		goto MORE;
	}
	return ok;
}
int ftpcmd(const char *a, const char *b)
{
	ftpcmd_send(a,b);
	return ftpcmd_recv();
}
void ftpcmd_pipeline(const char *a, const char *b)
{
	ftpcmd_send(a,b);
}


void ftpabort(void) {
	ftpcmd("\377\376ABOR", 0);
}

int ready(const char *a, const char *b)
{
	char dummy[128];
	int sock;
	int h[6];

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) abort();

	memset(&ftp_sin, 0, sizeof(ftp_sin));
	if (passive_flag) {
		ftpcmd_pipeline("PASV",0);
	} else {
		ftp_sin.sin_family = AF_INET;
		memcpy(&ftp_sin.sin_addr, out_addr, 4);
		if (bind(sock, (struct sockaddr *)&ftp_sin, sizeof(ftp_sin)) == -1) abort();
		if (listen(sock, 1) == -1) abort();

		h[0] = sizeof(ftp_sin);
		if (getsockname(sock, (struct sockaddr *)&ftp_sin, (void*)h) == -1) {
			perror("getsockname");
			ftpabort();
			return -1;
		}
		sprintf(dummy, "%d,%d,%d,%d,%d,%d",
				((unsigned char *)&ftp_sin.sin_addr)[0],
				((unsigned char *)&ftp_sin.sin_addr)[1],
				((unsigned char *)&ftp_sin.sin_addr)[2],
				((unsigned char *)&ftp_sin.sin_addr)[3],
				((unsigned char *)&ftp_sin.sin_port)[0],
				((unsigned char *)&ftp_sin.sin_port)[1]);
		ftpcmd_pipeline("PORT", dummy);
	}

	if (!ftpcmd(a, b) || (ftp_sin.sin_family != AF_INET) || ftp_sin.sin_port == 0) {
		ftpabort();
		return -1;
	}
	ftpsend_count++;

	if (passive_flag) {
AGAIN_CONN:	if (connect(sock, (struct sockaddr *)&ftp_sin, sizeof(ftp_sin)) == -1) {
			if (errno == EINTR) goto AGAIN_CONN;
			ftpabort();
			return -1;
		}
	} else {
		h[0] = sizeof(ftp_sin);
AGAIN_ACCEPT:	h[1] = accept(sock, (struct sockaddr *)&ftp_sin, (void*)h);
		if (h[1] == -1) {
			if (errno == EINTR) goto AGAIN_ACCEPT;
			ftpabort();
			return -1;
		}
		(void)close(sock);
		sock = h[1];
	}
	return sock;
}

FILE *ftpls(void)
{
	int fd;
	FILE *fp;

	fd = ready("LIST", 0);
	if (fd == -1) return NULL;
	fp = fdopen(fd, "r");
	if (!fp) {
		(void)close(fd);
		ftpabort();
		return NULL;
	}
	return fp;
}
int backup(const char *name, int mark_exec)
{
	static int cnt = 1234;
	char dummy[128];
	char dummy2[128];
	int fd, sock, r;

	if (v_flag) {
		if (name == NULL) {
			puts("checkpoint.txt");
		} else {
			puts(name);
		}
	}
	if (name != NULL) {
		fd = open(name, O_RDONLY|O_NOCTTY);
		if (fd == -1) return 0;
	} else {
		fd = -1;
	}
	sprintf(dummy, "%lu.%lu.%lu.~tmp", (unsigned long)time(0),
			(unsigned long)getpid(), (unsigned long)cnt); cnt++;

	sock = ready("STOR", dummy);
	if (sock == -1) {
		ftpcmd("DELE", dummy);
		(void)close(fd);
		return 0;
	}
	if (name != NULL) {
		r = blast(fd, sock);
		(void)close(fd);
	} else {
		r = 1;
		name = "checkpoint.txt";
	}
	(void)close(sock);

	if (!ftpcmd(0,0)) r = 0;
	if (!r) {
		ftpabort();
		ftpcmd("DELE", dummy);
		return 0;
	}
	if (mark_exec) {
		ftpcmd_pipeline("SITE CHMOD 0755", dummy);
	} else {
		ftpcmd_pipeline("SITE CHMOD 0644", dummy);
	}
	ftpcmd_pipeline("RNFR", dummy);
	if (!ftpcmd("RNTO", name)) {
		/* okay, this can fail if it was a directory; test that */
		sprintf(dummy2, "%lu.%lu.%lu.~tmp", (unsigned long)time(0),
				(unsigned long)getpid(),
				(unsigned long)cnt); cnt++;
		if (!ftpcmd("RNFR", name)) {
			ftpcmd("DELE", dummy);
			return 0;
		}
		if (!ftpcmd("RNTO", dummy2)) {
			ftpcmd("DELE", dummy);
			return 0;
		}
		if (!ftpcmd("RNFR", dummy)) {
			ftpcmd("RNFR", dummy2);
			ftpcmd("RNTO", name);
			ftpcmd("DELE", dummy);
			return 0;
		}
		if (!ftpcmd("RNTO", name)) {
			ftpcmd("RNFR", dummy2);
			ftpcmd("RNTO", name);
			ftpcmd("DELE", dummy);
			return 0;
		}
		/* fall through */
		ftpcmd("RMD", dummy2); /* hooray if it works */
	}
	return 1;
}

int walk1(int wd, struct stat *wd_sb, const char *name)
{
	static char line[PATH_MAX*2];

	DIR *dir;
	FILE *fp;
	struct dirent *d;
	struct stat sb;
	struct stat sb_lnk;
	int r, z, rd;
	char *q, *p;

	if (name != NULL && chdir(name) == -1) {
		return 0;
	}

	dir = opendir(".");
	rd = dirfd(dir);
	if (fstat(rd, &sb) == -1
	|| !S_ISDIR(sb.st_mode)) {
		r=errno;
		closedir(dir);
		(void)close(rd);
		if (fchdir(wd) == -1) abort();
		errno=r;
		return 0;
	}

	if (wd_sb) {
		if (wd_sb->st_dev != sb.st_dev
		|| wd_sb->st_rdev != sb.st_rdev) {
			/* crossing filesystem boundary */
			closedir(dir);
			(void)close(rd);
			if (fchdir(wd) == -1) abort();
			return 1;
		}
		if (stat("..", &sb_lnk) == -1) {
			r=errno;
			closedir(dir);
			(void)close(rd);
			if (fchdir(wd) == -1) abort();
			errno=r;
			return 0;
		}
		if (sb_lnk.st_dev != wd_sb->st_dev
		|| sb_lnk.st_ino != wd_sb->st_ino
		|| sb_lnk.st_rdev != wd_sb->st_rdev) {
			/* someone is fucking with us */
			closedir(dir);
			(void)close(rd);
			if (fchdir(wd) == -1) abort();
			return 1;
		}
	}

	if (name != NULL) {
		ftpcmd_pipeline("MKD", name);
		if (!ftpcmd("CWD", name)) {
			ftpcmd("PWD",0);
			closedir(dir);
			(void)close(rd);
			errno=EHOSTDOWN;
			return 0;
		}
	}

	while ((d = readdir(dir))) {
		if (strcmp(d->d_name, ".") == 0) continue;
		if (strcmp(d->d_name, "..") == 0) continue;

		if (lstat(d->d_name, &sb_lnk) == -1) continue;
		if (S_ISLNK(sb_lnk.st_mode)) continue;
		if (S_ISDIR(sb_lnk.st_mode)) {
			if (!walk1(rd, &sb, d->d_name)) {
				perror(d->d_name);
				if (c_flag) continue;
				closedir(dir);
				(void)close(rd);
				if (fchdir(wd) == -1) abort();
				if (name != NULL) ftpcmd_pipeline("CDUP", 0);
				return 0;
			}
			continue;
		}
		if (!S_ISREG(sb_lnk.st_mode)) continue;
		if (!a_flag && sb_lnk.st_mtime < checkpoint_stat.st_mtime) continue;

		if (!backup(d->d_name, sb_lnk.st_mode & 0111)) {
			perror(d->d_name);
			if (c_flag) continue;
			closedir(dir);
			(void)close(rd);
			if (fchdir(wd) == -1) abort();
			if (name != NULL) ftpcmd_pipeline("CDUP", 0);
			return 0;
		}
	}

	if (z_flag) {
		fp = ftpls();
		while (fp) {
			if (fgets(line, sizeof(line)-2, fp) <= 0) {
				break;
			}
			q = strchr(line, '\r');
			if (q) *q = '\0';
			p = strchr(line, '\n');
			if (p) *p = '\0';
			if (!q && !p) {
				do {
					r = fgetc(fp);
				} while (r >= 0 && r != '\r' && r != '\n');
				while (r == '\r' && r == '\n') {
					r = fgetc(fp);
				}
				/* put the last character (beginning of the next line) back */
				ungetc(r, fp);
			}
			if (line[0] != 'd' && line[0] != '-') continue;
			p = line+10;
#define sp(x) isspace(((unsigned int)(x)))
			while (sp(*p)) p++;
			while (*p >= '0' && *p <= '9') p++; /* nlinks */
			while (sp(*p)) p++;
			while (*p && !(sp(*p))) p++; /* owner */
			while (sp(*p)) p++;
			while (*p && !(sp(*p))) p++; /* group */
			while (sp(*p)) p++;
			while (*p >= '0' && *p <= '9') p++; /* size */
			while (sp(*p)) p++;
			/* okay, now comes the hard part; parsing the date */
#define DIGIT "%*[0123456789]"
			r = -1234;
			if (sscanf(p,
						DIGIT DIGIT DIGIT DIGIT "-"
						DIGIT DIGIT "-"
						DIGIT DIGIT " "
						DIGIT DIGIT ":"
						DIGIT "%d ", &r) > 0 && r >= 0 && r <= 9) {
				/* YYYY-MM-DD HH:MM */
				p += 17;
			} else if (sscanf(p,
				"%*[JFMASOND]%*c%*[nbrylgptvc] %*d %*d:%d %n", &r, &z) > 0
					&& r >= 0 && r <= 60) {
				/* ctime */
				p += z;
			} else {
				fprintf(stderr, "ACK: cannot parse \"%s\"\n", p);
				continue;
			}
			if (stat(p, &sb) == -1 && errno == ENOENT) {
				if (line[0] == 'd') {
					ftpcmd_pipeline("RMD", p);
				} else {
					ftpcmd_pipeline("DELE", p);
				}
			}
#undef sp
		}
		if (fp != NULL) {
			fclose(fp);
		}
		if (!ftpcmd(0,0)) r = 0;
	}

	closedir(dir);
	(void)close(rd);

	if (fchdir(wd) == -1) abort();
	if (name != NULL) ftpcmd_pipeline("CDUP", 0);

	return 1;
}
int walk(const char *name)
{
	struct stat sb;
	int r, fd, wd;
	char *s, *p, *q;
	int need_up;

	if (lstat(name, &sb) == -1) {
		perror(name);
		return 0;
	}
	if (S_ISREG(sb.st_mode)) {
		if (strchr(name, '/') == 0) return backup(name, sb.st_mode & 0111);
		fprintf(stderr, "Not implemented XXX\n");
		return 0;
	}

	wd = open(".", O_RDONLY);
	if (wd == -1) abort();
	if (chdir(name) == -1) {
		perror(name);
		return 0;
	}
	while (*name == '/') name++;
	need_up = 0;
	if (*name) {
		q = s = strdup(name);
		if (!q) abort();
		do {
			p = strchr(q, '/');
			if (p) *p = '\0';
			if (strcmp(q, "..") == 0) {
				need_up--;
				ftpcmd_pipeline("CDUP", 0);
			} else if (strcmp(q, ".") != 0) {
				ftpcmd_pipeline("MKD", q);
				ftpcmd_pipeline("CWD", q);
				need_up++;
			}
			if (p) {
				*p = '/';
				q = p + 1;
			}
		} while (p);
		(void)ftpcmd("PWD", 0); /* catchup */
	}

	fd = open(".", O_RDONLY);
	r = walk1(fd,NULL,NULL);
	(void)close(fd);

	while (need_up > 0) {
		ftpcmd_pipeline("CDUP", 0);
		need_up--;
	}
	(void)ftpcmd("PWD", 0); /* catchup */

	if (fchdir(wd) == -1) abort();
	(void)close(wd);

	return r;
}


int main(int argc, char *argv[])
{
	int i, j, h[4];
	struct url uu;
	struct sockaddr_in sin;
	struct hostent *db;
	char *q;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s roots... ftp://user:pass@host/\n", argv[0]);
		exit(EXIT_SUCCESS);
	}
	for (i = 1; i < (argc-1); i++) {
		if (argv[i][0] != '-') continue;
		for (j = 1; argv[i][j]; j++) {
			switch (argv[i][j]) {
			case 'c': c_flag = 1; break;
			case 'v': v_flag = 1; break;
			case 'P': passive_flag = 1; break;
			case 'k': checkpoint_flag = 1; break;
			case 'A': a_flag = 1; break;
			case 'z': z_flag = 1; break;
			case '-': break;
			default:
				fprintf(stderr, "Invalid option -%c\n", argv[i][j]);
				exit(EXIT_FAILURE);
			};
		}
	}

	if (!url_parse(&uu, argv[argc-1])) {
		fprintf(stderr, "Cannot parse url \"%s\"\n", argv[argc-1]);
		exit(EXIT_FAILURE);
	}
	if (strcasecmp(uu.schema, "ftp") != 0) {
		fprintf(stderr, "linback only supports ftp:// urls (other kinds can use other tools)\n");
		exit(EXIT_FAILURE);
	}

	checkpoint_file = getenv("CHECKPOINT");
	if (checkpoint_file) {
		checkpoint_tmp = malloc(strlen(checkpoint_file) + 64);
		if (!checkpoint_tmp) abort();
		for (i = 1234;; i++) {
			sprintf(checkpoint_tmp, "%s.%lu-%lu.%d",
				checkpoint_file,
				(unsigned long)time(0),
				(unsigned long)getpid, i);
			checkpoint_fd = open(checkpoint_tmp, O_RDWR|O_CREAT|O_EXCL, 0600);
			if (checkpoint_fd == -1 && errno == EEXIST) continue;
			if (checkpoint_fd == -1) {
				fprintf(stderr, "Cannot open %s for writing: %s\n",
						checkpoint_tmp, strerror(errno));
				exit(EXIT_FAILURE);
			}
			break;
		}
		if (stat(checkpoint_file, &checkpoint_stat) == -1) {
			memset(&checkpoint_stat, 0, sizeof(checkpoint_stat));
		}
	} else {
		memset(&checkpoint_stat, 0, sizeof(checkpoint_stat));
	}

	netrc(&uu);

	ftp_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (ftp_socket < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	if (uu.port < -1) uu.port = 21;

	if (sscanf(uu.hostname, "%d.%d.%d.%d",&h[0],&h[1],&h[2],&h[3]) == 4) {
		/* use direct ip address connection */
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		((unsigned char *)&sin.sin_addr)[0] = h[0];
		((unsigned char *)&sin.sin_addr)[1] = h[1];
		((unsigned char *)&sin.sin_addr)[2] = h[2];
		((unsigned char *)&sin.sin_addr)[3] = h[3];
		sin.sin_port = htons(uu.port);
		if (connect(ftp_socket, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
			i = errno;
			(void)close(ftp_socket);
			ftp_socket = -1;
			errno = i;
		}
	} else {
		db = gethostbyname(uu.hostname);
		if (!db) {
			herror(uu.hostname);
			exit(EXIT_FAILURE);
		}
		h[0] = db->h_length / 4;
		for (i = 0; i < h[0]; i++) {
			memset(&sin, 0, sizeof(sin));
			sin.sin_family = AF_INET;
			memcpy(&sin.sin_addr, db->h_addr_list[i], 4);
			sin.sin_port = htons(uu.port);
			if (connect(ftp_socket, (struct sockaddr *)&sin, sizeof(sin)) == -1)
				continue;
			break;
		}
		if (h[0] == 0) {
			(void)close(ftp_socket);
			ftp_socket = -1;
			errno = ENOENT;
		} else if (i == h[0]) {
			i = errno;
			(void)close(ftp_socket);
			ftp_socket = -1;
			errno = i;
		}
	}
	if (ftp_socket == -1) {
		perror(uu.hostname);
		exit(EXIT_FAILURE);
	}
	h[0] = sizeof(sin);
	if (getsockname(ftp_socket, (struct sockaddr *)&sin, (void*)h) == -1) {
		perror("getsockname");
		exit(EXIT_FAILURE);
	}
	memcpy(out_addr, &sin.sin_addr, 4);
	ftp_response[0] = 0;
	ftpsend_count = 1;
	(void)ftpcmd(0,0); /* get the banner */
	if (uu.username && !ftpcmd("USER", uu.username)) goto BADLOGIN;
	if (uu.password && !ftpcmd("PASS", uu.password)) goto BADLOGIN;
	if (uu.path) {
		q = uu.path;
		for (;;) {
			while (*q == '/') q++;
			if (!*q) break;
			uu.path = q;
			while (*q && *q != '/') q++;
			*q = 0;
			if (!ftpcmd("CWD", uu.path)) goto BADLOGIN;
			*q = '/';
		}
	}
	if (!ftpcmd("TYPE", "I")) goto BADLOGIN;


	for (i = 1; i < (argc-1); i++) {
		if (argv[i][0] == '-') continue;
		if (!walk(argv[i])) {
			if (!c_flag) exit(EXIT_FAILURE);
		}
	}
	if (checkpoint_flag) {
		sleep(2);
		if (!backup(NULL, 0)) {
			if (!c_flag) exit(EXIT_FAILURE);
		}
	}
	if (checkpoint_file) {
		(void)rename(checkpoint_tmp, checkpoint_file);
	}
	exit(EXIT_SUCCESS);
BADLOGIN:	
	fprintf(stderr, "Error logging in; last response was: %s\n",ftp_response);
	exit(EXIT_FAILURE);
}
