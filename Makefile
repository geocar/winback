all: winback.exe linback

# Linux-specific
linback: linback.c netrc.c urlparse.c urlparse.h Makefile
	$(CC) $(CFLAGS) $(LDFLAGS) -Wall -o linback linback.c urlparse.c netrc.c

# Windows specific
MINGW=i386-mingw32
WIN32GCC=$(MINGW)-gcc
WIN32AR=$(MINGW)-ar
WIN32RANLIB=$(MINGW)-ranlib

SOURCES=backup.c fout.c urlparse.c ftp.c ensure.c bufout.c registry.c acprint.c ntfs.c sftp.c netrc.c
libntfs=attrib.c bitmap.c collate.c compress.c device.c index.c lcnalloc.c logging.c misc.c runlist.c unistr.c volume.c \
	attrlist.c bootsect.c compat.c debug.c dir.c inode.c logfile.c mft.c mst.c security.c version.c
libputty=sftp.c ssh.c sshaes.c ssharcf.c sshblowf.c sshbn.c sshcrc.c sshcrcda.c sshdes.c sshdh.c sshdss.c sshmd5.c \
	 sshpubk.c sshrand.c sshrsa.c sshsh256.c sshsh512.c sshsha.c sshzlib.c timing.c tree234.c x11fwd.c portfwd.c proxy.c \
	 cproxy.c version.c int64.c misc.c logging.c pinger.c wildcard.c ldisc.c settings.c cmdline.c
libputty_windows=wincons.c windefs.c winhandl.c winmisc.c winnet.c winnoise.c winpgntc.c winproxy.c winstore.c \
		 wintime.c


winback.exe: $(SOURCES) fout.h urlparse.h bufout.h acprint.h libntfs-3g.a libputty.a Makefile
	$(WIN32GCC) $(CFLAGS) $(LDFLAGS) -D_WINDOWS -Iputty -Iputty/windows -Wall -o winback.exe $(SOURCES) -lwsock32 -lwininet -ladvapi32 -L. -lntfs-3g -lputty

libntfs-3g.a: $(patsubst %.c,libntfs-3g/%.c,$(libntfs)) $(wildcard libntfs-3g/include/*.h) Makefile
	$(WIN32GCC) $(CFLAGS) -DWINDOWS -D_MT -D_LITTLE_ENDIAN -Wall -Ilibntfs-3g/include -c $(patsubst %.c,libntfs-3g/%.c,$(libntfs))
	$(WIN32AR) rcs $@.tmp $(patsubst %.c,%.o,$(libntfs))
	$(WIN32RANLIB) $@.tmp
	mv $@.tmp $@

libputty.a: $(patsubst %.c,putty/%.c,$(libputty)) $(patsubst %.c,putty/windows/%.c,$(libputty_windows)) Makefile \
$(wildcard putty/*.h) $(wildcard putty/charset/*.h) $(wildcard putty/windows/*.h)
	$(WIN32GCC) $(CFLAGS) -D_WIN32_IE=0x0500 -DWINVER=0x0500 -D_WIN32_WINDOWS=0x0410 -D_WIN32_WINNT=0x0500 \
		-Wall -O2 -D_WINDOWS -DWIN32S_COMPAT -D_NO_OLDNAMES -DNO_MULTIMON -DNO_HTMLHELP -Iputty \
		-Iputty/charset -Iputty/windows \
		-c $(patsubst %.c,putty/%.c,$(libputty)) $(patsubst %.c,putty/windows/%.c,$(libputty_windows))
	$(WIN32AR) rcs $@.tmp $(patsubst %.c,%.o,$(libputty)) $(patsubst %.c,%.o,$(libputty_windows))
	$(WIN32RANLIB) $@.tmp
	mv $@.tmp $@


clean:
	rm -f libntfs-3g.a $(patsubst %.c,%.o,$(libntfs))
	rm -f libputty.a $(patsubst %.c,%.o,$(libputty)) $(patsubst %.c,%.o,$(libputty_windows))
	rm -f winback.exe linback
