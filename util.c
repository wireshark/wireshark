/* util.c
 * Utility routines
 *
 * $Id: util.c,v 1.37 2000/02/22 07:07:46 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef NEED_SNPRINTF_H
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

#ifndef WIN32
#include <pwd.h>
#endif

#ifdef NEED_MKSTEMP
#include "mkstemp.h"
#endif

#include "util.h"

#ifdef HAVE_IO_H
#include <io.h>
typedef int mode_t;	/* for win32 */
#endif

#ifdef HAVE_LIBPCAP

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#ifdef HAVE_SYS_SOCKIO_H
# include <sys/sockio.h>
#endif

#include "globals.h"

#endif

/*
 * Given a pathname, return a pointer to the last pathname separator
 * character in the pathname, or NULL if the pathname contains no
 * separators.
 */
static char *
find_last_pathname_separator(char *path)
{
	char *separator;

#ifdef WIN32
	char c;

	/*
	 * We have to scan for '\' or '/'.
	 * Get to the end of the string.
	 */
	separator = path + strlen(path);	/* points to ending '\0' */
	while (separator > path) {
		c = *--separator;
		if (c == '\\' || c == '/')
			return separator;	/* found it */
	}

	/*
	 * OK, we didn't find any, so no directories - but there might
	 * be a drive letter....
	 */
	return strchr(path, ':');
#else
	separator = strrchr(path, '/');
#endif
	return separator;
}

/*
 * Given a pathname, return the last component.
 */
char *
get_basename(char *path)
{
	char *filename;

	filename = find_last_pathname_separator(path);
	if (filename == NULL) {
		/*
		 * There're no directories, drive letters, etc. in the
		 * name; the pathname *is* the file name.
		 */
		filename = path;
	} else {
		/*
		 * Skip past the pathname or drive letter separator.
		 */
		filename++;
	}
	return filename;
}

/*
 * Given a pathname, return a string containing everything but the
 * last component.  NOTE: this overwrites the pathname handed into
 * it....
 */
char *
get_dirname(char *path)
{
	char *separator;

	separator = find_last_pathname_separator(path);
	if (separator == NULL) {
		/*
		 * There're no directories, drive letters, etc. in the
		 * name; there is no directory path to return.
		 */
		return NULL;
	}

	/*
	 * Get rid of the last pathname separator and the final file
	 * name following it.
	 */
	*separator = '\0';

	/*
	 * "path" now contains the pathname of the directory containing
	 * the file/directory to which it referred.
	 */
	return path;
}

/*
 * Collect command-line arguments as a string consisting of the arguments,
 * separated by spaces.
 */
char *
get_args_as_string(int argc, char **argv, int optind)
{
	int len;
	int i;
	char *argstring;

	/*
	 * Find out how long the string will be.
	 */
	len = 0;
	for (i = optind; i < argc; i++) {
		len += strlen(argv[i]);
		len++;	/* space, or '\0' if this is the last argument */
	}

	/*
	 * Allocate the buffer for the string.
	 */
	argstring = g_malloc(len);

	/*
	 * Now construct the string.
	 */
	strcpy(argstring, "");
	i = optind;
	for (;;) {
		strcat(argstring, argv[i]);
		i++;
		if (i == argc)
			break;
		strcat(argstring, " ");
	}
	return argstring;
}

static char *
setup_tmpdir(char *dir)
{
	int len = strlen(dir);
	char *newdir;

	/* Append slash if necessary */
	if (dir[len - 1] == '/') {
		newdir = dir;
	}
	else {
		newdir = g_malloc(len + 2);
		strcpy(newdir, dir);
		strcat(newdir, "/");
	}
	return newdir;
}

static int
try_tempfile(char *namebuf, int namebuflen, const char *dir, const char *pfx)
{
	static const char suffix[] = "XXXXXXXXXX";
	int namelen = strlen(dir) + strlen(pfx) + sizeof suffix;
	mode_t old_umask;
	int tmp_fd;

	if (namebuflen < namelen) {
		/* Stick in a truncated name, so that if this error is
		   reported with the file name, you at least get
		   something. */
		snprintf(namebuf, namebuflen, "%s%s%s", dir, pfx, suffix);
		errno = ENAMETOOLONG;
		return -1;
	}
	strcpy(namebuf, dir);
	strcat(namebuf, pfx);
	strcat(namebuf, suffix);

	/* The Single UNIX Specification doesn't say that "mkstemp()"
	   creates the temporary file with mode rw-------, so we
	   won't assume that all UNIXes will do so; instead, we set
	   the umask to 0077 to take away all group and other
	   permissions, attempt to create the file, and then put
	   the umask back. */
	old_umask = umask(0077);
	tmp_fd = mkstemp(namebuf);
	umask(old_umask);
	return tmp_fd;
}

static char *tmpdir = NULL;
#ifdef WIN32
static char *temp = NULL;
#endif
static char *E_tmpdir;

#ifndef P_tmpdir
#define P_tmpdir "/var/tmp"
#endif

int
create_tempfile(char *namebuf, int namebuflen, const char *pfx)
{
	char *dir;
	int fd;
	static gboolean initialized;

	if (!initialized) {
		if ((dir = getenv("TMPDIR")) != NULL)
			tmpdir = setup_tmpdir(dir);
#ifdef WIN32
		if ((dir = getenv("TEMP")) != NULL)
			temp = setup_tmpdir(dir);
#endif

		E_tmpdir = setup_tmpdir(P_tmpdir);
		initialized = TRUE;
	}

	if (tmpdir != NULL) {
		fd = try_tempfile(namebuf, namebuflen, tmpdir, pfx);
		if (fd != -1)
			return fd;
	}

#ifdef WIN32
	if (temp != NULL) {
		fd = try_tempfile(namebuf, namebuflen, temp, pfx);
		if (fd != -1)
			return fd;
	}
#endif

	fd = try_tempfile(namebuf, namebuflen, E_tmpdir, pfx);
	if (fd != -1)
		return fd;

	return try_tempfile(namebuf, namebuflen, "/tmp", pfx);
}

/* ASCII/EBCDIC conversion tables from
 * http://www.room42.com/store/computer_center/code_tables.shtml
 */
static guint8 ASCII_translate_EBCDIC [ 256 ] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x40, 0x5A, 0x7F, 0x7B, 0x5B, 0x6C, 0x50, 0x7D, 0x4D,
    0x5D, 0x5C, 0x4E, 0x6B, 0x60, 0x4B, 0x61,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8,
    0xF9, 0x7A, 0x5E, 0x4C, 0x7E, 0x6E, 0x6F,
    0x7C, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8,
    0xC9, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6,
    0xD7, 0xD8, 0xD9, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
    0xE8, 0xE9, 0xAD, 0xE0, 0xBD, 0x5F, 0x6D,
    0x7D, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
    0x89, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
    0x97, 0x98, 0x99, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xC0, 0x6A, 0xD0, 0xA1, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B,
    0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B, 0x4B
};

void
ASCII_to_EBCDIC(guint8 *buf, guint bytes)
{
	guint	i;
	guint8	*bufptr;

	bufptr = buf;

	for (i = 0; i < bytes; i++, bufptr++) {
		*bufptr = ASCII_translate_EBCDIC[*bufptr];
	}
}

guint8
ASCII_to_EBCDIC1(guint8 c)
{
	return ASCII_translate_EBCDIC[c];
}

static guint8 EBCDIC_translate_ASCII [ 256 ] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x2E, 0x2E, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x2E, 0x3F,
    0x20, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x2E, 0x2E, 0x3C, 0x28, 0x2B, 0x7C,
    0x26, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x21, 0x24, 0x2A, 0x29, 0x3B, 0x5E,
    0x2D, 0x2F, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x7C, 0x2C, 0x25, 0x5F, 0x3E, 0x3F,
    0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x3A, 0x23, 0x40, 0x27, 0x3D, 0x22,
    0x2E, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71,
    0x72, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x7E, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
    0x7A, 0x2E, 0x2E, 0x2E, 0x5B, 0x2E, 0x2E,
    0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x2E, 0x2E, 0x2E, 0x2E, 0x5D, 0x2E, 0x2E,
    0x7B, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x7D, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51,                                             
    0x52, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x5C, 0x2E, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
    0x5A, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,                 
    0x39, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E, 0x2E
};

void
EBCDIC_to_ASCII(guint8 *buf, guint bytes)
{
	guint	i;
	guint8	*bufptr;

	bufptr = buf;

	for (i = 0; i < bytes; i++, bufptr++) {
		*bufptr = EBCDIC_translate_ASCII[*bufptr];
	}
}

guint8
EBCDIC_to_ASCII1(guint8 c)
{
	return EBCDIC_translate_ASCII[c];
}

#ifdef HAVE_LIBPCAP

/*
 * If the ability to capture packets is added to Wiretap, these
 * routines should be moved to the Wiretap source (with
 * "get_interface_list()" and "free_interface_list()" renamed to
 * "wtap_get_interface_list()" and "wtap_free_interface_list()",
 * and modified to use Wiretap routines to attempt to open the
 * interface.
 */

struct search_user_data {
	char	*name;
	int	found;
};

static void
search_for_if_cb(gpointer data, gpointer user_data);

static void
free_if_cb(gpointer data, gpointer user_data);

#ifndef WIN32
GList *
get_interface_list(int *err, char *err_str)
{
	GList  *il = NULL;
	gint    nonloopback_pos = 0;
	struct  ifreq *ifr, *last;
	struct  ifconf ifc;
	struct  ifreq ifrflags;
	int     sock = socket(AF_INET, SOCK_DGRAM, 0);
	struct search_user_data user_data;
	pcap_t *pch;

	if (sock < 0) {
		sprintf(err_str, "Error opening socket: %s",
		    strerror(errno));
		return NULL;
	}

	/*
	 * Since we have to grab the interface list all at once, we'll
	 * make plenty of room.
	 */
	ifc.ifc_len = 1024 * sizeof(struct ifreq);
	ifc.ifc_buf = malloc(ifc.ifc_len);

	if (ioctl(sock, SIOCGIFCONF, &ifc) < 0 ||
	    ifc.ifc_len < sizeof(struct ifreq)) {
		sprintf(err_str, "SIOCGIFCONF error getting list of interfaces: %s",
		    strerror(errno));
		goto fail;
	 }

	ifr = (struct ifreq *) ifc.ifc_req;
	last = (struct ifreq *) ((char *) ifr + ifc.ifc_len);
	while (ifr < last) {
		/*
		 * Skip addresses that begin with "dummy", or that include
		 * a ":" (the latter are Solaris virtuals).
		 */
		if (strncmp(ifr->ifr_name, "dummy", 5) == 0 ||
		    strchr(ifr->ifr_name, ':') != NULL)
			goto next;

		/*
		 * If we already have this interface name on the list,
		 * don't add it (SIOCGIFCONF returns, at least on
		 * BSD-flavored systems, one entry per interface *address*;
		 * if an interface has multiple addresses, we get multiple
		 * entries for it).
		 */
		user_data.name = ifr->ifr_name;
		user_data.found = FALSE;
		g_list_foreach(il, search_for_if_cb, &user_data);
		if (user_data.found)
			goto next;

		/*
		 * Get the interface flags.
		 */
		memset(&ifrflags, 0, sizeof ifrflags);
		strncpy(ifrflags.ifr_name, ifr->ifr_name,
		    sizeof ifrflags.ifr_name);
		if (ioctl(sock, SIOCGIFFLAGS, (char *)&ifrflags) < 0) {
			if (errno == ENXIO)
				goto next;
			sprintf(err_str, "SIOCGIFFLAGS error getting flags for interface %s: %s",
			    ifr->ifr_name, strerror(errno));
			goto fail;
		}

		/*
		 * Skip interfaces that aren't up.
		 */
		if (!(ifrflags.ifr_flags & IFF_UP))
			goto next;

		/*
		 * Skip interfaces that we can't open with "libpcap".
		 * Open with the minimum packet size - it appears that the
		 * IRIX SIOCSNOOPLEN "ioctl" may fail if the capture length
		 * supplied is too large, rather than just truncating it.
		 */
		pch = pcap_open_live(ifr->ifr_name, MIN_PACKET_SIZE, 0, 0,
		    err_str);
		if (pch == NULL)
			goto next;
		pcap_close(pch);

		/*
		 * If it's a loopback interface, add it at the end of the
		 * list, otherwise add it after the last non-loopback
		 * interface, so all loopback interfaces go at the end - we
		 * don't want a loopback interface to be the default capture
		 * device unless there are no non-loopback devices.
		 */
		if ((ifrflags.ifr_flags & IFF_LOOPBACK) ||
		    strncmp(ifr->ifr_name, "lo", 2) == 0)
			il = g_list_insert(il, g_strdup(ifr->ifr_name), -1);
		else {
			il = g_list_insert(il, g_strdup(ifr->ifr_name),
			    nonloopback_pos);
			/*
			 * Insert the next non-loopback interface after this
			 * one.
			 */
			nonloopback_pos++;
		}

	next:
#ifdef HAVE_SA_LEN
		ifr = (struct ifreq *) ((char *) ifr + ifr->ifr_addr.sa_len + IFNAMSIZ);
#else
		ifr = (struct ifreq *) ((char *) ifr + sizeof(struct ifreq));
#endif
	}

	free(ifc.ifc_buf);
	close(sock);

	if (il == NULL) {
		/*
		 * No interfaces found.
		 */
		*err = NO_INTERFACES_FOUND;
	}
	return il;

fail:
	if (il != NULL) {
		g_list_foreach(il, free_if_cb, NULL);
		g_list_free(il);
	}
	free(ifc.ifc_buf);
	close(sock);
	*err = CANT_GET_INTERFACE_LIST;
	return NULL;
}

static void
search_for_if_cb(gpointer data, gpointer user_data)
{
	struct search_user_data *search_user_data = user_data;

	if (strcmp((char *)data, search_user_data->name) == 0)
		search_user_data->found = TRUE;
}
#else
GList *
get_interface_list(int *err, char *err_str) {
  GList  *il = NULL;
  wchar_t *names;
  char newname[255];
  int i, j, done;
  
  names = (wchar_t *)pcap_lookupdev(err_str);
  i = done = 0;

  if (names)
     do
     {
        j = 0;
        while (names[i] != 0)
           newname[j++] = names[i++];
        i++;
        if (names[i] == 0)
           done = 1;
        newname[j++] = 0;
        il = g_list_append(il, g_strdup(newname));
     } while (!done);
  
  return(il);
}
#endif

static void
free_if_cb(gpointer data, gpointer user_data)
{
	g_free(data);
}

void
free_interface_list(GList *if_list)
{
	while (if_list != NULL) {
		g_free(if_list->data);
		if_list = g_list_remove_link(if_list, if_list);
	}
}

#endif /* HAVE_LIBPCAP */

const char*
get_home_dir(void)
{
	char *env_value;
	static const char *home = NULL;
#ifndef WIN32
	struct passwd *pwd;
#endif

	/* Return the cached value, if available */
	if (home)
		return home;

	env_value = getenv("HOME");

	if (env_value) {
		home = env_value;
	}
	else {
#ifdef WIN32
		/* XXX - on NT, get the user name and append it to
		   "C:\winnt\profiles\"?
		   What about Windows 9x? */
		home = "C:";
#else
		pwd = getpwuid(getuid());
		if (pwd != NULL) {
			/* This is cached, so we don't need to worry
			   about allocating multiple ones of them. */
			home = g_strdup(pwd->pw_dir);
		}
		else
			home = "/tmp";
#endif
	}

	return home;
}
