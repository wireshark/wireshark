/* file_access.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>

#include <wsutil/file_util.h>

#include "ftap-int.h"
#include "ft_file_wrappers.h"
#include "buffer.h"

/*
 * Add an extension, and all compressed versions thereof, to a GSList
 * of extensions.
 */
static GSList *add_extensions(GSList *extensions, const gchar *extension,
    GSList *compressed_file_extensions)
{
	GSList *compressed_file_extension;

	/*
	 * Add the specified extension.
	 */
	extensions = g_slist_append(extensions, g_strdup(extension));

	/*
	 * Now add the extensions for compressed-file versions of
	 * that extension.
	 */
	for (compressed_file_extension = compressed_file_extensions;
	    compressed_file_extension != NULL;
	    compressed_file_extension = g_slist_next(compressed_file_extension)) {
		extensions = g_slist_append(extensions,
		    g_strdup_printf("%s.%s", extension,
		      (gchar *)compressed_file_extension->data));
	}

	return extensions;
}

/*
 * File types that can be identified by file extensions.
 */
static const struct filetap_extension_info file_type_extensions_base[] = {
	{ "Wireshark/tcpdump/... - pcap", "pcap;cap;dmp" },
};

#define	N_FILE_TYPE_EXTENSIONS	(sizeof file_type_extensions_base / sizeof file_type_extensions_base[0])

static const struct filetap_extension_info* file_type_extensions = NULL;

static GArray* file_type_extensions_arr = NULL;

/* initialize the extensions array if it has not been initialized yet */
static void init_file_type_extensions(void) {

	if (file_type_extensions_arr) return;

	file_type_extensions_arr = g_array_new(FALSE,TRUE,sizeof(struct filetap_extension_info));

	g_array_append_vals(file_type_extensions_arr,file_type_extensions_base,N_FILE_TYPE_EXTENSIONS);

	file_type_extensions = (struct filetap_extension_info*)(void *)file_type_extensions_arr->data;
}

void ftap_register_file_type_extension(const struct filetap_extension_info *ei) {
	init_file_type_extensions();

	g_array_append_val(file_type_extensions_arr,*ei);

	file_type_extensions = (const struct filetap_extension_info*)(void *)file_type_extensions_arr->data;
}

int ftap_get_num_file_type_extensions(void)
{
	return file_type_extensions_arr->len;
}

const char *ftap_get_file_extension_type_name(int extension_type)
{
	return file_type_extensions[extension_type].name;
}

static GSList *add_extensions_for_file_extensions_type(int extension_type,
    GSList *extensions, GSList *compressed_file_extensions)
{
	gchar **extensions_set, **extensionp, *extension;

	/*
	 * Split the extension-list string into a set of extensions.
	 */
	extensions_set = g_strsplit(file_type_extensions[extension_type].extensions,
	    ";", 0);

	/*
	 * Add each of those extensions to the list.
	 */
	for (extensionp = extensions_set; *extensionp != NULL; extensionp++) {
		extension = *extensionp;

		/*
		 * Add the extension, and all compressed variants
		 * of it.
		 */
		extensions = add_extensions(extensions, extension,
		    compressed_file_extensions);
	}

	g_strfreev(extensions_set);
	return extensions;
}

/* Return a list of file extensions that are used by the specified file
   extension type.

   All strings in the list are allocated with g_malloc() and must be freed
   with g_free(). */
GSList *ftap_get_file_extension_type_extensions(guint extension_type)
{
	GSList *compressed_file_extensions;
	GSList *extensions;

	if (extension_type >= file_type_extensions_arr->len)
		return NULL;	/* not a valid extension type */

	extensions = NULL;	/* empty list, to start with */

	/*
	 * Get the list of compressed-file extensions.
	 */
	compressed_file_extensions = ftap_get_compressed_file_extensions();

	/*
	 * Add all this file extension type's extensions, with compressed
	 * variants.
	 */
	extensions = add_extensions_for_file_extensions_type(extension_type,
	    extensions, compressed_file_extensions);

	g_slist_free(compressed_file_extensions);
	return extensions;
}

/* Return a list of all extensions that are used by all file types,
   including compressed extensions, e.g. not just "pcap" but also
   "pcap.gz" if we can read gzipped files.

   All strings in the list are allocated with g_malloc() and must be freed
   with g_free(). */
GSList *ftap_get_all_file_extensions_list(void)
{
	GSList *compressed_file_extensions;
	GSList *extensions;
	unsigned int i;

	init_file_type_extensions();

	extensions = NULL;	/* empty list, to start with */

	/*
	 * Get the list of compressed-file extensions.
	 */
	compressed_file_extensions = ftap_get_compressed_file_extensions();

	for (i = 0; i < file_type_extensions_arr->len; i++) {
		/*
		 * Add all this file extension type's extensions, with
		 * compressed variants.
		 */
		extensions = add_extensions_for_file_extensions_type(i,
		    extensions, compressed_file_extensions);
	}

	g_slist_free(compressed_file_extensions);
	return extensions;
}

static int empty_open(ftap *wth _U_, int *err _U_, gchar **err_info _U_)
{
	return 0;
}

/* The open_file_* routines should return:
 *
 *	-1 on an I/O error;
 *
 *	1 if the file they're reading is one of the types it handles;
 *
 *	0 if the file they're reading isn't the type they're checking for.
 *
 * If the routine handles this type of file, it should set the "file_type"
 * field in the "struct ftap" to the type of the file.
 *
 * Note that the routine does not have to free the private data pointer on
 * error. The caller takes care of that by calling ftap_close on error.
 * (See https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8518)
 *
 * However, the caller does have to free the private data pointer when
 * returning 0, since the next file type will be called and will likely
 * just overwrite the pointer.
 */

/* Files that have magic bytes in fixed locations. These
 * are easy to identify.  Only an open routine is needed.
 */
static const ftap_open_routine_t magic_number_open_routines_base[] = {
	empty_open/* libpcap_open, */
};
#define	N_MAGIC_FILE_TYPES	(sizeof magic_number_open_routines_base / sizeof magic_number_open_routines_base[0])

static ftap_open_routine_t* magic_number_open_routines = NULL;

static GArray* magic_number_open_routines_arr = NULL;

/*
 * Initialize the magic-number open routines array if it has not been
 * initialized yet.
 */
static void init_magic_number_open_routines(void) {

	if (magic_number_open_routines_arr) return;

	magic_number_open_routines_arr = g_array_new(FALSE,TRUE,sizeof(ftap_open_routine_t));

	g_array_append_vals(magic_number_open_routines_arr,magic_number_open_routines_base,N_MAGIC_FILE_TYPES);

	magic_number_open_routines = (ftap_open_routine_t*)(void *)magic_number_open_routines_arr->data;
}

void ftap_register_magic_number_open_routine(ftap_open_routine_t open_routine) {
	init_magic_number_open_routines();

	g_array_append_val(magic_number_open_routines_arr,open_routine);

	magic_number_open_routines = (ftap_open_routine_t*)(void *)magic_number_open_routines_arr->data;
}

/* Files that don't have magic bytes at a fixed location,
 * but that instead require a heuristic of some sort to
 * identify them.  This includes ASCII trace files.
 *
 * Entries for the ASCII trace files that would be, for example,
 * saved copies of a Telnet session to some box are put after
 * most of the other entries, as we don't want to treat a capture
 * of such a session as a trace file from such a session
 * merely because it has the right text in it.  They still
 * appear before the *really* weak entries, such as the VWR entry.
 */
static const struct ftap_heuristic_open_info heuristic_open_info_base[] = {
	{ NULL, "(empty)", NULL},
};
#define	N_HEURISTIC_FILE_TYPES	(sizeof heuristic_open_info_base / sizeof heuristic_open_info_base[0])

static struct ftap_heuristic_open_info* heuristic_open_info = NULL;

static GArray* heuristic_open_info_arr = NULL;

/*
 * Initialize the heuristics array if it has not been initialized yet.
 */
static void init_heuristic_open_info(void) {
	unsigned int i;
	struct ftap_heuristic_open_info *i_open;

	if (heuristic_open_info_arr)
		return;

	heuristic_open_info_arr = g_array_new(FALSE,TRUE,sizeof(struct ftap_heuristic_open_info));

	g_array_append_vals(heuristic_open_info_arr,heuristic_open_info_base,N_HEURISTIC_FILE_TYPES);

	heuristic_open_info = (struct ftap_heuristic_open_info*)(void *)heuristic_open_info_arr->data;

	/* Populate the extensions_set list now */
	for (i = 0, i_open = heuristic_open_info; i < heuristic_open_info_arr->len; i++, i_open++) {
		if (i_open->extensions != NULL)
			i_open->extensions_set = g_strsplit(i_open->extensions, ";", 0);
	}
}

void ftap_register_heuristic_open_info(struct ftap_heuristic_open_info *hi) {
	init_heuristic_open_info();

	g_array_append_val(heuristic_open_info_arr,*hi);

	if (hi->extensions != NULL)
		hi->extensions_set = g_strsplit(hi->extensions, ";", 0);

	heuristic_open_info = (struct ftap_heuristic_open_info*)(void *)heuristic_open_info_arr->data;
}

/*
 * Visual C++ on Win32 systems doesn't define these.  (Old UNIX systems don't
 * define them either.)
 *
 * Visual C++ on Win32 systems doesn't define S_IFIFO, it defines _S_IFIFO.
 */
#ifndef S_ISREG
#define S_ISREG(mode)   (((mode) & S_IFMT) == S_IFREG)
#endif
#ifndef S_IFIFO
#define S_IFIFO	_S_IFIFO
#endif
#ifndef S_ISFIFO
#define S_ISFIFO(mode)  (((mode) & S_IFMT) == S_IFIFO)
#endif
#ifndef S_ISDIR
#define S_ISDIR(mode)   (((mode) & S_IFMT) == S_IFDIR)
#endif

static char *get_file_extension(const char *pathname)
{
	gchar *filename;
	gchar **components;
	size_t ncomponents;
	GSList *compressed_file_extensions, *compressed_file_extension;
	gchar *extensionp;

	/*
	 * Is the pathname empty?
	 */
	if (strcmp(pathname, "") == 0)
		return NULL;	/* no extension */

	/*
	 * Find the last component of the pathname.
	 */
	filename = g_path_get_basename(pathname);

	/*
	 * Does it have an extension?
	 */
	if (strchr(filename, '.') == NULL) {
		g_free(filename);
		return NULL;	/* no extension whatsoever */
	}

	/*
	 * Yes.  Split it into components separated by ".".
	 */
	components = g_strsplit(filename, ".", 0);
	g_free(filename);

	/*
	 * Count the components.
	 */
	for (ncomponents = 0; components[ncomponents] != NULL; ncomponents++)
		;

	if (ncomponents == 0) {
		g_strfreev(components);
		return NULL;	/* no components */
	}
	if (ncomponents == 1) {
		g_strfreev(components);
		return NULL;	/* only one component, with no "." */
	}

	/*
	 * Is the last component one of the extensions used for compressed
	 * files?
	 */
	compressed_file_extensions = ftap_get_compressed_file_extensions();
	if (compressed_file_extensions == NULL) {
		/*
		 * We don't support reading compressed files, so just
		 * return a copy of whatever extension we did find.
		 */
		extensionp = g_strdup(components[ncomponents - 1]);
		g_strfreev(components);
		return extensionp;
	}
	extensionp = components[ncomponents - 1];
	for (compressed_file_extension = compressed_file_extensions;
	    compressed_file_extension != NULL;
	    compressed_file_extension = g_slist_next(compressed_file_extension)) {
		if (strcmp(extensionp, (char *)compressed_file_extension->data) == 0) {
			/*
			 * Yes, it's one of the compressed-file extensions.
			 * Is there an extension before that?
			 */
			if (ncomponents == 2) {
				g_strfreev(components);
				return NULL;	/* no, only two components */
			}

			/*
			 * Yes, return that extension.
			 */
			extensionp = g_strdup(components[ncomponents - 2]);
			g_strfreev(components);
			return extensionp;
		}
	}

	/*
	 * The extension isn't one of the compressed-file extensions;
	 * return it.
	 */
	extensionp = g_strdup(extensionp);
	g_strfreev(components);
	return extensionp;
}

static gboolean heuristic_uses_extension(unsigned int i, const char *extension)
{
	gchar **extensionp;

	/*
	 * Does this file type *have* any extensions?
	 */
	if (heuristic_open_info[i].extensions == NULL)
		return FALSE;	/* no */

	/*
	 * Check each of them against the specified extension.
	 */
	for (extensionp = heuristic_open_info[i].extensions_set; *extensionp != NULL;
	    extensionp++) {
		if (strcmp(extension, *extensionp) == 0) {
			return TRUE;	/* it's one of them */
		}
	}
	return FALSE;	/* it's not one of them */
}

/* Opens a file and prepares a ftap struct.
   If "do_random" is TRUE, it opens the file twice; the second open
   allows the application to do random-access I/O without moving
   the seek offset for sequential I/O, which is used by Wireshark
   so that it can do sequential I/O to a capture file that's being
   written to as new packets arrive independently of random I/O done
   to display protocol trees for packets when they're selected. */
ftap* ftap_open_offline(const char *filename, int *err, char **err_info,
			gboolean do_random)
{
	int	fd;
	ws_statb64 statb;
	ftap	*fth;
	unsigned int	i;
	gboolean use_stdin = FALSE;
	gchar *extension;

	/* open standard input if filename is '-' */
	if (strcmp(filename, "-") == 0)
		use_stdin = TRUE;

	/* First, make sure the file is valid */
	if (use_stdin) {
		if (ws_fstat64(0, &statb) < 0) {
			*err = errno;
			return NULL;
		}
	} else {
		if (ws_stat64(filename, &statb) < 0) {
			*err = errno;
			return NULL;
		}
	}
	if (S_ISFIFO(statb.st_mode)) {
		/*
		 * Opens of FIFOs are allowed only when not opening
		 * for random access.
		 *
		 * XXX - currently, we do seeking when trying to find
		 * out the file type, so we don't actually support
		 * opening FIFOs.  However, we may eventually
		 * do buffering that allows us to do at least some
		 * file type determination even on pipes, so we
		 * allow FIFO opens and let things fail later when
		 * we try to seek.
		 */
		if (do_random) {
			*err = FTAP_ERR_RANDOM_OPEN_PIPE;
			return NULL;
		}
	} else if (S_ISDIR(statb.st_mode)) {
		/*
		 * Return different errors for "this is a directory"
		 * and "this is some random special file type", so
		 * the user can get a potentially more helpful error.
		 */
		*err = EISDIR;
		return NULL;
	} else if (! S_ISREG(statb.st_mode)) {
		*err = FTAP_ERR_NOT_REGULAR_FILE;
		return NULL;
	}

	/*
	 * We need two independent descriptors for random access, so
	 * they have different file positions.  If we're opening the
	 * standard input, we can only dup it to get additional
	 * descriptors, so we can't have two independent descriptors,
	 * and thus can't do random access.
	 */
	if (use_stdin && do_random) {
		*err = FTAP_ERR_RANDOM_OPEN_STDIN;
		return NULL;
	}

	errno = ENOMEM;
	fth = (ftap *)g_malloc0(sizeof(ftap));

	/* Open the file */
	errno = FTAP_ERR_CANT_OPEN;
	if (use_stdin) {
		/*
		 * We dup FD 0, so that we don't have to worry about
		 * a file_close of wth->fh closing the standard
		 * input of the process.
		 */
		fd = ws_dup(0);
		if (fd < 0) {
			*err = errno;
			g_free(fth);
			return NULL;
		}
#ifdef _WIN32
		if (_setmode(fd, O_BINARY) == -1) {
			/* "Shouldn't happen" */
			*err = errno;
			g_free(fth);
			return NULL;
		}
#endif
		if (!(fth->fh = file_fdopen(fd))) {
			*err = errno;
			ws_close(fd);
			g_free(fth);
			return NULL;
		}
	} else {
		if (!(fth->fh = file_open(filename))) {
			*err = errno;
			g_free(fth);
			return NULL;
		}
	}

	if (do_random) {
		if (!(fth->random_fh = file_open(filename))) {
			*err = errno;
			file_close(fth->fh);
			g_free(fth);
			return NULL;
		}
	} else
		fth->random_fh = NULL;

	/* initialization */
	fth->file_encap = FTAP_ENCAP_UNKNOWN;
	fth->subtype_sequential_close = NULL;
	fth->subtype_close = NULL;
    fth->priv = NULL;

    init_magic_number_open_routines();
	init_heuristic_open_info();
	if (fth->random_fh) {
		fth->fast_seek = g_ptr_array_new();

		file_set_random_access(fth->fh, FALSE, fth->fast_seek);
		file_set_random_access(fth->random_fh, TRUE, fth->fast_seek);
	}

	/* Try all file types that support magic numbers */
	for (i = 0; i < magic_number_open_routines_arr->len; i++) {
		/* Seek back to the beginning of the file; the open routine
		   for the previous file type may have left the file
		   position somewhere other than the beginning, and the
		   open routine for this file type will probably want
		   to start reading at the beginning.

		   Initialize the data offset while we're at it. */
		if (file_seek(fth->fh, 0, SEEK_SET, err) == -1) {
			/* I/O error - give up */
			ftap_close(fth);
			return NULL;
		}

		switch ((*magic_number_open_routines[i])(fth, err, err_info)) {

		case -1:
			/* I/O error - give up */
			ftap_close(fth);
			return NULL;

		case 0:
			/* No I/O error, but not that type of file */
			break;

		case 1:
			/* We found the file type */
			goto success;
		}
	}

	/* Does this file's name have an extension? */
	extension = get_file_extension(filename);
	if (extension != NULL) {
		/* Yes - try the heuristic types that use that extension first. */
		for (i = 0; i < heuristic_open_info_arr->len; i++) {
			/* Does this type use that extension? */
			if (heuristic_uses_extension(i, extension)) {
				/* Yes. */
				if (file_seek(fth->fh, 0, SEEK_SET, err) == -1) {
					/* I/O error - give up */
					g_free(extension);
					ftap_close(fth);
					return NULL;
				}

				switch ((*heuristic_open_info[i].open_routine)(fth,
				    err, err_info)) {

				case -1:
					/* I/O error - give up */
					g_free(extension);
					ftap_close(fth);
					return NULL;

				case 0:
					/* No I/O error, but not that type of file */
					break;

				case 1:
					/* We found the file type */
					g_free(extension);
					goto success;
				}
			}
		}

		/* Now try the ones that don't use it. */
		for (i = 0; i < heuristic_open_info_arr->len; i++) {
			/* Does this type use that extension? */
			if (!heuristic_uses_extension(i, extension)) {
				/* No. */
				if (file_seek(fth->fh, 0, SEEK_SET, err) == -1) {
					/* I/O error - give up */
					g_free(extension);
					ftap_close(fth);
					return NULL;
				}

				switch ((*heuristic_open_info[i].open_routine)(fth,
				    err, err_info)) {

				case -1:
					/* I/O error - give up */
					g_free(extension);
					ftap_close(fth);
					return NULL;

				case 0:
					/* No I/O error, but not that type of file */
					break;

				case 1:
					/* We found the file type */
					g_free(extension);
					goto success;
				}
			}
		}
		g_free(extension);
	} else {
		/* No - try all the heuristics types in order. */
		for (i = 0; i < heuristic_open_info_arr->len; i++) {
			if (file_seek(fth->fh, 0, SEEK_SET, err) == -1) {
				/* I/O error - give up */
				ftap_close(fth);
				return NULL;
			}

			switch ((*heuristic_open_info[i].open_routine)(fth,
			    err, err_info)) {

			case -1:
				/* I/O error - give up */
				ftap_close(fth);
				return NULL;

			case 0:
				/* No I/O error, but not that type of file */
				break;

			case 1:
				/* We found the file type */
				goto success;
			}
		}
	}

    /* Well, it's not one of the types of file we know about. */
	ftap_close(fth);
	*err = FTAP_ERR_FILE_UNKNOWN_FORMAT;
	return NULL;

success:
	fth->frame_buffer = (struct Buffer *)g_malloc(sizeof(struct Buffer));
	buffer_init(fth->frame_buffer, 1500);

	return fth;
}

/*
 * Given the pathname of the file we just closed with ftap_fdclose(), attempt
 * to reopen that file and assign the new file descriptor(s) to the sequential
 * stream and, if do_random is TRUE, to the random stream.  Used on Windows
 * after the rename of a file we had open was done or if the rename of a
 * file on top of a file we had open failed.
 *
 * This is only required by Wireshark, not TShark, and, at the point that
 * Wireshark is doing this, the sequential stream is closed, and the
 * random stream is open, so this refuses to open pipes, and only
 * reopens the random stream.
 */
gboolean
ftap_fdreopen(ftap *fth, const char *filename, int *err)
{
	ws_statb64 statb;

	/*
	 * We need two independent descriptors for random access, so
	 * they have different file positions.  If we're opening the
	 * standard input, we can only dup it to get additional
	 * descriptors, so we can't have two independent descriptors,
	 * and thus can't do random access.
	 */
	if (strcmp(filename, "-") == 0) {
		*err = FTAP_ERR_RANDOM_OPEN_STDIN;
		return FALSE;
	}

	/* First, make sure the file is valid */
	if (ws_stat64(filename, &statb) < 0) {
		*err = errno;
		return FALSE;
	}
	if (S_ISFIFO(statb.st_mode)) {
		/*
		 * Opens of FIFOs are not allowed; see above.
		 */
		*err = FTAP_ERR_RANDOM_OPEN_PIPE;
		return FALSE;
	} else if (S_ISDIR(statb.st_mode)) {
		/*
		 * Return different errors for "this is a directory"
		 * and "this is some random special file type", so
		 * the user can get a potentially more helpful error.
		 */
		*err = EISDIR;
		return FALSE;
	} else if (! S_ISREG(statb.st_mode)) {
		*err = FTAP_ERR_NOT_REGULAR_FILE;
		return FALSE;
	}

	/* Open the file */
	errno = FTAP_ERR_CANT_OPEN;
	if (!file_fdreopen(fth->random_fh, filename)) {
		*err = errno;
		return FALSE;
	}
	return TRUE;
}

/* Table of the file types we know about.
   Entries must be sorted by FTAP_FILE_TYPE_SUBTYPE_xxx values in ascending order */
static const struct ftap_file_type_subtype_info dump_open_table_base[] = {
	/* FTAP_FILE_TYPE_SUBTYPE_UNKNOWN (only used internally for initialization) */
	{ NULL, NULL, NULL, NULL },
};

gint ftap_num_file_types_subtypes = sizeof(dump_open_table_base) / sizeof(struct ftap_file_type_subtype_info);

static GArray*  dump_open_table_arr = NULL;
static const struct ftap_file_type_subtype_info* dump_open_table = dump_open_table_base;

/* initialize the file types array if it has not being initialized yet */
static void init_file_types_subtypes(void) {

	if (dump_open_table_arr) return;

	dump_open_table_arr = g_array_new(FALSE,TRUE,sizeof(struct ftap_file_type_subtype_info));

	g_array_append_vals(dump_open_table_arr,dump_open_table_base,ftap_num_file_types_subtypes);

	dump_open_table = (const struct ftap_file_type_subtype_info*)(void *)dump_open_table_arr->data;
}

int ftap_register_file_type_subtypes(const struct ftap_file_type_subtype_info* fi) {
	init_file_types_subtypes();

	g_array_append_val(dump_open_table_arr,*fi);

	dump_open_table = (const struct ftap_file_type_subtype_info*)(void *)dump_open_table_arr->data;

	return ftap_num_file_types_subtypes++;
}

int ftap_get_num_file_types_subtypes(void)
{
	return ftap_num_file_types_subtypes;
}

/*
 * Given a GArray of FTAP_ENCAP_ types, return the per-file encapsulation
 * type that would be needed to write out a file with those types.  If
 * there's only one type, it's that type, otherwise it's
 * FTAP_ENCAP_PER_RECORD.
 */
int
ftap_dump_file_encap_type(const GArray *file_encaps)
{
	int encap;

	encap = FTAP_ENCAP_PER_RECORD;
	if (file_encaps->len == 1) {
		/* OK, use the one-and-only encapsulation type. */
		encap = g_array_index(file_encaps, gint, 0);
	}
	return encap;
}

/* Name that should be somewhat descriptive. */
const char *ftap_file_type_subtype_string(int file_type_subtype)
{
	if (file_type_subtype < 0 || file_type_subtype >= ftap_num_file_types_subtypes) {
		g_error("Unknown capture file type %d", file_type_subtype);
		/** g_error() does an abort() and thus never returns **/
		return "";
	} else
		return dump_open_table[file_type_subtype].name;
}

/* Name to use in, say, a command-line flag specifying the type/subtype. */
const char *ftap_file_type_subtype_short_string(int file_type_subtype)
{
	if (file_type_subtype < 0 || file_type_subtype >= ftap_num_file_types_subtypes)
		return NULL;
	else
		return dump_open_table[file_type_subtype].short_name;
}

/* Translate a short name to a capture file type/subtype. */
int ftap_short_string_to_file_type_subtype(const char *short_name)
{
	int file_type_subtype;

	for (file_type_subtype = 0; file_type_subtype < ftap_num_file_types_subtypes; file_type_subtype++) {
		if (dump_open_table[file_type_subtype].short_name != NULL &&
		    strcmp(short_name, dump_open_table[file_type_subtype].short_name) == 0)
			return file_type_subtype;
	}

	return -1;	/* no such file type, or we can't write it */
}

static GSList *
add_extensions_for_file_type_subtype(int file_type_subtype, GSList *extensions,
    GSList *compressed_file_extensions)
{
	gchar **extensions_set, **extensionp;
	gchar *extension;

	/*
	 * Add the default extension, and all compressed variants of
	 * it.
	 */
	extensions = add_extensions(extensions,
	    dump_open_table[file_type_subtype].default_file_extension,
	    compressed_file_extensions);

	if (dump_open_table[file_type_subtype].additional_file_extensions != NULL) {
		/*
		 * We have additional extensions; add them.
		 *
		 * First, split the extension-list string into a set of
		 * extensions.
		 */
		extensions_set = g_strsplit(dump_open_table[file_type_subtype].additional_file_extensions,
		    ";", 0);

		/*
		 * Add each of those extensions to the list.
		 */
		for (extensionp = extensions_set; *extensionp != NULL;
		    extensionp++) {
			extension = *extensionp;

			/*
			 * Add the extension, and all compressed variants
			 * of it.
			 */
			extensions = add_extensions(extensions, extension,
			    compressed_file_extensions);
		}

		g_strfreev(extensions_set);
	}
	return extensions;
}

/* Return a list of file extensions that are used by the specified file type.

   If include_compressed is TRUE, the list will include compressed
   extensions, e.g. not just "pcap" but also "pcap.gz" if we can read
   gzipped files.

   All strings in the list are allocated with g_malloc() and must be freed
   with g_free(). */
GSList *ftap_get_file_extensions_list(int file_type_subtype, gboolean include_compressed)
{
	GSList *compressed_file_extensions;
	GSList *extensions;

	if (file_type_subtype < 0 || file_type_subtype >= ftap_num_file_types_subtypes)
		return NULL;	/* not a valid file type */

	if (dump_open_table[file_type_subtype].default_file_extension == NULL)
		return NULL;	/* valid, but no extensions known */

	extensions = NULL;	/* empty list, to start with */

	/*
	 * If include_compressions is true, get the list of compressed-file
	 * extensions.
	 */
	if (include_compressed)
		compressed_file_extensions = ftap_get_compressed_file_extensions();
	else
		compressed_file_extensions = NULL;

	/*
	 * Add all this file type's extensions, with compressed
	 * variants.
	 */
	extensions = add_extensions_for_file_type_subtype(file_type_subtype, extensions,
	    compressed_file_extensions);

	g_slist_free(compressed_file_extensions);
	return extensions;
}

/*
 * Free a list returned by ftap_get_file_extension_type_extensions(),
 * ftap_get_all_file_extensions_list, or ftap_get_file_extensions_list().
 */
void ftap_free_extensions_list(GSList *extensions)
{
	GSList *extension;

	for (extension = extensions; extension != NULL;
	    extension = g_slist_next(extension)) {
		g_free(extension->data);
	}
	g_slist_free(extensions);
}

/* Return the default file extension to use with the specified file type;
   that's just the extension, without any ".". */
const char *ftap_default_file_extension(int file_type_subtype)
{
	if (file_type_subtype < 0 || file_type_subtype >= ftap_num_file_types_subtypes)
		return NULL;
	else
		return dump_open_table[file_type_subtype].default_file_extension;
}
