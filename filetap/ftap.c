/* ftap.c
 *
 * Filetap Library
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "config.h"

#include <string.h>
#include <errno.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_LIBZ
#include <zlib.h>
#endif

#include "ftap-int.h"

#include "ft_file_wrappers.h"
#include <wsutil/file_util.h>
#include "buffer.h"

#ifdef HAVE_PLUGINS

#include <wsutil/plugins.h>

/*
 * List of wiretap plugins.
 */
typedef struct {
	void (*register_ftap_module)(void);  /* routine to call to register a wiretap module */
} ftap_plugin;

static GSList *ftap_plugins = NULL;

/*
 * Callback for each plugin found.
 */
static gboolean
check_for_ftap_plugin(GModule *handle)
{
	gpointer gp;
	void (*register_ftap_module)(void);
	ftap_plugin *plugin;

	/*
	 * Do we have a register_ftap_module routine?
	 */
	if (!g_module_symbol(handle, "register_ftap_module", &gp)) {
		/* No, so this isn't a filetap module plugin. */
		return FALSE;
	}

	/*
	 * Yes - this plugin includes one or more filetap modules.
	 */
	register_ftap_module = (void (*)(void))gp;

	/*
	 * Add this one to the list of wiretap module plugins.
	 */
	plugin = (ftap_plugin *)g_malloc(sizeof (ftap_plugin));
	plugin->register_ftap_module = register_ftap_module;
	ftap_plugins = g_slist_append(ftap_plugins, plugin);
	return TRUE;
}

void
ftap_register_plugin_types(void)
{
	add_plugin_type("file format", check_for_ftap_plugin);
}

static void
register_ftap_module_plugin(gpointer data, gpointer user_data _U_)
{
	ftap_plugin *plugin = (ftap_plugin *)data;

	(plugin->register_ftap_module)();
}

/*
 * For all wiretap module plugins, call their register routines.
 */
void
register_all_filetap_modules(void)
{
	g_slist_foreach(ftap_plugins, register_ftap_module_plugin, NULL);
}
#endif /* HAVE_PLUGINS */

/*
 * Return the size of the file, as reported by the OS.
 * (gint64, in case that's 64 bits.)
 */
gint64
ftap_file_size(ftap *fth, int *err)
{
	ws_statb64 statb;

	if (file_fstat((fth->fh == NULL) ? fth->random_fh : fth->fh,
	    &statb, err) == -1)
		return -1;
	return statb.st_size;
}

/*
 * Do an fstat on the file.
 */
int
ftap_fstat(ftap *fth, ws_statb64 *statb, int *err)
{
	if (file_fstat((fth->fh == NULL) ? fth->random_fh : fth->fh,
	    statb, err) == -1)
		return -1;
	return 0;
}

int
ftap_file_type_subtype(ftap *fth)
{
	return fth->file_type_subtype;
}

gboolean
ftap_iscompressed(ftap *fth)
{
	return file_iscompressed((fth->fh == NULL) ? fth->random_fh : fth->fh);
}

guint
ftap_snapshot_length(ftap *fth)
{
	return fth->snapshot_length;
}

int
ftap_file_encap(ftap *fth)
{
	return fth->file_encap;
}

/* Table of the encapsulation types we know about. */
struct encap_type_info {
	const char *name;
	const char *short_name;
};

static struct encap_type_info encap_table_base[] = {
	/* FTAP_ENCAP_UNKNOWN */
	{ "Unknown", "unknown" },
};

WS_DLL_LOCAL
gint ftap_num_encap_types = sizeof(encap_table_base) / sizeof(struct encap_type_info);
static GArray* encap_table_arr = NULL;

#define encap_table_entry(encap)	\
	g_array_index(encap_table_arr, struct encap_type_info, encap)

static void ftap_init_encap_types(void) {

	if (encap_table_arr) return;

	encap_table_arr = g_array_new(FALSE,TRUE,sizeof(struct encap_type_info));

	g_array_append_vals(encap_table_arr,encap_table_base,ftap_num_encap_types);
}

int ftap_get_num_encap_types(void) {
	ftap_init_encap_types();
	return ftap_num_encap_types;
}


int ftap_register_encap_type(const char* name, const char* short_name) {
	struct encap_type_info e;
	ftap_init_encap_types();

	e.name = g_strdup(name);
	e.short_name = g_strdup(short_name);

	g_array_append_val(encap_table_arr,e);

	return ftap_num_encap_types++;
}


/* Name that should be somewhat descriptive. */
const char *
ftap_encap_string(int encap)
{
	if (encap < FTAP_ENCAP_PER_RECORD || encap >= FTAP_NUM_ENCAP_TYPES)
		return "Illegal";
	else if (encap == FTAP_ENCAP_PER_RECORD)
		return "Per record";
	else
		return encap_table_entry(encap).name;
}

/* Name to use in, say, a command-line flag specifying the type. */
const char *
ftap_encap_short_string(int encap)
{
	if (encap < FTAP_ENCAP_PER_RECORD || encap >= FTAP_NUM_ENCAP_TYPES)
		return "illegal";
	else if (encap == FTAP_ENCAP_PER_RECORD)
		return "per-record";
	else
		return encap_table_entry(encap).short_name;
}

/* Translate a short name to a capture file type. */
int
ftap_short_string_to_encap(const char *short_name)
{
	int encap;

	for (encap = 0; encap < FTAP_NUM_ENCAP_TYPES; encap++) {
		if (encap_table_entry(encap).short_name != NULL &&
		    strcmp(short_name, encap_table_entry(encap).short_name) == 0)
			return encap;
	}
	return -1;	/* no such encapsulation type */
}

static const char *ftap_errlist[] = {
	"The file isn't a plain file or pipe",
	"The file is being opened for random access but is a pipe",
	"The file isn't a capture file in a known format",
	"File contains record data we don't support",
	"That file format cannot be written to a pipe",
	NULL,
	"Files can't be saved in that format",
	"Files from that network type can't be saved in that format",
	"That file format doesn't support per-packet encapsulations",
	NULL,
	NULL,
	"Less data was read than was expected",
	"The file appears to be damaged or corrupt",
	"Less data was written than was requested",
	"Uncompression error: data oddly truncated",
	"Uncompression error: data would overflow buffer",
	"Uncompression error: bad LZ77 offset",
	"The standard input cannot be opened for random access",
	"That file format doesn't support compression",
	NULL,
	NULL,
	"Uncompression error",
	"Internal error"
};
#define	FTAP_ERRLIST_SIZE	(sizeof ftap_errlist / sizeof ftap_errlist[0])

const char *
ftap_strerror(int err)
{
	static char errbuf[128];
	unsigned int ftap_errlist_index;

	if (err < 0) {
		ftap_errlist_index = -1 - err;
		if (ftap_errlist_index >= FTAP_ERRLIST_SIZE) {
			g_snprintf(errbuf, 128, "Error %d", err);
			return errbuf;
		}
		if (ftap_errlist[ftap_errlist_index] == NULL)
			return "Unknown reason";
		return ftap_errlist[ftap_errlist_index];
	} else
		return g_strerror(err);
}

/* Close only the sequential side, freeing up memory it uses.

   Note that we do *not* want to call the subtype's close function,
   as it would free any per-subtype data, and that data may be
   needed by the random-access side.

   Instead, if the subtype has a "sequential close" function, we call it,
   to free up stuff used only by the sequential side. */
void
ftap_sequential_close(ftap *fth)
{
	if (fth->subtype_sequential_close != NULL)
		(*fth->subtype_sequential_close)(fth);

	if (fth->fh != NULL) {
		file_close(fth->fh);
		fth->fh = NULL;
	}

	if (fth->frame_buffer) {
		buffer_free(fth->frame_buffer);
		g_free(fth->frame_buffer);
		fth->frame_buffer = NULL;
	}
}

static void
g_fast_seek_item_free(gpointer data, gpointer user_data _U_)
{
	g_free(data);
}

/*
 * Close the file descriptors for the sequential and random streams, but
 * don't discard any information about those streams.  Used on Windows if
 * we need to rename a file that we have open or if we need to rename on
 * top of a file we have open.
 */
void
ftap_fdclose(ftap *fth)
{
	if (fth->fh != NULL)
		file_fdclose(fth->fh);
	if (fth->random_fh != NULL)
		file_fdclose(fth->random_fh);
}

void
ftap_close(ftap *fth)
{
	ftap_sequential_close(fth);

	if (fth->subtype_close != NULL)
		(*fth->subtype_close)(fth);

	if (fth->random_fh != NULL)
		file_close(fth->random_fh);

	if (fth->priv != NULL)
		g_free(fth->priv);

	if (fth->fast_seek != NULL) {
		g_ptr_array_foreach(fth->fast_seek, g_fast_seek_item_free, NULL);
		g_ptr_array_free(fth->fast_seek, TRUE);
	}

    g_free(fth);
}

void
ftap_cleareof(ftap *fth) {
	/* Reset EOF */
	file_clearerr(fth->fh);
}

gboolean
ftap_read(ftap *fth, int *err, gchar **err_info, gint64 *data_offset)
{
#if 0
	/*
	 * Set the packet encapsulation to the file's encapsulation
	 * value; if that's not FTAP_ENCAP_PER_RECORD, it's the
	 * right answer (and means that the read routine for this
	 * capture file type doesn't have to set it), and if it
	 * *is* FTAP_ENCAP_PER_RECORD, the caller needs to set it
	 * anyway.
	 */
	wth->phdr.pkt_encap = wth->file_encap;
#endif

	if (!fth->subtype_read(fth, err, err_info, data_offset)) {
		/*
		 * If we didn't get an error indication, we read
		 * the last packet.  See if there's any deferred
		 * error, as might, for example, occur if we're
		 * reading a compressed file, and we got an error
		 * reading compressed data from the file, but
		 * got enough compressed data to decompress the
		 * last packet of the file.
		 */
		if (*err == 0)
			*err = file_error(fth->fh, err_info);
		return FALSE;	/* failure */
	}

#if 0
	/*
	 * It makes no sense for the captured data length to be bigger
	 * than the actual data length.
	 */
	if (wth->phdr.caplen > wth->phdr.len)
		wth->phdr.caplen = wth->phdr.len;

	/*
	 * Make sure that it's not FTAP_ENCAP_PER_RECORD, as that
	 * probably means the file has that encapsulation type
	 * but the read routine didn't set this packet's
	 * encapsulation type.
	 */
	g_assert(wth->phdr.pkt_encap != FTAP_ENCAP_PER_RECORD);

#endif
	return TRUE;	/* success */
}

/*
 * Read packet data into a Buffer, growing the buffer as necessary.
 *
 * This returns an error on a short read, even if the short read hit
 * the EOF immediately.  (The assumption is that each packet has a
 * header followed by raw packet data, and that we've already read the
 * header, so if we get an EOF trying to read the packet data, the file
 * has been cut short, even if the read didn't read any data at all.)
 */
gboolean
ftap_read_packet_bytes(FILE_F fh, Buffer *buf, guint length, int *err,
    gchar **err_info)
{
	int	bytes_read;

	buffer_assure_space(buf, length);
	errno = FTAP_ERR_CANT_READ;
	bytes_read = file_read(buffer_start_ptr(buf), length, fh);

	if (bytes_read < 0 || (guint)bytes_read != length) {
		*err = file_error(fh, err_info);
		if (*err == 0)
			*err = FTAP_ERR_SHORT_READ;
		return FALSE;
	}
	return TRUE;
}

/*
 * Return an approximation of the amount of data we've read sequentially
 * from the file so far.  (gint64, in case that's 64 bits.)
 */
gint64
ftap_read_so_far(ftap *fth)
{
	return file_tell_raw(fth->fh);
}

#if 0
struct wtap_pkthdr *
wtap_phdr(wtap *wth)
{
	return &wth->phdr;
}

guint8 *
wtap_buf_ptr(wtap *wth)
{
	return buffer_start_ptr(wth->frame_buffer);
}
#endif

gboolean
ftap_seek_read(ftap *fth, gint64 seek_off,
	Buffer *buf, int len,
	int *err, gchar **err_info)
{
	return fth->subtype_seek_read(fth, seek_off, buf, len,
		err, err_info);
}
