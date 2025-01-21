/* ringbuffer.c
 * Routines for packet capture windows
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * <laurent.deniel@free.fr>
 *
 * Almost completely rewritten in order to:
 *
 * - be able to use a unlimited number of ringbuffer files
 * - close the current file and open (truncating) the next file at switch
 * - set the final file name once open (or reopen)
 * - avoid the deletion of files that could not be truncated (can't arise now)
 *   and do not erase empty files
 *
 * The idea behind that is to remove the limitation of the maximum # of
 * ringbuffer files being less than the maximum # of open fd per process
 * and to be able to reduce the amount of virtual memory usage (having only
 * one file open at most) or the amount of file system usage (by truncating
 * the files at switch and not the capture stop, and by closing them which
 * makes possible their move or deletion after a switch).
 *
 */

#include <config.h>

#ifdef HAVE_LIBPCAP

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <stdlib.h>
#include <glib.h>

#include <pcap/pcap.h>

#include <glib.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef _WIN32
#include <wsutil/win32-utils.h>
#endif

#include "ringbuffer.h"
#include <wsutil/array.h>
#include <wsutil/file_util.h>

/* Ringbuffer file structure */
typedef struct _rb_file {
    char          *name;
} rb_file;

#define MAX_FILENAME_QUEUE  100

/** Ringbuffer data structure */
typedef struct _ringbuf_data {
    rb_file      *files;
    unsigned      num_files;           /**< Number of ringbuffer files (1 to ...) */
    unsigned      curr_file_num;       /**< Number of the current file (ever increasing) */
    char         *fprefix;             /**< Filename prefix */
    char         *fsuffix;             /**< Filename suffix */
    bool          nametimenum;         /**< ...num_time... or ...time_num...   */
    bool          unlimited;           /**< true if unlimited number of files */

    int           fd;                  /**< Current ringbuffer file descriptor */
    pcapio_writer* pdh;
    bool          group_read_access;   /**< true if files need to be opened with group read access */
    FILE         *name_h;              /**< write names of completed files to this handle */
    const char   *compress_type;       /**< compress type */
} ringbuf_data;

static ringbuf_data rb_data;

/*
 * create the next filename and open a new binary file with that name
 */
static int
ringbuf_open_file(rb_file *rfile, int *err)
{
    char    filenum[5+1];
    char    timestr[14+1];
    time_t  current_time;
    struct tm *tm;

    if (rfile->name != NULL) {
        if (rb_data.unlimited == false) {
            /* remove old file (if any, so ignore error) */
            ws_unlink(rfile->name);
        }
        g_free(rfile->name);
    }

#ifdef _WIN32
    _tzset();
#endif
    current_time = time(NULL);

    snprintf(filenum, sizeof(filenum), "%05u", (rb_data.curr_file_num + 1) % RINGBUFFER_MAX_NUM_FILES);
    tm = localtime(&current_time);
    if (tm != NULL)
        strftime(timestr, sizeof(timestr), "%Y%m%d%H%M%S", tm);
    else
        (void) g_strlcpy(timestr, "196912312359", sizeof(timestr)); /* second before the Epoch */
    if (rb_data.nametimenum) {
        rfile->name = g_strconcat(rb_data.fprefix, "_", timestr, "_", filenum, rb_data.fsuffix, NULL);
    } else {
        rfile->name = g_strconcat(rb_data.fprefix, "_", filenum, "_", timestr, rb_data.fsuffix, NULL);
    }

    if (rfile->name == NULL) {
        if (err != NULL)
            *err = ENOMEM;
        return -1;
    }

    rb_data.fd = ws_open(rfile->name, O_RDWR|O_BINARY|O_TRUNC|O_CREAT,
            rb_data.group_read_access ? 0640 : 0600);

    if (rb_data.fd == -1 && err != NULL) {
        *err = errno;
    }

    return rb_data.fd;
}

/*
 * Initialize the ringbuffer data structures
 */
int
ringbuf_init(const char *capfile_name, unsigned num_files, bool group_read_access,
        const char *compress_type, bool has_nametimenum)
{
    unsigned int i;
    char        *pfx;
    char        *dir_name, *base_name;

    rb_data.files = NULL;
    rb_data.curr_file_num = 0;
    rb_data.fprefix = NULL;
    rb_data.fsuffix = NULL;
    rb_data.nametimenum = has_nametimenum;
    rb_data.unlimited = false;
    rb_data.fd = -1;
    rb_data.pdh = NULL;
    rb_data.group_read_access = group_read_access;
    rb_data.name_h = NULL;
    rb_data.compress_type = compress_type;

    /* just to be sure ... */
    if (num_files <= RINGBUFFER_MAX_NUM_FILES) {
        rb_data.num_files = num_files;
    } else {
        rb_data.num_files = RINGBUFFER_MAX_NUM_FILES;
    }

    /* Check file name */
    if (capfile_name == NULL) {
        /* ringbuffer does not work with temporary files! */
        return -1;
    }

    /* set file name prefix/suffix */

    base_name = g_path_get_basename(capfile_name);
    dir_name = g_path_get_dirname(capfile_name);
    pfx = strrchr(base_name, '.');
    if (pfx != NULL) {
        /* The basename has a "." in it.

           Treat it as a separator between the rest of the file name and
           the file name suffix, and arrange that the names given to the
           ring buffer files have the specified suffix, i.e. put the
           changing part of the name *before* the suffix. */
        pfx[0] = '\0';
        /* Is the suffix a compression type extension? (XXX - Should
         * we only check this if compressing, and only for the compression
         * type used?) */
        GSList *compression_type_extensions = wtap_get_all_compression_type_extensions_list();
        for (GSList *compression_type_extension = compression_type_extensions;
            compression_type_extension != NULL;
            compression_type_extension = g_slist_next(compression_type_extension)) {

            if (g_ascii_strcasecmp(pfx + 1, (const char*)compression_type_extension->data) == 0) {
                /* It's a compression type extension. Is there a previous extension? */
                char *sfx = strrchr(base_name, '.');
                if (sfx != NULL) {
                    /* Yes. Use both extensions as the suffix. */
                    pfx[0] = '.'; /* restore last suffix */
                    sfx[0] = '\0';
                    pfx = sfx;
                }
                break;
            }
        }
        g_slist_free(compression_type_extensions);
        rb_data.fprefix = g_build_filename(dir_name, base_name, NULL);
        pfx[0] = '.'; /* restore capfile_name */
        rb_data.fsuffix = g_strdup(pfx);
    } else {
        /* The last component has no suffix. */
        rb_data.fprefix = g_strdup(capfile_name);
        rb_data.fsuffix = NULL;
    }
    g_free(dir_name);
    g_free(base_name);

    /* allocate rb_file structures (only one if unlimited since there is no
       need to save all file names in that case) */

    if (num_files == RINGBUFFER_UNLIMITED_FILES) {
        rb_data.unlimited = true;
        rb_data.num_files = 1;
    }

    rb_data.files = g_new(rb_file, rb_data.num_files);
    if (rb_data.files == NULL) {
        return -1;
    }

    for (i=0; i < rb_data.num_files; i++) {
        rb_data.files[i].name = NULL;
    }

    /* create the first file */
    if (ringbuf_open_file(&rb_data.files[0], NULL) == -1) {
        ringbuf_error_cleanup();
        return -1;
    }

    return rb_data.fd;
}

/*
 * Set name of file to which to print ringbuffer file names.
 */
bool
ringbuf_set_print_name(char *name, int *err)
{
    if (rb_data.name_h != NULL) {
        if (EOF == fclose(rb_data.name_h)) {
            if (err != NULL) {
                *err = errno;
            }
            return false;
        }
    }
    if (!strcmp(name, "-") || !strcmp(name, "stdout")) {
        rb_data.name_h = stdout;
    } else if (!strcmp(name, "stderr")) {
        rb_data.name_h = stderr;
    } else {
        if (NULL == (rb_data.name_h = ws_fopen(name, "wt"))) {
            if (err != NULL) {
                *err = errno;
            }
            return false;
        }
    }
    return true;
}

/*
 * Whether the ringbuf filenames are ready.
 * (Whether ringbuf_init is called and ringbuf_free is not called.)
 */
bool
ringbuf_is_initialized(void)
{
    return rb_data.files != NULL;
}

const char *
ringbuf_current_filename(void)
{
    return rb_data.files[rb_data.curr_file_num % rb_data.num_files].name;
}

/*
 * Calls ws_fdopen() for the current ringbuffer file
 */
pcapio_writer*
ringbuf_init_libpcap_fdopen(int *err)
{
    rb_data.pdh = writecap_fdopen(rb_data.fd, wtap_name_to_compression_type(rb_data.compress_type), err);

    return rb_data.pdh;
}

/*
 * Switches to the next ringbuffer file
 */
bool
ringbuf_switch_file(pcapio_writer* *pdh, char **save_file, int *save_file_fd, int *err)
{
    int     next_file_index;
    rb_file *next_rfile = NULL;

    /* close current file */

    if (!writecap_close(rb_data.pdh, err)) {
        ws_close(rb_data.fd);  /* XXX - the above should have closed this already */
        rb_data.pdh = NULL;    /* it's still closed, we just got an error while closing */
        rb_data.fd = -1;
        return false;
    }

    rb_data.pdh = NULL;
    rb_data.fd  = -1;

    if (rb_data.name_h != NULL) {
        fprintf(rb_data.name_h, "%s\n", ringbuf_current_filename());
        fflush(rb_data.name_h);
    }

    /* get the next file number and open it */

    rb_data.curr_file_num++ /* = next_file_num*/;
    next_file_index = (rb_data.curr_file_num) % rb_data.num_files;
    next_rfile = &rb_data.files[next_file_index];

    if (ringbuf_open_file(next_rfile, err) == -1) {
        return false;
    }

    if (ringbuf_init_libpcap_fdopen(err) == NULL) {
        return false;
    }

    /* switch to the new file */
    *save_file = next_rfile->name;
    *save_file_fd = rb_data.fd;
    (*pdh) = rb_data.pdh;

    return true;
}

/*
 * Calls fclose() for the current ringbuffer file
 */
bool
ringbuf_libpcap_dump_close(char **save_file, int *err)
{
    bool      ret_val = true;

    /* close current file, if it's open */
    if (rb_data.pdh != NULL) {
        if (!writecap_close(rb_data.pdh, err)) {
            ws_close(rb_data.fd);
            ret_val = false;
        }
        rb_data.pdh = NULL;
        rb_data.fd  = -1;
    }

    if (rb_data.name_h != NULL) {
        fprintf(rb_data.name_h, "%s\n", ringbuf_current_filename());
        fflush(rb_data.name_h);

        if (EOF == fclose(rb_data.name_h)) {
            /* Can't really do much about this, can we? */
        }
    }

    /* set the save file name to the current file */
    *save_file = rb_data.files[rb_data.curr_file_num % rb_data.num_files].name;
    return ret_val;
}

/*
 * Frees all memory allocated by the ringbuffer
 */
void
ringbuf_free(void)
{
    unsigned int i;

    if (rb_data.files != NULL) {
        for (i=0; i < rb_data.num_files; i++) {
            if (rb_data.files[i].name != NULL) {
                g_free(rb_data.files[i].name);
                rb_data.files[i].name = NULL;
            }
        }
        g_free(rb_data.files);
        rb_data.files = NULL;
    }
    if (rb_data.fprefix != NULL) {
        g_free(rb_data.fprefix);
        rb_data.fprefix = NULL;
    }
    if (rb_data.fsuffix != NULL) {
        g_free(rb_data.fsuffix);
        rb_data.fsuffix = NULL;
    }
}

/*
 * Frees all memory allocated by the ringbuffer
 */
void
ringbuf_error_cleanup(void)
{
    unsigned int i;

    /* try to close via wtap */
    if (rb_data.pdh != NULL) {
        if (writecap_close(rb_data.pdh, NULL) == 0) {
            rb_data.fd = -1;
        }
        rb_data.pdh = NULL;
    }

    /* close directly if still open */
    if (rb_data.fd != -1) {
        ws_close(rb_data.fd);
        rb_data.fd = -1;
    }

    if (rb_data.files != NULL) {
        for (i=0; i < rb_data.num_files; i++) {
            if (rb_data.files[i].name != NULL) {
                ws_unlink(rb_data.files[i].name);
            }
        }
    }

    if (rb_data.name_h != NULL) {
        if (EOF == fclose(rb_data.name_h)) {
            /* Can't really do much about this, can we? */
        }
    }

    /* free the memory */
    ringbuf_free();
}

#endif /* HAVE_LIBPCAP */
