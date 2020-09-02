/* Combine multiple dump files, either by appending or by merging by timestamp
 *
 * Written by Scott Renfro <scott@renfro.org> based on
 * editcap by Richard Sharpe and Guy Harris
 *
 * Copyright 2013, Scott Renfro <scott[AT]renfro.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <string.h>
#include "merge.h"
#include "wtap_opttypes.h"
#include "pcapng.h"
#include "wtap-int.h"

#include <wsutil/filesystem.h>
#include "wsutil/os_version_info.h"


#if 0
#define merge_debug(...) g_warning(__VA_ARGS__)
#else
#define merge_debug(...)
#endif


static const char* idb_merge_mode_strings[] = {
    /* IDB_MERGE_MODE_NONE */
    "none",
    /* IDB_MERGE_MODE_ALL_SAME */
    "all",
    /* IDB_MERGE_MODE_ANY_SAME */
    "any",
    /* IDB_MERGE_MODE_MAX */
    "UNKNOWN"
};

idb_merge_mode
merge_string_to_idb_merge_mode(const char *name)
{
    int i;
    for (i = 0; i < IDB_MERGE_MODE_MAX; i++) {
        if (g_strcmp0(name, idb_merge_mode_strings[i]) == 0) {
            return (idb_merge_mode) i;
        }
    }
    return IDB_MERGE_MODE_MAX;
}

const char *
merge_idb_merge_mode_to_string(const int mode)
{
    if (mode >= 0 && mode < IDB_MERGE_MODE_MAX) {
        return idb_merge_mode_strings[mode];
    }
    return idb_merge_mode_strings[(int)IDB_MERGE_MODE_MAX];
}


static void
cleanup_in_file(merge_in_file_t *in_file)
{
    g_assert(in_file != NULL);

    wtap_close(in_file->wth);
    in_file->wth = NULL;

    g_array_free(in_file->idb_index_map, TRUE);
    in_file->idb_index_map = NULL;

    wtap_rec_cleanup(&in_file->rec);
    ws_buffer_free(&in_file->frame_buffer);
}

static void
add_idb_index_map(merge_in_file_t *in_file, const guint orig_index, const guint found_index)
{
    g_assert(in_file != NULL);
    g_assert(in_file->idb_index_map != NULL);

    /*
     * we didn't really need the orig_index, since just appending to the array
     * should result in the orig_index being its location in the array; but we
     * pass it into this function to do a sanity check here
     */
    g_assert(orig_index == in_file->idb_index_map->len);

    g_array_append_val(in_file->idb_index_map, found_index);
}

/** Open a number of input files to merge.
 *
 * @param in_file_count number of entries in in_file_names
 * @param in_file_names filenames of the input files
 * @param out_files output pointer with filled file array, or NULL
 * @param err wiretap error, if failed
 * @param err_info wiretap error string, if failed
 * @param err_fileno file on which open failed, if failed
 * @return TRUE if all files could be opened, FALSE otherwise
 */
static gboolean
merge_open_in_files(guint in_file_count, const char *const *in_file_names,
                    merge_in_file_t **out_files, merge_progress_callback_t* cb,
                    int *err, gchar **err_info, guint *err_fileno)
{
    guint i;
    guint j;
    size_t files_size = in_file_count * sizeof(merge_in_file_t);
    merge_in_file_t *files;
    gint64 size;

    files = (merge_in_file_t *)g_malloc0(files_size);
    *out_files = NULL;

    for (i = 0; i < in_file_count; i++) {
        files[i].filename    = in_file_names[i];
        files[i].wth         = wtap_open_offline(in_file_names[i], WTAP_TYPE_AUTO, err, err_info, FALSE);
        files[i].state       = RECORD_NOT_PRESENT;
        files[i].packet_num  = 0;

        if (!files[i].wth) {
            /* Close the files we've already opened. */
            for (j = 0; j < i; j++)
                cleanup_in_file(&files[j]);
            g_free(files);
            *err_fileno = i;
            return FALSE;
        }
        size = wtap_file_size(files[i].wth, err);
        if (size == -1) {
            for (j = 0; j != G_MAXUINT && j <= i; j++)
                cleanup_in_file(&files[j]);
            g_free(files);
            *err_fileno = i;
            return FALSE;
        }
        wtap_rec_init(&files[i].rec);
        ws_buffer_init(&files[i].frame_buffer, 1514);
        files[i].size = size;
        files[i].idb_index_map = g_array_new(FALSE, FALSE, sizeof(guint));
    }

    if (cb)
        cb->callback_func(MERGE_EVENT_INPUT_FILES_OPENED, 0, files, in_file_count, cb->data);

    *out_files = files;
    return TRUE;
}

/** Close the input files again.
 *
 * @param in_file_count number of entries in in_files
 * @param in_files input file array to be closed
 */
static void
merge_close_in_files(int in_file_count, merge_in_file_t in_files[])
{
    int i;
    for (i = 0; i < in_file_count; i++) {
        cleanup_in_file(&in_files[i]);
    }
}

/** Select an output frame type based on the input files
 *
 * If all files have the same frame type, then use that.
 * Otherwise select WTAP_ENCAP_PER_PACKET.  If the selected
 * output file type doesn't support per packet frame types,
 * then the wtap_dump_open call will fail with a reasonable
 * error condition.
 *
 * @param in_file_count number of entries in in_files
 * @param in_files input file array
 * @return the frame type
 */
static int
merge_select_frame_type(int in_file_count, merge_in_file_t in_files[])
{
    int i;
    int selected_frame_type;

    selected_frame_type = wtap_file_encap(in_files[0].wth);

    for (i = 1; i < in_file_count; i++) {
        int this_frame_type = wtap_file_encap(in_files[i].wth);
        if (selected_frame_type != this_frame_type) {
            selected_frame_type = WTAP_ENCAP_PER_PACKET;
            break;
        }
    }

    return selected_frame_type;
}

/*
 * returns TRUE if first argument is earlier than second
 */
static gboolean
is_earlier(nstime_t *l, nstime_t *r) /* XXX, move to nstime.c */
{
    if (l->secs > r->secs) {  /* left is later */
        return FALSE;
    } else if (l->secs < r->secs) { /* left is earlier */
        return TRUE;
    } else if (l->nsecs > r->nsecs) { /* tv_sec equal, l.usec later */
        return FALSE;
    }
    /* either one < two or one == two
     * either way, return one
     */
    return TRUE;
}

/** Read the next packet, in chronological order, from the set of files to
 * be merged.
 *
 * On success, set *err to 0 and return a pointer to the merge_in_file_t
 * for the file from which the packet was read.
 *
 * On a read error, set *err to the error and return a pointer to the
 * merge_in_file_t for the file on which we got an error.
 *
 * On an EOF (meaning all the files are at EOF), set *err to 0 and return
 * NULL.
 *
 * @param in_file_count number of entries in in_files
 * @param in_files input file array
 * @param err wiretap error, if failed
 * @param err_info wiretap error string, if failed
 * @return pointer to merge_in_file_t for file from which that packet
 * came or on which we got a read error, or NULL if we're at EOF on
 * all files
 */
static merge_in_file_t *
merge_read_packet(int in_file_count, merge_in_file_t in_files[],
                  int *err, gchar **err_info)
{
    int i;
    int ei = -1;
    nstime_t tv = NSTIME_INIT_MAX;
    wtap_rec *rec;

    /*
     * Make sure we have a record available from each file that's not at
     * EOF, and search for the record with the earliest time stamp or
     * with no time stamp (those records are treated as earlier than
     * all other records).  Yes, this means you won't get a chronological
     * merge of those records, but you obviously *can't* get that.
     */
    for (i = 0; i < in_file_count; i++) {
        gint64 data_offset;

        if (in_files[i].state == RECORD_NOT_PRESENT) {
            /*
             * No packet available, and we haven't seen an error or EOF yet,
             * so try to read the next packet.
             */
            if (!wtap_read(in_files[i].wth, &in_files[i].rec,
                           &in_files[i].frame_buffer, err, err_info,
                           &data_offset)) {
                if (*err != 0) {
                    in_files[i].state = GOT_ERROR;
                    return &in_files[i];
                }
                in_files[i].state = AT_EOF;
            } else
                in_files[i].state = RECORD_PRESENT;
        }

        if (in_files[i].state == RECORD_PRESENT) {
            rec = &in_files[i].rec;
            if (!(rec->presence_flags & WTAP_HAS_TS)) {
                /*
                 * No time stamp.  Pick this record, and stop looking.
                 */
                ei = i;
                break;
            }
            if (is_earlier(&rec->ts, &tv)) {
                /*
                 * This record's time stamp is earlier than any of the
                 * records we've seen so far.  Pick it, for now, but
                 * keep looking.
                 */
                tv = rec->ts;
                ei = i;
            }
        }
    }

    if (ei == -1) {
        /* All the streams are at EOF.  Return an EOF indication. */
        *err = 0;
        return NULL;
    }

    /* We'll need to read another packet from this file. */
    in_files[ei].state = RECORD_NOT_PRESENT;

    /* Count this packet. */
    in_files[ei].packet_num++;

    /*
     * Return a pointer to the merge_in_file_t of the file from which the
     * packet was read.
     */
    *err = 0;
    return &in_files[ei];
}

/** Read the next packet, in file sequence order, from the set of files
 * to be merged.
 *
 * On success, set *err to 0 and return a pointer to the merge_in_file_t
 * for the file from which the packet was read.
 *
 * On a read error, set *err to the error and return a pointer to the
 * merge_in_file_t for the file on which we got an error.
 *
 * On an EOF (meaning all the files are at EOF), set *err to 0 and return
 * NULL.
 *
 * @param in_file_count number of entries in in_files
 * @param in_files input file array
 * @param err wiretap error, if failed
 * @param err_info wiretap error string, if failed
 * @return pointer to merge_in_file_t for file from which that packet
 * came or on which we got a read error, or NULL if we're at EOF on
 * all files
 */
static merge_in_file_t *
merge_append_read_packet(int in_file_count, merge_in_file_t in_files[],
                         int *err, gchar **err_info)
{
    int i;
    gint64 data_offset;

    /*
     * Find the first file not at EOF, and read the next packet from it.
     */
    for (i = 0; i < in_file_count; i++) {
        if (in_files[i].state == AT_EOF)
            continue; /* This file is already at EOF */
        if (wtap_read(in_files[i].wth, &in_files[i].rec,
                      &in_files[i].frame_buffer, err, err_info,
                      &data_offset))
            break; /* We have a packet */
        if (*err != 0) {
            /* Read error - quit immediately. */
            in_files[i].state = GOT_ERROR;
            return &in_files[i];
        }
        /* EOF - flag this file as being at EOF, and try the next one. */
        in_files[i].state = AT_EOF;
    }
    if (i == in_file_count) {
        /* All the streams are at EOF.  Return an EOF indication. */
        *err = 0;
        return NULL;
    }

    /*
     * Return a pointer to the merge_in_file_t of the file from which the
     * packet was read.
     */
    *err = 0;
    return &in_files[i];
}


/* creates a section header block for the new output file */
static GArray*
create_shb_header(const merge_in_file_t *in_files, const guint in_file_count,
                  const gchar *app_name)
{
    GArray  *shb_hdrs;
    wtap_block_t shb_hdr;
    GString *comment_gstr;
    GString *os_info_str;
    guint i;
    char* shb_comment = NULL;
    wtapng_mandatory_section_t* shb_data;
    gsize opt_len;
    gchar *opt_str;

    shb_hdrs = wtap_file_get_shb_for_new_file(in_files[0].wth);
    shb_hdr = g_array_index(shb_hdrs, wtap_block_t, 0);

    comment_gstr = g_string_new("");

    /*
     * TODO: merge comments from all files
     *
     * XXX - do we want some way to record which comments, hardware/OS/app
     * descriptions, IDBs, etc.? came from which files?
     *
     * XXX - fix this to handle multiple comments from a single file.
     */
    if (wtap_block_get_nth_string_option_value(shb_hdr, OPT_COMMENT, 0, &shb_comment) == WTAP_OPTTYPE_SUCCESS &&
        strlen(shb_comment) > 0) {
        /* very lame way to save comments - does not save them from the other files */
        g_string_append_printf(comment_gstr, "%s \n",shb_comment);
    }

    g_string_append_printf(comment_gstr, "File created by merging: \n");

    for (i = 0; i < in_file_count; i++) {
        g_string_append_printf(comment_gstr, "File%d: %s \n",i+1,in_files[i].filename);
    }

    os_info_str = g_string_new("");
    get_os_version_info(os_info_str);

    shb_data = (wtapng_mandatory_section_t*)wtap_block_get_mandatory_data(shb_hdr);
    shb_data->section_length = -1;
    /* TODO: handle comments from each file being merged */
    opt_len = comment_gstr->len;
    opt_str = g_string_free(comment_gstr, FALSE);
    wtap_block_set_nth_string_option_value(shb_hdr, OPT_COMMENT, 0, opt_str, opt_len); /* section comment */
    g_free(opt_str);
    /*
     * XXX - and how do we preserve all the OPT_SHB_HARDWARE, OPT_SHB_OS,
     * and OPT_SHB_USERAPPL values from all the previous files?
     */
    wtap_block_remove_option(shb_hdr, OPT_SHB_HARDWARE);
    opt_len = os_info_str->len;
    opt_str = g_string_free(os_info_str, FALSE);
    if (opt_str) {
        wtap_block_set_string_option_value(shb_hdr, OPT_SHB_OS, opt_str, opt_len); /* UTF-8 string containing the name   */
                                                                                   /*  of the operating system used to create this section.     */
        g_free(opt_str);
    } else {
        /*
         * No OS information; remove the old version.
         */
        wtap_block_remove_option(shb_hdr, OPT_SHB_OS);
    }
    wtap_block_set_string_option_value(shb_hdr, OPT_SHB_USERAPPL, app_name, app_name ? strlen(app_name): 0 ); /* NULL if not available, UTF-8 string containing the name */
                                                                                      /*  of the application used to create this section.          */

    return shb_hdrs;
}

static gboolean
is_duplicate_idb(const wtap_block_t idb1, const wtap_block_t idb2)
{
    wtapng_if_descr_mandatory_t *idb1_mand, *idb2_mand;
    gboolean have_idb1_value, have_idb2_value;
    guint64 idb1_if_speed, idb2_if_speed;
    guint8 idb1_if_tsresol, idb2_if_tsresol;
    guint8 idb1_if_fcslen, idb2_if_fcslen;
    char *idb1_opt_comment, *idb2_opt_comment;
    char *idb1_if_name, *idb2_if_name;
    char *idb1_if_description, *idb2_if_description;
    char *idb1_if_hardware, *idb2_if_hardware;
    char *idb1_if_os, *idb2_if_os;

    g_assert(idb1 && idb2);
    idb1_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(idb1);
    idb2_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(idb2);

    merge_debug("merge::is_duplicate_idb() called");
    merge_debug("idb1_mand->wtap_encap == idb2_mand->wtap_encap: %s",
                 (idb1_mand->wtap_encap == idb2_mand->wtap_encap) ? "TRUE":"FALSE");
    if (idb1_mand->wtap_encap != idb2_mand->wtap_encap) {
        /* Clearly not the same interface. */
        merge_debug("merge::is_duplicate_idb() returning FALSE");
        return FALSE;
    }

    merge_debug("idb1_mand->time_units_per_second == idb2_mand->time_units_per_second: %s",
                 (idb1_mand->time_units_per_second == idb2_mand->time_units_per_second) ? "TRUE":"FALSE");
    if (idb1_mand->time_units_per_second != idb2_mand->time_units_per_second) {
        /*
         * Probably not the same interface, and we can't combine them
         * in any case.
         */
        merge_debug("merge::is_duplicate_idb() returning FALSE");
        return FALSE;
    }

    merge_debug("idb1_mand->tsprecision == idb2_mand->tsprecision: %s",
                 (idb1_mand->tsprecision == idb2_mand->tsprecision) ? "TRUE":"FALSE");
    if (idb1_mand->tsprecision != idb2_mand->tsprecision) {
        /*
         * Probably not the same interface, and we can't combine them
         * in any case.
         */
        merge_debug("merge::is_duplicate_idb() returning FALSE");
        return FALSE;
    }

    /* XXX: should snaplen not be compared? */
    merge_debug("idb1_mand->snap_len == idb2_mand->snap_len: %s",
                 (idb1_mand->snap_len == idb2_mand->snap_len) ? "TRUE":"FALSE");
    if (idb1_mand->snap_len != idb2_mand->snap_len) {
        merge_debug("merge::is_duplicate_idb() returning FALSE");
        return FALSE;
    }

    /* XXX - what do to if we have only one value? */
    have_idb1_value = (wtap_block_get_uint64_option_value(idb1, OPT_IDB_SPEED, &idb1_if_speed) == WTAP_OPTTYPE_SUCCESS);
    have_idb2_value = (wtap_block_get_uint64_option_value(idb2, OPT_IDB_SPEED, &idb2_if_speed) == WTAP_OPTTYPE_SUCCESS);
    if (have_idb1_value && have_idb2_value) {
        merge_debug("idb1_if_speed == idb2_if_speed: %s",
                     (idb1_if_speed == idb2_if_speed) ? "TRUE":"FALSE");
        if (idb1_if_speed != idb2_if_speed) {
            merge_debug("merge::is_duplicate_idb() returning FALSE");
            return FALSE;
        }
    }

    /* XXX - what do to if we have only one value? */
    have_idb1_value = (wtap_block_get_uint8_option_value(idb1, OPT_IDB_TSRESOL, &idb1_if_tsresol) == WTAP_OPTTYPE_SUCCESS);
    have_idb2_value = (wtap_block_get_uint8_option_value(idb2, OPT_IDB_TSRESOL, &idb2_if_tsresol) == WTAP_OPTTYPE_SUCCESS);
    if (have_idb1_value && have_idb2_value) {
        merge_debug("idb1_if_tsresol == idb2_if_tsresol: %s",
                     (idb1_if_tsresol == idb2_if_tsresol) ? "TRUE":"FALSE");
        if (idb1_if_tsresol != idb2_if_tsresol) {
            merge_debug("merge::is_duplicate_idb() returning FALSE");
            return FALSE;
        }
    }

    /* XXX - what do to if we have only one value? */
    have_idb1_value = (wtap_block_get_uint8_option_value(idb1, OPT_IDB_FCSLEN, &idb1_if_fcslen) == WTAP_OPTTYPE_SUCCESS);
    have_idb2_value = (wtap_block_get_uint8_option_value(idb2, OPT_IDB_FCSLEN, &idb2_if_fcslen) == WTAP_OPTTYPE_SUCCESS);
    if (have_idb1_value && have_idb2_value) {
        merge_debug("idb1_if_fcslen == idb2_if_fcslen: %s",
                     (idb1_if_fcslen == idb2_if_fcslen) ? "TRUE":"FALSE");
        if (idb1_if_fcslen == idb2_if_fcslen) {
            merge_debug("merge::is_duplicate_idb() returning FALSE");
            return FALSE;
        }
    }

    /*
     * XXX - handle multiple comments?
     * XXX - if the comments are different, just combine them if we
     * decide the two interfaces are really the same?  As comments
     * can be arbitrary strings added by people, the fact that they're
     * different doesn't necessarily mean the interfaces are different.
     */
    have_idb1_value = (wtap_block_get_nth_string_option_value(idb1, OPT_COMMENT, 0, &idb1_opt_comment) == WTAP_OPTTYPE_SUCCESS);
    have_idb2_value = (wtap_block_get_nth_string_option_value(idb2, OPT_COMMENT, 0, &idb2_opt_comment) == WTAP_OPTTYPE_SUCCESS);
    if (have_idb1_value && have_idb2_value) {
        merge_debug("g_strcmp0(idb1_opt_comment, idb2_opt_comment) == 0: %s",
                     (g_strcmp0(idb1_opt_comment, idb2_opt_comment) == 0) ? "TRUE":"FALSE");
        if (g_strcmp0(idb1_opt_comment, idb2_opt_comment) != 0) {
            merge_debug("merge::is_duplicate_idb() returning FALSE");
            return FALSE;
        }
    }

    /* XXX - what do to if we have only one value? */
    have_idb1_value = (wtap_block_get_string_option_value(idb1, OPT_IDB_NAME, &idb1_if_name) == WTAP_OPTTYPE_SUCCESS);
    have_idb2_value = (wtap_block_get_string_option_value(idb2, OPT_IDB_NAME, &idb2_if_name) == WTAP_OPTTYPE_SUCCESS);
    if (have_idb1_value && have_idb2_value) {
        merge_debug("g_strcmp0(idb1_if_name, idb2_if_name) == 0: %s",
                     (g_strcmp0(idb1_if_name, idb2_if_name) == 0) ? "TRUE":"FALSE");
        if (g_strcmp0(idb1_if_name, idb2_if_name) != 0) {
            merge_debug("merge::is_duplicate_idb() returning FALSE");
            return FALSE;
        }
    }

    /* XXX - what do to if we have only one value? */
    have_idb1_value = (wtap_block_get_string_option_value(idb1, OPT_IDB_DESCR, &idb1_if_description) == WTAP_OPTTYPE_SUCCESS);
    have_idb2_value = (wtap_block_get_string_option_value(idb2, OPT_IDB_DESCR, &idb2_if_description) == WTAP_OPTTYPE_SUCCESS);
    if (have_idb1_value && have_idb2_value) {
        merge_debug("g_strcmp0(idb1_if_description, idb2_if_description) == 0: %s",
                     (g_strcmp0(idb1_if_description, idb2_if_description) == 0) ? "TRUE":"FALSE");
        if (g_strcmp0(idb1_if_description, idb2_if_description) != 0) {
            merge_debug("merge::is_duplicate_idb() returning FALSE");
            return FALSE;
        }
    }

    /* XXX - what do to if we have only one value? */
    have_idb1_value = (wtap_block_get_string_option_value(idb1, OPT_IDB_HARDWARE, &idb1_if_hardware) == WTAP_OPTTYPE_SUCCESS);
    have_idb2_value = (wtap_block_get_string_option_value(idb2, OPT_IDB_HARDWARE, &idb2_if_hardware) == WTAP_OPTTYPE_SUCCESS);
    if (have_idb1_value && have_idb2_value) {
        merge_debug("g_strcmp0(idb1_if_hardware, idb2_if_hardware) == 0: %s",
                     (g_strcmp0(idb1_if_hardware, idb2_if_hardware) == 0) ? "TRUE":"FALSE");
        if (g_strcmp0(idb1_if_hardware, idb2_if_hardware) != 0) {
            merge_debug("merge::is_duplicate_idb() returning FALSE");
            return FALSE;
        }
    }

    /* XXX - what do to if we have only one value? */
    have_idb1_value = (wtap_block_get_string_option_value(idb1, OPT_IDB_OS, &idb1_if_os) == WTAP_OPTTYPE_SUCCESS);
    have_idb2_value = (wtap_block_get_string_option_value(idb2, OPT_IDB_OS, &idb2_if_os) == WTAP_OPTTYPE_SUCCESS);
    if (have_idb1_value && have_idb2_value) {
        merge_debug("g_strcmp0(idb1_if_os, idb2_if_os) == 0: %s",
                     (g_strcmp0(idb1_if_os, idb2_if_os) == 0) ? "TRUE":"FALSE");
        if (g_strcmp0(idb1_if_os, idb2_if_os) != 0) {
            merge_debug("merge::is_duplicate_idb() returning FALSE");
            return FALSE;
        }
    }

    /* does not compare filters nor interface statistics */
    merge_debug("merge::is_duplicate_idb() returning TRUE");
    return TRUE;
}

/*
 * Returns true if all of the input files have duplicate IDBs to the other files.
 */
static gboolean
all_idbs_are_duplicates(const merge_in_file_t *in_files, const guint in_file_count)
{
    wtapng_iface_descriptions_t *first_idb_list = NULL;
    wtapng_iface_descriptions_t *other_idb_list = NULL;
    guint first_idb_list_size, other_idb_list_size;
    wtap_block_t first_file_idb, other_file_idb;
    guint i, j;

    g_assert(in_files != NULL);

    /* get the first file's info */
    first_idb_list = wtap_file_get_idb_info(in_files[0].wth);
    g_assert(first_idb_list->interface_data);

    first_idb_list_size = first_idb_list->interface_data->len;

    /* now compare the other input files with that */
    for (i = 1; i < in_file_count; i++) {
        other_idb_list = wtap_file_get_idb_info(in_files[i].wth);
        g_assert(other_idb_list->interface_data);
        other_idb_list_size = other_idb_list->interface_data->len;

        if (other_idb_list_size != first_idb_list_size) {
            merge_debug("merge::all_idbs_are_duplicates: sizes of IDB lists don't match: first=%u, other=%u",
                         first_idb_list_size, other_idb_list_size);
            g_free(other_idb_list);
            g_free(first_idb_list);
            return FALSE;
        }

        for (j = 0; j < other_idb_list_size; j++) {
            first_file_idb = g_array_index(first_idb_list->interface_data, wtap_block_t, j);
            other_file_idb = g_array_index(other_idb_list->interface_data, wtap_block_t, j);

            if (!is_duplicate_idb(first_file_idb, other_file_idb)) {
                merge_debug("merge::all_idbs_are_duplicates: IDBs at index %d do not match, returning FALSE", j);
                g_free(other_idb_list);
                g_free(first_idb_list);
                return FALSE;
            }
        }
        g_free(other_idb_list);
    }

    merge_debug("merge::all_idbs_are_duplicates: returning TRUE");

    g_free(first_idb_list);

    return TRUE;
}

/*
 * Returns true if the given input_file_idb is a duplicate of an existing one
 * in the merged_idb_list; it's a duplicate if the interface description data
 * is all identical to a previous one in another input file. For this
 * function, the input file IDB's index does NOT need to match the index
 * location of a previous one to be considered a duplicate; any match is
 * considered a success. That means it will even match another IDB from its
 * own (same) input file.
 */
static gboolean
find_duplicate_idb(const wtap_block_t input_file_idb,
               const wtapng_iface_descriptions_t *merged_idb_list,
               guint *found_index)
{
    wtap_block_t merged_idb;
    guint i;

    g_assert(input_file_idb != NULL);
    g_assert(merged_idb_list != NULL);
    g_assert(merged_idb_list->interface_data != NULL);
    g_assert(found_index != NULL);

    for (i = 0; i < merged_idb_list->interface_data->len; i++) {
        merged_idb = g_array_index(merged_idb_list->interface_data, wtap_block_t, i);

        if (is_duplicate_idb(input_file_idb, merged_idb)) {
            *found_index = i;
            return TRUE;
        }
    }

    return FALSE;
}

/* adds IDB to merged file info, returns its index */
static guint
add_idb_to_merged_file(wtapng_iface_descriptions_t *merged_idb_list,
                       const wtap_block_t input_file_idb)
{
    wtap_block_t idb = wtap_block_create(WTAP_BLOCK_IF_DESCR);
    wtapng_if_descr_mandatory_t* idb_mand;

    g_assert(merged_idb_list != NULL);
    g_assert(merged_idb_list->interface_data != NULL);
    g_assert(input_file_idb != NULL);

    wtap_block_copy(idb, input_file_idb);
    idb_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(idb);

    /* Don't copy filter or stat information */
    idb_mand->num_stat_entries      = 0;          /* Number of ISB:s */
    idb_mand->interface_statistics  = NULL;

    g_array_append_val(merged_idb_list->interface_data, idb);

    return merged_idb_list->interface_data->len - 1;
}

/*
 * Create clone IDBs for the merge file, based on the input files and mode.
 */
static wtapng_iface_descriptions_t *
generate_merged_idbs(merge_in_file_t *in_files, const guint in_file_count, const idb_merge_mode mode)
{
    wtapng_iface_descriptions_t *merged_idb_list = NULL;
    wtapng_iface_descriptions_t *input_file_idb_list = NULL;
    wtap_block_t                 input_file_idb;
    guint                        itf_count, merged_index;
    guint                        i;

    /* create new IDB info */
    merged_idb_list = g_new(wtapng_iface_descriptions_t,1);
    merged_idb_list->interface_data = g_array_new(FALSE, FALSE, sizeof(wtap_block_t));

    if (mode == IDB_MERGE_MODE_ALL_SAME && all_idbs_are_duplicates(in_files, in_file_count)) {
        guint num_idbs;

        merge_debug("merge::generate_merged_idbs: mode ALL set and all IDBs are duplicates");

        /* they're all the same, so just get the first file's IDBs */
        input_file_idb_list = wtap_file_get_idb_info(in_files[0].wth);
        /* this is really one more than number of IDBs, but that's good for the for-loops */
        num_idbs = input_file_idb_list->interface_data->len;

        /* put them in the merged file */
        for (itf_count = 0; itf_count < num_idbs; itf_count++) {
            input_file_idb = g_array_index(input_file_idb_list->interface_data,
                                            wtap_block_t, itf_count);
            merged_index = add_idb_to_merged_file(merged_idb_list, input_file_idb);
            add_idb_index_map(&in_files[0], itf_count, merged_index);
        }

        /* and set all the other file index maps the same way */
        for (i = 1; i < in_file_count; i++) {
            for (itf_count = 0; itf_count < num_idbs; itf_count++) {
                add_idb_index_map(&in_files[i], itf_count, itf_count);
            }
        }

        g_free(input_file_idb_list);
    }
    else {
        for (i = 0; i < in_file_count; i++) {
            input_file_idb_list = wtap_file_get_idb_info(in_files[i].wth);

            for (itf_count = 0; itf_count < input_file_idb_list->interface_data->len; itf_count++) {
                input_file_idb = g_array_index(input_file_idb_list->interface_data,
                                                wtap_block_t, itf_count);

                if (mode == IDB_MERGE_MODE_ANY_SAME &&
                    find_duplicate_idb(input_file_idb, merged_idb_list, &merged_index))
                {
                    merge_debug("merge::generate_merged_idbs: mode ANY set and found a duplicate");
                    /*
                     * It's the same as a previous IDB, so we're going to "merge"
                     * them into one by adding a map from its old IDB index to the new
                     * one. This will be used later to change the rec interface_id.
                     */
                    add_idb_index_map(&in_files[i], itf_count, merged_index);
                }
                else {
                    merge_debug("merge::generate_merged_idbs: mode NONE set or did not find a duplicate");
                    /*
                     * This IDB does not match a previous (or we want to save all IDBs),
                     * so add the IDB to the merge file, and add a map of the indeces.
                     */
                    merged_index = add_idb_to_merged_file(merged_idb_list, input_file_idb);
                    add_idb_index_map(&in_files[i], itf_count, merged_index);
                }
            }

            g_free(input_file_idb_list);
        }
    }

    return merged_idb_list;
}

static gboolean
map_rec_interface_id(wtap_rec *rec, const merge_in_file_t *in_file)
{
    guint current_interface_id = 0;
    g_assert(rec != NULL);
    g_assert(in_file != NULL);
    g_assert(in_file->idb_index_map != NULL);

    if (rec->presence_flags & WTAP_HAS_INTERFACE_ID) {
        current_interface_id = rec->rec_header.packet_header.interface_id;
    }

    if (current_interface_id >= in_file->idb_index_map->len) {
        /* this shouldn't happen, but in a malformed input file it could */
        merge_debug("merge::map_rec_interface_id: current_interface_id (%u) >= in_file->idb_index_map->len (%u) (ERROR?)",
            current_interface_id, in_file->idb_index_map->len);
        return FALSE;
    }

    rec->rec_header.packet_header.interface_id = g_array_index(in_file->idb_index_map, guint, current_interface_id);
    rec->presence_flags |= WTAP_HAS_INTERFACE_ID;

    return TRUE;
}

static merge_result
merge_process_packets(wtap_dumper *pdh, const int file_type,
                      merge_in_file_t *in_files, const guint in_file_count,
                      const gboolean do_append, guint snaplen,
                      merge_progress_callback_t* cb,
                      GArray *dsb_combined,
                      int *err, gchar **err_info, guint *err_fileno,
                      guint32 *err_framenum)
{
    merge_result        status = MERGE_OK;
    merge_in_file_t    *in_file;
    int                 count = 0;
    gboolean            stop_flag = FALSE;
    wtap_rec *rec,      snap_rec;

    for (;;) {
        *err = 0;

        if (do_append) {
            in_file = merge_append_read_packet(in_file_count, in_files, err,
                                               err_info);
        }
        else {
            in_file = merge_read_packet(in_file_count, in_files, err,
                                        err_info);
        }

        if (in_file == NULL) {
            /* We're at EOF on all input files */
            break;
        }

        if (*err != 0) {
            /* I/O error reading from in_file */
            status = MERGE_ERR_CANT_READ_INFILE;
            break;
        }

        count++;
        if (cb)
            stop_flag = cb->callback_func(MERGE_EVENT_RECORD_WAS_READ, count, in_files, in_file_count, cb->data);

        if (stop_flag) {
            /* The user decided to abort the merge. */
            status = MERGE_USER_ABORTED;
            break;
        }

        rec = &in_file->rec;

        switch (rec->rec_type) {

        case REC_TYPE_PACKET:
            if (rec->presence_flags & WTAP_HAS_CAP_LEN) {
                if (snaplen != 0 &&
                    rec->rec_header.packet_header.caplen > snaplen) {
                    /*
                     * The dumper will only write up to caplen bytes out,
                     * so we only need to change that value, instead of
                     * cloning the whole packet with fewer bytes.
                     *
                     * XXX: but do we need to change the IDBs' snap_len?
                     */
                    snap_rec = *rec;
                    snap_rec.rec_header.packet_header.caplen = snaplen;
                    rec = &snap_rec;
                }
            }
            break;
        }

        if (file_type == WTAP_FILE_TYPE_SUBTYPE_PCAPNG) {
            /*
             * XXX - We should do this only for record types
             * that pertain to a particular interface; for
             * now, we hardcode that, but we need to figure
             * out a more general way to handle this.
             */
            if (rec->rec_type == REC_TYPE_PACKET) {
                if (!map_rec_interface_id(rec, in_file)) {
                    status = MERGE_ERR_BAD_PHDR_INTERFACE_ID;
                    break;
                }
            }
        }
        /*
         * If any DSBs were read before this record, be sure to pass those now
         * such that wtap_dump can pick it up.
         */
        if (dsb_combined && in_file->wth->dsbs) {
            GArray *in_dsb = in_file->wth->dsbs;
            for (guint i = in_file->dsbs_seen; i < in_dsb->len; i++) {
                wtap_block_t wblock = g_array_index(in_dsb, wtap_block_t, i);
                g_array_append_val(dsb_combined, wblock);
                in_file->dsbs_seen++;
            }
        }

        if (!wtap_dump(pdh, rec, ws_buffer_start_ptr(&in_file->frame_buffer),
                       err, err_info)) {
            status = MERGE_ERR_CANT_WRITE_OUTFILE;
            break;
        }
    }

    if (cb)
        cb->callback_func(MERGE_EVENT_DONE, count, in_files, in_file_count, cb->data);

    if (status == MERGE_OK || status == MERGE_USER_ABORTED) {
        if (!wtap_dump_close(pdh, err))
            status = MERGE_ERR_CANT_CLOSE_OUTFILE;
    } else {
        /*
         * We already got some error; no need to report another error on
         * close.
         *
         * Don't overwrite the earlier error.
         */
        int close_err = 0;
        (void)wtap_dump_close(pdh, &close_err);
    }

    /* Close the input files after the output file in case the latter still
     * holds references to blocks in the input file (such as the DSB). Even if
     * those DSBs are only written when wtap_dump is called and nothing bad will
     * happen now, let's keep all pointers in pdh valid for correctness sake. */
    merge_close_in_files(in_file_count, in_files);

    if (status == MERGE_OK || in_file == NULL) {
        *err_fileno = 0;
        *err_framenum = 0;
    } else {
        *err_fileno = (guint)(in_file - in_files);
        *err_framenum = in_file->packet_num;
    }

    return status;
}

static merge_result
merge_files_common(const gchar* out_filename, /* normal output mode */
                   gchar **out_filenamep, const char *pfx, /* tempfile mode  */
                   const int file_type, const char *const *in_filenames,
                   const guint in_file_count, const gboolean do_append,
                   const idb_merge_mode mode, guint snaplen,
                   const gchar *app_name, merge_progress_callback_t* cb,
                   int *err, gchar **err_info, guint *err_fileno,
                   guint32 *err_framenum)
{
    merge_in_file_t    *in_files = NULL;
    int                 frame_type = WTAP_ENCAP_PER_PACKET;
    merge_result        status = MERGE_OK;
    wtap_dumper        *pdh;
    GArray             *shb_hdrs = NULL;
    wtapng_iface_descriptions_t *idb_inf = NULL;
    GArray             *dsb_combined = NULL;

    g_assert(in_file_count > 0);
    g_assert(in_filenames != NULL);
    g_assert(err != NULL);
    g_assert(err_info != NULL);
    g_assert(err_fileno != NULL);
    g_assert(err_framenum != NULL);

    /* if a callback was given, it has to have a callback function ptr */
    g_assert((cb != NULL) ? (cb->callback_func != NULL) : TRUE);

    merge_debug("merge_files: begin");

    /* open the input files */
    if (!merge_open_in_files(in_file_count, in_filenames, &in_files, cb,
                             err, err_info, err_fileno)) {
        merge_debug("merge_files: merge_open_in_files() failed with err=%d", *err);
        *err_framenum = 0;
        return MERGE_ERR_CANT_OPEN_INFILE;
    }

    if (snaplen == 0) {
        /* Snapshot length not specified - default to the maximum. */
        snaplen = WTAP_MAX_PACKET_SIZE_STANDARD;
    }

    /*
     * This doesn't tell us that much. It tells us what to set the outfile's
     * encap type to, but that's all - for example, it does *not* tells us
     * whether the input files had the same number of IDBs, for the same exact
     * interfaces, and only one IDB each, so it doesn't actually tell us
     * whether we can merge IDBs into one or not.
     */
    frame_type = merge_select_frame_type(in_file_count, in_files);
    merge_debug("merge_files: got frame_type=%d", frame_type);

    if (cb)
        cb->callback_func(MERGE_EVENT_FRAME_TYPE_SELECTED, frame_type, in_files, in_file_count, cb->data);

    /* prepare the outfile */
    wtap_dump_params params = WTAP_DUMP_PARAMS_INIT;
    params.encap = frame_type;
    params.snaplen = snaplen;
    if (file_type == WTAP_FILE_TYPE_SUBTYPE_PCAPNG) {
        shb_hdrs = create_shb_header(in_files, in_file_count, app_name);
        merge_debug("merge_files: SHB created");

        idb_inf = generate_merged_idbs(in_files, in_file_count, mode);
        merge_debug("merge_files: IDB merge operation complete, got %u IDBs", idb_inf ? idb_inf->interface_data->len : 0);

        /* XXX other blocks like NRB are now discarded. */
        params.shb_hdrs = shb_hdrs;
        params.idb_inf = idb_inf;
        dsb_combined = g_array_new(FALSE, FALSE, sizeof(wtap_block_t));
        params.dsbs_growing = dsb_combined;
    }
    if (out_filename) {
        pdh = wtap_dump_open(out_filename, file_type, WTAP_UNCOMPRESSED, &params, err);
    } else if (out_filenamep) {
        pdh = wtap_dump_open_tempfile(out_filenamep, pfx, file_type,
                                      WTAP_UNCOMPRESSED, &params, err);
    } else {
        pdh = wtap_dump_open_stdout(file_type, WTAP_UNCOMPRESSED, &params, err);
    }
    if (pdh == NULL) {
        merge_close_in_files(in_file_count, in_files);
        g_free(in_files);
        wtap_block_array_free(shb_hdrs);
        wtap_free_idb_info(idb_inf);
        if (dsb_combined) {
            g_array_free(dsb_combined, TRUE);
        }
        *err_framenum = 0;
        return MERGE_ERR_CANT_OPEN_OUTFILE;
    }

    if (cb)
        cb->callback_func(MERGE_EVENT_READY_TO_MERGE, 0, in_files, in_file_count, cb->data);

    status = merge_process_packets(pdh, file_type, in_files, in_file_count,
                                   do_append, snaplen, cb, dsb_combined, err, err_info,
                                   err_fileno, err_framenum);

    g_free(in_files);
    wtap_block_array_free(shb_hdrs);
    wtap_free_idb_info(idb_inf);
    if (dsb_combined) {
        g_array_free(dsb_combined, TRUE);
    }

    return status;
}

/*
 * Merges the files to an output file whose name is supplied as an argument,
 * based on given input, and invokes callback during execution. Returns
 * MERGE_OK on success, or a MERGE_ERR_XXX on failure.
 */
merge_result
merge_files(const gchar* out_filename, const int file_type,
            const char *const *in_filenames, const guint in_file_count,
            const gboolean do_append, const idb_merge_mode mode,
            guint snaplen, const gchar *app_name, merge_progress_callback_t* cb,
            int *err, gchar **err_info, guint *err_fileno,
            guint32 *err_framenum)
{
    g_assert(out_filename != NULL);

    return merge_files_common(out_filename, NULL, NULL,
                              file_type, in_filenames, in_file_count,
                              do_append, mode, snaplen, app_name, cb, err,
                              err_info, err_fileno, err_framenum);
}

/*
 * Merges the files to a temporary file based on given input, and invokes
 * callback during execution. Returns MERGE_OK on success, or a MERGE_ERR_XXX
 * on failure.
 */
merge_result
merge_files_to_tempfile(gchar **out_filenamep, const char *pfx,
                        const int file_type, const char *const *in_filenames,
                        const guint in_file_count, const gboolean do_append,
                        const idb_merge_mode mode, guint snaplen,
                        const gchar *app_name, merge_progress_callback_t* cb,
                        int *err, gchar **err_info, guint *err_fileno,
                        guint32 *err_framenum)
{
    g_assert(out_filenamep != NULL);

    /* no temporary file name yet */
    *out_filenamep = NULL;

    return merge_files_common(NULL, out_filenamep, pfx,
                              file_type, in_filenames, in_file_count,
                              do_append, mode, snaplen, app_name, cb, err,
                              err_info, err_fileno, err_framenum);
}

/*
 * Merges the files to the standard output based on given input, and invokes
 * callback during execution. Returns MERGE_OK on success, or a MERGE_ERR_XXX
 * on failure.
 */
merge_result
merge_files_to_stdout(const int file_type, const char *const *in_filenames,
                      const guint in_file_count, const gboolean do_append,
                      const idb_merge_mode mode, guint snaplen,
                      const gchar *app_name, merge_progress_callback_t* cb,
                      int *err, gchar **err_info, guint *err_fileno,
                      guint32 *err_framenum)
{
    return merge_files_common(NULL, NULL, NULL,
                              file_type, in_filenames, in_file_count,
                              do_append, mode, snaplen, app_name, cb, err,
                              err_info, err_fileno, err_framenum);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
