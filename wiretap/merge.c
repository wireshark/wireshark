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

#define WS_LOG_DOMAIN LOG_DOMAIN_WIRETAP
#include "merge.h"

#include <stdlib.h>
#include <errno.h>

#ifndef _WIN32
#include <sys/resource.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

#include <string.h>
#include "wtap_opttypes.h"
#include "wtap-int.h"

#include <wsutil/filesystem.h>
#include "wsutil/os_version_info.h"
#include <wsutil/report_message.h>
#include <wsutil/wslog.h>
#include <wsutil/ws_assert.h>


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
    ws_assert(in_file != NULL);

    wtap_close(in_file->wth);
    in_file->wth = NULL;

    g_array_free(in_file->idb_index_map, true);
    in_file->idb_index_map = NULL;

    wtap_rec_cleanup(&in_file->rec);
    ws_buffer_free(&in_file->frame_buffer);
}

static void
add_idb_index_map(merge_in_file_t *in_file, const unsigned orig_index _U_, const unsigned found_index)
{
    ws_assert(in_file != NULL);
    ws_assert(in_file->idb_index_map != NULL);

    /*
     * we didn't really need the orig_index, since just appending to the array
     * should result in the orig_index being its location in the array; but we
     * pass it into this function to do a sanity check here
     */
    ws_assert(orig_index == in_file->idb_index_map->len);

    g_array_append_val(in_file->idb_index_map, found_index);
}

#ifndef _WIN32
static bool
raise_limit(int resource, unsigned add)
{
    struct rlimit rl;
    /* For now don't try to raise the hard limit; we could if we
     * have the appropriate privileges (CAP_SYS_RESOURCE on Linux).
     */
    if ((getrlimit(resource, &rl) == 0) && rl.rlim_cur < rl.rlim_max) {
        rlim_t old_cur = rl.rlim_cur;
        /* What open file descriptor limit do we need? */
        rl.rlim_cur = rl.rlim_cur + add;
        /* Check for overflow (unlikely). */
        rl.rlim_cur = MAX(old_cur, rl.rlim_cur);
        rl.rlim_cur = MIN(rl.rlim_cur, rl.rlim_max);
        if (setrlimit(resource, &rl) == 0) {
            return true;
        }
#if defined(__APPLE__)
        /* On Leopard, setrlimit(RLIMIT_NOFILE, ...) fails
         * on attempts to set rlim_cur above OPEN_MAX, even
         * if rlim_max > OPEN_MAX. OPEN_MAX is 10240.
         *
         * Starting with some later version (at least Mojave,
         * possibly earlier), it can be set to kern.maxfilesperproc
         * from sysctl, which is _usually_ higher than 10240.
         *
         * In Big Sur and later, it can always be set to rlim_max.
         * (That is, setrlimit() will return 0 and getrlimit() will
         * subsequently return the set value; the enforced limit
         * is the lesser of that and kern.maxfilesperproc.)
         */
        if (resource == RLIMIT_NOFILE) {
            unsigned int nlimit = 0;
            size_t limit_len = sizeof(nlimit);
            if (sysctlbyname("kern.maxfilesperproc", &nlimit, &limit_len, NULL, 0) != 0 || nlimit < OPEN_MAX) {
                rl.rlim_cur = OPEN_MAX;
            } else {
                rl.rlim_cur = nlimit;
            }
            if (setrlimit(RLIMIT_NOFILE, &rl) == 0) {
                return true;
            }
            if (rl.rlim_cur > OPEN_MAX) {
                rl.rlim_cur = OPEN_MAX;
                if (setrlimit(RLIMIT_NOFILE, &rl) == 0) {
                    return true;
                }
            }
        }
#endif
    }
    return false;
}
#endif

/** Open a number of input files to merge.
 *
 * @param in_file_count number of entries in in_file_names
 * @param in_file_names filenames of the input files
 * @param out_files output pointer with filled file array, or NULL
 * @param err wiretap error, if failed
 * @param err_info wiretap error string, if failed
 * @param err_fileno file on which open failed, if failed
 * @return The number of input files opened, which can be less than
 * the number requested if the limit of open file descriptors is reached.
 */
static unsigned
merge_open_in_files(unsigned in_file_count, const char *const *in_file_names,
                    merge_in_file_t **out_files, merge_progress_callback_t* cb,
                    int *err, char **err_info, unsigned *err_fileno)
{
    unsigned i = 0;
    unsigned j;
    size_t files_size = in_file_count * sizeof(merge_in_file_t);
    merge_in_file_t *files;
    int64_t size;
#ifndef _WIN32
    bool try_raise_nofile = false;
#endif

    files = (merge_in_file_t *)g_malloc0(files_size);
    *out_files = NULL;

    while (i < in_file_count) {
        files[i].filename    = in_file_names[i];
        files[i].wth         = wtap_open_offline(in_file_names[i], WTAP_TYPE_AUTO, err, err_info, false);
        files[i].state       = RECORD_NOT_PRESENT;
        files[i].packet_num  = 0;

        if (!files[i].wth) {
            if (*err == EMFILE && i > 2) {
                /* We need at least two opened files to merge things if we
                 * are batch processing. (If there was only one file to open
                 * then we can "merge" a single file so long as we don't get
                 * EMFILE, even though that's pointless.)
                 */
#ifdef _WIN32
                report_warning("Requested opening %u files but could only open %u: %s\nUsing temporary files to batch process.", in_file_count, i, g_strerror(*err));
#else
                if (!try_raise_nofile) {
                    try_raise_nofile = true;
                    if (raise_limit(RLIMIT_NOFILE, in_file_count - i)) {
                        continue;
                    }
                }
                report_warning("Requested opening %u files but could only open %u: %s\nUsing temporary files to batch process (try ulimit -n to adjust the limit).", in_file_count, i, g_strerror(*err));
#endif
                in_file_count = i;
                files_size = in_file_count * sizeof(merge_in_file_t);
                files = (merge_in_file_t *)g_realloc(files, files_size);
                *err = 0;
                break;
            } else {
                /* Close the files we've already opened. */
                for (j = 0; j < i; j++)
                    cleanup_in_file(&files[j]);
                g_free(files);
                *err_fileno = i;
                return 0;
            }
        }
        size = wtap_file_size(files[i].wth, err);
        if (size == -1) {
            for (j = 0; j != UINT_MAX && j <= i; j++)
                cleanup_in_file(&files[j]);
            g_free(files);
            *err_fileno = i;
            return 0;
        }
        wtap_rec_init(&files[i].rec);
        ws_buffer_init(&files[i].frame_buffer, 1514);
        files[i].size = size;
        files[i].idb_index_map = g_array_new(false, false, sizeof(unsigned));

        i++;
    }

    if (cb)
        cb->callback_func(MERGE_EVENT_INPUT_FILES_OPENED, 0, files, in_file_count, cb->data);

    *out_files = files;
    return in_file_count;
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
 * @param file_type output file type
 * @param in_file_count number of entries in in_files
 * @param in_files input file array
 * @return the frame type
 */
static int
merge_select_frame_type(const int file_type, int in_file_count, merge_in_file_t in_files[])
{
    int i;
    int selected_frame_type;

    selected_frame_type = wtap_file_encap(in_files[0].wth);
    if (!wtap_dump_can_write_encap(file_type, selected_frame_type)) {
        return WTAP_ENCAP_UNKNOWN;
    }

    for (i = 1; i < in_file_count; i++) {
        int this_frame_type = wtap_file_encap(in_files[i].wth);
        if (!wtap_dump_can_write_encap(file_type, this_frame_type)) {
            return WTAP_ENCAP_UNKNOWN;
        }
        if (selected_frame_type != this_frame_type) {
            selected_frame_type = WTAP_ENCAP_PER_PACKET;
            break;
        }
    }

    return selected_frame_type;
}

/*
 * returns true if first argument is earlier than second
 */
static bool
is_earlier(nstime_t *l, nstime_t *r) /* XXX, move to nstime.c */
{
    if (l->secs > r->secs) {  /* left is later */
        return false;
    } else if (l->secs < r->secs) { /* left is earlier */
        return true;
    } else if (l->nsecs > r->nsecs) { /* tv_sec equal, l.usec later */
        return false;
    }
    /* either one < two or one == two
     * either way, return one
     */
    return true;
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
                  int *err, char **err_info)
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
        int64_t data_offset;

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
                         int *err, char **err_info)
{
    int i;
    int64_t data_offset;

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
create_shb_header(const merge_in_file_t *in_files, const unsigned in_file_count,
                  const char *app_name)
{
    GArray  *shb_hdrs;
    wtap_block_t shb_hdr;
    GString *comment_gstr;
    GString *os_info_str;
    unsigned i;
    wtapng_section_mandatory_t* shb_data;
    size_t opt_len;
    char *opt_str;

    shb_hdrs = wtap_file_get_shb_for_new_file(in_files[0].wth);
    shb_hdr = g_array_index(shb_hdrs, wtap_block_t, 0);

    comment_gstr = g_string_new("");

    /*
     * TODO: merge comments from all files
     *
     * XXX - do we want some way to record which comments, hardware/OS/app
     * descriptions, IDBs, etc.? came from which files?
     */

    g_string_append_printf(comment_gstr, "File created by merging: \n");

    for (i = 0; i < in_file_count; i++) {
        g_string_append_printf(comment_gstr, "File%d: %s \n",i+1,in_files[i].filename);
    }

    os_info_str = g_string_new("");
    get_os_version_info(os_info_str);

    shb_data = (wtapng_section_mandatory_t*)wtap_block_get_mandatory_data(shb_hdr);
    shb_data->section_length = -1;
    /* TODO: handle comments from each file being merged */
    /* XXX: 65535 is the maximum size for an option (hence comment) in pcapng.
     * Truncate it? Let wiretap/pcapng.c decide what to do? (Currently it
     * writes nothing without reporting an error.) What if we support other
     * output file formats later?
     */
    opt_str = g_string_free(comment_gstr, FALSE);
    /* XXX: We probably want to prepend (insert at index 0) instead? */
    wtap_block_add_string_option_owned(shb_hdr, OPT_COMMENT, opt_str);
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

static bool
is_duplicate_idb(const wtap_block_t idb1, const wtap_block_t idb2)
{
    wtapng_if_descr_mandatory_t *idb1_mand, *idb2_mand;
    bool have_idb1_value, have_idb2_value;
    uint64_t idb1_if_speed, idb2_if_speed;
    uint8_t idb1_if_tsresol, idb2_if_tsresol;
    uint8_t idb1_if_fcslen, idb2_if_fcslen;
    char *idb1_opt_comment, *idb2_opt_comment;
    char *idb1_if_name, *idb2_if_name;
    char *idb1_if_description, *idb2_if_description;
    char *idb1_if_hardware, *idb2_if_hardware;
    char *idb1_if_os, *idb2_if_os;

    ws_assert(idb1 && idb2);
    idb1_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(idb1);
    idb2_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(idb2);

    ws_debug("merge::is_duplicate_idb() called");
    ws_debug("idb1_mand->wtap_encap == idb2_mand->wtap_encap: %s",
                 (idb1_mand->wtap_encap == idb2_mand->wtap_encap) ? "true":"false");
    if (idb1_mand->wtap_encap != idb2_mand->wtap_encap) {
        /* Clearly not the same interface. */
        ws_debug("returning false");
        return false;
    }

    ws_debug("idb1_mand->time_units_per_second == idb2_mand->time_units_per_second: %s",
                 (idb1_mand->time_units_per_second == idb2_mand->time_units_per_second) ? "true":"false");
    if (idb1_mand->time_units_per_second != idb2_mand->time_units_per_second) {
        /*
         * Probably not the same interface, and we can't combine them
         * in any case.
         */
        ws_debug("returning false");
        return false;
    }

    ws_debug("idb1_mand->tsprecision == idb2_mand->tsprecision: %s",
                 (idb1_mand->tsprecision == idb2_mand->tsprecision) ? "true":"false");
    if (idb1_mand->tsprecision != idb2_mand->tsprecision) {
        /*
         * Probably not the same interface, and we can't combine them
         * in any case.
         */
        ws_debug("returning false");
        return false;
    }

    /* XXX: should snaplen not be compared? */
    ws_debug("idb1_mand->snap_len == idb2_mand->snap_len: %s",
                 (idb1_mand->snap_len == idb2_mand->snap_len) ? "true":"false");
    if (idb1_mand->snap_len != idb2_mand->snap_len) {
        ws_debug("returning false");
        return false;
    }

    /* XXX - what do to if we have only one value? */
    have_idb1_value = (wtap_block_get_uint64_option_value(idb1, OPT_IDB_SPEED, &idb1_if_speed) == WTAP_OPTTYPE_SUCCESS);
    have_idb2_value = (wtap_block_get_uint64_option_value(idb2, OPT_IDB_SPEED, &idb2_if_speed) == WTAP_OPTTYPE_SUCCESS);
    if (have_idb1_value && have_idb2_value) {
        ws_debug("idb1_if_speed == idb2_if_speed: %s",
                     (idb1_if_speed == idb2_if_speed) ? "true":"false");
        if (idb1_if_speed != idb2_if_speed) {
            ws_debug("returning false");
            return false;
        }
    }

    /* XXX - what do to if we have only one value? */
    have_idb1_value = (wtap_block_get_uint8_option_value(idb1, OPT_IDB_TSRESOL, &idb1_if_tsresol) == WTAP_OPTTYPE_SUCCESS);
    have_idb2_value = (wtap_block_get_uint8_option_value(idb2, OPT_IDB_TSRESOL, &idb2_if_tsresol) == WTAP_OPTTYPE_SUCCESS);
    if (have_idb1_value && have_idb2_value) {
        ws_debug("idb1_if_tsresol == idb2_if_tsresol: %s",
                     (idb1_if_tsresol == idb2_if_tsresol) ? "true":"false");
        if (idb1_if_tsresol != idb2_if_tsresol) {
            ws_debug("returning false");
            return false;
        }
    }

    /* XXX - what do to if we have only one value? */
    have_idb1_value = (wtap_block_get_uint8_option_value(idb1, OPT_IDB_FCSLEN, &idb1_if_fcslen) == WTAP_OPTTYPE_SUCCESS);
    have_idb2_value = (wtap_block_get_uint8_option_value(idb2, OPT_IDB_FCSLEN, &idb2_if_fcslen) == WTAP_OPTTYPE_SUCCESS);
    if (have_idb1_value && have_idb2_value) {
        ws_debug("idb1_if_fcslen == idb2_if_fcslen: %s",
                     (idb1_if_fcslen == idb2_if_fcslen) ? "true":"false");
        if (idb1_if_fcslen == idb2_if_fcslen) {
            ws_debug("returning false");
            return false;
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
        ws_debug("g_strcmp0(idb1_opt_comment, idb2_opt_comment) == 0: %s",
                     (g_strcmp0(idb1_opt_comment, idb2_opt_comment) == 0) ? "true":"false");
        if (g_strcmp0(idb1_opt_comment, idb2_opt_comment) != 0) {
            ws_debug("returning false");
            return false;
        }
    }

    /* XXX - what do to if we have only one value? */
    have_idb1_value = (wtap_block_get_string_option_value(idb1, OPT_IDB_NAME, &idb1_if_name) == WTAP_OPTTYPE_SUCCESS);
    have_idb2_value = (wtap_block_get_string_option_value(idb2, OPT_IDB_NAME, &idb2_if_name) == WTAP_OPTTYPE_SUCCESS);
    if (have_idb1_value && have_idb2_value) {
        ws_debug("g_strcmp0(idb1_if_name, idb2_if_name) == 0: %s",
                     (g_strcmp0(idb1_if_name, idb2_if_name) == 0) ? "true":"false");
        if (g_strcmp0(idb1_if_name, idb2_if_name) != 0) {
            ws_debug("returning false");
            return false;
        }
    }

    /* XXX - what do to if we have only one value? */
    have_idb1_value = (wtap_block_get_string_option_value(idb1, OPT_IDB_DESCRIPTION, &idb1_if_description) == WTAP_OPTTYPE_SUCCESS);
    have_idb2_value = (wtap_block_get_string_option_value(idb2, OPT_IDB_DESCRIPTION, &idb2_if_description) == WTAP_OPTTYPE_SUCCESS);
    if (have_idb1_value && have_idb2_value) {
        ws_debug("g_strcmp0(idb1_if_description, idb2_if_description) == 0: %s",
                     (g_strcmp0(idb1_if_description, idb2_if_description) == 0) ? "true":"false");
        if (g_strcmp0(idb1_if_description, idb2_if_description) != 0) {
            ws_debug("returning false");
            return false;
        }
    }

    /* XXX - what do to if we have only one value? */
    have_idb1_value = (wtap_block_get_string_option_value(idb1, OPT_IDB_HARDWARE, &idb1_if_hardware) == WTAP_OPTTYPE_SUCCESS);
    have_idb2_value = (wtap_block_get_string_option_value(idb2, OPT_IDB_HARDWARE, &idb2_if_hardware) == WTAP_OPTTYPE_SUCCESS);
    if (have_idb1_value && have_idb2_value) {
        ws_debug("g_strcmp0(idb1_if_hardware, idb2_if_hardware) == 0: %s",
                     (g_strcmp0(idb1_if_hardware, idb2_if_hardware) == 0) ? "true":"false");
        if (g_strcmp0(idb1_if_hardware, idb2_if_hardware) != 0) {
            ws_debug("returning false");
            return false;
        }
    }

    /* XXX - what do to if we have only one value? */
    have_idb1_value = (wtap_block_get_string_option_value(idb1, OPT_IDB_OS, &idb1_if_os) == WTAP_OPTTYPE_SUCCESS);
    have_idb2_value = (wtap_block_get_string_option_value(idb2, OPT_IDB_OS, &idb2_if_os) == WTAP_OPTTYPE_SUCCESS);
    if (have_idb1_value && have_idb2_value) {
        ws_debug("g_strcmp0(idb1_if_os, idb2_if_os) == 0: %s",
                     (g_strcmp0(idb1_if_os, idb2_if_os) == 0) ? "true":"false");
        if (g_strcmp0(idb1_if_os, idb2_if_os) != 0) {
            ws_debug("returning false");
            return false;
        }
    }

    /* does not compare filters nor interface statistics */
    ws_debug("returning true");
    return true;
}

/*
 * Returns true if all of the input files have duplicate IDBs to the other files.
 */
static bool
all_idbs_are_duplicates(const merge_in_file_t *in_files, const unsigned in_file_count)
{
    wtapng_iface_descriptions_t *first_idb_list = NULL;
    wtapng_iface_descriptions_t *other_idb_list = NULL;
    unsigned first_idb_list_size, other_idb_list_size;
    wtap_block_t first_file_idb, other_file_idb;
    unsigned i, j;

    ws_assert(in_files != NULL);

    /* get the first file's info */
    first_idb_list = wtap_file_get_idb_info(in_files[0].wth);
    ws_assert(first_idb_list->interface_data);

    first_idb_list_size = first_idb_list->interface_data->len;

    /* now compare the other input files with that */
    for (i = 1; i < in_file_count; i++) {
        other_idb_list = wtap_file_get_idb_info(in_files[i].wth);
        ws_assert(other_idb_list->interface_data);
        other_idb_list_size = other_idb_list->interface_data->len;

        if (other_idb_list_size != first_idb_list_size) {
            ws_debug("sizes of IDB lists don't match: first=%u, other=%u",
                         first_idb_list_size, other_idb_list_size);
            g_free(other_idb_list);
            g_free(first_idb_list);
            return false;
        }

        for (j = 0; j < other_idb_list_size; j++) {
            first_file_idb = g_array_index(first_idb_list->interface_data, wtap_block_t, j);
            other_file_idb = g_array_index(other_idb_list->interface_data, wtap_block_t, j);

            if (!is_duplicate_idb(first_file_idb, other_file_idb)) {
                ws_debug("IDBs at index %d do not match, returning false", j);
                g_free(other_idb_list);
                g_free(first_idb_list);
                return false;
            }
        }
        g_free(other_idb_list);
    }

    ws_debug("returning true");

    g_free(first_idb_list);

    return true;
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
static bool
find_duplicate_idb(const wtap_block_t input_file_idb,
               const wtapng_iface_descriptions_t *merged_idb_list,
               unsigned *found_index)
{
    wtap_block_t merged_idb;
    unsigned i;

    ws_assert(input_file_idb != NULL);
    ws_assert(merged_idb_list != NULL);
    ws_assert(merged_idb_list->interface_data != NULL);
    ws_assert(found_index != NULL);

    for (i = 0; i < merged_idb_list->interface_data->len; i++) {
        merged_idb = g_array_index(merged_idb_list->interface_data, wtap_block_t, i);

        if (is_duplicate_idb(input_file_idb, merged_idb)) {
            *found_index = i;
            return true;
        }
    }

    return false;
}

/* Adds IDB to merged file info. If pdh is not NULL, also tries to
 * add the IDB to the file (if the file type supports writing IDBs).
 * returns true on success
 * (merged_idb_list->interface_data->len - 1 is the new index) */
static bool
add_idb_to_merged_file(wtapng_iface_descriptions_t *merged_idb_list,
                       const wtap_block_t input_file_idb, wtap_dumper *pdh,
                       int *err, char **err_info)
{
    wtap_block_t idb;
    wtapng_if_descr_mandatory_t* idb_mand;

    ws_assert(merged_idb_list != NULL);
    ws_assert(merged_idb_list->interface_data != NULL);
    ws_assert(input_file_idb != NULL);

    idb = wtap_block_make_copy(input_file_idb);
    idb_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(idb);

    /* Don't copy filter or stat information */
    idb_mand->num_stat_entries      = 0;          /* Number of ISB:s */
    idb_mand->interface_statistics  = NULL;

    if (pdh != NULL) {
        if (wtap_file_type_subtype_supports_block(wtap_dump_file_type_subtype(pdh), WTAP_BLOCK_IF_ID_AND_INFO) != BLOCK_NOT_SUPPORTED) {
            if (!wtap_dump_add_idb(pdh, input_file_idb, err, err_info)) {
                return false;
            }
        }
    }
    g_array_append_val(merged_idb_list->interface_data, idb);

    return true;
}

/*
 * Create clone IDBs for the merge file for IDBs found in the middle of
 * input files while processing.
 */
static bool
process_new_idbs(wtap_dumper *pdh, merge_in_file_t *in_files, const unsigned in_file_count, const idb_merge_mode mode, wtapng_iface_descriptions_t *merged_idb_list, int *err, char **err_info)
{
    wtap_block_t                 input_file_idb;
    unsigned                     itf_count, merged_index;
    unsigned                     i;

    for (i = 0; i < in_file_count; i++) {

        /*
         * The number below is the global interface number within wth,
         * not the number within the section. We will do both mappings
         * in map_rec_interface_id().
         */
        itf_count = in_files[i].wth->next_interface_data;
        while ((input_file_idb = wtap_get_next_interface_description(in_files[i].wth)) != NULL) {

            /* If we were initially in ALL mode and all the interfaces
             * did match, then we set the mode to ANY (merge duplicates).
             * If the interfaces didn't match, then we are still in ALL
             * mode, but treat that as NONE (write out all IDBs.)
             * XXX: Should there be separate modes for "match ALL at the start
             * and ANY later" vs "match ALL at the beginning and NONE later"?
             * Should there be a two-pass mode for people who want ALL mode to
             * work for IDBs in the middle of the file? (See #16542)
             */

            if (mode == IDB_MERGE_MODE_ANY_SAME &&
                find_duplicate_idb(input_file_idb, merged_idb_list, &merged_index))
            {
                ws_debug("mode ANY set and found a duplicate");
                /*
                 * It's the same as a previous IDB, so we're going to "merge"
                 * them into one by adding a map from its old IDB index to the
                 * new one. This will be used later to change the rec
                 * interface_id.
                 */
                add_idb_index_map(&in_files[i], itf_count, merged_index);
            }
            else {
                ws_debug("mode NONE or ALL set or did not find a duplicate");
                /*
                 * This IDB does not match a previous (or we want to save all
                 * IDBs), so add the IDB to the merge file, and add a map of
                 * the indices.
                 */
                if (add_idb_to_merged_file(merged_idb_list, input_file_idb, pdh, err, err_info)) {
                    merged_index = merged_idb_list->interface_data->len - 1;
                    add_idb_index_map(&in_files[i], itf_count, merged_index);
                } else {
                    return false;
                }
            }
            itf_count = in_files[i].wth->next_interface_data;
        }
    }

    return true;
}

/*
 * Create clone IDBs for the merge file, based on the input files and mode.
 */
static wtapng_iface_descriptions_t *
generate_merged_idbs(merge_in_file_t *in_files, const unsigned in_file_count, idb_merge_mode * const mode)
{
    wtapng_iface_descriptions_t *merged_idb_list = NULL;
    wtap_block_t                 input_file_idb;
    unsigned                     itf_count, merged_index;
    unsigned                     i;

    /* create new IDB info */
    merged_idb_list = g_new(wtapng_iface_descriptions_t,1);
    merged_idb_list->interface_data = g_array_new(false, false, sizeof(wtap_block_t));

    if (*mode == IDB_MERGE_MODE_ALL_SAME && all_idbs_are_duplicates(in_files, in_file_count)) {
        ws_debug("mode ALL set and all IDBs are duplicates");

        /* All files have the same interfaces are the same, so merge any
         * IDBs found later in the files together with duplicates.
         * (Note this is also the right thing to do if we have some kind
         * of two-pass mode and all_idbs_are_duplicates actually did
         * compare all the IDBs instead of just the ones before any packets.)
         */
        *mode = IDB_MERGE_MODE_ANY_SAME;

        /* they're all the same, so just get the first file's IDBs */
        itf_count = in_files[0].wth->next_interface_data;
        /* put them in the merged file */
        while ((input_file_idb = wtap_get_next_interface_description(in_files[0].wth)) != NULL) {
            add_idb_to_merged_file(merged_idb_list, input_file_idb, NULL, NULL, NULL);
            merged_index = merged_idb_list->interface_data->len - 1;
            add_idb_index_map(&in_files[0], itf_count, merged_index);
            /* and set all the other file index maps the same way */
            for (i = 1; i < in_file_count; i++) {
                if (wtap_get_next_interface_description(in_files[i].wth) != NULL) {
                    add_idb_index_map(&in_files[i], itf_count, merged_index);
                } else {
                    ws_assert_not_reached();
                }
            }
            itf_count = in_files[0].wth->next_interface_data;
        }
    }
    else {
        for (i = 0; i < in_file_count; i++) {

            itf_count = in_files[i].wth->next_interface_data;
            while ((input_file_idb = wtap_get_next_interface_description(in_files[i].wth)) != NULL) {

                if (*mode == IDB_MERGE_MODE_ANY_SAME &&
                    find_duplicate_idb(input_file_idb, merged_idb_list, &merged_index))
                {
                    ws_debug("mode ANY set and found a duplicate");
                    /*
                     * It's the same as a previous IDB, so we're going to "merge"
                     * them into one by adding a map from its old IDB index to the new
                     * one. This will be used later to change the rec interface_id.
                     */
                    add_idb_index_map(&in_files[i], itf_count, merged_index);
                }
                else {
                    ws_debug("mode NONE set or did not find a duplicate");
                    /*
                     * This IDB does not match a previous (or we want to save all IDBs),
                     * so add the IDB to the merge file, and add a map of the indices.
                     */
                    add_idb_to_merged_file(merged_idb_list, input_file_idb, NULL, NULL, NULL);
                    merged_index = merged_idb_list->interface_data->len - 1;
                    add_idb_index_map(&in_files[i], itf_count, merged_index);
                }
                itf_count = in_files[i].wth->next_interface_data;
            }
        }
    }

    return merged_idb_list;
}

static bool
map_rec_interface_id(wtap_rec *rec, const merge_in_file_t *in_file)
{
    unsigned current_interface_id = 0;
    ws_assert(rec != NULL);
    ws_assert(in_file != NULL);
    ws_assert(in_file->idb_index_map != NULL);

    if (rec->presence_flags & WTAP_HAS_INTERFACE_ID) {
        unsigned section_num = (rec->presence_flags & WTAP_HAS_SECTION_NUMBER) ? rec->section_number : 0;
        current_interface_id = wtap_file_get_shb_global_interface_id(in_file->wth, section_num, rec->rec_header.packet_header.interface_id);
    }

    if (current_interface_id >= in_file->idb_index_map->len) {
        /* this shouldn't happen, but in a malformed input file it could */
        ws_debug("current_interface_id (%u) >= in_file->idb_index_map->len (%u) (ERROR?)",
            current_interface_id, in_file->idb_index_map->len);
        return false;
    }

    rec->rec_header.packet_header.interface_id = g_array_index(in_file->idb_index_map, unsigned, current_interface_id);
    rec->presence_flags |= WTAP_HAS_INTERFACE_ID;

    return true;
}

/** Return values from internal merge routines. */
typedef enum {
    MERGE_OK,
    MERGE_USER_ABORTED,
    /* below here are true errors */
    MERGE_ERR_CANT_OPEN_INFILE,
    MERGE_ERR_CANT_OPEN_OUTFILE,
    MERGE_ERR_CANT_READ_INFILE,
    MERGE_ERR_BAD_PHDR_INTERFACE_ID,
    MERGE_ERR_CANT_WRITE_OUTFILE,
    MERGE_ERR_CANT_CLOSE_OUTFILE
} merge_result;

static merge_result
merge_process_packets(wtap_dumper *pdh, const int file_type,
                      merge_in_file_t *in_files, const unsigned in_file_count,
                      const bool do_append,
                      const idb_merge_mode mode, unsigned snaplen,
                      merge_progress_callback_t* cb,
                      wtapng_iface_descriptions_t *idb_inf,
                      GArray *nrb_combined, GArray *dsb_combined,
                      int *err, char **err_info, unsigned *err_fileno,
                      uint32_t *err_framenum)
{
    merge_result        status = MERGE_OK;
    merge_in_file_t    *in_file;
    int                 count = 0;
    bool                stop_flag = false;
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
            if (*err == WTAP_ERR_SHORT_READ) {
                /*
                 * A truncated file is not a fatal error, just stop reading
                 * from that file, report it, and keep going.
                 * XXX - What about WTAP_ERR_BAD_FILE? Are there *any*
                 * read errors, as opposed to not being able to open the file
                 * or write a record, that make us want to abort the entire
                 * merge?
                 */
                report_cfile_read_failure(in_file->filename, *err, *err_info);
                *err = 0;
                g_free(*err_info);
                *err_info = NULL;
                continue;
            } else {
                status = MERGE_ERR_CANT_READ_INFILE;
                break;
            }
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

        if (wtap_file_type_subtype_supports_block(file_type,
                                                  WTAP_BLOCK_IF_ID_AND_INFO) != BLOCK_NOT_SUPPORTED) {
            if (!process_new_idbs(pdh, in_files, in_file_count, mode, idb_inf, err, err_info)) {
                status = MERGE_ERR_CANT_WRITE_OUTFILE;
                break;
            }
        }

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

        /*
         * Does this file type support identifying the interfaces on
         * which packets arrive?
         *
         * That mean that the abstract interface provided by libwiretap
         * involves WTAP_BLOCK_IF_ID_AND_INFO blocks.
         */
        if (wtap_file_type_subtype_supports_block(file_type,
                                                  WTAP_BLOCK_IF_ID_AND_INFO) != BLOCK_NOT_SUPPORTED) {
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
        if (nrb_combined && in_file->wth->nrbs) {
            GArray *in_nrb = in_file->wth->nrbs;
            for (unsigned i = in_file->nrbs_seen; i < in_nrb->len; i++) {
                wtap_block_t wblock = g_array_index(in_nrb, wtap_block_t, i);
                g_array_append_val(nrb_combined, wblock);
                in_file->nrbs_seen++;
            }
        }
        if (dsb_combined && in_file->wth->dsbs) {
            GArray *in_dsb = in_file->wth->dsbs;
            for (unsigned i = in_file->dsbs_seen; i < in_dsb->len; i++) {
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
        wtap_rec_reset(rec);
    }

    if (cb)
        cb->callback_func(MERGE_EVENT_DONE, count, in_files, in_file_count, cb->data);

    if (status == MERGE_OK || status == MERGE_USER_ABORTED) {
        /* Check for IDBs, NRBs, or DSBs read after the last packet records. */
        if (wtap_file_type_subtype_supports_block(file_type,
                                                  WTAP_BLOCK_IF_ID_AND_INFO) != BLOCK_NOT_SUPPORTED) {
            if (!process_new_idbs(pdh, in_files, in_file_count, mode, idb_inf, err, err_info)) {
                status = MERGE_ERR_CANT_WRITE_OUTFILE;
            }
        }
        if (nrb_combined) {
            for (unsigned j = 0; j < in_file_count; j++) {
                in_file = &in_files[j];
                GArray *in_nrb = in_file->wth->nrbs;
                if (in_nrb) {
                    for (unsigned i = in_file->nrbs_seen; i < in_nrb->len; i++) {
                        wtap_block_t wblock = g_array_index(in_nrb, wtap_block_t, i);
                        g_array_append_val(nrb_combined, wblock);
                        in_file->nrbs_seen++;
                    }
                }
            }
        }
        if (dsb_combined) {
            for (unsigned j = 0; j < in_file_count; j++) {
                in_file = &in_files[j];
                GArray *in_dsb = in_file->wth->dsbs;
                if (in_dsb) {
                    for (unsigned i = in_file->dsbs_seen; i < in_dsb->len; i++) {
                        wtap_block_t wblock = g_array_index(in_dsb, wtap_block_t, i);
                        g_array_append_val(dsb_combined, wblock);
                        in_file->dsbs_seen++;
                    }
                }
            }
        }
    }
    if (status == MERGE_OK || status == MERGE_USER_ABORTED) {
        if (!wtap_dump_close(pdh, NULL, err, err_info))
            status = MERGE_ERR_CANT_CLOSE_OUTFILE;
    } else {
        /*
         * We already got some error; no need to report another error on
         * close.
         *
         * Don't overwrite the earlier error.
         */
        int close_err = 0;
        char *close_err_info = NULL;
        (void)wtap_dump_close(pdh, NULL, &close_err, &close_err_info);
        g_free(close_err_info);
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
        *err_fileno = (unsigned)(in_file - in_files);
        *err_framenum = in_file->packet_num;
    }

    return status;
}

static void
tempfile_free(void *data) {
    char *filename = (char*)data;
    ws_unlink(filename);
    g_free(filename);
}

#define MAX_MERGE_FILES 10000 // Arbitrary
static bool
// NOLINTNEXTLINE(misc-no-recursion)
merge_files_common(const char* out_filename, /* filename in normal output mode,
                   optional tempdir in tempfile mode (NULL for OS default) */
                   char **out_filenamep, const char *pfx, /* tempfile mode  */
                   const int file_type, const char *const *in_filenames,
                   const unsigned in_file_count, const bool do_append,
                   idb_merge_mode mode, unsigned snaplen,
                   const char *app_name, merge_progress_callback_t* cb)
{
    merge_in_file_t    *in_files = NULL;
    int                 frame_type = WTAP_ENCAP_PER_PACKET;
    unsigned            open_file_count;
    int                 err = 0;
    char               *err_info = NULL;
    unsigned            err_fileno = 0;
    uint32_t            err_framenum = 0;
    merge_result        status = MERGE_OK;
    wtap_dumper        *pdh;
    GArray             *shb_hdrs = NULL;
    wtapng_iface_descriptions_t *idb_inf = NULL;
    GArray             *nrb_combined = NULL;
    GArray             *dsb_combined = NULL;
    GPtrArray          *temp_files = NULL;
    int                 dup_fd;

    ws_assert(in_file_count > 0);
    ws_assert(in_file_count < MAX_MERGE_FILES);
    ws_assert(in_filenames != NULL);

    /* if a callback was given, it has to have a callback function ptr */
    ws_assert((cb != NULL) ? (cb->callback_func != NULL) : true);

    ws_debug("merge_files: begin");

    for (unsigned total_file_count = 0; total_file_count < in_file_count && status == MERGE_OK; total_file_count += open_file_count) {

        /* Reserve a file descriptor for the output; if we run out of file
         * descriptors we will end up writing to a temp file instead of the
         * file or stdout originally requested, but this simplifies EMFILE
         * handling.
         */
        dup_fd = ws_dup(1);
        if (dup_fd == -1) {
            report_cfile_dump_open_failure(out_filename, errno, NULL, file_type);
            return false;
        }

        /* open the input files */
        open_file_count = merge_open_in_files(in_file_count - total_file_count, &in_filenames[total_file_count], &in_files, cb, &err, &err_info, &err_fileno);
        if (open_file_count == 0) {
            ws_debug("merge_open_in_files() failed with err=%d", err);
            report_cfile_open_failure(in_filenames[err_fileno], err, err_info);
            return false;
        }

        if (snaplen == 0) {
            /* Snapshot length not specified - default to the maximum. */
            snaplen = WTAP_MAX_PACKET_SIZE_STANDARD;
        }

        /*
         * This doesn't tell us that much. It tells us what to set the outfile's
         * encap type to, but that's all - for example, it does *not* tell us
         * whether the input files had the same number of IDBs, for the same exact
         * interfaces, and only one IDB each, so it doesn't actually tell us
         * whether we can merge IDBs into one or not.
         *
         * XXX: If an input file is WTAP_ENCAP_PER_PACKET, just because the
         * output file format (e.g. pcapng) can write WTAP_ENCAP_PER_PACKET,
         * that doesn't mean that the format can actually write all the IDBs.
         */
        frame_type = merge_select_frame_type(file_type, open_file_count, in_files);
        ws_debug("got frame_type=%d", frame_type);

        if (cb)
            cb->callback_func(MERGE_EVENT_FRAME_TYPE_SELECTED, frame_type, in_files, open_file_count, cb->data);

        /* prepare the outfile */
        wtap_dump_params params = WTAP_DUMP_PARAMS_INIT;
        params.encap = frame_type;
        params.snaplen = snaplen;
        /*
         * Does this file type support identifying the interfaces on
         * which packets arrive?
         *
         * That mean that the abstract interface provided by libwiretap
         * involves WTAP_BLOCK_IF_ID_AND_INFO blocks.
         */
        if (wtap_file_type_subtype_supports_block(file_type,
                                                  WTAP_BLOCK_IF_ID_AND_INFO) != BLOCK_NOT_SUPPORTED) {
            shb_hdrs = create_shb_header(in_files, open_file_count, app_name);
            ws_debug("SHB created");

            idb_inf = generate_merged_idbs(in_files, open_file_count, &mode);
            ws_debug("IDB merge operation complete, got %u IDBs", idb_inf ? idb_inf->interface_data->len : 0);

            /* We do our own mapping of interface numbers */
            params.shb_iface_to_global = NULL;
            /* XXX other blocks like ISB are now discarded. */
            params.shb_hdrs = shb_hdrs;
            params.idb_inf = idb_inf;
        }
        if (wtap_file_type_subtype_supports_block(file_type,
                                                  WTAP_BLOCK_NAME_RESOLUTION) != BLOCK_NOT_SUPPORTED) {
            nrb_combined = g_array_new(false, false, sizeof(wtap_block_t));
            params.nrbs_growing = nrb_combined;
        }
        if (wtap_file_type_subtype_supports_block(file_type,
                                                  WTAP_BLOCK_DECRYPTION_SECRETS) != BLOCK_NOT_SUPPORTED) {
            dsb_combined = g_array_new(false, false, sizeof(wtap_block_t));
            params.dsbs_growing = dsb_combined;
        }
        ws_close(dup_fd);
        if (open_file_count < in_file_count) {
            if (temp_files == NULL) {
                temp_files = g_ptr_array_new_with_free_func(tempfile_free);
            }
            char* temp_filename;
            /* If out_filenamep is not null, then out_filename is the
             * desired tempdir, so let's use that.
             */
            pdh = wtap_dump_open_tempfile(out_filenamep ? out_filename : NULL,
                                          &temp_filename,
                                          pfx ? pfx : "mergecap", file_type,
                                          WTAP_UNCOMPRESSED, &params, &err,
                                          &err_info);
            if (pdh) {
                g_ptr_array_add(temp_files, temp_filename);
            }
        } else if (out_filenamep) {
            pdh = wtap_dump_open_tempfile(out_filename, out_filenamep, pfx, file_type,
                                          WTAP_UNCOMPRESSED, &params, &err,
                                          &err_info);
        } else if (out_filename) {
            pdh = wtap_dump_open(out_filename, file_type, WTAP_UNCOMPRESSED,
                                 &params, &err, &err_info);
        } else {
            pdh = wtap_dump_open_stdout(file_type, WTAP_UNCOMPRESSED, &params,
                                        &err, &err_info);
        }
        if (pdh == NULL) {
            merge_close_in_files(open_file_count, in_files);
            g_free(in_files);
            wtap_block_array_free(shb_hdrs);
            wtap_free_idb_info(idb_inf);
            if (nrb_combined) {
                g_array_free(nrb_combined, true);
            }
            if (dsb_combined) {
                g_array_free(dsb_combined, true);
            }
            if (temp_files) {
                g_ptr_array_free(temp_files, true);
            }
            report_cfile_dump_open_failure(out_filename, err, err_info, file_type);
            return false;
        }

        if (cb)
            cb->callback_func(MERGE_EVENT_READY_TO_MERGE, 0, in_files, open_file_count, cb->data);

        status = merge_process_packets(pdh, file_type, in_files, open_file_count,
                                       do_append, mode, snaplen, cb,
                                       idb_inf, nrb_combined, dsb_combined,
                                       &err, &err_info,
                                       &err_fileno, &err_framenum);

        g_free(in_files);
        wtap_block_array_free(shb_hdrs);
        wtap_free_idb_info(idb_inf);
        if (nrb_combined) {
            g_array_free(nrb_combined, true);
            nrb_combined = NULL;
        }
        if (dsb_combined) {
            g_array_free(dsb_combined, true);
            dsb_combined = NULL;
        }

    }

    if (status != MERGE_OK) {
        /*
         * Failed.  Clean up and return false.
         */
        switch (status) {
            case MERGE_USER_ABORTED:
                /* This isn't an error, so no need to report anything */
                break;

            case MERGE_ERR_CANT_OPEN_INFILE:
                report_cfile_open_failure(in_filenames[err_fileno], err, err_info);
                break;

            case MERGE_ERR_CANT_OPEN_OUTFILE:
                report_cfile_dump_open_failure(out_filename, err, err_info, file_type);
                break;

            case MERGE_ERR_CANT_READ_INFILE:
                report_cfile_read_failure(in_filenames[err_fileno], err, err_info);
                break;

            case MERGE_ERR_BAD_PHDR_INTERFACE_ID:
                report_failure("Record %u of \"%s\" has an interface ID that does not match any IDB in its file.",
                        err_framenum, in_filenames[err_fileno]);
                break;

            case MERGE_ERR_CANT_WRITE_OUTFILE:
                report_cfile_write_failure(in_filenames[err_fileno], out_filename,
                        err, err_info, err_framenum, file_type);
                break;

            case MERGE_ERR_CANT_CLOSE_OUTFILE:
                report_cfile_close_failure(out_filename, err, err_info);
                break;

            default:
                report_failure("Unknown merge_files error %d", status);
                break;
        }
        if (temp_files != NULL)
            g_ptr_array_free(temp_files, true);
        return false;
    }

    if (temp_files != NULL) {
        // We recurse here, but we're limited by MAX_MERGE_FILES
        status = merge_files_common(out_filename, out_filenamep, pfx,
                    file_type, (const char**)temp_files->pdata,
                    temp_files->len, do_append, mode, snaplen, app_name, cb);
        /* If that failed, it has already reported an error */
        g_ptr_array_free(temp_files, true);
    }

    return status == MERGE_OK;
}

/*
 * Merges the files to an output file whose name is supplied as an argument,
 * based on given input, and invokes callback during execution. Returns
 * MERGE_OK on success, or a MERGE_ERR_XXX on failure.
 */
bool
merge_files(const char* out_filename, const int file_type,
            const char *const *in_filenames, const unsigned in_file_count,
            const bool do_append, const idb_merge_mode mode,
            unsigned snaplen, const char *app_name, merge_progress_callback_t* cb)
{
    ws_assert(out_filename != NULL);
    ws_assert(in_file_count > 0);
    ws_assert(in_filenames != NULL);

    /* #19402: ensure we aren't appending to one of our inputs */
    if (do_append) {
        unsigned int i;
        for (i = 0; i < in_file_count; i++) {
            if (files_identical(out_filename, in_filenames[i])) {
                report_failure("Output file %s is same as input file %s; "
                               "appending would create infinite loop",
                               out_filename, in_filenames[i]);
                return false;
            }
        }
    }

    return merge_files_common(out_filename, NULL, NULL,
                              file_type, in_filenames, in_file_count,
                              do_append, mode, snaplen, app_name, cb);
}

/*
 * Merges the files to a temporary file based on given input, and invokes
 * callback during execution. Returns MERGE_OK on success, or a MERGE_ERR_XXX
 * on failure.
 */
bool
merge_files_to_tempfile(const char *tmpdir, char **out_filenamep, const char *pfx,
                        const int file_type, const char *const *in_filenames,
                        const unsigned in_file_count, const bool do_append,
                        const idb_merge_mode mode, unsigned snaplen,
                        const char *app_name, merge_progress_callback_t* cb)
{
    ws_assert(out_filenamep != NULL);

    /* no temporary file name yet */
    *out_filenamep = NULL;

    return merge_files_common(tmpdir, out_filenamep, pfx,
                              file_type, in_filenames, in_file_count,
                              do_append, mode, snaplen, app_name, cb);
}

/*
 * Merges the files to the standard output based on given input, and invokes
 * callback during execution. Returns MERGE_OK on success, or a MERGE_ERR_XXX
 * on failure.
 */
bool
merge_files_to_stdout(const int file_type, const char *const *in_filenames,
                      const unsigned in_file_count, const bool do_append,
                      const idb_merge_mode mode, unsigned snaplen,
                      const char *app_name, merge_progress_callback_t* cb)
{
    return merge_files_common(NULL, NULL, NULL,
                              file_type, in_filenames, in_file_count,
                              do_append, mode, snaplen, app_name, cb);
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
