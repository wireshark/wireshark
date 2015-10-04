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
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdlib.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <string.h>
#include "merge.h"

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

/*
 * Scan through the arguments and open the input files
 */
gboolean
merge_open_in_files(int in_file_count, const char *const *in_file_names,
                    merge_in_file_t **in_files, int *err, gchar **err_info,
                    int *err_fileno)
{
    gint i;
    gint j;
    size_t files_size = in_file_count * sizeof(merge_in_file_t);
    merge_in_file_t *files;
    gint64 size;

    files = (merge_in_file_t *)g_malloc0(files_size);
    *in_files = files;

    for (i = 0; i < in_file_count; i++) {
        files[i].filename    = in_file_names[i];
        files[i].wth         = wtap_open_offline(in_file_names[i], WTAP_TYPE_AUTO, err, err_info, FALSE);
        files[i].data_offset = 0;
        files[i].state       = PACKET_NOT_PRESENT;
        files[i].packet_num  = 0;

        if (!files[i].wth) {
            /* Close the files we've already opened. */
            for (j = 0; j < i; j++)
                cleanup_in_file(&files[j]);
            *err_fileno = i;
            return FALSE;
        }
        size = wtap_file_size(files[i].wth, err);
        if (size == -1) {
            for (j = 0; j + 1 > j && j <= i; j++)
                cleanup_in_file(&files[j]);
            *err_fileno = i;
            return FALSE;
        }
        files[i].size = size;
        files[i].idb_index_map = g_array_new(FALSE, FALSE, sizeof(guint));
    }
    return TRUE;
}

/*
 * Scan through and close each input file
 */
void
merge_close_in_files(int count, merge_in_file_t in_files[])
{
    int i;
    for (i = 0; i < count; i++) {
        cleanup_in_file(&in_files[i]);
    }
}

/*
 * Select an output frame type based on the input files
 * From Guy: If all files have the same frame type, then use that.
 *           Otherwise select WTAP_ENCAP_PER_PACKET.  If the selected
 *           output file type doesn't support per packet frame types,
 *           then the wtap_dump_open call will fail with a reasonable
 *           error condition.
 */
int
merge_select_frame_type(int count, merge_in_file_t files[])
{
    int i;
    int selected_frame_type;

    selected_frame_type = wtap_file_encap(files[0].wth);

    for (i = 1; i < count; i++) {
        int this_frame_type = wtap_file_encap(files[i].wth);
        if (selected_frame_type != this_frame_type) {
            selected_frame_type = WTAP_ENCAP_PER_PACKET;
            break;
        }
    }

    return selected_frame_type;
}

/*
 * Scan through input files and find maximum snapshot length
 */
int
merge_max_snapshot_length(int count, merge_in_file_t in_files[])
{
    int i;
    int max_snapshot = 0;
    int snapshot_length;

    for (i = 0; i < count; i++) {
        snapshot_length = wtap_snapshot_length(in_files[i].wth);
        if (snapshot_length == 0) {
            /* Snapshot length of input file not known. */
            snapshot_length = WTAP_MAX_PACKET_SIZE;
        }
        if (snapshot_length > max_snapshot)
            max_snapshot = snapshot_length;
    }
    return max_snapshot;
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

/*
 * Read the next packet, in chronological order, from the set of files
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
 */
merge_in_file_t *
merge_read_packet(int in_file_count, merge_in_file_t in_files[],
                  int *err, gchar **err_info)
{
    int i;
    int ei = -1;
    nstime_t tv = { sizeof(time_t) > sizeof(int) ? LONG_MAX : INT_MAX, INT_MAX };
    struct wtap_pkthdr *phdr;

    /*
     * Make sure we have a packet available from each file, if there are any
     * packets left in the file in question, and search for the packet
     * with the earliest time stamp.
     */
    for (i = 0; i < in_file_count; i++) {
        if (in_files[i].state == PACKET_NOT_PRESENT) {
            /*
             * No packet available, and we haven't seen an error or EOF yet,
             * so try to read the next packet.
             */
            if (!wtap_read(in_files[i].wth, err, err_info, &in_files[i].data_offset)) {
                if (*err != 0) {
                    in_files[i].state = GOT_ERROR;
                    return &in_files[i];
                }
                in_files[i].state = AT_EOF;
            } else
                in_files[i].state = PACKET_PRESENT;
        }

        if (in_files[i].state == PACKET_PRESENT) {
            phdr = wtap_phdr(in_files[i].wth);
            if (is_earlier(&phdr->ts, &tv)) {
                tv = phdr->ts;
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
    in_files[ei].state = PACKET_NOT_PRESENT;

    /* Count this packet. */
    in_files[ei].packet_num++;

    /*
     * Return a pointer to the merge_in_file_t of the file from which the
     * packet was read.
     */
    *err = 0;
    return &in_files[ei];
}

/*
 * Read the next packet, in file sequence order, from the set of files
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
 */
merge_in_file_t *
merge_append_read_packet(int in_file_count, merge_in_file_t in_files[],
                         int *err, gchar **err_info)
{
    int i;

    /*
     * Find the first file not at EOF, and read the next packet from it.
     */
    for (i = 0; i < in_file_count; i++) {
        if (in_files[i].state == AT_EOF)
            continue; /* This file is already at EOF */
        if (wtap_read(in_files[i].wth, err, err_info, &in_files[i].data_offset))
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
static wtapng_section_t*
create_shb_header(const merge_in_file_t *in_files, const guint in_file_count,
                  const gchar *app_name)
{
    wtapng_section_t *shb_hdr = NULL;
    GString *comment_gstr;
    GString *os_info_str;
    guint i;

    shb_hdr = wtap_file_get_shb_for_new_file(in_files[0].wth);

    comment_gstr = g_string_new("");

    /* TODO: merge comments from all files */

    /* very lame way to save comments - does not save them from the other files */
    if (shb_hdr->opt_comment && strlen(shb_hdr->opt_comment) > 0) {
        g_string_append_printf(comment_gstr, "%s \n",shb_hdr->opt_comment);
    }
    g_free(shb_hdr->opt_comment);
    shb_hdr->opt_comment = NULL;

    g_string_append_printf(comment_gstr, "File created by merging: \n");

    for (i = 0; i < in_file_count; i++) {
        g_string_append_printf(comment_gstr, "File%d: %s \n",i+1,in_files[i].filename);
    }

    os_info_str = g_string_new("");
    get_os_version_info(os_info_str);

    shb_hdr->section_length = -1;
    /* TODO: handle comments from each file being merged */
    shb_hdr->opt_comment   = g_string_free(comment_gstr, FALSE);  /* section comment */
    shb_hdr->shb_hardware  = NULL;        /* NULL if not available, UTF-8 string containing the        */
                                          /*  description of the hardware used to create this section. */
    shb_hdr->shb_os        = g_string_free(os_info_str, FALSE); /* UTF-8 string containing the name   */
                                          /*  of the operating system used to create this section.     */
    shb_hdr->shb_user_appl = g_strdup(app_name); /* NULL if not available, UTF-8 string containing the name */
                                          /*  of the application used to create this section.          */

    return shb_hdr;
}

static gboolean
is_duplicate_idb(const wtapng_if_descr_t *idb1, const wtapng_if_descr_t *idb2)
{
    g_assert(idb1 && idb2);

    merge_debug("merge::is_duplicate_idb() called");
    merge_debug("idb1->wtap_encap == idb2->wtap_encap: %s",
                 (idb1->wtap_encap == idb2->wtap_encap) ? "TRUE":"FALSE");
    merge_debug("idb1->time_units_per_second == idb2->time_units_per_second: %s",
                 (idb1->time_units_per_second == idb2->time_units_per_second) ? "TRUE":"FALSE");
    merge_debug("idb1->tsprecision == idb2->tsprecision: %s",
                 (idb1->tsprecision == idb2->tsprecision) ? "TRUE":"FALSE");
    merge_debug("idb1->link_type == idb2->link_type: %s",
                 (idb1->link_type == idb2->link_type) ? "TRUE":"FALSE");
    merge_debug("idb1->snap_len == idb2->snap_len: %s",
                 (idb1->snap_len == idb2->snap_len) ? "TRUE":"FALSE");
    merge_debug("idb1->if_speed == idb2->if_speed: %s",
                 (idb1->if_speed == idb2->if_speed) ? "TRUE":"FALSE");
    merge_debug("idb1->if_tsresol == idb2->if_tsresol: %s",
                 (idb1->if_tsresol == idb2->if_tsresol) ? "TRUE":"FALSE");
    merge_debug("idb1->if_fcslen == idb2->if_fcslen: %s",
                 (idb1->if_fcslen == idb2->if_fcslen) ? "TRUE":"FALSE");
    merge_debug("g_strcmp0(idb1->opt_comment, idb2->opt_comment) == 0: %s",
                 (g_strcmp0(idb1->opt_comment, idb2->opt_comment) == 0) ? "TRUE":"FALSE");
    merge_debug("g_strcmp0(idb1->if_name, idb2->if_name) == 0: %s",
                 (g_strcmp0(idb1->if_name, idb2->if_name) == 0) ? "TRUE":"FALSE");
    merge_debug("g_strcmp0(idb1->if_description, idb2->if_description) == 0: %s",
                 (g_strcmp0(idb1->if_description, idb2->if_description) == 0) ? "TRUE":"FALSE");
    merge_debug("g_strcmp0(idb1->if_os, idb2->if_os) == 0: %s",
                 (g_strcmp0(idb1->if_os, idb2->if_os) == 0) ? "TRUE":"FALSE");
    merge_debug("merge::is_duplicate_idb() returning");

    /* does not compare filters nor interface statistics */
    return (idb1->wtap_encap == idb2->wtap_encap &&
            idb1->time_units_per_second == idb2->time_units_per_second &&
            idb1->tsprecision == idb2->tsprecision &&
            idb1->link_type == idb2->link_type &&
            /* XXX: should snaplen not be compared? */
            idb1->snap_len == idb2->snap_len &&
            idb1->if_speed == idb2->if_speed &&
            idb1->if_tsresol == idb2->if_tsresol &&
            idb1->if_fcslen == idb2->if_fcslen &&
            g_strcmp0(idb1->opt_comment, idb2->opt_comment) == 0 &&
            g_strcmp0(idb1->if_name, idb2->if_name) == 0 &&
            g_strcmp0(idb1->if_description, idb2->if_description) == 0 &&
            g_strcmp0(idb1->if_os, idb2->if_os) == 0);
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
    const wtapng_if_descr_t *first_file_idb, *other_file_idb;
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
            first_file_idb = &g_array_index(first_idb_list->interface_data, wtapng_if_descr_t, j);
            other_file_idb = &g_array_index(other_idb_list->interface_data, wtapng_if_descr_t, j);

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
find_duplicate_idb(const wtapng_if_descr_t *input_file_idb,
               const wtapng_iface_descriptions_t *merged_idb_list,
               guint *found_index)
{
    const wtapng_if_descr_t *merged_idb;
    guint i;

    g_assert(input_file_idb != NULL);
    g_assert(merged_idb_list != NULL);
    g_assert(merged_idb_list->interface_data != NULL);
    g_assert(found_index != NULL);

    for (i = 0; i < merged_idb_list->interface_data->len; i++) {
        merged_idb = &g_array_index(merged_idb_list->interface_data, wtapng_if_descr_t, i);

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
                       const wtapng_if_descr_t *input_file_idb)
{
    wtapng_if_descr_t idb;

    g_assert(merged_idb_list != NULL);
    g_assert(merged_idb_list->interface_data != NULL);
    g_assert(input_file_idb != NULL);

    idb.wtap_encap            = input_file_idb->wtap_encap;
    idb.time_units_per_second = input_file_idb->time_units_per_second;
    idb.tsprecision           = input_file_idb->tsprecision;
    idb.link_type             = input_file_idb->link_type;
    idb.snap_len              = input_file_idb->snap_len;
    idb.if_name               = g_strdup(input_file_idb->if_name);
    idb.opt_comment           = g_strdup(input_file_idb->opt_comment);;
    idb.if_description        = g_strdup(input_file_idb->if_description);
    idb.if_speed              = input_file_idb->if_speed;
    idb.if_tsresol            = input_file_idb->if_tsresol;
    idb.if_filter_str         = NULL;
    idb.bpf_filter_len        = 0;
    idb.if_filter_bpf_bytes   = NULL;
    idb.if_os                 = g_strdup(input_file_idb->if_os);
    idb.if_fcslen             = input_file_idb->if_fcslen;
    idb.num_stat_entries      = 0;          /* Number of ISB:s */
    idb.interface_statistics  = NULL;

    g_array_append_val(merged_idb_list->interface_data, idb);

    return merged_idb_list->interface_data->len - 1;
}

/*
 * Create clone IDBs for the merge file, based on the input files and mode.
 */
static wtapng_iface_descriptions_t *
generate_merged_idb(merge_in_file_t *in_files, const guint in_file_count, const idb_merge_mode mode)
{
    wtapng_iface_descriptions_t *merged_idb_list = NULL;
    wtapng_iface_descriptions_t *input_file_idb_list = NULL;
    const wtapng_if_descr_t     *input_file_idb = NULL;
    guint                        itf_count, merged_index;
    guint                        i;

    /* create new IDB info */
    merged_idb_list = g_new(wtapng_iface_descriptions_t,1);
    merged_idb_list->interface_data = g_array_new(FALSE, FALSE, sizeof(wtapng_if_descr_t));

    if (mode == IDB_MERGE_MODE_ALL_SAME && all_idbs_are_duplicates(in_files, in_file_count)) {
        guint num_idbs;

        merge_debug("merge::generate_merged_idb: mode ALL set and all IDBs are duplicates");

        /* they're all the same, so just get the first file's IDBs */
        input_file_idb_list = wtap_file_get_idb_info(in_files[0].wth);
        /* this is really one more than number of IDBs, but that's good for the for-loops */
        num_idbs = input_file_idb_list->interface_data->len;

        /* put them in the merged file */
        for (itf_count = 0; itf_count < num_idbs; itf_count++) {
            input_file_idb = &g_array_index(input_file_idb_list->interface_data,
                                            wtapng_if_descr_t, itf_count);
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
                input_file_idb = &g_array_index(input_file_idb_list->interface_data,
                                                wtapng_if_descr_t, itf_count);

                if (mode == IDB_MERGE_MODE_ANY_SAME &&
                    find_duplicate_idb(input_file_idb, merged_idb_list, &merged_index))
                {
                    merge_debug("merge::generate_merged_idb: mode ANY set and found a duplicate");
                    /*
                     * It's the same as a previous IDB, so we're going to "merge"
                     * them into one by adding a map from its old IDB index to the new
                     * one. This will be used later to change the phdr interface_id.
                     */
                    add_idb_index_map(&in_files[i], itf_count, merged_index);
                }
                else {
                    merge_debug("merge::generate_merged_idb: mode NONE set or did not find a duplicate");
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
map_phdr_interface_id(struct wtap_pkthdr *phdr, const merge_in_file_t *in_file)
{
    guint current_interface_id = 0;
    g_assert(phdr != NULL);
    g_assert(in_file != NULL);
    g_assert(in_file->idb_index_map != NULL);

    if (phdr->presence_flags & WTAP_HAS_INTERFACE_ID) {
        current_interface_id = phdr->interface_id;
    }

    if (current_interface_id >= in_file->idb_index_map->len) {
        /* this shouldn't happen, but in a malformed input file it could */
        merge_debug("merge::map_phdr_interface_id: current_interface_id >= in_file->idb_index_map->len (ERROR?)");
        return FALSE;
    }

    phdr->interface_id = g_array_index(in_file->idb_index_map, guint, current_interface_id);
    phdr->presence_flags |= WTAP_HAS_INTERFACE_ID;

    return TRUE;
}

static gchar*
get_read_error_string(const merge_in_file_t *in_files, const guint in_file_count,
                      const int *err, gchar **err_info)
{
    GString *err_message = g_string_new("");
    gchar   *display_basename = NULL;
    guint    i;

    g_assert(in_files != NULL);
    g_assert(err != NULL);
    g_assert(err_info != NULL);

    if (*err_info == NULL) {
        *err_info = g_strdup("no information supplied");
    }

    /*
     * Find the file on which we got the error, and report the error.
     */
    for (i = 0; i < in_file_count; i++) {
        if (in_files[i].state == GOT_ERROR) {
            display_basename = g_filename_display_basename(in_files[i].filename);

            switch (*err) {

                case WTAP_ERR_SHORT_READ:
                    g_string_printf(err_message,
                         "The capture file %s appears to have been cut short"
                          " in the middle of a packet.", display_basename);
                    break;

                case WTAP_ERR_BAD_FILE:
                    g_string_printf(err_message,
                         "The capture file %s appears to be damaged or corrupt.\n(%s)",
                         display_basename, *err_info);
                    break;

                case WTAP_ERR_DECOMPRESS:
                    g_string_printf(err_message,
                         "The compressed capture file %s appears to be damaged or corrupt.\n"
                         "(%s)", display_basename, *err_info);
                    break;

                default:
                    g_string_printf(err_message,
                         "An error occurred while reading the"
                         " capture file %s: %s.",
                         display_basename,  wtap_strerror(*err));
                    break;
            }

            g_free(display_basename);
            break;
        }
    }

    g_free(*err_info);
    *err_info = g_string_free(err_message, FALSE);

    return *err_info;
}

static gchar*
get_write_error_string(const merge_in_file_t *in_file, const int file_type,
                       const gchar* out_filename, const int *err, gchar **err_info)
{
    GString *err_message = g_string_new("");
    gchar *display_basename = NULL;
    int write_err;

    /* in_file may be NULL */
    g_assert(err != NULL);
    g_assert(err_info != NULL);

    if (*err_info == NULL) {
        *err_info = g_strdup("no information supplied");
    }

    write_err = *err;

    display_basename = g_filename_display_basename(in_file ? in_file->filename : "UNKNOWN");

    if (write_err < 0) {

        switch (write_err) {

            case WTAP_ERR_UNWRITABLE_ENCAP:
                /*
                 * This is a problem with the particular frame we're writing and
                 * the file type and subtype we're wwriting; note that, and
                 * report the frame number and file type/subtype.
                 */
                g_string_printf(err_message,
                    "Frame %u of \"%s\" has a network type that can't be saved in a \"%s\" file.\n",
                    in_file ? in_file->packet_num : 0, display_basename,
                    wtap_file_type_subtype_string(file_type));
                break;

            case WTAP_ERR_PACKET_TOO_LARGE:
                /*
                 * This is a problem with the particular frame we're writing and
                 * the file type and subtype we're writing; note that, and report
                 * the frame number and file type/subtype.
                 */
                g_string_printf(err_message,
                    "Frame %u of \"%s\" is too large for a \"%s\" file.",
                    in_file ? in_file->packet_num : 0, display_basename,
                    wtap_file_type_subtype_string(file_type));
                break;

            case WTAP_ERR_UNWRITABLE_REC_TYPE:
                /*
                 * This is a problem with the particular record we're writing and
                 * the file type and subtype we're writing; note that, and report
                 * the record number and file type/subtype.
                 */
                g_string_printf(err_message,
                    "Record %u of \"%s\" has a record type that can't be saved in a \"%s\" file.",
                    in_file ? in_file->packet_num : 0, display_basename,
                    wtap_file_type_subtype_string(file_type));
                break;

            case WTAP_ERR_UNWRITABLE_REC_DATA:
                /*
                 * This is a problem with the particular record we're writing and
                 * the file type and subtype we're writing; note that, and report
                 * the frame number and file type/subtype.
                 */
                g_string_printf(err_message,
                    "Record %u of \"%s\" has data that can't be saved in a \"%s\" file.\n(%s)",
                    in_file ? in_file->packet_num : 0, display_basename,
                    wtap_file_type_subtype_string(file_type), *err_info);
                break;

            default:
                g_string_printf(err_message,
                    "An error occurred while writing to the file \"%s\": %s.",
                    out_filename, wtap_strerror(write_err));
                break;
        }
    }
    else {
        /* OS error. */
        g_string_printf(err_message, file_write_error_message(write_err), out_filename);
    }

    g_free(display_basename);
    g_free(*err_info);
    *err_info = g_string_free(err_message, FALSE);

    return *err_info;
}


/*
 * Merges the files base don given input, and invokes callback during
 * execution. Returns MERGE_OK on success, or a MERGE_ERR_XXX on failure; note
 * that the passed-in 'err' variable will be more specific to what failed, and
 * err_info will have pretty output.
 */
merge_result
merge_files(int out_fd, const gchar* out_filename, const int file_type,
            const char *const *in_filenames, const guint in_file_count,
            const gboolean do_append, const idb_merge_mode mode,
            guint snaplen, const gchar *app_name, merge_progress_callback_t* cb,
            int *err, gchar **err_info, int *err_fileno)
{
    merge_in_file_t    *in_files = NULL, *in_file = NULL;
    int                 frame_type = WTAP_ENCAP_PER_PACKET;
    merge_result        status = MERGE_OK;
    wtap_dumper        *pdh;
    struct wtap_pkthdr *phdr, snap_phdr;
    int                 count = 0;
    gboolean            stop_flag = FALSE;
    wtapng_section_t            *shb_hdr = NULL;
    wtapng_iface_descriptions_t *idb_inf = NULL;

    g_assert(out_fd > 0);
    g_assert(in_file_count > 0);
    g_assert(in_filenames != NULL);
    g_assert(err != NULL);
    g_assert(err_info != NULL);
    g_assert(err_fileno != NULL);

    /* if a callback was given, it has to have a callback function ptr */
    g_assert((cb != NULL) ? (cb->callback_func != NULL) : TRUE);

    merge_debug("merge_files: begin");

    /* open the input files */
    if (!merge_open_in_files(in_file_count, in_filenames, &in_files,
                             err, err_info, err_fileno)) {
        merge_debug("merge_files: merge_open_in_files() failed with err=%d", *err);
        return MERGE_ERR_CANT_OPEN_INFILE;
    }

    if (cb)
        cb->callback_func(MERGE_EVENT_INPUT_FILES_OPENED, 0, in_files, in_file_count, cb->data);

    if (snaplen == 0) {
        /* Snapshot length not specified - default to the maximum. */
        snaplen = WTAP_MAX_PACKET_SIZE;
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
    if (file_type == WTAP_FILE_TYPE_SUBTYPE_PCAPNG) {
        shb_hdr = create_shb_header(in_files, in_file_count, app_name);
        merge_debug("merge_files: SHB created");

        idb_inf = generate_merged_idb(in_files, in_file_count, mode);
        merge_debug("merge_files: IDB merge operation complete, got %u IDBs", idb_inf ? idb_inf->interface_data->len : 0);

        pdh = wtap_dump_fdopen_ng(out_fd, file_type, frame_type, snaplen,
                                  FALSE /* compressed */, shb_hdr, idb_inf,
                                  NULL, err);
    }
    else {
        pdh = wtap_dump_fdopen(out_fd, file_type, frame_type, snaplen, FALSE /* compressed */, err);
    }

    if (pdh == NULL) {
        merge_close_in_files(in_file_count, in_files);
        g_free(in_files);
        wtap_free_shb(shb_hdr);
        wtap_free_idb_info(idb_inf);
        return MERGE_ERR_CANT_OPEN_OUTFILE;
    }

    if (cb)
        cb->callback_func(MERGE_EVENT_READY_TO_MERGE, 0, in_files, in_file_count, cb->data);

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
            /* EOF */
            break;
        }

        if (*err != 0) {
            /* I/O error reading from in_file */
            status = MERGE_ERR_CANT_READ_INFILE;
            break;
        }

        count++;
        if (cb)
            stop_flag = cb->callback_func(MERGE_EVENT_PACKET_WAS_READ, count, in_files, in_file_count, cb->data);

        if (stop_flag) {
            /* The user decided to abort the merge. */
            status = MERGE_USER_ABORTED;
            break;
        }

        phdr = wtap_phdr(in_file->wth);

        if (snaplen != 0 && phdr->caplen > snaplen) {
            /*
             * The dumper will only write up to caplen bytes out, so we only
             * need to change that value, instead of cloning the whole packet
             * with fewer bytes.
             *
             * XXX: but do we need to change the IDBs' snap_len?
             */
            snap_phdr = *phdr;
            snap_phdr.caplen = snaplen;
            phdr = &snap_phdr;
        }

        if (file_type == WTAP_FILE_TYPE_SUBTYPE_PCAPNG) {
            if (!map_phdr_interface_id(phdr, in_file)) {
                status = MERGE_ERR_BAD_PHDR_INTERFACE_ID;
                break;
            }
        }

        if (!wtap_dump(pdh, phdr, wtap_buf_ptr(in_file->wth), err, err_info)) {
            status = MERGE_ERR_CANT_WRITE_OUTFILE;
            break;
        }
    }

    if (cb)
        cb->callback_func(MERGE_EVENT_DONE, count, in_files, in_file_count, cb->data);

    merge_close_in_files(in_file_count, in_files);

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

    if (status != MERGE_OK) {
        GString *err_message = NULL;
        gchar   *display_basename = NULL;

        switch(status) {

            case MERGE_ERR_CANT_READ_INFILE:
                *err_info = get_read_error_string(in_files, in_file_count, err, err_info);
                break;

            case MERGE_ERR_CANT_WRITE_OUTFILE: /* fall through */
            case MERGE_ERR_CANT_CLOSE_OUTFILE:
                *err_info = get_write_error_string(in_file, file_type, out_filename, err, err_info);
                break;

            case MERGE_ERR_BAD_PHDR_INTERFACE_ID:
                display_basename = g_filename_display_basename(in_file ? in_file->filename : "UNKNOWN");
                if (*err_info != NULL)
                    g_free(*err_info);
                err_message = g_string_new("");
                g_string_printf(err_message,
                    "Record %u of \"%s\" has an interface ID which does not match any IDB in its file.",
                    in_file ? in_file->packet_num : 0, display_basename);
                g_free(display_basename);
                *err_info = g_string_free(err_message, FALSE);
                break;

            case MERGE_USER_ABORTED: /* not really an error */
            default:
                break;
        }
    }

    g_free(in_files);
    wtap_free_shb(shb_hdr);
    wtap_free_idb_info(idb_inf);

    return status;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
