/* file.h
 * Definitions for file structures and routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#ifndef __FILE_H__
#define __FILE_H__

#include "wiretap/wtap.h"
#include <errno.h>
#include <epan/epan.h>

#include <epan/print.h>
#include <epan/packet-range.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Return values from functions that only can succeed or fail. */
typedef enum {
    CF_OK,      /**< operation succeeded */
    CF_ERROR    /**< operation got an error (function may provide err with details) */
} cf_status_t;

/** Return values from functions that read capture files. */
typedef enum {
    CF_READ_OK,	     /**< operation succeeded */
    CF_READ_ERROR,   /**< operation got an error (function may provide err with details) */
    CF_READ_ABORTED  /**< operation aborted by user */
} cf_read_status_t;

/** Return values from functions that write out packets. */
typedef enum {
    CF_WRITE_OK,      /**< operation succeeded */
    CF_WRITE_ERROR,   /**< operation got an error (function may provide err with details) */
    CF_WRITE_ABORTED  /**< operation aborted by user */
} cf_write_status_t;

/** Return values from functions that print sets of packets. */
typedef enum {
	CF_PRINT_OK,            /**< print operation succeeded */
	CF_PRINT_OPEN_ERROR,    /**< print operation failed while opening printer */
	CF_PRINT_WRITE_ERROR    /**< print operation failed while writing to the printer */
} cf_print_status_t;

typedef enum {
    cf_cb_file_opened,
    cf_cb_file_closing,
    cf_cb_file_closed,
    cf_cb_file_read_started,
    cf_cb_file_read_finished,
    cf_cb_file_reload_started,
    cf_cb_file_reload_finished,
    cf_cb_file_rescan_started,
    cf_cb_file_rescan_finished,
    cf_cb_file_fast_save_finished,
    cf_cb_packet_selected,
    cf_cb_packet_unselected,
    cf_cb_field_unselected,
    cf_cb_file_save_started,
    cf_cb_file_save_finished,
    cf_cb_file_save_failed,
    cf_cb_file_save_stopped,
    cf_cb_file_export_specified_packets_started,
    cf_cb_file_export_specified_packets_finished,
    cf_cb_file_export_specified_packets_failed,
    cf_cb_file_export_specified_packets_stopped
} cf_cbs;

typedef void (*cf_callback_t) (gint event, gpointer data, gpointer user_data);

typedef struct {
    const char    *string;
    size_t         string_len;
    capture_file  *cf;
    gboolean       frame_matched;
    field_info    *finfo;
} match_data;

extern void
cf_callback_add(cf_callback_t func, gpointer user_data);

extern void
cf_callback_remove(cf_callback_t func);

/**
 * Open a capture file.
 *
 * @param cf the capture file to be opened
 * @param fname the filename to be opened
 * @param type WTAP_TYPE_AUTO for automatic or index to direct open routine
 * @param is_tempfile is this a temporary file?
 * @param err error code
 * @return one of cf_status_t
 */
cf_status_t cf_open(capture_file *cf, const char *fname, unsigned int type, gboolean is_tempfile, int *err);

/**
 * Close a capture file.
 *
 * @param cf the capture file to be closed
 */
void cf_close(capture_file *cf);

/**
 * Reload a capture file.
 *
 * @param cf the capture file to be reloaded
 */
void cf_reload(capture_file *cf);

/**
 * Read all packets of a capture file into the internal structures.
 *
 * @param cf the capture file to be read
 * @param from_save reread asked from cf_save_records
 * @return one of cf_read_status_t
 */
cf_read_status_t cf_read(capture_file *cf, gboolean from_save);

/**
 * Read the metadata and raw data for a record.  It will pop
 * up an alert box if there's an error.
 *
 * @param cf the capture file from which to read the record
 * @param fdata the frame_data structure for the record in question
 * @param phdr pointer to a wtap_pkthdr structure to contain the
 * record's metadata
 * @param buf a Buffer into which to read the record's raw data
 * @return TRUE if the read succeeded, FALSE if there was an error
 */
gboolean cf_read_record_r(capture_file *cf, const frame_data *fdata,
                          struct wtap_pkthdr *phdr, Buffer *buf);

/**
 * Read the metadata and raw data for a record into a
 * capture_file structure's phdr and buf members.
 * It will pop up an alert box if there's an error.
 *
 * @param cf the capture file from which to read the record
 * @param fdata the frame_data structure for the record in question
 * @return TRUE if the read succeeded, FALSE if there was an error
 */
gboolean cf_read_record(capture_file *cf, frame_data *fdata);

/**
 * Read packets from the "end" of a capture file.
 *
 * @param cf the capture file to be read from
 * @param to_read the number of packets to read
 * @param err the error code, if an error had occurred
 * @return one of cf_read_status_t
 */
cf_read_status_t cf_continue_tail(capture_file *cf, volatile int to_read, int *err);

/**
 * Fake reading packets from the "end" of a capture file.
 *
 * @param cf the capture file to be read from
 */
void cf_fake_continue_tail(capture_file *cf);

/**
 * Finish reading from "end" of a capture file.
 *
 * @param cf the capture file to be read from
 * @param err the error code, if an error had occurred
 * @return one of cf_read_status_t
 */
cf_read_status_t cf_finish_tail(capture_file *cf, int *err);

/**
 * Determine whether this capture file (or a range of it) can be written
 * in any format using Wiretap rather than by copying the raw data.
 *
 * @param cf the capture file to check
 * @return TRUE if it can be written, FALSE if it can't
 */
gboolean cf_can_write_with_wiretap(capture_file *cf);

/**
 * Determine whether this capture file can be saved with a "save" operation;
 * if there's nothing unsaved, it can't.
 *
 * @param cf the capture file to check
 * @return TRUE if it can be saved, FALSE if it can't
 */
gboolean cf_can_save(capture_file *cf);

/**
 * Determine whether this capture file can be saved with a "save as" operation.
 *
 * @param cf the capture file to check
 * @return TRUE if it can be saved, FALSE if it can't
 */
gboolean cf_can_save_as(capture_file *cf);

/**
 * Determine whether this capture file has unsaved data.
 *
 * @param cf the capture file to check
 * @return TRUE if it has unsaved data, FALSE if it doesn't
 */
gboolean cf_has_unsaved_data(capture_file *cf);

/**
 * Save all packets in a capture file to a new file, and, if that succeeds,
 * make that file the current capture file.  If there's already a file with
 * that name, do a "safe save", writing to a temporary file in the same
 * directory and, if the write succeeds, renaming the new file on top of the
 * old file, so that if the write fails, the old file is still intact.
 *
 * @param cf the capture file to save to
 * @param fname the filename to save to
 * @param save_format the format of the file to save (libpcap, ...)
 * @param compressed whether to gzip compress the file
 * @param discard_comments TRUE if we should discard comments if the save
 * succeeds (because we saved in a format that doesn't support
 * comments)
 * @param dont_reopen TRUE if it shouldn't reopen and make that file the
 * current capture file
 * @return one of cf_write_status_t
 */
cf_write_status_t cf_save_records(capture_file * cf, const char *fname,
                                  guint save_format, gboolean compressed,
                                  gboolean discard_comments,
                                  gboolean dont_reopen);

/**
 * Export some or all packets from a capture file to a new file.  If there's
 * already a file with that name, do a "safe save", writing to a temporary
 * file in the same directory and, if the write succeeds, renaming the new
 * file on top of the old file, so that if the write fails, the old file is
 * still intact.
 *
 * @param cf the capture file to write to
 * @param fname the filename to write to
 * @param range the range of packets to write
 * @param save_format the format of the file to write (libpcap, ...)
 * @param compressed whether to gzip compress the file
 * @return one of cf_write_status_t
 */
cf_write_status_t cf_export_specified_packets(capture_file *cf,
                                              const char *fname,
                                              packet_range_t *range,
                                              guint save_format,
                                              gboolean compressed);

/**
 * Get a displayable name of the capture file.
 *
 * @param cf the capture file
 * @return the displayable name (must be g_free'd)
 */
gchar *cf_get_display_name(capture_file *cf);

/**
 * Set the source of the capture data for temporary files, e.g.
 * "Interface eth0" or "Pipe from Pong"
 *
 * @param cf the capture file
 * @param source the source description. this will be copied internally.
 */
void cf_set_tempfile_source(capture_file *cf, gchar *source);

/**
 * Get the source of the capture data for temporary files. Guaranteed to
 * return a non-null value. The returned value should not be freed.
 *
 * @param cf the capture file
 */
const gchar *cf_get_tempfile_source(capture_file *cf);

/**
 * Get the number of packets in the capture file.
 *
 * @param cf the capture file
 * @return the number of packets in the capture file
 */
int cf_get_packet_count(capture_file *cf);

/**
 * Set the number of packets in the capture file.
 *
 * @param cf the capture file
 * @param packet_count the number of packets in the capture file
 */
void cf_set_packet_count(capture_file *cf, int packet_count);

/**
 * Is this capture file a temporary file?
 *
 * @param cf the capture file
 * @return TRUE if it's a temporary file, FALSE otherwise
 */
gboolean cf_is_tempfile(capture_file *cf);

/**
 * Set flag, that this file is a tempfile.
 */
void cf_set_tempfile(capture_file *cf, gboolean is_tempfile);

/**
 * Set flag, if the number of packet drops while capturing are known or not.
 *
 * @param cf the capture file
 * @param drops_known TRUE if the number of packet drops are known, FALSE otherwise
 */
void cf_set_drops_known(capture_file *cf, gboolean drops_known);

/**
 * Set the number of packet drops while capturing.
 *
 * @param cf the capture file
 * @param drops the number of packet drops occurred while capturing
 */
void cf_set_drops(capture_file *cf, guint32 drops);

/**
 * Get flag state, if the number of packet drops while capturing are known or not.
 *
 * @param cf the capture file
 * @return TRUE if the number of packet drops are known, FALSE otherwise
 */
gboolean cf_get_drops_known(capture_file *cf);

/**
 * Get the number of packet drops while capturing.
 *
 * @param cf the capture file
 * @return the number of packet drops occurred while capturing
 */
guint32 cf_get_drops(capture_file *cf);

/**
 * Set the read filter.
 * @todo this shouldn't be required, remove it somehow
 *
 * @param cf the capture file
 * @param rfcode the readfilter
 */
void cf_set_rfcode(capture_file *cf, dfilter_t *rfcode);

/**
 * "Display Filter" packets in the capture file.
 *
 * @param cf the capture file
 * @param dfilter the display filter
 * @param force TRUE if do in any case, FALSE only if dfilter changed
 * @return one of cf_status_t
 */
cf_status_t cf_filter_packets(capture_file *cf, gchar *dfilter, gboolean force);

/**
 * At least one "Refence Time" flag has changed, rescan all packets.
 *
 * @param cf the capture file
 */
void cf_reftime_packets(capture_file *cf);

/**
 * Return the time it took to load the file
 */
gulong cf_get_computed_elapsed(capture_file *cf);

/**
 * "Something" has changed, rescan all packets.
 *
 * @param cf the capture file
 */
void cf_redissect_packets(capture_file *cf);

/**
 * Rescan all packets and just run taps - don't reconstruct the display.
 *
 * @param cf the capture file
 * @return one of cf_read_status_t
 */
cf_read_status_t cf_retap_packets(capture_file *cf);

/**
 * Adjust timestamp precision if auto is selected.
 *
 * @param cf the capture file
 */
void cf_timestamp_auto_precision(capture_file *cf);

/**
 * Print the capture file.
 *
 * @param cf the capture file
 * @param print_args the arguments what and how to print
 * @return one of cf_print_status_t
 */
cf_print_status_t cf_print_packets(capture_file *cf, print_args_t *print_args);

/**
 * Print (export) the capture file into PDML format.
 *
 * @param cf the capture file
 * @param print_args the arguments what and how to export
 * @return one of cf_print_status_t
 */
cf_print_status_t cf_write_pdml_packets(capture_file *cf, print_args_t *print_args);

/**
 * Print (export) the capture file into PSML format.
 *
 * @param cf the capture file
 * @param print_args the arguments what and how to export
 * @return one of cf_print_status_t
 */
cf_print_status_t cf_write_psml_packets(capture_file *cf, print_args_t *print_args);

/**
 * Print (export) the capture file into CSV format.
 *
 * @param cf the capture file
 * @param print_args the arguments what and how to export
 * @return one of cf_print_status_t
 */
cf_print_status_t cf_write_csv_packets(capture_file *cf, print_args_t *print_args);

/**
 * Print (export) the capture file into C Arrays format.
 *
 * @param cf the capture file
 * @param print_args the arguments what and how to export
 * @return one of cf_print_status_t
 */
cf_print_status_t cf_write_carrays_packets(capture_file *cf, print_args_t *print_args);

/**
 * Find packet with a protocol tree item that contains a specified text string.
 *
 * @param cf the capture file
 * @param string the string to find
 * @param dir direction in which to search
 * @return TRUE if a packet was found, FALSE otherwise
 */
gboolean cf_find_packet_protocol_tree(capture_file *cf, const char *string,
                                      search_direction dir);

/**
 * Find field with a label that contains text string cfile->sfilter.
 *
 * @param cf the capture file
 * @param tree the protocol tree
 * @param mdata the first field (mdata->finfo) that matched the string
 * @return TRUE if a packet was found, FALSE otherwise
 */
extern gboolean cf_find_string_protocol_tree(capture_file *cf, proto_tree *tree,
                                             match_data *mdata);

/**
 * Find packet whose summary line contains a specified text string.
 *
 * @param cf the capture file
 * @param string the string to find
 * @param dir direction in which to search
 * @return TRUE if a packet was found, FALSE otherwise
 */
gboolean cf_find_packet_summary_line(capture_file *cf, const char *string,
                                     search_direction dir);

/**
 * Find packet whose data contains a specified byte string.
 *
 * @param cf the capture file
 * @param string the string to find
 * @param string_size the size of the string to find
 * @param dir direction in which to search
 * @return TRUE if a packet was found, FALSE otherwise
 */
gboolean cf_find_packet_data(capture_file *cf, const guint8 *string,
                             size_t string_size, search_direction dir);

/**
 * Find packet that matches a compiled display filter.
 *
 * @param cf the capture file
 * @param sfcode the display filter to match
 * @param dir direction in which to search
 * @return TRUE if a packet was found, FALSE otherwise
 */
gboolean cf_find_packet_dfilter(capture_file *cf, dfilter_t *sfcode,
                                search_direction dir);

/**
 * Find packet that matches a display filter given as a text string.
 *
 * @param cf the capture file
 * @param filter the display filter to match
 * @param dir direction in which to search
 * @return TRUE if a packet was found, FALSE otherwise
 */
gboolean
cf_find_packet_dfilter_string(capture_file *cf, const char *filter,
                              search_direction dir);

/**
 * Find marked packet.
 *
 * @param cf the capture file
 * @param dir direction in which to search
 * @return TRUE if a packet was found, FALSE otherwise
 */
gboolean cf_find_packet_marked(capture_file *cf, search_direction dir);

/**
 * Find time-reference packet.
 *
 * @param cf the capture file
 * @param dir direction in which to search
 * @return TRUE if a packet was found, FALSE otherwise
 */
gboolean cf_find_packet_time_reference(capture_file *cf, search_direction dir);

/**
 * GoTo Packet in first row.
 *
 * @return TRUE if the first row exists, FALSE otherwise
 */
gboolean cf_goto_top_frame(void);

/**
 * GoTo Packet in last row.
 *
 * @return TRUE if last row exists, FALSE otherwise
 */
gboolean cf_goto_bottom_frame(void);

/**
 * GoTo Packet with the given row.
 *
 * @param cf the capture file
 * @param row the row to go to
 * @return TRUE if this row exists, FALSE otherwise
 */
gboolean cf_goto_frame(capture_file *cf, guint row);

/**
 * Go to frame specified by currently selected protocol tree field.
 * (Go To Corresponding Packet)
 * @todo this is ugly and should be improved!
 *
 * @param cf the capture file
 * @return TRUE if this packet exists, FALSE otherwise
 */
gboolean cf_goto_framenum(capture_file *cf);

/**
 * Select the packet in the given row.
 *
 * @param cf the capture file
 * @param row the row to select
 */
void cf_select_packet(capture_file *cf, int row);

/**
 * Unselect all packets, if any.
 *
 * @param cf the capture file
 */
void cf_unselect_packet(capture_file *cf);

/**
 * Unselect all protocol tree fields, if any.
 *
 * @param cf the capture file
 */
void cf_unselect_field(capture_file *cf);

/**
 * Mark a particular frame in a particular capture.
 *
 * @param cf the capture file
 * @param frame the frame to be marked
 */
void cf_mark_frame(capture_file *cf, frame_data *frame);

/**
 * Unmark a particular frame in a particular capture.
 *
 * @param cf the capture file
 * @param frame the frame to be unmarked
 */
void cf_unmark_frame(capture_file *cf, frame_data *frame);

/**
 * Ignore a particular frame in a particular capture.
 *
 * @param cf the capture file
 * @param frame the frame to be ignored
 */
void cf_ignore_frame(capture_file *cf, frame_data *frame);

/**
 * Unignore a particular frame in a particular capture.
 *
 * @param cf the capture file
 * @param frame the frame to be unignored
 */
void cf_unignore_frame(capture_file *cf, frame_data *frame);

/**
 * Merge two (or more) capture files into one.
 * @todo is this the right place for this function? It doesn't have to do a lot with capture_file.
 *
 * @param out_filename pointer to output filename; if output filename is
 * NULL, a temporary file name is generated and *out_filename is set
 * to point to the generated file name
 * @param in_file_count the number of input files to merge
 * @param in_filenames array of input filenames
 * @param file_type the output filetype
 * @param do_append FALSE to merge chronologically, TRUE simply append
 * @return one of cf_status_t
 */
cf_status_t
cf_merge_files(char **out_filename, int in_file_count,
               char *const *in_filenames, int file_type, gboolean do_append);


/**
 * Get the comment on a capture from the SHB data block
 *
 * @param cf the capture file
 */
const gchar* cf_read_shb_comment(capture_file *cf);

/**
 * Update(replace) the comment on a capture from the SHB data block
 *
 * @param cf the capture file
 * @param comment the string replacing the old comment
 */
void cf_update_capture_comment(capture_file *cf, gchar *comment);

char *cf_get_comment(capture_file *cf, const frame_data *fd);

/**
 * Update(replace) the comment on a capture from a frame
 *
 * @param cf the capture file
 * @param fd the frame_data structure for the frame
 * @param new_comment the string replacing the old comment
 */
gboolean cf_set_user_packet_comment(capture_file *cf, frame_data *fd, const gchar *new_comment);

/**
 * What types of comments does this file have?
 *
 * @param cf the capture file
 * @return bitset of WTAP_COMMENT_ values
 */
guint32 cf_comment_types(capture_file *cf);

#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)
WS_DLL_PUBLIC
void read_keytab_file(const char *);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* file.h */
