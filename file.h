/* file.h
 * Definitions for file structures and routines
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __FILE_H__
#define __FILE_H__

#include "packet-range.h"
#include "wiretap/wtap.h"
#include <epan/dfilter/dfilter.h>
#include "print.h"
#include <errno.h>
#include <epan/epan.h>

#include "cfile.h"


/** Return values from functions that only can succeed or fail. */
typedef enum {
	CF_OK,			    /**< operation succeeded */
	CF_ERROR	/**< operation got an error (function may provide err with details) */
} cf_status_t;

/** Return values from functions that read capture files. */
typedef enum {
	CF_READ_OK,		/**< operation succeeded */
	CF_READ_ERROR,		/**< operation got an error (function may provide err with details) */
	CF_READ_ABORTED		/**< operation aborted by user */
} cf_read_status_t;

/** Return values from functions that print sets of packets. */
typedef enum {
	CF_PRINT_OK,		    /**< print operation succeeded */
	CF_PRINT_OPEN_ERROR,    /**< print operation failed while opening printer */
	CF_PRINT_WRITE_ERROR    /**< print operation failed while writing to the printer */
} cf_print_status_t;

typedef enum {
    cf_cb_file_closing,
    cf_cb_file_closed,
    cf_cb_file_read_started,
    cf_cb_file_read_finished,
    cf_cb_packet_selected,
    cf_cb_packet_unselected,
    cf_cb_field_unselected,
    cf_cb_file_save_started,
    cf_cb_file_save_finished,
    cf_cb_file_save_reload_finished,
    cf_cb_file_save_failed
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
 * @param is_tempfile is this a temporary file?
 * @param err error code
 * @return one of cf_status_t
 */
cf_status_t cf_open(capture_file *cf, const char *fname, gboolean is_tempfile, int *err);

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
 * @param from_save reread asked from cf_save
 * @return one of cf_read_status_t
 */
cf_read_status_t cf_read(capture_file *cf, gboolean from_save);

/**
 * Read the pseudo-header and raw data for a packet.  It will pop
 * up an alert box if there's an error.
 *
 * @param cf the capture file from which to read the packet
 * @param fdata the frame_data structure for the packet in question
 * @param pseudo_header pointer to a wtap_pseudo_header union into
 * which to read the packet's pseudo-header
 * @param pd a guin8 array into which to read the packet's raw data
 * @return TRUE if the read succeeded, FALSE if there was an error
 */
gboolean cf_read_frame_r(capture_file *cf, frame_data *fdata,
                         union wtap_pseudo_header *pseudo_header, guint8 *pd);

/**
 * Read the pseudo-header and raw data for a packet into a
 * capture_file structure's pseudo_header and pd members.
 * It will pop up an alert box if there's an error.
 *
 * @param cf the capture file from which to read the packet
 * @param fdata the frame_data structure for the packet in question
 * @return TRUE if the read succeeded, FALSE if there was an error
 */
gboolean cf_read_frame(capture_file *cf, frame_data *fdata);

/**
 * Start reading from the end of a capture file.
 * This is used in "Update list of packets in Real-Time".
 *
 * @param cf the capture file to be read from
 * @param fname the filename to be read from
 * @param is_tempfile is this a temporary file?
 * @param err the error code, if an error had occured
 * @return one of cf_status_t
 */
cf_status_t cf_start_tail(capture_file *cf, const char *fname, gboolean is_tempfile, int *err);

/**
 * Read packets from the "end" of a capture file.
 *
 * @param cf the capture file to be read from
 * @param to_read the number of packets to read
 * @param err the error code, if an error had occured
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
 * @param err the error code, if an error had occured
 * @return one of cf_read_status_t
 */
cf_read_status_t cf_finish_tail(capture_file *cf, int *err);

/**
 * Determine whether this capture file (or a range of it) can be saved
 * (except by copying the raw file data).
 *
 * @param cf the capture file to check
 * @return TRUE if it can be saved, FALSE if it can't
 */
gboolean cf_can_save_as(capture_file *cf);

/**
 * Save a capture file (or a range of it).
 *
 * @param cf the capture file to save to
 * @param fname the filename to save to
 * @param range the range of packets to save
 * @param save_format the format of the file to save (libpcap, ...)
 * @param compressed whether to gzip compress the file
 * @return one of cf_status_t
 */
cf_status_t cf_save(capture_file * cf, const char *fname, packet_range_t *range, guint save_format, gboolean compressed);

/**
 * Get a displayable name of the capture file.
 *
 * @param cf the capture file
 * @return the displayable name (don't have to be g_free'd)
 */
const gchar *cf_get_display_name(capture_file *cf);

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
 * @param drops the number of packet drops occured while capturing
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
 * @return the number of packet drops occured while capturing
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
gulong cf_get_computed_elapsed(void);

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

#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)
void read_keytab_file(const char *);
#endif

#endif /* file.h */
