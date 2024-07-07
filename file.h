/** @file
 *
 * Definitions for file structures and routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __FILE_H__
#define __FILE_H__

#include <wiretap/wtap.h>
#include <epan/epan.h>
#include <epan/print.h>
#include <epan/fifo_string_cache.h>
#include <ui/packet_range.h>

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
    CF_READ_OK,      /**< operation succeeded */
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
    cf_cb_file_retap_started,
    cf_cb_file_retap_finished,
    cf_cb_file_merge_started, /* Qt only */
    cf_cb_file_merge_finished, /* Qt only */
    cf_cb_file_fast_save_finished,
    cf_cb_file_save_started,
    cf_cb_file_save_finished,
    cf_cb_file_save_failed,
    cf_cb_file_save_stopped
} cf_cbs;

typedef void (*cf_callback_t) (int event, void *data, void *user_data);

typedef struct {
    const char    *string;
    size_t         string_len;
    capture_file  *cf;
    field_info    *finfo;
    field_info    *prev_finfo;
    bool           frame_matched;
    bool           halt;
} match_data;

/**
 * Set maximum number of records per capture file.
 *
 * @param max_records maximum number of records to support.
 */
extern void
cf_set_max_records(unsigned max_records);

/**
 * Add a capture file event callback.
 *
 * @param func The function to be called for each event.
 *             The function will be passed three parameters: The event type (event),
 *             event-dependent data (data), and user-supplied data (user_data).
 *             Event-dependent data may be a capture_file pointer, character pointer,
 *             or NULL.
 * @param user_data User-supplied data to pass to the callback. May be NULL.
 */

extern void
cf_callback_add(cf_callback_t func, void *user_data);

/**
 * Remove a capture file event callback.
 *
 * @param func The function to be removed.
 * @param user_data User-supplied data. Must be the same value supplied to cf_callback_add.
 */

extern void
cf_callback_remove(cf_callback_t func, void *user_data);

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
cf_status_t cf_open(capture_file *cf, const char *fname, unsigned int type, bool is_tempfile, int *err);

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
 * @return one of cf_status_t
 */
cf_status_t cf_reload(capture_file *cf);

/**
 * Read all packets of a capture file into the internal structures.
 *
 * @param cf the capture file to be read
 * @param reloading reread asked for from cf_save_records()
 * @return one of cf_read_status_t
 */
cf_read_status_t cf_read(capture_file *cf, bool reloading);

/**
 * Read the metadata and raw data for a record.  It will pop
 * up an alert box if there's an error.
 *
 * @param cf the capture file from which to read the record
 * @param fdata the frame_data structure for the record in question
 * @param rec pointer to a wtap_rec structure to contain the
 * record's metadata
 * @param buf a Buffer into which to read the record's raw data
 * @return true if the read succeeded, false if there was an error
 */
bool cf_read_record(capture_file *cf, const frame_data *fdata,
                          wtap_rec *rec, Buffer *buf);

/** Same as cf_read_record() but does not pop alert box on error */
bool cf_read_record_no_alert(capture_file *cf, const frame_data *fdata,
                                 wtap_rec *rec, Buffer *buf);


/**
 * Read the metadata and raw data for the current record into a
 * capture_file structure's rec and buf for the current record.
 * It will pop up an alert box if there's an error.
 *
 * @param cf the capture file from which to read the record
 * @return true if the read succeeded, false if there was an error
 */
bool cf_read_current_record(capture_file *cf);

/**
 * Read packets from the "end" of a capture file.
 *
 * @param cf the capture file to be read from
 * @param to_read the number of packets to read
 * @param rec pointer to wtap_rec to use when reading
 * @param buf pointer to Buffer to use when reading
 * @param err the error code, if an error had occurred
 * @return one of cf_read_status_t
 */
cf_read_status_t cf_continue_tail(capture_file *cf, volatile int to_read,
                                  wtap_rec *rec, Buffer *buf, int *err,
                                  fifo_string_cache_t *frame_dup_cache, GChecksum *frame_cksum);

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
 * @param rec pointer to wtap_rec to use when reading
 * @param buf pointer to Buffer to use when reading
 * @param err the error code, if an error had occurred
 * @return one of cf_read_status_t
 */
cf_read_status_t cf_finish_tail(capture_file *cf, wtap_rec *rec,
                                Buffer *buf, int *err,
                                fifo_string_cache_t *frame_dup_cache, GChecksum *frame_cksum);

/**
 * Determine whether this capture file (or a range of it) can be written
 * in any format using Wiretap rather than by copying the raw data.
 *
 * @param cf the capture file to check
 * @return true if it can be written, false if it can't
 */
bool cf_can_write_with_wiretap(capture_file *cf);

/**
 * Determine whether this capture file can be saved with a "save" operation;
 * if there's nothing unsaved, it can't.
 *
 * @param cf the capture file to check
 * @return true if it can be saved, false if it can't
 */
bool cf_can_save(capture_file *cf);

/**
 * Determine whether this capture file can be saved with a "save as" operation.
 *
 * @param cf the capture file to check
 * @return true if it can be saved, false if it can't
 */
bool cf_can_save_as(capture_file *cf);

/**
 * Determine whether this capture file has unsaved data.
 *
 * @param cf the capture file to check
 * @return true if it has unsaved data, false if it doesn't
 */
bool cf_has_unsaved_data(capture_file *cf);

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
 * @param compression_type type of compression to use when writing, if any
 * @param discard_comments true if we should discard comments if the save
 * succeeds (because we saved in a format that doesn't support
 * comments)
 * @param dont_reopen true if it shouldn't reopen and make that file the
 * current capture file
 * @return one of cf_write_status_t
 */
cf_write_status_t cf_save_records(capture_file * cf, const char *fname,
                                  unsigned save_format,
                                  wtap_compression_type compression_type,
                                  bool discard_comments,
                                  bool dont_reopen);

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
 * @param compression_type type of compression to use when writing, if any
 * @return one of cf_write_status_t
 */
cf_write_status_t cf_export_specified_packets(capture_file *cf,
                                              const char *fname,
                                              packet_range_t *range,
                                              unsigned save_format,
                                              wtap_compression_type compression_type);

/**
 * Get a displayable name of the capture file.
 *
 * @param cf the capture file
 * @return the displayable name (must be g_free'd)
 */
char *cf_get_display_name(capture_file *cf);

/**
 * Get a name that can be used to generate a file name from the
 * capture file name.  It's based on the displayable name, so it's
 * UTF-8; if it ends with a suffix that's used by a file type libwiretap
 * can read, we strip that suffix off.
 *
 * @param cf the capture file
 * @return the base name (must be g_free'd)
 */
char *cf_get_basename(capture_file *cf);

/**
 * Set the source of the capture data for temporary files, e.g.
 * "Interface eth0" or "Pipe from Pong"
 *
 * @param cf the capture file
 * @param source the source description. this will be copied internally.
 */
void cf_set_tempfile_source(capture_file *cf, char *source);

/**
 * Get the source of the capture data for temporary files. Guaranteed to
 * return a non-null value. The returned value should not be freed.
 *
 * @param cf the capture file
 */
const char *cf_get_tempfile_source(capture_file *cf);

/**
 * Get the number of packets in the capture file.
 *
 * @param cf the capture file
 * @return the number of packets in the capture file
 */
int cf_get_packet_count(capture_file *cf);

/**
 * Is this capture file a temporary file?
 *
 * @param cf the capture file
 * @return true if it's a temporary file, false otherwise
 */
bool cf_is_tempfile(capture_file *cf);

/**
 * Set flag, that this file is a tempfile.
 */
void cf_set_tempfile(capture_file *cf, bool is_tempfile);

/**
 * Set flag, if the number of packet drops while capturing are known or not.
 *
 * @param cf the capture file
 * @param drops_known true if the number of packet drops are known, false otherwise
 */
void cf_set_drops_known(capture_file *cf, bool drops_known);

/**
 * Set the number of packet drops while capturing.
 *
 * @param cf the capture file
 * @param drops the number of packet drops occurred while capturing
 */
void cf_set_drops(capture_file *cf, uint32_t drops);

/**
 * Get flag state, if the number of packet drops while capturing are known or not.
 *
 * @param cf the capture file
 * @return true if the number of packet drops are known, false otherwise
 */
bool cf_get_drops_known(capture_file *cf);

/**
 * Get the number of packet drops while capturing.
 *
 * @param cf the capture file
 * @return the number of packet drops occurred while capturing
 */
uint32_t cf_get_drops(capture_file *cf);

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
 * @param force true if do in any case, false only if dfilter changed
 * @return one of cf_status_t
 */
cf_status_t cf_filter_packets(capture_file *cf, char *dfilter, bool force);

/**
 * Scan through all frame data and recalculate the ref time
 * without rereading the file.
 *
 * @param cf the capture file
 */
void cf_reftime_packets(capture_file *cf);

/**
 * Return the time it took to load the file (in msec).
 */
unsigned long cf_get_computed_elapsed(capture_file *cf);

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

/* print_range, enum which frames should be printed */
typedef enum {
    print_range_selected_only,    /* selected frame(s) only (currently only one) */
    print_range_marked_only,      /* marked frames only */
    print_range_all_displayed,    /* all frames currently displayed */
    print_range_all_captured      /* all frames in capture */
} print_range_e;

typedef struct {
    print_stream_t *stream;       /* the stream to which we're printing */
    print_format_e format;        /* plain text or PostScript */
    bool to_file;             /* true if we're printing to a file */
    char *file;                   /* file output pathname */
    char *cmd;                    /* print command string (not win32) */
    packet_range_t range;

    bool print_summary;       /* true if we should print summary line. */
    bool print_col_headings;  /* true if we should print column headings */
    print_dissections_e print_dissections;
    bool print_hex;           /* true if we should print hex data;
                                   * false if we should print only if not dissected. */
    unsigned hexdump_options;        /* Hexdump options if print_hex is true. */
    bool print_formfeed;      /* true if a formfeed should be printed before
                                   * each new packet */
} print_args_t;

/**
 * Print the capture file.
 *
 * @param cf the capture file
 * @param print_args the arguments what and how to print
 * @param show_progress_bar true if a progress bar is to be shown
 * @return one of cf_print_status_t
 */
cf_print_status_t cf_print_packets(capture_file *cf, print_args_t *print_args,
                                   bool show_progress_bar);

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
 * Print (export) the capture file into JSON format.
 *
 * @param cf the capture file
 * @param print_args the arguments what and how to export
 * @return one of cf_print_status_t
 */
cf_print_status_t cf_write_json_packets(capture_file *cf, print_args_t *print_args);

/**
 * Find packet with a protocol tree item that contains a specified text string.
 *
 * @param cf the capture file
 * @param string the string to find
 * @param dir direction in which to search
 * @param multiple whether to look for the next occurrence of the same string
 * in the current packet, or to only match once per frame
 * @return true if a packet was found, false otherwise
 */
bool cf_find_packet_protocol_tree(capture_file *cf, const char *string,
                                      search_direction dir, bool multiple);

/**
 * Find field with a label that contains the text string cfile->sfilter in
 * a protocol tree.
 *
 * @param cf the capture file
 * @param tree the protocol tree
 * @return The first field in the tree that matched the string if found, NULL otherwise
 */
extern field_info* cf_find_string_protocol_tree(capture_file *cf, proto_tree *tree);

/**
 * Find packet whose summary line contains a specified text string.
 *
 * @param cf the capture file
 * @param string the string to find
 * @param dir direction in which to search
 * @return true if a packet was found, false otherwise
 */
bool cf_find_packet_summary_line(capture_file *cf, const char *string,
                                     search_direction dir);

/**
 * Find packet whose data contains a specified byte string.
 *
 * @param cf the capture file
 * @param string the string to find
 * @param string_size the size of the string to find
 * @param dir direction in which to search
 * @param multiple whether to look for the next occurrence of the same string
 * in the current packet, or to only match once per frame
 * @return true if a packet was found, false otherwise
 */
bool cf_find_packet_data(capture_file *cf, const uint8_t *string,
                             size_t string_size, search_direction dir,
                             bool multiple);

/**
 * Find packet that matches a compiled display filter.
 *
 * @param cf the capture file
 * @param sfcode the display filter to match
 * @param dir direction in which to search
 * @return true if a packet was found, false otherwise
 */
bool cf_find_packet_dfilter(capture_file *cf, dfilter_t *sfcode,
                                search_direction dir);

/**
 * Find packet that matches a display filter given as a text string.
 *
 * @param cf the capture file
 * @param filter the display filter to match
 * @param dir direction in which to search
 * @return true if a packet was found, false otherwise
 */
bool
cf_find_packet_dfilter_string(capture_file *cf, const char *filter,
                              search_direction dir);

/**
 * Find marked packet.
 *
 * @param cf the capture file
 * @param dir direction in which to search
 * @return true if a packet was found, false otherwise
 */
bool cf_find_packet_marked(capture_file *cf, search_direction dir);

/**
 * Find time-reference packet.
 *
 * @param cf the capture file
 * @param dir direction in which to search
 * @return true if a packet was found, false otherwise
 */
bool cf_find_packet_time_reference(capture_file *cf, search_direction dir);

/**
 * GoTo Packet with the given row.
 *
 * @param cf the capture file
 * @param row the row to go to
 * @param exact if true, fail if the row exists and is filtered (not displayed)
 * if false, go to the nearest displayed packet instead
 * @return true if this row exists, false otherwise
 */
bool cf_goto_frame(capture_file *cf, unsigned row, bool exact);

/**
 * Go to frame specified by currently selected protocol tree field.
 * (Go To Corresponding Packet)
 * @todo this is ugly and should be improved!
 *
 * @param cf the capture file
 * @return true if this packet exists, false otherwise
 */
bool cf_goto_framenum(capture_file *cf);

/**
 * Select the packet in the given row.
 *
 * @param cf the capture file
 * @param frame the frame to be selected
 */
void cf_select_packet(capture_file *cf, frame_data *frame);

/**
 * Unselect all packets, if any.
 *
 * @param cf the capture file
 */
void cf_unselect_packet(capture_file *cf);

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
 * Merge two or more capture files into a temporary file.
 * @todo is this the right place for this function? It doesn't have to do a lot with capture_file.
 *
 * @param pd_window Window pointer suitable for use by delayed_create_progress_dlg.
 * @param out_filenamep Points to a pointer that's set to point to the
 *        pathname of the temporary file; it's allocated with g_malloc()
 * @param in_file_count the number of input files to merge
 * @param in_filenames array of input filenames
 * @param file_type the output filetype
 * @param do_append false to merge chronologically, true simply append
 * @return one of cf_status_t
 */
cf_status_t
cf_merge_files_to_tempfile(void *pd_window, const char *temp_dir, char **out_filenamep,
                           int in_file_count, const char *const *in_filenames,
                           int file_type, bool do_append);

/**
 * Update(replace) the comment on a capture from the SHB data block
 * XXX - should support multiple sections.
 *
 * @param cf the capture file
 * @param comment the string replacing the old comment
 */
void cf_update_section_comment(capture_file *cf, char *comment);

/**
 * Update(replace) the comments on a capture from the SHB data block
 *
 * @param cf the capture file
 * @param shb_idx the index of the SHB (0-indexed)
 * @param comments a NULL-terminated string array of comments. The function
 * takes ownership of the string array and frees it and the contents.
 */
void cf_update_section_comments(capture_file *cf, unsigned shb_idx, char **comments);

/*
 * Get the packet block for a packet (record).
 * If the block has been edited, it returns the result of the edit,
 * otherwise it returns the block from the file.
 *
 * @param cf the capture file
 * @param fd the frame_data structure for the frame
 * @returns A block (use wtap_block_unref to free) or NULL if there is none.
 */
wtap_block_t cf_get_packet_block(capture_file *cf, const frame_data *fd);

/**
 * Update(replace) the block on a capture from a frame
 *
 * @param cf the capture file
 * @param fd the frame_data structure for the frame
 * @param new_block the block replacing the old block
 *
 * @return true if the block is modified for the first time. false if
 * the block was already modified before, in which case the caller is
 * responsible for updating the comment count.
 */
bool cf_set_modified_block(capture_file *cf, frame_data *fd, const wtap_block_t new_block);

/**
 * What types of comments does this file have?
 *
 * @param cf the capture file
 * @return bitset of WTAP_COMMENT_ values
 */
uint32_t cf_comment_types(capture_file *cf);

/**
 * Add a resolved address to this file's list of resolved addresses.
 *
 * @param cf the capture file
 * @param addr a string representing an IPv4 or IPv6 address
 * @param name a string containing a name corresponding to that address
 * @return true if it succeeds, false if not
 */
bool cf_add_ip_name_from_string(capture_file *cf, const char *addr, const char *name);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* file.h */
