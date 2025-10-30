/** @file
 * Definitions for routines for merging files.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __MERGE_H__
#define __MERGE_H__

#include "wiretap/wtap.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief State of input file during merge.
 *
 * Indicates the result of reading from an input file.
 */
typedef enum {
    RECORD_PRESENT,      /**< A record was successfully read. */
    RECORD_NOT_PRESENT,  /**< No record available at current position. */
    AT_EOF,              /**< End of file reached. */
    GOT_ERROR            /**< An error occurred while reading. */
} in_file_state_e;


/**
 * @brief Structure to manage input files during merge.
 *
 * Holds state and metadata for each input file processed.
 */
typedef struct merge_in_file_s {
    const char     *filename;        /**< Input file name. */
    wtap           *wth;             /**< Wiretap handle for reading packets. */
    wtap_rec        rec;             /**< Current packet record. */
    in_file_state_e state;           /**< Input file state. */
    uint32_t        packet_num;      /**< Current packet number. */
    int64_t         size;            /**< File size in bytes. */
    GArray         *idb_index_map;   /**< Maps legacy phdr interface_id to new IDs during merge. */
    unsigned        nrbs_seen;       /**< Count of processed elements from wth->nrbs. */
    unsigned        dsbs_seen;       /**< Count of processed elements from wth->dsbs. */
} merge_in_file_t;

/**
 * @brief Merge event types passed to the callback function.
 *
 * Indicates the stage at which the merge callback was invoked.
 */
typedef enum {
    MERGE_EVENT_INPUT_FILES_OPENED,   /**< Input files have been opened. */
    MERGE_EVENT_FRAME_TYPE_SELECTED,  /**< Frame type has been selected. */
    MERGE_EVENT_READY_TO_MERGE,       /**< Ready to begin merging packets. */
    MERGE_EVENT_RECORD_WAS_READ,      /**< A packet record was read. */
    MERGE_EVENT_DONE                  /**< Merge process is complete. */
} merge_event;


/**
 * @brief Merge mode for Interface Description Blocks (IDBs).
 *
 * Controls how duplicate IDBs are handled during file merge.
 */
typedef enum {
    IDB_MERGE_MODE_NONE = 0,     /**< No merging; all IDBs are copied into the merged file. */
    IDB_MERGE_MODE_ALL_SAME,     /**< Merge only if all input files share identical IDBs. */
    IDB_MERGE_MODE_ANY_SAME,     /**< Merge any duplicate IDBs, even within a single file. */
    IDB_MERGE_MODE_MAX           /**< Sentinel value; not a valid mode. */
} idb_merge_mode;



/**
 * @brief Returns the idb_merge_mode for the given string name.
 *
 * @param name The name of the mode.
 * @return The idb_merge_mode, or IDB_MERGE_MODE_MAX on failure.
 */
WS_DLL_PUBLIC idb_merge_mode
merge_string_to_idb_merge_mode(const char *name);


/**
 * @brief Returns the string name for the given number.
 *
 * @param mode The number of the mode, representing the idb_merge_mode enum value.
 * @return The string name, or "UNKNOWN" on failure.
 */
WS_DLL_PUBLIC const char*
merge_idb_merge_mode_to_string(const int mode);


/** @struct merge_progress_callback_t
 *
 * @brief Callback information for merging.
 *
 * @details The merge_files() routine can invoke a callback during its execution,
 * to enable verbose printing or progress bar updating, for example. This struct
 * provides merge_files() with the callback routine to invoke, and optionally
 * private data to pass through to the callback each time it is invoked.
 * For the callback_func routine's arguments: the event is when the callback
 * was invoked, the num is an int specific to the event, in_files is an array
 * of the created merge info, in_file_count is the size of the array, data is
 * whatever was passed in the data member of this struct. The callback_func
 * routine's return value should be true if merging should be aborted.
 */
typedef struct {
    bool (*callback_func)(merge_event event, int num,
                              const merge_in_file_t in_files[], const unsigned in_file_count,
                              void *data);
    void *data; /**< private data to use for passing through to the callback function */
} merge_progress_callback_t;


/**
 * @brief Merge the given input files to a file with the given filename
 *
 * @param out_filename The output filename
 * @param file_type The WTAP_FILE_TYPE_SUBTYPE_XXX output file type
 * @param in_filenames An array of input filenames to merge from
 * @param in_file_count The number of entries in in_filenames
 * @param do_append Whether to append by file order instead of chronological order
 * @param mode The IDB_MERGE_MODE_XXX merge mode for interface data
 * @param snaplen The snaplen to limit it to, or 0 to leave as it is in the files
 * @param app_name The application name performing the merge, used in SHB info
 * @param cb The callback information to use during execution
 * @param compression_type The compression type to use for the output
 * @return true on success, false on failure
 */
WS_DLL_PUBLIC bool
merge_files(const char* out_filename, const int file_type,
            const char *const *in_filenames, const unsigned in_file_count,
            const bool do_append, const idb_merge_mode mode,
            unsigned snaplen, const char *app_name, merge_progress_callback_t* cb,
            ws_compression_type compression_type);

/**
 * @brief Merge the given input files to a temporary file
 *
 * @param tmpdir Points to the directory in which to write the temporary file
 * @param out_filenamep Points to a pointer that's set to point to the
 *        pathname of the temporary file; it's allocated with g_malloc()
 * @param pfx A string to be used as the prefix for the temporary file name
 * @param file_type The WTAP_FILE_TYPE_SUBTYPE_XXX output file type
 * @param in_filenames An array of input filenames to merge from
 * @param in_file_count The number of entries in in_filenames
 * @param do_append Whether to append by file order instead of chronological order
 * @param mode The IDB_MERGE_MODE_XXX merge mode for interface data
 * @param snaplen The snaplen to limit it to, or 0 to leave as it is in the files
 * @param app_name The application name performing the merge, used in SHB info
 * @param cb The callback information to use during execution
 * @return true on success, false on failure
 */
WS_DLL_PUBLIC bool
merge_files_to_tempfile(const char *tmpdir, char **out_filenamep, const char *pfx,
                        const int file_type, const char *const *in_filenames,
                        const unsigned in_file_count, const bool do_append,
                        const idb_merge_mode mode, unsigned snaplen,
                        const char *app_name, merge_progress_callback_t* cb);

/**
 * @brief Merge the given input files to the standard output
 *
 * @param file_type The WTAP_FILE_TYPE_SUBTYPE_XXX output file type
 * @param in_filenames An array of input filenames to merge from
 * @param in_file_count The number of entries in in_filenames
 * @param do_append Whether to append by file order instead of chronological order
 * @param mode The IDB_MERGE_MODE_XXX merge mode for interface data
 * @param snaplen The snaplen to limit it to, or 0 to leave as it is in the files
 * @param app_name The application name performing the merge, used in SHB info
 * @param cb The callback information to use during execution
 * @return true on success, false on failure
 */
WS_DLL_PUBLIC bool
merge_files_to_stdout(const int file_type, const char *const *in_filenames,
                      const unsigned in_file_count, const bool do_append,
                      const idb_merge_mode mode, unsigned snaplen,
                      const char *app_name, merge_progress_callback_t* cb,
                      ws_compression_type compression_type);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MERGE_H__ */

