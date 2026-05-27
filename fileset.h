/** @file
 *
 * Definitions for routines for file sets.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __FILESET_H__
#define __FILESET_H__

#include <inttypes.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Describes a single file belonging to a capture file set.
 */
typedef struct _fileset_entry {
    char    *fullname; /**< File path including directory (heap-allocated via g_strdup) */
    char    *name;     /**< File name without directory path (heap-allocated via g_strdup) */
    time_t   ctime;    /**< File creation timestamp */
    time_t   mtime;    /**< File last-modified timestamp */
    int64_t  size;     /**< File size in bytes */
    bool     current;  /**< True if this entry represents the currently loaded capture file */
} fileset_entry;

/**
 * @brief Describes the naming pattern detected in a capture file set's filenames.
 */
typedef enum {
    FILESET_NO_MATCH,  /**< Filename does not match any recognized file set naming pattern */
    FILESET_TIME_NUM,  /**< Filename follows the timestamp-then-sequence-number pattern */
    FILESET_NUM_TIME   /**< Filename follows the sequence-number-then-timestamp pattern */
} fileset_match_t;

/* helper: is this a probable file of a file set (does the naming pattern match)?
 * Possible naming patterns are prefix_NNNNN_YYYYMMDDHHMMSS.ext[.gz] and
 * prefix_YYYYMMDDHHMMSS_NNNNN.ext[.gz], where any compression suffix
 * supported by libwiretap is allowed. The validation is minimal; e.g., the
 * time is only checked to see if all 14 characters are digits.
 *
 * @param[in] fname The filename to check for a naming pattern.
 * @param[out] prefix If not NULL and the filename matches, the prefix
 * @param[out] suffix If not NULL and the filename matches, the suffix
 * (file extension) not including the compression suffix
 * @param[out] time If not NULL and the filename matches, the time component
 * @return The type of pattern match, or FILESET_NO_MATCH.
 * */

/**
 * @brief Determines if a filename matches a specific pattern and extracts relevant parts.
 *
 * This function checks if the given filename matches predefined patterns for filesets and extracts
 * the prefix, suffix, and time components from the filename.
 *
 * @param fname The filename to be checked.
 * @param prefix Pointer to store the prefix extracted from the filename.
 * @param suffix Pointer to store the suffix extracted from the filename.
 * @param time Pointer to store the time extracted from the filename.
 * @return fileset_match_t Indicates whether the filename matches any of the predefined patterns.
 */
extern fileset_match_t fileset_filename_match_pattern(const char *fname, char **prefix, char **suffix, char **time);

 /**
  * @brief Adds a directory to the fileset.
  *
  * @param fname The name of the directory to add.
  * @param window A pointer to the window associated with the operation.
  */
extern void fileset_add_dir(const char *fname, void *window);

 /**
  * @brief Deletes the fileset and frees all associated resources.
  *
  * This function releases all memory allocated for the fileset, including its entries and directory name.
  */
extern void fileset_delete(void);

/**
 * @brief Get the current directory name.
 *
 * @return The current directory name, or NULL if not available.
 */
extern const char *fileset_get_dirname(void);

/**
 * @brief Get the next fileset entry.
 *
 * @return The next fileset entry, or NULL if there is no next entry.
 */
extern fileset_entry *fileset_get_next(void);

/**
 * @brief Get the previous fileset entry.
 *
 * @return The previous fileset entry, or NULL if there is no previous entry.
 */
extern fileset_entry *fileset_get_previous(void);

/**
 * @brief Add an entry to our dialog / window.
 *
 * Called by fileset_update_dlg. Must be implemented in the UI.
 *
 * @param entry The new fileset entry.
 * @param window Window / dialog reference provided by the UI code.
 */
extern void fileset_dlg_add_file(fileset_entry *entry, void *window);

/**
 * Notify our dialog / window that we're about to add files. Called by fileset_update_dlg.
 * Must be implemented in the UI.
 *
 * @param window Window / dialog reference provided by the UI code.
 */
extern void fileset_dlg_begin_add_file(void *window);

/**
 * @brief Notify our dialog / window that we're done adding files.
 *
 * Called by fileset_update_dlg. Must be implemented in the UI.
 *
 * @param window Window / dialog reference provided by the UI code.
 */
extern void fileset_dlg_end_add_file(void *window);

/**
 * @brief Updates the file dialog with the current file entries.
 *
 * @param window Pointer to the window containing the file dialog.
 */
extern void fileset_update_dlg(void *window);

/**
 * @brief Updates the file entry with the given path.
 *
 * This function updates the file entry in the fileset with the specified path,
 * setting its creation time, modification time, and size based on the current
 * state of the file.
 *
 * @param path The path to the file to be updated.
 */
extern void fileset_update_file(const char *path);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FILESET_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
