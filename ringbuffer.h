/** @file
 *
 * Definitions for capture ringbuffer files
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __RINGBUFFER_H__
#define __RINGBUFFER_H__

#include <wireshark.h>
#include <writecap/pcapio.h>

#define RINGBUFFER_UNLIMITED_FILES 0
/* Minimum number of ringbuffer files */
#define RINGBUFFER_MIN_NUM_FILES 0
/* Maximum number of ringbuffer files */
/* Avoid crashes on very large numbers. Should be a power of 10 */
#define RINGBUFFER_MAX_NUM_FILES 100000
/* Maximum number for FAT filesystems */
#define RINGBUFFER_WARN_NUM_FILES 65535

/**
 * @brief Initialize the ringbuffer system.
 *
 * Initializes the ringbuffer system with the specified parameters.
 *
 * @param capture_name The name of the capture file.
 * @param num_files The number of files in the ringbuffer.
 * @param group_read_access Whether to set group read access for the files.
 * @param compress_type The compression type for the files.
 * @param nametimenum Whether to include name, time, and number in the filenames.
 * @return file descriptor on success, -1 on failure.
 */
int ringbuf_init(const char *capture_name, unsigned num_files, bool group_read_access,
                 const char *compress_type, bool nametimenum);

/**
 * @brief Check if the ringbuffer system is initialized.
 *
 * Determines whether the ringbuffer system has been initialized.
 *
 * @return true if the ringbuffer system is initialized, false otherwise.
 */
bool ringbuf_is_initialized(void);

/**
 * @brief Get the current filename used by the ringbuffer.
 * @return The current filename used by the ringbuffer.
 */
const char *ringbuf_current_filename(void);

/**
 * @brief Initialize a libpcap dump file for the ringbuffer.
 * Initializes a libpcap dump file for writing captured packets to the ringbuffer.
 * @param err Pointer to an integer that will be set to an error code if an error occurs.
 * @return A pointer to a ws_cwstream on success, or NULL on failure.
 */
ws_cwstream* ringbuf_init_libpcap_fdopen(int *err);

/**
 * @brief Switch the ringbuffer dump file.
 * @param pdh Pointer to the current pcap dump handle, which will be updated to the new handle.
 * @param save_file Pointer to a string that will be set to the name of the saved file.
 * @param save_file_fd Pointer to an integer that will be set to the file descriptor of the saved file.
 * @param err Pointer to an integer that will be set to an error code if an error occurs.
 * @return true on success, false otherwise.
 */
bool ringbuf_switch_file(ws_cwstream* *pdh, char **save_file, int *save_file_fd,
                             int *err);

/**
 * @brief Close the ringbuffer dump file.
 *
 * Closes the current ringbuffer dump file and cleans up resources.
 *
 * @param save_file Pointer to a string that will be set to the name of the saved file.
 * @param err Pointer to an integer that will be set to an error code if an error occurs.
 * @return true on success, false otherwise.
 */
bool ringbuf_libpcap_dump_close(char **save_file, int *err);

/**
 * @brief Frees all memory allocated by the ringbuffer.
 *
 * Cleans up and frees all resources used by the ringbuffer system.
 */
void ringbuf_free(void);

/**
 * @brief Clean up any errors related to the ringbuffer system.
 *
 * Frees all memory allocated by the ringbuffer and closes any open files.
 */
void ringbuf_error_cleanup(void);

/**
 * @brief Set the name for the ringbuffer.
 *
 * Sets the name of the file to which the ringbuffer will write data.
 *
 * @param name Pointer to a string that will be set to the name of the capture file.
 * @param err Pointer to an integer that will be set to an error code if an error occurs.
 * @return true on success, false otherwise.
 */
bool ringbuf_set_print_name(char *name, int *err);

#endif /* ringbuffer.h */
