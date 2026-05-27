/** @file
 *
 * Copyright (C) 2016 Jakub Zawadzki
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __SHARKD_H
#define __SHARKD_H

#include <file.h>
#include <wiretap/wtap_opttypes.h>

#define SHARKD_DISSECT_FLAG_NULL       0x00u
#define SHARKD_DISSECT_FLAG_BYTES      0x01u
#define SHARKD_DISSECT_FLAG_COLUMNS    0x02u
#define SHARKD_DISSECT_FLAG_PROTO_TREE 0x04u
#define SHARKD_DISSECT_FLAG_COLOR      0x08u

#define SHARKD_MODE_CLASSIC_CONSOLE    1
#define SHARKD_MODE_CLASSIC_DAEMON     2
#define SHARKD_MODE_GOLD_CONSOLE       3
#define SHARKD_MODE_GOLD_DAEMON        4

typedef void (*sharkd_dissect_func_t)(epan_dissect_t *edt, proto_tree *tree, struct epan_column_info *cinfo, const GSList *data_src, void *data);

#define LONGOPT_FOREGROUND 4000

/* sharkd.c */

/**
 * @brief Open a capture file.
 *
 * @param fname The filename of the capture file to open.
 * @param type The type of the capture file.
 * @param is_tempfile True if the file is a temporary file.
 * @param err Pointer to an integer where error information will be stored.
 * @return cf_status_t The status of the operation.
 */
cf_status_t sharkd_cf_open(const char *fname, unsigned int type, bool is_tempfile, int *err);

/**
 * @brief Load a capture file without any limits.
 *
 * This function loads a capture file into the current session without applying any packet or byte count limits.
 *
 * @return 0 on success, non-zero on failure.
 */
int sharkd_load_cap_file(void);

/**
 * @brief Load a capture file with specified limits.
 *
 * This function loads a capture file into the current session with the specified packet and byte count limits.
 *
 * @param max_packet_count The maximum number of packets to load.
 * @param max_byte_count The maximum number of bytes to load.
 * @return 0 on success, non-zero on failure.
 */
int sharkd_load_cap_file_with_limits(int max_packet_count, int64_t max_byte_count);

/**
 * @brief Retaps all packets in the current capture file.
 *
 * This function triggers a re-dissection of all packets in the currently loaded capture file, applying any active filters and taps.
 *
 * @return 0 on success, non-zero on failure.
 */
int sharkd_retap(void);

/**
 * @brief Apply a display filter to the current capture file and return the results.
 *
 * This function compiles the provided display filter text and applies it to all frames in the currently
 * loaded capture file, returning a bit array indicating which frames match the filter.
 *
 * @param dftext The display filter text to compile and apply.
 * @param result Pointer to a uint8_t array where the results will be stored. The caller is responsible for freeing this array. Each bit in the array corresponds to a frame, with a value of 1 indicating a match and 0 indicating no match.
 * @return The number of frames processed, or -1 if an error occurred during filter compilation or application.
 */
int sharkd_filter(const char *dftext, uint8_t **result);

/**
 * @brief Get a frame by its number.
 *
 * @param framenum The number of the frame to retrieve.
 * @return A pointer to the frame data if found, NULL otherwise.
 */
frame_data *sharkd_get_frame(uint32_t framenum);

/**
 * @brief Return status for a frame dissection request.
 */
enum dissect_request_status {
    DISSECT_REQUEST_SUCCESS,       /**< The requested frame was found and successfully dissected */
    DISSECT_REQUEST_NO_SUCH_FRAME, /**< The requested frame number does not exist in the capture */
    DISSECT_REQUEST_READ_ERROR     /**< The frame data could not be read due to an I/O error */
};
enum dissect_request_status

/**
 * @brief Dissects a request for packet data.
 *
 * @param framenum The frame number to dissect.
 * @param frame_ref_num Reference number of the frame.
 * @param prev_dis_num Previous dissection number.
 * @param rec Pointer to the wtap_rec structure.
 * @param cinfo Pointer to the column_info structure.
 * @param dissect_flags Flags indicating how to perform the dissection.
 * @param cb Callback function for handling the dissection result.
 * @param data User data passed to the callback function.
 * @param err Error code if an error occurs.
 * @param err_info Error information if an error occurs.
 * @return The status of the dissection request.
 */
sharkd_dissect_request(uint32_t framenum, uint32_t frame_ref_num,
                       uint32_t prev_dis_num, wtap_rec *rec,
                       column_info *cinfo, uint32_t dissect_flags,
                       sharkd_dissect_func_t cb, void *data,
                       int *err, char **err_info);

/**
 * @brief Get the modified packet block for a given frame, if available.
 *
 * @param fd Pointer to the frame data structure.
 * @return The modified packet block, or NULL if no modification is available.
 */
wtap_block_t sharkd_get_modified_block(const frame_data *fd);

/**
 * @brief Get the packet block for a given frame.
 *
 * @param fd Pointer to the frame data structure.
 * @return The packet block, or NULL if an error occurred.
 */
wtap_block_t sharkd_get_packet_block(const frame_data *fd);

/**
 * @brief Set a modified block for a frame.
 *
 * @param fd Pointer to the frame data structure.
 * @param new_block The new block to set.
 * @return 0 on success, -1 on failure.
 */
int sharkd_set_modified_block(frame_data *fd, wtap_block_t new_block);

/**
 * @brief Retrieves the version of the SharkD server.
 *
 * @return A string representing the version of the SharkD server.
 */
const char *sharkd_version(void);

/**
 * @brief Get the long options for the sharkd daemon.
 *
 * @return const struct ws_option* - An array of ws_option structures representing the long options for the sharkd daemon.
 */
const struct ws_option* sharkd_long_options(void);

/**
 * @brief Get the string of valid options for the sharkd daemon.
 *
 * @return const char* - The string containing valid options.
 */
const char* sharkd_optstring(void);


/* sharkd_daemon.c */

/**
 * @brief Initialize the sharkd server.
 *
 * This function initializes the sharkd server with command-line arguments.
 *
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line argument strings.
 * @return 0 on success, -1 on failure.
 */
int sharkd_init(int argc, char **argv);

/**
 * @brief Main loop for the sharkd daemon.
 *
 * This function runs the main loop for the sharkd daemon, processing incoming requests.
 *
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line argument strings.
 * @return int Return code indicating success or failure of the daemon.
 */
int sharkd_loop(int argc _U_, char* argv[] _U_);

/* sharkd_session.c */

/**
 * @brief Main function for handling sharkd sessions.
 *
 * This function initializes the session with a given mode setting and processes commands received from stdin.
 *
 * @param mode_setting The mode in which the session should operate.
 * @return 0 on success, non-zero for failure.
 */
int sharkd_session_main(int mode_setting);

#endif /* __SHARKD_H */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
