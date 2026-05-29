/** @file
 *
 * Common command line handling between GUIs
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __COMMANDLINE_H__
#define __COMMANDLINE_H__

#include <epan/cfile.h> /* For search_direction */
#include "ui/capture_opts.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef void (*commandline_usage_output_cb_t)(FILE* const output);

/**
 * @brief Holds application-specific strings and callbacks used to render command-line usage/help output.
 */
typedef struct commandline_usage_app_data
{
    const char                   *item_name;                /**< Short identifier name of the application (e.g. "wireshark", "tshark"). */
    const char                   *console_name;             /**< Display name of the application shown in console usage output. */
    const char                   *help_header;              /**< Header string printed at the top of the help/usage message. */
#ifdef HAVE_LIBPCAP
    commandline_usage_output_cb_t capture_interface_options; /**< Callback to print capture interface option help; only present when libpcap support is compiled in. */
    commandline_usage_output_cb_t list_interface_options;    /**< Callback to print interface listing option help; only present when libpcap support is compiled in. */
    commandline_usage_output_cb_t capture_output_options;    /**< Callback to print capture output option help; only present when libpcap support is compiled in. */
#endif
} commandline_usage_app_data_t;

extern capture_options global_capture_opts;

/**
 * @brief Process early command-line options.
 *
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line argument strings.
 * @param app_data Application-specific data structure.
 * @return Return code indicating success or failure.
 */
extern int commandline_early_options(int argc, char *argv[], commandline_usage_app_data_t* app_data);

/**
* @brief Retrieve the array of long options for command-line parsing.
*
* @return Pointer to the array of long options.
*/
extern const struct ws_option* commandline_long_options(void);

/**
 * @brief Returns a string containing all valid command-line options.
 *
 * @return A pointer to a static string containing the option string.
 */
extern const char* commandline_optstring(void);

/**
 * @brief Override preferences from command line arguments.
 *
 * @param argc Number of command line arguments.
 * @param argv Array of command line argument strings.
 * @param opt_reset Flag to reset the options parser.
 */
extern void commandline_override_prefs(int argc, char *argv[], bool opt_reset);

/**
 * @brief Process other command-line options.
 *
 * This function processes additional command-line options after epan_init() is called,
 * handling various capture and display preferences.
 *
 * @param capture_opts Capture options structure (unused).
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line argument strings.
 * @param app_data Application-specific data structure.
 * @param opt_reset Flag indicating whether to reset options.
 */
extern void commandline_other_options(capture_options* capture_opts, int argc, char *argv[], commandline_usage_app_data_t* app_data, bool opt_reset);

/**
 * @brief Drop command line options for a specific module and preference.
 *
 * @param module_name The name of the module.
 * @param pref_name The name of the preference.
 */
extern void commandline_options_drop(const char *module_name, const char *pref_name);

/**
 * @brief Reapply user-supplied command line options.
 *
 * This function iterates through a list of user options and applies them using the prefs_set_pref function.
 * It does not check the validity of these options again, assuming they were checked before being added to the list.
 */
extern void commandline_options_reapply(void);

/**
 * @brief Apply external capture options based on command line arguments.
 *
 * This function processes user-provided options related to external captures,
 * setting preferences accordingly. It skips processing if external captures are disabled.
 */
extern void commandline_options_apply_extcap(void);

/**
 * @brief Free command line options.
 *
 * This function frees all allocated memory for command line options.
 */
extern void commandline_options_free(void);

/**
 * @brief Checks if Wireshark is running in full screen mode.
 *
 * @return true if Wireshark is in full screen mode, false otherwise.
 */
extern bool commandline_is_full_screen(void);

/**
 * @brief Get the current capture file name.
 *
 * @return The name of the current capture file.
 */
extern char* commandline_get_cf_name(void);

/**
 * @brief Get the current read filter.
 *
 * @return The read filter string.
 */
extern char* commandline_get_rfilter(void);

/**
 * @brief Get the display filter from the commandline.
 *
 * @return The current display filter.
 */
extern char* commandline_get_dfilter(void);

/**
 * @brief Get the current jump filter.
 *
 * @return The jump filter as a string.
 */
extern char* commandline_get_jfilter(void);

 /**
  * @brief Get the jump direction from command line.
  *
  * @return The jump direction (forward or backward).
  */

extern search_direction commandline_get_jump_direction(void);

/**
* @brief Retrieves the packet number to which the user wants to jump.
*
* @return The packet number.
*/
extern uint32_t commandline_get_go_to_packet(void);

#ifdef HAVE_LIBPCAP
/**
 * @brief Get the capture queries specified on the command line.
 *
 * @return An integer representing the capture queries (bitmask).
 */
extern bool commandline_is_start_capture(void);

/**
 * @brief Check if the user specified the option to quit after capture.
 *
 * @return true if the user specified to quit after capture, false otherwise.
 */
extern bool commandline_is_quit_after_capture(void);

/**
 * @brief Get the first capture comment specified on the command line.
 *
 * @return A pointer to the first capture comment.
 */
extern char* commandline_get_first_capture_comment(void);

/**
 * @brief Get the capture queries specified on the command line.
 *
 * @return An integer representing the capture queries (bitmask).
 */
extern int commandline_get_caps_queries(void);

/**
 * @brief Get the array of capture comments specified on the command line.
 *
 * @return A pointer to the array of capture comments.
 */
extern GPtrArray* commandline_get_capture_comments(void);

#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __COMMANDLINE_H__ */
