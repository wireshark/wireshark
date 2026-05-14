/** @file
 *
 * Base function for extcaps
 *
 * Copyright 2016, Dario Lombardo
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __EXTCAP_BASE_H__
#define __EXTCAP_BASE_H__

#include <glib.h>
#include <glib/gprintf.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <wsutil/ws_getopt.h>

#ifdef _WIN32
#include <io.h>
#endif

#include <wsutil/socket.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define EXTCAP_BASE_OPTIONS_ENUM \
    EXTCAP_OPT_LIST_INTERFACES, \
    EXTCAP_OPT_VERSION, \
    EXTCAP_OPT_LIST_DLTS, \
    EXTCAP_OPT_INTERFACE, \
    EXTCAP_OPT_CONFIG, \
    EXTCAP_OPT_CONFIG_OPTION_NAME, \
    EXTCAP_OPT_CONFIG_OPTION_VALUE, \
    EXTCAP_OPT_CLEANUP_POSTKILL, \
    EXTCAP_OPT_CAPTURE, \
    EXTCAP_OPT_CAPTURE_FILTER, \
    EXTCAP_OPT_FIFO, \
    EXTCAP_OPT_LOG_LEVEL, \
    EXTCAP_OPT_LOG_FILE


#define EXTCAP_BASE_OPTIONS \
    { "extcap-interfaces", ws_no_argument, NULL, EXTCAP_OPT_LIST_INTERFACES}, \
    { "extcap-version", ws_optional_argument, NULL, EXTCAP_OPT_VERSION}, \
    { "extcap-dlts", ws_no_argument, NULL, EXTCAP_OPT_LIST_DLTS}, \
    { "extcap-interface", ws_required_argument, NULL, EXTCAP_OPT_INTERFACE}, \
    { "extcap-config", ws_no_argument, NULL, EXTCAP_OPT_CONFIG}, \
    { "extcap-config-option-name", ws_required_argument, NULL, EXTCAP_OPT_CONFIG_OPTION_NAME}, \
    { "extcap-config-option-value", ws_required_argument, NULL, EXTCAP_OPT_CONFIG_OPTION_VALUE }, \
    { "extcap-cleanup-postkill", ws_no_argument, NULL, EXTCAP_OPT_CLEANUP_POSTKILL }, \
    { "capture", ws_no_argument, NULL, EXTCAP_OPT_CAPTURE}, \
    { "extcap-capture-filter", ws_required_argument,    NULL, EXTCAP_OPT_CAPTURE_FILTER}, \
    { "fifo", ws_required_argument, NULL, EXTCAP_OPT_FIFO}, \
    { "log-level", ws_required_argument, NULL, EXTCAP_OPT_LOG_LEVEL}, \
    { "log-file", ws_required_argument, NULL, EXTCAP_OPT_LOG_FILE}

typedef struct _extcap_parameters
{
    char * exename;
    char * fifo;
    char * interface;
    char * capture_filter;

    char * version;
    char * compiled_with;
    char * running_with;
    char * helppage;
    uint8_t capture;
    uint8_t show_config;
    uint8_t show_config_option;
    char * config_option_name;
    char * config_option_value;

    char * ws_version;

    /* private content */
    GList * interfaces;
    uint8_t do_version;
    uint8_t do_list_dlts;
    uint8_t do_list_interfaces;
    uint8_t do_cleanup_postkill;

    char * help_header;
    GList * help_options;

    enum ws_log_level debug;

    void (*cleanup_postkill_cb)(void);
} extcap_parameters;

/**
 * @brief Flag indicating whether a graceful shutdown of the extcap application has been requested.
 *
 * This variable is set to true when a signal is received that indicates the application should exit gracefully.
 * The extcap application can check this flag periodically to determine if it should perform cleanup and exit.
 */
extern bool extcap_end_application;

/**
 * @brief Registers a basic interface with the extcap framework.
 *
 * @param extcap Pointer to the extcap parameters structure.
 * @param interface Name of the interface to register.
 * @param ifdescription Description of the interface.
 * @param dlt Data Link Type (DLT) for the interface.
 * @param dltdescription Description of the DLT.
 */
void extcap_base_register_interface(extcap_parameters * extcap, const char * interface, const char * ifdescription, uint16_t dlt, const char * dltdescription );

/**
 * @brief Registers an interface with extended information for the extcap framework.
 *
 * @param extcap Pointer to the extcap parameters structure.
 * @param interface Name of the interface to register.
 * @param ifdescription Description of the interface.
 * @param dlt Data Link Type (DLT) for the interface.
 * @param dltname Name of the DLT.
 * @param dltdescription Description of the DLT.
 */
void extcap_base_register_interface_ext(extcap_parameters * extcap, const char * interface, const char * ifdescription, uint16_t dlt, const char * dltname, const char * dltdescription );

/**
 * @brief Registers a callback function for graceful shutdown in the extcap framework.
 *
 * This function allows an extcap application to register a callback that will be called when a graceful shutdown is requested.
 * The callback can be used to perform any necessary cleanup before the application exits.
 *
 * @param extcap Pointer to the extcap parameters structure.
 * @param callback Function pointer to the callback function that will be called on graceful shutdown.
 * @return true if the callback was successfully registered, false otherwise.
 */
bool extcap_base_register_graceful_shutdown_cb(extcap_parameters * extcap, void (*callback)(void));

/**
 * @brief Registers a callback function to be called after the extcap application is killed.
 *
 * This function allows an extcap application to register a callback that will be called after the application has been terminated.
 * This can be useful for performing cleanup tasks that need to occur after the application has been killed.
 *
 * @param extcap Pointer to the extcap parameters structure.
 * @param callback Function pointer to the callback function that will be called post-kill.
 * @return true if the callback was successfully registered, false otherwise.
 */
bool extcap_base_register_cleanup_postkill_cb(extcap_parameters* extcap, void (*callback)(void));

/**
 * @brief Set the version and help page information for an extcap utility.
 *
 * @param extcap    The extcap parameter block to populate.
 * @param exename   The full path or name of the extcap executable. Only the
 *                  basename is stored (path components are stripped).
 * @param major     The major version number string (must not be NULL).
 * @param minor     The minor version number string, or NULL if not applicable.
 * @param release   The release/patch version number string, or NULL if not
 *                  applicable.
 * @param helppage  URL of the online help page for this extcap utility, or
 *                  NULL if no help page is available.
 */
void extcap_base_set_util_info(extcap_parameters * extcap, const char * exename, const char * major, const char * minor, const char * release, const char * helppage);

/**
 * @brief Set the "compiled with" information string for an extcap utility.
 *
 * @param extcap The extcap parameter block to populate.
 * @param fmt    A printf-style format string describing compiled-with
 *               dependencies.
 * @param ...    Arguments for the format string.
 */
void extcap_base_set_compiled_with(extcap_parameters * extcap, const char *fmt, ...);

/**
 * @brief Set the running_with field of extcap_parameters with a formatted string.
 *
 * @param extcap Pointer to the extcap_parameters structure.
 * @param fmt Format string for the message.
 * @param ... Additional arguments for the format string.
 */
void extcap_base_set_running_with(extcap_parameters * extcap, const char *fmt, ...);

/**
 * @brief Parses options for an extcap tool.
 *
 * @param extcap Pointer to the extcap_parameters structure.
 * @param result The result of option parsing.
 * @param optargument The argument associated with the option.
 * @return 1 if successful, 0 otherwise.
 */
uint8_t extcap_base_parse_options(extcap_parameters * extcap, int result, char * optargument);

/**
 * @brief Handle interface operations based on provided parameters.
 *
 * This function processes various interface-related operations such as capturing,
 * listing interfaces, and handling cleanup based on the settings in the extcap_parameters structure.
 *
 * @param extcap Pointer to the extcap_parameters structure containing configuration details.
 * @return 1 if successful, 0 otherwise.
 */
uint8_t extcap_base_handle_interface(extcap_parameters * extcap);

/**
 * @brief Cleans up and frees memory allocated for extcap parameters.
 *
 * @param extcap Pointer to a pointer to extcap_parameters structure to be cleaned up.
 */
void extcap_base_cleanup(extcap_parameters ** extcap);

/**
 * @brief Adds a header to the help text.
 *
 * @param extcap Pointer to the extcap_parameters structure.
 * @param help_header The header text to add.
 */
void extcap_help_add_header(extcap_parameters * extcap, char * help_header);

/**
 * @brief Adds a help option to the extcap parameters.
 *
 * @param extcap Pointer to the extcap_parameters structure.
 * @param help_option_name Name of the help option.
 * @param help_option_desc Description of the help option.
 */
void extcap_help_add_option(extcap_parameters * extcap, const char * help_option_name, const char * help_option_desc);

/**
 * @brief Print the version information of an extcap tool.
 *
 * @param extcap Pointer to the extcap_parameters structure containing the tool's name and version.
 */
void extcap_version_print(extcap_parameters * extcap);

/**
 * @brief Print help information for extcap.
 *
 * @param extcap Pointer to the extcap_parameters structure containing help information.
 */
void extcap_help_print(extcap_parameters * extcap);

/**
 * @brief Log the command line arguments for debugging purposes.
 *
 * Constructs a string from the provided array of command line arguments and logs it using ws_debug().
 *
 * @param ar Array of command line arguments.
 * @param n Number of elements in the array.
 */
void extcap_cmdline_debug(char** ar, const unsigned n);

/**
 * @brief Initialize logging for extcap.
 *
 * Initializes the logging system used by extcap to handle messages and warnings.
 */
void extcap_config_debug(unsigned* count);

/**
 * @brief Display help information for extcap.
 *
 * Outputs usage instructions and available options for extcap to stdout.
 */
void extcap_base_help(void);

/**
 * @brief Initialize logging for extcap.
 *
 * Initializes the logging system for extcap, setting up a console writer to use stdout and
 * logging an initialization message.
 */
void extcap_log_init(void);

/**
 * @brief Logs a command argument error message.
 *
 * @param msg_format The format string for the error message.
 * @param ap The variable arguments list for the format string.
 */
void extcap_log_cmdarg_err(const char *msg_format, va_list ap);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // __EXTCAP_BASE_H__

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
