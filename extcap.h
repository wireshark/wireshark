/** @file
 *
 * Definitions for extcap external capture
 * Copyright 2013, Mike Ryan <mikeryan@lacklustre.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __EXTCAP_H__
#define __EXTCAP_H__


#include <glib.h>

#ifdef _WIN32
#include <wsutil/unicode-utils.h>
#endif

#include <wsutil/plugins.h>

#include "capture/capture_session.h"
#include <ui/capture_ui_utils.h>

/* As boolean flags will be allowed any form of yes, true or any number != 0 (or starting with 0)
 * The regex will be matched case-insensitive, so only the lower-case is defined here. */
#define EXTCAP_BOOLEAN_REGEX "^.*([yt1-9])"

/* Prefix for the pipe interfaces */
#define EXTCAP_PIPE_PREFIX "wireshark_extcap"
#define EXTCAP_CONTROL_IN_PREFIX  "wireshark_control_ext_to_ws"
#define EXTCAP_CONTROL_OUT_PREFIX "wireshark_control_ws_to_ext"

#define EXTCAP_ARGUMENT_CONFIG                  "--extcap-config"
#define EXTCAP_ARGUMENT_RELOAD_OPTION           "--extcap-reload-option"
#define EXTCAP_ARGUMENT_LIST_INTERFACES         "--extcap-interfaces"
#define EXTCAP_ARGUMENT_INTERFACE               "--extcap-interface"
#define EXTCAP_ARGUMENT_LIST_DLTS               "--extcap-dlts"
#define EXTCAP_ARGUMENT_VERSION                 "--extcap-version"

#define EXTCAP_ARGUMENT_RUN_CAPTURE             "--capture"
#define EXTCAP_ARGUMENT_CAPTURE_FILTER          "--extcap-capture-filter"
#define EXTCAP_ARGUMENT_RUN_PIPE                "--fifo"
#define EXTCAP_ARGUMENT_CONTROL_IN              "--extcap-control-in"
#define EXTCAP_ARGUMENT_CONTROL_OUT             "--extcap-control-out"

typedef struct _extcap_info {
    gchar * basename;
    gchar * full_path;
    gchar * version;
    gchar * help;

    GList * interfaces;
} extcap_info;

typedef enum {
    EXTCAP_FILTER_UNKNOWN,
    EXTCAP_FILTER_VALID,
    EXTCAP_FILTER_INVALID
} extcap_filter_status;

struct _extcap_arg;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Registers preferences for all interfaces.
 * Initializes the extcap interface list if that hasn't already been done.
 */
void
extcap_register_preferences(void);

/**
 * Fetches the interface capabilities for the named extcap interface.
 * Initializes the extcap interface list if that hasn't already been done.
 * @param ifname The interface name.
 * @param err_str Set to NULL on success, error description on failure.
 * @return The interface capabilities on success, NULL on failure.
 */
if_capabilities_t *
extcap_get_if_dlts(const gchar * ifname, char ** err_str);

/**
 * Append a list of all extcap capture interfaces to the specified list.
 * Initializes the extcap interface list if that hasn't already been done.
 * @param list An existing GList of if_info_t.
 * @param err_str Set to NULL on success, error description on failure.
 * @return An updated list on success, an unchanged list on failure.
 */
GList *
append_extcap_interface_list(GList *list, char **err_str);

/**
 * Retrieves information about an extcap executable.
 * Initializes the extcap interface list if that hasn't already been done.
 * @param toolname The extcap name.
 * @return The extcap information on success, NULL on failure.
 */
extcap_info *
extcap_get_tool_info(const gchar * toolname);

/**
 * Retrieves information about an extcap interface.
 * Initializes the extcap interface list if that hasn't already been done.
 * @param ifname The extcap interface name.
 * @return The extcap information on success, NULL on failure.
 */
extcap_info *
extcap_get_tool_by_ifname(const gchar *ifname);

/**
 * Retrieves help information for an extcap interface.
 * Initializes the extcap interface list if that hasn't already been done.
 * @param ifname The extcap interface name.
 * @return A help string on success or NULL on failure.
 */
gchar *
extcap_get_help_for_ifname(const char *ifname);

/**
 * Remove all loaded extcap interfaces.
 */
void
extcap_clear_interfaces(void);

/**
 * Retrieves information about all available extcap executables.
 * Initializes the extcap interface list if that hasn't already been done.
 * @param callback The description callback routine.
 * @param callback_data Data to be passed to the callback routine.
 */
void
extcap_get_descriptions(plugin_description_callback callback, void *callback_data);

/**
 * Print information about all available extcap executables.
 * Initializes the extcap interface list if that hasn't already been done.
 */
void
extcap_dump_all(void);

/**
 * Returns the configuration for the given interface name, or an
 * empty list, if no configuration has been found.
 * Initializes the extcap interface list if that hasn't already been done.
 * @param ifname The interface name.
 */
GList *
extcap_get_if_configuration(const char * ifname);

/**
 * Returns the configuration values for the given argument, or an
 * empty list, if no values could been found.
 * Initializes the extcap interface list if that hasn't already been done.
 * @param ifname The interface name.
 * @param argname The name of the argument for which the values should be retrieved.
 */
GList *
extcap_get_if_configuration_values(const char * ifname, const char * argname, GHashTable * arguments);

/**
 * Check if the capture filter for the given interface name is valid.
 * Initializes the extcap interface list if that hasn't already been done.
 * @param ifname Interface to check
 * @param filter Capture filter to check
 * @param err_str Error string returned if filter is invalid
 * @return Filter check status.
 */
extcap_filter_status
extcap_verify_capture_filter(const char *ifname, const char *filter, gchar **err_str);

/**
 * Frees the memory from extcap_get_if_configuration.
 * @param list The list returned by extcap_get_if_configuration.
 * @param free_args TRUE if all arguments in the list must be freed too or FALSE
 * if the ownership of the arguments is taken by the caller.
 */
void
extcap_free_if_configuration(GList *list, gboolean free_args);

/**
 * Checks to see if an interface has configurable options.
 * If is_required is FALSE: returns TRUE if the extcap interface has
 * configurable options.
 * If is_required is TRUE: returns TRUE when the extcap interface has
 * configurable options that required modification. (For example, when an
 * argument is required but empty.)
 * Initializes the extcap interface list if that hasn't already been done.
 * @param ifname Interface to check.
 * @param is_required Required configuration flag.
 */
gboolean
extcap_has_configuration(const char * ifname, gboolean is_required);

/**
 * Checks to see if the interface has an associated toolbar.
 * Initializes the extcap interface list if that hasn't already been done.
 * @param ifname Interface to check.
 * @return TRUE if the interface has a toolbar, FALSE otherwise.
 */
gboolean
extcap_has_toolbar(const char *ifname);

#ifdef HAVE_LIBPCAP
/**
 * Cleanup after capture session.
 * @param cap_session Capture session.
 * @return TRUE if session can be stopped, FALSE if there are remaining tasks.
 */
gboolean
extcap_session_stop(capture_session *cap_session);

/**
 * Initializes each extcap interface with the supplied capture session.
 * Initializes the extcap interface list if that hasn't already been done.
 * @param cap_session Capture session.
 * @return TRUE on success, FALSE on failure.
 */
gboolean
extcap_init_interfaces(capture_session *cap_session);
#endif /* HAVE_LIBPCAP */

/**
 * Notify all extcaps that capture session should be stopped.
 * Forcefully stop session if extcaps do not finish before timeout.
 * @param cap_session Capture session.
 */
void
extcap_request_stop(capture_session *cap_session);

/**
 * Fetch an extcap preference for a given argument.
 * Initializes the extcap interface list if that hasn't already been done.
 * @param ifname The interface to check.
 * @param arg The command line argument to check.
 * @return The associated preference on success, NULL on failure.
 */
struct preference *
extcap_pref_for_argument(const gchar *ifname, struct _extcap_arg * arg);

/**
 * Clean up global extcap stuff on program exit.
 */
void extcap_cleanup(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

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
