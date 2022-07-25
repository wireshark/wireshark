/* software_update.h
 * Wrappers and routines to check for software updates.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "software_update.h"
#include "language.h"
#include "../epan/prefs.h"
#include "../wsutil/filesystem.h"

/*
 * Version 0 of the update URI path has the following elements:
 * - The update path prefix (fixed, "update")
 * - The schema version (fixed, 0)
 * - The application name (variable, "Wireshark" or "Logray")
 * - The application version ("<major>.<minor>.<micro>")
 * - The operating system (variable, one of "Windows" or "macOS")
 * - The architecture name (variable, one of "x86", "x86-64", or "arm64")
 * - The locale (fixed, "en-US")
 * - The update channel (variable, one of "development" or "stable") + .xml
 *
 * Based on https://wiki.mozilla.org/Software_Update:Checking_For_Updates
 *
 * To do for version 1:
 * - Distinguish between NSIS (.exe) and WiX (.msi) on Windows.
 */

#ifdef HAVE_SOFTWARE_UPDATE
#define SU_SCHEMA_PREFIX "update"
#define SU_SCHEMA_VERSION 0
#define SU_LOCALE "en-US"
#endif /* HAVE_SOFTWARE_UPDATE */

#ifdef HAVE_SOFTWARE_UPDATE

#include "glib.h"

#ifdef _WIN32
#include <winsparkle.h>
#define SU_OSNAME "Windows"
#elif defined(__APPLE__)
#include <macosx/sparkle_bridge.h>
#define SU_OSNAME "macOS"
#else
#error HAVE_SOFTWARE_UPDATE can only be defined for Windows or macOS.
#endif

// https://sourceforge.net/p/predef/wiki/Architectures/
#if defined(__x86_64__) || defined(_M_X64)
#define SU_ARCH "x86-64"
#elif defined(__i386__) || defined(_M_IX86)
#define SU_ARCH "x86"
#elif defined(__arm64__)
#define SU_ARCH "arm64"
#else
#error HAVE_SOFTWARE_UPDATE can only be defined for x86-64 or x86 or arm64.
#endif

static char *get_appcast_update_url(software_update_channel_e chan) {
    GString *update_url_str = g_string_new("");;
    const char *chan_name;
    const char *su_application = get_configuration_namespace();
    const char *su_version = VERSION;

    if (!is_packet_configuration_namespace()) {
        su_version = LOG_VERSION;
    }

    switch (chan) {
        case UPDATE_CHANNEL_DEVELOPMENT:
            chan_name = "development";
            break;
        default:
            chan_name = "stable";
            break;
    }
    g_string_printf(update_url_str, "https://www.wireshark.org/%s/%u/%s/%s/%s/%s/en-US/%s.xml",
                    SU_SCHEMA_PREFIX,
                    SU_SCHEMA_VERSION,
                    su_application,
                    su_version,
                    SU_OSNAME,
                    SU_ARCH,
                    chan_name);
    return g_string_free(update_url_str, FALSE);
}

#ifdef _WIN32
/** Initialize software updates.
 */
void
software_update_init(void) {
    const char *update_url = get_appcast_update_url(prefs.gui_update_channel);

    /*
     * According to the WinSparkle 0.5 documentation these must be called
     * once, before win_sparkle_init. We can't update them dynamically when
     * our preferences change.
     */
    win_sparkle_set_registry_path("Software\\Wireshark\\WinSparkle Settings");
    win_sparkle_set_appcast_url(update_url);
    win_sparkle_set_automatic_check_for_updates(prefs.gui_update_enabled ? 1 : 0);
    win_sparkle_set_update_check_interval(prefs.gui_update_interval);
    win_sparkle_set_can_shutdown_callback(software_update_can_shutdown_callback);
    win_sparkle_set_shutdown_request_callback(software_update_shutdown_request_callback);
    if ((language != NULL) && (strcmp(language, "system") != 0)) {
        win_sparkle_set_lang(language);
    }
    win_sparkle_init();
}

/** Force a software update check.
 */
void
software_update_check(void) {
    win_sparkle_check_update_with_ui();
}

/** Clean up software update checking.
 *
 * Does nothing on platforms that don't support software updates.
 */
extern void software_update_cleanup(void) {
    win_sparkle_cleanup();
}

const char *software_update_info(void) {
    return "WinSparkle " WIN_SPARKLE_VERSION_STRING;
}

#elif defined (__APPLE__)
/** Initialize software updates.
 */
void
software_update_init(void) {
    char *update_url = get_appcast_update_url(prefs.gui_update_channel);

    sparkle_software_update_init(update_url, prefs.gui_update_enabled, prefs.gui_update_interval);

    g_free(update_url);
}

/** Force a software update check.
 */
void
software_update_check(void) {
    sparkle_software_update_check();
}

/** Clean up software update checking.
 */
void software_update_cleanup(void) {
}

const char *software_update_info(void) {
    return "Sparkle";
}
#endif

#else /* No updates */

/** Initialize software updates.
 */
void
software_update_init(void) {
}

/** Force a software update check.
 */
void
software_update_check(void) {
}

/** Clean up software update checking.
 */
void software_update_cleanup(void) {
}

const char *software_update_info(void) {
    return NULL;
}

#endif /* defined(HAVE_SOFTWARE_UPDATE) && defined (_WIN32) */
