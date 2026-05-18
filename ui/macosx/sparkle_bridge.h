/** @file
 *
 * C wrapper for the macOS Sparkle update framework.
 *
 * Sparkle (https://sparkle-project.org/) is the standard macOS framework for
 * automatic software updates, similar to WinSparkle on Windows.  Its native
 * API is Objective-C / Swift, so this thin C bridge exposes the two operations
 * Wireshark needs — initialize and check-for-updates — as plain C functions
 * that can be called from the platform-independent C++ code in software_update.cpp.
 *
 * The corresponding implementation lives in sparkle_bridge.m (Objective-C).
 * ".m" files are the Objective-C equivalent of ".cpp" files; CMake compiles
 * them with the Objective-C compiler on macOS automatically.
 *
 * Why a bridge?  Qt/C++ code cannot directly call Objective-C APIs.  This
 * header provides a C linkage boundary so that software_update.cpp can call
 * into the Sparkle framework without knowing any Objective-C specifics.
 * A similar pattern is used on Windows with the WinSparkle C API.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

// XXX We could alternatively do this via C++:
// https://github.com/sparkle-project/Sparkle/issues/1137


#ifndef SPARKLE_BRIDGE_H
#define SPARKLE_BRIDGE_H

/**
 * Callback invoked when the user has engaged with the update alert
 * (clicked the gentle reminder, interacted with the Sparkle UI, etc.).
 * The callee should hide any custom reminder UI at this point.
 */
typedef void (*sparkle_update_attention_callback_t)(void);

// Callback invoked when Sparkle wants to relaunch for an update.
// The application should save all documents and perform cleanup.
// Call the provided proceed function pointer when ready.
typedef void (*sparkle_postpone_relaunch_callback_t)(void (*proceed)(void *ctx), void *ctx);

// Callback invoked right before the application is relaunched.
// Last-chance notification — cannot be vetoed.
typedef void (*sparkle_will_relaunch_callback_t)(void);

/**
 * @brief C++ wrapper for the Sparkle update framework.
 */
class SparkleBridge
{
    /**
     * @brief Constructor for the SparkleBridge class.
     */
    SparkleBridge() {}

public:

    /**
     * Initialize the Sparkle update subsystem.
     *
     * Must be called once at application startup (from software_update_init()).
     * Sets the appcast feed URL, whether automatic background checks are enabled,
     * and the interval between automatic checks.
     *
     * Internally this creates a singleton SPUStandardUpdaterController — the
     * Sparkle 2 equivalent of the deprecated SUUpdater sharedUpdater from
     * Sparkle 1.  The singleton ensures that only one updater instance exists
     * for the lifetime of the application.
     *
     * @param url       Appcast feed URL (an XML file describing available updates).
     *                  Built by get_appcast_update_url() in software_update.c.
     * @param enabled   Whether to check for updates automatically in the background.
     *                  Maps to the Wireshark preference "gui.update.enabled".
     * @param interval  Seconds between automatic update checks.
     *                  Maps to the Wireshark preference "gui.update.interval".
     */
    static void updateInit(const char *url, bool enabled, int interval);

    /**
     * Trigger an immediate, user-initiated update check.
     *
     * Called when the user selects "Check for Updates…" from the Help menu.
     * Sparkle shows its own native macOS UI (progress sheet, release notes,
     * install prompt) — no additional Qt UI is needed.
     */
    static void updateCheck();

    /**
     * Register callbacks for Sparkle
     *
     * All callbacks are invoked on the main thread.  Any of them may be NULL
     * to ignore that particular event.
     *
     * @param attention_cb Called when the user has engaged with the update.
     * @param postpone_relaunch_cb Called when the update is ready for the app to handle any pre-relaunch tasks (e.g. saving documents). The app should perform the tasks, then call the provided proceed() function pointer to allow Sparkle to continue with the relaunch.
     * @param will_relaunch_cb Called when the app is about to be relaunched.
     */
    static void setUpdateCallbacks(
        sparkle_update_attention_callback_t attention_cb,
        sparkle_postpone_relaunch_callback_t postpone_relaunch_cb,
        sparkle_will_relaunch_callback_t will_relaunch_cb);

};

#endif // SPARKLE_BRIDGE_H
