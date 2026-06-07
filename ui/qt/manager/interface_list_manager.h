/** @file
 *
 * Coordinates local interface enumeration: a single, coalesced, capture-aware
 * refresh entry point that repopulates the global interface list.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef INTERFACE_LIST_MANAGER_H
#define INTERFACE_LIST_MANAGER_H

#include <config.h>

#ifdef HAVE_LIBPCAP
#include <glib.h>
#endif

#include <QObject>
#include <QStringList>

class InterfaceStatistics;

/**
 * @brief GUI-thread coordinator for local interface enumeration and statistics.
 *
 * Replaces the scattered MainApplication::refreshLocalInterfaces /
 * scanLocalInterfaces path (and its eight ad-hoc callers) with one well-defined
 * entry point, requestRefresh(), that:
 *  - never runs the scan inline in the caller's stack (it is posted to the event
 *    loop), so callers cannot re-enter the scan or read a half-updated list;
 *  - coalesces a burst of requests into a single scan;
 *  - defers scanning while a capture is active and runs the pending request once
 *    the capture finishes;
 *  - serializes scans (one at a time).
 *
 * The enumeration itself runs on the GUI thread because it repopulates the
 * process-global global_capture_opts.all_ifaces that the rest of the GUI reads
 * directly. It omits the event-loop-pumping update callback (re-entrancy is
 * impossible); moving enumeration off the GUI thread is a future step (blocked on
 * all_ifaces being GUI-global) and is noted at the call site.
 *
 * The manager owns the live InterfaceStatistics, analogous to a view's default
 * model: a statistics object is always paired with a manager. The manager creates
 * it and hands out the reference via statistics(); it also drives it directly
 * (pruning removed interfaces, resetting activity on a user refresh, and pausing
 * sampling while a capture is active), so consumers and the window never wire the
 * manager to the statistics themselves. The only outward signal is
 * interfaceListChanged(), a UI notification that the list is stable.
 */
class InterfaceListManager : public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Constructs an idle manager.
     * @param parent Optional parent QObject.
     */
    explicit InterfaceListManager(QObject *parent = nullptr);

    /**
     * @brief Interface names from the most recent completed scan.
     * @return The current interface names.
     */
    QStringList currentInterfaceNames() const;

    /** @brief Whether a scan is currently in progress. */
    bool isScanning() const;

    /**
     * @brief Returns the live interface statistics owned by this manager.
     * @return Pointer to the InterfaceStatistics (never null).
     */
    InterfaceStatistics *statistics() const;

#ifdef HAVE_LIBPCAP
    /**
     * @brief Provides the cached local interface list for capture_opts.
     *
     * Registered in main() as capture_opts' get_iface_list callback, so the C
     * capture layer (scan_local_interfaces, numeric/name -i resolution, the -D
     * listing) pulls interfaces through here instead of re-spawning dumpcap on
     * every lookup. The list is enumerated once on first use and cached. The
     * cache is process-static rather than instance state because the callback can
     * fire during commandline parsing, before the GUI (and any manager) exists.
     *
     * NOTE: this enumerates via dumpcap (capture_interface_list). A flavor that
     * captures extcap-only (Stratoshark) must not use it and registers its own
     * callback; teaching the manager about that flavor split is a future step.
     *
     * @param err Set to the capture_interface_list() error code on failure.
     * @param err_str Set to an allocated error string on failure; caller frees.
     * @return A deep copy of the cached list (if_info_t), owned by the caller and
     *         freed with free_interface_list(); NULL on error/empty.
     */
    static GList *cachedInterfaceList(int *err, char **err_str);

    /**
     * @brief Warms the cache with a deep copy of an already-enumerated list.
     *
     * Lets a scan that just produced a fresh list seed the cache so the next
     * cachedInterfaceList() does not re-enumerate. The caller retains ownership
     * of @p if_list.
     * @param if_list The interface list to cache.
     */
    static void cacheInterfaceList(GList *if_list);
#endif

public slots:
    /**
     * @brief Requests a (coalesced, deferred-if-capturing) interface rescan.
     *
     * Safe to call from anywhere and as often as needed; the scan runs once,
     * asynchronously, off the caller's stack.
     * @param userInitiated true if a user explicitly asked to refresh; this
     *        additionally resets the statistics' activity so a now-quiet
     *        interface can be re-evaluated.
     */
    void requestRefresh(bool userInitiated = false);

    /**
     * @brief Performs an interface rescan synchronously, before returning.
     *
     * For the few contexts that need global_capture_opts.all_ifaces populated
     * immediately rather than on the next event-loop turn - notably startup
     * commandline resolution (-i / capture_device) which runs before the Qt
     * event loop starts. Honors the capture-active guard (no scan while
     * capturing). Prefer requestRefresh() everywhere else.
     */
    void refreshNow();

    /**
     * @brief Announces that the interface list changed without re-enumerating.
     *
     * For edits to already-enumerated interfaces (hide/comment/add/remove a
     * pipe or extcap, or a profile switch that only changes display attributes)
     * where a full rescan is unwanted - just emits interfaceListChanged() so
     * subscribers re-read global_capture_opts.all_ifaces.
     */
    void notifyListChanged();

    /**
     * @brief Re-derives interface display attributes from preferences, in place.
     *
     * Re-applies the per-interface display name, hidden flag and link type from
     * the current preferences over the existing global_capture_opts.all_ifaces,
     * without re-enumerating via dumpcap. Runs synchronously (see the
     * implementation comment): it is the profile-switch reapply that must finish
     * before MainApplication::setConfigurationProfile() emits preferencesChanged().
     * Everywhere else prefer the asynchronous requestRefresh().
     */
    void reapplyInterfacePreferences();

    /**
     * @brief Tells the manager whether a capture is active.
     *
     * While active, refresh requests are deferred and the statistics' sampling is
     * paused; on the transition back to inactive sampling resumes and any pending
     * request is serviced.
     * @param active true if a capture is currently running.
     */
    void setCaptureActive(bool active);

signals:
    /** @brief Emitted once after a scan, when the interface list is stable. */
    void interfaceListChanged();

private slots:
    /** @brief Performs the actual enumeration; invoked via the event loop. */
    void performScan();

    /**
     * @brief Reacts to a preferences change: rescans if a capture-interface pref
     *        (capture_no_interface_load / capture_no_extcap) actually flipped.
     */
    void onPreferencesChanged();

private:
    /** @brief Posts a single performScan() if one is warranted and not pending. */
    void maybeSchedule();

    InterfaceStatistics *interface_stats_; /**< Owned; created in the ctor. */
    QStringList currentNames_;     /**< Names from the last completed scan. */
    bool scanning_;                /**< True while performScan() runs. */
    bool refreshPending_;          /**< A refresh has been requested, unserviced. */
    bool pendingUserInitiated_;    /**< Any pending request was user-initiated. */
    bool captureActive_;           /**< Scans deferred while true. */
    bool scanScheduled_;           /**< A performScan() is already posted. */
    bool prevCaptureNoInterfaceLoad_; /**< Last-seen prefs.capture_no_interface_load. */
    bool prevCaptureNoExtcap_;        /**< Last-seen prefs.capture_no_extcap. */
};

#endif // INTERFACE_LIST_MANAGER_H
