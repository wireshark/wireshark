/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <config.h>

#include "capture_event.h"
#include <epan/cfile.h>

#include <QObject>
#include <QVector>

/**
 * @brief Associates a configuration profile name with a compiled display-filter
 *        program used to trigger an automatic profile switch.
 */
struct profile_switch_filter {
    QString    name;   /**< Name of the configuration profile to switch to. */
    dfilter_t *dfcode; /**< Compiled display-filter program that, when matched, triggers the switch. */
};


class PacketListModel;


/**
 * @brief Monitors incoming packets and automatically switches the active
 *        configuration profile when a packet matches a profile's trigger filter.
 */
class ProfileSwitcher : public QObject
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a ProfileSwitcher with no active filters.
     * @param parent Optional parent QObject.
     */
    explicit ProfileSwitcher(QObject *parent = nullptr);

public slots:
    /**
     * @brief Handles capture lifecycle events (e.g. file open/close, capture start/stop)
     *        and updates internal state to reflect whether switching is appropriate.
     * @param ev The capture event to process.
     */
    void captureEventHandler(CaptureEvent ev);

    /**
     * @brief Evaluates a single packet against all registered profile filters and
     *        switches the active profile if a match is found.
     * @param cap_file Capture file that owns the packet.
     * @param fdata    Frame metadata for the packet to evaluate.
     * @param row      Row index of the packet in the packet list model.
     */
    void checkPacket(capture_file *cap_file, frame_data *fdata, qsizetype row);

private:
    QVector<struct profile_switch_filter> profile_filters_; /**< Ordered list of profile trigger filters loaded from configuration. */
    bool    capture_file_changed_; /**< @c true when the active capture file has changed since the last check. */
    bool    profile_changed_;      /**< @c true when the active configuration profile has changed since the last check. */
    QString previous_cap_file_;    /**< Path or name of the capture file active before the most recent file change. */

    /**
     * @brief Frees all compiled display-filter programs and empties @c profile_filters_.
     */
    void clearProfileFilters();

private slots:
    /**
     * @brief Disables automatic profile switching, e.g. after a manual profile
     *        change or when switching would be unsafe.
     */
    void disableSwitching();
};
