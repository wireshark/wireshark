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
#include "cfile.h"

#include <QObject>
#include <QVector>

struct profile_switch_filter {
    QString name;
    dfilter_t *dfcode;
};

class PacketListModel;

class ProfileSwitcher : public QObject
{
    Q_OBJECT
public:
    explicit ProfileSwitcher(QObject *parent = nullptr);

public slots:
    void captureEventHandler(CaptureEvent ev);
    void checkPacket(capture_file *cap_file, frame_data *fdata, qsizetype row);

private:
    PacketListModel *packet_list_model_;
    QVector<struct profile_switch_filter> profile_filters_;
    bool capture_file_changed_;
    bool profile_changed_;
    QString previous_cap_file_;

    void clearProfileFilters();

private slots:
    void disableSwitching();
};
