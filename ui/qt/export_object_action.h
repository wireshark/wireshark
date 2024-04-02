/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef EXPORTOBJECTACTION_H
#define EXPORTOBJECTACTION_H

#include "config.h"

#include <epan/packet_info.h>
#include <epan/export_object.h>

#include <QAction>

#include <ui/qt/capture_file.h>

// Actions for "Export Objects" menu items.

class ExportObjectAction : public QAction
{
    Q_OBJECT
public:
    ExportObjectAction(QObject *parent, register_eo_t *eo = NULL);

    register_eo_t* exportObject() {return eo_;}

public slots:
    void captureFileEvent(CaptureEvent e);

private:
    register_eo_t *eo_;
};

#endif // EXPORTOBJECTACTION_H
