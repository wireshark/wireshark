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

/**
 * @brief An action to trigger the export of a specific object type from a capture file.
 */
class ExportObjectAction : public QAction
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new ExportObjectAction.
     * @param parent The parent QObject.
     * @param eo Pointer to the registered export object type (defaults to NULL).
     */
    ExportObjectAction(QObject *parent, register_eo_t *eo = NULL);

    /**
     * @brief Retrieves the associated export object type.
     * @return Pointer to the registered export object.
     */
    register_eo_t* exportObject() {return eo_;}

public slots:
    /**
     * @brief Handles capture file events to update the action's state.
     * @param e The capture file event to handle.
     */
    void captureFileEvent(CaptureEvent e);

private:
    /** Pointer to the registered export object type. */
    register_eo_t *eo_;
};

#endif // EXPORTOBJECTACTION_H
