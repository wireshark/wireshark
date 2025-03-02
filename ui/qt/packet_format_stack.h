/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef PACKET_FORMAT_STACK_H
#define PACKET_FORMAT_STACK_H

#include "file.h"
#include "ui/file_dialog.h"

#include <QStackedWidget>
#include <QMap>

class PacketFormatStack : public QStackedWidget
{
    Q_OBJECT

public:
    explicit PacketFormatStack(QWidget *parent = 0);
    ~PacketFormatStack();

    void setExportType(export_type_e type);
    bool isValid() const;
    void updatePrintArgs(print_args_t& print_args);

signals:
    void formatChanged();

private:
    QMap<export_type_e, int> export_type_map_;
    int blank_idx_;
};

#endif // PACKET_FORMAT_STACK_H
