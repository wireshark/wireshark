/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef IO_GRAPH_ACTION_H
#define IO_GRAPH_ACTION_H

#include <ui/qt/utils/field_information.h>
#include <ui/io_graph_item.h>

#include <QAction>

class IOGraphAction : public QAction
{
    Q_OBJECT
public:
    explicit IOGraphAction(QObject *parent, io_graph_item_unit_t unit = IOG_ITEM_UNIT_PACKETS, QString field = QString());
    explicit IOGraphAction(QObject *parent);

    io_graph_item_unit_t unit() const { return unit_; }

    QString valueField() const { return field_; }

    static const QString unitName(io_graph_item_unit_t unit);

    static QList<io_graph_item_unit_t> unitTypes(const FieldInformation::HeaderInfo& headerinfo);
    static QMenu * createMenu(const FieldInformation::HeaderInfo& headerinfo, QWidget * parent);

signals:
    void openIOGraphDialog(io_graph_item_unit_t, QString);

public slots:

private:
    io_graph_item_unit_t unit_;
    QString field_;

private slots:

};

#endif // IO_GRAPH_ACTION_H
