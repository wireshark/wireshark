/* @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "io_graph_action.h"

#include <ui/qt/main_application.h>
#include <ui/qt/main_window.h>
#include <ui/qt/io_graph_dialog.h>
#include <ui/qt/utils/field_information.h>

#include <ui/io_graph_item.h>

#include <wsutil/filesystem.h>

#include <QMenu>

IOGraphAction::IOGraphAction(QObject *parent, io_graph_item_unit_t unit, QString field) :
    QAction(parent),
    unit_(unit),
    field_(field)
{
    setText(unitName(unit));
    connect(this, &QAction::triggered, [&](){ emit openIOGraphDialog(unit_, field_); });
}

const QString IOGraphAction::unitName(io_graph_item_unit_t unit) {
    switch (unit) {
    case IOG_ITEM_UNIT_PACKETS:
        if (is_packet_configuration_namespace()) {
            return QObject::tr("PACKETS");
        }
        return QObject::tr("EVENTS");
    case IOG_ITEM_UNIT_BYTES:
        return QObject::tr("BYTES");
    case IOG_ITEM_UNIT_BITS:
        return QObject::tr("BITS");
    case IOG_ITEM_UNIT_CALC_FRAMES:
        return QObject::tr("COUNT FRAMES");
    case IOG_ITEM_UNIT_CALC_FIELDS:
        return QObject::tr("COUNT FIELDS");
    case IOG_ITEM_UNIT_CALC_SUM:
        return QObject::tr("SUM");
    case IOG_ITEM_UNIT_CALC_MAX:
        return QObject::tr("MAX");
    case IOG_ITEM_UNIT_CALC_MIN:
        return QObject::tr("MIN");
    case IOG_ITEM_UNIT_CALC_AVERAGE:
        return QObject::tr("AVERAGE");
    case IOG_ITEM_UNIT_CALC_THROUGHPUT:
        return QObject::tr("THROUGHPUT");
    case IOG_ITEM_UNIT_CALC_LOAD:
        return QObject::tr("LOAD");
    default:
        return QObject::tr("UNKNOWN");
    }
}

QList<io_graph_item_unit_t> IOGraphAction::unitTypes(const FieldInformation::HeaderInfo& headerinfo)
{
    static const QList<io_graph_item_unit_t> simple_types_ = QList<io_graph_item_unit_t>()
        << IOG_ITEM_UNIT_CALC_FRAMES
        << IOG_ITEM_UNIT_CALC_FIELDS;

    static const QList<io_graph_item_unit_t> number_types_ = QList<io_graph_item_unit_t>()
        << IOG_ITEM_UNIT_CALC_SUM
        << IOG_ITEM_UNIT_CALC_FRAMES
        << IOG_ITEM_UNIT_CALC_FIELDS
        << IOG_ITEM_UNIT_CALC_MAX
        << IOG_ITEM_UNIT_CALC_MIN
        << IOG_ITEM_UNIT_CALC_THROUGHPUT
        << IOG_ITEM_UNIT_CALC_AVERAGE;

    static const QList<io_graph_item_unit_t> time_types_ = QList<io_graph_item_unit_t>(number_types_)
        << IOG_ITEM_UNIT_CALC_LOAD;

    switch (headerinfo.type) {
    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
    case FT_UINT64:
    case FT_INT8:
    case FT_INT16:
    case FT_INT24:
    case FT_INT32:
    case FT_INT64:
    case FT_FLOAT:
    case FT_DOUBLE:
        return number_types_;
    case FT_RELATIVE_TIME:
        return time_types_;
    default:
        return simple_types_;
    }
}

QMenu * IOGraphAction::createMenu(const FieldInformation::HeaderInfo& headerinfo, QWidget * parent)
{
    MainWindow *mw(nullptr);
    if (mainApp)
    {
        QWidget * mainWin = mainApp->mainWindow();
        if (qobject_cast<MainWindow *>(mainWin)) {
            mw = qobject_cast<MainWindow *>(mainWin);
        }
    }

    QString title("I/O Graph");
    QMenu * submenu = new QMenu(title, parent);

    int one_em = submenu->fontMetrics().height();
    QString prep_text = QString("%1: %2").arg(title).arg(headerinfo.abbreviation);
    prep_text = submenu->fontMetrics().elidedText(prep_text, Qt::ElideRight, one_em * 40);
    QAction * comment = submenu->addAction(prep_text);
    comment->setEnabled(false);
    submenu->addSeparator();

    IOGraphAction *graphAction;
    for (const auto &unit : IOGraphAction::unitTypes(headerinfo)) {
        graphAction = new IOGraphAction(submenu, unit, headerinfo.abbreviation);
        if (mw) {
                connect(graphAction, &IOGraphAction::openIOGraphDialog, mw, &MainWindow::showIOGraphDialog);
        }
        submenu->addAction(graphAction);
    }

    return submenu;
}
