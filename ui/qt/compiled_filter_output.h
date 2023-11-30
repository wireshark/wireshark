/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef COMPILEDFILTEROUTPUT_H
#define COMPILEDFILTEROUTPUT_H

#include "geometry_state_dialog.h"

#include <config.h>
#include <QList>
#include <QHash>
#include <QListWidgetItem>

#include <glib.h>

struct InterfaceFilter {
    InterfaceFilter(QString intf, QString filt) : interface(intf), filter(filt) {}

    QString interface;
    QString filter;
};

namespace Ui {
class CompiledFilterOutput;
}

class CompiledFilterOutput : public GeometryStateDialog
{
    Q_OBJECT

private:
    QList<InterfaceFilter> intList_;
    Ui::CompiledFilterOutput *ui;
    GMutex pcap_compile_mtx_;
    QHash<QString, QString> compile_results;
    QListWidget *interface_list_;
    QPushButton *copy_bt_;
#ifdef HAVE_LIBPCAP
    void compileFilter();
#endif

public:
    explicit CompiledFilterOutput(QWidget *parent = 0, QList<InterfaceFilter> &intList = *new QList<InterfaceFilter>());

    ~CompiledFilterOutput();

private slots:
    void on_interfaceList_currentItemChanged(QListWidgetItem *current, QListWidgetItem *previous);
    void copyFilterText();
};

#endif // COMPILEDFILTEROUTPUT_H
