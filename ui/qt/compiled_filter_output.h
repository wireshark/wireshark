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

#include <capture/capture_ifinfo.h>

#include <QList>
#include <QHash>
#include <QListWidgetItem>

struct InterfaceFilter {
    InterfaceFilter(QString dev_name, interface_type type, QString disp_name, QString filt, int link = -1) : device_name(dev_name), iftype(type), display_name(disp_name), filter(filt), linktype(link) {}
    InterfaceFilter(QString dev_name, interface_type type, QString disp_name, QString filt, QVariant link) : device_name(dev_name), iftype(type), display_name(disp_name), filter(filt)
    {
        bool ok;
        linktype = link.toInt(&ok);
        if (!ok) {
            linktype = -1;
        }
    }

    QString device_name;
    interface_type iftype;
    QString display_name;
    QString filter;
    int linktype;
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
    QHash<QString, QString> compile_results;
    QPushButton *copy_bt_;
    void setTitle();
#ifdef HAVE_LIBPCAP
    bool compileFilter(const InterfaceFilter &filter);
    void compileFilters();
#endif

public:
    explicit CompiledFilterOutput(QWidget *parent = 0, QList<InterfaceFilter> &intList = *new QList<InterfaceFilter>());

    ~CompiledFilterOutput();

private slots:
    void on_interfaceList_currentItemChanged(QListWidgetItem *current, QListWidgetItem *previous);
    void copyFilterText();
};

#endif // COMPILEDFILTEROUTPUT_H
