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

typedef struct interface_tag interface_t;
typedef QList<interface_t *> InterfaceList;

namespace Ui {
class CompiledFilterOutput;
}

class CompiledFilterOutput : public GeometryStateDialog
{
    Q_OBJECT

private:
    InterfaceList intList_;
    Ui::CompiledFilterOutput *ui;
    QHash<QString, QString> compile_results;
    QPushButton *copy_bt_;
    void setTitle();
#ifdef HAVE_LIBPCAP
    bool compileFilter(const interface_t *interface);
    void compileFilters();
#endif

public:
    explicit CompiledFilterOutput(QWidget *parent = 0, InterfaceList &intList = *new InterfaceList());

    ~CompiledFilterOutput();

private slots:
    void on_interfaceList_currentItemChanged(QListWidgetItem *current, QListWidgetItem *previous);
    void copyFilterText();
};

#endif // COMPILEDFILTEROUTPUT_H
