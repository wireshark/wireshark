/* compiled_filter_output.h
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

namespace Ui {
class CompiledFilterOutput;
}

class CompiledFilterOutput : public GeometryStateDialog
{
    Q_OBJECT

private:
    QStringList intList_;
    QString &compile_filter_;
    Ui::CompiledFilterOutput *ui;
    GMutex *pcap_compile_mtx;
    QHash<QString, QString> compile_results;
    QListWidget *interface_list_;
    QPushButton *copy_bt_;
#ifdef HAVE_LIBPCAP
    void compileFilter();
#endif

public:
    explicit CompiledFilterOutput(QWidget *parent = 0, QStringList &intList = *new QStringList(), QString &filter = *new QString());

    ~CompiledFilterOutput();

private slots:
    void on_interfaceList_currentItemChanged(QListWidgetItem *current, QListWidgetItem *previous);
    void copyFilterText();
};

#endif // COMPILEDFILTEROUTPUT_H

//
// Editor modelines  -  https://www.wireshark.org/tools/modelines.html
//
// Local variables:
// c-basic-offset: 4
// tab-width: 8
// indent-tabs-mode: nil
// End:
//
// vi: set shiftwidth=4 tabstop=8 expandtab:
// :indentSize=4:tabSize=8:noTabs=true:
//
