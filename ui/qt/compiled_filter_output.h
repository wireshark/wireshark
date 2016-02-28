/* compiled_filter_output.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
    void compileFilter();

public:
    explicit CompiledFilterOutput(QWidget *parent = 0, QStringList &intList = *new QStringList(), QString &filter = *new QString());

    ~CompiledFilterOutput();

private slots:
    void on_interfaceList_currentItemChanged(QListWidgetItem *current, QListWidgetItem *previous);
    void copyFilterText();
};

#endif // COMPILEDFILTEROUTPUT_H

//
// Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
