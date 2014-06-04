/* compiled_filter_output.cpp
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


#include "ui_compiled_filter_output.h"
#include "compiled_filter_output.h"

#include "capture_opts.h"
#include "wtap.h"
#include <pcap.h>
#include "ui/capture_globals.h"

CompiledFilterOutput::CompiledFilterOutput(QWidget *parent, QStringList *intList, QString &compile_filter) :
    QDialog(parent),
    intList_(intList),
    compile_filter_(compile_filter),
    ui(new Ui::CompiledFilterOutput)
{
    ui->setupUi(this);

    interface_list_ = ui->interfaceList;
#if GLIB_CHECK_VERSION(2,31,0)
    pcap_compile_mtx = g_new(GMutex,1);
    g_mutex_init(pcap_compile_mtx);
#else
    pcap_compile_mtx = g_mutex_new();
#endif
    compileFilter();
    connect(interface_list_, SIGNAL(currentItemChanged(QListWidgetItem*, QListWidgetItem*)), this, SLOT(compile_clicked(QListWidgetItem*, QListWidgetItem*)));
}

CompiledFilterOutput::~CompiledFilterOutput()
{
    delete ui;
}


void CompiledFilterOutput::compileFilter()
{
    struct bpf_program fcode;

    foreach (QString interfaces, *intList_) {
        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            interface_t device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);

            if (interfaces.compare(device.display_name)) {
                continue;
            } else {
                pcap_t *pd = pcap_open_dead(device.active_dlt, WTAP_MAX_PACKET_SIZE);
                g_mutex_lock(pcap_compile_mtx);
                if (pcap_compile(pd, &fcode, compile_filter_.toUtf8().constData(), 1, 0) < 0) {
                    compile_results.insert(interfaces, QString("%1").arg(g_strdup(pcap_geterr(pd))));
                    g_mutex_unlock(pcap_compile_mtx);
                    ui->interfaceList->addItem(new QListWidgetItem(QIcon(":expert/expert_error.png"),interfaces));
                } else {
                    GString *bpf_code_dump = g_string_new("");
                    struct bpf_insn *insn = fcode.bf_insns;
                    int ii, n = fcode.bf_len;
                    gchar *bpf_code_str;
                    for (ii = 0; ii < n; ++insn, ++ii) {
                        g_string_append(bpf_code_dump, bpf_image(insn, ii));
                        g_string_append(bpf_code_dump, "\n");
                    }
                    bpf_code_str = g_string_free(bpf_code_dump, FALSE);
                    g_mutex_unlock(pcap_compile_mtx);
                    compile_results.insert(interfaces, QString("%1").arg(g_strdup(bpf_code_str)));
                    ui->interfaceList->addItem(new QListWidgetItem(QIcon(":expert/expert_ok.png"),interfaces));
                }
                break;
            }
        }
    }
}


void CompiledFilterOutput::compile_clicked(QListWidgetItem *current, QListWidgetItem *previous)
{
    Q_UNUSED(previous);

    QString interface = current->text();
    QHash<QString, QString>::const_iterator iter = compile_results.find(interface);
    ui->filterList->clear();
    ui->filterList->setText(iter.value());
}

//
// Editor modelines  -  http://www.wireshark.org/tools/modelines.html
//
// Local variables:
// c-basic-offset: 4
// tab-width: 4
// indent-tabs-mode: nil
// End:
//
// vi: set shiftwidth=4 tabstop=4 expandtab:
// :indentSize=4:tabSize=4:noTabs=true:
//
