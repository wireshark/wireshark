/* compiled_filter_output.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui_compiled_filter_output.h>
#include "compiled_filter_output.h"

#ifdef HAVE_LIBPCAP
#include "wspcap.h"
#endif

#include "capture_opts.h"
#include <wiretap/wtap.h>
#include "ui/capture_globals.h"

#include "wireshark_application.h"

#include <QClipboard>
#include <QPushButton>

CompiledFilterOutput::CompiledFilterOutput(QWidget *parent, QStringList &intList, QString &compile_filter) :
    GeometryStateDialog(parent),
    intList_(intList),
    compile_filter_(compile_filter),
    ui(new Ui::CompiledFilterOutput)
{
    ui->setupUi(this);
    loadGeometry();
    setAttribute(Qt::WA_DeleteOnClose, true);
    ui->filterList->setCurrentFont(wsApp->monospaceFont());

    copy_bt_ = ui->buttonBox->addButton(tr("Copy"), QDialogButtonBox::ActionRole);
    copy_bt_->setToolTip(tr("Copy filter text to the clipboard."));
    connect(copy_bt_, SIGNAL(clicked()), this, SLOT(copyFilterText()));

    QPushButton *close_bt = ui->buttonBox->button(QDialogButtonBox::Close);
    close_bt->setDefault(true);

    interface_list_ = ui->interfaceList;
    pcap_compile_mtx = g_new(GMutex,1);
    g_mutex_init(pcap_compile_mtx);
#ifdef HAVE_LIBPCAP
    compileFilter();
#endif
}

CompiledFilterOutput::~CompiledFilterOutput()
{
    // For some reason closing this dialog either lowers the Capture Options dialog
    // or raises the main window. Work around the problem for now by manually raising
    // and activating our parent (presumably the Capture Options dialog).
    if (parentWidget()) {
        parentWidget()->raise();
        parentWidget()->activateWindow();
    }
    delete ui;
}

#ifdef HAVE_LIBPCAP
void CompiledFilterOutput::compileFilter()
{
    struct bpf_program fcode;

    foreach (QString interfaces, intList_) {
        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);

            if (interfaces.compare(device->display_name)) {
                continue;
            } else {
                pcap_t *pd = pcap_open_dead(device->active_dlt, WTAP_MAX_PACKET_SIZE_STANDARD);
                if (pd == NULL)
                    break;
                g_mutex_lock(pcap_compile_mtx);
                if (pcap_compile(pd, &fcode, compile_filter_.toUtf8().data(), 1, 0) < 0) {
                    compile_results.insert(interfaces, QString(pcap_geterr(pd)));
                    g_mutex_unlock(pcap_compile_mtx);
                    ui->interfaceList->addItem(new QListWidgetItem(QIcon(":expert/expert_error.png"),interfaces));
                } else {
                    GString *bpf_code_dump = g_string_new("");
                    struct bpf_insn *insn = fcode.bf_insns;
                    int ii, n = fcode.bf_len;
                    for (ii = 0; ii < n; ++insn, ++ii) {
                        g_string_append(bpf_code_dump, bpf_image(insn, ii));
                        g_string_append(bpf_code_dump, "\n");
                    }
                    g_mutex_unlock(pcap_compile_mtx);
                    compile_results.insert(interfaces, QString(bpf_code_dump->str));
                    g_string_free(bpf_code_dump, TRUE);
                    ui->interfaceList->addItem(new QListWidgetItem(interfaces));
                }
                break;
            }
        }
    }
}
#endif

void CompiledFilterOutput::on_interfaceList_currentItemChanged(QListWidgetItem *current, QListWidgetItem *)
{
    QString interface = current->text();
    QHash<QString, QString>::const_iterator iter = compile_results.find(interface);
    ui->filterList->clear();
    ui->filterList->setPlainText(iter.value());
}

void CompiledFilterOutput::copyFilterText()
{
    wsApp->clipboard()->setText(ui->filterList->toPlainText());
}

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
