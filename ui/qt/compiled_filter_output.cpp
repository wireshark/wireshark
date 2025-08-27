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
#include <pcap/pcap.h>
#endif

#include <wiretap/wtap.h>
#include <capture/capture_sync.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/stock_icon.h>

#include "main_application.h"

#include <QClipboard>
#include <QMutexLocker>
#include <QPushButton>

// We use a global mutex to protect pcap_compile since it calls gethostbyname,
// at least before libpcap 1.8.0. (pcap_compile(3PCAP) says as of libpcap 1.8.0,
// it is thread-safe.)
// This probably isn't needed on Windows (where pcap_compile calls
// EnterCriticalSection + LeaveCriticalSection) or *BSD or macOS where
// gethostbyname(3) claims that it's thread safe.
static QMutex pcap_compile_mtx_;

CompiledFilterOutput::CompiledFilterOutput(QWidget *parent, QList<InterfaceFilter> &intList) :
    GeometryStateDialog(parent),
    intList_(intList),
    ui(new Ui::CompiledFilterOutput)
{
    ui->setupUi(this);
    ui->hintLabel->setSmallText();

    loadGeometry();
    setAttribute(Qt::WA_DeleteOnClose, true);
    ui->filterList->setCurrentFont(mainApp->monospaceFont());

    copy_bt_ = ui->buttonBox->addButton(tr("Copy"), QDialogButtonBox::ActionRole);
    copy_bt_->setToolTip(tr("Copy filter text to the clipboard."));
    connect(copy_bt_, &QPushButton::clicked, this, &CompiledFilterOutput::copyFilterText);

    QPushButton *close_bt = ui->buttonBox->button(QDialogButtonBox::Close);
    close_bt->setDefault(true);

    setTitle();

#ifdef HAVE_LIBPCAP
    compileFilters();
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

void CompiledFilterOutput::setTitle()
{
    // How many unique filters do we have?
    QSet<QString> filterSet;
    for (const auto &current : intList_) {
        filterSet << current.filter;
    }
    QStringList titleList;
    titleList << tr("Compiled Filter Output");
    switch (filterSet.size()) {
    case 0:
        titleList << tr("No capture filter");
        break;
    case 1:
        // There's only one member. (Clang complains if this is a for loop.)
        titleList << *filterSet.cbegin();
        break;
    default:
        titleList << tr("Multiple filters");
    }
    setWindowTitle(mainApp->windowTitleString(titleList));

}

#ifdef HAVE_LIBPCAP
bool CompiledFilterOutput::compileFilter(const InterfaceFilter& filter)
{
    struct bpf_program fcode;

    pcap_t *pd = pcap_open_dead(filter.linktype, WTAP_MAX_PACKET_SIZE_STANDARD);
    if (pd == NULL) {
        return false;
    }
    QMutexLocker locker(&pcap_compile_mtx_);
    int err = pcap_compile(pd, &fcode, filter.filter.toUtf8().constData(), 1, 0);
    if (err < 0) {
        compile_results.insert(filter.display_name, QString(pcap_geterr(pd)));
        pcap_close(pd);
        return false;
    }

    QStringList bpf_code_dump;
    struct bpf_insn *insn = fcode.bf_insns;
    for (u_int i = 0; i < fcode.bf_len; ++insn, ++i) {
        bpf_code_dump << QString::fromUtf8(bpf_image(insn, i));
    }
    pcap_freecode(&fcode);
    compile_results.insert(filter.display_name, bpf_code_dump.join('\n'));
    return true;
}

void CompiledFilterOutput::compileFilters()
{
    char *data, *primary_msg, *secondary_msg;
    bool success;
    QListWidgetItem *newitem;

    foreach (InterfaceFilter current, intList_) {
        switch (current.iftype) {

        case IF_EXTCAP:
            // Extcaps should perhaps have a method to compile a filter
            // (Cf. extcap_verify_capture_filter())
            success = compileFilter(current);
            break;

        case IF_STDIN:
            success = false;
            compile_results.insert(current.display_name, tr("Capture filters cannot be compiled for standard input."));
            break;

        case IF_PIPE:
            success = false;
            compile_results.insert(current.display_name, tr("Capture filters cannot be compiled for pipes."));
            break;

        default:
            // See if dumpcap can compile the filter. This is more accurate
            // because BPF extensions might need to be used for a particular
            // device.
            if (sync_if_bpf_filter_open(current.device_name.toUtf8().constData(), current.filter.toUtf8().constData(), current.linktype, &data, &primary_msg, &secondary_msg, NULL)) {
                compile_results.insert(current.display_name, gchar_free_to_qstring(primary_msg));
                g_free(secondary_msg);
                success = false;
            } else {
                compile_results.insert(current.display_name, gchar_free_to_qstring(data));
                success = true;
            }
            break;
        }
        if (success) {
            newitem = new QListWidgetItem(current.display_name);
        } else {
            newitem = new QListWidgetItem(StockIcon("x-expert-error"), current.display_name);
        }
        newitem->setData(Qt::UserRole, current.filter);
        ui->interfaceList->addItem(newitem);
    }
}
#endif

void CompiledFilterOutput::on_interfaceList_currentItemChanged(QListWidgetItem *current, QListWidgetItem *)
{
    QString interface = current->text();
    QHash<QString, QString>::const_iterator iter = compile_results.find(interface);
    ui->filterList->clear();
    ui->filterList->setPlainText(iter.value());
    QString filter = current->data(Qt::UserRole).toString();
    if (filter.isEmpty()) {
        ui->hintLabel->setText(tr("No capture filter"));
    } else {
        ui->hintLabel->setText(tr("Capture filter: %1").arg(filter));
    }
}

void CompiledFilterOutput::copyFilterText()
{
    mainApp->clipboard()->setText(ui->filterList->toPlainText());
}
