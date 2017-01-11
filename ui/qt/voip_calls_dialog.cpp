/* voip_calls_dialog.cpp
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

#include "voip_calls_dialog.h"
#include <ui_voip_calls_dialog.h>

#include "file.h"

#include "epan/addr_resolv.h"
#include "epan/dissectors/packet-h225.h"

#include "ui/rtp_stream.h"
#include <wsutil/utf8_entities.h>

#include "qt_ui_utils.h"
#include "rtp_player_dialog.h"
#include "sequence_dialog.h"
#include "stock_icon.h"
#include "wireshark_application.h"

#include <QClipboard>
#include <QContextMenuEvent>
#include <QPushButton>

// To do:
// - More context menu items
//   - Don't select on right click
// - Player
// - Add a screenshot to the user's guide

// Bugs:
// - Preparing a filter overwrites the existing filter. The GTK+ UI appends.
//   We'll probably have to add an "append" parameter to MainWindow::filterPackets.

// VoipCallsTreeWidgetItem
// QTreeWidgetItem subclass that allows sorting

const int start_time_col_ = 0;
const int stop_time_col_ = 1;
const int initial_speaker_col_ = 2;
const int from_col_ = 3;
const int to_col_ = 4;
const int protocol_col_ = 5;
const int packets_col_ = 6;
const int state_col_ = 7;
const int comments_col_ = 8;

Q_DECLARE_METATYPE(voip_calls_info_t*)

enum { voip_calls_type_ = 1000 };

class VoipCallsTreeWidgetItem : public QTreeWidgetItem
{
public:
    VoipCallsTreeWidgetItem(QTreeWidget *tree, voip_calls_info_t *call_info) :
        QTreeWidgetItem(tree, voip_calls_type_),
        call_info_(call_info)
    {
        drawData();
    }

    voip_calls_info_t *callInfo() {
        // XXX Not needed? We explicitly pass selected conversations to RtpPlayerDialog.
//        call_info_->selected = isSelected() ? TRUE : FALSE;
        return call_info_;
    }

    void drawData() {
        if (!call_info_) {
            setText(start_time_col_, QObject::tr("Error"));
            return;
        }

        // XXX Pull digit count from capture file precision
        setText(start_time_col_, QString::number(nstime_to_sec(&(call_info_->start_rel_ts)), 'f', 6));
        setText(stop_time_col_, QString::number(nstime_to_sec(&(call_info_->stop_rel_ts)), 'f', 6));
        setText(initial_speaker_col_, address_to_display_qstring(&(call_info_->initial_speaker)));
        setText(from_col_, call_info_->from_identity);
        setText(to_col_, call_info_->to_identity);
        setText(protocol_col_, ((call_info_->protocol == VOIP_COMMON) && call_info_->protocol_name) ?
                        call_info_->protocol_name : voip_protocol_name[call_info_->protocol]);
        setText(packets_col_, QString::number(call_info_->npackets));
        setText(state_col_, voip_call_state_name[call_info_->call_state]);

        /* Add comments based on the protocol */
        QString call_comments;
        switch (call_info_->protocol) {
        case VOIP_ISUP:
        {
            isup_calls_info_t *isup_info = (isup_calls_info_t *)call_info_->prot_info;
            call_comments = QString("%1-%2 %3 %4-%5")
                    .arg(isup_info->ni)
                    .arg(isup_info->opc)
                    .arg(UTF8_RIGHTWARDS_ARROW)
                    .arg(isup_info->ni)
                    .arg(isup_info->dpc);
        }
            break;
        case VOIP_H323:
        {
            h323_calls_info_t *h323_info = (h323_calls_info_t *)call_info_->prot_info;
            gboolean flag = FALSE;
            static const QString on_str = QObject::tr("On");
            static const QString off_str = QObject::tr("Off");
            if (call_info_->call_state == VOIP_CALL_SETUP) {
                flag = h323_info->is_faststart_Setup;
            } else {
                if ((h323_info->is_faststart_Setup) && (h323_info->is_faststart_Proc)) {
                    flag = TRUE;
                }
            }
            call_comments = QObject::tr("Tunneling: %1  Fast Start: %2")
                    .arg(h323_info->is_h245Tunneling ? on_str : off_str)
                    .arg(flag ? on_str : off_str);
        }
            break;
        case VOIP_COMMON:
        default:
            call_comments = call_info_->call_comment;
            break;
        }
        setText(comments_col_, call_comments);
    }

    // Return a QString, int, double, or invalid QVariant representing the raw column data.
    QVariant colData(int col) const {
        if (!call_info_) {
            return QVariant();
        }

        switch(col) {
        case start_time_col_:
            return nstime_to_sec(&call_info_->start_rel_ts);
            break;
        case stop_time_col_:
            return nstime_to_sec(&call_info_->stop_rel_ts);
            break;
        case initial_speaker_col_:
        case from_col_:
        case to_col_:
        case protocol_col_:
        case state_col_:
        case comments_col_:
            return text(col);
            break;
        case packets_col_:
            return call_info_->npackets;
            break;
        default:
            break;
        }
        return QVariant();
    }

    bool operator< (const QTreeWidgetItem &other) const
    {
        if (other.type() != voip_calls_type_) return QTreeWidgetItem::operator< (other);
        const VoipCallsTreeWidgetItem *other_row = static_cast<const VoipCallsTreeWidgetItem *>(&other);

        if (!call_info_ || !other_row->call_info_) {
            return QTreeWidgetItem::operator< (other);
        }

        switch (treeWidget()->sortColumn()) {
        case start_time_col_:
            return nstime_cmp(&(call_info_->start_rel_ts), &(other_row->call_info_->start_rel_ts)) < 0;
            break;
        case stop_time_col_:
            return nstime_cmp(&(call_info_->stop_rel_ts), &(other_row->call_info_->stop_rel_ts)) < 0;
            break;
        case initial_speaker_col_:
            return cmp_address(&(call_info_->initial_speaker), &(other_row->call_info_->initial_speaker)) < 0;
            break;
        case packets_col_:
            return call_info_->npackets < other_row->call_info_->npackets;
            break;
        default:
            break;
        }

        // Fall back to string comparison
        return QTreeWidgetItem::operator <(other);
    }
private:
    voip_calls_info_t *call_info_;
};

VoipCallsDialog::VoipCallsDialog(QWidget &parent, CaptureFile &cf, bool all_flows) :
    WiresharkDialog(parent, cf),
    ui(new Ui::VoipCallsDialog),
    parent_(parent)
{
    ui->setupUi(this);
    loadGeometry(parent.width() * 4 / 5, parent.height() * 2 / 3);

    ui->callTreeWidget->sortByColumn(start_time_col_, Qt::AscendingOrder);
    setWindowSubtitle(all_flows ? tr("SIP Flows") : tr("VoIP Calls"));

    ctx_menu_.addAction(ui->actionSelect_All);
    ctx_menu_.addSeparator();
    ctx_menu_.addAction(ui->actionCopyAsCsv);
    ctx_menu_.addAction(ui->actionCopyAsYaml);

    prepare_button_ = ui->buttonBox->addButton(tr("Prepare Filter"), QDialogButtonBox::ApplyRole);
    sequence_button_ = ui->buttonBox->addButton(tr("Flow Sequence"), QDialogButtonBox::ApplyRole);
    player_button_ = RtpPlayerDialog::addPlayerButton(ui->buttonBox);

    copy_button_ = ui->buttonBox->addButton(tr("Copy"), QDialogButtonBox::ApplyRole);
    QMenu *copy_menu = new QMenu();
    QAction *ca;
    ca = copy_menu->addAction(tr("as CSV"));
    ca->setToolTip(ui->actionCopyAsCsv->toolTip());
    connect(ca, SIGNAL(triggered()), this, SLOT(on_actionCopyAsCsv_triggered()));
    ca = copy_menu->addAction(tr("as YAML"));
    ca->setToolTip(ui->actionCopyAsYaml->toolTip());
    connect(ca, SIGNAL(triggered()), this, SLOT(on_actionCopyAsYaml_triggered()));
    copy_button_->setMenu(copy_menu);

    memset (&tapinfo_, 0, sizeof(tapinfo_));
    tapinfo_.tap_packet = tapPacket;
    tapinfo_.tap_draw = tapDraw;
    tapinfo_.tap_data = this;
    tapinfo_.callsinfos = g_queue_new();
    tapinfo_.h225_cstype = H225_OTHER;
    tapinfo_.fs_option = all_flows ? FLOW_ALL : FLOW_ONLY_INVITES; /* flow show option */
    tapinfo_.graph_analysis = sequence_analysis_info_new();
    tapinfo_.graph_analysis->type = SEQ_ANALYSIS_VOIP;
    sequence_info_ = new SequenceInfo(tapinfo_.graph_analysis);

    voip_calls_init_all_taps(&tapinfo_);

    updateWidgets();

    if (cap_file_.isValid()) {
        tapinfo_.session = cap_file_.capFile()->epan;
        cap_file_.delayedRetapPackets();
    }
}

VoipCallsDialog::~VoipCallsDialog()
{
    delete ui;

    voip_calls_reset_all_taps(&tapinfo_);
    voip_calls_remove_all_tap_listeners(&tapinfo_);
    sequence_info_->unref();
    g_queue_free(tapinfo_.callsinfos);
}

void VoipCallsDialog::endRetapPackets()
{
    voip_calls_remove_all_tap_listeners(&tapinfo_);
    WiresharkDialog::endRetapPackets();
}

void VoipCallsDialog::captureFileClosing()
{
    voip_calls_remove_all_tap_listeners(&tapinfo_);
    tapinfo_.session = NULL;
    WiresharkDialog::captureFileClosing();
}

void VoipCallsDialog::contextMenuEvent(QContextMenuEvent *event)
{
    ctx_menu_.exec(event->globalPos());
}

void VoipCallsDialog::changeEvent(QEvent *event)
{
    if (0 != event)
    {
        switch (event->type())
        {
        case QEvent::LanguageChange:
            ui->retranslateUi(this);
            break;
        default:
            break;
        }
    }
    QDialog::changeEvent(event);
}

//void VoipCallsDialog::tapReset(void *)
//{
//    voip_calls_tapinfo_t *tapinfo = (voip_calls_tapinfo_t *) tapinfo_ptr;
//}

gboolean VoipCallsDialog::tapPacket(void *, packet_info *, epan_dissect_t *, const void *)
{
#ifdef QT_MULTIMEDIA_LIB
//    voip_calls_tapinfo_t *tapinfo = (voip_calls_tapinfo_t *) tapinfo_ptr;
    // add_rtp_packet for voip player.
//    return TRUE;
#endif
    return FALSE;
}

void VoipCallsDialog::tapDraw(void *tapinfo_ptr)
{
    voip_calls_tapinfo_t *tapinfo = (voip_calls_tapinfo_t *) tapinfo_ptr;

    if (!tapinfo || !tapinfo->redraw) {
        return;
    }

    GList *graph_item = g_queue_peek_nth_link(tapinfo->graph_analysis->items, 0);
    for (; graph_item; graph_item = g_list_next(graph_item)) {
        for (GList *rsi_entry = g_list_first(tapinfo->rtp_stream_list); rsi_entry; rsi_entry = g_list_next(rsi_entry)) {
            seq_analysis_item_t * sai = (seq_analysis_item_t *)graph_item->data;
            rtp_stream_info_t *rsi = (rtp_stream_info_t *)rsi_entry->data;

            if (rsi->start_fd->num == sai->frame_number) {
                rsi->call_num = sai->conv_num;
                // VOIP_CALLS_DEBUG("setting conv num %u for frame %u", sai->conv_num, sai->frame_number);
            }
        }
    }

    VoipCallsDialog *voip_calls_dialog = static_cast<VoipCallsDialog *>(tapinfo->tap_data);
    if (voip_calls_dialog) {
        voip_calls_dialog->updateCalls();
    }
}

void VoipCallsDialog::updateCalls()
{
    GList *cur_call = g_queue_peek_nth_link(tapinfo_.callsinfos, ui->callTreeWidget->topLevelItemCount());
    ui->callTreeWidget->setSortingEnabled(false);

    // Add any missing items
    while (cur_call && cur_call->data) {
        voip_calls_info_t *call_info = (voip_calls_info_t*) cur_call->data;
        new VoipCallsTreeWidgetItem(ui->callTreeWidget, call_info);
        cur_call = g_list_next(cur_call);
    }

    // Fill in the tree
    QTreeWidgetItemIterator iter(ui->callTreeWidget);
    while (*iter) {
        VoipCallsTreeWidgetItem *vcti = static_cast<VoipCallsTreeWidgetItem*>(*iter);
        vcti->drawData();
        ++iter;
    }

    // Resize columns
    for (int i = 0; i < ui->callTreeWidget->columnCount(); i++) {
        ui->callTreeWidget->resizeColumnToContents(i);
    }

    ui->callTreeWidget->setSortingEnabled(true);

    updateWidgets();
}

void VoipCallsDialog::updateWidgets()
{
    bool selected = ui->callTreeWidget->selectedItems().count() > 0 ? true : false;
    bool have_ga_items = false;

    if (tapinfo_.graph_analysis && tapinfo_.graph_analysis->items) {
        have_ga_items = true;
    }

    foreach (QMenu *submenu, ctx_menu_.findChildren<QMenu*>()) {
        submenu->setEnabled(selected);
    }
    prepare_button_->setEnabled(selected && have_ga_items);
    sequence_button_->setEnabled(selected && have_ga_items);
#if defined(QT_MULTIMEDIA_LIB)
    player_button_->setEnabled(selected && have_ga_items);
#else
    player_button_->setEnabled(false);
    player_button_->setText(tr("No Audio"));
#endif
}

void VoipCallsDialog::prepareFilter()
{
    if (ui->callTreeWidget->selectedItems().count() < 1 || !tapinfo_.graph_analysis) {
        return;
    }

    QString filter_str;
    QSet<guint16> selected_calls;

    /* Build a new filter based on frame numbers */
    const char *or_prepend = "";
    foreach (QTreeWidgetItem *ti, ui->callTreeWidget->selectedItems()) {
        VoipCallsTreeWidgetItem *vc_ti = static_cast<VoipCallsTreeWidgetItem *>(ti);
        voip_calls_info_t *call_info = vc_ti->callInfo();
        if (!call_info) {
            return;
        }
        selected_calls << call_info->call_num;
    }

    GList *cur_ga_item = g_queue_peek_nth_link(tapinfo_.graph_analysis->items, 0);
    while (cur_ga_item && cur_ga_item->data) {
        seq_analysis_item_t *ga_item = (seq_analysis_item_t*) cur_ga_item->data;
        if (selected_calls.contains(ga_item->conv_num)) {
            filter_str += QString("%1frame.number == %2").arg(or_prepend).arg(ga_item->frame_number);
            or_prepend = " or ";
        }
        cur_ga_item = g_list_next(cur_ga_item);
    }

#if 0
    // XXX The GTK+ UI falls back to building a filter based on protocols if the filter
    // length is too long. Leaving this here for the time being in case we need to do
    // the same in the Qt UI.
    const sip_calls_info_t *sipinfo;
    const isup_calls_info_t *isupinfo;
    const h323_calls_info_t *h323info;
    const h245_address_t *h245_add = NULL;
    const gcp_ctx_t* ctx;
    char *guid_str;

    if (filter_length < max_filter_length) {
        gtk_editable_insert_text(GTK_EDITABLE(main_display_filter_widget), filter_string_fwd->str, -1, &pos);
    } else {
        g_string_free(filter_string_fwd, TRUE);
        filter_string_fwd = g_string_new(filter_prepend);

        g_string_append_printf(filter_string_fwd, "(");
        is_first = TRUE;
        /* Build a new filter based on protocol fields */
        lista = g_queue_peek_nth_link(voip_calls_get_info()->callsinfos, 0);
        while (lista) {
            listinfo = (voip_calls_info_t *)lista->data;
            if (listinfo->selected) {
                if (!is_first)
                    g_string_append_printf(filter_string_fwd, " or ");
                switch (listinfo->protocol) {
                case VOIP_SIP:
                    sipinfo = (sip_calls_info_t *)listinfo->prot_info;
                    g_string_append_printf(filter_string_fwd,
                        "(sip.Call-ID == \"%s\")",
                        sipinfo->call_identifier
                    );
                    break;
                case VOIP_ISUP:
                    isupinfo = (isup_calls_info_t *)listinfo->prot_info;
                    g_string_append_printf(filter_string_fwd,
                        "(isup.cic == %i and frame.number >= %i and frame.number <= %i and mtp3.network_indicator == %i and ((mtp3.dpc == %i) and (mtp3.opc == %i)) or ((mtp3.dpc == %i) and (mtp3.opc == %i)))",
                        isupinfo->cic, listinfo->start_fd->num,
                        listinfo->stop_fd->num,
                        isupinfo->ni, isupinfo->dpc, isupinfo->opc,
                        isupinfo->opc, isupinfo->dpc
                    );
                    break;
                case VOIP_H323:
                {
                    h323info = (h323_calls_info_t *)listinfo->prot_info;
					guid_str = guid_to_str(NULL, &h323info->guid[0]);
                    g_string_append_printf(filter_string_fwd,
                        "((h225.guid == %s || q931.call_ref == %x:%x || q931.call_ref == %x:%x)",
                        guid_str,
                        (guint8) (h323info->q931_crv & 0x00ff),
                        (guint8)((h323info->q931_crv & 0xff00)>>8),
                        (guint8) (h323info->q931_crv2 & 0x00ff),
                        (guint8)((h323info->q931_crv2 & 0xff00)>>8));
                    listb = g_list_first(h323info->h245_list);
					wmem_free(NULL, guid_str);
                    while (listb) {
                        h245_add = (h245_address_t *)listb->data;
                        g_string_append_printf(filter_string_fwd,
                            " || (ip.addr == %s && tcp.port == %d && h245)",
                            address_to_qstring(&h245_add->h245_address), h245_add->h245_port);
                        listb = g_list_next(listb);
                    }
                    g_string_append_printf(filter_string_fwd, ")");
                }
                    break;
                case TEL_H248:
                    ctx = (gcp_ctx_t *)listinfo->prot_info;
                    g_string_append_printf(filter_string_fwd,
                        "(h248.ctx == 0x%x)", ctx->id);
                    break;
                default:
                    /* placeholder to assure valid display filter expression */
                    g_string_append_printf(filter_string_fwd,
                        "(frame)");
                    break;
                }
                is_first = FALSE;
            }
            lista = g_list_next(lista);
        }

        g_string_append_printf(filter_string_fwd, ")");
        gtk_editable_insert_text(GTK_EDITABLE(main_display_filter_widget), filter_string_fwd->str, -1, &pos);
    }
#endif

    emit updateFilter(filter_str);
}

void VoipCallsDialog::showSequence()
{
    if (file_closed_) return;

    QSet<guint16> selected_calls;
    foreach (QTreeWidgetItem *ti, ui->callTreeWidget->selectedItems()) {
        VoipCallsTreeWidgetItem *vc_ti = static_cast<VoipCallsTreeWidgetItem *>(ti);
        voip_calls_info_t *call_info = vc_ti->callInfo();
        if (!call_info) {
            return;
        }
        selected_calls << call_info->call_num;
    }

    sequence_analysis_list_sort(tapinfo_.graph_analysis);
    GList *cur_ga_item = g_queue_peek_nth_link(tapinfo_.graph_analysis->items, 0);
    while (cur_ga_item && cur_ga_item->data) {
        seq_analysis_item_t *ga_item = (seq_analysis_item_t*) cur_ga_item->data;
        ga_item->display = selected_calls.contains(ga_item->conv_num);
        cur_ga_item = g_list_next(cur_ga_item);
    }

    SequenceDialog *sequence_dialog = new SequenceDialog(parent_, cap_file_, sequence_info_);
    sequence_dialog->show();
}

void VoipCallsDialog::showPlayer()
{
#ifdef QT_MULTIMEDIA_LIB
    RtpPlayerDialog rtp_player_dialog(*this, cap_file_);

    foreach (QTreeWidgetItem *ti, ui->callTreeWidget->selectedItems()) {
        VoipCallsTreeWidgetItem *vc_ti = static_cast<VoipCallsTreeWidgetItem *>(ti);
        for (GList *rsi_entry = g_list_first(tapinfo_.rtp_stream_list); rsi_entry; rsi_entry = g_list_next(rsi_entry)) {
            rtp_stream_info_t *rsi = (rtp_stream_info_t *)rsi_entry->data;
            if (!rsi) continue;

            //VOIP_CALLS_DEBUG("checking call %u, start frame %u == stream call %u, start frame %u, setup frame %u",
            //                vc_ti->callInfo()->call_num, vc_ti->callInfo()->start_fd->num,
            //                rsi->call_num, rsi->start_fd->num, rsi->setup_frame_number);
            if (vc_ti->callInfo()->call_num == rsi->call_num) {
                //VOIP_CALLS_DEBUG("adding call number %u", vc_ti->callInfo()->call_num);
                rtp_player_dialog.addRtpStream(rsi);
            }
        }
    }

    connect(&rtp_player_dialog, SIGNAL(goToPacket(int)), this, SIGNAL(goToPacket(int)));

    rtp_player_dialog.exec();
#endif // QT_MULTIMEDIA_LIB
}

QList<QVariant> VoipCallsDialog::streamRowData(int row) const
{
    QList<QVariant> row_data;

    if (row >= ui->callTreeWidget->topLevelItemCount()) {
        return row_data;
    }

    for (int col = 0; col < ui->callTreeWidget->columnCount(); col++) {
        if (row < 0) {
            row_data << ui->callTreeWidget->headerItem()->text(col);
        } else {
            VoipCallsTreeWidgetItem *vcti = static_cast<VoipCallsTreeWidgetItem*>(ui->callTreeWidget->topLevelItem(row));
            if (vcti) {
                row_data << vcti->colData(col);
            }
        }
    }
    return row_data;
}

void VoipCallsDialog::on_callTreeWidget_itemActivated(QTreeWidgetItem *item, int)
{
    VoipCallsTreeWidgetItem *vc_ti = static_cast<VoipCallsTreeWidgetItem *>(item);
    voip_calls_info_t *call_info = vc_ti->callInfo();
    if (!call_info) {
        return;
    }
    emit goToPacket(call_info->start_fd->num);
}

void VoipCallsDialog::on_callTreeWidget_itemSelectionChanged()
{
    updateWidgets();
}

void VoipCallsDialog::on_actionSelect_All_triggered()
{
    ui->callTreeWidget->selectAll();
}

void VoipCallsDialog::on_actionCopyAsCsv_triggered()
{
    QString csv;
    QTextStream stream(&csv, QIODevice::Text);
    for (int row = -1; row < ui->callTreeWidget->topLevelItemCount(); row++) {
        QStringList rdsl;
        foreach (QVariant v, streamRowData(row)) {
            if (!v.isValid()) {
                rdsl << "\"\"";
            } else if ((int) v.type() == (int) QMetaType::QString) {
                rdsl << QString("\"%1\"").arg(v.toString());
            } else {
                rdsl << v.toString();
            }
        }
        stream << rdsl.join(",") << endl;
    }
    wsApp->clipboard()->setText(stream.readAll());
}

void VoipCallsDialog::on_actionCopyAsYaml_triggered()
{
    QString yaml;
    QTextStream stream(&yaml, QIODevice::Text);
    stream << "---" << endl;
    for (int row = -1; row < ui->callTreeWidget->topLevelItemCount(); row ++) {
        stream << "-" << endl;
        foreach (QVariant v, streamRowData(row)) {
            stream << " - " << v.toString() << endl;
        }
    }
    wsApp->clipboard()->setText(stream.readAll());
}

void VoipCallsDialog::on_buttonBox_clicked(QAbstractButton *button)
{
    if (button == prepare_button_) {
        prepareFilter();
    } else if (button == sequence_button_) {
        showSequence();
    } else if (button == player_button_) {
        showPlayer();
    }
}

void VoipCallsDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_TELEPHONY_VOIP_CALLS_DIALOG);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
