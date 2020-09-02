/* voip_calls_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "voip_calls_dialog.h"
#include <ui_voip_calls_dialog.h>

#include "file.h"

#include "epan/addr_resolv.h"
#include "epan/dissectors/packet-h225.h"

#include "ui/rtp_stream.h"

#include <ui/qt/utils/qt_ui_utils.h>
#include "rtp_player_dialog.h"
#include "sequence_dialog.h"
#include <ui/qt/utils/stock_icon.h>
#include "wireshark_application.h"
#include <ui/qt/models/voip_calls_info_model.h>

#include <QClipboard>
#include <QContextMenuEvent>
#include <QPushButton>

// To do:
// - More context menu items
//   - Don't select on right click
// - Player
// - Add a screenshot to the user's guide
// - Add filter for quickly searching through list?

// Bugs:
// - Preparing a filter overwrites the existing filter. The GTK+ UI appends.
//   We'll probably have to add an "append" parameter to MainWindow::filterPackets.

enum { voip_calls_type_ = 1000 };

VoipCallsDialog::VoipCallsDialog(QWidget &parent, CaptureFile &cf, bool all_flows) :
    WiresharkDialog(parent, cf),
    ui(new Ui::VoipCallsDialog),
    parent_(parent),
    voip_calls_tap_listeners_removed_(false)
{
    ui->setupUi(this);
    loadGeometry(parent.width() * 4 / 5, parent.height() * 2 / 3);

    // Create the model that stores the actual data and the proxy model that is
    // responsible for sorting and filtering data in the display.
    call_infos_model_ = new VoipCallsInfoModel(this);
    cache_model_ = new CacheProxyModel(this);
    cache_model_->setSourceModel(call_infos_model_);
    sorted_model_ = new VoipCallsInfoSortedModel(this);
    sorted_model_->setSourceModel(cache_model_);
    ui->callTreeView->setModel(sorted_model_);

    connect(ui->callTreeView->selectionModel(), SIGNAL(selectionChanged(QItemSelection,QItemSelection)),
            this, SLOT(updateWidgets()));
    ui->callTreeView->sortByColumn(VoipCallsInfoModel::StartTime, Qt::AscendingOrder);
    setWindowSubtitle(all_flows ? tr("SIP Flows") : tr("VoIP Calls"));

    prepare_button_ = ui->buttonBox->addButton(tr("Prepare Filter"), QDialogButtonBox::ApplyRole);
    sequence_button_ = ui->buttonBox->addButton(tr("Flow Sequence"), QDialogButtonBox::ApplyRole);
    player_button_ = RtpPlayerDialog::addPlayerButton(ui->buttonBox);

    connect (ui->todCheckBox, &QAbstractButton::toggled, this, &VoipCallsDialog::switchTimeOfDay);

    copy_button_ = ui->buttonBox->addButton(tr("Copy"), QDialogButtonBox::ApplyRole);
    QMenu *copy_menu = new QMenu(copy_button_);
    QAction *ca;
    ca = copy_menu->addAction(tr("as CSV"));
    connect(ca, SIGNAL(triggered()), this, SLOT(copyAsCSV()));
    ca = copy_menu->addAction(tr("as YAML"));
    connect(ca, SIGNAL(triggered()), this, SLOT(copyAsYAML()));
    copy_button_->setMenu(copy_menu);

    memset (&tapinfo_, 0, sizeof(tapinfo_));
    tapinfo_.tap_packet = tapPacket;
    tapinfo_.tap_draw = tapDraw;
    tapinfo_.tap_data = this;
    tapinfo_.callsinfos = g_queue_new();
    tapinfo_.h225_cstype = H225_OTHER;
    tapinfo_.fs_option = all_flows ? FLOW_ALL : FLOW_ONLY_INVITES; /* flow show option */
    tapinfo_.graph_analysis = sequence_analysis_info_new();
    tapinfo_.graph_analysis->name = "voip";
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
    if (!voip_calls_tap_listeners_removed_) {
        voip_calls_remove_all_tap_listeners(&tapinfo_);
        voip_calls_tap_listeners_removed_ = true;
    }
    sequence_info_->unref();
    g_queue_free(tapinfo_.callsinfos);
}

void VoipCallsDialog::removeTapListeners()
{
    if (!voip_calls_tap_listeners_removed_) {
        voip_calls_remove_all_tap_listeners(&tapinfo_);
        voip_calls_tap_listeners_removed_ = true;
    }
    WiresharkDialog::removeTapListeners();
}

void VoipCallsDialog::captureFileClosing()
{
    // The time formatting is currently provided by VoipCallsInfoModel, but when
    // the cache is active, the ToD cannot be modified.
    ui->todCheckBox->setEnabled(false);
    cache_model_->setSourceModel(NULL);
    if (!voip_calls_tap_listeners_removed_) {
        voip_calls_remove_all_tap_listeners(&tapinfo_);
        voip_calls_tap_listeners_removed_ = true;
    }
    tapinfo_.session = NULL;
    WiresharkDialog::captureFileClosing();
}

void VoipCallsDialog::contextMenuEvent(QContextMenuEvent *event)
{
    bool selected = ui->callTreeView->selectionModel()->hasSelection();

    if (! selected)
        return;

    QMenu popupMenu;

    QAction * action = popupMenu.addAction(tr("Select &All"), this, SLOT(selectAll()));
    action->setToolTip(tr("Select all calls"));
    popupMenu.addSeparator();
    action = popupMenu.addAction(tr("Display time as time of day"), this, SLOT(switchTimeOfDay()));
    action->setCheckable(true);
    action->setChecked(call_infos_model_->timeOfDay());
    popupMenu.addSeparator();
    action = popupMenu.addAction(tr("Copy as CSV"), this, SLOT(copyAsCSV()));
    action->setToolTip(tr("Copy stream list as CSV."));
    action = popupMenu.addAction(tr("Copy as YAML"), this, SLOT(copyAsYAML()));
    action->setToolTip(tr("Copy stream list as YAML."));

    popupMenu.exec(event->globalPos());
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

tap_packet_status VoipCallsDialog::tapPacket(void *, packet_info *, epan_dissect_t *, const void *)
{
#ifdef QT_MULTIMEDIA_LIB
//    voip_calls_tapinfo_t *tapinfo = (voip_calls_tapinfo_t *) tapinfo_ptr;
    // add_rtp_packet for voip player.
//    return TAP_PACKET_REDRAW;
#endif
    return TAP_PACKET_DONT_REDRAW;
}

void VoipCallsDialog::tapDraw(void *tapinfo_ptr)
{
    voip_calls_tapinfo_t *tapinfo = static_cast<voip_calls_tapinfo_t *>(tapinfo_ptr);

    if (!tapinfo || !tapinfo->redraw) {
        return;
    }

    GList *graph_item = g_queue_peek_nth_link(tapinfo->graph_analysis->items, 0);
    for (; graph_item; graph_item = gxx_list_next(graph_item)) {
        for (GList *rsi_entry = g_list_first(tapinfo->rtpstream_list); rsi_entry; rsi_entry = gxx_list_next(rsi_entry)) {
            seq_analysis_item_t * sai = gxx_list_data(seq_analysis_item_t *, graph_item);
            rtpstream_info_t *rsi = gxx_list_data(rtpstream_info_t *, rsi_entry);

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
    ui->callTreeView->setSortingEnabled(false);

    // Add any missing items
    call_infos_model_->updateCalls(tapinfo_.callsinfos);

    // Resize columns
    for (int i = 0; i < call_infos_model_->columnCount(); i++) {
        ui->callTreeView->resizeColumnToContents(i);
    }

    ui->callTreeView->setSortingEnabled(true);

    updateWidgets();
}

void VoipCallsDialog::updateWidgets()
{
    bool selected = ui->callTreeView->selectionModel()->hasSelection();
    bool have_ga_items = false;

    if (tapinfo_.graph_analysis && tapinfo_.graph_analysis->items) {
        have_ga_items = true;
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
    if (!ui->callTreeView->selectionModel()->hasSelection() || !tapinfo_.graph_analysis) {
        return;
    }

    QString filter_str;
    QSet<guint16> selected_calls;
    QString frame_numbers;
    QList<int> rows;

    /* Build a new filter based on frame numbers */
    foreach (QModelIndex index, ui->callTreeView->selectionModel()->selectedIndexes()) {
        if (index.isValid() && ! rows.contains(index.row()))
        {
            voip_calls_info_t *call_info = VoipCallsInfoModel::indexToCallInfo(index);
            if (!call_info) {
                return;
            }

            selected_calls << call_info->call_num;
            rows << index.row();
        }
    }

    GList *cur_ga_item = g_queue_peek_nth_link(tapinfo_.graph_analysis->items, 0);
    while (cur_ga_item && cur_ga_item->data) {
        seq_analysis_item_t *ga_item = gxx_list_data(seq_analysis_item_t*, cur_ga_item);
        if (selected_calls.contains(ga_item->conv_num)) {
            frame_numbers += QString("%1 ").arg(ga_item->frame_number);
        }
        cur_ga_item = gxx_list_next(cur_ga_item);
    }

    if (!frame_numbers.isEmpty()) {
        frame_numbers.chop(1);
        filter_str = QString("frame.number in {%1} or rtp.setup-frame in {%1}").arg(frame_numbers);
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
            listinfo = gxx_list_data(voip_calls_info_t *, lista);
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
                        h245_add = gxx_list_data(h245_address_t *, listb);
                        g_string_append_printf(filter_string_fwd,
                            " || (ip.addr == %s && tcp.port == %d && h245)",
                            address_to_qstring(&h245_add->h245_address), h245_add->h245_port);
                        listb = gxx_list_next(listb);
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
            lista = gxx_list_next(lista);
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
    foreach (QModelIndex index, ui->callTreeView->selectionModel()->selectedIndexes()) {
        voip_calls_info_t *call_info = VoipCallsInfoModel::indexToCallInfo(index);
        if (!call_info) {
            return;
        }
        selected_calls << call_info->call_num;
    }

    sequence_analysis_list_sort(tapinfo_.graph_analysis);
    GList *cur_ga_item = g_queue_peek_nth_link(tapinfo_.graph_analysis->items, 0);
    while (cur_ga_item && cur_ga_item->data) {
        seq_analysis_item_t *ga_item = gxx_list_data(seq_analysis_item_t*, cur_ga_item);
        ga_item->display = selected_calls.contains(ga_item->conv_num);
        cur_ga_item = gxx_list_next(cur_ga_item);
    }

    SequenceDialog *sequence_dialog = new SequenceDialog(parent_, cap_file_, sequence_info_);
    sequence_dialog->setAttribute(Qt::WA_DeleteOnClose);
    sequence_dialog->show();
}

void VoipCallsDialog::showPlayer()
{
#ifdef QT_MULTIMEDIA_LIB
    RtpPlayerDialog *rtp_player_dialog = new RtpPlayerDialog(*this, cap_file_);

    foreach (QModelIndex index, ui->callTreeView->selectionModel()->selectedIndexes()) {
        voip_calls_info_t *vci = VoipCallsInfoModel::indexToCallInfo(index);
        if (!vci) continue;

        for (GList *rsi_entry = g_list_first(tapinfo_.rtpstream_list); rsi_entry; rsi_entry = gxx_list_next(rsi_entry)) {
            rtpstream_info_t *rsi = gxx_list_data(rtpstream_info_t *, rsi_entry);
            if (!rsi) continue;

            //VOIP_CALLS_DEBUG("checking call %u, start frame %u == stream call %u, start frame %u, setup frame %u",
            //                vci->call_num, vci->start_fd->num,
            //                rsi->call_num, rsi->start_fd->num, rsi->setup_frame_number);
            if (vci->call_num == static_cast<guint>(rsi->call_num)) {
                //VOIP_CALLS_DEBUG("adding call number %u", vci->call_num);
                rtp_player_dialog->addRtpStream(rsi);
            }
        }
    }

    connect(rtp_player_dialog, SIGNAL(goToPacket(int)), this, SIGNAL(goToPacket(int)));

    rtp_player_dialog->setWindowModality(Qt::ApplicationModal);
    rtp_player_dialog->setAttribute(Qt::WA_DeleteOnClose);
    rtp_player_dialog->setMarkers();
    rtp_player_dialog->show();
#endif // QT_MULTIMEDIA_LIB
}

QList<QVariant> VoipCallsDialog::streamRowData(int row) const
{
    QList<QVariant> row_data;

    if (row >= sorted_model_->rowCount()) {
        return row_data;
    }

    for (int col = 0; col < sorted_model_->columnCount(); col++) {
        if (row < 0) {
            row_data << sorted_model_->headerData(col, Qt::Horizontal);
        } else {
            row_data << sorted_model_->index(row, col).data();
        }
    }
    return row_data;
}

void VoipCallsDialog::on_callTreeView_activated(const QModelIndex &index)
{
    voip_calls_info_t *call_info = VoipCallsInfoModel::indexToCallInfo(index);
    if (!call_info) {
        return;
    }
    emit goToPacket(call_info->start_fd->num);
}

void VoipCallsDialog::selectAll()
{
    ui->callTreeView->selectAll();
}

void VoipCallsDialog::copyAsCSV()
{
    QString csv;
    QTextStream stream(&csv, QIODevice::Text);
    for (int row = -1; row < sorted_model_->rowCount(); row++) {
        QStringList rdsl;
        foreach (QVariant v, streamRowData(row)) {
            QString strval = v.toString();
            // XXX should quotes (") in strval be stripped/sanitized?
            rdsl << QString("\"%1\"").arg(strval);
        }
        stream << rdsl.join(",") << '\n';
    }
    wsApp->clipboard()->setText(stream.readAll());
}

void VoipCallsDialog::copyAsYAML()
{
    QString yaml;
    QTextStream stream(&yaml, QIODevice::Text);
    stream << "---" << '\n';
    for (int row = -1; row < sorted_model_->rowCount(); row++) {
        stream << "-" << '\n';
        foreach (QVariant v, streamRowData(row)) {
            stream << " - " << v.toString() << '\n';
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

void VoipCallsDialog::switchTimeOfDay()
{
    bool checked = ! call_infos_model_->timeOfDay();

    ui->todCheckBox->setChecked(checked);
    call_infos_model_->setTimeOfDay(checked);
    ui->callTreeView->resizeColumnToContents(VoipCallsInfoModel::StartTime);
    ui->callTreeView->resizeColumnToContents(VoipCallsInfoModel::StopTime);
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
