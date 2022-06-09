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
#include "ui/rtp_stream_id.h"

#include <ui/qt/utils/qt_ui_utils.h>
#include "rtp_player_dialog.h"
#include "sequence_dialog.h"
#include <ui/qt/utils/stock_icon.h>
#include "main_application.h"
#include <ui/qt/models/voip_calls_info_model.h>

#include <QClipboard>
#include <QContextMenuEvent>
#include <QToolButton>

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

VoipCallsDialog *VoipCallsDialog::pinstance_voip_{nullptr};
VoipCallsDialog *VoipCallsDialog::pinstance_sip_{nullptr};
std::mutex VoipCallsDialog::init_mutex_;

VoipCallsDialog *VoipCallsDialog::openVoipCallsDialogVoip(QWidget &parent, CaptureFile &cf, QObject *packet_list)
{
    std::lock_guard<std::mutex> lock(init_mutex_);
    if (pinstance_voip_ == nullptr)
    {
        pinstance_voip_ = new VoipCallsDialog(parent, cf, false);
        connect(pinstance_voip_, SIGNAL(goToPacket(int)),
                packet_list, SLOT(goToPacket(int)));
    }
    return pinstance_voip_;
}

VoipCallsDialog *VoipCallsDialog::openVoipCallsDialogSip(QWidget &parent, CaptureFile &cf, QObject *packet_list)
{
    std::lock_guard<std::mutex> lock(init_mutex_);
    if (pinstance_sip_ == nullptr)
    {
        pinstance_sip_ = new VoipCallsDialog(parent, cf, true);
        connect(pinstance_sip_, SIGNAL(goToPacket(int)),
                packet_list, SLOT(goToPacket(int)));
    }
    return pinstance_sip_;
}

VoipCallsDialog::VoipCallsDialog(QWidget &parent, CaptureFile &cf, bool all_flows) :
    WiresharkDialog(parent, cf),
    all_flows_(all_flows),
    ui(new Ui::VoipCallsDialog),
    parent_(parent),
    voip_calls_tap_listeners_removed_(false)
{
    ui->setupUi(this);
    loadGeometry(parent.width() * 4 / 5, parent.height() * 2 / 3);
    ui->callTreeView->installEventFilter(this);

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
    setWindowSubtitle(all_flows_ ? tr("SIP Flows") : tr("VoIP Calls"));

    sequence_button_ = ui->buttonBox->addButton(ui->actionFlowSequence->text(), QDialogButtonBox::ActionRole);
    sequence_button_->setToolTip(ui->actionFlowSequence->toolTip());
    prepare_button_ = ui->buttonBox->addButton(ui->actionPrepareFilter->text(), QDialogButtonBox::ActionRole);
    prepare_button_->setToolTip(ui->actionPrepareFilter->toolTip());
    player_button_ = RtpPlayerDialog::addPlayerButton(ui->buttonBox, this);

    connect (ui->todCheckBox, &QAbstractButton::toggled, this, &VoipCallsDialog::switchTimeOfDay);

    copy_button_ = ui->buttonBox->addButton(ui->actionCopyButton->text(), QDialogButtonBox::ActionRole);
    copy_button_->setToolTip(ui->actionCopyButton->toolTip());
    QMenu *copy_menu = new QMenu(copy_button_);
    QAction *ca;
    ca = copy_menu->addAction(tr("as CSV"));
    connect(ca, SIGNAL(triggered()), this, SLOT(copyAsCSV()));
    ca = copy_menu->addAction(tr("as YAML"));
    connect(ca, SIGNAL(triggered()), this, SLOT(copyAsYAML()));
    copy_button_->setMenu(copy_menu);
    connect(&cap_file_, SIGNAL(captureEvent(CaptureEvent)),
            this, SLOT(captureEvent(CaptureEvent)));

    connect(this, SIGNAL(rtpStreamsDialogSelectRtpStreams(QVector<rtpstream_id_t *>)), &parent_, SLOT(rtpStreamsDialogSelectRtpStreams(QVector<rtpstream_id_t *>)));
    connect(this, SIGNAL(rtpStreamsDialogDeselectRtpStreams(QVector<rtpstream_id_t *>)), &parent_, SLOT(rtpStreamsDialogDeselectRtpStreams(QVector<rtpstream_id_t *>)));

    memset (&tapinfo_, 0, sizeof(tapinfo_));
    tapinfo_.tap_packet = tapPacket;
    tapinfo_.tap_reset = tapReset;
    tapinfo_.tap_draw = tapDraw;
    tapinfo_.tap_data = this;
    tapinfo_.callsinfos = g_queue_new();
    tapinfo_.h225_cstype = H225_OTHER;
    tapinfo_.fs_option = all_flows_ ? FLOW_ALL : FLOW_ONLY_INVITES; /* flow show option */
    tapinfo_.graph_analysis = sequence_analysis_info_new();
    tapinfo_.graph_analysis->name = "voip";
    sequence_info_ = new SequenceInfo(tapinfo_.graph_analysis);
    shown_callsinfos_ = g_queue_new();

    voip_calls_init_all_taps(&tapinfo_);
    if (cap_file_.isValid() && cap_file_.capFile()->dfilter) {
        // Activate display filter checking
        tapinfo_.apply_display_filter = true;
        ui->displayFilterCheckBox->setChecked(true);
    }

    connect(this, SIGNAL(updateFilter(QString, bool)),
            &parent, SLOT(filterPackets(QString, bool)));
    connect(&parent, SIGNAL(displayFilterSuccess(bool)),
            this, SLOT(displayFilterSuccess(bool)));
    connect(this, SIGNAL(rtpPlayerDialogReplaceRtpStreams(QVector<rtpstream_id_t *>)),
            &parent, SLOT(rtpPlayerDialogReplaceRtpStreams(QVector<rtpstream_id_t *>)));
    connect(this, SIGNAL(rtpPlayerDialogAddRtpStreams(QVector<rtpstream_id_t *>)),
            &parent, SLOT(rtpPlayerDialogAddRtpStreams(QVector<rtpstream_id_t *>)));
    connect(this, SIGNAL(rtpPlayerDialogRemoveRtpStreams(QVector<rtpstream_id_t *>)),
            &parent, SLOT(rtpPlayerDialogRemoveRtpStreams(QVector<rtpstream_id_t *>)));

    updateWidgets();

    if (cap_file_.isValid()) {
        tapinfo_.session = cap_file_.capFile()->epan;
        cap_file_.delayedRetapPackets();
    }
}

bool VoipCallsDialog::eventFilter(QObject *, QEvent *event)
{
    if (ui->callTreeView->hasFocus() && event->type() == QEvent::KeyPress) {
        QKeyEvent &keyEvent = static_cast<QKeyEvent&>(*event);
        switch(keyEvent.key()) {
            case Qt::Key_I:
                if (keyEvent.modifiers() == Qt::ControlModifier) {
                    // Ctrl+I
                    on_actionSelectInvert_triggered();
                    return true;
                }
                break;
            case Qt::Key_A:
                if (keyEvent.modifiers() == Qt::ControlModifier) {
                    // Ctrl+A
                    on_actionSelectAll_triggered();
                    return true;
                } else if (keyEvent.modifiers() == (Qt::ShiftModifier | Qt::ControlModifier)) {
                    // Ctrl+Shift+A
                    on_actionSelectNone_triggered();
                    return true;
                }
                break;
            case Qt::Key_S:
                on_actionSelectRtpStreams_triggered();
                break;
            case Qt::Key_D:
                on_actionDeselectRtpStreams_triggered();
                break;
            default:
                break;
        }
    }
    return false;
}

VoipCallsDialog::~VoipCallsDialog()
{
    std::lock_guard<std::mutex> lock(init_mutex_);
    if ((all_flows_ && (pinstance_sip_ != nullptr))
        || (!all_flows_ && (pinstance_voip_ != nullptr))
       ) {
        delete ui;

        voip_calls_reset_all_taps(&tapinfo_);
        if (!voip_calls_tap_listeners_removed_) {
            voip_calls_remove_all_tap_listeners(&tapinfo_);
            voip_calls_tap_listeners_removed_ = true;
        }
        sequence_info_->unref();
        g_queue_free(tapinfo_.callsinfos);
        // We don't need to clear shown_callsinfos_ data, it was shared
        // with tapinfo_.callsinfos and was cleared
        // during voip_calls_reset_all_taps
        g_queue_free(shown_callsinfos_);
        if (all_flows_) {
            pinstance_sip_ = nullptr;
        } else {
            pinstance_voip_ = nullptr;
        }
    }
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
    cache_model_->setSourceModel(NULL);
    if (!voip_calls_tap_listeners_removed_) {
        voip_calls_remove_all_tap_listeners(&tapinfo_);
        voip_calls_tap_listeners_removed_ = true;
    }
    tapinfo_.session = NULL;

    WiresharkDialog::captureFileClosing();
}

void VoipCallsDialog::captureFileClosed()
{
    // The time formatting is currently provided by VoipCallsInfoModel, but when
    // the cache is active, the ToD cannot be modified.
    ui->todCheckBox->setEnabled(false);
    ui->displayFilterCheckBox->setEnabled(false);

    WiresharkDialog::captureFileClosed();
}

void VoipCallsDialog::contextMenuEvent(QContextMenuEvent *event)
{
    bool selected = ui->callTreeView->selectionModel()->hasSelection();

    if (! selected)
        return;

    QMenu popupMenu;
    QAction *action;

    popupMenu.addMenu(ui->menuSelect);
    action = popupMenu.addAction(tr("Display time as time of day"), this, SLOT(switchTimeOfDay()));
    action->setCheckable(true);
    action->setChecked(call_infos_model_->timeOfDay());
    action->setEnabled(!file_closed_);
    popupMenu.addSeparator();
    action = popupMenu.addAction(tr("Copy as CSV"), this, SLOT(copyAsCSV()));
    action->setToolTip(tr("Copy stream list as CSV."));
    action = popupMenu.addAction(tr("Copy as YAML"), this, SLOT(copyAsYAML()));
    action->setToolTip(tr("Copy stream list as YAML."));
    popupMenu.addSeparator();
    popupMenu.addAction(ui->actionSelectRtpStreams);
    popupMenu.addAction(ui->actionDeselectRtpStreams);

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

void VoipCallsDialog::captureEvent(CaptureEvent e)
{
    if (e.captureContext() == CaptureEvent::Retap)
    {
        switch (e.eventType())
        {
        case CaptureEvent::Started:
            ui->displayFilterCheckBox->setEnabled(false);
            break;
        case CaptureEvent::Finished:
            ui->displayFilterCheckBox->setEnabled(true);
            break;
        default:
            break;
        }
    }

}

void VoipCallsDialog::tapReset(void *tapinfo_ptr)
{
    voip_calls_tapinfo_t *tapinfo = static_cast<voip_calls_tapinfo_t *>(tapinfo_ptr);
    VoipCallsDialog *voip_calls_dialog = static_cast<VoipCallsDialog *>(tapinfo->tap_data);

    // Create new callsinfos queue in tapinfo. Current callsinfos are
    // in shown_callsinfos_.
    voip_calls_dialog->tapinfo_.callsinfos = g_queue_new();
    voip_calls_reset_all_taps(tapinfo);

    // Leave old graph_analysis as is and allocate new one
    voip_calls_dialog->sequence_info_->unref();
    voip_calls_dialog->tapinfo_.graph_analysis = sequence_analysis_info_new();
    voip_calls_dialog->tapinfo_.graph_analysis->name = "voip";
    voip_calls_dialog->sequence_info_ = new SequenceInfo(voip_calls_dialog->tapinfo_.graph_analysis);
}

tap_packet_status VoipCallsDialog::tapPacket(void *, packet_info *, epan_dissect_t *, const void *, tap_flags_t)
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

gint VoipCallsDialog::compareCallNums(gconstpointer a, gconstpointer b)
{
    const voip_calls_info_t *call_a = (const voip_calls_info_t *)a;
    const voip_calls_info_t *call_b = (const voip_calls_info_t *)b;

    return (call_a->call_num != call_b->call_num);
}

void VoipCallsDialog::updateCalls()
{
    voip_calls_info_t *new_callsinfo;
    voip_calls_info_t *old_callsinfo;
    GList *found;

    ui->callTreeView->setSortingEnabled(false);

    // Merge new callsinfos with old ones
    // It keeps list of calls visible including selected items
    GList *list = g_queue_peek_nth_link(tapinfo_.callsinfos, 0);
    while (list) {
        // Find new callsinfo
        new_callsinfo = gxx_list_data(voip_calls_info_t*, list);
        found = g_queue_find_custom(shown_callsinfos_, new_callsinfo, VoipCallsDialog::compareCallNums);
        if (!found) {
            // New call, add it to list for show
            g_queue_push_tail(shown_callsinfos_, new_callsinfo);
        } else {
            // Existing call
            old_callsinfo = (voip_calls_info_t *)found->data;
            if (new_callsinfo != old_callsinfo) {
                // Replace it
                voip_calls_free_callsinfo(old_callsinfo);
                found->data = new_callsinfo;
            }
        }

        list = gxx_list_next(list);
    }

    // Update model
    call_infos_model_->updateCalls(shown_callsinfos_);

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

    bool enable = selected && have_ga_items && !file_closed_;

    prepare_button_->setEnabled(enable);
    sequence_button_->setEnabled(enable);
    ui->actionSelectRtpStreams->setEnabled(enable);
    ui->actionDeselectRtpStreams->setEnabled(enable);
#if defined(QT_MULTIMEDIA_LIB)
    player_button_->setEnabled(enable);
#endif

    WiresharkDialog::updateWidgets();
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
            frame_numbers += QString("%1,").arg(ga_item->frame_number);
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
    // Bypass this dialog and forward signals to parent
    connect(sequence_dialog, SIGNAL(rtpStreamsDialogSelectRtpStreams(QVector<rtpstream_id_t *>)), &parent_, SLOT(rtpStreamsDialogSelectRtpStreams(QVector<rtpstream_id_t *>)));
    connect(sequence_dialog, SIGNAL(rtpStreamsDialogDeselectRtpStreams(QVector<rtpstream_id_t *>)), &parent_, SLOT(rtpStreamsDialogDeselectRtpStreams(QVector<rtpstream_id_t *>)));
    connect(sequence_dialog, SIGNAL(rtpPlayerDialogReplaceRtpStreams(QVector<rtpstream_id_t *>)), &parent_, SLOT(rtpPlayerDialogReplaceRtpStreams(QVector<rtpstream_id_t *>)));
    connect(sequence_dialog, SIGNAL(rtpPlayerDialogAddRtpStreams(QVector<rtpstream_id_t *>)), &parent_, SLOT(rtpPlayerDialogAddRtpStreams(QVector<rtpstream_id_t *>)));
    connect(sequence_dialog, SIGNAL(rtpPlayerDialogRemoveRtpStreams(QVector<rtpstream_id_t *>)), &parent_, SLOT(rtpPlayerDialogRemoveRtpStreams(QVector<rtpstream_id_t *>)));

    sequence_dialog->setAttribute(Qt::WA_DeleteOnClose);
    sequence_dialog->enableVoIPFeatures();
    sequence_dialog->show();
}

QVector<rtpstream_id_t *>VoipCallsDialog::getSelectedRtpIds()
{
    QVector<rtpstream_id_t *> stream_ids;
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
                if (-1 == stream_ids.indexOf(&(rsi->id))) {
                    // Add only new stream
                    stream_ids << &(rsi->id);
                }
            }
        }
    }

    return stream_ids;
}

void VoipCallsDialog::rtpPlayerReplace()
{
    if (ui->callTreeView->selectionModel()->selectedIndexes().count() < 1) return;

    emit rtpPlayerDialogReplaceRtpStreams(getSelectedRtpIds());
}

void VoipCallsDialog::rtpPlayerAdd()
{
    if (ui->callTreeView->selectionModel()->selectedIndexes().count() < 1) return;

    emit rtpPlayerDialogAddRtpStreams(getSelectedRtpIds());
}

void VoipCallsDialog::rtpPlayerRemove()
{
    if (ui->callTreeView->selectionModel()->selectedIndexes().count() < 1) return;

    emit rtpPlayerDialogRemoveRtpStreams(getSelectedRtpIds());
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

void VoipCallsDialog::selectNone()
{
    ui->callTreeView->clearSelection();
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
    mainApp->clipboard()->setText(stream.readAll());
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
    mainApp->clipboard()->setText(stream.readAll());
}

void VoipCallsDialog::on_buttonBox_clicked(QAbstractButton *button)
{
    if (button == prepare_button_) {
        prepareFilter();
    } else if (button == sequence_button_) {
        showSequence();
    }
}

void VoipCallsDialog::removeAllCalls()
{
    voip_calls_info_t *callsinfo;
    GList *list = NULL;

    call_infos_model_->removeAllCalls();

    /* Free shown callsinfos */
    list = g_queue_peek_nth_link(shown_callsinfos_, 0);
    while (list)
    {
        callsinfo = (voip_calls_info_t *)list->data;
        voip_calls_free_callsinfo(callsinfo);
        list = g_list_next(list);
    }
    g_queue_clear(shown_callsinfos_);
}

void VoipCallsDialog::on_displayFilterCheckBox_toggled(bool checked)
{
    if (!cap_file_.isValid()) {
        return;
    }

    tapinfo_.apply_display_filter = checked;
    removeAllCalls();

    cap_file_.retapPackets();
}

void VoipCallsDialog::on_buttonBox_helpRequested()
{
    mainApp->helpTopicAction(HELP_TELEPHONY_VOIP_CALLS_DIALOG);
}

void VoipCallsDialog::switchTimeOfDay()
{
    bool checked = ! call_infos_model_->timeOfDay();

    ui->todCheckBox->setChecked(checked);
    call_infos_model_->setTimeOfDay(checked);
    ui->callTreeView->resizeColumnToContents(VoipCallsInfoModel::StartTime);
    ui->callTreeView->resizeColumnToContents(VoipCallsInfoModel::StopTime);
}

void VoipCallsDialog::displayFilterSuccess(bool success)
{
    if (success && ui->displayFilterCheckBox->isChecked()) {
        removeAllCalls();
        cap_file_.retapPackets();
    }
}

void VoipCallsDialog::invertSelection()
{
    QModelIndex rootIndex = ui->callTreeView->rootIndex();
    QModelIndex first = sorted_model_->index(0, 0, QModelIndex());
    int numOfItems = sorted_model_->rowCount(rootIndex);
    int numOfCols = sorted_model_->columnCount(rootIndex);
    QModelIndex last = sorted_model_->index(numOfItems - 1, numOfCols - 1, QModelIndex());

    QItemSelection selection(first, last);
    ui->callTreeView->selectionModel()->select(selection, QItemSelectionModel::Toggle);
}

void VoipCallsDialog::on_actionSelectAll_triggered()
{
    ui->callTreeView->selectAll();
}

void VoipCallsDialog::on_actionSelectInvert_triggered()
{
    invertSelection();
}

void VoipCallsDialog::on_actionSelectNone_triggered()
{
    ui->callTreeView->clearSelection();
}

void VoipCallsDialog::on_actionSelectRtpStreams_triggered()
{
    QVector<rtpstream_id_t *>stream_ids = qvector_rtpstream_ids_copy(getSelectedRtpIds());

    emit rtpStreamsDialogSelectRtpStreams(stream_ids);

    qvector_rtpstream_ids_free(stream_ids);
    raise();
}

void VoipCallsDialog::on_actionDeselectRtpStreams_triggered()
{
    QVector<rtpstream_id_t *>stream_ids = qvector_rtpstream_ids_copy(getSelectedRtpIds());

    emit rtpStreamsDialogDeselectRtpStreams(stream_ids);

    qvector_rtpstream_ids_free(stream_ids);
    raise();
}

