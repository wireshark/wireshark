/* lte_mac_statistics_dialog.cpp
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

#include "lte_mac_statistics_dialog.h"

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/tap.h>

#include <epan/dissectors/packet-mac-lte.h>

#include <QFormLayout>
#include <QTreeWidget>
#include <QTreeWidgetItem>

#include "percent_bar_delegate.h"
#include "qt_ui_utils.h"
#include "wireshark_application.h"

// To do:
// - Tidy up common stats. Use HTML tables to line up counters?
// - Add missing controls (RACH, SR checkboxes)

// Whole-UE headings.
enum {
    col_rnti_,
    col_type_,
    col_ueid_,
    // UL-specific
    col_ul_frames_,
    col_ul_bytes_,
    col_ul_mb_s_,
    col_ul_padding_percent_,
    col_ul_retx_,
    // DL-specific
    col_dl_frames_,
    col_dl_bytes_,
    col_dl_mb_s_,
    col_dl_padding_percent_,
    col_dl_crc_failed_,
    col_dl_retx_
};


// Type of tree item, so can set column headings properly.
enum {
    mac_whole_ue_row_type_ = 1000,
    mac_ulsch_packet_count_row_type,
    mac_ulsch_byte_count_row_type,
    mac_dlsch_packet_count_row_type,
    mac_dlsch_byte_count_row_type
};



// Channels (by LCID) data node. Used for UL/DL frames/bytes.
class MacULDLTreeWidgetItem : public QTreeWidgetItem
{
public:
    MacULDLTreeWidgetItem(QTreeWidgetItem *parent, unsigned ueid, unsigned rnti, int row_type) :
        QTreeWidgetItem (parent, row_type),
        ueid_(ueid),
        rnti_(rnti)
    {
        // Init values held for all lcids to 0.
        for (int n=0; n < 11; n++) {
            lcids[n] = 0;
        }

        // Set first column to show what counts in this row mean.
        switch (row_type) {
            case mac_ulsch_packet_count_row_type:
                setText(col_rnti_, "UL Packets");
                break;
            case mac_ulsch_byte_count_row_type:
                setText(col_rnti_, "UL Bytes");
                break;
            case mac_dlsch_packet_count_row_type:
                setText(col_rnti_, "DL Packets");
                break;
            case mac_dlsch_byte_count_row_type:
                setText(col_rnti_, "DL Bytes");
                break;
            default:
                // Should never get here...
                break;
        }
    }

    bool operator< (const QTreeWidgetItem &other) const
    {
        // We want rows with a UE to appear in the order they appear in the row_type enum.
        return type() < other.type();
    }

    void draw()
    {
        // Show current value of counter for each LCID.
        for (int n=0; n < 11; n++) {
            setText(col_type_+n, QString("").sprintf("%u", lcids[n]));
        }
    }

    // Increase value held for lcid by given value.
    void updateLCID(guint8 lcid, guint value)
    {
        lcids[lcid] += value;
    }

    // TODO: not currently used. Delete?
    void update(const mac_lte_tap_info *) {
    }

    // TODO: when SR and RACH checkboxes added, check state and add to expression.
    const QString filterExpression() {
        int direction = (type() == mac_dlsch_packet_count_row_type) ||
                        (type() == mac_dlsch_byte_count_row_type);
        // Create an expression to match with all traffic for this UE, but only in the
        // direction of this row.
        QString filter_expr =
            QString("mac-lte.ueid==%1 && mac-lte.rnti==%2 && mac-lte.direction==%3").
                arg(ueid_).arg(rnti_).arg(direction);
        return filter_expr;
    }

private:
    unsigned ueid_;
    unsigned rnti_;
    int lcids[11];
};



// Whole UE tree item
class MacUETreeWidgetItem : public QTreeWidgetItem
{
public:
    MacUETreeWidgetItem(QTreeWidget *parent, const mac_lte_tap_info *mlt_info) :
        QTreeWidgetItem (parent, mac_whole_ue_row_type_),
        rnti_(0),
        type_(0),
        ueid_(0),
        ul_frames_(0),
        ul_bytes_(0),
        ul_raw_bytes_(0),
        ul_padding_bytes_(0),
        ul_retx_(0),
        dl_frames_(0),
        dl_bytes_(0),
        dl_raw_bytes_(0),
        dl_padding_bytes_(0),
        dl_crc_failed_(0),
        dl_retx_(0)
    {
        // Set fixed fields.
        rnti_ = mlt_info->rnti;
        type_ = mlt_info->rntiType;
        ueid_ = mlt_info->ueid;
        setText(col_rnti_, QString::number(rnti_));
        setText(col_type_, type_ == C_RNTI ? QObject::tr("C-RNTI") : QObject::tr("SPS-RNTI"));
        setText(col_ueid_, QString::number(ueid_));

        // TODO: OK to do this here?
        addDetails();
    }

    // Does this tap-info match this existing UE item?
    bool isMatch(const mac_lte_tap_info *mlt_info) {
        return ((rnti_ == mlt_info->rnti) &&
                (type_ == mlt_info->rntiType) &&
                (ueid_ == mlt_info->ueid));
    }

    // Update this UE according to the tap info
    void update(const mac_lte_tap_info *mlt_info) {
        // Update stats for this UE.

        // Uplink.
        if (mlt_info->direction == DIRECTION_UPLINK) {
            if (mlt_info->isPHYRetx) {
                ul_retx_++;
                return;
            }

            if (mlt_info->crcStatusValid && (mlt_info->crcStatus != crc_success)) {
                // TODO: there is not a column for this...
                //ul_crc_errors_++;
                return;
            }

            // Update time range
            if (ul_frames_ == 0) {
                ul_time_start_ = mlt_info->mac_lte_time;
            }
            ul_time_stop_ = mlt_info->mac_lte_time;

            ul_frames_++;

            // These values needed for padding % calculation.
            ul_raw_bytes_ += mlt_info->raw_length;
            ul_padding_bytes_ += mlt_info->padding_bytes;

            // N.B. Not going to support predefined data in Qt version.
            if (!mlt_info->isPredefinedData) {
                for (int n=0; n < 11; n++) {
                    // Update UL child items
                    ul_frames_item_->updateLCID(n, mlt_info->sdus_for_lcid[n]);
                    ul_bytes_item_->updateLCID(n, mlt_info->bytes_for_lcid[n]);

                    ul_bytes_ += mlt_info->bytes_for_lcid[n];
                }
            }
        }

        // Downlink
        else {
            if (mlt_info->isPHYRetx) {
                dl_retx_++;
                return;
            }

            if (mlt_info->crcStatusValid && (mlt_info->crcStatus != crc_success)) {
                switch (mlt_info->crcStatus) {
                    case crc_fail:
                        dl_crc_failed_++;
                        break;

                    default:
                        // Not a reason we currently care about.
                        break;
                }
                return;
            }

            // Update time range
            if (dl_frames_ == 0) {
                dl_time_start_ = mlt_info->mac_lte_time;
            }
            dl_time_stop_ = mlt_info->mac_lte_time;

            dl_frames_++;

            // These values needed for padding % calculation.
            dl_raw_bytes_ += mlt_info->raw_length;
            dl_padding_bytes_ += mlt_info->padding_bytes;

            // N.B. Not going to support predefined data in Qt version.
            if (!mlt_info->isPredefinedData) {
                for (int n=0; n < 11; n++) {
                    // Update DL child items
                    dl_frames_item_->updateLCID(n, mlt_info->sdus_for_lcid[n]);
                    dl_bytes_item_->updateLCID(n, mlt_info->bytes_for_lcid[n]);

                    dl_bytes_ += mlt_info->bytes_for_lcid[n];
                }
            }
        }
    }

    void addDetails() {
        // Add UL/DL packet and byte counts.
        ul_frames_item_ = new MacULDLTreeWidgetItem(this,  ueid_, rnti_, mac_ulsch_packet_count_row_type);
        ul_bytes_item_ = new MacULDLTreeWidgetItem(this,  ueid_, rnti_, mac_ulsch_byte_count_row_type);
        dl_frames_item_ = new MacULDLTreeWidgetItem(this,  ueid_, rnti_, mac_dlsch_packet_count_row_type);
        dl_bytes_item_ = new MacULDLTreeWidgetItem(this,  ueid_, rnti_, mac_dlsch_byte_count_row_type);

        setExpanded(false);
    }


    // Calculate and return a bandwidth figure, in Mbs
    double calculate_bw(nstime_t *start_time, nstime_t *stop_time, guint32 bytes)
    {
        // Can only calculate bandwidth if have time delta
        if (memcmp(start_time, stop_time, sizeof(nstime_t)) != 0) {
            double elapsed_ms = (((double)stop_time->secs - (double)start_time->secs) * 1000) +
                               (((double)stop_time->nsecs - (double)start_time->nsecs) / 1000000);

            // Only really meaningful if have a few frames spread over time...
            //   For now at least avoid dividing by something very close to 0.0
            if (elapsed_ms < 2.0) {
               return 0.0f;
            }
            return ((bytes * 8) / elapsed_ms) / 1000;
        }
        else {
            return 0.0f;
        }
    }

    void draw() {
        // Fixed fields (rnti, type, ueid) won't change during lifetime of UE entry.

        // Calculate bw now.
        double UL_bw = calculate_bw(&ul_time_start_,
                                    &ul_time_stop_,
                                    ul_bytes_);
        double DL_bw = calculate_bw(&dl_time_start_,
                                    &dl_time_stop_,
                                    dl_bytes_);

        // Set columns with current values.
        setText(col_ul_frames_, QString::number(ul_frames_));
        setText(col_ul_bytes_, QString::number(ul_bytes_));
        setText(col_ul_mb_s_, QString::number(UL_bw));
        setData(col_ul_padding_percent_, Qt::UserRole,
                QVariant::fromValue<double>(ul_raw_bytes_ ?
                                                (((float)ul_padding_bytes_ / (float)ul_raw_bytes_) * 100.0) :
                                                0.0));
        setText(col_ul_retx_, QString::number(ul_retx_));

        setText(col_dl_frames_, QString::number(dl_frames_));
        setText(col_dl_bytes_, QString::number(dl_bytes_));
        setText(col_dl_mb_s_, QString::number(DL_bw));

        setData(col_dl_padding_percent_, Qt::UserRole,
                QVariant::fromValue<double>(dl_raw_bytes_ ?
                                                (((float)dl_padding_bytes_ / (float)dl_raw_bytes_) * 100.0) :
                                                0.0));
        setText(col_dl_crc_failed_, QString::number(dl_crc_failed_));
        setText(col_dl_retx_, QString::number(dl_retx_));

        // Draw child items with channel counts.
        ul_frames_item_->draw();
        ul_bytes_item_->draw();
        dl_frames_item_->draw();
        dl_bytes_item_->draw();
    }

    // < operator.  Compare this item with another item, using the column we are currently sorting on.
    bool operator< (const QTreeWidgetItem &other) const
    {
        if (other.type() != mac_whole_ue_row_type_) return QTreeWidgetItem::operator< (other);
        const MacUETreeWidgetItem *other_row = static_cast<const MacUETreeWidgetItem *>(&other);

        switch (treeWidget()->sortColumn()) {
            case col_rnti_:
                return rnti_ < other_row->rnti_;
            case col_type_:
                return type_ < other_row->type_;
            case col_ueid_:
                return ueid_ < other_row->ueid_;
            // TODO: other fields?
            default:
                break;
        }

        return QTreeWidgetItem::operator< (other);
    }

    // TODO: when SR and RACH checkboxes added, check state and add to expression.
    const QString filterExpression() {
        // Create an expression to match with all traffic for this UE.
        QString filter_expr =
            QString("mac-lte.ueid==%1 && mac-lte.rnti==%2").arg(ueid_).arg(rnti_);
        return filter_expr;
    }

private:
    // Unchanging (key) fields.
    unsigned rnti_;
    unsigned type_;
    unsigned ueid_;

    // UL-specific.
    unsigned ul_frames_;
    unsigned ul_bytes_;
    unsigned ul_raw_bytes_;
    unsigned ul_padding_bytes_;
    nstime_t ul_time_start_;
    nstime_t ul_time_stop_;
    unsigned ul_retx_;

    // DL-specific.
    unsigned dl_frames_;
    unsigned dl_bytes_;
    unsigned dl_raw_bytes_;
    unsigned dl_padding_bytes_;
    nstime_t dl_time_start_;
    nstime_t dl_time_stop_;
    unsigned dl_crc_failed_;
    unsigned dl_retx_;

    // Child nodes storing per-lcid counts.
    MacULDLTreeWidgetItem *ul_frames_item_;
    MacULDLTreeWidgetItem *ul_bytes_item_;
    MacULDLTreeWidgetItem *dl_frames_item_;
    MacULDLTreeWidgetItem *dl_bytes_item_;
};




// Label headings. Show according to which type of tree item is currently selected.
static const QStringList mac_whole_ue_row_labels = QStringList()
        << QObject::tr("RNTI") << QObject::tr("Type") << QObject::tr("UEId")
        << QObject::tr("UL Frames") << QObject::tr("UL Bytes") << QObject::tr("UL MB/s")
        << QObject::tr("UL Padding %") << QObject::tr("UL Re TX")
        << QObject::tr("DL Frames") << QObject::tr("DL Bytes") << QObject::tr("DL MB/s")
        << QObject::tr("DL Padding %") << QObject::tr("DL CRC Failed")
        << QObject::tr("DL ReTX");

static const QStringList mac_channel_counts_labels = QStringList()
        << QObject::tr("") << QObject::tr("CCCH") << QObject::tr("LCID 1") << QObject::tr("LCID 2")
        << QObject::tr("LCID 3") << QObject::tr("LCID 4") << QObject::tr("LCID 5")
        << QObject::tr("LCID 6")
        << QObject::tr("LCID 7") << QObject::tr("LCID 8") << QObject::tr("LCID 9")
        << QObject::tr("LCID 10")
        // 'Blank out' UE-level fields
        << QObject::tr("") << QObject::tr("");



//------------------------------------------------------------------------------------------
// Dialog

// Constructor.
LteMacStatisticsDialog::LteMacStatisticsDialog(QWidget &parent, CaptureFile &cf, const char *filter) :
    TapParameterDialog(parent, cf, HELP_STATS_LTE_MAC_TRAFFIC_DIALOG),
    commonStatsCurrent(false)
{
    setWindowSubtitle(tr("LTE Mac Statistics"));

    clearCommonStats();

    // Create common_stats_grid to appear just above the filter area.
    int statstree_layout_idx = verticalLayout()->indexOf(filterLayout()->widget());
    QGridLayout *common_stats_grid = new QGridLayout();
    verticalLayout()->insertLayout(statstree_layout_idx, common_stats_grid);
    int one_em = fontMetrics().height();
    common_stats_grid->setColumnMinimumWidth(2, one_em * 2);
    common_stats_grid->setColumnStretch(2, 1);
    common_stats_grid->setColumnMinimumWidth(5, one_em * 2);
    common_stats_grid->setColumnStretch(5, 1);


    // Create statistics label.
    commonStatsLabel = new QLabel(this);
    commonStatsLabel ->setObjectName("statisticsLabel");
    commonStatsLabel ->setTextFormat(Qt::RichText);
    commonStatsLabel ->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);
    common_stats_grid->addWidget(commonStatsLabel);


    // XXX Use recent settings instead
    resize(parent.width() * 1, parent.height() * 3 / 4);

    // Will set whole-UE headings originally.
    updateHeaderLabels();

    statsTreeWidget()->setItemDelegateForColumn(col_ul_padding_percent_, new PercentBarDelegate());
    statsTreeWidget()->setItemDelegateForColumn(col_dl_padding_percent_, new PercentBarDelegate());

    statsTreeWidget()->sortByColumn(col_rnti_, Qt::AscendingOrder);

    // Set up column widths.
    // resizeColumnToContents doesn't work well here, so set sizes manually.
    for (int col = 0; col < statsTreeWidget()->columnCount() - 1; col++) {
        switch (col) {
            case col_rnti_:
                statsTreeWidget()->setColumnWidth(col, one_em * 8);
                break;
            case col_ul_frames_:
                statsTreeWidget()->setColumnWidth(col, one_em * 5);
                break;
            case col_ul_bytes_:
                statsTreeWidget()->setColumnWidth(col, one_em * 5);
                break;
            case col_ul_mb_s_:
                statsTreeWidget()->setColumnWidth(col, one_em * 4);
                break;
            case col_ul_padding_percent_:
                statsTreeWidget()->setColumnWidth(col, one_em * 6);
                break;
            case col_ul_retx_:
                statsTreeWidget()->setColumnWidth(col, one_em * 6);
                break;
            case col_dl_frames_:
                statsTreeWidget()->setColumnWidth(col, one_em * 5);
                break;
            case col_dl_bytes_:
                statsTreeWidget()->setColumnWidth(col, one_em * 5);
                break;
            case col_dl_mb_s_:
                statsTreeWidget()->setColumnWidth(col, one_em * 4);
                break;
            case col_dl_padding_percent_:
                statsTreeWidget()->setColumnWidth(col, one_em * 6);
                break;
            case col_dl_crc_failed_:
                statsTreeWidget()->setColumnWidth(col, one_em * 6);
                break;
            case col_dl_retx_:
                statsTreeWidget()->setColumnWidth(col, one_em * 6);
                break;

            default:
                // The rest are numeric
                statsTreeWidget()->setColumnWidth(col, one_em * 4);
                statsTreeWidget()->headerItem()->setTextAlignment(col, Qt::AlignRight);
                break;
        }
    }

    addFilterActions();

    if (filter) {
        setDisplayFilter(filter);
    }

    // Set handler for when the tree item changes to set the appropriate labels.
    connect(statsTreeWidget(), SIGNAL(itemSelectionChanged()),
            this, SLOT(updateHeaderLabels()));
}

// Destructor.
LteMacStatisticsDialog::~LteMacStatisticsDialog()
{
}

// Update system/common counters, and redraw if changed.
void LteMacStatisticsDialog::updateCommonStats(const mac_lte_tap_info *tap_info)
{
    common_stats.all_frames++;

    // For common channels, just update global counters
    switch (tap_info->rntiType) {
        case P_RNTI:
            common_stats.pch_frames++;
            common_stats.pch_bytes += tap_info->single_number_of_bytes;
            common_stats.pch_paging_ids += tap_info->number_of_paging_ids;
            commonStatsCurrent = false;
            break;
        case SI_RNTI:
            common_stats.sib_frames++;
            common_stats.sib_bytes += tap_info->single_number_of_bytes;
            commonStatsCurrent = false;
            break;
        case NO_RNTI:
            common_stats.mib_frames++;
            commonStatsCurrent = false;
            break;
        case RA_RNTI:
            common_stats.rar_frames++;
            common_stats.rar_entries += tap_info->number_of_rars;
            commonStatsCurrent = false;
            break;
        case C_RNTI:
        case SPS_RNTI:
            // UE-specific.
            break;

        default:
            // Error...
            return;
    }

    // Check max UEs/tti counter
    switch (tap_info->direction) {
        case DIRECTION_UPLINK:
            if (tap_info->ueInTTI > common_stats.max_ul_ues_in_tti) {
                common_stats.max_ul_ues_in_tti = tap_info->ueInTTI;
                commonStatsCurrent = false;
            }
            break;
        case DIRECTION_DOWNLINK:
            if (tap_info->ueInTTI > common_stats.max_dl_ues_in_tti) {
                common_stats.max_dl_ues_in_tti = tap_info->ueInTTI;
                commonStatsCurrent = false;
            }
            break;
    }

    if (!commonStatsCurrent) {
        QString stats_tables = "<html><head></head><body>\n";
        stats_tables += QString("<p><b>System:</b> Max UL UEs/TTI=%1       ").arg(common_stats.max_ul_ues_in_tti);
        stats_tables += QString("Max DL UEs/TTI=%1\n").arg(common_stats.max_dl_ues_in_tti);

        stats_tables += QString("<p><b>System broadcast:</b> MIBs=%1       ").arg(common_stats.mib_frames);
        stats_tables += QString("SIBs=%1 (%2 bytes)      ").arg(common_stats.sib_frames).arg(common_stats.sib_bytes);
        stats_tables += QString("<p><b>RACH:</b> RARs=%1 frames (%2 RARs)      ").arg(common_stats.rar_frames).arg(common_stats.rar_entries);
        stats_tables += QString("<p><b>Paging:</b> PCH=%1 (%2 bytes, %3 IDs)      ").
               arg(common_stats.pch_frames).
               arg(common_stats.pch_bytes).
               arg(common_stats.pch_paging_ids);
        stats_tables += "</body>\n";

        commonStatsLabel->setText(stats_tables);

        commonStatsCurrent = true;
    }
}

void LteMacStatisticsDialog::clearCommonStats()
{
    memset(&common_stats, 0, sizeof(common_stats));
}

void LteMacStatisticsDialog::tapReset(void *ws_dlg_ptr)
{
    LteMacStatisticsDialog *ws_dlg = static_cast<LteMacStatisticsDialog *>(ws_dlg_ptr);
    if (!ws_dlg) return;

    ws_dlg->statsTreeWidget()->clear();
    ws_dlg->clearCommonStats();
}

//---------------------------------------------------------------------------------------
// Process tap info from a new packet.
gboolean LteMacStatisticsDialog::tapPacket(void *ws_dlg_ptr, struct _packet_info *, epan_dissect *, const void *mac_lte_tap_info_ptr)
{
    // Look up dialog and tap info.
    LteMacStatisticsDialog *ws_dlg = static_cast<LteMacStatisticsDialog *>(ws_dlg_ptr);
    const mac_lte_tap_info *mlt_info  = (mac_lte_tap_info *) mac_lte_tap_info_ptr;
    if (!ws_dlg || !mlt_info) {
        return FALSE;
    }

    // Update common stats.
    ws_dlg->updateCommonStats(mlt_info);

    // Nothing more to do if tap entry isn't for a UE.
    if ((mlt_info->rntiType != C_RNTI) && (mlt_info->rntiType != SPS_RNTI)) {
        return TRUE;
    }

    // Look for an existing UE to match this tap info.
    MacUETreeWidgetItem *mac_ue_ti = NULL;
    for (int i = 0; i < ws_dlg->statsTreeWidget()->topLevelItemCount(); i++) {
        QTreeWidgetItem *ti = ws_dlg->statsTreeWidget()->topLevelItem(i);
        // Make sure we're looking at a UE entry
        if (ti->type() != mac_whole_ue_row_type_) {
            continue;
        }

        // See if current item matches tap.
        MacUETreeWidgetItem *cur_muds_ti = static_cast<MacUETreeWidgetItem*>(ti);
        if (cur_muds_ti->isMatch(mlt_info)) {
            mac_ue_ti = cur_muds_ti;
            break;
        }
    }

    // If don't find matching UE, create a new one.
    if (!mac_ue_ti) {
        mac_ue_ti = new MacUETreeWidgetItem(ws_dlg->statsTreeWidget(), mlt_info);
        for (int col = 0; col < ws_dlg->statsTreeWidget()->columnCount(); col++) {
            mac_ue_ti->setTextAlignment(col, ws_dlg->statsTreeWidget()->headerItem()->textAlignment(col));
        }
    }

    // Update the UE item with info from tap!
    mac_ue_ti->update(mlt_info);
    return TRUE;
}

// Return total number of frames tapped.
unsigned LteMacStatisticsDialog::getFrameCount()
{
    return common_stats.all_frames;
}

void LteMacStatisticsDialog::tapDraw(void *ws_dlg_ptr)
{
    // Look up dialog.
    LteMacStatisticsDialog *ws_dlg = static_cast<LteMacStatisticsDialog *>(ws_dlg_ptr);
    if (!ws_dlg) {
        return;
    }

    // Go over all of the top-level items.
    for (int i = 0; i < ws_dlg->statsTreeWidget()->topLevelItemCount(); i++) {
        // Get item, make sure its of the whole-UE type.
        QTreeWidgetItem *ti = ws_dlg->statsTreeWidget()->topLevelItem(i);
        if (ti->type() != mac_whole_ue_row_type_) {
            continue;
        }

        // Tell the UE item to draw itself.
        MacUETreeWidgetItem *mac_ue_ti = static_cast<MacUETreeWidgetItem*>(ti);
        mac_ue_ti->draw();
    }

    // Update title
    ws_dlg->setWindowSubtitle(QString("LTE Mac Statistics (%1 UEs, %2 frames)").
                                  arg(ws_dlg->statsTreeWidget()->topLevelItemCount()).arg(ws_dlg->getFrameCount()));
}

const QString LteMacStatisticsDialog::filterExpression()
{
    QString filter_expr;
    if (statsTreeWidget()->selectedItems().count() > 0) {
        QTreeWidgetItem *ti = statsTreeWidget()->selectedItems()[0];

        if (ti->type() == mac_whole_ue_row_type_) {
            MacUETreeWidgetItem *mac_ue_ti = static_cast<MacUETreeWidgetItem*>(ti);
            filter_expr = mac_ue_ti->filterExpression();
        } else {
            MacULDLTreeWidgetItem *mac_channels_ti = static_cast<MacULDLTreeWidgetItem*>(ti);
            filter_expr = mac_channels_ti->filterExpression();
        }
    }
    return filter_expr;
}

void LteMacStatisticsDialog::fillTree()
{
    if (!registerTapListener("mac-lte",
                             this,
                             NULL,
                             TL_REQUIRES_NOTHING,
                             tapReset,
                             tapPacket,
                             tapDraw)) {
        reject();
        return;
    }

    cap_file_.retapPackets();
    tapDraw(this);
    removeTapListeners();
}

void LteMacStatisticsDialog::updateHeaderLabels()
{
    if (statsTreeWidget()->selectedItems().count() > 0 && statsTreeWidget()->selectedItems()[0]->type() == mac_whole_ue_row_type_) {
        // Whole-UE labels
        statsTreeWidget()->setHeaderLabels(mac_whole_ue_row_labels);
    } else if (statsTreeWidget()->selectedItems().count() > 0) {
        switch (statsTreeWidget()->selectedItems()[0]->type()) {
            case mac_ulsch_packet_count_row_type:
            case mac_ulsch_byte_count_row_type:
            case mac_dlsch_packet_count_row_type:
            case mac_dlsch_byte_count_row_type:
                statsTreeWidget()->setHeaderLabels(mac_channel_counts_labels);
                break;

            default:
                break;
        }
    }
    else {
        // Nothing selected yet, but set whole-UE labels.
        statsTreeWidget()->setHeaderLabels(mac_whole_ue_row_labels);
    }
}

void LteMacStatisticsDialog::captureFileClosing()
{
    remove_tap_listener(this);
    updateWidgets();
}

// Stat command + args

static void
lte_mac_statistics_init(const char *args, void*) {
    QStringList args_l = QString(args).split(',');
    QByteArray filter;
    if (args_l.length() > 2) {
        filter = QStringList(args_l.mid(2)).join(",").toUtf8();
    }
    wsApp->emitStatCommandSignal("LteMacStatistics", filter.constData(), NULL);
}

static stat_tap_ui lte_mac_statistics_ui = {
    REGISTER_STAT_GROUP_TELEPHONY_LTE,
    "MAC Statistics",
    "mac-lte,stat",
    lte_mac_statistics_init,
    0,
    NULL
};

extern "C" {
void
    register_tap_listener_qt_lte_mac_statistics(void)
    {
        register_stat_tap_ui(&lte_mac_statistics_ui, NULL);
    }
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
