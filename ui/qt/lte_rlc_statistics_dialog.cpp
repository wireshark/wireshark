/* lte_rlc_statistics_dialog.cpp
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

#include "lte_rlc_statistics_dialog.h"

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/tap.h>

#include <epan/dissectors/packet-rlc-lte.h>

#include <QFormLayout>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QPushButton>

#include "lte_rlc_graph_dialog.h"
#include "qt_ui_utils.h"
#include "wireshark_application.h"

#include "ui/recent.h"

// TODO: have lost the ability to filter on only UL or DL of a channel.
// - can we override the context menu inherited from TapParameterDialog?

enum {
    col_ueid_,
    col_mode_,     // channel only
    col_priority_, // channel only
    col_ul_frames_,
    col_ul_bytes_,
    col_ul_mb_s_,
    col_ul_acks_,
    col_ul_nacks_,
    col_ul_missing_,
    col_dl_frames_,
    col_dl_bytes_,
    col_dl_mb_s_,
    col_dl_acks_,
    col_dl_nacks_,
    col_dl_missing_
};

enum {
    rlc_ue_row_type_ = 1000,
    rlc_channel_row_type_
};

/* Calculate and return a bandwidth figure, in Mbs */
static float calculate_bw(nstime_t *start_time, nstime_t *stop_time, guint32 bytes)
{
    /* Can only calculate bandwidth if have time delta */
    if (memcmp(start_time, stop_time, sizeof(nstime_t)) != 0) {
        float elapsed_ms = (((float)stop_time->secs - (float)start_time->secs) * 1000) +
                           (((float)stop_time->nsecs - (float)start_time->nsecs) / 1000000);

        /* Only really meaningful if have a few frames spread over time...
           For now at least avoid dividing by something very close to 0.0 */
        if (elapsed_ms < 2.0) {
           return 0.0f;
        }
        float bw = ((bytes * 8) / elapsed_ms) / 1000;
        if (bw < 0.0001) {
            // Very small values aren't interesting/useful, and would rather see 0 than scientific notation.
            return 0.0f;
        }
        else
        {
            return bw;
        }
    }
    else {
        return 0.0f;
    }
}


// Stats kept for one channel.
typedef struct rlc_channel_stats {
    guint8   inUse;
    guint8   rlcMode;
    guint8   priority;
    guint16  channelType;
    guint16  channelId;

    guint32  UL_frames;
    guint32  UL_bytes;
    nstime_t UL_time_start;
    nstime_t UL_time_stop;
    gboolean UL_has_data; // i.e. not just ACKs for DL.

    guint32  DL_frames;
    guint32  DL_bytes;
    nstime_t DL_time_start;
    nstime_t DL_time_stop;
    gboolean DL_has_data;  // i.e. not just ACKs for UL.

    guint32  UL_acks;
    guint32  UL_nacks;

    guint32  DL_acks;
    guint32  DL_nacks;

    guint32  UL_missing;
    guint32  DL_missing;
} rlc_channel_stats;

//-------------------------------------------------------------------
// Channel item.
//-------------------------------------------------------------------
class RlcChannelTreeWidgetItem : public QTreeWidgetItem
{
public:
    RlcChannelTreeWidgetItem(QTreeWidgetItem *parent,
                             unsigned ueid,
                             unsigned mode,
                             unsigned channelType, unsigned channelId) :
        QTreeWidgetItem(parent, rlc_channel_row_type_),
        ueid_(ueid),
        channelType_(channelType),
        channelId_(channelId),
        mode_(mode),
        priority_(0)
    {
        QString mode_str;
        switch (mode_) {
            case RLC_TM_MODE:
                mode_str = QObject::tr("TM");
                break;
            case RLC_UM_MODE:
                mode_str = QObject::tr("UM");
                break;
            case RLC_AM_MODE:
                mode_str = QObject::tr("AM");
                break;
            case RLC_PREDEF:
                mode_str = QObject::tr("Predef");
                break;

            default:
                mode_str = QObject::tr("Unknown (%1)").arg(mode_);
                break;
        }

        // Set name of channel.
        switch (channelType) {
            case CHANNEL_TYPE_CCCH:
                setText(col_ueid_, QObject::tr("CCCH"));
                break;
            case CHANNEL_TYPE_SRB:
                setText(col_ueid_, QObject::tr("SRB-%1").arg(channelId));
                break;
            case CHANNEL_TYPE_DRB:
                setText(col_ueid_, QObject::tr("DRB-%1").arg(channelId));
                break;

            default:
                setText(col_ueid_, QObject::tr("Unknown"));
                break;
        }

        // Zero out stats.
        memset(&stats_, 0, sizeof(stats_));

        // TODO: could change, but should only reset string if changes.
        setText(col_mode_, mode_str);
    }

    // Update UE/channels from tap info.
    void update(const rlc_lte_tap_info *tap_info) {

        // Copy these fields into UE stats.
        if (tap_info->rlcMode != stats_.rlcMode) {
            stats_.rlcMode = tap_info->rlcMode;
            // TODO: update the column string!
        }

        // TODO: these 2 really shouldn't change!!
        stats_.channelType = tap_info->channelType;
        stats_.channelId = tap_info->channelId;

        if (tap_info->priority != 0) {
            priority_ = tap_info->priority;
        }

        if (tap_info->direction == DIRECTION_UPLINK) {
            // Update time range.
            if (stats_.UL_frames == 0) {
                stats_.UL_time_start = tap_info->rlc_lte_time;
            }
            stats_.UL_time_stop = tap_info->rlc_lte_time;

            stats_.UL_frames++;
            stats_.UL_bytes += tap_info->pduLength;
            stats_.UL_nacks += tap_info->noOfNACKs;
            stats_.UL_missing += tap_info->missingSNs;
            if (tap_info->isControlPDU) {
                stats_.UL_acks++;
            }
            else {
                stats_.UL_has_data = TRUE;
            }
        }
        else {
            // Update time range.
            if (stats_.DL_frames == 0) {
                stats_.DL_time_start = tap_info->rlc_lte_time;
            }
            stats_.DL_time_stop = tap_info->rlc_lte_time;

            stats_.DL_frames++;
            stats_.DL_bytes += tap_info->pduLength;
            stats_.DL_nacks += tap_info->noOfNACKs;
            stats_.DL_missing += tap_info->missingSNs;
            if (tap_info->isControlPDU) {
                stats_.DL_acks++;
            }
            else {
                stats_.DL_has_data = TRUE;
            }
        }
    }

    void draw() {
        // Calculate bandwidth.
        float UL_bw = calculate_bw(&stats_.UL_time_start,
                                   &stats_.UL_time_stop,
                                   stats_.UL_bytes);
        float DL_bw = calculate_bw(&stats_.DL_time_start,
                                   &stats_.DL_time_stop,
                                   stats_.DL_bytes);

        // Priority
        setText(col_priority_,   QString::number(priority_));

        // Uplink.
        setText(col_ul_frames_,  QString::number(stats_.UL_frames));
        setText(col_ul_bytes_,   QString::number(stats_.UL_bytes));
        setText(col_ul_mb_s_,    bits_s_to_qstring(UL_bw));
        setText(col_ul_acks_,    QString::number(stats_.UL_acks));
        setText(col_ul_nacks_,   QString::number(stats_.UL_nacks));
        setText(col_ul_missing_, QString::number(stats_.UL_missing));

        // Downlink.
        setText(col_dl_frames_,  QString::number(stats_.DL_frames));
        setText(col_dl_bytes_,   QString::number(stats_.DL_bytes));
        setText(col_ul_mb_s_,    bits_s_to_qstring(DL_bw));
        setText(col_dl_acks_,    QString::number(stats_.DL_acks));
        setText(col_dl_nacks_,   QString::number(stats_.DL_nacks));
        setText(col_dl_missing_, QString::number(stats_.DL_missing));
    }

    bool operator< (const QTreeWidgetItem &other) const
    {
        if (other.type() != rlc_channel_row_type_) return QTreeWidgetItem::operator< (other);
        const RlcChannelTreeWidgetItem *other_row = static_cast<const RlcChannelTreeWidgetItem *>(&other);

        // Switch by selected column.
        switch (treeWidget()->sortColumn()) {
            case col_ueid_:
                // This is channel name. Rank CCCH before SRB before DRB, then channel ID.
                return channelRank() < other_row->channelRank();
            case col_mode_:
                return mode_ < other_row->mode_;
            case col_priority_:
                return priority_ < other_row->priority_;
            default:
                break;
        }

        return QTreeWidgetItem::operator< (other);
    }

    const QString filterExpression(bool showSR, bool showRACH) {
        // Create an expression to match with all traffic for this UE.
        QString filter_expr;

        // Are we taking RLC PDUs from MAC, or not?
        if (!recent.gui_rlc_use_pdus_from_mac) {
            filter_expr += QString("not mac-lte and ");
        }
        else {
            filter_expr += QString("mac-lte and ");
        }

        if (showSR) {
            filter_expr += QString("(mac-lte.sr-req and mac-lte.ueid == %1) or (").arg(ueid_);
        }

        if (showRACH) {
            filter_expr += QString("(mac-lte.rar or (mac-lte.preamble-sent and mac-lte.ueid == %1)) or (").arg(ueid_);
        }

        // Main part of expression.
        filter_expr += QString("rlc-lte.ueid==%1 and rlc-lte.channel-type == %2").
                                  arg(ueid_).arg(channelType_);
        if ((channelType_ == CHANNEL_TYPE_SRB) || (channelType_ == CHANNEL_TYPE_DRB)) {
            filter_expr += QString(" and rlc-lte.channel-id == %1").arg(channelId_);
        }

        // Close () if open because of SR
        if (showSR) {
            filter_expr += QString(")");
        }
        // Close () if open because of RACH
        if (showRACH) {
            filter_expr += QString(")");
        }

        return filter_expr;
    }

    // Accessors (queried for launching graph)
    unsigned get_ueid() const { return ueid_; }
    unsigned get_channelType() const { return channelType_; }
    unsigned get_channelId() const { return channelId_; }
    unsigned get_mode() const { return mode_; }

    bool     hasULData() const { return stats_.UL_has_data != 0; }
    bool     hasDLData() const { return stats_.DL_has_data != 0; }

private:
    unsigned ueid_;
    unsigned channelType_;
    unsigned channelId_;
    unsigned mode_;
    unsigned priority_;

    unsigned channelRank() const
    {
        switch (channelType_) {
            case CHANNEL_TYPE_CCCH:
                return 0;
            case CHANNEL_TYPE_SRB:
                return channelId_;
            case CHANNEL_TYPE_DRB:
                return 3 + channelId_;
            default:
                // Shouldn't really get here..
                return 0;
        }
    }

    rlc_channel_stats stats_;
};


// Stats for one UE.  TODO: private to class?
typedef struct rlc_ue_stats {

    guint32  UL_frames;
    guint32  UL_total_bytes;
    nstime_t UL_time_start;
    nstime_t UL_time_stop;
    guint32  UL_total_acks;
    guint32  UL_total_nacks;
    guint32  UL_total_missing;

    guint32  DL_frames;
    guint32  DL_total_bytes;
    nstime_t DL_time_start;
    nstime_t DL_time_stop;
    guint32  DL_total_acks;
    guint32  DL_total_nacks;
    guint32  DL_total_missing;

} rlc_ue_stats;

//-------------------------------------------------------------------
// UE item.
//-------------------------------------------------------------------
class RlcUeTreeWidgetItem : public QTreeWidgetItem
{
public:
    RlcUeTreeWidgetItem(QTreeWidget *parent, const rlc_lte_tap_info *rlt_info) :
        QTreeWidgetItem (parent, rlc_ue_row_type_),
        ueid_(0)
    {
        ueid_ = rlt_info->ueid;
        setText(col_ueid_, QString::number(ueid_));

        // We create RlcChannelTreeWidgetItems when first data on new channel is seen.
        // Of course, there will be a channel associated with the PDU
        // that causes this UE item to be created...
        memset(&stats_, 0, sizeof(stats_));
        CCCH_stats_ = NULL;
        for (int srb=0; srb < 2; srb++) {
            srb_stats_[srb] = NULL;
        }
        for (int drb=0; drb < 32; drb++) {
            drb_stats_[drb] = NULL;
        }
    }

    bool isMatch(const rlc_lte_tap_info *rlt_info) {
        return ueid_ == rlt_info->ueid;
    }

    // Update UE/channels from tap info.
    void update(const rlc_lte_tap_info *tap_info) {

        // Are we ignoring RLC frames that were found in MAC frames, or only those
        // that were logged separately?
        if ((!recent.gui_rlc_use_pdus_from_mac && tap_info->loggedInMACFrame) ||
            (recent.gui_rlc_use_pdus_from_mac  && !tap_info->loggedInMACFrame)) {
            return;
        }

        // TODO: update title with number of UEs and frames like MAC does?

        // N.B. not really expecting to see common stats - ignoring them.
        switch (tap_info->channelType) {
            case CHANNEL_TYPE_BCCH_BCH:
            case CHANNEL_TYPE_BCCH_DL_SCH:
            case CHANNEL_TYPE_PCCH:
                return;

            default:
                // Drop through for UE-specific.
                break;
        }

        // UE-level traffic stats.
        if (tap_info->direction == DIRECTION_UPLINK) {
            // Update time range.
            if (stats_.UL_frames == 0) {
                stats_.UL_time_start = tap_info->rlc_lte_time;
            }
            stats_.UL_time_stop = tap_info->rlc_lte_time;

            stats_.UL_frames++;
            stats_.UL_total_bytes += tap_info->pduLength;

            // Status PDU counters.
            if (tap_info->isControlPDU) {
                stats_.UL_total_acks++;
                stats_.UL_total_nacks += tap_info->noOfNACKs;
            }

            stats_.UL_total_missing += tap_info->missingSNs;
        }
        else {
            // Update time range.
            if (stats_.DL_frames == 0) {
                stats_.DL_time_start = tap_info->rlc_lte_time;
            }
            stats_.DL_time_stop = tap_info->rlc_lte_time;

            stats_.DL_frames++;
            stats_.DL_total_bytes += tap_info->pduLength;

            // Status PDU counters.
            if (tap_info->isControlPDU) {
                stats_.DL_total_acks++;
                stats_.DL_total_nacks += tap_info->noOfNACKs;
            }

            stats_.DL_total_missing += tap_info->missingSNs;
        }

        RlcChannelTreeWidgetItem *channel_item;

        // Find or create tree item for this channel.
        switch (tap_info->channelType) {
            case CHANNEL_TYPE_CCCH:
                channel_item = CCCH_stats_;
                if (channel_item == NULL) {
                    channel_item = CCCH_stats_ =
                            new RlcChannelTreeWidgetItem(this, tap_info->ueid, RLC_TM_MODE,
                                                         tap_info->channelType, tap_info->channelId);
                }
                break;

            case CHANNEL_TYPE_SRB:
                channel_item = srb_stats_[tap_info->channelId-1];
                if (channel_item == NULL) {
                    channel_item = srb_stats_[tap_info->channelId-1] =
                            new RlcChannelTreeWidgetItem(this, tap_info->ueid, RLC_AM_MODE,
                                                         tap_info->channelType, tap_info->channelId);
                }
                break;

            case CHANNEL_TYPE_DRB:
                channel_item = drb_stats_[tap_info->channelId-1];
                if (channel_item == NULL) {
                    channel_item = drb_stats_[tap_info->channelId-1] =
                            new RlcChannelTreeWidgetItem(this, tap_info->ueid, tap_info->rlcMode,
                                                         tap_info->channelType, tap_info->channelId);
                }
                break;

            default:
                // Shouldn't get here...
                return;
        }

        // Update channel with tap_info.
        if (channel_item != NULL) {
            channel_item->update(tap_info);
        }
    }


    void draw() {
        // Fixed fields only drawn once from constructor so don't redraw here.

        /* Calculate bandwidth */
        float UL_bw = calculate_bw(&stats_.UL_time_start,
                                   &stats_.UL_time_stop,
                                   stats_.UL_total_bytes);
        float DL_bw = calculate_bw(&stats_.DL_time_start,
                                   &stats_.DL_time_stop,
                                   stats_.DL_total_bytes);

        // Uplink.
        setText(col_ul_frames_,  QString::number(stats_.UL_frames));
        setText(col_ul_bytes_,   QString::number(stats_.UL_total_bytes));
        setText(col_ul_mb_s_,    bits_s_to_qstring(UL_bw));
        setText(col_ul_acks_,    QString::number(stats_.UL_total_acks));
        setText(col_ul_nacks_,   QString::number(stats_.UL_total_nacks));
        setText(col_ul_missing_, QString::number(stats_.UL_total_missing));

        // Downlink.
        setText(col_dl_frames_,  QString::number(stats_.DL_frames));
        setText(col_dl_bytes_,   QString::number(stats_.DL_total_bytes));
        setText(col_dl_mb_s_,    bits_s_to_qstring(DL_bw));
        setText(col_dl_acks_,    QString::number(stats_.DL_total_acks));
        setText(col_dl_nacks_,   QString::number(stats_.DL_total_nacks));
        setText(col_dl_missing_, QString::number(stats_.DL_total_missing));

        // Call draw() for each channel present.
        if (CCCH_stats_ != NULL) {
            CCCH_stats_->draw();
        }
        for (int srb=0; srb < 2; srb++) {
            if (srb_stats_[srb] != NULL) {
                srb_stats_[srb]->draw();
            }
        }
        for (int drb=0; drb < 32; drb++) {
            if (drb_stats_[drb] != NULL) {
                drb_stats_[drb]->draw();
            }
        }
    }

    bool operator< (const QTreeWidgetItem &other) const
    {
        if (other.type() != rlc_ue_row_type_) return QTreeWidgetItem::operator< (other);
        const RlcUeTreeWidgetItem *other_row = static_cast<const RlcUeTreeWidgetItem *>(&other);

        switch (treeWidget()->sortColumn()) {
            case col_ueid_:
                return ueid_ < other_row->ueid_;
            default:
                break;
        }

        return QTreeWidgetItem::operator< (other);
    }

    const QString filterExpression(bool showSR, bool showRACH) {
        // Create an expression to match with all traffic for this UE.
        QString filter_expr;

        // Are we taking RLC PDUs from MAC, or not?
        if (!recent.gui_rlc_use_pdus_from_mac) {
            filter_expr += QString("not mac-lte and ");
        }
        else {
            filter_expr += QString("mac-lte and ");
        }

        if (showSR) {
            filter_expr += QString("(mac-lte.sr-req and mac-lte.ueid == %1) or (").arg(ueid_);
        }

        if (showRACH) {
            filter_expr += QString("(mac-lte.rar or (mac-lte.preamble-sent and mac-lte.ueid == %1)) or (").arg(ueid_);
        }

        filter_expr += QString("rlc-lte.ueid==%1").arg(ueid_);

        // Close () if open because of SR
        if (showSR) {
            filter_expr += QString(")");
        }
        // Close () if open because of RACH
        if (showRACH) {
            filter_expr += QString(")");
        }

        return filter_expr;
    }

private:
    unsigned ueid_;
    rlc_ue_stats stats_;

    // Channel counters stored in channel sub-items.
    RlcChannelTreeWidgetItem* CCCH_stats_;
    RlcChannelTreeWidgetItem* srb_stats_[2];
    RlcChannelTreeWidgetItem* drb_stats_[32];
};


// Only the first 3 columns headings differ between UE and channel rows.
static const QString ue_col_0_title_ = QObject::tr("UE Id");
static const QString ue_col_1_title_ = "";
static const QString ue_col_2_title_ = "";

static const QString channel_col_0_title_ = QObject::tr("Name");
static const QString channel_col_1_title_ = QObject::tr("Mode");
static const QString channel_col_2_title_ = QObject::tr("Priority");



//------------------------------------------------------------------------------------------
// Dialog

// Constructor.
LteRlcStatisticsDialog::LteRlcStatisticsDialog(QWidget &parent, CaptureFile &cf, const char *filter) :
    TapParameterDialog(parent, cf, HELP_STATS_LTE_MAC_TRAFFIC_DIALOG),
    cf_(cf),
    packet_count_(0)
{
    setWindowSubtitle(tr("LTE RLC Statistics"));
    loadGeometry((parent.width() * 5) / 5, (parent.height() * 3) / 4, "LTERLCStatisticsDialog");

    // Create a grid for filtering-related widgetsto also appear in layout.
    int filter_controls_layout_idx = verticalLayout()->indexOf(filterLayout()->widget());
    QGridLayout *filter_controls_grid = new QGridLayout();
    // Insert into the vertical layout
    verticalLayout()->insertLayout(filter_controls_layout_idx, filter_controls_grid);
    int one_em = fontMetrics().height();
    filter_controls_grid->setColumnMinimumWidth(2, one_em * 2);
    filter_controls_grid->setColumnStretch(2, 1);
    filter_controls_grid->setColumnMinimumWidth(5, one_em * 2);
    filter_controls_grid->setColumnStretch(5, 1);

    // Add individual controls into the grid
    launchULGraph_ = new QPushButton(QString("Launch UL Graph"));
    launchULGraph_->setEnabled(false);
    filter_controls_grid->addWidget(launchULGraph_);
    connect(launchULGraph_, SIGNAL(pressed()), this, SLOT(launchULGraphButtonClicked()));
    launchDLGraph_ = new QPushButton(QString("Launch DL Graph"));
    launchDLGraph_->setEnabled(false);
    filter_controls_grid->addWidget(launchDLGraph_);
    connect(launchDLGraph_, SIGNAL(pressed()), this, SLOT(launchDLGraphButtonClicked()));

    showSRFilterCheckBox_ = new QCheckBox(tr("Include SR frames in filter"));
    filter_controls_grid->addWidget(showSRFilterCheckBox_);
    showRACHFilterCheckBox_ = new QCheckBox(tr("Include RACH frames in filter"));
    filter_controls_grid->addWidget(showRACHFilterCheckBox_);

    useRLCFramesFromMacCheckBox_ = new QCheckBox(tr("Use RLC frames only from MAC frames"));
    useRLCFramesFromMacCheckBox_->setCheckState(recent.gui_rlc_use_pdus_from_mac ?
                                                    Qt::Checked :
                                                    Qt::Unchecked);
    connect(useRLCFramesFromMacCheckBox_, SIGNAL(clicked(bool)), this,
            SLOT(useRLCFramesFromMacCheckBoxToggled(bool)));
    filter_controls_grid->addWidget(useRLCFramesFromMacCheckBox_);

    QStringList header_labels = QStringList()
            << "" << "" << ""
            << tr("UL Frames") << tr("UL Bytes") << tr("UL MB/s")
            << tr("UL ACKs") << tr("UL NACKs") << tr("UL Missing")
            << tr("DL Frames") << tr("DL Bytes") << tr("DL MB/s")
            << tr("DL ACKs") << tr("DL NACKs") << tr("DL Missing");
    statsTreeWidget()->setHeaderLabels(header_labels);
    updateHeaderLabels();

    statsTreeWidget()->sortByColumn(col_ueid_, Qt::AscendingOrder);

    // resizeColumnToContents doesn't work well here, so set sizes manually.
    for (int col = 0; col < statsTreeWidget()->columnCount() - 1; col++) {
        switch (col) {
            case col_ueid_:
                statsTreeWidget()->setColumnWidth(col, one_em * 7);
                break;
            case col_ul_frames_:
            case col_dl_frames_:
                statsTreeWidget()->setColumnWidth(col, one_em * 5);
                break;
            case col_ul_acks_:
            case col_dl_acks_:
                statsTreeWidget()->setColumnWidth(col, one_em * 5);
                break;
            case col_ul_nacks_:
            case col_dl_nacks_:
                statsTreeWidget()->setColumnWidth(col, one_em * 6);
                break;
            case col_ul_missing_:
            case col_dl_missing_:
                statsTreeWidget()->setColumnWidth(col, one_em * 7);
                break;
            case col_ul_mb_s_:
            case col_dl_mb_s_:
                statsTreeWidget()->setColumnWidth(col, one_em * 6);
                break;

            default:
                // The rest are numeric.
                statsTreeWidget()->setColumnWidth(col, one_em * 4);
                break;
        }
    }

    addFilterActions();

    if (filter) {
        setDisplayFilter(filter);
    }

    // Set handler for when the tree item changes to set the appropriate labels.
    connect(statsTreeWidget(), SIGNAL(itemSelectionChanged()),
            this, SLOT(updateItemSelectionChanged()));
}

// Destructor.
LteRlcStatisticsDialog::~LteRlcStatisticsDialog()
{
}

void LteRlcStatisticsDialog::tapReset(void *ws_dlg_ptr)
{
    LteRlcStatisticsDialog *ws_dlg = static_cast<LteRlcStatisticsDialog *>(ws_dlg_ptr);
    if (!ws_dlg) {
        return;
    }

    // Clears/deletes all UEs.
    ws_dlg->statsTreeWidget()->clear();
    ws_dlg->packet_count_ = 0;
}

// Process the tap info from a dissected RLC PDU.
gboolean LteRlcStatisticsDialog::tapPacket(void *ws_dlg_ptr, struct _packet_info *, epan_dissect *, const void *rlc_lte_tap_info_ptr)
{
    // Look up dialog.
    LteRlcStatisticsDialog *ws_dlg = static_cast<LteRlcStatisticsDialog *>(ws_dlg_ptr);
    const rlc_lte_tap_info *rlt_info  = (rlc_lte_tap_info *) rlc_lte_tap_info_ptr;
    if (!ws_dlg || !rlt_info) {
        return FALSE;
    }

    ws_dlg->incFrameCount();

    // Look for this UE (linear search...).
    RlcUeTreeWidgetItem *ue_ti = NULL;
    for (int i = 0; i < ws_dlg->statsTreeWidget()->topLevelItemCount(); i++) {
        QTreeWidgetItem *ti = ws_dlg->statsTreeWidget()->topLevelItem(i);
        if (ti->type() != rlc_ue_row_type_) continue;
        RlcUeTreeWidgetItem *cur_ru_ti = static_cast<RlcUeTreeWidgetItem*>(ti);

        if (cur_ru_ti->isMatch(rlt_info)) {
            ue_ti = cur_ru_ti;
            break;
        }
    }

    if (!ue_ti) {
        // Existing UE wasn't found so create a new one.
        ue_ti = new RlcUeTreeWidgetItem(ws_dlg->statsTreeWidget(), rlt_info);
        for (int col = 0; col < ws_dlg->statsTreeWidget()->columnCount(); col++) {
            ue_ti->setTextAlignment(col, ws_dlg->statsTreeWidget()->headerItem()->textAlignment(col));
        }
    }

    // Update the UE from the information in the tap structure.
    ue_ti->update(rlt_info);

    return TRUE;
}

void LteRlcStatisticsDialog::tapDraw(void *ws_dlg_ptr)
{
    // Look up UE.
    LteRlcStatisticsDialog *ws_dlg = static_cast<LteRlcStatisticsDialog *>(ws_dlg_ptr);
    if (!ws_dlg) return;

    // Draw each UE.
    for (int i = 0; i < ws_dlg->statsTreeWidget()->topLevelItemCount(); i++) {
        QTreeWidgetItem *ti = ws_dlg->statsTreeWidget()->topLevelItem(i);
        if (ti->type() != rlc_ue_row_type_) continue;

        RlcUeTreeWidgetItem *ru_ti = static_cast<RlcUeTreeWidgetItem*>(ti);
        ru_ti->draw();
    }

    // Update title
    ws_dlg->setWindowSubtitle(QString("LTE RLC Statistics (%1 UEs, %2 frames)").
                                  arg(ws_dlg->statsTreeWidget()->topLevelItemCount()).arg(ws_dlg->getFrameCount()));
}

void LteRlcStatisticsDialog::useRLCFramesFromMacCheckBoxToggled(bool state)
{
    // Update state to be stored in recent preferences
    recent.gui_rlc_use_pdus_from_mac = state;

    // Retap to get updated list of PDUs
    fillTree();
}

const QString LteRlcStatisticsDialog::filterExpression()
{
    QString filter_expr;
    if (statsTreeWidget()->selectedItems().count() > 0) {
        QTreeWidgetItem *ti = statsTreeWidget()->selectedItems()[0];

        // Generate expression according to what type of item is selected.
        if (ti->type() == rlc_ue_row_type_) {
            RlcUeTreeWidgetItem *ru_ti = static_cast<RlcUeTreeWidgetItem*>(ti);
            filter_expr = ru_ti->filterExpression(showSRFilterCheckBox_->checkState() > Qt::Unchecked,
                                                  showRACHFilterCheckBox_->checkState() > Qt::Unchecked);
        } else if (ti->type() == rlc_channel_row_type_) {
            RlcChannelTreeWidgetItem *rc_ti = static_cast<RlcChannelTreeWidgetItem*>(ti);
            filter_expr = rc_ti->filterExpression(showSRFilterCheckBox_->checkState() > Qt::Unchecked,
                                                  showRACHFilterCheckBox_->checkState() > Qt::Unchecked);
        }
    }
    return filter_expr;
}

void LteRlcStatisticsDialog::fillTree()
{
    if (!registerTapListener("rlc-lte",
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

void LteRlcStatisticsDialog::updateItemSelectionChanged()
{
    updateHeaderLabels();

    bool enableULGraphButton = false, enableDLGraphButton = false;
    if (statsTreeWidget()->selectedItems().count() > 0 && statsTreeWidget()->selectedItems()[0]->type() == rlc_channel_row_type_) {
        QTreeWidgetItem *ti = statsTreeWidget()->selectedItems()[0];
        RlcChannelTreeWidgetItem *rc_ti = static_cast<RlcChannelTreeWidgetItem*>(ti);
        enableULGraphButton = rc_ti->hasULData();
        enableDLGraphButton = rc_ti->hasDLData();
    }

    // Only enabling graph buttons for channel entries.
    launchULGraph_->setEnabled(enableULGraphButton);
    launchDLGraph_->setEnabled(enableDLGraphButton);
}

void LteRlcStatisticsDialog::updateHeaderLabels()
{
    if (statsTreeWidget()->selectedItems().count() > 0 && statsTreeWidget()->selectedItems()[0]->type() == rlc_channel_row_type_) {
        statsTreeWidget()->headerItem()->setText(col_ueid_, channel_col_0_title_);
        statsTreeWidget()->headerItem()->setText(col_mode_, channel_col_1_title_);
        statsTreeWidget()->headerItem()->setText(col_priority_, channel_col_2_title_);
    } else {
        statsTreeWidget()->headerItem()->setText(col_ueid_, ue_col_0_title_);
        statsTreeWidget()->headerItem()->setText(col_mode_, ue_col_1_title_);
        statsTreeWidget()->headerItem()->setText(col_priority_, ue_col_2_title_);
    }
}

void LteRlcStatisticsDialog::captureFileClosing()
{
    remove_tap_listener(this);
    updateWidgets();

    WiresharkDialog::captureFileClosing();
}

// Launch a UL graph for the currently-selected channel.
void LteRlcStatisticsDialog::launchULGraphButtonClicked()
{
    if (statsTreeWidget()->selectedItems().count() > 0 && statsTreeWidget()->selectedItems()[0]->type() == rlc_channel_row_type_) {
        // Get the channel item.
        QTreeWidgetItem *ti = statsTreeWidget()->selectedItems()[0];
        RlcChannelTreeWidgetItem *rc_ti = static_cast<RlcChannelTreeWidgetItem*>(ti);
        emit launchRLCGraph(true,
                            rc_ti->get_ueid(),
                            rc_ti->get_mode(),
                            rc_ti->get_channelType(),
                            rc_ti->get_channelId(),
                            DIRECTION_UPLINK);
    }
}

// Launch a DL graph for the currently-selected channel.
void LteRlcStatisticsDialog::launchDLGraphButtonClicked()
{
    if (statsTreeWidget()->selectedItems().count() > 0 && statsTreeWidget()->selectedItems()[0]->type() == rlc_channel_row_type_) {
        // Get the channel item.
        QTreeWidgetItem *ti = statsTreeWidget()->selectedItems()[0];
        RlcChannelTreeWidgetItem *rc_ti = static_cast<RlcChannelTreeWidgetItem*>(ti);
        emit launchRLCGraph(true,
                            rc_ti->get_ueid(),
                            rc_ti->get_mode(),
                            rc_ti->get_channelType(),
                            rc_ti->get_channelId(),
                            DIRECTION_DOWNLINK);
    }
}

// Stat command + args

static void
lte_rlc_statistics_init(const char *args, void*) {
    QStringList args_l = QString(args).split(',');
    QByteArray filter;
    if (args_l.length() > 2) {
        filter = QStringList(args_l.mid(2)).join(",").toUtf8();
    }
    wsApp->emitStatCommandSignal("LteRlcStatistics", filter.constData(), NULL);
}

static stat_tap_ui lte_rlc_statistics_ui = {
    REGISTER_STAT_GROUP_TELEPHONY_LTE,
    "RLC Statistics",
    "rlc-lte,stat",
    lte_rlc_statistics_init,
    0,
    NULL
};

extern "C" {
void
register_tap_listener_qt_lte_rlc_statistics(void)
{
    register_stat_tap_ui(&lte_rlc_statistics_ui, NULL);
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
