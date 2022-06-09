/* lte_mac_statistics_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "lte_mac_statistics_dialog.h"

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/tap.h>

#include <epan/dissectors/packet-mac-lte.h>

#include <QFormLayout>
#include <QTreeWidgetItem>

#include <ui/qt/models/percent_bar_delegate.h>
#include "main_application.h"

// TODO: have never tested in a live capture.

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
    /* col_ul_crc_failed_, */
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

// Calculate and return a bandwidth figure, in Mbs
static double calculate_bw(const nstime_t *start_time, const nstime_t *stop_time,
                           guint32 bytes)
{
    // Can only calculate bandwidth if have time delta
    if (memcmp(start_time, stop_time, sizeof(nstime_t)) != 0) {
        double elapsed_ms = (((double)stop_time->secs -  start_time->secs) * 1000) +
                            (((double)stop_time->nsecs - start_time->nsecs) / 1000000);

        // Only really meaningful if have a few frames spread over time...
        // For now at least avoid dividing by something very close to 0.0
        if (elapsed_ms < 2.0) {
           return 0.0f;
        }

        // N.B. very small values will display as scientific notation, but rather that than show 0
        // when there is some traffic..
        return ((bytes * 8) / elapsed_ms) / 1000;
    }
    else {
        return 0.0f;
    }
}


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
        for (int n=0; n < MAC_LTE_DATA_LCID_COUNT_MAX; n++) {
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
        // N.B. fields that are set as % using percent_bar_delegate.h
        // for UE headings don't display here...
        for (int n=0; n < MAC_LTE_DATA_LCID_COUNT_MAX; n++) {
            setText(col_type_+n, QString::number((uint)lcids[n]));
        }
    }

    // Increase value held for lcid by given value.
    void updateLCID(guint8 lcid, guint value)
    {
        lcids[lcid] += value;
    }

    // Generate expression for this UE and direction, also filter for SRs and RACH if indicated.
    const QString filterExpression(bool showSR, bool showRACH) {
        int direction = (type() == mac_dlsch_packet_count_row_type) ||
                        (type() == mac_dlsch_byte_count_row_type);

        QString filter_expr;

        if (showSR) {
            filter_expr = QString("(mac-lte.sr-req and mac-lte.ueid == %1) or (").arg(ueid_);
        }

        if (showRACH) {
            filter_expr += QString("(mac-lte.rar or (mac-lte.preamble-sent and mac-lte.ueid == %1)) or (").arg(ueid_);
        }

        // Main expression matching this UE and direction
        filter_expr += QString("mac-lte.ueid==%1 && mac-lte.rnti==%2 && mac-lte.direction==%3").
                              arg(ueid_).arg(rnti_).arg(direction);

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

    // Not showing anything for individual channels.  Headings are different than from UEs, and
    // trying to show both would be too confusing.
    QList<QVariant> rowData() const
    {
        return QList<QVariant>();
    }

private:
    unsigned ueid_;
    unsigned rnti_;
    int lcids[MAC_LTE_DATA_LCID_COUNT_MAX]; /* 0 to 10 and 32 to 38 */
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

        // Add UL/DL packet/byte count subitems.
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

            // N.B. Not going to support predefined data in Qt version..
            if (!mlt_info->isPredefinedData) {
                for (int n=0; n < MAC_LTE_DATA_LCID_COUNT_MAX; n++) {
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

            // N.B. Not going to support predefined data in Qt version..
            if (!mlt_info->isPredefinedData) {
                for (int n=0; n < MAC_LTE_DATA_LCID_COUNT_MAX; n++) {
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

    // Draw this UE.
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
                                                (((double)ul_padding_bytes_ / (double)ul_raw_bytes_) * 100.0) :
                                                0.0));
        setText(col_ul_retx_, QString::number(ul_retx_));

        setText(col_dl_frames_, QString::number(dl_frames_));
        setText(col_dl_bytes_, QString::number(dl_bytes_));
        setText(col_dl_mb_s_, QString::number(DL_bw));

        setData(col_dl_padding_percent_, Qt::UserRole,
                QVariant::fromValue<double>(dl_raw_bytes_ ?
                                                (((double)dl_padding_bytes_ / (double)dl_raw_bytes_) * 100.0) :
                                                0.0));
        setText(col_dl_crc_failed_, QString::number(dl_crc_failed_));
        setText(col_dl_retx_, QString::number(dl_retx_));

        // Draw child items with per-channel counts.
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

    // Generate expression for this UE, also filter for SRs and RACH if indicated.
    const QString filterExpression(bool showSR, bool showRACH) {
        QString filter_expr;

        if (showSR) {
            filter_expr = QString("(mac-lte.sr-req and mac-lte.ueid == %1) or (").arg(ueid_);
        }

        if (showRACH) {
            filter_expr += QString("(mac-lte.rar or (mac-lte.preamble-sent and mac-lte.ueid == %1)) or (").arg(ueid_);
        }

        // Main expression matching this UE
        filter_expr += QString("mac-lte.ueid==%1 && mac-lte.rnti==%2").arg(ueid_).arg(rnti_);

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

    // Return the UE-specific fields.
    QList<QVariant> rowData() const
    {
        QList<QVariant> row_data;

        // Key fields
        row_data << rnti_ << (type_ == C_RNTI ? QObject::tr("C-RNTI") : QObject::tr("SPS-RNTI")) << ueid_;

        // UL
        row_data << ul_frames_ << ul_bytes_
                 << calculate_bw(&ul_time_start_, &ul_time_stop_, ul_bytes_)
                 << QVariant::fromValue<double>(ul_raw_bytes_ ?
                                                    (((double)ul_padding_bytes_ / (double)ul_raw_bytes_) * 100.0) :
                                                    0.0)
                 << ul_retx_;

        // DL
        row_data << dl_frames_ << dl_bytes_
                 << calculate_bw(&dl_time_start_, &dl_time_stop_, dl_bytes_)
                 << QVariant::fromValue<double>(dl_raw_bytes_ ?
                                                    (((double)dl_padding_bytes_ / (double)dl_raw_bytes_) * 100.0) :
                                                    0.0)
                 << dl_crc_failed_ << dl_retx_;
        return row_data;
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
        << QObject::tr("DL ReTX")
        // 'Blank out' Channel-level fields
        << QObject::tr("") << QObject::tr("") << QObject::tr("") << QObject::tr("") << QObject::tr("");

static const QStringList mac_channel_counts_labels = QStringList()
        << QObject::tr("") << QObject::tr("CCCH")
        << QObject::tr("LCID 1") << QObject::tr("LCID 2") << QObject::tr("LCID 3")
        << QObject::tr("LCID 4") << QObject::tr("LCID 5") << QObject::tr("LCID 6")
        << QObject::tr("LCID 7") << QObject::tr("LCID 8") << QObject::tr("LCID 9")
        << QObject::tr("LCID 10") << QObject::tr("LCID 32") << QObject::tr("LCID 33")
        << QObject::tr("LCID 34") << QObject::tr("LCID 35") << QObject::tr("LCID 36")
        << QObject::tr("LCID 37") << QObject::tr("LCID 38");



//------------------------------------------------------------------------------------------
// Dialog

// Constructor.
LteMacStatisticsDialog::LteMacStatisticsDialog(QWidget &parent, CaptureFile &cf, const char *filter) :
    TapParameterDialog(parent, cf, HELP_STATS_LTE_MAC_TRAFFIC_DIALOG),
    commonStatsCurrent_(false)
{
    setWindowSubtitle(tr("LTE Mac Statistics"));
    loadGeometry(parent.width() * 1, parent.height() * 3 / 4, "LTEMacStatisticsDialog");

    clearCommonStats();

    // Create common_stats_grid to appear just above the filter area.
    int statstree_layout_idx = verticalLayout()->indexOf(filterLayout()->widget());
    QGridLayout *common_stats_grid = new QGridLayout();
    // Insert into the vertical layout
    verticalLayout()->insertLayout(statstree_layout_idx, common_stats_grid);
    int one_em = fontMetrics().height();
    common_stats_grid->setColumnMinimumWidth(2, one_em * 2);
    common_stats_grid->setColumnStretch(2, 1);
    common_stats_grid->setColumnMinimumWidth(5, one_em * 2);
    common_stats_grid->setColumnStretch(5, 1);

    // Create statistics label.
    commonStatsLabel_ = new QLabel(this);
    commonStatsLabel_->setObjectName("statisticsLabel");
    commonStatsLabel_->setTextFormat(Qt::RichText);
    commonStatsLabel_->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);
    common_stats_grid->addWidget(commonStatsLabel_);


    // Create a grid for filtering-related widgetsto also appear in layout.
    int filter_controls_layout_idx = verticalLayout()->indexOf(filterLayout()->widget());
    QGridLayout *filter_controls_grid = new QGridLayout();
    // Insert into the vertical layout
    verticalLayout()->insertLayout(filter_controls_layout_idx, filter_controls_grid);
    filter_controls_grid->setColumnMinimumWidth(2, one_em * 2);
    filter_controls_grid->setColumnStretch(2, 1);
    filter_controls_grid->setColumnMinimumWidth(5, one_em * 2);
    filter_controls_grid->setColumnStretch(5, 1);

    // Add individual controls into the grid
    showSRFilterCheckBox_ = new QCheckBox(tr("Include SR frames in filter"));
    filter_controls_grid->addWidget(showSRFilterCheckBox_);
    showRACHFilterCheckBox_ = new QCheckBox(tr("Include RACH frames in filter"));
    filter_controls_grid->addWidget(showRACHFilterCheckBox_);

    // Will set whole-UE headings originally.
    updateHeaderLabels();

    ul_delegate_ = new PercentBarDelegate();
    statsTreeWidget()->setItemDelegateForColumn(col_ul_padding_percent_, ul_delegate_);
    dl_delegate_ = new PercentBarDelegate();
    statsTreeWidget()->setItemDelegateForColumn(col_dl_padding_percent_, dl_delegate_);

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
    connect(statsTreeWidget(), &QTreeWidget::itemSelectionChanged,
            this, &LteMacStatisticsDialog::updateHeaderLabels);

    // Set handler for when display filter string is changed.
    connect(this, &LteMacStatisticsDialog::updateFilter,
            this, &LteMacStatisticsDialog::filterUpdated);
}

// Destructor.
LteMacStatisticsDialog::~LteMacStatisticsDialog()
{
    delete ul_delegate_;
    delete dl_delegate_;
}

// Update system/common counters, and redraw if changed.
void LteMacStatisticsDialog::updateCommonStats(const mac_lte_tap_info *tap_info)
{
    commonStats_.all_frames++;

    // For common channels, just update global counters
    switch (tap_info->rntiType) {
        case P_RNTI:
            commonStats_.pch_frames++;
            commonStats_.pch_bytes += tap_info->single_number_of_bytes;
            commonStats_.pch_paging_ids += tap_info->number_of_paging_ids;
            commonStatsCurrent_ = false;
            break;
        case SI_RNTI:
            commonStats_.sib_frames++;
            commonStats_.sib_bytes += tap_info->single_number_of_bytes;
            commonStatsCurrent_ = false;
            break;
        case NO_RNTI:
            commonStats_.mib_frames++;
            commonStatsCurrent_ = false;
            break;
        case RA_RNTI:
            commonStats_.rar_frames++;
            commonStats_.rar_entries += tap_info->number_of_rars;
            commonStatsCurrent_ = false;
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
            if (tap_info->ueInTTI > commonStats_.max_ul_ues_in_tti) {
                commonStats_.max_ul_ues_in_tti = tap_info->ueInTTI;
                commonStatsCurrent_ = false;
            }
            break;
        case DIRECTION_DOWNLINK:
            if (tap_info->ueInTTI > commonStats_.max_dl_ues_in_tti) {
                commonStats_.max_dl_ues_in_tti = tap_info->ueInTTI;
                commonStatsCurrent_ = false;
            }
            break;
    }
}

// Draw current common statistics by regenerating label with current values.
void LteMacStatisticsDialog::drawCommonStats()
{
    if (!commonStatsCurrent_) {
        QString stats_tables = "<html><head></head><body>\n";
        stats_tables += QString("<table>\n");
        stats_tables += QString("<tr><th align=\"left\">System</th> <td align=\"left\"> Max UL UEs/TTI=%1</td>").arg(commonStats_.max_ul_ues_in_tti);
        stats_tables += QString("<td align=\"left\">Max DL UEs/TTI=%1</td></tr>\n").arg(commonStats_.max_dl_ues_in_tti);

        stats_tables += QString("<tr><th align=\"left\">System broadcast</th><td align=\"left\">MIBs=%1</td>").arg(commonStats_.mib_frames);
        stats_tables += QString("<td align=\"left\">SIBs=%1 (%2 bytes)</td></tr>\n").arg(commonStats_.sib_frames).arg(commonStats_.sib_bytes);

        stats_tables += QString("<tr><th align=\"left\">RACH</th><td align=\"left\">RARs=%1 frames (%2 RARs)</td></tr>\n").
                                   arg(commonStats_.rar_frames).
                                   arg(commonStats_.rar_entries);

        stats_tables += QString("<tr><th align=\"left\">Paging</th><td align=\"left\">PCH=%1 (%2 bytes, %3 IDs)</td></tr>\n").
               arg(commonStats_.pch_frames).
               arg(commonStats_.pch_bytes).
               arg(commonStats_.pch_paging_ids);

        stats_tables += QString("</table>\n");
        stats_tables += "</body>\n";

        commonStatsLabel_->setText(stats_tables);

        commonStatsCurrent_ = true;
    }
}

void LteMacStatisticsDialog::clearCommonStats()
{
    memset(&commonStats_, 0, sizeof(commonStats_));
}

void LteMacStatisticsDialog::tapReset(void *ws_dlg_ptr)
{
    LteMacStatisticsDialog *ws_dlg = static_cast<LteMacStatisticsDialog *>(ws_dlg_ptr);
    if (!ws_dlg) {
        return;
    }

    ws_dlg->statsTreeWidget()->clear();
    ws_dlg->clearCommonStats();
}

//---------------------------------------------------------------------------------------
// Process tap info from a new packet.
// Returns TAP_PACKET_REDRAW if a redraw is needed, TAP_PACKET_DONT_REDRAW otherwise.
tap_packet_status LteMacStatisticsDialog::tapPacket(void *ws_dlg_ptr, struct _packet_info *, epan_dissect *, const void *mac_lte_tap_info_ptr, tap_flags_t)
{
    // Look up dialog and tap info.
    LteMacStatisticsDialog *ws_dlg = static_cast<LteMacStatisticsDialog *>(ws_dlg_ptr);
    const mac_lte_tap_info *mlt_info  = (const mac_lte_tap_info *) mac_lte_tap_info_ptr;
    if (!ws_dlg || !mlt_info) {
        return TAP_PACKET_DONT_REDRAW;
    }

    // Update common stats.
    ws_dlg->updateCommonStats(mlt_info);

    // Nothing more to do if tap entry isn't for a UE.
    if ((mlt_info->rntiType != C_RNTI) && (mlt_info->rntiType != SPS_RNTI)) {
        return TAP_PACKET_DONT_REDRAW;
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
    return TAP_PACKET_REDRAW;
}

// Return total number of frames tapped.
unsigned LteMacStatisticsDialog::getFrameCount()
{
    return commonStats_.all_frames;
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

    ws_dlg->drawCommonStats();

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
            filter_expr = mac_ue_ti->filterExpression(showSRFilterCheckBox_->checkState() > Qt::Unchecked,
                                                      showRACHFilterCheckBox_->checkState() > Qt::Unchecked);
        } else {
            MacULDLTreeWidgetItem *mac_channels_ti = static_cast<MacULDLTreeWidgetItem*>(ti);
            filter_expr = mac_channels_ti->filterExpression(showSRFilterCheckBox_->checkState() > Qt::Unchecked,
                                                            showRACHFilterCheckBox_->checkState() > Qt::Unchecked);
        }
    }
    return filter_expr;
}

void LteMacStatisticsDialog::fillTree()
{
    if (!registerTapListener("mac-lte",
                             this,
                             displayFilter_.toLatin1().data(),
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
        // ULDL labels
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

    WiresharkDialog::captureFileClosing();
}

// Store filter from signal.
void LteMacStatisticsDialog::filterUpdated(QString filter)
{
    displayFilter_ = filter;
}

// Get the item for the row, depending upon the type of tree item.
QList<QVariant> LteMacStatisticsDialog::treeItemData(QTreeWidgetItem *item) const
{
    // Cast up to our type.
    MacULDLTreeWidgetItem *channel_item = dynamic_cast<MacULDLTreeWidgetItem*>(item);
    if (channel_item) {
        return channel_item->rowData();
    }
    MacUETreeWidgetItem *ue_item = dynamic_cast<MacUETreeWidgetItem*>(item);
    if (ue_item) {
        return ue_item->rowData();
    }

    // Need to return something..
    return QList<QVariant>();
}


// Stat command + args

static void
lte_mac_statistics_init(const char *args, void*) {
    QStringList args_l = QString(args).split(',');
    QByteArray filter;
    if (args_l.length() > 2) {
        filter = QStringList(args_l.mid(2)).join(",").toUtf8();
    }
    mainApp->emitStatCommandSignal("LteMacStatistics", filter.constData(), NULL);
}

static stat_tap_ui lte_mac_statistics_ui = {
    REGISTER_STAT_GROUP_TELEPHONY_LTE,
    QT_TRANSLATE_NOOP("LteMacStatisticsDialog", "MAC Statistics"),
    "mac-lte,stat",
    lte_mac_statistics_init,
    0,
    NULL
};

extern "C" {

void register_tap_listener_qt_lte_mac_statistics(void);

void
register_tap_listener_qt_lte_mac_statistics(void)
{
    register_stat_tap_ui(&lte_mac_statistics_ui, NULL);
}

}
