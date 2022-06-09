/* rtp_analysis_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "rtp_analysis_dialog.h"
#include <ui_rtp_analysis_dialog.h>

#include "file.h"
#include "frame_tvbuff.h"

#include "epan/epan_dissect.h"
#include <epan/addr_resolv.h>
#include "epan/rtp_pt.h"

#include "epan/dfilter/dfilter.h"

#include "epan/dissectors/packet-rtp.h"

#include <ui/rtp_media.h>

#include "ui/help_url.h"
#include "ui/simple_dialog.h"
#include <wsutil/utf8_entities.h>

#include <wsutil/g711.h>
#include <wsutil/pint.h>

#include <QMessageBox>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QToolButton>
#include <QWidget>
#include <QCheckBox>

#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include "rtp_player_dialog.h"
#include <ui/qt/utils/stock_icon.h>
#include "main_application.h"
#include "ui/qt/widgets/wireshark_file_dialog.h"

/*
 * @file RTP stream analysis dialog
 *
 * Displays forward and reverse RTP streams and graphs each stream
 */

// To do:
// - Progress bar for tapping and saving.
// - Add a refresh button and/or action.
// - Fixup output file names.
// - Add a graph title and legend when saving?

enum {
    packet_col_,
    sequence_col_,
    delta_col_,
    jitter_col_,
    skew_col_,
    bandwidth_col_,
    marker_col_,
    status_col_
};

static const QRgb color_cn_ = 0xbfbfff;
static const QRgb color_rtp_warn_ = 0xffdbbf;
static const QRgb color_pt_event_ = 0xefffff;

enum { rtp_analysis_type_ = 1000 };
class RtpAnalysisTreeWidgetItem : public QTreeWidgetItem
{
public:
    RtpAnalysisTreeWidgetItem(QTreeWidget *tree, tap_rtp_stat_t *statinfo, packet_info *pinfo, const struct _rtp_info *rtpinfo) :
        QTreeWidgetItem(tree, rtp_analysis_type_)
    {
        frame_num_ = pinfo->num;
        sequence_num_ = rtpinfo->info_seq_num;
        pkt_len_ = pinfo->fd->pkt_len;
        flags_ = statinfo->flags;
        if (flags_ & STAT_FLAG_FIRST) {
            delta_ = 0.0;
            jitter_ = 0.0;
            skew_ = 0.0;
        } else {
            delta_ = statinfo->delta;
            jitter_ = statinfo->jitter;
            skew_ = statinfo->skew;
        }
        bandwidth_ = statinfo->bandwidth;
        marker_ = rtpinfo->info_marker_set ? true : false;
        ok_ = false;

        QColor bg_color = QColor();
        QString status;

        if (statinfo->pt == PT_CN) {
            status = "Comfort noise (PT=13, RFC 3389)";
            bg_color = color_cn_;
        } else if (statinfo->pt == PT_CN_OLD) {
            status = "Comfort noise (PT=19, reserved)";
            bg_color = color_cn_;
        } else if (statinfo->flags & STAT_FLAG_WRONG_SEQ) {
            status = "Wrong sequence number";
            bg_color = ColorUtils::expert_color_error;
        } else if (statinfo->flags & STAT_FLAG_DUP_PKT) {
            status = "Suspected duplicate (MAC address) only delta time calculated";
            bg_color = color_rtp_warn_;
        } else if (statinfo->flags & STAT_FLAG_REG_PT_CHANGE) {
            status = QString("Payload changed to PT=%1").arg(statinfo->pt);
            if (statinfo->flags & STAT_FLAG_PT_T_EVENT) {
                status.append(" telephone/event");
            }
            bg_color = color_rtp_warn_;
        } else if (statinfo->flags & STAT_FLAG_WRONG_TIMESTAMP) {
            status = "Incorrect timestamp";
            /* color = COLOR_WARNING; */
            bg_color = color_rtp_warn_;
        } else if ((statinfo->flags & STAT_FLAG_PT_CHANGE)
            &&  !(statinfo->flags & STAT_FLAG_FIRST)
            &&  !(statinfo->flags & STAT_FLAG_PT_CN)
            &&  (statinfo->flags & STAT_FLAG_FOLLOW_PT_CN)
            &&  !(statinfo->flags & STAT_FLAG_MARKER)) {
            status = "Marker missing?";
            bg_color = color_rtp_warn_;
        } else if (statinfo->flags & STAT_FLAG_PT_T_EVENT) {
            status = QString("PT=%1 telephone/event").arg(statinfo->pt);
            /* XXX add color? */
            bg_color = color_pt_event_;
        } else {
            if (statinfo->flags & STAT_FLAG_MARKER) {
                bg_color = color_rtp_warn_;
            }
        }

        if (status.isEmpty()) {
            ok_ = true;
            status = UTF8_CHECK_MARK;
        }

        setText(packet_col_, QString::number(frame_num_));
        setText(sequence_col_, QString::number(sequence_num_));
        setText(delta_col_, QString::number(delta_, 'f', prefs.gui_decimal_places3));
        setText(jitter_col_, QString::number(jitter_, 'f', prefs.gui_decimal_places3));
        setText(skew_col_, QString::number(skew_, 'f', prefs.gui_decimal_places3));
        setText(bandwidth_col_, QString::number(bandwidth_, 'f', prefs.gui_decimal_places1));
        if (marker_) {
            setText(marker_col_, UTF8_BULLET);
        }
        setText(status_col_, status);

        setTextAlignment(packet_col_, Qt::AlignRight);
        setTextAlignment(sequence_col_, Qt::AlignRight);
        setTextAlignment(delta_col_, Qt::AlignRight);
        setTextAlignment(jitter_col_, Qt::AlignRight);
        setTextAlignment(skew_col_, Qt::AlignRight);
        setTextAlignment(bandwidth_col_, Qt::AlignRight);
        setTextAlignment(marker_col_, Qt::AlignCenter);

        if (bg_color.isValid()) {
            for (int col = 0; col < columnCount(); col++) {
                setBackground(col, bg_color);
                setForeground(col, ColorUtils::expert_color_foreground);
            }
        }
    }

    uint32_t frameNum() { return frame_num_; }
    bool frameStatus() { return ok_; }

    QList<QVariant> rowData() {
        QString marker_str;
        QString status_str = ok_ ? "OK" : text(status_col_);

        if (marker_) marker_str = "SET";

        return QList<QVariant>()
                << frame_num_ << sequence_num_ << delta_ << jitter_ << skew_ << bandwidth_
                << marker_str << status_str;
    }

    bool operator< (const QTreeWidgetItem &other) const
    {
        if (other.type() != rtp_analysis_type_) return QTreeWidgetItem::operator< (other);
        const RtpAnalysisTreeWidgetItem *other_row = static_cast<const RtpAnalysisTreeWidgetItem *>(&other);

        switch (treeWidget()->sortColumn()) {
        case (packet_col_):
            return frame_num_ < other_row->frame_num_;
            break;
        case (sequence_col_):
            return sequence_num_ < other_row->sequence_num_;
            break;
        case (delta_col_):
            return delta_ < other_row->delta_;
            break;
        case (jitter_col_):
            return jitter_ < other_row->jitter_;
            break;
        case (skew_col_):
            return skew_ < other_row->skew_;
            break;
        case (bandwidth_col_):
            return bandwidth_ < other_row->bandwidth_;
            break;
        default:
            break;
        }

        // Fall back to string comparison
        return QTreeWidgetItem::operator <(other);
    }
private:
    uint32_t frame_num_;
    uint32_t sequence_num_;
    uint32_t pkt_len_;
    uint32_t flags_;
    double delta_;
    double jitter_;
    double skew_;
    double bandwidth_;
    bool marker_;
    bool ok_;
};

enum {
    fwd_jitter_graph_,
    fwd_diff_graph_,
    fwd_delta_graph_,
    rev_jitter_graph_,
    rev_diff_graph_,
    rev_delta_graph_,
    num_graphs_
};

RtpAnalysisDialog *RtpAnalysisDialog::pinstance_{nullptr};
std::mutex RtpAnalysisDialog::init_mutex_;
std::mutex RtpAnalysisDialog::run_mutex_;

RtpAnalysisDialog *RtpAnalysisDialog::openRtpAnalysisDialog(QWidget &parent, CaptureFile &cf, QObject *packet_list)
{
    std::lock_guard<std::mutex> lock(init_mutex_);
    if (pinstance_ == nullptr)
    {
        pinstance_ = new RtpAnalysisDialog(parent, cf);
        connect(pinstance_, SIGNAL(goToPacket(int)),
                packet_list, SLOT(goToPacket(int)));
    }
    return pinstance_;
}

RtpAnalysisDialog::RtpAnalysisDialog(QWidget &parent, CaptureFile &cf) :
    WiresharkDialog(parent, cf),
    ui(new Ui::RtpAnalysisDialog),
    tab_seq(0)
{
    ui->setupUi(this);
    loadGeometry(parent.width() * 4 / 5, parent.height() * 4 / 5);
    setWindowSubtitle(tr("RTP Stream Analysis"));
    // Used when tab contains IPs
    //ui->tabWidget->setStyleSheet("QTabBar::tab { height: 7ex; }");
    ui->tabWidget->tabBar()->setTabsClosable(true);

    ui->progressFrame->hide();

    stream_ctx_menu_.addAction(ui->actionGoToPacket);
    stream_ctx_menu_.addAction(ui->actionNextProblem);
    set_action_shortcuts_visible_in_context_menu(stream_ctx_menu_.actions());

    connect(ui->streamGraph, SIGNAL(mousePress(QMouseEvent*)),
            this, SLOT(graphClicked(QMouseEvent*)));

    graph_ctx_menu_.addAction(ui->actionSaveGraph);

    ui->streamGraph->xAxis->setLabel("Arrival Time");
    ui->streamGraph->yAxis->setLabel("Value (ms)");

    QPushButton *prepare_button = ui->buttonBox->addButton(ui->actionPrepareButton->text(), QDialogButtonBox::ActionRole);
    prepare_button->setToolTip(ui->actionPrepareButton->toolTip());
    prepare_button->setMenu(ui->menuPrepareFilter);

    player_button_ = RtpPlayerDialog::addPlayerButton(ui->buttonBox, this);

    QPushButton *export_btn = ui->buttonBox->addButton(ui->actionExportButton->text(), QDialogButtonBox::ActionRole);
    export_btn->setToolTip(ui->actionExportButton->toolTip());

    QMenu *save_menu = new QMenu(export_btn);
    save_menu->addAction(ui->actionSaveOneCsv);
    save_menu->addAction(ui->actionSaveAllCsv);
    save_menu->addSeparator();
    save_menu->addAction(ui->actionSaveGraph);
    export_btn->setMenu(save_menu);

    connect(ui->tabWidget, SIGNAL(currentChanged(int)),
            this, SLOT(updateWidgets()));
    connect(ui->tabWidget->tabBar(), SIGNAL(tabCloseRequested(int)),
            this, SLOT(closeTab(int)));
    connect(this, SIGNAL(updateFilter(QString, bool)),
            &parent, SLOT(filterPackets(QString, bool)));
    connect(this, SIGNAL(rtpPlayerDialogReplaceRtpStreams(QVector<rtpstream_id_t *>)),
            &parent, SLOT(rtpPlayerDialogReplaceRtpStreams(QVector<rtpstream_id_t *>)));
    connect(this, SIGNAL(rtpPlayerDialogAddRtpStreams(QVector<rtpstream_id_t *>)),
            &parent, SLOT(rtpPlayerDialogAddRtpStreams(QVector<rtpstream_id_t *>)));
    connect(this, SIGNAL(rtpPlayerDialogRemoveRtpStreams(QVector<rtpstream_id_t *>)),
            &parent, SLOT(rtpPlayerDialogRemoveRtpStreams(QVector<rtpstream_id_t *>)));

    updateWidgets();

    updateStatistics();
}

RtpAnalysisDialog::~RtpAnalysisDialog()
{
    std::lock_guard<std::mutex> lock(init_mutex_);
    if (pinstance_ != nullptr) {
        delete ui;
        for(int i=0; i<tabs_.count(); i++) {
            deleteTabInfo(tabs_[i]);
            g_free(tabs_[i]);
        }
        pinstance_ = nullptr;
    }
}

void RtpAnalysisDialog::deleteTabInfo(tab_info_t *tab_info)
{
    delete tab_info->time_vals;
    delete tab_info->jitter_vals;
    delete tab_info->diff_vals;
    delete tab_info->delta_vals;
    // tab_info->tree_widget was deleted by ui
    // tab_info->statistics_label was deleted by ui
    rtpstream_info_free_data(&tab_info->stream);
}

int RtpAnalysisDialog::addTabUI(tab_info_t *new_tab)
{
    int new_tab_no;
    rtpstream_info_calc_t s_calc;
    rtpstream_info_calculate(&new_tab->stream, &s_calc);
    new_tab->tab_name = new QString(QString("%1:%2 " UTF8_RIGHTWARDS_ARROW "\n%3:%4\n(%5)")
            .arg(s_calc.src_addr_str)
            .arg(s_calc.src_port)
            .arg(s_calc.dst_addr_str)
            .arg(s_calc.dst_port)
            .arg(int_to_qstring(s_calc.ssrc, 8, 16)));

    QWidget *tab = new QWidget();
    tab->setProperty("tab_data", QVariant::fromValue((void *)new_tab));
    QHBoxLayout *horizontalLayout = new QHBoxLayout(tab);
    QVBoxLayout *verticalLayout = new QVBoxLayout();
    new_tab->statistics_label = new QLabel();
    //new_tab->statistics_label->setStyleSheet("QLabel { color : blue; }");
    new_tab->statistics_label->setTextFormat(Qt::RichText);
    new_tab->statistics_label->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

    verticalLayout->addWidget(new_tab->statistics_label);

    QSpacerItem *verticalSpacer = new QSpacerItem(20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);

    verticalLayout->addItem(verticalSpacer);

    horizontalLayout->addLayout(verticalLayout);

    new_tab->tree_widget = new QTreeWidget();
    new_tab->tree_widget->setRootIsDecorated(false);
    new_tab->tree_widget->setUniformRowHeights(true);
    new_tab->tree_widget->setItemsExpandable(false);
    new_tab->tree_widget->setSortingEnabled(true);
    new_tab->tree_widget->setExpandsOnDoubleClick(false);

    new_tab->tree_widget->installEventFilter(this);
    new_tab->tree_widget->setContextMenuPolicy(Qt::CustomContextMenu);
    new_tab->tree_widget->header()->setSortIndicator(0, Qt::AscendingOrder);
    connect(new_tab->tree_widget, SIGNAL(customContextMenuRequested(QPoint)),
                SLOT(showStreamMenu(QPoint)));
    connect(new_tab->tree_widget, SIGNAL(itemSelectionChanged()),
            this, SLOT(updateWidgets()));

    QTreeWidgetItem *ti = new_tab->tree_widget->headerItem();
    ti->setText(packet_col_, tr("Packet"));
    ti->setText(sequence_col_, tr("Sequence"));
    ti->setText(delta_col_, tr("Delta (ms)"));
    ti->setText(jitter_col_, tr("Jitter (ms)"));
    ti->setText(skew_col_, tr("Skew"));
    ti->setText(bandwidth_col_, tr("Bandwidth"));
    ti->setText(marker_col_, tr("Marker"));
    ti->setText(status_col_, tr("Status"));

    QColor color = ColorUtils::graphColor(tab_seq++);
    ui->tabWidget->setUpdatesEnabled(false);
    horizontalLayout->addWidget(new_tab->tree_widget);
    new_tab_no = ui->tabWidget->count() - 1;
    // Used when tab contains IPs
    //ui->tabWidget->insertTab(new_tab_no, tab, *new_tab->tab_name);
    ui->tabWidget->insertTab(new_tab_no, tab, QString(tr("Stream %1")).arg(tab_seq - 1));
    ui->tabWidget->tabBar()->setTabTextColor(new_tab_no, color);
    ui->tabWidget->tabBar()->setTabToolTip(new_tab_no, *new_tab->tab_name);
    ui->tabWidget->setUpdatesEnabled(true);

    QPen pen = QPen(color);
    QCPScatterStyle jitter_shape;
    QCPScatterStyle diff_shape;
    QCPScatterStyle delta_shape;
    jitter_shape.setShape(QCPScatterStyle::ssCircle);
    //jitter_shape.setSize(5);
    diff_shape.setShape(QCPScatterStyle::ssCross);
    //diff_shape.setSize(5);
    delta_shape.setShape(QCPScatterStyle::ssTriangle);
    //delta_shape.setSize(5);

    new_tab->jitter_graph = ui->streamGraph->addGraph();
    new_tab->diff_graph = ui->streamGraph->addGraph();
    new_tab->delta_graph = ui->streamGraph->addGraph();
    new_tab->jitter_graph->setPen(pen);
    new_tab->diff_graph->setPen(pen);
    new_tab->delta_graph->setPen(pen);
    new_tab->jitter_graph->setScatterStyle(jitter_shape);
    new_tab->diff_graph->setScatterStyle(diff_shape);
    new_tab->delta_graph->setScatterStyle(delta_shape);

    new_tab->graphHorizontalLayout = new QHBoxLayout();

    new_tab->stream_checkbox = new QCheckBox(tr("Stream %1").arg(tab_seq - 1), ui->graphTab);
    new_tab->stream_checkbox->setChecked(true);
    new_tab->stream_checkbox->setIcon(StockIcon::colorIcon(color.rgb(), QPalette::Text));
    new_tab->graphHorizontalLayout->addWidget(new_tab->stream_checkbox);
    new_tab->graphHorizontalLayout->addItem(new QSpacerItem(10, 5, QSizePolicy::Expanding, QSizePolicy::Minimum));
    connect(new_tab->stream_checkbox, SIGNAL(stateChanged(int)),
            this, SLOT(rowCheckboxChanged(int)));

    new_tab->jitter_checkbox = new QCheckBox(tr("Stream %1 Jitter").arg(tab_seq - 1), ui->graphTab);
    new_tab->jitter_checkbox->setChecked(true);
    new_tab->jitter_checkbox->setIcon(StockIcon::colorIconCircle(color.rgb(), QPalette::Text));
    new_tab->graphHorizontalLayout->addWidget(new_tab->jitter_checkbox);
    new_tab->graphHorizontalLayout->addItem(new QSpacerItem(10, 5, QSizePolicy::Expanding, QSizePolicy::Minimum));
    connect(new_tab->jitter_checkbox, SIGNAL(stateChanged(int)),
            this, SLOT(singleCheckboxChanged(int)));

    new_tab->diff_checkbox = new QCheckBox(tr("Stream %1 Difference").arg(tab_seq - 1), ui->graphTab);
    new_tab->diff_checkbox->setChecked(true);
    new_tab->diff_checkbox->setIcon(StockIcon::colorIconCross(color.rgb(), QPalette::Text));
    new_tab->graphHorizontalLayout->addWidget(new_tab->diff_checkbox);
    new_tab->graphHorizontalLayout->addItem(new QSpacerItem(10, 5, QSizePolicy::Expanding, QSizePolicy::Minimum));
    connect(new_tab->diff_checkbox, SIGNAL(stateChanged(int)),
            this, SLOT(singleCheckboxChanged(int)));

    new_tab->delta_checkbox = new QCheckBox(tr("Stream %1 Delta").arg(tab_seq - 1), ui->graphTab);
    new_tab->delta_checkbox->setChecked(true);
    new_tab->delta_checkbox->setIcon(StockIcon::colorIconTriangle(color.rgb(), QPalette::Text));
    new_tab->graphHorizontalLayout->addWidget(new_tab->delta_checkbox);
    new_tab->graphHorizontalLayout->addItem(new QSpacerItem(10, 5, QSizePolicy::Expanding, QSizePolicy::Minimum));
    connect(new_tab->delta_checkbox, SIGNAL(stateChanged(int)),
            this, SLOT(singleCheckboxChanged(int)));

    new_tab->graphHorizontalLayout->setStretch(6, 1);

    ui->layout->addLayout(new_tab->graphHorizontalLayout);

    return new_tab_no;
}

// Handles all row checkBoxes
void RtpAnalysisDialog::rowCheckboxChanged(int checked)
{
    QObject *obj = sender();

    // Find correct tab data
    for(int i=0; i<tabs_.count(); i++) {
        tab_info_t *tab = tabs_[i];
        if (obj == tab->stream_checkbox) {
            // Set new state for all checkboxes on row
            Qt::CheckState new_state;

            if (checked) {
                new_state = Qt::Checked;
            } else {
                new_state = Qt::Unchecked;
            }
            tab->jitter_checkbox->setCheckState(new_state);
            tab->diff_checkbox->setCheckState(new_state);
            tab->delta_checkbox->setCheckState(new_state);
            break;
        }
    }
}

// Handles all single CheckBoxes
void RtpAnalysisDialog::singleCheckboxChanged(int checked)
{
    QObject *obj = sender();

    // Find correct tab data
    for(int i=0; i<tabs_.count(); i++) {
        tab_info_t *tab = tabs_[i];
        if (obj == tab->jitter_checkbox) {
            tab->jitter_graph->setVisible(checked);
            updateGraph();
            break;
        } else if (obj == tab->diff_checkbox) {
            tab->diff_graph->setVisible(checked);
            updateGraph();
            break;
        } else if (obj == tab->delta_checkbox) {
            tab->delta_graph->setVisible(checked);
            updateGraph();
            break;
        }
    }
}

void RtpAnalysisDialog::updateWidgets()
{
    bool enable_tab = false;
    bool enable_nav = false;
    QString hint = err_str_;

    if ((!file_closed_) &&
        (tabs_.count() > 0)) {
        enable_tab = true;
    }

    if ((!file_closed_) &&
        (tabs_.count() > 0) &&
        (ui->tabWidget->currentIndex() < (ui->tabWidget->count()-1))) {
        enable_nav = true;
    }

    ui->actionGoToPacket->setEnabled(enable_nav);
    ui->actionNextProblem->setEnabled(enable_nav);

    if (enable_nav) {
        hint.append(tr(" %1 streams, ").arg(tabs_.count() - 1));
        hint.append(tr(" G: Go to packet, N: Next problem packet"));
    }

    ui->actionExportButton->setEnabled(enable_tab);
    ui->actionSaveOneCsv->setEnabled(enable_nav);
    ui->actionSaveAllCsv->setEnabled(enable_tab);
    ui->actionSaveGraph->setEnabled(enable_tab);

    ui->actionPrepareFilterOne->setEnabled(enable_nav);
    ui->actionPrepareFilterAll->setEnabled(enable_tab);

#if defined(QT_MULTIMEDIA_LIB)
    player_button_->setEnabled(enable_tab);
#endif

    ui->tabWidget->setEnabled(enable_tab);
    hint.prepend("<small><i>");
    hint.append("</i></small>");
    ui->hintLabel->setText(hint);

    WiresharkDialog::updateWidgets();
}

void RtpAnalysisDialog::on_actionGoToPacket_triggered()
{
    tab_info_t *tab_data = getTabInfoForCurrentTab();
    if (!tab_data) return;

    QTreeWidget *cur_tree = tab_data->tree_widget;
    if (!cur_tree || cur_tree->selectedItems().length() < 1) return;

    QTreeWidgetItem *ti = cur_tree->selectedItems()[0];
    if (ti->type() != rtp_analysis_type_) return;

    RtpAnalysisTreeWidgetItem *ra_ti = dynamic_cast<RtpAnalysisTreeWidgetItem *>((RtpAnalysisTreeWidgetItem *)ti);
    emit goToPacket(ra_ti->frameNum());
}

void RtpAnalysisDialog::on_actionNextProblem_triggered()
{
    tab_info_t *tab_data = getTabInfoForCurrentTab();
    if (!tab_data) return;

    QTreeWidget *cur_tree = tab_data->tree_widget;
    if (!cur_tree || cur_tree->topLevelItemCount() < 2) return;

    // Choose convenience over correctness.
    if (cur_tree->selectedItems().length() < 1) {
        cur_tree->setCurrentItem(cur_tree->topLevelItem(0));
    }

    QTreeWidgetItem *sel_ti = cur_tree->selectedItems()[0];
    if (sel_ti->type() != rtp_analysis_type_) return;
    QTreeWidgetItem *test_ti = cur_tree->itemBelow(sel_ti);
    if (!test_ti) test_ti = cur_tree->topLevelItem(0);
    while (test_ti != sel_ti) {
        RtpAnalysisTreeWidgetItem *ra_ti = dynamic_cast<RtpAnalysisTreeWidgetItem *>((RtpAnalysisTreeWidgetItem *)test_ti);
        if (!ra_ti->frameStatus()) {
            cur_tree->setCurrentItem(ra_ti);
            break;
        }

        test_ti = cur_tree->itemBelow(test_ti);
        if (!test_ti) test_ti = cur_tree->topLevelItem(0);
    }
}

void RtpAnalysisDialog::on_actionSaveOneCsv_triggered()
{
    saveCsv(dir_one_);
}

void RtpAnalysisDialog::on_actionSaveAllCsv_triggered()
{
    saveCsv(dir_all_);
}

void RtpAnalysisDialog::on_actionSaveGraph_triggered()
{
    ui->tabWidget->setCurrentWidget(ui->graphTab);

    QString file_name, extension;
    QDir path(mainApp->lastOpenDir());
    QString pdf_filter = tr("Portable Document Format (*.pdf)");
    QString png_filter = tr("Portable Network Graphics (*.png)");
    QString bmp_filter = tr("Windows Bitmap (*.bmp)");
    // Gaze upon my beautiful graph with lossy artifacts!
    QString jpeg_filter = tr("JPEG File Interchange Format (*.jpeg *.jpg)");
    QString filter = QString("%1;;%2;;%3;;%4")
            .arg(pdf_filter)
            .arg(png_filter)
            .arg(bmp_filter)
            .arg(jpeg_filter);

    QString save_file = path.canonicalPath();
    if (!file_closed_) {
        save_file += QString("/%1").arg(cap_file_.fileBaseName());
    }
    file_name = WiresharkFileDialog::getSaveFileName(this, mainApp->windowTitleString(tr("Save Graph As…")),
                                             save_file, filter, &extension);

    if (!file_name.isEmpty()) {
        bool save_ok = false;
        // https://www.qcustomplot.com/index.php/support/forum/63
//        ui->streamGraph->legend->setVisible(true);
        if (extension.compare(pdf_filter) == 0) {
            save_ok = ui->streamGraph->savePdf(file_name);
        } else if (extension.compare(png_filter) == 0) {
            save_ok = ui->streamGraph->savePng(file_name);
        } else if (extension.compare(bmp_filter) == 0) {
            save_ok = ui->streamGraph->saveBmp(file_name);
        } else if (extension.compare(jpeg_filter) == 0) {
            save_ok = ui->streamGraph->saveJpg(file_name);
        }
//        ui->streamGraph->legend->setVisible(false);
        // else error dialog?
        if (save_ok) {
            mainApp->setLastOpenDirFromFilename(file_name);
        }
    }
}

void RtpAnalysisDialog::on_buttonBox_helpRequested()
{
    mainApp->helpTopicAction(HELP_TELEPHONY_RTP_ANALYSIS_DIALOG);
}

void RtpAnalysisDialog::tapReset(void *tapinfo_ptr)
{
    RtpAnalysisDialog *rtp_analysis_dialog = dynamic_cast<RtpAnalysisDialog *>((RtpAnalysisDialog*)tapinfo_ptr);
    if (!rtp_analysis_dialog) return;

    rtp_analysis_dialog->resetStatistics();
}

tap_packet_status RtpAnalysisDialog::tapPacket(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *, const void *rtpinfo_ptr, tap_flags_t)
{
    RtpAnalysisDialog *rtp_analysis_dialog = dynamic_cast<RtpAnalysisDialog *>((RtpAnalysisDialog*)tapinfo_ptr);
    if (!rtp_analysis_dialog) return TAP_PACKET_DONT_REDRAW;

    const struct _rtp_info *rtpinfo = (const struct _rtp_info *)rtpinfo_ptr;
    if (!rtpinfo) return TAP_PACKET_DONT_REDRAW;

    /* we ignore packets that are not displayed */
    if (pinfo->fd->passed_dfilter == 0)
        return TAP_PACKET_DONT_REDRAW;
    /* also ignore RTP Version != 2 */
    else if (rtpinfo->info_version != 2)
        return TAP_PACKET_DONT_REDRAW;
    /* is it the forward direction?  */
    else {
        // Search tab in hash key, if there are multiple tabs with same hash
        QList<tab_info_t *> tabs = rtp_analysis_dialog->tab_hash_.values(pinfo_rtp_info_to_hash(pinfo, rtpinfo));
        for (int i = 0; i < tabs.size(); i++) {
            tab_info_t *tab = tabs.at(i);
            if (rtpstream_id_equal_pinfo_rtp_info(&tab->stream.id, pinfo, rtpinfo))  {
                rtp_analysis_dialog->addPacket(tab, pinfo, rtpinfo);
                break;
            }
        }
    }

    return TAP_PACKET_DONT_REDRAW;
}

void RtpAnalysisDialog::tapDraw(void *tapinfo_ptr)
{
    RtpAnalysisDialog *rtp_analysis_dialog = dynamic_cast<RtpAnalysisDialog *>((RtpAnalysisDialog*)tapinfo_ptr);
    if (!rtp_analysis_dialog) return;

    rtp_analysis_dialog->updateStatistics();
}

void RtpAnalysisDialog::resetStatistics()
{
    for(int i=0; i<tabs_.count(); i++) {
        tab_info_t *tab = tabs_[i];
        memset(&tab->stream.rtp_stats, 0, sizeof(tab->stream.rtp_stats));

        tab->stream.rtp_stats.first_packet = true;
        tab->stream.rtp_stats.reg_pt = PT_UNDEFINED;
        tab->time_vals->clear();
        tab->jitter_vals->clear();
        tab->diff_vals->clear();
        tab->delta_vals->clear();
        tab->tree_widget->clear();
    }

    for (int i = 0; i < ui->streamGraph->graphCount(); i++) {
        ui->streamGraph->graph(i)->data()->clear();
    }
}

void RtpAnalysisDialog::addPacket(tab_info_t *tab, packet_info *pinfo, const _rtp_info *rtpinfo)
{
    rtppacket_analyse(&tab->stream.rtp_stats, pinfo, rtpinfo);
    new RtpAnalysisTreeWidgetItem(tab->tree_widget, &tab->stream.rtp_stats, pinfo, rtpinfo);
    tab->time_vals->append(tab->stream.rtp_stats.time / 1000);
    tab->jitter_vals->append(tab->stream.rtp_stats.jitter);
    tab->diff_vals->append(tab->stream.rtp_stats.diff);
    tab->delta_vals->append(tab->stream.rtp_stats.delta);
}

void RtpAnalysisDialog::updateStatistics()
{
    for(int i=0; i<tabs_.count(); i++) {
        rtpstream_info_t *stream = &tabs_[i]->stream;
        rtpstream_info_calc_t s_calc;
        rtpstream_info_calculate(stream, &s_calc);

        QString stats_tables = "<html><head><style>td{vertical-align:bottom;}</style></head><body>\n";
        stats_tables += "<h4>Stream</h4>\n";
        stats_tables += QString("<p>%1:%2 " UTF8_RIGHTWARDS_ARROW)
                .arg(s_calc.src_addr_str)
                .arg(s_calc.src_port);
        stats_tables += QString("<br>%1:%2</p>\n")
                .arg(s_calc.dst_addr_str)
                .arg(s_calc.dst_port);
        stats_tables += "<p><table>\n";
        stats_tables += QString("<tr><th align=\"left\">SSRC</th><td>%1</td></tr>")
                .arg(int_to_qstring(s_calc.ssrc, 8, 16));
        stats_tables += QString("<tr><th align=\"left\">Max Delta</th><td>%1 ms @ %2</td></tr>")
                .arg(s_calc.max_delta, 0, 'f', prefs.gui_decimal_places3)
                .arg(s_calc.last_packet_num);
        stats_tables += QString("<tr><th align=\"left\">Max Jitter</th><td>%1 ms</td></tr>")
                .arg(s_calc.max_jitter, 0, 'f', prefs.gui_decimal_places3);
        stats_tables += QString("<tr><th align=\"left\">Mean Jitter</th><td>%1 ms</td></tr>")
                .arg(s_calc.mean_jitter, 0, 'f', prefs.gui_decimal_places3);
        stats_tables += QString("<tr><th align=\"left\">Max Skew</th><td>%1 ms</td></tr>")
                .arg(s_calc.max_skew, 0, 'f', prefs.gui_decimal_places3);
        stats_tables += QString("<tr><th align=\"left\">RTP Packets</th><td>%1</td></tr>")
                .arg(s_calc.total_nr);
        stats_tables += QString("<tr><th align=\"left\">Expected</th><td>%1</td></tr>")
                .arg(s_calc.packet_expected);
        stats_tables += QString("<tr><th align=\"left\">Lost</th><td>%1 (%2 %)</td></tr>")
                .arg(s_calc.lost_num).arg(s_calc.lost_perc, 0, 'f', prefs.gui_decimal_places1);
        stats_tables += QString("<tr><th align=\"left\">Seq Errs</th><td>%1</td></tr>")
                .arg(s_calc.sequence_err);
        stats_tables += QString("<tr><th align=\"left\">Start at</th><td>%1 s @ %2</td></tr>")
                .arg(s_calc.start_time_ms, 0, 'f', 6)
                .arg(s_calc.first_packet_num);
        stats_tables += QString("<tr><th align=\"left\">Duration</th><td>%1 s</td></tr>")
                .arg(s_calc.duration_ms, 0, 'f', prefs.gui_decimal_places1);
        stats_tables += QString("<tr><th align=\"left\">Clock Drift</th><td>%1 ms</td></tr>")
                .arg(s_calc.clock_drift_ms, 0, 'f', 0);
        stats_tables += QString("<tr><th align=\"left\">Freq Drift</th><td>%1 Hz (%2 %)</td></tr>") // XXX Terminology?
                .arg(s_calc.freq_drift_hz, 0, 'f', 0).arg(s_calc.freq_drift_perc, 0, 'f', 2);
        stats_tables += "</table></p>\n";

        tabs_[i]->statistics_label->setText(stats_tables);

        for (int col = 0; col < tabs_[i]->tree_widget->columnCount() - 1; col++) {
            tabs_[i]->tree_widget->resizeColumnToContents(col);
        }

        tabs_[i]->jitter_graph->setData(*tabs_[i]->time_vals, *tabs_[i]->jitter_vals);
        tabs_[i]->diff_graph->setData(*tabs_[i]->time_vals, *tabs_[i]->diff_vals);
        tabs_[i]->delta_graph->setData(*tabs_[i]->time_vals, *tabs_[i]->delta_vals);
    }

    updateGraph();

    updateWidgets();
}

void RtpAnalysisDialog::updateGraph()
{
    for (int i = 0; i < ui->streamGraph->graphCount(); i++) {
        if (ui->streamGraph->graph(i)->visible()) {
            ui->streamGraph->graph(i)->rescaleAxes(i > 0);
        }
    }
    ui->streamGraph->replot();
}

QVector<rtpstream_id_t *>RtpAnalysisDialog::getSelectedRtpIds()
{
    QVector<rtpstream_id_t *> stream_ids;
    for(int i=0; i < tabs_.count(); i++) {
        stream_ids << &(tabs_[i]->stream.id);
    }

    return stream_ids;
}

void RtpAnalysisDialog::rtpPlayerReplace()
{
    if (tabs_.count() < 1) return;

    emit rtpPlayerDialogReplaceRtpStreams(getSelectedRtpIds());
}

void RtpAnalysisDialog::rtpPlayerAdd()
{
    if (tabs_.count() < 1) return;

    emit rtpPlayerDialogAddRtpStreams(getSelectedRtpIds());
}

void RtpAnalysisDialog::rtpPlayerRemove()
{
    if (tabs_.count() < 1) return;

    emit rtpPlayerDialogRemoveRtpStreams(getSelectedRtpIds());
}

void RtpAnalysisDialog::saveCsvHeader(QFile *save_file, QTreeWidget *tree)
{
    QList<QVariant> row_data;
    QStringList values;

    for (int col = 0; col < tree->columnCount(); col++) {
            row_data << tree->headerItem()->text(col);
    }
    foreach (QVariant v, row_data) {
        if (!v.isValid()) {
            values << "\"\"";
        } else if (v.userType() == QMetaType::QString) {
            values << QString("\"%1\"").arg(v.toString());
        } else {
            values << v.toString();
        }
    }
    save_file->write(values.join(",").toUtf8());
    save_file->write("\n");
}

void RtpAnalysisDialog::saveCsvData(QFile *save_file, QTreeWidget *tree)
{
    for (int row = 0; row < tree->topLevelItemCount(); row++) {
        QTreeWidgetItem *ti = tree->topLevelItem(row);
        if (ti->type() != rtp_analysis_type_) continue;
        RtpAnalysisTreeWidgetItem *ra_ti = dynamic_cast<RtpAnalysisTreeWidgetItem *>((RtpAnalysisTreeWidgetItem *)ti);
        QStringList values;
        foreach (QVariant v, ra_ti->rowData()) {
            if (!v.isValid()) {
                values << "\"\"";
            } else if (v.userType() == QMetaType::QString) {
                values << QString("\"%1\"").arg(v.toString());
            } else {
                values << v.toString();
            }
        }
        save_file->write(values.join(",").toUtf8());
        save_file->write("\n");
    }
}

// XXX The GTK+ UI saves the length and timestamp.
void RtpAnalysisDialog::saveCsv(RtpAnalysisDialog::StreamDirection direction)
{
    QString caption;

    switch (direction) {
    case dir_one_:
        caption = tr("Save one stream CSV");
        break;
    case dir_all_:
    default:
        caption = tr("Save all stream's CSV");
        break;
    }

    QString file_path = WiresharkFileDialog::getSaveFileName(
                this, caption, mainApp->lastOpenDir().absoluteFilePath("RTP Packet Data.csv"),
                tr("Comma-separated values (*.csv)"));

    if (file_path.isEmpty()) return;

    QFile save_file(file_path);
    save_file.open(QFile::WriteOnly);

    switch (direction) {
    case dir_one_:
        {
            tab_info_t *tab_data = getTabInfoForCurrentTab();
            if (tab_data) {

                saveCsvHeader(&save_file, tab_data->tree_widget);

                QString n = QString(*tab_data->tab_name);
                n.replace("\n"," ");
                save_file.write("\"");
                save_file.write(n.toUtf8());
                save_file.write("\"\n");
                saveCsvData(&save_file, tab_data->tree_widget);
            }
        }
        break;
    case dir_all_:
    default:
        if (tabs_.count() > 0) {
            saveCsvHeader(&save_file, tabs_[0]->tree_widget);
        }

        for(int i=0; i<tabs_.count(); i++) {
            QString n = QString(*tabs_[i]->tab_name);
            n.replace("\n"," ");
            save_file.write("\"");
            save_file.write(n.toUtf8());
            save_file.write("\"\n");
            saveCsvData(&save_file, tabs_[i]->tree_widget);
            save_file.write("\n");
        }
        break;
    }
}

bool RtpAnalysisDialog::eventFilter(QObject *, QEvent *event)
{
    if (event->type() != QEvent::KeyPress) return false;

    QKeyEvent *kevt = static_cast<QKeyEvent *>(event);

    switch(kevt->key()) {
    case Qt::Key_G:
        on_actionGoToPacket_triggered();
        return true;
    case Qt::Key_N:
        on_actionNextProblem_triggered();
        return true;
    default:
        break;
    }
    return false;
}

void RtpAnalysisDialog::graphClicked(QMouseEvent *event)
{
    updateWidgets();
    if (event->button() == Qt::RightButton) {
#if QT_VERSION >= QT_VERSION_CHECK(6, 0 ,0)
        graph_ctx_menu_.popup(event->globalPosition().toPoint());
#else
        graph_ctx_menu_.popup(event->globalPos());
#endif
    }
}

void RtpAnalysisDialog::clearLayout(QLayout *layout)
{
    if (layout) {
        QLayoutItem *item;

        //the key point here is that the layout items are stored inside the layout in a stack
        while((item = layout->takeAt(0)) != 0) {
            if (item->widget()) {
                layout->removeWidget(item->widget());
                delete item->widget();
            }

            delete item;
        }
    }
}

void RtpAnalysisDialog::closeTab(int index)
{
    // Do not close last tab with graph
    if (index != tabs_.count()) {
        QWidget *remove_tab = qobject_cast<QWidget *>(ui->tabWidget->widget(index));
        tab_info_t *tab = tabs_[index];
        tab_hash_.remove(rtpstream_to_hash(&tab->stream), tab);
        tabs_.remove(index);
        ui->tabWidget->removeTab(index);
        ui->streamGraph->removeGraph(tab->jitter_graph);
        ui->streamGraph->removeGraph(tab->diff_graph);
        ui->streamGraph->removeGraph(tab->delta_graph);
        clearLayout(tab->graphHorizontalLayout);
        delete remove_tab;
        deleteTabInfo(tab);
        g_free(tab);

        updateGraph();
    }
}

void RtpAnalysisDialog::showStreamMenu(QPoint pos)
{
    tab_info_t *tab_data = getTabInfoForCurrentTab();
    if (!tab_data) return;

    QTreeWidget *cur_tree = tab_data->tree_widget;
    if (!cur_tree) return;

    updateWidgets();
    stream_ctx_menu_.popup(cur_tree->viewport()->mapToGlobal(pos));
}

void RtpAnalysisDialog::replaceRtpStreams(QVector<rtpstream_id_t *> stream_ids)
{
    std::unique_lock<std::mutex> lock(run_mutex_, std::try_to_lock);
    if (lock.owns_lock()) {
        // Delete existing tabs (from last to first)
        if (tabs_.count() > 0) {
            for(int i = static_cast<int>(tabs_.count()); i>0; i--) {
                closeTab(i-1);
            }
        }
        addRtpStreamsPrivate(stream_ids);
    } else {
        ws_warning("replaceRtpStreams was called while other thread locked it. Current call is ignored, try it later.");
    }
}

void RtpAnalysisDialog::addRtpStreams(QVector<rtpstream_id_t *> stream_ids)
{
    std::unique_lock<std::mutex> lock(run_mutex_, std::try_to_lock);
    if (lock.owns_lock()) {
        addRtpStreamsPrivate(stream_ids);
    } else {
        ws_warning("addRtpStreams was called while other thread locked it. Current call is ignored, try it later.");
    }
}

void RtpAnalysisDialog::addRtpStreamsPrivate(QVector<rtpstream_id_t *> stream_ids)
{
    int first_tab_no = -1;

    setUpdatesEnabled(false);
    foreach(rtpstream_id_t *id, stream_ids) {
        bool found = false;

        QList<tab_info_t *> tabs = tab_hash_.values(rtpstream_id_to_hash(id));
        for (int i = 0; i < tabs.size(); i++) {
            tab_info_t *tab = tabs.at(i);
            if (rtpstream_id_equal(&tab->stream.id, id, RTPSTREAM_ID_EQUAL_SSRC))  {
                found = true;
                break;
            }
        }

        if (!found) {
            int cur_tab_no;

            tab_info_t *new_tab = g_new0(tab_info_t, 1);
            rtpstream_id_copy(id, &(new_tab->stream.id));
            new_tab->time_vals = new QVector<double>();
            new_tab->jitter_vals = new QVector<double>();
            new_tab->diff_vals = new QVector<double>();
            new_tab->delta_vals = new QVector<double>();
            tabs_ << new_tab;
            cur_tab_no = addTabUI(new_tab);
            tab_hash_.insert(rtpstream_id_to_hash(id), new_tab);
            if (first_tab_no == -1) {
                first_tab_no = cur_tab_no;
            }
        }
    }
    if (first_tab_no != -1) {
         ui->tabWidget->setCurrentIndex(first_tab_no);
    }
    setUpdatesEnabled(true);
    registerTapListener("rtp", this, NULL, 0, tapReset, tapPacket, tapDraw);
    cap_file_.retapPackets();
    updateStatistics();
    removeTapListeners();

    updateGraph();
}

void RtpAnalysisDialog::removeRtpStreams(QVector<rtpstream_id_t *> stream_ids)
{
    std::unique_lock<std::mutex> lock(run_mutex_, std::try_to_lock);
    if (lock.owns_lock()) {
        setUpdatesEnabled(false);
        foreach(rtpstream_id_t *id, stream_ids) {
            QList<tab_info_t *> tabs = tab_hash_.values(rtpstream_id_to_hash(id));
            for (int i = 0; i < tabs.size(); i++) {
                tab_info_t *tab = tabs.at(i);
                if (rtpstream_id_equal(&tab->stream.id, id, RTPSTREAM_ID_EQUAL_SSRC))  {
                    closeTab(static_cast<int>(tabs_.indexOf(tab)));
                }
            }
        }
        setUpdatesEnabled(true);

        updateGraph();
    } else {
        ws_warning("removeRtpStreams was called while other thread locked it. Current call is ignored, try it later.");
    }
}

tab_info_t *RtpAnalysisDialog::getTabInfoForCurrentTab()
{
    tab_info_t *tab_data;

    if (file_closed_) return NULL;
    QWidget *cur_tab = qobject_cast<QWidget *>(ui->tabWidget->currentWidget());
    if (!cur_tab) return NULL;
    tab_data = static_cast<tab_info_t *>(cur_tab->property("tab_data").value<void*>());

    return tab_data;
}

QToolButton *RtpAnalysisDialog::addAnalyzeButton(QDialogButtonBox *button_box, QDialog *dialog)
{
    if (!button_box) return NULL;

    QAction *ca;
    QToolButton *analysis_button = new QToolButton();
    button_box->addButton(analysis_button, QDialogButtonBox::ActionRole);
    analysis_button->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    analysis_button->setPopupMode(QToolButton::MenuButtonPopup);

    ca = new QAction(tr("&Analyze"));
    ca->setToolTip(tr("Open the analysis window for the selected stream(s)"));
    connect(ca, SIGNAL(triggered()), dialog, SLOT(rtpAnalysisReplace()));
    analysis_button->setDefaultAction(ca);
    // Overrides text striping of shortcut undercode in QAction
    analysis_button->setText(ca->text());

    QMenu *button_menu = new QMenu(analysis_button);
    button_menu->setToolTipsVisible(true);
    ca = button_menu->addAction(tr("&Set List"));
    ca->setToolTip(tr("Replace existing list in RTP Analysis Dialog with new one"));
    connect(ca, SIGNAL(triggered()), dialog, SLOT(rtpAnalysisReplace()));
    ca = button_menu->addAction(tr("&Add to List"));
    ca->setToolTip(tr("Add new set to existing list in RTP Analysis Dialog"));
    connect(ca, SIGNAL(triggered()), dialog, SLOT(rtpAnalysisAdd()));
    ca = button_menu->addAction(tr("&Remove from List"));
    ca->setToolTip(tr("Remove selected streams from list in RTP Analysis Dialog"));
    connect(ca, SIGNAL(triggered()), dialog, SLOT(rtpAnalysisRemove()));
    analysis_button->setMenu(button_menu);

    return analysis_button;
}

void RtpAnalysisDialog::on_actionPrepareFilterOne_triggered()
{
    if ((ui->tabWidget->currentIndex() < (ui->tabWidget->count()-1))) {
        QVector<rtpstream_id_t *> ids;
        ids << &(tabs_[ui->tabWidget->currentIndex()]->stream.id);
        QString filter = make_filter_based_on_rtpstream_id(ids);
        if (filter.length() > 0) {
            emit updateFilter(filter);
        }
    }
}

void RtpAnalysisDialog::on_actionPrepareFilterAll_triggered()
{
    QVector<rtpstream_id_t *>ids = getSelectedRtpIds();
    QString filter = make_filter_based_on_rtpstream_id(ids);
    if (filter.length() > 0) {
        emit updateFilter(filter);
    }
}

