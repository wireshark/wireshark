/* sequence_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "sequence_dialog.h"
#include <ui_sequence_dialog.h>

#include "epan/addr_resolv.h"

#include "file.h"

#include "wsutil/nstime.h"
#include "wsutil/utf8_entities.h"
#include "wsutil/file_util.h"
#include <wsutil/report_message.h>

#include <ui/qt/utils/color_utils.h>
#include "progress_frame.h"
#include <ui/qt/utils/qt_ui_utils.h>
#include "sequence_diagram.h"
#include "main_application.h"
#include <ui/qt/utils/variant_pointer.h>
#include <ui/alert_box.h>
#include "ui/qt/widgets/wireshark_file_dialog.h"
#include <ui/voip_calls.h>
#include "rtp_stream_dialog.h"

#include <QDir>
#include <QFontMetrics>
#include <QPoint>

// To do:
// - Resize the Time and Comment axis as well?
// - For general flows, let the user show columns other than COL_INFO.
//   (#12549)
// - Add UTF8 to text dump
// - Save to XMI? https://www.spinellis.gr/umlgraph/
// - Save to SVG? https://www.qcustomplot.com/index.php/support/forum/1677
// - Time: abs vs delta (XXX - This is currently achieved by changing
//   View->Time Display Format before opening the dialog.)
// - Hide nodes
// - Clickable time + comments? (XXX - Clicking on them selects the item for
//   the row, is there anything else?)
// - Incorporate packet comments?
// - Change line_style to seq_type (i.e. draw ACKs dashed)
// - Create WSGraph subclasses with common behavior.

static const double min_top_ = -1.0;
static const double min_left_ = -0.5;

typedef struct {
    int curr_index;
    QComboBox *flow;
    SequenceInfo *info;
} sequence_items_t;

SequenceDialog::SequenceDialog(QWidget &parent, CaptureFile &cf, SequenceInfo *info, bool voipFeatures) :
    WiresharkDialog(parent, cf),
    ui(new Ui::SequenceDialog),
    info_(info),
    num_items_(0),
    packet_num_(0),
    sequence_w_(1),
    axis_pressed_(false),
    current_rtp_sai_hovered_(nullptr),
    voipFeaturesEnabled(voipFeatures)
{
    QAction *action;

    ui->setupUi(this);
    ui->hintLabel->setSmallText();

    QCustomPlot *sp = ui->sequencePlot;
    setWindowSubtitle(info_ ? tr("Call Flow") : tr("Flow"));

    if (!info_) {
        info_ = new SequenceInfo(sequence_analysis_info_new());
        info_->sainfo()->name = "any";
        info_->sainfo()->any_addr = true;
    } else {
        info_->ref();
        sequence_analysis_free_nodes(info_->sainfo());
        num_items_ = sequence_analysis_get_nodes(info_->sainfo());
    }

    seq_diagram_ = new SequenceDiagram(sp->yAxis, sp->xAxis2, sp->yAxis2);

    // When dragging is enabled it's easy to drag past the lower and upper
    // bounds of each axis. Disable it for now.
    //sp->axisRect()->setRangeDragAxes(sp->xAxis2, sp->yAxis);
    //sp->setInteractions(QCP::iRangeDrag);

    sp->setInteraction(QCP::iSelectAxes, true);
    sp->xAxis->setSelectableParts(QCPAxis::spNone);
    sp->xAxis2->setSelectableParts(QCPAxis::spNone);
    sp->yAxis->setSelectableParts(QCPAxis::spNone);
    sp->yAxis2->setSelectableParts(QCPAxis::spAxis);

    sp->xAxis->setVisible(false);
    sp->xAxis->setPadding(0);
    sp->xAxis->setLabelPadding(0);
    sp->xAxis->setTickLabelPadding(0);

    // Light border for the diagram
    QPen base_pen(ColorUtils::alphaBlend(palette().text(), palette().base(), 0.25));
    base_pen.setWidthF(0.5);
    sp->xAxis2->setBasePen(base_pen);
    sp->yAxis->setBasePen(base_pen);
    sp->yAxis2->setBasePen(base_pen);
    // Keep the border the same if/when the axis is selected, instead of blue
    sp->xAxis2->setSelectedBasePen(base_pen);
    sp->yAxis->setSelectedBasePen(base_pen);
    sp->yAxis2->setSelectedBasePen(base_pen);

    /* QCP documentation for setTicks() says "setting show to false does not imply
     * that tick labels are invisible, too." In practice it seems to make them
     * invisible, though, so set the length to 0.
     */
    sp->yAxis2->setTickLength(0);

    sp->xAxis2->setVisible(true);
    sp->yAxis2->setVisible(true);

    key_text_ = new QCPItemText(sp);
    key_text_->setText(tr("Time"));

    key_text_->setPositionAlignment(Qt::AlignRight | Qt::AlignVCenter);
    key_text_->position->setType(QCPItemPosition::ptAbsolute);
    key_text_->setClipToAxisRect(false);

    comment_text_ = new QCPItemText(sp);
    comment_text_->setText(tr("Comment"));

    comment_text_->setPositionAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    comment_text_->position->setType(QCPItemPosition::ptAbsolute);
    comment_text_->setClipToAxisRect(false);

    one_em_ = QFontMetrics(sp->yAxis->labelFont()).height();
    ui->horizontalScrollBar->setSingleStep(100 / one_em_);
    ui->verticalScrollBar->setSingleStep(100 / one_em_);

    ui->gridLayout->setSpacing(0);
    connect(sp->yAxis, SIGNAL(rangeChanged(QCPRange)), sp->yAxis2, SLOT(setRange(QCPRange)));

    ctx_menu_.addAction(ui->actionZoomIn);
    ctx_menu_.addAction(ui->actionZoomOut);
    action = ctx_menu_.addAction(tr("Reset Diagram"), this, SLOT(resetView()));
    action->setToolTip(tr("Reset the diagram to its initial state."));
    ctx_menu_.addSeparator();
    ctx_menu_.addAction(ui->actionMoveRight10);
    ctx_menu_.addAction(ui->actionMoveLeft10);
    ctx_menu_.addAction(ui->actionMoveUp10);
    ctx_menu_.addAction(ui->actionMoveDown10);
    ctx_menu_.addAction(ui->actionMoveRight1);
    ctx_menu_.addAction(ui->actionMoveLeft1);
    ctx_menu_.addAction(ui->actionMoveUp1);
    ctx_menu_.addAction(ui->actionMoveDown1);
    ctx_menu_.addSeparator();
    ctx_menu_.addAction(ui->actionGoToPacket);
    ctx_menu_.addAction(ui->actionGoToNextPacket);
    ctx_menu_.addAction(ui->actionGoToPreviousPacket);
    ctx_menu_.addSeparator();
    action = ui->actionSelectRtpStreams;
    ctx_menu_.addAction(action);
    action->setVisible(false);
    action->setEnabled(false);
    action = ui->actionDeselectRtpStreams;
    ctx_menu_.addAction(action);
    action->setVisible(false);
    action->setEnabled(false);
    set_action_shortcuts_visible_in_context_menu(ctx_menu_.actions());

    sp->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(sp, &QCustomPlot::customContextMenuRequested, this, &SequenceDialog::showContextMenu);

    ui->addressComboBox->addItem(tr("Any"), QVariant(true));
    ui->addressComboBox->addItem(tr("Network"), QVariant(false));
    ui->addressComboBox->setCurrentIndex(ui->addressComboBox->findData(QVariant(true)));

#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
    connect(ui->addressComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &SequenceDialog::addressChanged);
#else
    connect(ui->addressComboBox, &QComboBox::currentIndexChanged, this, &SequenceDialog::addressChanged);
#endif

    sequence_items_t item_data;

    item_data.curr_index = 0;
    item_data.flow = ui->flowComboBox;
    item_data.info = info_;

    //Add all registered analysis to combo box
    sequence_analysis_table_iterate_tables(addFlowSequenceItem, &item_data);

    if (strcmp(info_->sainfo()->name, "voip") == 0) {
        ui->flowComboBox->blockSignals(true);
        ui->controlFrame->hide();
    }

    reset_button_ = ui->buttonBox->addButton(ui->actionResetDiagram->text(), QDialogButtonBox::ActionRole);
    reset_button_->setToolTip(ui->actionResetDiagram->toolTip());
    player_button_ = RtpPlayerDialog::addPlayerButton(ui->buttonBox, this);
    export_button_ = ui->buttonBox->addButton(ui->actionExportDiagram->text(), QDialogButtonBox::ActionRole);
    export_button_->setToolTip(ui->actionExportDiagram->toolTip());

    QPushButton *close_bt = ui->buttonBox->button(QDialogButtonBox::Close);
    if (close_bt) {
        close_bt->setDefault(true);
    }

    enableVoIPFeatures();

    // Enable or disable VoIP features before adding the ProgressFrame,
    // because the layout position depends on whether player_button_ is
    // visible.
    ProgressFrame::addToButtonBox(ui->buttonBox, &parent);

    loadGeometry(parent.width(), parent.height() * 4 / 5);

    if (cf.isValid() && cf.displayFilter().length() > 0) {
        ui->displayFilterCheckBox->setChecked(true);
    }

    connect(ui->displayFilterCheckBox, &QCheckBox::toggled, this, &SequenceDialog::displayFilterCheckBoxToggled);
    connect(ui->horizontalScrollBar, SIGNAL(valueChanged(int)), this, SLOT(hScrollBarChanged(int)));
    connect(ui->verticalScrollBar, SIGNAL(valueChanged(int)), this, SLOT(vScrollBarChanged(int)));
    connect(sp->xAxis2, SIGNAL(rangeChanged(QCPRange)), this, SLOT(xAxisChanged(QCPRange)));
    connect(sp->yAxis, SIGNAL(rangeChanged(QCPRange)), this, SLOT(yAxisChanged(QCPRange)));
    connect(sp, &QCustomPlot::mousePress, this, &SequenceDialog::diagramClicked);
    connect(sp, &QCustomPlot::mouseRelease, this, &SequenceDialog::mouseReleased);
    connect(sp, &QCustomPlot::mouseMove, this, &SequenceDialog::mouseMoved);
    connect(sp, &QCustomPlot::mouseWheel, this, &SequenceDialog::mouseWheeled);
    connect(sp, &QCustomPlot::axisDoubleClick, this, &SequenceDialog::axisDoubleClicked);
    connect(sp, &QCustomPlot::afterLayout, this, &SequenceDialog::layoutAxisLabels);
}

SequenceDialog::~SequenceDialog()
{
    info_->unref();
    delete ui;
}

void SequenceDialog::enableVoIPFeatures()
{
    player_button_->setVisible(voipFeaturesEnabled);
    ui->actionSelectRtpStreams->setVisible(voipFeaturesEnabled);
    ui->actionDeselectRtpStreams->setVisible(voipFeaturesEnabled);
    // Buttons and actions are enabled when valid call selected
}

void SequenceDialog::updateWidgets()
{
    WiresharkDialog::updateWidgets();
}

bool SequenceDialog::event(QEvent *event)
{
    if (event->type() == QEvent::ToolTip) {
        QHelpEvent *helpEvent = static_cast<QHelpEvent *>(event);
        seq_analysis_item_t *sai = seq_diagram_->itemForPosY(helpEvent->pos().y());
        if (sai && seq_diagram_->inComment(helpEvent->pos()) && (sai->comment != seq_diagram_->elidedComment(sai->comment))) {
            QToolTip::showText(helpEvent->globalPos(), sai->comment);
        } else {
            QToolTip::hideText();
            event->ignore();
        }

        return true;
    }
    return QWidget::event(event);
}

void SequenceDialog::showEvent(QShowEvent *)
{
    QTimer::singleShot(0, this, SLOT(fillDiagram()));
}

void SequenceDialog::resizeEvent(QResizeEvent *)
{
    if (!info_) return;

    resetAxes(true);
}

void SequenceDialog::keyPressEvent(QKeyEvent *event)
{
    int pan_pixels = event->modifiers() & Qt::ShiftModifier ? 1 : 10;

    // XXX - Copy some shortcuts from tcp_stream_dialog.cpp
    switch(event->key()) {
    case Qt::Key_Minus:
    case Qt::Key_Underscore:    // Shifted minus on U.S. keyboards
        on_actionZoomOut_triggered();
        break;
    case Qt::Key_Plus:
    case Qt::Key_Equal:         // Unshifted plus on U.S. keyboards
        on_actionZoomIn_triggered();
        break;

    case Qt::Key_Right:
    case Qt::Key_L:
        panAxes(pan_pixels, 0);
        break;
    case Qt::Key_Left:
    case Qt::Key_H:
        panAxes(-1 * pan_pixels, 0);
        break;
    case Qt::Key_Up:
    case Qt::Key_K:
        panAxes(0, pan_pixels);
        break;
    case Qt::Key_Down:
    case Qt::Key_J:
        panAxes(0, -1 * pan_pixels);
        break;

    case Qt::Key_PageDown:
    case Qt::Key_Space:
        ui->verticalScrollBar->setValue(ui->verticalScrollBar->value() + ui->verticalScrollBar->pageStep());
        break;
    case Qt::Key_PageUp:
        ui->verticalScrollBar->setValue(ui->verticalScrollBar->value() - ui->verticalScrollBar->pageStep());
        break;

    case Qt::Key_0:
    case Qt::Key_ParenRight:    // Shifted 0 on U.S. keyboards
    case Qt::Key_R:
    case Qt::Key_Home:
        resetAxes();
        break;

    case Qt::Key_G:
        on_actionGoToPacket_triggered();
        break;
    case Qt::Key_N:
        on_actionGoToNextPacket_triggered();
        break;
    case Qt::Key_P:
        on_actionGoToPreviousPacket_triggered();
        break;
    case Qt::Key_S:
        if (voipFeaturesEnabled) {
            on_actionSelectRtpStreams_triggered();
        }
        break;
    case Qt::Key_D:
        if (voipFeaturesEnabled) {
            on_actionDeselectRtpStreams_triggered();
        }
        break;
    }

    QDialog::keyPressEvent(event);
}

void SequenceDialog::hScrollBarChanged(int value)
{
    if (qAbs(ui->sequencePlot->xAxis2->range().center()-value/100.0) > 0.01) {
      ui->sequencePlot->xAxis2->setRange(value/100.0, ui->sequencePlot->xAxis2->range().size(), Qt::AlignCenter);
      ui->sequencePlot->replot(QCustomPlot::rpQueuedReplot);
    }
}

void SequenceDialog::vScrollBarChanged(int value)
{
    if (qAbs(ui->sequencePlot->yAxis->range().center()-value/100.0) > 0.01) {
      ui->sequencePlot->yAxis->setRange(value/100.0, ui->sequencePlot->yAxis->range().size(), Qt::AlignCenter);
      ui->sequencePlot->replot(QCustomPlot::rpQueuedReplot);
    }
}

void SequenceDialog::xAxisChanged(QCPRange range)
{
    ui->horizontalScrollBar->setValue(qRound(qreal(range.center()*100.0)));
    ui->horizontalScrollBar->setPageStep(qRound(qreal(range.size()*100.0)));
}

void SequenceDialog::yAxisChanged(QCPRange range)
{
    ui->verticalScrollBar->setValue(qRound(qreal(range.center()*100.0)));
    ui->verticalScrollBar->setPageStep(qRound(qreal(range.size()*100.0)));
}

void SequenceDialog::showContextMenu(const QPoint &pos)
{
    ctx_menu_.popup(ui->sequencePlot->mapToGlobal(pos));
}

void SequenceDialog::diagramClicked(QMouseEvent *event)
{
    current_rtp_sai_selected_ = NULL;
    if (event) {
        QCPAxis *yAxis2 = ui->sequencePlot->yAxis2;
        if (std::abs(event->pos().x() - yAxis2->axisRect()->right()) < 5) {
            yAxis2->setSelectedParts(QCPAxis::spAxis);
            axis_pressed_ = true;
        }
        seq_analysis_item_t *sai = seq_diagram_->itemForPosY(event->pos().y());
        if (voipFeaturesEnabled) {
            ui->actionSelectRtpStreams->setEnabled(false);
            ui->actionDeselectRtpStreams->setEnabled(false);
            player_button_->setEnabled(false);
            if (sai) {
                if (GA_INFO_TYPE_RTP == sai->info_type) {
                    ui->actionSelectRtpStreams->setEnabled(true && !file_closed_);
                    ui->actionDeselectRtpStreams->setEnabled(true && !file_closed_);
                    player_button_->setEnabled(true && !file_closed_);
                    current_rtp_sai_selected_ = sai;
                }
            }
        }

        switch (event->button()) {
        case Qt::LeftButton:
            on_actionGoToPacket_triggered();
            break;
        default:
            break;
        }
    }

}

void SequenceDialog::axisDoubleClicked(QCPAxis *axis, QCPAxis::SelectablePart, QMouseEvent*)
{
    if (axis == ui->sequencePlot->yAxis2) {
        QCP::MarginSides autoMargins = axis->axisRect()->autoMargins();
        axis->axisRect()->setAutoMargins(autoMargins | QCP::msRight);
        ui->sequencePlot->replot();
        axis->axisRect()->setAutoMargins(autoMargins);
        ui->sequencePlot->replot();
    }
}

void SequenceDialog::mouseReleased(QMouseEvent*)
{
    QCustomPlot *sp = ui->sequencePlot;
    sp->yAxis2->setSelectedParts(QCPAxis::spNone);
    axis_pressed_ = false;
    sp->replot(QCustomPlot::rpQueuedReplot);
}

void SequenceDialog::mouseMoved(QMouseEvent *event)
{
    current_rtp_sai_hovered_ = NULL;
    packet_num_ = 0;
    QString hint;
    Qt::CursorShape shape = Qt::ArrowCursor;
    if (event) {
        QCPAxis *yAxis2 = ui->sequencePlot->yAxis2;
        // For some reason we need this extra bool and can't rely just on
        // yAxis2->selectedParts().testFlag(QCPAxis::spAxis)
        if (axis_pressed_) {
            int x = qMax(event->pos().x(), yAxis2->axisRect()->left());
            QMargins margins = yAxis2->axisRect()->margins();
            margins += QMargins(0, 0, yAxis2->axisRect()->right() - x, 0);
            yAxis2->axisRect()->setMargins(margins);
            shape = Qt::SplitHCursor;
            ui->sequencePlot->replot(QCustomPlot::rpQueuedReplot);
        } else {
            if (std::abs(event->pos().x() - yAxis2->axisRect()->right()) < 5) {
                shape = Qt::SplitHCursor;
            }
        }
        seq_analysis_item_t *sai = seq_diagram_->itemForPosY(event->pos().y());
        if (sai) {
            if (GA_INFO_TYPE_RTP == sai->info_type) {
                ui->actionSelectRtpStreams->setEnabled(true);
                ui->actionDeselectRtpStreams->setEnabled(true);
                current_rtp_sai_hovered_ = sai;
            }
            packet_num_ = sai->frame_number;
            hint = QString("Packet %1: %2").arg(packet_num_).arg(sai->comment);
        }
    }

    if (ui->sequencePlot->cursor().shape() != shape) {
        ui->sequencePlot->setCursor(QCursor(shape));
    }

    if (hint.isEmpty()) {
        if (!info_->sainfo()) {
            hint += tr("No data");
        } else {
            hint += tr("%Ln node(s)", "", info_->sainfo()->num_nodes) + QString(", ")
                    + tr("%Ln item(s)", "", num_items_);
        }
    }

    ui->hintLabel->setText(hint);
}

void SequenceDialog::mouseWheeled(QWheelEvent *event)
{
    int scroll_x = event->angleDelta().x() * -1 / 8;
    scroll_x *= ui->horizontalScrollBar->singleStep();
    if (scroll_x) {
        ui->horizontalScrollBar->setValue(ui->horizontalScrollBar->value() + scroll_x);
    }

    int scroll_y = event->angleDelta().ry() * -1 / 8;
    scroll_y *= ui->verticalScrollBar->singleStep();
    if (scroll_y) {
        ui->verticalScrollBar->setValue(ui->verticalScrollBar->value() + scroll_y);
    }

    event->accept();
}

void SequenceDialog::on_buttonBox_clicked(QAbstractButton *button)
{
    if (button == reset_button_) {
        resetView();
    } else if (button == export_button_) {
        exportDiagram();
    }
}

void SequenceDialog::exportDiagram()
{
    QString file_name, extension;
    QDir path(mainApp->openDialogInitialDir());
    QString pdf_filter = tr("Portable Document Format (*.pdf)");
    QString png_filter = tr("Portable Network Graphics (*.png)");
    QString bmp_filter = tr("Windows Bitmap (*.bmp)");
    // Gaze upon my beautiful graph with lossy artifacts!
    QString jpeg_filter = tr("JPEG File Interchange Format (*.jpeg *.jpg)");
    QString ascii_filter = tr("ASCII (*.txt)");

    QString filter = QString("%1;;%2;;%3;;%4")
            .arg(pdf_filter)
            .arg(png_filter)
            .arg(bmp_filter)
            .arg(jpeg_filter);
    if (!file_closed_) {
        filter.append(QString(";;%5").arg(ascii_filter));
    }

    file_name = WiresharkFileDialog::getSaveFileName(this, mainApp->windowTitleString(tr("Save Graph As…")),
                                             path.canonicalPath(), filter, &extension);

    if (file_name.length() > 0) {
        bool save_ok = false;
        // The QCustomPlot save functions take a width and a height, measured
        // in pixels (for the entire viewport).
        // In order to display the whole graph, we have to change the axes
        // and scale up the width and height appropriately so that the text
        // has the proper spacing. (Using the scale factor in some of the
        // image writing functions makes the text illegible.)
        // If we set the axes back to their old value without replotting,
        // there's no visual effects from doing this.
        QCustomPlot *sp = ui->sequencePlot;
        QCPRange old_yrange = sp->yAxis->range();
        QCPRange old_xrange = sp->xAxis2->range();
        // For the horizontal aspect, we'll display all the nodes.
        // Nodes can excluded by filtering (hiding nodes is in the todo list.)
        // Use the current width of a node as determined by the user zooming
        // with Key_Plus and Key_Minus, multiply that by the number of nodes,
        // and add in the margin from the Time and Comment columns.
        // MAX_NUM_NODES is 40, which results in a manageable 8802 pixel width
        // at the default zoom level on my Linux box.
        // (If the user has zoomed in unreasonably, that's on the user.)
        int hmargin = sp->axisRect()->outerRect().width() - sp->axisRect()->width();
        double nodeSize = (sp->axisRect()->width()) / old_xrange.size();
        // For the vertical aspect, we need to put a bound on the number of
        // pixels or items we'll put in an image, as it can get far too large.
        // (JPEG only supports 16 bit aspect sizes, PNG supports 31 bit but
        // many viewers don't.)
        int vmargin = sp->axisRect()->outerRect().height() - sp->axisRect()->height();
        // 1000 items is a little over 27000 pixels in height on my machine.
        // XXX - Should this pref be pixels instead of items?
        //int max_pixel = 24576;
        //double range_span = ((max_pixel - vmargin) / (one_em_ * 1.5));
        double range_span = prefs.flow_graph_max_export_items;
        // Start at the current top item, and QCPRange::bounded does what
        // we want, with margins of 1.0 on top and bottom.
        QCPRange new_yrange(old_yrange.lower, old_yrange.lower + range_span);
        new_yrange = new_yrange.bounded(min_top_, num_items_);
        sp->yAxis->setRange(new_yrange);
        // margins of 0.5 on left and right for port number, etc.
        sp->xAxis2->setRange(min_left_, info_->sainfo()->num_nodes - 0.5);
        // As seen in resetAxes(), we have an item take ~ 1.5*one_em_ pixels.
        int ySize = new_yrange.size() * (one_em_ * 1.5) + vmargin;
        int xSize = (nodeSize * info_->sainfo()->num_nodes) + hmargin;
        if (extension.compare(pdf_filter) == 0) {
            save_ok = ui->sequencePlot->savePdf(file_name, xSize, ySize);
        } else if (extension.compare(png_filter) == 0) {
            save_ok = ui->sequencePlot->savePng(file_name, xSize, ySize);
        } else if (extension.compare(bmp_filter) == 0) {
            save_ok = ui->sequencePlot->saveBmp(file_name, xSize, ySize);
        } else if (extension.compare(jpeg_filter) == 0) {
            save_ok = ui->sequencePlot->saveJpg(file_name, xSize, ySize);
        } else if (extension.compare(ascii_filter) == 0 && !file_closed_ && info_->sainfo()) {
            FILE  *outfile = ws_fopen(file_name.toUtf8().constData(), "w");
            if (outfile != NULL) {
                sequence_analysis_dump_to_file(outfile, info_->sainfo(), 0);
                save_ok = true;
                fclose(outfile);
            } else {
                save_ok = false;
            }
        }
        sp->yAxis->setRange(old_yrange);
        sp->xAxis2->setRange(old_xrange);
        // else error dialog?
        if (save_ok) {
            mainApp->setLastOpenDirFromFilename(file_name);
        } else {
            open_failure_alert_box(file_name.toUtf8().constData(), errno, true);
        }
    }
}

void SequenceDialog::fillDiagram()
{
    if (!info_->sainfo() || file_closed_) return;

    QCustomPlot *sp = ui->sequencePlot;

    if (strcmp(info_->sainfo()->name, "voip") == 0) {
        seq_diagram_->setData(info_->sainfo());
    } else {
        seq_diagram_->clearData();
        sequence_analysis_list_free(info_->sainfo());

        register_analysis_t* analysis = sequence_analysis_find_by_name(info_->sainfo()->name);
        if (analysis != NULL)
        {
            GString *error_string;
            const char *filter = NULL;
            if (ui->displayFilterCheckBox->checkState() == Qt::Checked)
                filter = cap_file_.capFile()->dfilter;

            error_string = register_tap_listener(sequence_analysis_get_tap_listener_name(analysis), info_->sainfo(), filter, sequence_analysis_get_tap_flags(analysis),
                                       NULL, sequence_analysis_get_packet_func(analysis), NULL, NULL);
            if (error_string) {
                report_failure("Sequence dialog - tap registration failed: %s", error_string->str);
                g_string_free(error_string, TRUE);
            }

            cf_retap_packets(cap_file_.capFile());
            remove_tap_listener(info_->sainfo());

            num_items_ = sequence_analysis_get_nodes(info_->sainfo());
            seq_diagram_->setData(info_->sainfo());
        }
    }

    sequence_w_ = one_em_ * 15; // Arbitrary

    mouseMoved(NULL);
    resetAxes();

    // XXX QCustomPlot doesn't seem to draw any sort of focus indicator.
    sp->setFocus();
}

void SequenceDialog::panAxes(int x_pixels, int y_pixels)
{
    // We could simplify this quite a bit if we set the scroll bar values instead.
    if (!info_->sainfo()) return;

    QCustomPlot *sp = ui->sequencePlot;
    double h_pan = 0.0;
    double v_pan = 0.0;

    h_pan = sp->xAxis2->range().size() * x_pixels / sp->xAxis2->axisRect()->width();
    // The nodes are placed on integer x values from 0 to num_nodes - 1.
    // We allow 0.5 of margin around a node (also reflected in the
    // horizontalScrollBar range.)
    if (h_pan < 0) {
        h_pan = qMax(h_pan, min_left_ - sp->xAxis2->range().lower);
    } else {
        h_pan = qMin(h_pan, info_->sainfo()->num_nodes - 0.5 - sp->xAxis2->range().upper);
    }

    if (sp->yAxis->rangeReversed()) {
        // For reversed axes, lower still references the mathematically
        // smaller number than upper, so reverse the direction.
        y_pixels = -y_pixels;
    }
    v_pan = sp->yAxis->range().size() * y_pixels / sp->yAxis->axisRect()->height();
    if (v_pan < 0) {
        v_pan = qMax(v_pan, min_top_ - sp->yAxis->range().lower);
    } else {
        v_pan = qMin(v_pan, num_items_ - sp->yAxis->range().upper);
    }

    if (h_pan && !(sp->xAxis2->range().contains(min_left_) && sp->xAxis2->range().contains(info_->sainfo()->num_nodes - 0.5))) {
        sp->xAxis2->moveRange(h_pan);
        sp->replot(QCustomPlot::rpQueuedReplot);
    }
    if (v_pan && !(sp->yAxis->range().contains(min_top_) && sp->yAxis->range().contains(num_items_))) {
        sp->yAxis->moveRange(v_pan);
        sp->replot(QCustomPlot::rpQueuedReplot);
    }
}

void SequenceDialog::resetAxes(bool keep_lower)
{
    if (!info_->sainfo()) return;

    QCustomPlot *sp = ui->sequencePlot;

    // Allow space for labels on the top and port numbers on the left.
    double top_pos = min_top_, left_pos = min_left_;
    if (keep_lower) {
        top_pos = sp->yAxis->range().lower;
        left_pos = sp->xAxis2->range().lower;
    }

    double range_span = sp->viewport().width() / sequence_w_ * sp->axisRect()->rangeZoomFactor(Qt::Horizontal);
    sp->xAxis2->setRange(left_pos, range_span + left_pos);

    range_span = sp->axisRect()->height() / (one_em_ * 1.5);
    sp->yAxis->setRange(top_pos, range_span + top_pos);

    double rmin = sp->xAxis2->range().size() / 2;
    ui->horizontalScrollBar->setRange((rmin + min_left_) * 100, (info_->sainfo()->num_nodes - 0.5 - rmin) * 100);
    xAxisChanged(sp->xAxis2->range());
    ui->horizontalScrollBar->setValue(ui->horizontalScrollBar->minimum()); // Shouldn't be needed.

    rmin = (sp->yAxis->range().size() / 2);
    ui->verticalScrollBar->setRange((rmin + min_top_) * 100, (num_items_ - 0.5 - rmin) * 100);
    yAxisChanged(sp->yAxis->range());

    sp->replot(QCustomPlot::rpQueuedReplot);
}

void SequenceDialog::layoutAxisLabels()
{
    // It would be exceedingly handy if we could do one or both of the
    // following:
    // - Position an axis label above its axis inline with the tick labels.
    // - Anchor a QCPItemText to one of the corners of a QCPAxis.
    // Neither of those appear to be possible, so we place our labels using
    // absolute positioning immediately after the layout size and positions
    // are set, and right before the replot (or print) draw step occurs,
    // using the new QCustomPlot 2.1.0 QCustomPlot::afterLayout signal.

    QCustomPlot *sp = ui->sequencePlot;

    QRect axis_rect = sp->axisRect()->rect();

    key_text_->position->setCoords(axis_rect.left()
                                   - sp->yAxis->padding()
                                   - sp->yAxis->tickLabelPadding()
                                   - sp->yAxis->offset(),
                                   axis_rect.top() / 2);
    comment_text_->position->setCoords(axis_rect.right()
                                       + sp->yAxis2->padding()
                                       + sp->yAxis2->tickLabelPadding()
                                       + sp->yAxis2->offset(),
                                       axis_rect.top()  / 2);
}

void SequenceDialog::resetView()
{
    resetAxes();
}

void SequenceDialog::on_actionGoToPacket_triggered()
{
    if (!file_closed_ && packet_num_ > 0) {
        cf_goto_frame(cap_file_.capFile(), packet_num_, false);
        seq_diagram_->setSelectedPacket(packet_num_);
    }
}

void SequenceDialog::goToAdjacentPacket(bool next)
{
    if (file_closed_) return;

    int old_key = seq_diagram_->selectedKey();
    int adjacent_packet = seq_diagram_->adjacentPacket(next);
    int new_key = seq_diagram_->selectedKey();

    if (adjacent_packet > 0) {
        if (new_key >= 0) {
            QCustomPlot *sp = ui->sequencePlot;
            double range_offset = 0.0;
            // Scroll if we're at our scroll margin and we haven't reached
            // the end of our range.
            double scroll_margin = 3.0; // Lines

            if (old_key >= 0) {
                range_offset = new_key - old_key;
            }

            if (new_key < sp->yAxis->range().lower) {
                // Out of range, top
                range_offset = qRound(new_key - sp->yAxis->range().lower - scroll_margin - 0.5);
            } else if (new_key > sp->yAxis->range().upper) {
                // Out of range, bottom
                range_offset = qRound(new_key - sp->yAxis->range().upper + scroll_margin + 0.5);
            } else if (next) {
                // In range, next
                if (new_key + scroll_margin < sp->yAxis->range().upper) {
                    range_offset = 0.0;
                }
            } else {
                // In range, previous
                if (new_key - scroll_margin > sp->yAxis->range().lower) {
                    range_offset = 0.0;
                }
            }

            // Clamp to our upper & lower bounds.
            if (range_offset > 0) {
                range_offset = qMin(range_offset, num_items_ - sp->yAxis->range().upper);
            } else if (range_offset < 0) {
                range_offset = qMax(range_offset, min_top_ - sp->yAxis->range().lower);
            }
            sp->yAxis->moveRange(range_offset);
        }
        cf_goto_frame(cap_file_.capFile(), adjacent_packet, false);
        seq_diagram_->setSelectedPacket(adjacent_packet);
    }
}

void SequenceDialog::displayFilterCheckBoxToggled(bool)
{
    fillDiagram();
}

void SequenceDialog::on_flowComboBox_activated(int index)
{
    if (!info_->sainfo() || (strcmp(info_->sainfo()->name, "voip") == 0) || index < 0)
        return;

    register_analysis_t* analysis = VariantPointer<register_analysis_t>::asPtr(ui->flowComboBox->itemData(index));
    info_->sainfo()->name = sequence_analysis_get_name(analysis);

    fillDiagram();
}

void SequenceDialog::addressChanged(int)
{
    if (!info_->sainfo()) return;

    QVariant data = ui->addressComboBox->currentData();
    if (data.isValid()) {
        info_->sainfo()->any_addr = data.toBool();
        fillDiagram();
    }
}

void SequenceDialog::on_actionMoveRight10_triggered()
{
    panAxes(10, 0);
}

void SequenceDialog::on_actionMoveLeft10_triggered()
{
    panAxes(-10, 0);
}

void SequenceDialog::on_actionMoveUp10_triggered()
{
    panAxes(0, 10);
}

void SequenceDialog::on_actionMoveDown10_triggered()
{
    panAxes(0, -10);
}

void SequenceDialog::on_actionMoveRight1_triggered()
{
    panAxes(1, 0);
}

void SequenceDialog::on_actionMoveLeft1_triggered()
{
    panAxes(-1, 0);
}

void SequenceDialog::on_actionMoveUp1_triggered()
{
    panAxes(0, 1);
}

void SequenceDialog::on_actionMoveDown1_triggered()
{
    panAxes(0, -1);
}

void SequenceDialog::on_actionZoomIn_triggered()
{
    zoomXAxis(true);
}

void SequenceDialog::on_actionZoomOut_triggered()
{
    zoomXAxis(false);
}

void SequenceDialog::processRtpStream(bool select)
{
    seq_analysis_item_t *current_rtp_sai = NULL;

    // If RTP sai is below mouse, use it. If not, try selected RTP sai
    if (current_rtp_sai_hovered_ && GA_INFO_TYPE_RTP == current_rtp_sai_hovered_->info_type) {
        current_rtp_sai = current_rtp_sai_hovered_;
    } else if (current_rtp_sai_selected_ && GA_INFO_TYPE_RTP == current_rtp_sai_selected_->info_type) {
        current_rtp_sai = current_rtp_sai_selected_;
    }

    if (current_rtp_sai) {
        QVector<rtpstream_id_t *> stream_ids;

        // We don't need copy it as it is not cleared during retap
        stream_ids << &((rtpstream_info_t *)current_rtp_sai->info_ptr)->id;
        if (select) {
            emit rtpStreamsDialogSelectRtpStreams(stream_ids);
        } else {
            emit rtpStreamsDialogDeselectRtpStreams(stream_ids);
        }
        raise();
    }
}

void SequenceDialog::on_actionSelectRtpStreams_triggered()
{
    processRtpStream(true);
}

void SequenceDialog::on_actionDeselectRtpStreams_triggered()
{
    processRtpStream(false);
}

void SequenceDialog::zoomXAxis(bool in)
{
    QCustomPlot *sp = ui->sequencePlot;
    double h_factor = sp->axisRect()->rangeZoomFactor(Qt::Horizontal);

    if (!in) {
        h_factor = pow(h_factor, -1);
    }

    sp->xAxis2->scaleRange(h_factor, sp->xAxis->range().lower);
    sp->replot();
}

bool SequenceDialog::addFlowSequenceItem(const void* key, void *value, void *userdata)
{
    const char* name = (const char*)key;
    register_analysis_t* analysis = (register_analysis_t*)value;
    sequence_items_t* item_data = (sequence_items_t*)userdata;

    /* XXX - Although "voip" isn't a registered name yet, it appears to have special
       handling that will be done outside of registered data */
    if (strcmp(name, "voip") == 0)
        return false;

    item_data->flow->addItem(sequence_analysis_get_ui_name(analysis), VariantPointer<register_analysis_t>::asQVariant(analysis));

    if (item_data->flow->itemData(item_data->curr_index).toString().compare(item_data->info->sainfo()->name) == 0)
        item_data->flow->setCurrentIndex(item_data->curr_index);

    item_data->curr_index++;

    return false;
}

QVector<rtpstream_id_t *>SequenceDialog::getSelectedRtpIds()
{
    QVector<rtpstream_id_t *> stream_ids;

    if (current_rtp_sai_selected_ && GA_INFO_TYPE_RTP == current_rtp_sai_selected_->info_type) {
        stream_ids << &((rtpstream_info_t *)current_rtp_sai_selected_->info_ptr)->id;
    }

    return stream_ids;
}

void SequenceDialog::rtpPlayerReplace()
{
    emit rtpPlayerDialogReplaceRtpStreams(getSelectedRtpIds());
}

void SequenceDialog::rtpPlayerAdd()
{
    emit rtpPlayerDialogAddRtpStreams(getSelectedRtpIds());
}

void SequenceDialog::rtpPlayerRemove()
{
    emit rtpPlayerDialogRemoveRtpStreams(getSelectedRtpIds());
}

void SequenceDialog::on_buttonBox_helpRequested()
{
    mainApp->helpTopicAction(HELP_STAT_FLOW_GRAPH);
}

SequenceInfo::SequenceInfo(seq_analysis_info_t *sainfo) :
    sainfo_(sainfo),
    count_(1)
{
}

SequenceInfo::~SequenceInfo()
{
    sequence_analysis_info_free(sainfo_);
}
