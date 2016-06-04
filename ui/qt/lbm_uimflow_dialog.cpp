/* lbm_uimflow_dialog.cpp
 *
 * Copyright (c) 2005-2014 Informatica Corporation. All Rights Reserved.
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

// Adapted from sequence_dialog.cpp

#include "lbm_uimflow_dialog.h"
#include <ui_lbm_uimflow_dialog.h>

#include "file.h"

#include <epan/dissectors/packet-lbm.h>
#include <epan/packet_info.h>
#include <epan/tap.h>
#include <epan/to_str.h>
#include <epan/addr_resolv.h>
#include <wsutil/nstime.h>

#include <wsutil/utf8_entities.h>

#include "qt_ui_utils.h"
#include "sequence_diagram.h"
#include "wireshark_application.h"

#include <QDir>
#include <QFileDialog>
#include <QFontMetrics>
#include <QPoint>

#include <QDebug>

static gboolean lbm_uimflow_add_to_graph(seq_analysis_info_t * seq_info, packet_info * pinfo, const lbm_uim_stream_info_t * stream_info)
{
    lbm_uim_stream_endpoint_t epa;
    lbm_uim_stream_endpoint_t epb;
    seq_analysis_item_t * item;
    gchar * ctxinst1 = NULL;
    gchar * ctxinst2 = NULL;
    gboolean swap_endpoints = FALSE;
    int rc;

    if (stream_info->endpoint_a.type != stream_info->endpoint_b.type)
    {
        return (FALSE);
    }
    if (stream_info->endpoint_a.type == lbm_uim_instance_stream)
    {
        rc = memcmp((void *)stream_info->endpoint_a.stream_info.ctxinst.ctxinst,
            (void *)stream_info->endpoint_b.stream_info.ctxinst.ctxinst,
            LBM_CONTEXT_INSTANCE_BLOCK_SZ);
        if (rc <= 0)
        {
            swap_endpoints = FALSE;
        }
        else
        {
            swap_endpoints = TRUE;
        }
    }
    else
    {
        if (stream_info->endpoint_a.stream_info.dest.domain < stream_info->endpoint_b.stream_info.dest.domain)
        {
            swap_endpoints = FALSE;
        }
        else if (stream_info->endpoint_a.stream_info.dest.domain > stream_info->endpoint_b.stream_info.dest.domain)
        {
            swap_endpoints = TRUE;
        }
        else
        {
            int compare;

            compare = cmp_address(&(stream_info->endpoint_a.stream_info.dest.addr), &(stream_info->endpoint_b.stream_info.dest.addr));
            if (compare < 0)
            {
                swap_endpoints = FALSE;
            }
            else if (compare > 0)
            {
                swap_endpoints = TRUE;
            }
            else
            {
                if (stream_info->endpoint_a.stream_info.dest.port <= stream_info->endpoint_b.stream_info.dest.port)
                {
                    swap_endpoints = FALSE;
                }
                else
                {
                    swap_endpoints = TRUE;
                }
            }
        }
    }
    if (swap_endpoints == FALSE)
    {
        epa = stream_info->endpoint_a;
        epb = stream_info->endpoint_b;
    }
    else
    {
        epb = stream_info->endpoint_a;
        epa = stream_info->endpoint_b;
    }
    item = (seq_analysis_item_t *)g_malloc0(sizeof(seq_analysis_item_t));
    copy_address(&(item->src_addr), &(pinfo->src));
    copy_address(&(item->dst_addr), &(pinfo->dst));
    item->frame_number = pinfo->num;
    item->port_src = pinfo->srcport;
    item->port_dst = pinfo->destport;
    item->protocol = g_strdup(port_type_to_str(pinfo->ptype));
    if (stream_info->description == NULL)
    {
        item->frame_label = g_strdup_printf("(%" G_GUINT32_FORMAT ")", stream_info->sqn);
    }
    else
    {
        item->frame_label = g_strdup_printf("%s (%" G_GUINT32_FORMAT ")", stream_info->description, stream_info->sqn);
    }
    if (epa.type == lbm_uim_instance_stream)
    {
        ctxinst1 = bytes_to_str(pinfo->pool, epa.stream_info.ctxinst.ctxinst, sizeof(epa.stream_info.ctxinst.ctxinst));
        ctxinst2 = bytes_to_str(pinfo->pool, epb.stream_info.ctxinst.ctxinst, sizeof(epb.stream_info.ctxinst.ctxinst));
        item->comment = g_strdup_printf("%s <-> %s [%" G_GUINT64_FORMAT "]",
            ctxinst1,
            ctxinst2,
            stream_info->channel);
    }
    else
    {
        item->comment = g_strdup_printf("%" G_GUINT32_FORMAT ":%s:%" G_GUINT16_FORMAT " <-> %" G_GUINT32_FORMAT ":%s:%" G_GUINT16_FORMAT " [%" G_GUINT64_FORMAT "]",
            epa.stream_info.dest.domain,
            address_to_str(pinfo->pool, &(epa.stream_info.dest.addr)),
            epa.stream_info.dest.port,
            epb.stream_info.dest.domain,
            address_to_str(pinfo->pool, &(epb.stream_info.dest.addr)),
            epb.stream_info.dest.port,
            stream_info->channel);
    }
    item->conv_num = (guint16)LBM_CHANNEL_ID(stream_info->channel);
    item->display = TRUE;
    item->line_style = 1;
    g_queue_push_tail(seq_info->items, item);
    return (TRUE);
}

static gboolean lbm_uimflow_tap_packet(void * tap_data, packet_info * pinfo, epan_dissect_t *, const void * stream_info)
{
    seq_analysis_info_t * sainfo = (seq_analysis_info_t *)tap_data;
    const lbm_uim_stream_info_t * info = (const lbm_uim_stream_info_t *)stream_info;

    if ((sainfo->all_packets) || (pinfo->fd->flags.passed_dfilter == 1))
    {
        gboolean rc = lbm_uimflow_add_to_graph(sainfo, pinfo, info);
        return (rc);
    }
    return (FALSE);
}

static void lbm_uimflow_get_analysis(capture_file * cfile, seq_analysis_info_t * seq_info)
{
    GList * list = NULL;
    gchar time_str[COL_MAX_LEN];

    register_tap_listener("lbm_uim", (void *)seq_info, NULL, TL_REQUIRES_COLUMNS, NULL, lbm_uimflow_tap_packet, NULL);
    cf_retap_packets(cfile);
    remove_tap_listener((void *)seq_info);

    /* Fill in the timestamps. */
    list = g_queue_peek_nth_link(seq_info->items, 0);
    while (list != NULL)
    {
        seq_analysis_item_t * seq_item = (seq_analysis_item_t *)list->data;
        set_fd_time(cfile->epan, frame_data_sequence_find(cfile->frames, seq_item->frame_number), time_str);
        seq_item->time_str = g_strdup(time_str);
        list = g_list_next(list);
    }
}

// To do:
// - Add UTF8 to text dump
// - Save to XMI? http://www.umlgraph.org/
// - Time: abs vs delta
// - Hide nodes
// - Clickable time + comments?
// - Incorporate packet comments?
// - Change line_style to seq_type (i.e. draw ACKs dashed)
// - Create WSGraph subclasses with common behavior.
// - Help button and text

LBMUIMFlowDialog::LBMUIMFlowDialog(QWidget * parent, capture_file * cfile) :
    GeometryStateDialog(parent),
    m_ui(new Ui::LBMUIMFlowDialog),
    m_capture_file(cfile),
    m_num_items(0),
    m_packet_num(0),
    m_node_label_width(20)
{
    m_ui->setupUi(this);
    if (parent) loadGeometry(parent->width(), parent->height() * 4 / 5);

    QCustomPlot * sp = m_ui->sequencePlot;

    m_sequence_diagram = new SequenceDiagram(sp->yAxis, sp->xAxis2, sp->yAxis2);
    sp->addPlottable(m_sequence_diagram);
    sp->axisRect()->setRangeDragAxes(sp->xAxis2, sp->yAxis);

    sp->xAxis->setVisible(false);
    sp->xAxis->setPadding(0);
    sp->xAxis->setLabelPadding(0);
    sp->xAxis->setTickLabelPadding(0);
    sp->xAxis2->setVisible(true);
    sp->yAxis2->setVisible(true);

    m_one_em = QFontMetrics(sp->yAxis->labelFont()).height();
    m_ui->horizontalScrollBar->setSingleStep(100 / m_one_em);
    m_ui->verticalScrollBar->setSingleStep(100 / m_one_em);

    sp->setInteractions(QCP::iRangeDrag);

    m_ui->gridLayout->setSpacing(0);
    connect(sp->yAxis, SIGNAL(rangeChanged(QCPRange)), sp->yAxis2, SLOT(setRange(QCPRange)));

    m_context_menu.addAction(m_ui->actionReset);
    m_context_menu.addSeparator();
    m_context_menu.addAction(m_ui->actionMoveRight10);
    m_context_menu.addAction(m_ui->actionMoveLeft10);
    m_context_menu.addAction(m_ui->actionMoveUp10);
    m_context_menu.addAction(m_ui->actionMoveDown10);
    m_context_menu.addAction(m_ui->actionMoveRight1);
    m_context_menu.addAction(m_ui->actionMoveLeft1);
    m_context_menu.addAction(m_ui->actionMoveUp1);
    m_context_menu.addAction(m_ui->actionMoveDown1);
    m_context_menu.addSeparator();
    m_context_menu.addAction(m_ui->actionGoToPacket);

    memset(&m_sequence_analysis, 0, sizeof(m_sequence_analysis));

    m_ui->showComboBox->blockSignals(true);
    m_ui->showComboBox->setCurrentIndex(0);
    m_ui->showComboBox->blockSignals(false);
    m_sequence_analysis.all_packets = TRUE;
    m_sequence_analysis.any_addr = TRUE;

    QPushButton * save_bt = m_ui->buttonBox->button(QDialogButtonBox::Save);
    save_bt->setText(tr("Save As" UTF8_HORIZONTAL_ELLIPSIS));

    connect(m_ui->horizontalScrollBar, SIGNAL(valueChanged(int)), this, SLOT(hScrollBarChanged(int)));
    connect(m_ui->verticalScrollBar, SIGNAL(valueChanged(int)), this, SLOT(vScrollBarChanged(int)));
    connect(sp->xAxis2, SIGNAL(rangeChanged(QCPRange)), this, SLOT(xAxisChanged(QCPRange)));
    connect(sp->yAxis, SIGNAL(rangeChanged(QCPRange)), this, SLOT(yAxisChanged(QCPRange)));
    connect(sp, SIGNAL(mousePress(QMouseEvent*)), this, SLOT(diagramClicked(QMouseEvent*)));
    connect(sp, SIGNAL(mouseMove(QMouseEvent*)), this, SLOT(mouseMoved(QMouseEvent*)));
    connect(sp, SIGNAL(mouseRelease(QMouseEvent*)), this, SLOT(mouseReleased(QMouseEvent*)));
    connect(this, SIGNAL(goToPacket(int)), m_sequence_diagram, SLOT(setSelectedPacket(int)));

    disconnect(m_ui->buttonBox, SIGNAL(accepted()), this, SLOT(accept()));

    fillDiagram();
}

LBMUIMFlowDialog::~LBMUIMFlowDialog(void)
{
    delete m_ui;
}

void LBMUIMFlowDialog::setCaptureFile(capture_file * cfile)
{
    if (cfile == NULL) // We only want to know when the file closes.
    {
        m_capture_file = NULL;
    }
}

void LBMUIMFlowDialog::showEvent(QShowEvent *)
{
    resetAxes();
}

void LBMUIMFlowDialog::resizeEvent(QResizeEvent *)
{
    resetAxes(true);
}

void LBMUIMFlowDialog::keyPressEvent(QKeyEvent * event)
{
    int pan_pixels = (event->modifiers() & Qt::ShiftModifier) ? 1 : 10;

    // XXX - Copy some shortcuts from tcp_stream_dialog.cpp
    switch (event->key())
    {
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
            panAxes(0, -1 * pan_pixels);
            break;
        case Qt::Key_Down:
        case Qt::Key_J:
            panAxes(0, pan_pixels);
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
    }

    QDialog::keyPressEvent(event);
}

void LBMUIMFlowDialog::mouseReleaseEvent(QMouseEvent * event)
{
    mouseReleased(event);
}

void LBMUIMFlowDialog::hScrollBarChanged(int value)
{
    if (qAbs(m_ui->sequencePlot->xAxis2->range().center() - value / 100.0) > 0.01)
    {
        m_ui->sequencePlot->xAxis2->setRange(value / 100.0, m_ui->sequencePlot->xAxis2->range().size(), Qt::AlignCenter);
        m_ui->sequencePlot->replot();
    }
}

void LBMUIMFlowDialog::vScrollBarChanged(int value)
{
    if (qAbs(m_ui->sequencePlot->yAxis->range().center() - value / 100.0) > 0.01)
    {
        m_ui->sequencePlot->yAxis->setRange(value / 100.0, m_ui->sequencePlot->yAxis->range().size(), Qt::AlignCenter);
        m_ui->sequencePlot->replot();
    }
}

void LBMUIMFlowDialog::xAxisChanged(QCPRange range)
{
    m_ui->horizontalScrollBar->setValue(qRound(qreal(range.center() * 100.0)));
    m_ui->horizontalScrollBar->setPageStep(qRound(qreal(range.size() * 100.0)));
}

void LBMUIMFlowDialog::yAxisChanged(QCPRange range)
{
    m_ui->verticalScrollBar->setValue(qRound(qreal(range.center() * 100.0)));
    m_ui->verticalScrollBar->setPageStep(qRound(qreal(range.size() * 100.0)));
}

void LBMUIMFlowDialog::diagramClicked(QMouseEvent * event)
{
    QCustomPlot * sp = m_ui->sequencePlot;

    if (event->button() == Qt::RightButton)
    {
        // XXX We should find some way to get sequenceDiagram to handle a
        // contextMenuEvent instead.
        m_context_menu.exec(event->globalPos());
    }
    else if (sp->axisRect()->rect().contains(event->pos()))
    {
        sp->setCursor(QCursor(Qt::ClosedHandCursor));
    }
    on_actionGoToPacket_triggered();
}

void LBMUIMFlowDialog::mouseMoved(QMouseEvent * event)
{
    QCustomPlot * sp = m_ui->sequencePlot;
    Qt::CursorShape shape = Qt::ArrowCursor;
    if (event)
    {
        if (event->buttons().testFlag(Qt::LeftButton))
        {
            shape = Qt::ClosedHandCursor;
        }
        else
        {
            if (sp->axisRect()->rect().contains(event->pos()))
            {
                shape = Qt::OpenHandCursor;
            }
        }
    }
    sp->setCursor(QCursor(shape));

    m_packet_num = 0;
    QString hint;
    if (event)
    {
        seq_analysis_item_t * sai = m_sequence_diagram->itemForPosY(event->pos().y());
        if (sai)
        {
            m_packet_num = sai->frame_number;
            hint = QString("Packet %1: %2").arg(m_packet_num).arg(sai->comment);
        }
    }

    if (hint.isEmpty())
    {
        hint += tr("%Ln node(s)", "", m_sequence_analysis.num_nodes) + QString(", ")
            + tr("%Ln item(s)", "", m_num_items);
    }

    hint.prepend("<small><i>");
    hint.append("</i></small>");
    m_ui->hintLabel->setText(hint);
}

void LBMUIMFlowDialog::mouseReleased(QMouseEvent *)
{
    if (m_ui->sequencePlot->cursor().shape() == Qt::ClosedHandCursor)
    {
        m_ui->sequencePlot->setCursor(QCursor(Qt::OpenHandCursor));
    }
}

void LBMUIMFlowDialog::on_buttonBox_accepted(void)
{
    QString file_name, extension;
    QDir path(wsApp->lastOpenDir());
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
    if (m_capture_file)
    {
        filter.append(QString(";;%5").arg(ascii_filter));
    }

    file_name = QFileDialog::getSaveFileName(this, wsApp->windowTitleString(tr("Save Graph As" UTF8_HORIZONTAL_ELLIPSIS)),
        path.canonicalPath(), filter, &extension);

    if (file_name.length() > 0)
    {
        bool save_ok = false;
        if (extension.compare(pdf_filter) == 0)
        {
            save_ok = m_ui->sequencePlot->savePdf(file_name);
        }
        else if (extension.compare(png_filter) == 0)
        {
            save_ok = m_ui->sequencePlot->savePng(file_name);
        }
        else if (extension.compare(bmp_filter) == 0)
        {
            save_ok = m_ui->sequencePlot->saveBmp(file_name);
        }
        else if (extension.compare(jpeg_filter) == 0)
        {
            save_ok = m_ui->sequencePlot->saveJpg(file_name);
        }
        else if (extension.compare(ascii_filter) == 0 && m_capture_file)
        {
            save_ok = sequence_analysis_dump_to_file(file_name.toUtf8().constData(), &m_sequence_analysis, m_capture_file, 0);
        }
        // else error dialog?
        if (save_ok)
        {
            path = QDir(file_name);
            wsApp->setLastOpenDir(path.canonicalPath().toUtf8().constData());
        }
    }
}

void LBMUIMFlowDialog::fillDiagram(void)
{
    QCustomPlot * sp = m_ui->sequencePlot;
    seq_analysis_info_t new_sa;

    new_sa = m_sequence_analysis;
    new_sa.items = g_queue_new();
    new_sa.ht = NULL;
    new_sa.num_nodes = 0;
    lbm_uimflow_get_analysis(m_capture_file, &new_sa);
    m_num_items = sequence_analysis_get_nodes(&new_sa);
    m_sequence_diagram->setData(&new_sa);
    sequence_analysis_list_free(&m_sequence_analysis);
    m_sequence_analysis = new_sa;

    QFontMetrics vfm = QFontMetrics(sp->xAxis2->labelFont());
    m_node_label_width = 0;
    for (guint i = 0; i < m_sequence_analysis.num_nodes; i++)
    {
        QString addr_str = address_to_display_qstring(&(m_sequence_analysis.nodes[i]));
        int label_w = vfm.width(addr_str);
        if (m_node_label_width < label_w)
        {
            m_node_label_width = label_w;
        }
    }
    m_node_label_width = (m_node_label_width * 3 / 4) + m_one_em;

    mouseMoved(NULL);
    resetAxes();

    // XXX QCustomPlot doesn't seem to draw any sort of focus indicator.
    sp->setFocus();
}

void LBMUIMFlowDialog::panAxes(int x_pixels, int y_pixels)
{
    QCustomPlot * sp = m_ui->sequencePlot;
    double h_pan = 0.0;
    double v_pan = 0.0;

    h_pan = sp->xAxis2->range().size() * x_pixels / sp->xAxis2->axisRect()->width();
    v_pan = sp->yAxis->range().size() * y_pixels / sp->yAxis->axisRect()->height();
    // The GTK+ version won't pan unless we're zoomed. Should we do the same here?
    if (h_pan)
    {
        sp->xAxis2->moveRange(h_pan);
        sp->replot();
    }
    if (v_pan)
    {
        sp->yAxis->moveRange(v_pan);
        sp->replot();
    }
}

void LBMUIMFlowDialog::resetAxes(bool keep_lower)
{
    QCustomPlot * sp = m_ui->sequencePlot;
    // Allow space for labels on the top and port numbers on the left.
    double top_pos = -1.0, left_pos = -0.5;
    if (keep_lower)
    {
        top_pos = sp->yAxis->range().lower;
        left_pos = sp->xAxis2->range().lower;
    }

    double range_ratio = sp->xAxis2->axisRect()->width() / m_node_label_width;
    sp->xAxis2->setRange(left_pos, range_ratio + left_pos);

    range_ratio = sp->yAxis->axisRect()->height() / (m_one_em * 1.5);
    sp->yAxis->setRange(top_pos, range_ratio + top_pos);

    double rmin = sp->xAxis2->range().size() / 2;
    m_ui->horizontalScrollBar->setRange((rmin - 0.5) * 100, (m_sequence_analysis.num_nodes - 0.5 - rmin) * 100);
    xAxisChanged(sp->xAxis2->range());

    rmin = (sp->yAxis->range().size() / 2);
    m_ui->verticalScrollBar->setRange((rmin - 1.0) * 100, (m_num_items - 0.5 - rmin) * 100);
    yAxisChanged(sp->yAxis->range());

    sp->replot();
}

void LBMUIMFlowDialog::on_resetButton_clicked(void)
{
    resetAxes();
}

void LBMUIMFlowDialog::on_actionGoToPacket_triggered(void)
{
    if (m_capture_file && m_packet_num > 0)
    {
        emit goToPacket(m_packet_num);
    }
}

void LBMUIMFlowDialog::on_showComboBox_currentIndexChanged(int index)
{
    if (index == 0)
    {
        m_sequence_analysis.all_packets = TRUE;
    }
    else
    {
        m_sequence_analysis.all_packets = FALSE;
    }
    fillDiagram();
}

void LBMUIMFlowDialog::on_actionReset_triggered(void)
{
    on_resetButton_clicked();
}

void LBMUIMFlowDialog::on_actionMoveRight10_triggered(void)
{
    panAxes(10, 0);
}

void LBMUIMFlowDialog::on_actionMoveLeft10_triggered(void)
{
    panAxes(-10, 0);
}

void LBMUIMFlowDialog::on_actionMoveUp10_triggered(void)
{
    panAxes(0, -10);
}

void LBMUIMFlowDialog::on_actionMoveDown10_triggered(void)
{
    panAxes(0, 10);
}

void LBMUIMFlowDialog::on_actionMoveRight1_triggered(void)
{
    panAxes(1, 0);
}

void LBMUIMFlowDialog::on_actionMoveLeft1_triggered(void)
{
    panAxes(-1, 0);
}

void LBMUIMFlowDialog::on_actionMoveUp1_triggered(void)
{
    panAxes(0, -1);
}

void LBMUIMFlowDialog::on_actionMoveDown1_triggered(void)
{
    panAxes(0, 1);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
