/* rtp_audio_graph.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "rtp_audio_graph.h"

#include <epan/prefs.h>
#include <ui/qt/utils/color_utils.h>

static const double wf_graph_normal_width_ = 0.5;

RtpAudioGraph::RtpAudioGraph(QCustomPlot *audio_plot, QRgb color) : QObject(audio_plot)
{
    QPen p;
    QPalette sel_pal;

    color_ = color;
    wave_ = audio_plot->addGraph();
    p = QPen(wave_->pen());
    p.setColor(color_);
    p.setWidthF(wf_graph_normal_width_);
    wave_->setPen(p);
    wave_->setSelectable(QCP::stNone);
    wave_->removeFromLegend();
    selection_color_ = sel_pal.color(QPalette::Highlight);
}

// Indicate that audio will not be hearable
void RtpAudioGraph::setMuted(bool isMuted)
{
    QPen p = wave_->pen();
    if (isMuted) {
        p.setStyle(Qt::DotLine);
    } else {
        p.setStyle(Qt::SolidLine);
    }
    wave_->setPen(p);
}

void RtpAudioGraph::setHighlight(bool isHighlighted)
{
    wave_->setSelection(isHighlighted ? QCPDataSelection(QCPDataRange()) : QCPDataSelection());
    QPen p = wave_->pen();
    if (isHighlighted) {
        p.setWidthF(wf_graph_normal_width_*2);
    } else {
        p.setWidthF(wf_graph_normal_width_);
    }
    wave_->setPen(p);
}

void RtpAudioGraph::setSelected(bool isSelected)
{
    wave_->setSelection(isSelected ? QCPDataSelection(QCPDataRange()) : QCPDataSelection());
    QPen p = wave_->pen();
    if (isSelected) {
        p.setColor(selection_color_);
    } else {
        p.setColor(color_);
    }
    wave_->setPen(p);
}

void RtpAudioGraph::setData(const QVector<double> &keys, const QVector<double> &values, bool alreadySorted)
{
    wave_->setData(keys, values, alreadySorted);
}

void RtpAudioGraph::remove(QCustomPlot *audioPlot)
{
    audioPlot->removeGraph(wave_);
}

bool RtpAudioGraph::isMyPlottable(QCPAbstractPlottable *plottable)
{
    if (plottable == wave_) {
        return true;
    } else {
        return false;
    }
}
