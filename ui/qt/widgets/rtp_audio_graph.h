/* rtp_audio_graph.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RTP_AUDIO_GRAPH_H
#define RTP_AUDIO_GRAPH_H

#include "config.h"

#include <ui/qt/widgets/qcustomplot.h>

//class QCPItemStraightLine;
//class QCPAxisTicker;
//class QCPAxisTickerDateTime;

class RtpAudioGraph : public QObject
{
  Q_OBJECT
public:
  explicit RtpAudioGraph(QCustomPlot *audioPlot, QRgb color);
  void setMuted(bool isMuted);
  void setHighlight(bool isHighlighted);
  void setSelected(bool isSelected);
  void setData(const QVector<double> &keys, const QVector<double> &values, bool alreadySorted=false);
  void remove(QCustomPlot *audioPlot);
  bool isMyPlottable(QCPAbstractPlottable *plottable);


private:
  QCPGraph *wave_;
  QRgb color_;
  QColor selection_color_;
};

#endif // RTP_AUDIO_GRAPH_H
