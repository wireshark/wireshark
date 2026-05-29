/** @file
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

/**
 * @brief Manages the visual rendering of an RTP audio stream as a waveform graph.
 */
class RtpAudioGraph : public QObject
{
  Q_OBJECT
public:
    /**
     * @brief Constructs an RtpAudioGraph.
     * @param audioPlot Pointer to the QCustomPlot widget where the graph will be drawn.
     * @param color The base color for the waveform graph.
     */
    explicit RtpAudioGraph(QCustomPlot *audioPlot, QColor color);

    /**
     * @brief Sets the muted state of the graph, adjusting its opacity.
     * @param isMuted True to indicate muted, false otherwise.
     */
    void setMuted(bool isMuted);

    /**
     * @brief Sets the highlight state of the graph, drawing it more prominently.
     * @param isHighlighted True to highlight, false to draw normally.
     */
    void setHighlight(bool isHighlighted);

    /**
     * @brief Sets the selection state of the graph, altering its color.
     * @param isSelected True if selected, false otherwise.
     */
    void setSelected(bool isSelected);

    /**
     * @brief Updates the data points plotted on the graph.
     * @param keys The X-axis values (e.g., timestamps).
     * @param values The Y-axis values (e.g., audio samples).
     * @param alreadySorted True if the data is already sorted by keys, improving performance.
     */
    void setData(const QVector<double> &keys, const QVector<double> &values, bool alreadySorted=false);

    /**
     * @brief Removes the graph from the plot widget.
     * @param audioPlot Pointer to the plot widget.
     */
    void remove(QCustomPlot *audioPlot);

    /**
     * @brief Checks if a given plottable object belongs to this graph.
     * @param plottable Pointer to the abstract plottable object to check.
     * @return True if the plottable is managed by this graph, false otherwise.
     */
    bool isMyPlottable(QCPAbstractPlottable *plottable);


private:
    /** @brief Pointer to the underlying QCPGraph object. */
    QCPGraph *wave_;

    /** @brief The base color of the waveform. */
    QColor color_;

    /** @brief The color used when the graph is selected. */
    QColor selection_color_;
};

#endif // RTP_AUDIO_GRAPH_H
