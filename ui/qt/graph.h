/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef GRAPH_H
#define GRAPH_H

#include <config.h>

#include "wireshark_dialog.h"

class QCPBars;
class QCPGraph;
class QCustomPlot;

class Graph : public QObject {
    Q_OBJECT
public:
    static const int default_y_axis_factor_ = 1;
    const qreal graph_line_width_ = 1.0;
    enum PlotStyles { psLine, psDotLine, psStepLine, psDotStepLine, psImpulse, psBar, psStackedBar, psDot, psSquare, psDiamond, psCross, psPlus, psCircle };

    explicit Graph(QCustomPlot* parent);
    ~Graph();
    QString name() const { return name_; }
    void setName(const QString& name);
    QRgb color() const;
    void setColor(const QRgb color);
    bool visible() const { return visible_; }
    void setVisible(bool visible);
    unsigned int yAxisFactor() const { return y_axis_factor_; }
    void setYAxisFactor(unsigned int y_axis_factor);
    QCPGraph* graph() const { return graph_; }
    QCPBars* bars() const { return bars_; }
    bool addToLegend();
    bool setPlotStyle(PlotStyles style);

protected:
    QCustomPlot* parent_;
    QCPGraph* graph_;
    QCPBars* bars_;
    QString name_;
    QBrush color_;
    bool visible_;
    unsigned int y_axis_factor_;

    void applyCurrentColor();
    bool removeFromLegend();
    void clearAllData();
};

#endif // GRAPH_H
