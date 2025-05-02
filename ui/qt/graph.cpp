/* graph.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define WS_LOG_DOMAIN LOG_DOMAIN_QTUI
#include "graph.h"

#include <ui/qt/widgets/qcustomplot.h>

Graph::Graph(QCustomPlot* parent) :
    parent_(parent),
    graph_(NULL),
    bars_(NULL),
    visible_(false),
    y_axis_factor_(default_y_axis_factor_)
{
    Q_ASSERT(parent_ != NULL);
    graph_ = parent_->addGraph(parent_->xAxis, parent_->yAxis);
    Q_ASSERT(graph_ != NULL);
}

Graph::~Graph() {
    if (graph_) {
        parent_->removeGraph(graph_);
    }
    if (bars_) {
        parent_->removePlottable(bars_);
    }
}

void Graph::setName(const QString& name)
{
    name_ = name;
    if (graph_) {
        graph_->setName(name_);
    }
    if (bars_) {
        bars_->setName(name_);
    }
}

QRgb Graph::color() const
{
    return color_.color().rgb();
}

void Graph::setColor(const QRgb color)
{
    color_ = QBrush(color);
    applyCurrentColor();
}

void Graph::applyCurrentColor()
{
    if (graph_) {
        graph_->setPen(QPen(color_, graph_line_width_));
    }
    else if (bars_) {
        bars_->setPen(QPen(color_.color().darker(110), graph_line_width_));
        // ...or omit it altogether?
        // bars_->setPen(QPen(color_);
        // XXX - We should do something like
        // bars_->setPen(QPen(ColorUtils::alphaBlend(color_, palette().windowText(), 0.65));
        // to get a darker outline in light mode and a lighter outline in dark
        // mode, but we don't yet respect dark mode in IOGraph (or anything
        // that uses QCustomPlot) - see link below for how to set QCP colors:
        // https://www.qcustomplot.com/index.php/demos/barchartdemo
        bars_->setBrush(color_);
    }
}

void Graph::setVisible(bool visible)
{
    visible_ = visible;
    if (graph_) {
        graph_->setVisible(visible_);
    }
    if (bars_) {
        bars_->setVisible(visible_);
    }
}

void Graph::setYAxisFactor(unsigned int y_axis_factor)
{
    y_axis_factor_ = y_axis_factor;
}

bool Graph::addToLegend()
{
    if (graph_) {
        return graph_->addToLegend();
    }
    if (bars_) {
        return bars_->addToLegend();
    }
    return false;
}

bool Graph::removeFromLegend()
{
    if (graph_) {
        return graph_->removeFromLegend();
    }
    if (bars_) {
        return bars_->removeFromLegend();
    }
    return false;
}

void Graph::clearAllData()
{
    if (graph_) {
        graph_->data()->clear();
    }
    if (bars_) {
        bars_->data()->clear();
    }
}

bool Graph::setPlotStyle(PlotStyles style)
{
    bool type_changed = false;

    // Switch plottable if needed
    switch (style) {
    case psBar:
    case psStackedBar:
        if (graph_) {
            bars_ = new QCPBars(parent_->xAxis, parent_->yAxis);
            parent_->removeGraph(graph_);
            graph_ = NULL;
            type_changed = true;
        }
        break;
    default:
        if (bars_) {
            graph_ = parent_->addGraph(parent_->xAxis, parent_->yAxis);
            parent_->removePlottable(bars_);
            bars_ = NULL;
            type_changed = true;
        }
        break;
    }

    if (graph_) {
        graph_->setLineStyle(QCPGraph::lsNone);
        graph_->setScatterStyle(QCPScatterStyle::ssNone);
    }
    switch (style) {
    case psLine:
        if (graph_) {
            graph_->setLineStyle(QCPGraph::lsLine);
        }
        break;
    case psDotLine:
        if (graph_) {
            graph_->setLineStyle(QCPGraph::lsLine);
            graph_->setScatterStyle(QCPScatterStyle::ssDisc);
        }
        break;
    case psStepLine:
        if (graph_) {
            graph_->setLineStyle(QCPGraph::lsStepLeft);
        }
        break;
    case psDotStepLine:
        if (graph_) {
            graph_->setLineStyle(QCPGraph::lsStepLeft);
            graph_->setScatterStyle(QCPScatterStyle::ssDisc);
        }
        break;
    case psImpulse:
        if (graph_) {
            graph_->setLineStyle(QCPGraph::lsImpulse);
        }
        break;
    case psDot:
        if (graph_) {
            graph_->setScatterStyle(QCPScatterStyle::ssDisc);
        }
        break;
    case psSquare:
        if (graph_) {
            graph_->setScatterStyle(QCPScatterStyle::ssSquare);
        }
        break;
    case psDiamond:
        if (graph_) {
            graph_->setScatterStyle(QCPScatterStyle::ssDiamond);
        }
        break;
    case psCross:
        if (graph_) {
            graph_->setScatterStyle(QCPScatterStyle::ssCross);
        }
        break;
    case psPlus:
        if (graph_) {
            graph_->setScatterStyle(QCPScatterStyle::ssPlus);
        }
        break;
    case psCircle:
        if (graph_) {
            graph_->setScatterStyle(QCPScatterStyle::ssCircle);
        }
        break;

    case psBar:
    case psStackedBar:
        // Stacking set in scanGraphs
        bars_->moveBelow(NULL);
        break;
    }

    setName(name_);
    applyCurrentColor();

    return type_changed;
}
