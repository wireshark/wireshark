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

class QCPAxis;
class QCPBars;
class QCPGraph;
class QCustomPlot;

/**
 * @brief Represents a single data graph within a QCustomPlot, managing its data, visual style, and axes mapping.
 */
class Graph : public QObject {
    Q_OBJECT
public:
    /** The default multiplication factor applied to the Y-axis. */
    static constexpr double default_y_axis_factor_ = 1;

    /** The default line width used when drawing the graph. */
    const qreal graph_line_width_ = 1.0;

    /**
     * @brief Defines the available visual styles for plotting data.
     */
    enum PlotStyles {
        psLine,         /**< Continuous line plot. */
        psDotLine,      /**< Dotted line plot. */
        psStepLine,     /**< Step line plot. */
        psDotStepLine,  /**< Dotted step line plot. */
        psImpulse,      /**< Impulse (stem) plot. */
        psBar,          /**< Bar chart. */
        psStackedBar,   /**< Stacked bar chart. */
        psDot,          /**< Data points as dots. */
        psSquare,       /**< Data points as squares. */
        psDiamond,      /**< Data points as diamonds. */
        psCross,        /**< Data points as crosses (x). */
        psPlus,         /**< Data points as plus signs (+). */
        psCircle        /**< Data points as circles. */
    };

    /**
     * @brief Constructs a new Graph.
     * @param parent The parent QCustomPlot widget.
     * @param keyAxis The axis to use for key (X) coordinates (defaults to nullptr).
     * @param valueAxis The axis to use for value (Y) coordinates (defaults to nullptr).
     */
    explicit Graph(QCustomPlot* parent, QCPAxis* keyAxis = nullptr, QCPAxis* valueAxis = nullptr);

    /**
     * @brief Destroys the Graph.
     */
    ~Graph();

    /**
     * @brief Retrieves the name of the graph.
     * @return The graph name.
     */
    QString name() const { return name_; }

    /**
     * @brief Sets the name of the graph.
     * @param name The new name string.
     */
    void setName(const QString& name);

    /**
     * @brief Retrieves the color of the graph.
     * @return The QRgb color value.
     */
    QRgb color() const;

    /**
     * @brief Sets the color of the graph.
     * @param color The new QRgb color value.
     */
    void setColor(const QRgb color);

    /**
     * @brief Checks if the graph is currently visible.
     * @return True if visible, false otherwise.
     */
    bool visible() const { return visible_; }

    /**
     * @brief Sets the visibility of the graph.
     * @param visible True to show the graph, false to hide it.
     */
    void setVisible(bool visible);

    /**
     * @brief Retrieves the scaling factor for the Y-axis.
     * @return The Y-axis factor.
     */
    double yAxisFactor() const { return y_axis_factor_; }

    /**
     * @brief Sets the scaling factor for the Y-axis.
     * @param y_axis_factor The new scaling factor.
     */
    void setYAxisFactor(double y_axis_factor);

    /**
     * @brief Retrieves the underlying QCPGraph object.
     * @return A pointer to the QCPGraph instance.
     */
    QCPGraph* graph() const { return graph_; }

    /**
     * @brief Retrieves the underlying QCPBars object.
     * @return A pointer to the QCPBars instance.
     */
    QCPBars* bars() const { return bars_; }

    /**
     * @brief Adds the graph to the parent plot's legend.
     * @return True if successfully added, false otherwise.
     */
    bool addToLegend();

    /**
     * @brief Sets the visual style of the plot.
     * @param style The PlotStyles enum value to apply.
     * @return True if the style was successfully applied, false otherwise.
     */
    bool setPlotStyle(PlotStyles style);

protected:
    /** Pointer to the parent QCustomPlot widget. */
    QCustomPlot* parent_;

    /** Pointer to the underlying QCPGraph instance. */
    QCPGraph* graph_;

    /** Pointer to the underlying QCPBars instance. */
    QCPBars* bars_;

    /** The name of the graph. */
    QString name_;

    /** The brush color of the graph. */
    QBrush color_;

    /** Flag indicating whether the graph is currently visible. */
    bool visible_;

    /** The scaling factor applied to the Y-axis. */
    double y_axis_factor_;

    /**
     * @brief Applies the currently set color to the underlying graphical elements.
     */
    void applyCurrentColor();

    /**
     * @brief Removes the graph from the parent plot's legend.
     * @return True if successfully removed, false otherwise.
     */
    bool removeFromLegend();

    /**
     * @brief Clears all data points currently loaded into the graph.
     */
    void clearAllData();
};

#endif // GRAPH_H
