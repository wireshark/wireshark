/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Plots feature by Giovanni Musto <giovanni.musto@partner.italdesign.it>
 * Copyright (c) 2025
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PLOT_DIALOG_H
#define PLOT_DIALOG_H

#include <config.h>
#include "plot.h"

#include <ui/qt/models/uat_model.h>
#include <ui/qt/models/uat_delegate.h>
#include <ui/qt/widgets/customplot.h>
#include "wireshark_dialog.h"

#include <QPointer>
#include <QMenu>
#include <QTextStream>
#include <QItemSelection>

#include <vector>

class CopyFromProfileButton;
class QAbstractButton;
class QCPAxisRect;
class QCPGraph;
class QCPItemTracer;
class QCPMarginGroup;
class QPushButton;
class QRubberBand;
class QTimer;
class QCustomPlot;
/* define Plot specific UAT columns */
enum UatColumnsPlot { plotColEnabled = 0, plotColIdx, plotColName, plotColDFilter, plotColColor, plotColStyle, plotColYField, plotColYAxisFactor, plotColMaxNum };

namespace Ui {
    class PlotDialog;
}

// Saved plot settings
typedef struct _plot_settings_t {
    bool enabled;
    unsigned group;
    char* name;
    char* dfilter;
    unsigned color;
    uint32_t style;
    char* yfield;
    double y_axis_factor;
} plot_settings_t;

static const value_string plot_graph_style_vs[] = {
    { Graph::psLine, "Line" },
    { Graph::psDotLine, "Dot Line" },
    { Graph::psStepLine, "Step Line" },
    { Graph::psDotStepLine, "Dot Step Line" },
    { Graph::psImpulse, "Impulse" },
    //{ Graph::psBar, "Bar" },
    //{ Graph::psStackedBar, "Stacked Bar" },
    { Graph::psDot, "Dot" },
    { Graph::psSquare, "Square" },
    { Graph::psDiamond, "Diamond" },
    { Graph::psCross, "Cross" },
    { Graph::psCircle, "Circle" },
    { Graph::psPlus, "Plus" },
    { 0, NULL }
};

/**
 * @brief Dialog for configuring and displaying packet field value plots.
 */
class PlotDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /**
     * @brief Construct a PlotDialog.
     * @param parent The parent widget (passed to WiresharkDialog).
     * @param cf     The capture file to plot.
     */
    explicit PlotDialog(QWidget &parent, CaptureFile &cf);

    /** @brief Destroy the dialog and its associated resources. */
    virtual ~PlotDialog();

    /**
     * @brief Finish initialising the dialog after construction.
     *
     * @param parent      The parent widget.
     * @param plot_fields UAT field descriptors for the plot table.
     * @param show_default If true, call addDefaultPlot() to pre-populate
     *                     the dialog with sensible defaults.
     */
    void initialize(QWidget &parent, uat_field_t *plot_fields, bool show_default = true);

    /**
     * @brief Add a plot with default name, style, colour, and Y-axis factor.
     *
     * @param checked Whether the plot starts enabled.
     * @param dfilter Display filter expression (empty = no filter).
     * @param yfield  Header field abbreviation for the Y-axis values.
     */
    void addPlot(bool checked, const QString &dfilter, const QString &yfield);

public slots:
    /** @brief Request a lightweight QCustomPlot replot of existing data. */
    void scheduleReplot() { need_replot_ = true; }
    /** @brief Request a medium-weight value recalculation then replot. */
    void scheduleRecalc() { need_recalc_ = true; }
    /** @brief Request a full retap of the capture file. */
    void scheduleRetap() { need_retap_ = true; }


protected:
    /**
     * @brief Handle capture file closing.
     */
    void captureFileClosing() override;

    /**
     * @brief Handle key press events.
     * @param event The key event.
     */
    void keyPressEvent(QKeyEvent *event) override;

    /**
     * @brief Handle dialog rejection (Close button / Escape).
     */
    void reject() override;

    /**
     * @brief Return the display-filter-qualified window/tab title suffix.
     * @return A string appended to the dialog title.
     */
    virtual QString getFilteredName() const;

    /**
     * @brief Return the default Y-axis label for this dialog type.
     * @return A human-readable Y-axis name (e.g. "Value").
     */
    virtual QString getYAxisName() const;

    /**
     * @brief Return the status-bar hint text for normal operation.
     * @param num_items The number of data points currently plotted.
     * @return A localised summary string for the hint label.
     */
    virtual QString getHintText(unsigned num_items) const;

    /**
     * @brief Add one of the two (or four) default plots.
     * @param enabled  Whether the default plot starts enabled.
     * @param filtered Whether to add the filtered or unfiltered variant.
     */
    virtual void addDefaultPlot(bool enabled, bool filtered);

    /**
     * @brief Add a fully-specified plot to the dialog.
     *
     * @param checked       Whether the plot starts enabled.
     * @param name          Display name shown in the legend.
     * @param dfilter       Display filter expression (empty = no filter).
     * @param color_idx     RGB pen colour.
     * @param style         Plot style (line, dot, bar, stacked bar, etc.).
     * @param yfield        Header field abbreviation for the Y-axis values.
     * @param y_axis_factor Multiplier applied to all Y values before plotting
     *                      (default: Graph::default_y_axis_factor_).
     */
    void addPlot(bool checked, const QString &name, const QString &dfilter, QRgb color_idx,
                 Graph::PlotStyles style, const QString &yfield,
                 double y_axis_factor = Graph::default_y_axis_factor_);

protected slots:
    /**
     * @brief Respond to data changes in the UAT model.
     *
     * @param topLeft     Top-left index of the changed model region.
     * @param bottomRight Bottom-right index of the changed model region.
     * @param roles       The data roles that changed.
     */
    void modelDataChanged(const QModelIndex &topLeft, const QModelIndex &bottomRight,
                          const QVector<int> &roles);

    /**
     * @brief Respond to a full UAT model reset.
     */
    void modelRowsReset();

    /**
     * @brief Respond to new rows being inserted into the UAT model.
     * @param parent The parent model index (always invalid for a flat list).
     * @param first  First inserted row index.
     * @param last   Last inserted row index.
     */
    void modelRowsInserted(const QModelIndex &parent, int first, int last);

    /**
     * @brief Respond to rows being removed from the UAT model.
     * @param parent The parent model index.
     * @param first  First removed row index.
     * @param last   Last removed row index.
     */
    void modelRowsRemoved(const QModelIndex &parent, int first, int last);

    /**
     * @brief Respond to rows being reordered within the UAT model.
     * @param sourceParent      Source parent index.
     * @param sourceStart       First moved source row.
     * @param sourceEnd         Last moved source row.
     * @param destinationParent Destination parent index.
     * @param destinationRow    Destination insertion row.
     */
    void modelRowsMoved(const QModelIndex &sourceParent, int sourceStart, int sourceEnd,
                        const QModelIndex &destinationParent, int destinationRow);

signals:
    /**
     * @brief Emitted when the packet list should navigate to a specific packet.
     * @param packet The 1-based frame number to navigate to.
     * @param hf_id  The header field ID whose value was clicked, for column
     *               highlighting.
     */
    void goToPacket(int packet, int hf_id);

    /**
     * @brief Emitted to update the size and position of a measurement marker.
     * @param size    Marker size in pixels.
     * @param xCoord  X-axis coordinate of the marker in plot units.
     */
    void updateMarker(const int size, const double xCoord, const int);

    /**
     * @brief Emitted to set the position of a position or difference marker.
     * @param xCoord     X-axis coordinate of the marker.
     * @param selectMPos Index of the selected measurement marker.
     * @param posMPos    Index of the position marker.
     */
    void setPosMarker(const double xCoord, const int selectMPos, const int posMPos);

private:
    /**
     * @brief Load plot rows from a UAT field descriptor array.
     * @param plot_fields UAT field descriptors to load from.
     */
    void loadProfileGraphs(uat_field_t *plot_fields);

    /**
     * @brief Construct and register a Plot object for a UAT model row.
     * @param currentRow The zero-based UAT row to create a Plot for.
     */
    void createPlot(int currentRow);

    /**
     * @brief Synchronise the Plot object for @p row with its UAT model data.
     * @param row The zero-based UAT row to sync.
     */
    void syncPlotSettings(int row);

    /**
     * @brief Return the index of the last Plot in @c plots_.
     * @return The zero-based index of the last plot, or -1 if empty.
     */
    int getLastPlotIdx();

    /**
     * @brief Return whether the plot at @p row is enabled in the UAT.
     * @param row Zero-based UAT row index.
     * @return true if the plot is checked/enabled.
     */
    bool graphIsEnabled(int row) const;

    /**
     * @brief Return the first enabled Plot, or nullptr if none.
     * @return The currently active Plot object.
     */
    Plot *currentActiveGraph() const;

    /** @brief Collect axis range and interval metadata from all plots. */
    void getGraphInfo();

    /** @brief Refresh the hint label below the plot. */
    void updateHint();

    /** @brief Reposition the legend according to @c legend_alignment_. */
    void updateLegendPos();

    /** @brief Reset all axes to auto-fit all visible data. */
    void resetAxes();

    /**
     * @brief Perform a zoom step on one or both axes.
     * @param in true to zoom in; false to zoom out.
     * @param y  true to zoom the Y axis; false to zoom the X axis.
     */
    void doZoom(bool in, bool y);

    /** @brief Zoom both axes in or out. @param in true to zoom in. */
    void zoomAxes(bool in);
    /** @brief Zoom the X axis only. @param in true to zoom in. */
    void zoomXAxis(bool in);
    /** @brief Zoom the Y axis only. @param in true to zoom in. */
    void zoomYAxis(bool in);

    /**
     * @brief Pan the visible axes by a pixel offset.
     * @param x_pixels Horizontal pan amount (positive = right).
     * @param y_pixels Vertical pan amount (positive = up).
     */
    void panAxes(int x_pixels, int y_pixels);

    /** @brief Update the X-axis label to reflect the current time display mode. */
    void updateXAxisLabel();

    /**
     * @brief Compute the axis-coordinate rectangle covered by a rubber-band rect.
     * @param zoom_rect       The rubber-band rectangle in widget coordinates.
     * @param matchedAxisRect If non-null, receives the QCPAxisRect under the cursor.
     * @return The corresponding axis-coordinate rectangle.
     */
    QRectF getZoomRanges(QRect zoom_rect, QCPAxisRect **matchedAxisRect = nullptr);

    /**
     * @brief Write all plot data as CSV rows to @p stream.
     * @param stream The text stream to write to.
     * @return true on success.
     */
    bool makeCsv(QTextStream &stream) const;

    /**
     * @brief Return the QCPAxisRect at position @p idx in the layout.
     * @param idx Zero-based index of the axis rect.
     * @return The matching QCPAxisRect, or nullptr if out of range.
     */
    QCPAxisRect *getAxisRect(int idx);

    /**
     * @brief Remove Plot objects and axis rects that no longer have a
     * corresponding UAT row.
     */
    void removeExcessPlots();

    /** @brief Update the tracer dot colour to match the plot under the cursor. */
    void setTracerColor();

    /**
     * @brief Return the QCPAxisRect under a given widget position.
     * @param pos The position in plot-widget coordinates.
     * @return The axis rect at @p pos, or nullptr if none.
     */
    QCPAxisRect *axisRectFromPos(const QPoint &pos);

    /**
     * @brief Append a difference annotation between the two active markers.
     */
    void addMarkerDifference();

    /**
     * @brief Return the index of a visible marker.
     * @param first true to return the first visible marker; false for the last.
     * @return The index of the matching marker, or -1 if none is visible.
     */
    int visibleMarker(const bool first = true) const;

    /**
     * @brief Allocate and register a new Marker object.
     * @param isPosMarker true to create a position marker; false for a
     *                    measurement/delta marker.
     * @return The newly created Marker.
     */
    Marker *addMarker(const bool isPosMarker);

    /**
     * @brief Render a single marker onto the plot.
     * @param marker The marker to draw.
     */
    void drawMarker(const Marker *marker);

    /** @brief Redraw all registered markers. */
    void drawMarkers();

    /** @brief Add data-point snap markers at every sample in the active plot. */
    void addDataPointsMarkers();

    /** @brief Recalculate and apply the height of the primary axis rect. */
    void updateFirstAxisRectHeight();

    /**
     * @brief Rebuild the per-plot Y-axis rects when multi-Y-axes mode changes.
     */
    void recreateMultiValueAxes();

    /**
     * @brief Return all QCPAxisRect objects currently in the plot layout.
     * @return An ordered list of axis rects, top to bottom.
     */
    QList<QCPAxisRect *> axisRects() const;

    /** @brief Auto-scroll the X axis to keep the most recent data in view. */
    void autoScroll() const;

    Ui::PlotDialog *ui;                     /**< UI elements generated from the .ui file. */
    QPushButton *copy_bt_;                  /**< "Copy" button in the button box. */
    CopyFromProfileButton *copy_profile_bt_; /**< Button for copying settings from another profile. */

    // Model and delegate chosen over UatFrame to allow custom button layout.
    QPointer<UatModel> uat_model_;  /**< UAT-backed table model for plot rows. */
    UatDelegate *uat_delegate_;     /**< Item delegate providing in-place editors for UAT fields. */

    /** Plot objects in UAT row order; must stay synchronised with uat_model_. */
    QVector<Plot *> plots_;

    QString hint_err_;                   /**< Error string shown in the hint label. */
    QCPGraph *base_graph_;               /**< Reference QCPGraph used for time-axis alignment. */
    QCPItemTracer *tracer_;              /**< Crosshair tracer shown on mouse hover. */
    uint32_t packet_num_;                /**< Frame number nearest the last click. */
    double start_time_;                  /**< Common time origin for relative-time display. */
    QRubberBand *rubber_band_;           /**< Rubber-band rectangle for zoom selection. */
    QPoint rb_origin_;                   /**< Origin of the rubber-band drag in widget coordinates. */
    QMenu ctx_menu_;                     /**< Context menu shown on right-click in the plot. */
    QTimer *stat_timer_;                 /**< Timer driving periodic replot/recalc/retap. */
    QCPMarginGroup *margin_group_;       /**< Margin group that aligns axis rects horizontally. */
    Qt::Alignment legend_alignment_;     /**< Current corner alignment of the legend. */
    bool need_replot_;                   /**< Pending lightweight replot request. */
    bool need_recalc_;                   /**< Pending medium-weight recalculate request. */
    bool need_retap_;                    /**< Pending full retap request. */
    bool auto_axes_;                     /**< Whether to auto-rescale axes after each retap. */
    bool abs_time_;                      /**< true = absolute time X axis; false = elapsed time. */
    double last_right_clicked_pos_;      /**< X-axis position of the most recent right-click, in plot units. */

private slots:
    /**
     * @brief Commit pending UAT edits to the registration tables.
     */
    static void applyChanges();

    /**
     * @brief Perform the periodic stat update — retap, recalc, or replot
     * depending on which pending flags are set.
     */
    void updateStatistics();

    /** @brief Rebuild the QCustomPlot legend from the current plot set. */
    void updateLegend();

    /**
     * @brief Copy plot settings from an external profile file.
     * @param filename Path of the profile file to import.
     */
    void copyFromProfile(const QString &filename);

    /** @brief Copy all plot data to the clipboard as CSV text. */
    void copyAsCsvClicked();

    /**
     * @brief Display the plot context menu.
     * @param pos The right-click position in plot-widget coordinates.
     */
    void showContextMenu(const QPoint &pos);

    /** @brief Rotate the legend to the next corner position. */
    void moveLegend();

    /**
     * @brief Handle a mouse button press on the plot.
     *
     * @param event The mouse event.
     */
    void graphClicked(QMouseEvent *event);

    /**
     * @brief Handle mouse movement over the plot.
     * @param event The mouse event.
     */
    void mouseMoved(QMouseEvent *event);

    /**
     * @brief Handle a mouse button release on the plot.
     * @param event The mouse event.
     */
    void mouseReleased(QMouseEvent *event);

    /**
     * @brief Respond to a selection change in the packet list.
     * @param frames List of selected 1-based frame numbers.
     */
    void selectedFrameChanged(const QList<int> &frames);

    /**
     * @brief Respond to a selection change in the plot UAT view.
     * @param selected   Newly selected items.
     * @param deselected Previously selected items now deselected.
     */
    void plotUatSelectionChanged(const QItemSelection &selected,
                                 const QItemSelection &deselected);

    /**
     * @brief Dispatch left button box clicks to the appropriate action.
     * @param button The button that was clicked.
     */
    void on_leftButtonBox_clicked(QAbstractButton *button);

    /**
     * @brief Show or hide the plot legend.
     * @param checked true to show the legend.
     */
    void on_actionLegend_triggered(bool checked);

    /**
     * @brief Toggle the Y axis between linear and logarithmic scale.
     * @param checked true for logarithmic scale.
     */
    void on_actionLogScale_triggered(bool checked);

    /**
     * @brief Toggle the crosshair/tracer visibility.
     * @param checked true to show the crosshair.
     */
    void on_actionCrosshairs_triggered(bool checked);

    /**
     * @brief Toggle the secondary top X axis.
     * @param checked true to show the top axis.
     */
    void on_actionTopAxis_triggered(bool checked);

    /**
     * @brief Toggle automatic plot updates when new packets arrive.
     * @param checked true to enable auto-update.
     */
    void on_automaticUpdateCheckBox_toggled(bool checked);

    /**
     * @brief Handle navigation to a different row in the plot UAT view.
     * @param current  The newly selected model index.
     * @param previous The previously selected model index.
     */
    void on_plotUat_currentItemChanged(const QModelIndex &current,
                                       const QModelIndex &previous);

    /** @brief Navigate the packet list to the packet nearest the tracer. */
    void on_actionGoToPacket_triggered();

    /** @brief Add a new default plot row to the UAT. */
    void on_newToolButton_clicked();
    /** @brief Delete the currently selected plot row from the UAT. */
    void on_deleteToolButton_clicked();
    /** @brief Duplicate the currently selected plot row. */
    void on_copyToolButton_clicked();
    /** @brief Remove all plot rows from the UAT. */
    void on_clearToolButton_clicked();
    /** @brief Move the selected plot row one position up in the UAT. */
    void on_moveUpwardsToolButton_clicked();
    /** @brief Move the selected plot row one position down in the UAT. */
    void on_moveDownwardsToolButton_clicked();

    /** @brief Open the dialog help page. */
    void on_rightButtonBox_helpRequested();

    /** @brief Reset both axes (action triggered from menu or shortcut). */
    void on_actionReset_triggered() { resetAxes(); }
    /** @brief Zoom both axes in. */
    void on_actionZoomIn_triggered() { zoomAxes(true); }
    /** @brief Zoom the X axis in. */
    void on_actionZoomInX_triggered() { zoomXAxis(true); }
    /** @brief Zoom the Y axis in. */
    void on_actionZoomInY_triggered() { zoomYAxis(true); }
    /** @brief Zoom both axes out. */
    void on_actionZoomOut_triggered() { zoomAxes(false); }
    /** @brief Zoom the X axis out. */
    void on_actionZoomOutX_triggered() { zoomXAxis(false); }
    /** @brief Zoom the Y axis out. */
    void on_actionZoomOutY_triggered() { zoomYAxis(false); }
    /** @brief Pan the view up by 10 pixels. */
    void on_actionMoveUp10_triggered()    { panAxes(0, 10); }
    /** @brief Pan the view left by 10 pixels. */
    void on_actionMoveLeft10_triggered()  { panAxes(-10, 0); }
    /** @brief Pan the view right by 10 pixels. */
    void on_actionMoveRight10_triggered() { panAxes(10, 0); }
    /** @brief Pan the view down by 10 pixels. */
    void on_actionMoveDown10_triggered()  { panAxes(0, -10); }
    /** @brief Pan the view up by 1 pixel. */
    void on_actionMoveUp1_triggered()     { panAxes(0, 1); }
    /** @brief Pan the view left by 1 pixel. */
    void on_actionMoveLeft1_triggered()   { panAxes(-1, 0); }
    /** @brief Pan the view right by 1 pixel. */
    void on_actionMoveRight1_triggered()  { panAxes(1, 0); }
    /** @brief Pan the view down by 1 pixel. */
    void on_actionMoveDown1_triggered()   { panAxes(0, -1); }
    /** @brief Pan the view up by 100 pixels. */
    void on_actionMoveUp100_triggered()    { panAxes(0, 100); }
    /** @brief Pan the view left by 100 pixels. */
    void on_actionMoveLeft100_triggered()  { panAxes(-100, 0); }
    /** @brief Pan the view right by 100 pixels. */
    void on_actionMoveRight100_triggered() { panAxes(100, 0); }
    /** @brief Pan the view down by 100 pixels. */
    void on_actionMoveDown100_triggered()  { panAxes(0, -100); }

    /**
     * @brief Toggle the X axis between elapsed seconds and absolute time-of-day.
     */
    void on_actionToggleTimeOrigin_triggered();

    /** @brief Apply UAT changes and close the dialog. */
    void on_rightButtonBox_accepted();

    /**
     * @brief Toggle auto-scroll mode.
     * @param checked true to keep the most recent data in view.
     */
    void on_actionAutoScroll_triggered(bool checked);

    /**
     * @brief Toggle independent Y axes for each plot series.
     * @param checked true to assign each plot its own Y axis rect.
     */
    void on_actionEnableMultiYAxes_triggered(bool checked);

    /** @brief Add a new measurement marker at the last right-clicked position. */
    void on_actionAddMarker_triggered();
    /** @brief Enter marker-move mode for the selected marker. */
    void on_actionMoveMarker_triggered();
    /** @brief Toggle visibility of the position marker. */
    void on_actionShowPosMarker_triggered();
    /** @brief Toggle display of the difference annotation between two markers. */
    void on_actionShowMarkersDifference_triggered();
    /** @brief Delete the currently selected marker. */
    void on_actionDeleteMarker_triggered();
    /** @brief Delete all markers from the plot. */
    void on_actionDeleteAllMarkers_triggered();
    /** @brief Toggle snap-to-data-point markers on the active series. */
    void on_actionShowDataPointMarker_triggered();
};

#endif // PLOT_DIALOG_H
