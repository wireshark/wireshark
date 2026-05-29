/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef IO_GRAPH_DIALOG_H
#define IO_GRAPH_DIALOG_H

#include <config.h>
#include "io_graph.h"

#include <epan/epan_dissect.h>
#include <epan/prefs.h>
#include <epan/uat.h>

#include <wsutil/str_util.h>

#include <ui/preference_utils.h>
#include <ui/io_graph_item.h>
#include <ui/qt/models/uat_model.h>
#include <ui/qt/models/uat_delegate.h>

#include "wireshark_dialog.h"

#include <QPointer>
#include <QMenu>
#include <QTextStream>
#include <QItemSelection>

#include <vector>

class QRubberBand;
class QTimer;
class QAbstractButton;
class CopyFromProfileButton;

class QCPGraph;
class QCPItemTracer;
class QCPAxisTicker;
class QCPAxisTickerDateTime;

/**
 * @brief Persisted configuration for a single I/O Graph plot, corresponding to one UAT row.
 */
typedef struct _io_graph_settings_t {
    bool     enabled;       /**< True if this graph is active and should be rendered */
    bool     asAOT;         /**< True if this graph should be drawn always-on-top of others */
    char    *name;          /**< User-visible display name for this graph */
    char    *dfilter;       /**< Display filter string restricting which packets contribute to this graph */
    unsigned color;         /**< Plot colour encoded as a packed RGB value */
    uint32_t style;         /**< Plot style (e.g. line, impulse, bar, dot); maps to a ::io_graph_plot_style value */
    uint32_t yaxis;         /**< Y-axis unit or aggregate mode (see ::io_graph_item_unit_t) */
    char    *yfield;        /**< Display filter field whose value is used for Y-axis calculations */
    uint32_t sma_period;    /**< Simple Moving Average period in number of intervals; 0 disables SMA */
    double   y_axis_factor; /**< Multiplicative scaling factor applied to all Y-axis values before plotting */
} io_graph_settings_t;


extern const value_string moving_avg_vs[];

/**
 * @brief Column indices for the I/O Graph UAT (User Accessible Table) configuration table.
 */
enum UatColumnsIOG {
    colEnabled     = 0, /**< Whether the graph is enabled/visible */
    colName,            /**< Display name of the graph */
    colDFilter,         /**< Display filter string restricting which packets contribute to the graph */
    colColor,           /**< Plot line or bar colour */
    colStyle,           /**< Plot style (e.g. line, bar, dot) */
    colYAxis,           /**< Y-axis unit or aggregate calculation mode (see ::io_graph_item_unit_t) */
    colYField,          /**< Display filter field used for Y-axis value calculations */
    colSMAPeriod,       /**< Simple Moving Average period (number of intervals to average) */
    colYAxisFactor,     /**< Scaling factor applied to Y-axis values */
    colAOT,             /**< Always-on-top flag; keeps this graph drawn above others */
    colMaxNum           /**< Sentinel: total number of UAT columns */
};

namespace Ui {
class IOGraphDialog;
}

static const value_string io_graph_style_vs[] = {
    { IOGraph::psLine, "Line" },
    { IOGraph::psDotLine, "Dot Line" },
    { IOGraph::psStepLine, "Step Line" },
    { IOGraph::psDotStepLine, "Dot Step Line" },
    { IOGraph::psImpulse, "Impulse" },
    { IOGraph::psBar, "Bar" },
    { IOGraph::psStackedBar, "Stacked Bar" },
    { IOGraph::psDot, "Dot" },
    { IOGraph::psSquare, "Square" },
    { IOGraph::psDiamond, "Diamond" },
    { IOGraph::psCross, "Cross" },
    { IOGraph::psCircle, "Circle" },
    { IOGraph::psPlus, "Plus" },
    { 0, NULL }
};

/**
 * @brief Dialog for configuring and displaying I/O throughput graphs.
 *
 * Presents a QCustomPlot-based line/bar graph of per-interval packet,
 * byte, or calculated-field statistics drawn from a live or saved capture
 * file. Supports multiple overlaid graphs, UAT-backed configuration,
 * CSV export, zoom/pan/crosshair interaction, and a movable legend.
 *
 * Subclasses may override the virtual helpers to produce specialised graph
 * variants (e.g. flow graphs, conversation graphs) while reusing the core
 * plot and scheduling machinery.
 */
class IOGraphDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /**
     * @brief Construct an IOGraphDialog.
     * @param parent         The parent widget (passed to WiresharkDialog).
     * @param cf             The capture file to graph.
     * @param type_unit_name Short name describing the Y-axis unit type,
     *                       used in window titles and axis labels.
     */
    explicit IOGraphDialog(QWidget &parent, CaptureFile &cf, const char *type_unit_name);

    /** @brief Destroy the dialog. */
    virtual ~IOGraphDialog();

    /**
     * @brief Finish initialising the dialog after construction.
     *
     * Separated from the constructor to allow subclass polymorphism.
     * Loads profile graphs from @p io_graph_fields, applies @p displayFilter
     * to the first graph, and configures the Y-axis unit and field.
     *
     * @param parent            The parent widget.
     * @param io_graph_fields   UAT field descriptors for the graph table.
     * @param displayFilter     Initial display filter string (empty = none).
     * @param value_units       Y-axis unit (default: IOG_ITEM_UNIT_PACKETS).
     * @param yfield            Y-axis field expression (empty = none).
     * @param is_sibling_dialog true if this dialog was opened as a companion
     *                          to another statistics dialog rather than
     *                          standalone.
     * @param convFilters       Optional per-conversation display filters to
     *                          populate as additional graph rows.
     */
    void initialize(QWidget &parent, uat_field_t *io_graph_fields,
                    QString displayFilter     = QString(),
                    io_graph_item_unit_t value_units = IOG_ITEM_UNIT_PACKETS,
                    QString yfield            = QString(),
                    bool is_sibling_dialog    = false,
                    const QVector<QString> convFilters = QVector<QString>());


    /**
     * @brief Add a fully-specified graph to the dialog.
     * @param checked        Whether the graph is initially enabled.
     * @param asAOT          Whether to draw the graph as "all other traffic"
     *                       (i.e. traffic not matched by any other graph).
     * @param name           Display name shown in the legend.
     * @param dfilter        Display filter expression for the graph.
     * @param color_idx      RGB pen colour.
     * @param style          Plot style (line, bar, dot, etc.).
     * @param value_units    Y-axis unit.
     * @param yfield         Y-axis field expression.
     * @param moving_average Window size for the moving average, or 0 to disable.
     * @param yaxisfactor    Multiplier applied to all Y values before plotting.
     */
    void addGraph(bool checked, bool asAOT, QString name, QString dfilter,
                  QColor color_idx, IOGraph::PlotStyles style,
                  io_graph_item_unit_t value_units, QString yfield,
                  int moving_average, double yaxisfactor);

    /**
     * @brief Add a graph with a minimal set of parameters.
     *
     * Convenience overload — name, style, moving average, and Y-axis factor
     * are set to their defaults.
     *
     * @param checked      Whether the graph is initially enabled.
     * @param asAOT        Whether to draw as "all other traffic".
     * @param dfilter      Display filter expression for the graph.
     * @param value_units  Y-axis unit.
     * @param yfield       Y-axis field expression.
     */
    void addGraph(bool checked, bool asAOT, QString dfilter,
                  io_graph_item_unit_t value_units, QString yfield);

    /**
     * @brief Add a blank graph or copy the currently selected graph.
     * @param copy_from_current If true, duplicate the currently selected
     *                          graph row; if false, append a new default row.
     */
    void addGraph(bool copy_from_current = false);

    /**
     * @brief Add the default graph(s) for this dialog type.
     *
     * Called by initialize() to populate an empty graph table. Subclasses
     * may override this to provide a different default set.
     *
     * @param enabled Whether the default graph should start enabled.
     * @param idx     Index hint passed to the default graph factory.
     */
    virtual void addDefaultGraph(bool enabled, int idx = 0);

    /**
     * @brief Synchronise the QCustomPlot graph object for @p row with
     * its UAT model row data.
     *
     * Called after the UAT model changes a row to push the updated name,
     * filter, colour, style, and unit settings into the corresponding
     * IOGraph and QCPGraph objects.
     *
     * @param row The zero-based UAT model row to sync.
     */
    void syncGraphSettings(int row);

    /**
     * @brief Return the number of graphs currently in the dialog.
     * @return The size of the @c ioGraphs_ vector.
     */
    qsizetype graphCount() const;


public slots:
    /**
     * @brief Request a lightweight replot of already-computed graph data.
     *
     * Tells QCustomPlot to redraw existing data without recalculating values.
     * If the stat timer fires before @p now, the replot is deferred until
     * the next timer tick.
     *
     * @param now If true, replot immediately; otherwise defer to the next
     *            timer tick.
     */
    void scheduleReplot(bool now = false);

    /**
     * @brief Request a medium-weight value recalculation followed by replot.
     *
     * Recalculates per-interval Y values from already-tapped packet data,
     * then replots. Does not re-read the capture file.
     *
     * @param now If true, recalculate immediately; otherwise defer.
     */
    void scheduleRecalc(bool now = false);

    /**
     * @brief Request a heavy-weight retap of all packet data.
     *
     * Re-reads the capture file through all graph tap listeners, then
     * recalculates and replots. Most expensive of the three schedule calls.
     *
     * @param now If true, retap immediately; otherwise defer.
     */
    void scheduleRetap(bool now = false);

    /**
     * @brief Reload the list of available Y-axis field names.
     *
     * Repopulates any field selector combo boxes after a protocol
     * registration change or profile switch.
     */
    void reloadFields();


protected:
    /**
     * @brief Handle capture file closing.
     *
     * Stops the stat timer and disables graph controls that require an
     * open capture file.
     */
    void captureFileClosing();

    /**
     * @brief Handle key press events.
     *
     * Processes zoom, pan, reset, and other keyboard shortcuts while
     * the plot has focus.
     *
     * @param event The key event.
     */
    void keyPressEvent(QKeyEvent *event);

    /**
     * @brief Handle dialog rejection (Close button / Escape).
     *
     * Applies any pending UAT changes before closing.
     */
    void reject();

    /**
     * @brief Return the display-filter-qualified window/tab title suffix.
     *
     * Subclasses override this to report the appropriate filtered name
     * (e.g. "Filtered" vs. a specific filter expression).
     *
     * @return A string appended to the dialog title when a filter is active.
     */
    virtual QString getFilteredName() const;

    /**
     * @brief Return the X-axis label for this graph type.
     * @return The human-readable X-axis name (e.g. "Time (s)").
     */
    virtual QString getXAxisName() const;

    /**
     * @brief Return the Y-axis label for a given unit.
     * @param value_units The active Y-axis unit.
     * @return A C string label for the Y axis (e.g. "Packets/s").
     */
    virtual const char *getYAxisName(io_graph_item_unit_t value_units) const;

    /**
     * @brief Return the effective Y-axis field expression to use.
     *
     * Subclasses may normalise or replace @p yfield based on @p value_units.
     *
     * @param value_units The active Y-axis unit.
     * @param yfield      The raw field expression from the UAT row.
     * @return The field expression to pass to the tap engine.
     */
    virtual QString getYFieldName(io_graph_item_unit_t value_units, const QString &yfield) const;

    /**
     * @brief Parse a Y-axis value string from the UAT and return its int value.
     *
     * Used when the Y-axis unit is IOG_ITEM_UNIT_CALC_FRAMES or similar
     * fixed-value modes.
     *
     * @param data The string value from the UAT row.
     * @return The parsed integer Y value.
     */
    virtual int getYAxisValue(const QString &data);

    /**
     * @brief Return the hint text shown when no data is available.
     * @return A localised string such as "No data" or a subclass-specific
     *         message explaining how to populate the graph.
     */
    virtual QString getNoDataHint() const;

    /**
     * @brief Return the status-bar hint text shown during normal operation.
     * @param num_items The number of time intervals currently plotted.
     * @return A localised string summarising the current graph state.
     */
    virtual QString getHintText(unsigned num_items) const;


protected slots:
    /**
     * @brief Respond to data changes in the UAT model.
     *
     * Syncs QCustomPlot graph settings for any row whose data changed within
     * the rectangle defined by @p topLeft and @p bottomRight, then schedules
     * a retap or recalc as required.
     *
     * @param topLeft     Top-left index of the changed model region.
     * @param bottomRight Bottom-right index of the changed model region.
     * @param roles       The data roles that changed.
     */
    void modelDataChanged(const QModelIndex &topLeft, const QModelIndex &bottomRight,
                          const QVector<int> &roles);

    /**
     * @brief Respond to a full UAT model reset.
     *
     * Clears and rebuilds the @c ioGraphs_ vector to match the new model
     * state, then schedules a retap.
     */
    void modelRowsReset();

    /**
     * @brief Respond to new rows being inserted into the UAT model.
     *
     * Creates IOGraph and QCPGraph objects for each inserted row and
     * schedules a retap.
     *
     * @param parent The parent model index (always invalid for a flat list).
     * @param first  First inserted row index.
     * @param last   Last inserted row index.
     */
    void modelRowsInserted(const QModelIndex &parent, int first, int last);

    /**
     * @brief Respond to rows being removed from the UAT model.
     *
     * Destroys the IOGraph and QCPGraph objects for the removed rows and
     * schedules a replot.
     *
     * @param parent The parent model index.
     * @param first  First removed row index.
     * @param last   Last removed row index.
     */
    void modelRowsRemoved(const QModelIndex &parent, int first, int last);

    /**
     * @brief Respond to rows being moved within the UAT model.
     *
     * Reorders the @c ioGraphs_ vector to match the new row order and
     * schedules a replot.
     *
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
     * @brief Emitted when the plot should navigate to a specific packet.
     * @param packet_num The 1-based packet number to navigate to.
     */
    void goToPacket(int packet_num);

    /**
     * @brief Emitted to trigger a full recalculation of all graph data.
     * @param cap_file The capture file to recalculate from.
     */
    void recalcGraphData(capture_file *cap_file);

    /**
     * @brief Emitted when the time interval selection changes.
     * @param interval The new interval in milliseconds.
     */
    void intervalChanged(int interval);

    /**
     * @brief Emitted to request that Y-axis field combo boxes reload their
     * available field lists.
     */
    void reloadValueUnitFields();


protected:
    static const int DEFAULT_MOVING_AVERAGE = 0;  /**< Moving average disabled. */
    static const int DEFAULT_Y_AXIS_FACTOR  = 1;  /**< Y-axis multiplier of 1 (no scaling). */


private:
    Ui::IOGraphDialog *ui;
    CopyFromProfileButton *copy_profile_bt_; /**< Button that copies graph settings from another profile. */

    // Model and delegate chosen over UatFrame to allow custom button layout.
    QPointer<UatModel> uat_model_;  /**< UAT-backed table model for graph rows. */
    UatDelegate *uat_delegate_;     /**< Item delegate providing in-place editors for UAT fields. */

    /** Graph objects in UAT row order; must stay synchronised with uat_model_. */
    QVector<IOGraph *> ioGraphs_;

    QString hint_err_;                         /**< Error string shown in the hint area. */
    QCPGraph *base_graph_;                     /**< The first QCPGraph, used as the time-axis reference. */
    QCPItemTracer *tracer_;                    /**< Crosshair tracer shown on mouse hover. */
    uint32_t packet_num_;                      /**< Packet number nearest the last click. */
    nstime_t start_time_;                      /**< Timestamp of the first interval. */
    bool mouse_drags_;                         /**< true = drag mode; false = rubber-band zoom mode. */
    QRubberBand *rubber_band_;                 /**< Rubber-band selection rectangle for zoom. */
    QPoint rb_origin_;                         /**< Origin of the rubber-band drag in widget coordinates. */
    QMenu ctx_menu_;                           /**< Context menu shown on right-click in the plot. */
    QTimer *stat_timer_;                       /**< Timer driving periodic replot/recalc/retap. */
    bool need_replot_;                         /**< Pending lightweight replot request. */
    bool need_recalc_;                         /**< Pending medium-weight recalculate request. */
    bool need_retap_;                          /**< Pending heavy-weight retap request. */
    bool auto_axes_;                           /**< Whether to auto-rescale axes after each retap. */
    int precision_;                            /**< Decimal precision for axis tick labels. */
    const char *type_unit_name_;               /**< Short Y-axis unit name (e.g. "packets"). */

    QSharedPointer<QCPAxisTicker>         number_ticker_;   /**< Numeric axis ticker for relative time display. */
    QSharedPointer<QCPAxisTickerDateTime> datetime_ticker_; /**< Date/time axis ticker for time-of-day display. */

    /**
     * @brief Theme-default color last assigned to each UAT row.
     *
     * Indexed by UAT row position.  onThemeChanged() refreshes only rows
     * whose current color still equals the recorded default — i.e. rows the
     * user has not customized via the color editor.  The map is best-effort:
     * row delete or reorder leaves stale keys, in which case the affected
     * rows are skipped on the next theme flip rather than wrongly overwritten.
     */
    QHash<int, QColor> themeDefaultColors_;


    /** @brief Zoom both axes in or out by a fixed factor. @param in true to zoom in. */
    void zoomAxes(bool in);
    /** @brief Zoom the X axis only. @param in true to zoom in. */
    void zoomXAxis(bool in);
    /** @brief Zoom the Y axis only. @param in true to zoom in. */
    void zoomYAxis(bool in);
    /**
     * @brief Pan the visible axes by a given pixel offset.
     * @param x_pixels Horizontal pan amount in screen pixels (positive = right).
     * @param y_pixels Vertical pan amount in screen pixels (positive = down).
     */
    void panAxes(int x_pixels, int y_pixels);
    /**
     * @brief Toggle the tracer dot style between default and highlighted.
     * @param force_default If true, always revert to the default style.
     */
    void toggleTracerStyle(bool force_default = false);
    /** @brief Collect axis range and interval information from all graphs. */
    void getGraphInfo();
    /** @brief Refresh the hint label below the plot. */
    void updateHint();
    /** @brief Rebuild the QCustomPlot legend from the current graph set. */
    void updateLegend();
    /**
     * @brief Compute the axis-coordinate rectangle covered by a rubber-band rect.
     * @param zoom_rect The rubber-band rectangle in widget coordinates.
     * @return The corresponding axis-coordinate rectangle.
     */
    QRectF getZoomRanges(QRect zoom_rect);
    /**
     * @brief Construct and register an IOGraph object for a UAT model row.
     * @param currentRow The zero-based UAT row to create an IOGraph for.
     */
    void createIOGraph(int currentRow);
    /**
     * @brief Load graph rows from a UAT field descriptor array.
     * @param io_graph_fields UAT field descriptors to load from.
     */
    void loadProfileGraphs(uat_field_t *io_graph_fields);
    /**
     * @brief Write all graph data as CSV to @p stream.
     * @param stream The text stream to write to.
     */
    void makeCsv(QTextStream &stream) const;
    /**
     * @brief Save all graph data as a CSV file.
     * @param file_name The path of the file to write.
     * @return true on success, false if the file could not be written.
     */
    bool saveCsv(const QString &file_name) const;
    /**
     * @brief Return the first enabled, checked graph, or nullptr if none.
     * @return The currently active IOGraph, or nullptr.
     */
    IOGraph *currentActiveGraph() const;
    /**
     * @brief Return whether the graph at @p row is enabled (checked) in the UAT.
     * @param row Zero-based UAT row index.
     * @return true if the graph is enabled.
     */
    bool graphIsEnabled(int row) const;
    /**
     * @brief Return whether the graph at @p row is drawn as "all other traffic".
     * @param row Zero-based UAT row index.
     * @return true if the graph uses the AOT mode.
     */
    bool graphAsAOT(int row) const;


private slots:
    /**
     * @brief Refresh theme-default graph colors after a theme change.
     *
     * For each UAT row whose current color still equals the previously
     * recorded theme default, replace it with the new theme's
     * graphColor(row) and resync the IOGraph.  User-customized rows
     * (where the current color no longer matches the recorded default)
     * are left untouched.
     */
    void onThemeChanged();

    /**
     * @brief Apply pending UAT changes to the registration tables.
     *
     * Static slot called when the dialog is accepted; commits in-progress
     * UAT edits so they persist across sessions.
     */
    static void applyChanges();

    /**
     * @brief Copy graph settings from an external profile file.
     * @param filename Path of the profile file to copy from.
     */
    void copyFromProfile(QString filename);

    /** @brief Refresh enabled/disabled state of all toolbar and dialog widgets. */
    void updateWidgets();

    /**
     * @brief Display the plot context menu.
     * @param pos The right-click position in plot-widget coordinates.
     */
    void showContextMenu(const QPoint &pos);

    /**
     * @brief Handle a mouse button press on the plot.
     *
     * Initiates a drag-pan or rubber-band-zoom operation depending on the
     * current interaction mode.
     *
     * @param event The mouse event.
     */
    void graphClicked(QMouseEvent *event);

    /**
     * @brief Handle mouse movement over the plot.
     *
     * Updates the crosshair tracer and hint label with the value under the
     * cursor, and updates the rubber-band rectangle during zoom operations.
     *
     * @param event The mouse event.
     */
    void mouseMoved(QMouseEvent *event);

    /**
     * @brief Handle a mouse button release on the plot.
     *
     * Finalises a rubber-band zoom or ends a drag-pan operation.
     *
     * @param event The mouse event.
     */
    void mouseReleased(QMouseEvent *event);

    /**
     * @brief Respond to a change in the selected frame(s) in the packet list.
     *
     * Moves the tracer to the interval containing the first selected frame.
     *
     * @param frames List of selected 1-based frame numbers.
     */
    void selectedFrameChanged(QList<int> frames);

    /** @brief Move the plot legend to the next corner position. */
    void moveLegend();

    /** @brief Reset both axes to auto-fit all visible data. */
    void resetAxes();

    /**
     * @brief Perform the periodic stat update: retap, recalc, or replot
     * depending on the pending flags.
     */
    void updateStatistics(void);

    /** @brief Copy all graph data to the clipboard as CSV text. */
    void copyAsCsvClicked();

    /**
     * @brief Respond to a selection change in the graph UAT view.
     *
     * Enables or disables row-level action buttons (delete, copy, move)
     * based on the new selection.
     *
     * @param selected   Newly selected items.
     * @param deselected Previously selected items that are now deselected.
     */
    void graphUatSelectionChanged(const QItemSelection &selected,
                                  const QItemSelection &deselected);

    /**
     * @brief Handle a change in the interval combo box selection.
     *
     * Updates the tap interval for all graphs and schedules a retap.
     *
     * @param index The new combo box index.
     */
    void on_intervalComboBox_currentIndexChanged(int index);

    /**
     * @brief Handle navigation to a different row in the graph UAT view.
     *
     * Updates displayed per-graph settings (filter, colour, style) to
     * reflect the newly selected row.
     *
     * @param current  The newly selected model index.
     * @param previous The previously selected model index.
     */
    void on_graphUat_currentItemChanged(const QModelIndex &current,
                                        const QModelIndex &previous);

    /**
     * @brief Toggle automatic plot updates when new packets arrive.
     * @param checked true to enable auto-update; false to disable.
     */
    void on_automaticUpdateCheckBox_toggled(bool checked);

    /** @brief Add a new default graph row to the UAT. */
    void on_newToolButton_clicked();
    /** @brief Delete the currently selected graph row from the UAT. */
    void on_deleteToolButton_clicked();
    /** @brief Duplicate the currently selected graph row. */
    void on_copyToolButton_clicked();
    /** @brief Remove all graph rows from the UAT. */
    void on_clearToolButton_clicked();
    /** @brief Move the selected graph row one position up in the UAT. */
    void on_moveUpwardsToolButton_clicked();
    /** @brief Move the selected graph row one position down in the UAT. */
    void on_moveDownwardsToolButton_clicked();

    /**
     * @brief Switch the plot to drag/pan interaction mode.
     * @param checked true when the drag radio button is selected.
     */
    void on_dragRadioButton_toggled(bool checked);

    /**
     * @brief Switch the plot to rubber-band zoom interaction mode.
     * @param checked true when the zoom radio button is selected.
     */
    void on_zoomRadioButton_toggled(bool checked);

    /** @brief Reset both axes (action triggered from menu or shortcut). */
    void on_actionReset_triggered();
    /** @brief Zoom both axes in. */
    void on_actionZoomIn_triggered();
    /** @brief Zoom the X axis in. */
    void on_actionZoomInX_triggered();
    /** @brief Zoom the Y axis in. */
    void on_actionZoomInY_triggered();
    /** @brief Zoom both axes out. */
    void on_actionZoomOut_triggered();
    /** @brief Zoom the X axis out. */
    void on_actionZoomOutX_triggered();
    /** @brief Zoom the Y axis out. */
    void on_actionZoomOutY_triggered();
    /** @brief Pan the view up by 10 pixels. */
    void on_actionMoveUp10_triggered();
    /** @brief Pan the view left by 10 pixels. */
    void on_actionMoveLeft10_triggered();
    /** @brief Pan the view right by 10 pixels. */
    void on_actionMoveRight10_triggered();
    /** @brief Pan the view down by 10 pixels. */
    void on_actionMoveDown10_triggered();
    /** @brief Pan the view up by 1 pixel. */
    void on_actionMoveUp1_triggered();
    /** @brief Pan the view left by 1 pixel. */
    void on_actionMoveLeft1_triggered();
    /** @brief Pan the view right by 1 pixel. */
    void on_actionMoveRight1_triggered();
    /** @brief Pan the view down by 1 pixel. */
    void on_actionMoveDown1_triggered();
    /** @brief Pan the view up by 100 pixels. */
    void on_actionMoveUp100_triggered();
    /** @brief Pan the view left by 100 pixels. */
    void on_actionMoveLeft100_triggered();
    /** @brief Pan the view right by 100 pixels. */
    void on_actionMoveRight100_triggered();
    /** @brief Pan the view down by 100 pixels. */
    void on_actionMoveDown100_triggered();

    /**
     * @brief Navigate the packet list to the packet nearest the tracer position.
     */
    void on_actionGoToPacket_triggered();

    /** @brief Toggle between drag and zoom interaction modes. */
    void on_actionDragZoom_triggered();

    /**
     * @brief Toggle the X-axis between elapsed seconds and absolute time-of-day.
     */
    void on_actionToggleTimeOrigin_triggered();

    /** @brief Toggle the crosshair/tracer visibility on the plot. */
    void on_actionCrosshairs_triggered();

    /** @brief Open the dialog help page. */
    void on_buttonBox_helpRequested();

    /** @brief Apply UAT changes and close the dialog. */
    void on_buttonBox_accepted();

    /**
     * @brief Dispatch button box clicks to the appropriate action.
     * @param button The button that was clicked.
     */
    void buttonBoxClicked(QAbstractButton *button);

    /**
     * @brief Show or hide the plot legend.
     * @param checked true to show the legend; false to hide it.
     */
    void actionLegendTriggered(bool checked);

    /**
     * @brief Toggle the X-axis between elapsed time and time-of-day display.
     * @param checked true to display time-of-day; false for elapsed seconds.
     */
    void actionTimeOfDayTriggered(bool checked);

    /**
     * @brief Toggle the Y-axis between linear and logarithmic scale.
     * @param checked true to use a logarithmic scale; false for linear.
     */
    void actionLogScaleTriggered(bool checked);
};
#endif // IO_GRAPH_DIALOG_H
