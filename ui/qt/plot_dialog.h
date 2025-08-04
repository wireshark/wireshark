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
    uint32_t y_axis_factor;
} plot_settings_t;

static const value_string graph_style_vs[] = {
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

class PlotDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit PlotDialog(QWidget& parent, CaptureFile& cf, bool show_default = true);
    ~PlotDialog();
    /* Add plot with default name, style, color and scale. */
    void addPlot(bool checked, const QString& dfilter, const QString& yfield);

public slots:
    void scheduleReplot() { need_replot_ = true; }
    void scheduleRecalc() { need_recalc_ = true; }
    void scheduleRetap() { need_retap_ = true; }

protected:
    void captureFileClosing() override;
    void keyPressEvent(QKeyEvent* event) override;
    void reject() override;

protected slots:
    void modelDataChanged(const QModelIndex& topLeft, const QModelIndex& bottomRight, const QVector<int>& roles);
    void modelRowsReset();
    void modelRowsInserted(const QModelIndex& parent, int first, int last);
    void modelRowsRemoved(const QModelIndex& parent, int first, int last);
    void modelRowsMoved(const QModelIndex& sourceParent, int sourceStart, int sourceEnd, const QModelIndex& destinationParent, int destinationRow);

signals:
    void goToPacket(int packet, int hf_id);
    void updateMarker(const int size, const double xCoord, const int);
    void setPosMarker(const double xCoord, const int selectMPos, const int posMPos);
private:
    void loadProfileGraphs();
    void createPlot(int currentRow);
    void syncPlotSettings(int row);
    int getLastPlotIdx();
    /* Add plot with all defined parameters. */
    void addPlot(bool checked, const QString& name, const QString& dfilter, QRgb color_idx,
        Graph::PlotStyles style, const QString& yfield, int y_axis_factor = Graph::default_y_axis_factor_);
    /* Add one of the two (four) default plots. */
    void addDefaultPlot(bool enabled, bool filtered);

    bool graphIsEnabled(int row) const;
    Plot* currentActiveGraph() const;
    void getGraphInfo();
    void updateHint();
    void updateLegendPos();
    void resetAxes();
    void doZoom(bool in, bool y);
    void zoomAxes(bool in);
    void zoomXAxis(bool in);
    void zoomYAxis(bool in);
    void panAxes(int x_pixels, int y_pixels);
    void updateXAxisLabel();
    QRectF getZoomRanges(QRect zoom_rect, QCPAxisRect** matchedAxisRect = nullptr);
    bool makeCsv(QTextStream& stream) const;
    QCPAxisRect* getAxisRect(int idx);
    void removeExcessPlots();
    void setTracerColor();
    QCPAxisRect* axisRectFromPos(const QPoint& pos);
    void addMarkerDifference();
    int visibleMarker(const bool first = true) const;
    Marker* addMarker(const bool isPosMarker);
    void drawMarker(const Marker*);
    void drawMarkers();
    void addDataPointsMarkers();
    void updateFirstAxisRectHeight();
    QList<QCPAxisRect*> axisRects() const;
    void autoScroll() const;
    Ui::PlotDialog* ui;
    QPushButton* copy_bt_;
    CopyFromProfileButton* copy_profile_bt_;

    //Model and delegate were chosen over UatFrame because add/remove/copy
    //buttons would need realignment (UatFrame has its own)
    QPointer<UatModel> uat_model_;
    UatDelegate* uat_delegate_;

    // XXX - This needs to stay synced with UAT index
    QVector<Plot*> plots_;

    QString hint_err_;
    QCPGraph* base_graph_;
    QCPItemTracer* tracer_;
    uint32_t packet_num_;
    double start_time_;
    QRubberBand* rubber_band_;
    QPoint rb_origin_;
    QMenu ctx_menu_;
    QTimer* stat_timer_;
    QCPMarginGroup* margin_group_;
    Qt::Alignment legend_alignment_;
    bool need_replot_; // Light weight: tell QCP to replot existing data
    bool need_recalc_; // Medium weight: recalculate values, then replot
    bool need_retap_; // Heavy weight: re-read packet data
    bool auto_axes_;
    bool abs_time_;
    double last_right_clicked_pos_;
private slots:
    static void applyChanges();
    /* This function will take care of retapping and redrawing. */
    void updateStatistics();
    void updateLegend();
    void copyFromProfile(const QString& filename);
    void copyAsCsvClicked();

    void showContextMenu(const QPoint& pos);
    void moveLegend();
    void graphClicked(QMouseEvent* event);
    void mouseMoved(QMouseEvent* event);
    void mouseReleased(QMouseEvent* event);

    void selectedFrameChanged(const QList<int>& frames);
    void plotUatSelectionChanged(const QItemSelection& selected, const QItemSelection& deselected);
    void on_leftButtonBox_clicked(QAbstractButton* button);
    void on_actionLegend_triggered(bool checked);
    void on_actionLogScale_triggered(bool checked);
    void on_actionCrosshairs_triggered(bool checked);
    void on_actionTopAxis_triggered(bool checked);
    void on_automaticUpdateCheckBox_toggled(bool checked);
    void on_plotUat_currentItemChanged(const QModelIndex& current, const QModelIndex& previous);
    void on_actionGoToPacket_triggered();
    void on_newToolButton_clicked();
    void on_deleteToolButton_clicked();
    void on_copyToolButton_clicked();
    void on_clearToolButton_clicked();
    void on_moveUpwardsToolButton_clicked();
    void on_moveDownwardsToolButton_clicked();
    void on_rightButtonBox_helpRequested();
    void on_actionReset_triggered() { resetAxes(); }
    void on_actionZoomIn_triggered() { zoomAxes(true); }
    void on_actionZoomInX_triggered() { zoomXAxis(true); }
    void on_actionZoomInY_triggered() { zoomYAxis(true); }
    void on_actionZoomOut_triggered() { zoomAxes(false); }
    void on_actionZoomOutX_triggered() { zoomXAxis(false); }
    void on_actionZoomOutY_triggered() { zoomYAxis(false); }
    void on_actionMoveUp10_triggered() { panAxes(0, 10); }
    void on_actionMoveLeft10_triggered() { panAxes(-10, 0); }
    void on_actionMoveRight10_triggered() { panAxes(10, 0); }
    void on_actionMoveDown10_triggered() { panAxes(0, -10); }
    void on_actionMoveUp1_triggered() { panAxes(0, 1); }
    void on_actionMoveLeft1_triggered() { panAxes(-1, 0); }
    void on_actionMoveRight1_triggered() { panAxes(1, 0); }
    void on_actionMoveDown1_triggered() { panAxes(0, -1); }
    void on_actionToggleTimeOrigin_triggered();
    void on_rightButtonBox_accepted();
    void on_actionAutoScroll_triggered(bool checked);

    void on_actionAddMarker_triggered();
    void on_actionMoveMarker_triggered();
    void on_actionShowPosMarker_triggered();
    void on_actionShowMarkersDifference_triggered();
    void on_actionDeleteMarker_triggered();
    void on_actionDeleteAllMarkers_triggered();
    void on_actionShowDataPointMarker_triggered();

};

#endif // PLOT_DIALOG_H
