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

#include <glib.h>

#include "epan/epan_dissect.h"
#include "epan/prefs.h"
#include "ui/preference_utils.h"

#include "ui/io_graph_item.h"

#include "wireshark_dialog.h"

#include <ui/qt/models/uat_model.h>
#include <ui/qt/models/uat_delegate.h>

#include <QIcon>
#include <QMenu>
#include <QTextStream>

class QRubberBand;
class QTimer;

class QCPBars;
class QCPGraph;
class QCPItemTracer;
class QCustomPlot;
class QCPAxisTicker;
class QCPAxisTickerDateTime;

// GTK+ sets this to 100000 (NUM_IO_ITEMS)
const int max_io_items_ = 250000;

// XXX - Move to its own file?
class IOGraph : public QObject {
Q_OBJECT
public:
    // COUNT_TYPE_* in gtk/io_graph.c
    enum PlotStyles { psLine, psImpulse, psBar, psStackedBar, psDot, psSquare, psDiamond, psCross, psPlus, psCircle };

    explicit IOGraph(QCustomPlot *parent);
    ~IOGraph();
    const QString configError() { return config_err_; }
    const QString name() { return name_; }
    void setName(const QString &name);
    const QString filter() { return filter_; }
    void setFilter(const QString &filter);
    void applyCurrentColor();
    bool visible() { return visible_; }
    void setVisible(bool visible);
    QRgb color();
    void setColor(const QRgb color);
    void setPlotStyle(int style);
    const QString valueUnitLabel();
    void setValueUnits(int val_units);
    const QString valueUnitField() { return vu_field_; }
    void setValueUnitField(const QString &vu_field);
    unsigned int movingAveragePeriod() { return moving_avg_period_; }
    void setInterval(int interval);
    bool addToLegend();
    bool removeFromLegend();
    QCPGraph *graph() { return graph_; }
    QCPBars *bars() { return bars_; }
    double startOffset();
    int packetFromTime(double ts);
    bool hasItemToShow(int idx, double value) const;
    double getItemValue(int idx, const capture_file *cap_file) const;
    int maxInterval () const { return cur_idx_; }
    QString scaledValueUnit() const { return scaled_value_unit_; }

    void clearAllData();

    unsigned int moving_avg_period_;
    unsigned int y_axis_factor_;

public slots:
    void recalcGraphData(capture_file *cap_file, bool enable_scaling);
    void captureEvent(CaptureEvent e);
    void reloadValueUnitField();

signals:
    void requestReplot();
    void requestRecalc();
    void requestRetap();

private:
    // Callbacks for register_tap_listener
    static void tapReset(void *iog_ptr);
    static tap_packet_status tapPacket(void *iog_ptr, packet_info *pinfo, epan_dissect_t *edt, const void *data, tap_flags_t flags);
    static void tapDraw(void *iog_ptr);

    void calculateScaledValueUnit();
    template<class DataMap> double maxValueFromGraphData(const DataMap &map);
    template<class DataMap> void scaleGraphData(DataMap &map, int scalar);

    QCustomPlot *parent_;
    QString config_err_;
    QString name_;
    bool visible_;
    QCPGraph *graph_;
    QCPBars *bars_;
    QString filter_;
    QBrush color_;
    io_graph_item_unit_t val_units_;
    QString vu_field_;
    int hf_index_;
    int interval_;
    double start_time_;
    QString scaled_value_unit_;

    // Cached data. We should be able to change the Y axis without retapping as
    // much as is feasible.
    io_graph_item_t items_[max_io_items_];
    int cur_idx_;
};

namespace Ui {
class IOGraphDialog;
}

class IOGraphDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit IOGraphDialog(QWidget &parent, CaptureFile &cf, QString displayFilter = QString());
    ~IOGraphDialog();

    enum UatColumns { colEnabled = 0, colName, colDFilter, colColor, colStyle, colYAxis, colYField, colSMAPeriod, colYAxisFactor, colMaxNum};

    void addGraph(bool checked, QString name, QString dfilter, QRgb color_idx, IOGraph::PlotStyles style,
                  io_graph_item_unit_t value_units, QString yfield, int moving_average, int yaxisfactor);
    void addGraph(bool copy_from_current = false);
    void addDefaultGraph(bool enabled, int idx = 0);
    void syncGraphSettings(int row);

public slots:
    void scheduleReplot(bool now = false);
    void scheduleRecalc(bool now = false);
    void scheduleRetap(bool now = false);
    void modelRowsReset();
    void reloadFields();

protected:
    void keyPressEvent(QKeyEvent *event);
    void reject();

signals:
    void goToPacket(int packet_num);
    void recalcGraphData(capture_file *cap_file, bool enable_scaling);
    void intervalChanged(int interval);
    void reloadValueUnitFields();

private:
    Ui::IOGraphDialog *ui;

    //Model and delegate were chosen over UatFrame because add/remove/copy
    //buttons would need realignment (UatFrame has its own)
    UatModel *uat_model_;
    UatDelegate *uat_delegate_;

    // XXX - This needs to stay synced with UAT index
    QVector<IOGraph*> ioGraphs_;

    QString hint_err_;
    QCPGraph *base_graph_;
    QCPItemTracer *tracer_;
    guint32 packet_num_;
    double start_time_;
    bool mouse_drags_;
    QRubberBand *rubber_band_;
    QPoint rb_origin_;
    QMenu ctx_menu_;
    QTimer *stat_timer_;
    bool need_replot_; // Light weight: tell QCP to replot existing data
    bool need_recalc_; // Medium weight: recalculate values, then replot
    bool need_retap_; // Heavy weight: re-read packet data
    bool auto_axes_;

    QSharedPointer<QCPAxisTicker> number_ticker_;
    QSharedPointer<QCPAxisTickerDateTime> datetime_ticker_;


//    void fillGraph();
    void zoomAxes(bool in);
    void zoomXAxis(bool in);
    void zoomYAxis(bool in);
    void panAxes(int x_pixels, int y_pixels);
    void toggleTracerStyle(bool force_default = false);
    void getGraphInfo();
    void updateLegend();
    QRectF getZoomRanges(QRect zoom_rect);
    void createIOGraph(int currentRow);
    void loadProfileGraphs();
    void makeCsv(QTextStream &stream) const;
    bool saveCsv(const QString &file_name) const;
    IOGraph *currentActiveGraph() const;
    bool graphIsEnabled(int row) const;

private slots:
    void copyFromProfile(QString filename);
    void updateWidgets();
    void graphClicked(QMouseEvent *event);
    void mouseMoved(QMouseEvent *event);
    void mouseReleased(QMouseEvent *event);

    void resetAxes();
    void updateStatistics(void);
    void copyAsCsvClicked();

    void on_intervalComboBox_currentIndexChanged(int index);
    void on_todCheckBox_toggled(bool checked);
    void modelDataChanged(const QModelIndex &index);
    void on_graphUat_currentItemChanged(const QModelIndex &current, const QModelIndex &previous);

    void on_resetButton_clicked();
    void on_logCheckBox_toggled(bool checked);
    void on_automaticUpdateCheckBox_toggled(bool checked);
    void on_newToolButton_clicked();
    void on_deleteToolButton_clicked();
    void on_copyToolButton_clicked();
    void on_clearToolButton_clicked();
    void on_dragRadioButton_toggled(bool checked);
    void on_zoomRadioButton_toggled(bool checked);
    void on_actionReset_triggered();
    void on_actionZoomIn_triggered();
    void on_actionZoomInX_triggered();
    void on_actionZoomInY_triggered();
    void on_actionZoomOut_triggered();
    void on_actionZoomOutX_triggered();
    void on_actionZoomOutY_triggered();
    void on_actionMoveUp10_triggered();
    void on_actionMoveLeft10_triggered();
    void on_actionMoveRight10_triggered();
    void on_actionMoveDown10_triggered();
    void on_actionMoveUp1_triggered();
    void on_actionMoveLeft1_triggered();
    void on_actionMoveRight1_triggered();
    void on_actionMoveDown1_triggered();
    void on_actionGoToPacket_triggered();
    void on_actionDragZoom_triggered();
    void on_actionToggleTimeOrigin_triggered();
    void on_actionCrosshairs_triggered();
    void on_buttonBox_helpRequested();
    void on_buttonBox_accepted();
};

#endif // IO_GRAPH_DIALOG_H
