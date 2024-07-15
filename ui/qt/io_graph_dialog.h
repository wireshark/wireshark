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

#include "epan/epan_dissect.h"
#include "epan/prefs.h"
#include "ui/preference_utils.h"

#include "ui/io_graph_item.h"

#include "wireshark_dialog.h"

#include <ui/qt/models/uat_model.h>
#include <ui/qt/models/uat_delegate.h>

#include <wsutil/str_util.h>

#include <QPointer>
#include <QIcon>
#include <QMenu>
#include <QTextStream>
#include <QItemSelection>

#include <vector>

class QRubberBand;
class QTimer;
class QAbstractButton;
class CopyFromProfileButton;

class QCPBars;
class QCPGraph;
class QCPItemTracer;
class QCustomPlot;
class QCPAxisTicker;
class QCPAxisTickerDateTime;

// GTK+ set this to 100000 (NUM_IO_ITEMS) before raising it to unlimited
// in commit 524583298beb671f43e972476693866754d38a38.
// This is the maximum index returned from get_io_graph_index that will
// be added to the graph. Thus, for a minimum interval size of 1 μs no
// more than 33.55 s.
// Each io_graph_item_t is 88 bytes on a system with 64 bit time_t, so
// the max size we'll attempt to allocate for the array of items is 2.75 GiB
// (plus a tiny amount extra for the std::vector bookkeeping.)
// 2^25 = 16777216
const int max_io_items_ = 1 << 25;

// XXX - Move to its own file?
class IOGraph : public QObject {
Q_OBJECT
public:
    // COUNT_TYPE_* in gtk/io_graph.c
    enum PlotStyles { psLine, psDotLine, psStepLine, psDotStepLine, psImpulse, psBar, psStackedBar, psDot, psSquare, psDiamond, psCross, psPlus, psCircle };

    explicit IOGraph(QCustomPlot *parent);
    ~IOGraph();
    QString configError() const { return config_err_; }
    QString name() const { return name_; }
    void setName(const QString &name);
    QString filter() const { return filter_; }
    bool setFilter(const QString &filter);
    void applyCurrentColor();
    bool visible() const { return visible_; }
    void setVisible(bool visible);
    bool needRetap() const { return need_retap_; }
    void setNeedRetap(bool retap);
    QRgb color() const;
    void setColor(const QRgb color);
    void setPlotStyle(int style);
    QString valueUnitLabel() const;
    format_size_units_e formatUnits() const;
    io_graph_item_unit_t valueUnits() const { return val_units_; }
    void setValueUnits(int val_units);
    QString valueUnitField() const { return vu_field_; }
    void setValueUnitField(const QString &vu_field);
    unsigned int movingAveragePeriod() const { return moving_avg_period_; }
    void setInterval(int interval);
    bool addToLegend();
    bool removeFromLegend();
    QCPGraph *graph() const { return graph_; }
    QCPBars *bars() const { return bars_; }
    double startOffset() const;
    nstime_t startTime() const;
    int packetFromTime(double ts) const;
    bool hasItemToShow(int idx, double value) const;
    double getItemValue(int idx, const capture_file *cap_file) const;
    int maxInterval () const { return cur_idx_; }

    void clearAllData();

    unsigned int moving_avg_period_;
    unsigned int y_axis_factor_;

public slots:
    void recalcGraphData(capture_file *cap_file);
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

    void removeTapListener();

    bool showsZero() const;

    template<class DataMap> double maxValueFromGraphData(const DataMap &map);
    template<class DataMap> void scaleGraphData(DataMap &map, int scalar);

    QCustomPlot *parent_;
    QString config_err_;
    QString name_;
    bool tap_registered_;
    bool visible_;
    bool need_retap_;
    QCPGraph *graph_;
    QCPBars *bars_;
    QString filter_;
    QString full_filter_; // Includes vu_field_ if used
    QBrush color_;
    io_graph_item_unit_t val_units_;
    QString vu_field_;
    int hf_index_;
    int interval_;
    nstime_t start_time_;

    // Cached data. We should be able to change the Y axis without retapping as
    // much as is feasible.
    std::vector<io_graph_item_t> items_;
    int cur_idx_;
};

namespace Ui {
class IOGraphDialog;
}

class IOGraphDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit IOGraphDialog(QWidget &parent, CaptureFile &cf, QString displayFilter = QString(), io_graph_item_unit_t value_units = IOG_ITEM_UNIT_PACKETS, QString yfield = QString());
    ~IOGraphDialog();

    enum UatColumns { colEnabled = 0, colName, colDFilter, colColor, colStyle, colYAxis, colYField, colSMAPeriod, colYAxisFactor, colMaxNum};

    void addGraph(bool checked, QString name, QString dfilter, QRgb color_idx, IOGraph::PlotStyles style,
                  io_graph_item_unit_t value_units, QString yfield, int moving_average, int yaxisfactor);
    void addGraph(bool checked, QString dfilter, io_graph_item_unit_t value_units, QString yfield);
    void addGraph(bool copy_from_current = false);
    void addDefaultGraph(bool enabled, int idx = 0);
    void syncGraphSettings(int row);
    qsizetype graphCount() const;

public slots:
    void scheduleReplot(bool now = false);
    void scheduleRecalc(bool now = false);
    void scheduleRetap(bool now = false);
    void reloadFields();

protected:
    void captureFileClosing();
    void keyPressEvent(QKeyEvent *event);
    void reject();

protected slots:
    void modelDataChanged(const QModelIndex &topLeft, const QModelIndex &bottomRight, const QVector<int> &roles);
    void modelRowsReset();
    void modelRowsInserted(const QModelIndex &parent, int first, int last);
    void modelRowsRemoved(const QModelIndex &parent, int first, int last);
    void modelRowsMoved(const QModelIndex &sourceParent, int sourceStart, int sourceEnd, const QModelIndex &destinationParent, int destinationRow);

signals:
    void goToPacket(int packet_num);
    void recalcGraphData(capture_file *cap_file);
    void intervalChanged(int interval);
    void reloadValueUnitFields();

private:
    Ui::IOGraphDialog *ui;
    CopyFromProfileButton *copy_profile_bt_;

    //Model and delegate were chosen over UatFrame because add/remove/copy
    //buttons would need realignment (UatFrame has its own)
    QPointer<UatModel> uat_model_;
    UatDelegate *uat_delegate_;

    // XXX - This needs to stay synced with UAT index
    QVector<IOGraph*> ioGraphs_;

    QString hint_err_;
    QCPGraph *base_graph_;
    QCPItemTracer *tracer_;
    uint32_t packet_num_;
    nstime_t start_time_;
    bool mouse_drags_;
    QRubberBand *rubber_band_;
    QPoint rb_origin_;
    QMenu ctx_menu_;
    QTimer *stat_timer_;
    bool need_replot_; // Light weight: tell QCP to replot existing data
    bool need_recalc_; // Medium weight: recalculate values, then replot
    bool need_retap_; // Heavy weight: re-read packet data
    bool auto_axes_;
    int precision_;

    QSharedPointer<QCPAxisTicker> number_ticker_;
    QSharedPointer<QCPAxisTickerDateTime> datetime_ticker_;


//    void fillGraph();
    void zoomAxes(bool in);
    void zoomXAxis(bool in);
    void zoomYAxis(bool in);
    void panAxes(int x_pixels, int y_pixels);
    void toggleTracerStyle(bool force_default = false);
    void getGraphInfo();
    void updateHint();
    void updateLegend();
    QRectF getZoomRanges(QRect zoom_rect);
    void createIOGraph(int currentRow);
    void loadProfileGraphs();
    void makeCsv(QTextStream &stream) const;
    bool saveCsv(const QString &file_name) const;
    IOGraph *currentActiveGraph() const;
    bool graphIsEnabled(int row) const;

private slots:
    static void applyChanges();

    void copyFromProfile(QString filename);
    void updateWidgets();
    void showContextMenu(const QPoint &pos);
    void graphClicked(QMouseEvent *event);
    void mouseMoved(QMouseEvent *event);
    void mouseReleased(QMouseEvent *event);
    void selectedFrameChanged(QList<int> frames);
    void moveLegend();

    void resetAxes();
    void updateStatistics(void);
    void copyAsCsvClicked();

    void graphUatSelectionChanged(const QItemSelection &selected, const QItemSelection &deselected);
    void on_intervalComboBox_currentIndexChanged(int index);
    void on_todCheckBox_toggled(bool checked);
    void on_graphUat_currentItemChanged(const QModelIndex &current, const QModelIndex &previous);

    void on_logCheckBox_toggled(bool checked);
    void on_automaticUpdateCheckBox_toggled(bool checked);
    void on_enableLegendCheckBox_toggled(bool checked);
    void on_newToolButton_clicked();
    void on_deleteToolButton_clicked();
    void on_copyToolButton_clicked();
    void on_clearToolButton_clicked();
    void on_moveUpwardsToolButton_clicked();
    void on_moveDownwardsToolButton_clicked();
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
    void buttonBoxClicked(QAbstractButton *button);
};

#endif // IO_GRAPH_DIALOG_H
