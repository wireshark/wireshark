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

// Saved graph settings
typedef struct _io_graph_settings_t {
    bool enabled;
    bool asAOT;
    char* name;
    char* dfilter;
    unsigned color;
    uint32_t style;
    uint32_t yaxis;
    char* yfield;
    uint32_t sma_period;
    double y_axis_factor;
} io_graph_settings_t;


extern const value_string moving_avg_vs[];

/* define I/O Graph specific UAT columns */
enum UatColumnsIOG {colEnabled = 0, colName, colDFilter, colColor, colStyle, colYAxis, colYField, colSMAPeriod, colYAxisFactor, colAOT, colMaxNum};

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

class IOGraphDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit IOGraphDialog(QWidget &parent, CaptureFile &cf, const char* type_unit_name);
    virtual ~IOGraphDialog();
    // Initialize the dialog after construction to allow polymorphic behavior.
    void initialize(QWidget& parent, uat_field_t* io_graph_fields, QString displayFilter = QString(),
        io_graph_item_unit_t value_units = IOG_ITEM_UNIT_PACKETS,
        QString yfield = QString(),
        bool is_sibling_dialog = false,
        const QVector<QString> convFilters = QVector<QString>());

    void addGraph(bool checked, bool asAOT, QString name, QString dfilter, QRgb color_idx, IOGraph::PlotStyles style,
                  io_graph_item_unit_t value_units, QString yfield, int moving_average, double yaxisfactor);
    void addGraph(bool checked, bool asAOT, QString dfilter, io_graph_item_unit_t value_units, QString yfield);
    void addGraph(bool copy_from_current = false);
    virtual void addDefaultGraph(bool enabled, int idx = 0);
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
    virtual QString getFilteredName() const;
    virtual QString getXAxisName() const;
    virtual const char* getYAxisName(io_graph_item_unit_t value_units) const;
    virtual QString getYFieldName(io_graph_item_unit_t value_units, const QString& yfield) const;
    virtual int getYAxisValue(const QString& data);
    virtual QString getNoDataHint() const;
    virtual QString getHintText(unsigned num_items) const;

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

protected:
    static const int DEFAULT_MOVING_AVERAGE = 0;
    static const int DEFAULT_Y_AXIS_FACTOR = 1;

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
    const char* type_unit_name_;

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
    void loadProfileGraphs(uat_field_t* io_graph_fields);
    void makeCsv(QTextStream &stream) const;
    bool saveCsv(const QString &file_name) const;
    IOGraph *currentActiveGraph() const;
    bool graphIsEnabled(int row) const;
    bool graphAsAOT(int row) const;

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
    void on_graphUat_currentItemChanged(const QModelIndex &current, const QModelIndex &previous);

    void on_automaticUpdateCheckBox_toggled(bool checked);
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
    void on_actionMoveUp100_triggered();
    void on_actionMoveLeft100_triggered();
    void on_actionMoveRight100_triggered();
    void on_actionMoveDown100_triggered();
    void on_actionGoToPacket_triggered();
    void on_actionDragZoom_triggered();
    void on_actionToggleTimeOrigin_triggered();
    void on_actionCrosshairs_triggered();
    void on_buttonBox_helpRequested();
    void on_buttonBox_accepted();
    void buttonBoxClicked(QAbstractButton *button);
    void actionLegendTriggered(bool checked);
    void actionTimeOfDayTriggered(bool checked);
    void actionLogScaleTriggered(bool checked);
};

#endif // IO_GRAPH_DIALOG_H
