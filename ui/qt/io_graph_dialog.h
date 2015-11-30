/* io_graph_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef IO_GRAPH_DIALOG_H
#define IO_GRAPH_DIALOG_H

#include <config.h>

#include <glib.h>

#include "epan/epan_dissect.h"

#include "ui/io_graph_item.h"

#include "wireshark_dialog.h"

#include <QIcon>
#include <QMenu>
#include <QTextStream>

class QComboBox;
class QLineEdit;
class QRubberBand;
class QTimer;
class QTreeWidgetItem;

class SyntaxLineEdit;

class QCPBars;
class QCPGraph;
class QCPItemTracer;
class QCustomPlot;

// GTK+ sets this to 100000 (NUM_IO_ITEMS)
const int max_io_items_ = 250000;

// XXX - Move to its own file?
class IOGraph : public QObject {
Q_OBJECT
public:
    // COUNT_TYPE_* in gtk/io_graph.c
    enum PlotStyles { psLine, psImpulse, psBar, psStackedBar, psDot, psSquare, psDiamond };

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
    double getItemValue(int idx, const capture_file *cap_file) const;
    int maxInterval () const { return cur_idx_; }

    void clearAllData();

    static QMap<io_graph_item_unit_t, QString> valueUnitsToNames();
    static QMap<PlotStyles, QString> plotStylesToNames();
    static QMap<int, QString> movingAveragesToNames();

    unsigned int moving_avg_period_;

public slots:
    void recalcGraphData(capture_file *cap_file);
    void captureFileClosing();
    void reloadValueUnitField();

signals:
    void requestReplot();
    void requestRecalc();
    void requestRetap();

private:
    // Callbacks for register_tap_listener
    static void tapReset(void *iog_ptr);
    static gboolean tapPacket(void *iog_ptr, packet_info *pinfo, epan_dissect_t *edt, const void *data);
    static void tapDraw(void *iog_ptr);

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
    explicit IOGraphDialog(QWidget &parent, CaptureFile &cf);
    ~IOGraphDialog();

    void addGraph(bool checked, QString name, QString dfilter, int color_idx, IOGraph::PlotStyles style,
                  io_graph_item_unit_t value_units, QString yfield, int moving_average);
    void addGraph(bool copy_from_current = false);
    void addDefaultGraph(bool enabled, int idx = 0);
    void syncGraphSettings(QTreeWidgetItem *item);

public slots:
    void scheduleReplot(bool now = false);
    void scheduleRecalc(bool now = false);
    void scheduleRetap(bool now = false);
    void reloadFields();

protected:
    void keyPressEvent(QKeyEvent *event);
    void reject();

signals:
    void goToPacket(int packet_num);
    void recalcGraphData(capture_file *);
    void intervalChanged(int interval);
    void reloadValueUnitFields();

private:
    Ui::IOGraphDialog *ui;

    QLineEdit *name_line_edit_;
    SyntaxLineEdit *dfilter_line_edit_;
    SyntaxLineEdit *yfield_line_edit_;
    QComboBox *color_combo_box_;
    QComboBox *style_combo_box_;
    QComboBox *yaxis_combo_box_;
    QComboBox *sma_combo_box_;
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
    // Available colors
    // XXX - Add custom
    QList<QRgb> colors_;


//    void fillGraph();
    void zoomAxes(bool in);
    void zoomXAxis(bool in);
    void zoomYAxis(bool in);
    void panAxes(int x_pixels, int y_pixels);
    QIcon graphColorIcon(int color_idx);
    void toggleTracerStyle(bool force_default = false);
    void getGraphInfo();
    void updateLegend();
    QRectF getZoomRanges(QRect zoom_rect);
    void itemEditingFinished(QTreeWidgetItem *item);
    void loadProfileGraphs();
    void makeCsv(QTextStream &stream) const;
    bool saveCsv(const QString &file_name) const;

private slots:
    void updateWidgets();
    void graphClicked(QMouseEvent *event);
    void mouseMoved(QMouseEvent *event);
    void mouseReleased(QMouseEvent *event);
    void focusChanged(QWidget *previous, QWidget *current);
    void activateLastItem();
    void resetAxes();
    void updateStatistics(void);
    void copyAsCsvClicked();

    void on_intervalComboBox_currentIndexChanged(int index);
    void on_todCheckBox_toggled(bool checked);
    void on_graphTreeWidget_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous);
    void on_graphTreeWidget_itemActivated(QTreeWidgetItem *item, int column);
    void on_graphTreeWidget_itemSelectionChanged();
    void on_graphTreeWidget_itemChanged(QTreeWidgetItem *item, int column);

    void on_resetButton_clicked();
    void on_logCheckBox_toggled(bool checked);
    void on_newToolButton_clicked();
    void on_deleteToolButton_clicked();
    void on_copyToolButton_clicked();
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

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
