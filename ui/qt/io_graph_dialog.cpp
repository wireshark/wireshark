/* io_graph_dialog.cpp
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

#include "io_graph_dialog.h"
#include <ui_io_graph_dialog.h>

#include "file.h"

#include <epan/stat_tap_ui.h>
#include "epan/stats_tree_priv.h"
#include "epan/uat-int.h"

#include <wsutil/utf8_entities.h>

#include "qt_ui_utils.h"

#include "color_utils.h"
#include "qcustomplot.h"
#include "progress_frame.h"
#include "stock_icon.h"
#include "syntax_line_edit.h"
#include "display_filter_edit.h"
#include "field_filter_edit.h"
#include "wireshark_application.h"

#include <QClipboard>
#include <QComboBox>
#include <QFileDialog>
#include <QFontMetrics>
#include <QFrame>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QRubberBand>
#include <QSpacerItem>
#include <QTimer>
#include <QTreeWidget>
#include <QVariant>

// Bugs and uncertainties:
// - Regular (non-stacked) bar graphs are drawn on top of each other on the Z axis.
//   The QCP forum suggests drawing them side by side:
//   http://www.qcustomplot.com/index.php/support/forum/62
// - You can't manually set a graph color other than manually editing the io_graphs
//   UAT. We should add a "graph color" preference.
// - We retap and redraw more than we should.
// - Smoothing doesn't seem to match GTK+

// To do:
// - Use scroll bars?
// - Scroll during live captures
// - Set ticks per pixel (e.g. pressing "2" sets 2 tpp).

const int name_col_    = 0;
const int dfilter_col_ = 1;
const int color_col_   = 2;
const int style_col_   = 3;
const int yaxis_col_   = 4;
const int yfield_col_  = 5;
const int sma_period_col_ = 6;
const int num_cols_ = 7;

const qreal graph_line_width_ = 1.0;

// When we drop support for Qt <5 we can initialize these with
// datastreams.
const QMap<io_graph_item_unit_t, QString> value_unit_to_name_ = IOGraph::valueUnitsToNames();
const QMap<IOGraph::PlotStyles, QString> plot_style_to_name_ = IOGraph::plotStylesToNames();
const QMap<int, QString> moving_average_to_name_ = IOGraph::movingAveragesToNames();

const int default_moving_average_ = 0;

// Don't accidentally zoom into a 1x1 rect if you happen to click on the graph
// in zoom mode.
const int min_zoom_pixels_ = 20;

const int stat_update_interval_ = 200; // ms

// Saved graph settings

static const value_string graph_enabled_vs[] = {
    { 0, "Disabled" },
    { 1, "Enabled" },
    { 0, NULL }
};

typedef struct _io_graph_settings_t {
    guint32 enabled;
    char* name;
    char* dfilter;
    char* color;
    char* style;
    char* yaxis;
    char* yfield;
    int sma_period;
} io_graph_settings_t;

static io_graph_settings_t *iog_settings_ = NULL;
static guint num_io_graphs_ = 0;
static uat_t *iog_uat_ = NULL;

extern "C" {

UAT_VS_DEF(io_graph, enabled, io_graph_settings_t, guint32, 0, "Disabled")
UAT_CSTRING_CB_DEF(io_graph, name, io_graph_settings_t)
UAT_CSTRING_CB_DEF(io_graph, dfilter, io_graph_settings_t)
UAT_CSTRING_CB_DEF(io_graph, color, io_graph_settings_t)
UAT_CSTRING_CB_DEF(io_graph, style, io_graph_settings_t)
UAT_CSTRING_CB_DEF(io_graph, yaxis, io_graph_settings_t)
UAT_CSTRING_CB_DEF(io_graph, yfield, io_graph_settings_t)
UAT_DEC_CB_DEF(io_graph, sma_period, io_graph_settings_t)

static uat_field_t io_graph_fields[] = {
    UAT_FLD_VS(io_graph, enabled, "Enabled", graph_enabled_vs, "Graph visibility"),
    UAT_FLD_CSTRING(io_graph, name, "Graph Name", "The name of the graph"),
    UAT_FLD_CSTRING(io_graph, dfilter, "Display Filter", "Graph packets matching this display filter"),
    UAT_FLD_CSTRING(io_graph, color, "Color", "Graph color (#RRGGBB)"),
    UAT_FLD_CSTRING(io_graph, style, "Style", "Graph style (Line, Bars, etc.)"),
    UAT_FLD_CSTRING(io_graph, yaxis, "Y Axis", "Y Axis units"),
    UAT_FLD_CSTRING(io_graph, yfield, "Y Field", "Apply calculations to this field"),
    UAT_FLD_DEC(io_graph, sma_period, "SMA Period", "Simple moving average period"),
    UAT_END_FIELDS
};

static void* io_graph_copy_cb(void* dst_ptr, const void* src_ptr, size_t) {
    io_graph_settings_t* dst = (io_graph_settings_t *)dst_ptr;
    const io_graph_settings_t* src = (const io_graph_settings_t *)src_ptr;

    dst->enabled = src->enabled;
    dst->name = g_strdup(src->name);
    dst->dfilter = g_strdup(src->dfilter);
    dst->color = g_strdup(src->color);
    dst->style = g_strdup(src->style);
    dst->yaxis = g_strdup(src->yaxis);
    dst->yfield = g_strdup(src->yfield);
    dst->sma_period = src->sma_period;

    return dst;
}

static void io_graph_free_cb(void* p) {
    io_graph_settings_t *iogs = (io_graph_settings_t *)p;
    g_free(iogs->name);
    g_free(iogs->dfilter);
    g_free(iogs->color);
    g_free(iogs->yfield);
}

} // extern "C"


Q_DECLARE_METATYPE(IOGraph *)

IOGraphDialog::IOGraphDialog(QWidget &parent, CaptureFile &cf) :
    WiresharkDialog(parent, cf),
    ui(new Ui::IOGraphDialog),
    name_line_edit_(NULL),
    dfilter_line_edit_(NULL),
    yfield_line_edit_(NULL),
    color_combo_box_(NULL),
    style_combo_box_(NULL),
    yaxis_combo_box_(NULL),
    sma_combo_box_(NULL),
    base_graph_(NULL),
    tracer_(NULL),
    start_time_(0.0),
    mouse_drags_(true),
    rubber_band_(NULL),
    stat_timer_(NULL),
    need_replot_(false),
    need_retap_(false),
    auto_axes_(true),
    colors_(ColorUtils::graphColors())
{
    ui->setupUi(this);
    loadGeometry();

    setWindowSubtitle(tr("IO Graphs"));
    setAttribute(Qt::WA_DeleteOnClose, true);
    QCustomPlot *iop = ui->ioPlot;

    QPushButton *save_bt = ui->buttonBox->button(QDialogButtonBox::Save);
    save_bt->setText(tr("Save As" UTF8_HORIZONTAL_ELLIPSIS));

    QPushButton *copy_bt = ui->buttonBox->addButton(tr("Copy"), QDialogButtonBox::ActionRole);
    connect (copy_bt, SIGNAL(clicked()), this, SLOT(copyAsCsvClicked()));

    QPushButton *close_bt = ui->buttonBox->button(QDialogButtonBox::Close);
    if (close_bt) {
        close_bt->setDefault(true);
    }

    stat_timer_ = new QTimer(this);
    connect(stat_timer_, SIGNAL(timeout()), this, SLOT(updateStatistics()));
    stat_timer_->start(stat_update_interval_);

    // Intervals (ms)
    ui->intervalComboBox->addItem(tr("1 ms"),        1);
    ui->intervalComboBox->addItem(tr("10 ms"),      10);
    ui->intervalComboBox->addItem(tr("100 ms"),    100);
    ui->intervalComboBox->addItem(tr("1 sec"),    1000);
    ui->intervalComboBox->addItem(tr("10 sec"),  10000);
    ui->intervalComboBox->addItem(tr("1 min"),   60000);
    ui->intervalComboBox->addItem(tr("10 min"), 600000);
    ui->intervalComboBox->setCurrentIndex(3);

    ui->todCheckBox->setChecked(false);

    ui->dragRadioButton->setChecked(mouse_drags_);

    ctx_menu_.addAction(ui->actionZoomIn);
    ctx_menu_.addAction(ui->actionZoomInX);
    ctx_menu_.addAction(ui->actionZoomInY);
    ctx_menu_.addAction(ui->actionZoomOut);
    ctx_menu_.addAction(ui->actionZoomOutX);
    ctx_menu_.addAction(ui->actionZoomOutY);
    ctx_menu_.addAction(ui->actionReset);
    ctx_menu_.addSeparator();
    ctx_menu_.addAction(ui->actionMoveRight10);
    ctx_menu_.addAction(ui->actionMoveLeft10);
    ctx_menu_.addAction(ui->actionMoveUp10);
    ctx_menu_.addAction(ui->actionMoveDown10);
    ctx_menu_.addAction(ui->actionMoveRight1);
    ctx_menu_.addAction(ui->actionMoveLeft1);
    ctx_menu_.addAction(ui->actionMoveUp1);
    ctx_menu_.addAction(ui->actionMoveDown1);
    ctx_menu_.addSeparator();
    ctx_menu_.addAction(ui->actionGoToPacket);
    ctx_menu_.addSeparator();
    ctx_menu_.addAction(ui->actionDragZoom);
    ctx_menu_.addAction(ui->actionToggleTimeOrigin);
    ctx_menu_.addAction(ui->actionCrosshairs);

    iop->xAxis->setLabel(tr("Time (s)"));

    iop->setMouseTracking(true);
    iop->setEnabled(true);

    QCPPlotTitle *title = new QCPPlotTitle(iop);
    iop->plotLayout()->insertRow(0);
    iop->plotLayout()->addElement(0, 0, title);
    title->setText(tr("Wireshark IO Graphs: %1").arg(cap_file_.fileTitle()));

    tracer_ = new QCPItemTracer(iop);
    iop->addItem(tracer_);

    loadProfileGraphs();
    if (num_io_graphs_ > 0) {
        for (guint i = 0; i < num_io_graphs_; i++) {
            io_graph_settings_t *iogs = &iog_settings_[i];
            QRgb pcolor = QColor(iogs->color).rgb();
            int color_idx;
            IOGraph::PlotStyles style = plot_style_to_name_.key(iogs->style, IOGraph::psLine);

            io_graph_item_unit_t value_units;
            if (g_strcmp0(iogs->yaxis, "Bytes/s") == 0) { // Silently upgrade obsolete yaxis unit name
                value_units = value_unit_to_name_.key(iogs->yaxis, IOG_ITEM_UNIT_BYTES);
            } else if (g_strcmp0(iogs->yaxis, "Bits/s") == 0) { // Silently upgrade obsolete yaxis unit name
                value_units = value_unit_to_name_.key(iogs->yaxis, IOG_ITEM_UNIT_BITS);
            } else {
                value_units = value_unit_to_name_.key(iogs->yaxis, IOG_ITEM_UNIT_PACKETS);
            }

            for (color_idx = 0; color_idx < colors_.size(); color_idx++) {
                if (pcolor == colors_[color_idx]) break;
            }
            if (color_idx >= colors_.size()) {
                colors_ << pcolor;
            }

            addGraph(iogs->enabled == 1, iogs->name, iogs->dfilter, color_idx, style, value_units, iogs->yfield, iogs->sma_period);
        }
    } else {
        addDefaultGraph(true, 0);
        addDefaultGraph(true, 1);
    }

    on_graphTreeWidget_itemSelectionChanged();

    toggleTracerStyle(true);
    iop->setFocus();

    iop->rescaleAxes();

    // Shrink columns down, then expand as needed
    QTreeWidget *gtw = ui->graphTreeWidget;
    int one_em = fontMetrics().height();
    gtw->setRootIsDecorated(false);
    gtw->setColumnWidth(name_col_, one_em * 10);
    gtw->setColumnWidth(dfilter_col_, one_em * 10);
    gtw->setColumnWidth(color_col_, one_em * 2.5);
    gtw->setColumnWidth(style_col_, one_em * 5.5);
    gtw->setColumnWidth(yaxis_col_, one_em * 6.5);
    gtw->setColumnWidth(yfield_col_, one_em * 6);
    gtw->setColumnWidth(sma_period_col_, one_em * 6);

    ProgressFrame::addToButtonBox(ui->buttonBox, &parent);

    connect(wsApp, SIGNAL(focusChanged(QWidget*,QWidget*)), this, SLOT(focusChanged(QWidget*,QWidget*)));
    connect(iop, SIGNAL(mousePress(QMouseEvent*)), this, SLOT(graphClicked(QMouseEvent*)));
    connect(iop, SIGNAL(mouseMove(QMouseEvent*)), this, SLOT(mouseMoved(QMouseEvent*)));
    connect(iop, SIGNAL(mouseRelease(QMouseEvent*)), this, SLOT(mouseReleased(QMouseEvent*)));
    disconnect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
}

IOGraphDialog::~IOGraphDialog()
{
    cap_file_.stopLoading();
    for (int i = 0; i < ui->graphTreeWidget->topLevelItemCount(); i++) {
        IOGraph *iog = qvariant_cast<IOGraph *>(ui->graphTreeWidget->topLevelItem(i)->data(name_col_, Qt::UserRole));
        delete iog;
    }
    delete ui;
    ui = NULL;
}

void IOGraphDialog::addGraph(bool checked, QString name, QString dfilter, int color_idx, IOGraph::PlotStyles style, io_graph_item_unit_t value_units, QString yfield, int moving_average)
{
    QTreeWidgetItem *ti = new QTreeWidgetItem();
    ui->graphTreeWidget->addTopLevelItem(ti);

    IOGraph *iog = new IOGraph(ui->ioPlot);
    ti->setData(name_col_, Qt::UserRole, qVariantFromValue(iog));
    ti->setCheckState(name_col_, checked ? Qt::Checked : Qt::Unchecked);
    ti->setText(name_col_, name);
    ti->setText(dfilter_col_, dfilter);
    color_idx = color_idx % colors_.size();
    ti->setData(color_col_, Qt::UserRole, color_idx);
    ti->setIcon(color_col_, graphColorIcon(color_idx));
    ti->setText(style_col_, plot_style_to_name_[style]);
    ti->setData(style_col_, Qt::UserRole, style);
    ti->setText(yaxis_col_, value_unit_to_name_[value_units]);
    ti->setData(yaxis_col_, Qt::UserRole, value_units);
    ti->setText(yfield_col_, yfield);
    ti->setText(sma_period_col_, moving_average_to_name_[moving_average]);
    ti->setData(sma_period_col_, Qt::UserRole, moving_average);

    connect(this, SIGNAL(recalcGraphData(capture_file *)), iog, SLOT(recalcGraphData(capture_file *)));
    connect(this, SIGNAL(reloadValueUnitFields()), iog, SLOT(reloadValueUnitField()));
    connect(&cap_file_, SIGNAL(captureFileClosing()), iog, SLOT(captureFileClosing()));
    connect(iog, SIGNAL(requestRetap()), this, SLOT(scheduleRetap()));
    connect(iog, SIGNAL(requestRecalc()), this, SLOT(scheduleRecalc()));
    connect(iog, SIGNAL(requestReplot()), this, SLOT(scheduleReplot()));

    syncGraphSettings(ti);
    if (iog->visible()) {
        scheduleRetap();
    }
}

void IOGraphDialog::addGraph(bool copy_from_current)
{
    QTreeWidgetItem *cur_ti = NULL;

    if (copy_from_current) {
        cur_ti = ui->graphTreeWidget->currentItem();
    }

    if (copy_from_current && cur_ti) {
        addGraph(cur_ti->checkState(name_col_) == Qt::Checked,
                 cur_ti->text(name_col_),
                 cur_ti->text(dfilter_col_),
                 cur_ti->data(color_col_, Qt::UserRole).toInt(),
                 (IOGraph::PlotStyles)cur_ti->data(style_col_, Qt::UserRole).toInt(),
                 (io_graph_item_unit_t)cur_ti->data(yaxis_col_, Qt::UserRole).toInt(),
                 cur_ti->text(yfield_col_),
                 cur_ti->data(sma_period_col_, Qt::UserRole).toInt());
    } else {
        addDefaultGraph(false);
    }
}

void IOGraphDialog::addDefaultGraph(bool enabled, int idx)
{
    switch (idx % 2) {
    case 0:
        addGraph(enabled, tr("All packets"), QString(), ui->graphTreeWidget->topLevelItemCount(),
                 IOGraph::psLine, IOG_ITEM_UNIT_PACKETS, QString(), default_moving_average_);
        break;
    default:
        addGraph(enabled, tr("TCP errors"), "tcp.analysis.flags", ui->graphTreeWidget->topLevelItemCount(),
                 IOGraph::psBar, IOG_ITEM_UNIT_PACKETS, QString(), default_moving_average_);
        break;
    }
}

// Sync the settings from a graphTreeWidget item to its IOGraph.
// Disables the graph if any errors are found.
void IOGraphDialog::syncGraphSettings(QTreeWidgetItem *item)
{
    if (!item) return;
    IOGraph *iog = item->data(name_col_, Qt::UserRole).value<IOGraph *>();
    if (!iog) return;

    bool visible = item->checkState(name_col_) == Qt::Checked;
    bool retap = !iog->visible() && visible;

    iog->setName(item->text(name_col_));

    iog->setFilter(item->text(dfilter_col_));
    iog->setColor(colors_[item->data(color_col_, Qt::UserRole).toInt() % colors_.size()]);
    iog->setPlotStyle(item->data(style_col_, Qt::UserRole).toInt());

    iog->setValueUnits(item->data(yaxis_col_, Qt::UserRole).toInt());
    iog->setValueUnitField(item->text(yfield_col_));

    iog->moving_avg_period_ = item->data(sma_period_col_, Qt::UserRole).toUInt();

    iog->setInterval(ui->intervalComboBox->itemData(ui->intervalComboBox->currentIndex()).toInt());

    ui->graphTreeWidget->blockSignals(true); // setFlags emits itemChanged
    if (!iog->configError().isEmpty()) {
        hint_err_ = iog->configError();
        visible = false;
        retap = false;
        // On OS X the "not user checkable" checkbox isn't obviously disabled.
        // For now show it as partially checked.
        item->setCheckState(name_col_, Qt::PartiallyChecked);
        item->setFlags(item->flags() & ~Qt::ItemIsUserCheckable);
    } else {
        item->setFlags(item->flags() | Qt::ItemIsUserCheckable);
    }
    ui->graphTreeWidget->blockSignals(false);

    iog->setVisible(visible);

    getGraphInfo();
    mouseMoved(NULL); // Update hint
    updateLegend();

    if (visible) {
        if (retap) {
            scheduleRetap();
        } else {
            scheduleReplot();
        }
    }
}

void IOGraphDialog::updateWidgets()
{
    WiresharkDialog::updateWidgets();
}

void IOGraphDialog::scheduleReplot(bool now)
{
    need_replot_ = true;
    if (now) updateStatistics();
}

void IOGraphDialog::scheduleRecalc(bool now)
{
    need_recalc_ = true;
    if (now) updateStatistics();
}

void IOGraphDialog::scheduleRetap(bool now)
{
    need_retap_ = true;
    if (now) updateStatistics();
}

void IOGraphDialog::reloadFields()
{
    emit reloadValueUnitFields();
}

void IOGraphDialog::keyPressEvent(QKeyEvent *event)
{
    int pan_pixels = event->modifiers() & Qt::ShiftModifier ? 1 : 10;

    switch(event->key()) {
    case Qt::Key_Minus:
    case Qt::Key_Underscore:    // Shifted minus on U.S. keyboards
    case Qt::Key_O:             // GTK+
    case Qt::Key_R:
        zoomAxes(false);
        break;
    case Qt::Key_Plus:
    case Qt::Key_Equal:         // Unshifted plus on U.S. keyboards
    case Qt::Key_I:             // GTK+
        zoomAxes(true);
        break;
    case Qt::Key_X:             // Zoom X axis only
        if(event->modifiers() & Qt::ShiftModifier){
            zoomXAxis(false);   // upper case X -> Zoom out
        } else {
            zoomXAxis(true);    // lower case x -> Zoom in
        }
        break;
    case Qt::Key_Y:             // Zoom Y axis only
        if(event->modifiers() & Qt::ShiftModifier){
            zoomYAxis(false);   // upper case Y -> Zoom out
        } else {
            zoomYAxis(true);    // lower case y -> Zoom in
        }
        break;
    case Qt::Key_Right:
    case Qt::Key_L:
        panAxes(pan_pixels, 0);
        break;
    case Qt::Key_Left:
    case Qt::Key_H:
        panAxes(-1 * pan_pixels, 0);
        break;
    case Qt::Key_Up:
    case Qt::Key_K:
        panAxes(0, pan_pixels);
        break;
    case Qt::Key_Down:
    case Qt::Key_J:
        panAxes(0, -1 * pan_pixels);
        break;

    case Qt::Key_Space:
        toggleTracerStyle();
        break;

    case Qt::Key_0:
    case Qt::Key_ParenRight:    // Shifted 0 on U.S. keyboards
    case Qt::Key_Home:
        resetAxes();
        break;

    case Qt::Key_G:
        on_actionGoToPacket_triggered();
        break;
    case Qt::Key_T:
        on_actionToggleTimeOrigin_triggered();
        break;
    case Qt::Key_Z:
        on_actionDragZoom_triggered();
        break;
    }

    QDialog::keyPressEvent(event);
}

void IOGraphDialog::reject()
{
    // Catch escape keys.
    QList<QWidget *>editors = QList<QWidget *>() << name_line_edit_ << dfilter_line_edit_ << yfield_line_edit_;

    foreach (QWidget *w, editors) {
        if (w && w->hasFocus()) {
            ui->graphTreeWidget->setFocus(); // Trigger itemEditingFinished
            return;
        }
    }

    QList<QComboBox *>combos = QList<QComboBox *>() << color_combo_box_ << style_combo_box_ <<
                                                  yaxis_combo_box_ << sma_combo_box_;
    foreach (QComboBox *cb, combos) {
        if (cb && (cb->hasFocus() || cb->view()->hasFocus())) {
            ui->graphTreeWidget->setFocus(); // Trigger itemEditingFinished
            return;
        }
    }

    if (iog_uat_) {
        uat_clear(iog_uat_);

        for (int i = 0; i < ui->graphTreeWidget->topLevelItemCount(); i++) {
            QTreeWidgetItem *item = ui->graphTreeWidget->topLevelItem(i);
            IOGraph *iog = NULL;
            if (item) {
                iog = item->data(name_col_, Qt::UserRole).value<IOGraph *>();
                io_graph_settings_t iogs;
                QColor color(iog->color());
                iogs.enabled = iog->visible() ? 1 : 0;
                iogs.name = qstring_strdup(iog->name());
                iogs.dfilter = qstring_strdup(iog->filter());
                iogs.color = qstring_strdup(color.name());
                iogs.style = qstring_strdup(plot_style_to_name_[(IOGraph::PlotStyles)item->data(style_col_, Qt::UserRole).toInt()]);
                iogs.yaxis = qstring_strdup(iog->valueUnitLabel());
                iogs.yfield = qstring_strdup(iog->valueUnitField());
                iogs.sma_period = iog->movingAveragePeriod();
                uat_add_record(iog_uat_, &iogs, TRUE);
                io_graph_free_cb(&iogs);
            }
        }
        char* err = NULL;
        if (!uat_save(iog_uat_, &err)) {
            /* XXX - report this error */
            g_free(err);
        }
    }

    QDialog::reject();
}

void IOGraphDialog::zoomAxes(bool in)
{
    QCustomPlot *iop = ui->ioPlot;
    double h_factor = iop->axisRect()->rangeZoomFactor(Qt::Horizontal);
    double v_factor = iop->axisRect()->rangeZoomFactor(Qt::Vertical);

    auto_axes_ = false;

    if (!in) {
        h_factor = pow(h_factor, -1);
        v_factor = pow(v_factor, -1);
    }

    iop->xAxis->scaleRange(h_factor, iop->xAxis->range().center());
    iop->yAxis->scaleRange(v_factor, iop->yAxis->range().center());
    iop->replot();
}

void IOGraphDialog::zoomXAxis(bool in)
{
    QCustomPlot *iop = ui->ioPlot;
    double h_factor = iop->axisRect()->rangeZoomFactor(Qt::Horizontal);

    auto_axes_ = false;

    if (!in) {
        h_factor = pow(h_factor, -1);
    }

    iop->xAxis->scaleRange(h_factor, iop->xAxis->range().center());
    iop->replot();
}

void IOGraphDialog::zoomYAxis(bool in)
{
    QCustomPlot *iop = ui->ioPlot;
    double v_factor = iop->axisRect()->rangeZoomFactor(Qt::Vertical);

    auto_axes_ = false;

    if (!in) {
        v_factor = pow(v_factor, -1);
    }

    iop->yAxis->scaleRange(v_factor, iop->yAxis->range().center());
    iop->replot();
}

void IOGraphDialog::panAxes(int x_pixels, int y_pixels)
{
    QCustomPlot *iop = ui->ioPlot;
    double h_pan = 0.0;
    double v_pan = 0.0;

    auto_axes_ = false;

    h_pan = iop->xAxis->range().size() * x_pixels / iop->xAxis->axisRect()->width();
    v_pan = iop->yAxis->range().size() * y_pixels / iop->yAxis->axisRect()->height();
    // The GTK+ version won't pan unless we're zoomed. Should we do the same here?
    if (h_pan) {
        iop->xAxis->moveRange(h_pan);
        iop->replot();
    }
    if (v_pan) {
        iop->yAxis->moveRange(v_pan);
        iop->replot();
    }
}

QIcon IOGraphDialog::graphColorIcon(int color_idx)
{
    return StockIcon::colorIcon(colors_[color_idx % colors_.size()], QColor(QPalette::Mid).rgb());
}

void IOGraphDialog::toggleTracerStyle(bool force_default)
{
    if (!tracer_->visible() && !force_default) return;
    if (!ui->ioPlot->graph(0)) return;

    QPen sp_pen = ui->ioPlot->graph(0)->pen();
    QCPItemTracer::TracerStyle tstyle = QCPItemTracer::tsCrosshair;
    QPen tr_pen = QPen(tracer_->pen());
    QColor tr_color = sp_pen.color();

    if (force_default || tracer_->style() != QCPItemTracer::tsCircle) {
        tstyle = QCPItemTracer::tsCircle;
        tr_color.setAlphaF(1.0);
        tr_pen.setWidthF(1.5);
    } else {
        tr_color.setAlphaF(0.5);
        tr_pen.setWidthF(1.0);
    }

    tracer_->setStyle(tstyle);
    tr_pen.setColor(tr_color);
    tracer_->setPen(tr_pen);
    ui->ioPlot->replot();
}

// Scan through our graphs and gather information.
// QCPItemTracers can only be associated with QCPGraphs. Find the first one
// and associate it with our tracer. Set bar stacking order while we're here.
void IOGraphDialog::getGraphInfo()
{
    base_graph_ = NULL;
    QCPBars *prev_bars = NULL;
    start_time_ = 0.0;

    tracer_->setGraph(NULL);
    for (int i = 0; i < ui->graphTreeWidget->topLevelItemCount(); i++) {
        QTreeWidgetItem *item = ui->graphTreeWidget->topLevelItem(i);
        IOGraph *iog = NULL;
        if (item) {
            iog = item->data(name_col_, Qt::UserRole).value<IOGraph *>();
            QCPGraph *graph = iog->graph();
            QCPBars *bars = iog->bars();
            int style = item->data(style_col_, Qt::UserRole).toInt();
            if (graph && !base_graph_) {
                base_graph_ = graph;
            } else if (bars && style == IOGraph::psStackedBar && iog->visible()) {
                bars->moveBelow(NULL); // Remove from existing stack
                bars->moveBelow(prev_bars);
                prev_bars = bars;
            }
            if (iog->visible()) {
                double iog_start = iog->startOffset();
                if (start_time_ == 0.0 || iog_start < start_time_) {
                    start_time_ = iog_start;
                }
            }
        }
    }
    if (base_graph_ && base_graph_->data()->size() > 0) {
        tracer_->setGraph(base_graph_);
        tracer_->setVisible(true);
    }
}

void IOGraphDialog::updateLegend()
{
    QCustomPlot *iop = ui->ioPlot;
    QSet<QString> vu_label_set;
    QString intervalText = ui->intervalComboBox->itemText(ui->intervalComboBox->currentIndex());

    iop->legend->setVisible(false);
    iop->yAxis->setLabel(QString());

    // Find unique labels
    for (int i = 0; i < ui->graphTreeWidget->topLevelItemCount(); i++) {
        QTreeWidgetItem *ti = ui->graphTreeWidget->topLevelItem(i);
        IOGraph *iog = NULL;
        if (ti && ti->checkState(name_col_) == Qt::Checked) {
            iog = ti->data(name_col_, Qt::UserRole).value<IOGraph *>();
            vu_label_set.insert(iog->valueUnitLabel());
        }
    }

    // Nothing.
    if (vu_label_set.size() < 1) {
        return;
    }

    // All the same. Use the Y Axis label.
    if (vu_label_set.size() == 1) {
        iop->yAxis->setLabel(vu_label_set.values()[0] + "/" + intervalText);
        return;
    }

    // Differing labels. Create a legend with a Title label at top.
    // Legend Title thanks to: http://www.qcustomplot.com/index.php/support/forum/443
    QCPStringLegendItem* legendTitle = qobject_cast<QCPStringLegendItem*>(iop->legend->elementAt(0));
    if (legendTitle == NULL) {
        legendTitle = new QCPStringLegendItem(iop->legend, QString(""));
        iop->legend->insertRow(0);
        iop->legend->addElement(0, 0, legendTitle);
    }
    legendTitle->setText(QString(intervalText + " Intervals "));

    for (int i = 0; i < ui->graphTreeWidget->topLevelItemCount(); i++) {
        QTreeWidgetItem *ti = ui->graphTreeWidget->topLevelItem(i);
        IOGraph *iog = NULL;
        if (ti) {
            iog = ti->data(name_col_, Qt::UserRole).value<IOGraph *>();
            if (ti->checkState(name_col_) == Qt::Checked) {
                iog->addToLegend();
            } else {
                iog->removeFromLegend();
            }
        }
    }
    iop->legend->setVisible(true);
}

QRectF IOGraphDialog::getZoomRanges(QRect zoom_rect)
{
    QRectF zoom_ranges = QRectF();

    if (zoom_rect.width() < min_zoom_pixels_ && zoom_rect.height() < min_zoom_pixels_) {
        return zoom_ranges;
    }

    QCustomPlot *iop = ui->ioPlot;
    QRect zr = zoom_rect.normalized();
    QRect ar = iop->axisRect()->rect();
    if (ar.intersects(zr)) {
        QRect zsr = ar.intersected(zr);
        zoom_ranges.setX(iop->xAxis->range().lower
                         + iop->xAxis->range().size() * (zsr.left() - ar.left()) / ar.width());
        zoom_ranges.setWidth(iop->xAxis->range().size() * zsr.width() / ar.width());

        // QRects grow down
        zoom_ranges.setY(iop->yAxis->range().lower
                         + iop->yAxis->range().size() * (ar.bottom() - zsr.bottom()) / ar.height());
        zoom_ranges.setHeight(iop->yAxis->range().size() * zsr.height() / ar.height());
    }
    return zoom_ranges;
}

void IOGraphDialog::graphClicked(QMouseEvent *event)
{
    QCustomPlot *iop = ui->ioPlot;

    if (event->button() == Qt::RightButton) {
        // XXX We should find some way to get ioPlot to handle a
        // contextMenuEvent instead.
        ctx_menu_.exec(event->globalPos());
    } else  if (mouse_drags_) {
        if (iop->axisRect()->rect().contains(event->pos())) {
            iop->setCursor(QCursor(Qt::ClosedHandCursor));
        }
        on_actionGoToPacket_triggered();
    } else {
        if (!rubber_band_) {
            rubber_band_ = new QRubberBand(QRubberBand::Rectangle, iop);
        }
        rb_origin_ = event->pos();
        rubber_band_->setGeometry(QRect(rb_origin_, QSize()));
        rubber_band_->show();
    }
    iop->setFocus();
}

void IOGraphDialog::mouseMoved(QMouseEvent *event)
{
    QCustomPlot *iop = ui->ioPlot;
    QString hint;
    Qt::CursorShape shape = Qt::ArrowCursor;

    if (!hint_err_.isEmpty()) {
        hint += QString("<b>%1</b> ").arg(hint_err_);
    }
    if (event) {
        if (event->buttons().testFlag(Qt::LeftButton)) {
            if (mouse_drags_) {
                shape = Qt::ClosedHandCursor;
            } else {
                shape = Qt::CrossCursor;
            }
        } else if (iop->axisRect()->rect().contains(event->pos())) {
            if (mouse_drags_) {
                shape = Qt::OpenHandCursor;
            } else {
                shape = Qt::CrossCursor;
            }
        }
        iop->setCursor(QCursor(shape));
    }

    if (mouse_drags_) {
        double ts = 0;
        packet_num_ = 0;
        int interval_packet = -1;

        if (event && tracer_->graph()) {
            tracer_->setGraphKey(iop->xAxis->pixelToCoord(event->pos().x()));
            ts = tracer_->position->key();

            QTreeWidgetItem *ti = ui->graphTreeWidget->topLevelItem(0);
            IOGraph *iog = NULL;
            if (ti) {
                iog = ti->data(name_col_, Qt::UserRole).value<IOGraph *>();
                interval_packet = iog->packetFromTime(ts);
            }
        }

        if (interval_packet < 0) {
            hint += tr("Hover over the graph for details.");
        } else {
            QString msg = tr("No packets in interval");
            QString val;
            if (interval_packet > 0) {
                packet_num_ = (guint32) interval_packet;
                msg = QString("%1 %2")
                        .arg(!file_closed_ ? tr("Click to select packet") : tr("Packet"))
                        .arg(packet_num_);
                val = " = " + QString::number(tracer_->position->value(), 'g', 4);
            }
            hint += tr("%1 (%2s%3).")
                    .arg(msg)
                    .arg(QString::number(ts, 'g', 4))
                    .arg(val);
        }
        iop->replot();
    } else {
        if (event && rubber_band_ && rubber_band_->isVisible()) {
            rubber_band_->setGeometry(QRect(rb_origin_, event->pos()).normalized());
            QRectF zoom_ranges = getZoomRanges(QRect(rb_origin_, event->pos()));
            if (zoom_ranges.width() > 0.0 && zoom_ranges.height() > 0.0) {
                hint += tr("Release to zoom, x = %1 to %2, y = %3 to %4")
                        .arg(zoom_ranges.x())
                        .arg(zoom_ranges.x() + zoom_ranges.width())
                        .arg(zoom_ranges.y())
                        .arg(zoom_ranges.y() + zoom_ranges.height());
            } else {
                hint += tr("Unable to select range.");
            }
        } else {
            hint += tr("Click to select a portion of the graph.");
        }
    }

    hint.prepend("<small><i>");
    hint.append("</i></small>");
    ui->hintLabel->setText(hint);
}

void IOGraphDialog::mouseReleased(QMouseEvent *event)
{
    QCustomPlot *iop = ui->ioPlot;
    auto_axes_ = false;
    if (rubber_band_) {
        rubber_band_->hide();
        if (!mouse_drags_) {
            QRectF zoom_ranges = getZoomRanges(QRect(rb_origin_, event->pos()));
            if (zoom_ranges.width() > 0.0 && zoom_ranges.height() > 0.0) {
                iop->xAxis->setRangeLower(zoom_ranges.x());
                iop->xAxis->setRangeUpper(zoom_ranges.x() + zoom_ranges.width());
                iop->yAxis->setRangeLower(zoom_ranges.y());
                iop->yAxis->setRangeUpper(zoom_ranges.y() + zoom_ranges.height());
                iop->replot();
            }
        }
    } else if (iop->cursor().shape() == Qt::ClosedHandCursor) {
        iop->setCursor(QCursor(Qt::OpenHandCursor));
    }
}

void IOGraphDialog::focusChanged(QWidget *, QWidget *current)
{
    QTreeWidgetItem *item = ui->graphTreeWidget->currentItem();
    if (!item) {
        return;
    }

    // If we navigated away from an editing session, clear it.
    QList<QWidget *>editors = QList<QWidget *>() << name_line_edit_ << dfilter_line_edit_ <<
                                                  color_combo_box_ << style_combo_box_ <<
                                                  yaxis_combo_box_ << yfield_line_edit_ <<
                                                  sma_combo_box_;
    bool edit_active = false;
    foreach (QWidget *w, editors) {
        if (w) {
            edit_active = true;
        }
    }
    if (!edit_active) {
        return;
    }
    editors.append(color_combo_box_->view());
    editors.append(style_combo_box_->view());
    editors.append(yaxis_combo_box_->view());
    editors.append(sma_combo_box_->view());

    if (! editors.contains(current)) {
        itemEditingFinished(item);
    }
}

void IOGraphDialog::activateLastItem()
{
    int last_idx = ui->graphTreeWidget->topLevelItemCount() - 1;
    if (last_idx < 0) return;

    QTreeWidgetItem *last_item = ui->graphTreeWidget->invisibleRootItem()->child(last_idx);
    if (!last_item) return;

    ui->graphTreeWidget->setCurrentItem(last_item);
    on_graphTreeWidget_itemActivated(last_item, name_col_);
}

void IOGraphDialog::resetAxes()
{
    QCustomPlot *iop = ui->ioPlot;
    QCPRange x_range = iop->xAxis->scaleType() == QCPAxis::stLogarithmic ?
                iop->xAxis->range().sanitizedForLogScale() : iop->xAxis->range();

    double pixel_pad = 10.0; // per side

    iop->rescaleAxes(true);

    double axis_pixels = iop->xAxis->axisRect()->width();
    iop->xAxis->scaleRange((axis_pixels + (pixel_pad * 2)) / axis_pixels, x_range.center());

    axis_pixels = iop->yAxis->axisRect()->height();
    iop->yAxis->scaleRange((axis_pixels + (pixel_pad * 2)) / axis_pixels, iop->yAxis->range().center());

    auto_axes_ = true;
    iop->replot();
}

void IOGraphDialog::updateStatistics()
{
    if (!isVisible()) return;

    if (need_retap_ && !file_closed_) {
        need_retap_ = false;
        cap_file_.retapPackets();
        // The user might have closed the window while tapping, which means
        // we might no longer exist.
    } else {
        if (need_recalc_ && !file_closed_) {
            need_recalc_ = false;
            need_replot_ = true;
            emit recalcGraphData(cap_file_.capFile());
            if (!tracer_->graph()) {
                if (base_graph_ && base_graph_->data()->size() > 0) {
                    tracer_->setGraph(base_graph_);
                    tracer_->setVisible(true);
                } else {
                    tracer_->setVisible(false);
                }
            }
        }
        if (need_replot_) {
            need_replot_ = false;
            if (auto_axes_) {
                resetAxes();
            }
            ui->ioPlot->replot();
        }
    }
}

// We're done editing a treewidgetitem. Set its values based on its
// widgets, remove each widget, then sync with our associated graph.
void IOGraphDialog::itemEditingFinished(QTreeWidgetItem *item)
{
    if (item) {
        bool recalc = false;
        // Don't force a retap here. Disable the graph instead.
        Qt::CheckState check_state = item->checkState(name_col_);
        hint_err_.clear();
        io_graph_item_unit_t item_unit = IOG_ITEM_UNIT_PACKETS;
        QString field_name;

        if (name_line_edit_) {
            item->setText(name_col_, name_line_edit_->text());
            name_line_edit_ = NULL;
        }
        if (dfilter_line_edit_) {
            QString df = dfilter_line_edit_->text();
            if (item->text(dfilter_col_).compare(df)) {
                check_state = Qt::Unchecked;
            }
            item->setText(dfilter_col_, df);
            dfilter_line_edit_ = NULL;
        }
        if (color_combo_box_) {
            int index = color_combo_box_->currentIndex();
            item->setData(color_col_, Qt::UserRole, index);
            item->setIcon(color_col_, graphColorIcon(index));
            color_combo_box_ = NULL;
        }
        if (style_combo_box_) {
            IOGraph::PlotStyles ps = IOGraph::psLine;
            int index = style_combo_box_->currentIndex();
            if (index < plot_style_to_name_.size()) {
                ps = plot_style_to_name_.keys()[index];
            }
            item->setText(style_col_, plot_style_to_name_[ps]);
            item->setData(style_col_, Qt::UserRole, ps);
            style_combo_box_ = NULL;
        }
        if (yaxis_combo_box_) {
            int index = yaxis_combo_box_->currentIndex();
            if (index != item->data(yaxis_col_, Qt::UserRole).toInt()) {
                if (index <= IOG_ITEM_UNIT_CALC_SUM) {
                    recalc = true;
                } else {
                    check_state = Qt::Unchecked;
                }
            }
            if (index < value_unit_to_name_.size()) {
                item_unit = value_unit_to_name_.keys()[index];
            }
            item->setText(yaxis_col_, value_unit_to_name_[item_unit]);
            item->setData(yaxis_col_, Qt::UserRole, item_unit);
            yaxis_combo_box_ = NULL;
        }
        if (yfield_line_edit_) {
            if (item->text(yfield_col_).compare(yfield_line_edit_->text())) {
                check_state = Qt::Unchecked;
            }
            item->setText(yfield_col_, yfield_line_edit_->text());
            field_name = yfield_line_edit_->text();
            yfield_line_edit_ = NULL;
        }
        if (sma_combo_box_) {
            int index = sma_combo_box_->currentIndex();
            if (index != item->data(sma_period_col_, Qt::UserRole).toInt()) {
                recalc = true;
            }
            QString text = sma_combo_box_->itemText(index);
            int sma = sma_combo_box_->itemData(index, Qt::UserRole).toInt();
            item->setText(sma_period_col_, text);
            item->setData(sma_period_col_, Qt::UserRole, sma);
            sma_combo_box_ = NULL;
        }

        for (int col = 0; col < num_cols_; col++) {
            QWidget *w = ui->graphTreeWidget->itemWidget(item, col);
            if (w) {
                ui->graphTreeWidget->removeItemWidget(item, col);
            }
        }

        item->setCheckState(name_col_, check_state);
        syncGraphSettings(item);

        if (recalc) {
            scheduleRecalc(true);
        } else {
            scheduleReplot(true);
        }
    }
}

void IOGraphDialog::loadProfileGraphs()
{
    if (iog_uat_) return;

    iog_uat_ = uat_new("I/O Graphs",
                       sizeof(io_graph_settings_t),
                       "io_graphs",
                       TRUE,
                       &iog_settings_,
                       &num_io_graphs_,
                       0, /* doesn't affect anything that requires a GUI update */
                       "ChStatIOGraphs",
                       io_graph_copy_cb,
                       NULL,
                       io_graph_free_cb,
                       NULL,
                       io_graph_fields);
    char* err = NULL;
    if (!uat_load(iog_uat_, &err)) {
        /* XXX - report the error */
        g_free(err);
    }
}

// Slots

void IOGraphDialog::on_intervalComboBox_currentIndexChanged(int)
{
    int interval = ui->intervalComboBox->itemData(ui->intervalComboBox->currentIndex()).toInt();
    bool need_retap = false;

    for (int i = 0; i < ui->graphTreeWidget->topLevelItemCount(); i++) {
        QTreeWidgetItem *item = ui->graphTreeWidget->topLevelItem(i);
        IOGraph *iog = NULL;
        if (item) {
            iog = item->data(name_col_, Qt::UserRole).value<IOGraph *>();
            if (iog) {
                iog->setInterval(interval);
                if (iog->visible()) {
                    need_retap = true;
                }
            }
        }
    }

    if (need_retap) {
        scheduleRetap(true);
    }

    updateLegend();
}

void IOGraphDialog::on_todCheckBox_toggled(bool checked)
{
    double orig_start = start_time_;
    bool orig_auto = auto_axes_;

    ui->ioPlot->xAxis->setTickLabelType(checked ? QCPAxis::ltDateTime : QCPAxis::ltNumber);
    auto_axes_ = false;
    scheduleRecalc(true);
    auto_axes_ = orig_auto;
    getGraphInfo();
    ui->ioPlot->xAxis->moveRange(start_time_ - orig_start);
    mouseMoved(NULL); // Update hint
}

void IOGraphDialog::on_graphTreeWidget_currentItemChanged(QTreeWidgetItem *, QTreeWidgetItem *previous)
{
    if (previous && ui->graphTreeWidget->itemWidget(previous, name_col_)) {
        itemEditingFinished(previous);
    }
}

// XXX It might be more correct to create a custom item delegate for editing
// an item, but that appears to only allow one editor widget at a time. Adding
// editors for every column is *much* more convenient since it lets the user
// move from item to item with a single mouse click or by tabbing.
void IOGraphDialog::on_graphTreeWidget_itemActivated(QTreeWidgetItem *item, int column)
{
    if (!item || name_line_edit_) return;

    QWidget *editor = NULL;
    int cur_idx;

    name_line_edit_ = new QLineEdit();
    name_line_edit_->setText(item->text(name_col_));

    dfilter_line_edit_ = new DisplayFilterEdit();
    connect(dfilter_line_edit_, SIGNAL(textChanged(QString)),
            dfilter_line_edit_, SLOT(checkDisplayFilter(QString)));
    dfilter_line_edit_->setText(item->text(dfilter_col_));

    color_combo_box_ = new QComboBox();
    cur_idx = item->data(color_col_, Qt::UserRole).toInt();
    for (int i = 0; i < colors_.size(); i++) {
        color_combo_box_->addItem(QString());
        color_combo_box_->setItemIcon(i, graphColorIcon(i));
        if (i == cur_idx) {
            color_combo_box_->setCurrentIndex(i);
        }
    }
    item->setIcon(color_col_, QIcon());
    color_combo_box_->setFocusPolicy(Qt::StrongFocus);

#ifdef Q_OS_WIN
    // QTBUG-3097
    color_combo_box_->view()->setMinimumWidth(
        style()->pixelMetric(QStyle::PM_ListViewIconSize) + // Not entirely correct but close enough.
        style()->pixelMetric(QStyle::PM_ScrollBarExtent));
#endif

    style_combo_box_ = new QComboBox();
    cur_idx = item->data(style_col_, Qt::UserRole).toInt();
    for (int i = 0; i < plot_style_to_name_.size(); i++) {
        IOGraph::PlotStyles ps = plot_style_to_name_.keys()[i];
        style_combo_box_->addItem(plot_style_to_name_[ps], ps);
        if (ps == cur_idx) {
            style_combo_box_->setCurrentIndex(i);
        }
    }
    style_combo_box_->setFocusPolicy(Qt::StrongFocus);

    yaxis_combo_box_ = new QComboBox();
    cur_idx = item->data(yaxis_col_, Qt::UserRole).toInt();
    for (int i = 0; i < value_unit_to_name_.size(); i++) {
        io_graph_item_unit_t vu = value_unit_to_name_.keys()[i];
        yaxis_combo_box_->addItem(value_unit_to_name_[vu], vu);
        if (vu == cur_idx) {
            yaxis_combo_box_->setCurrentIndex(i);
        }
    }
    yaxis_combo_box_->setFocusPolicy(Qt::StrongFocus);

    yfield_line_edit_ = new FieldFilterEdit();
    connect(yfield_line_edit_, SIGNAL(textChanged(QString)),
            yfield_line_edit_, SLOT(checkFieldName(QString)));
    yfield_line_edit_->setText(item->text(yfield_col_));

    sma_combo_box_ = new QComboBox();
    cur_idx = item->data(sma_period_col_, Qt::UserRole).toInt();
    for (int i = 0; i < moving_average_to_name_.size(); i++) {
        int sma = moving_average_to_name_.keys()[i];
        sma_combo_box_->addItem(moving_average_to_name_[sma], sma);
        if (sma == cur_idx) {
            sma_combo_box_->setCurrentIndex(i);
        }
    }
    sma_combo_box_->setFocusPolicy(Qt::StrongFocus);

    switch (column) {
    case name_col_:
        editor = name_line_edit_;
        name_line_edit_->selectAll();
        break;
    case dfilter_col_:
        editor = dfilter_line_edit_;
        dfilter_line_edit_->selectAll();
        break;
    case color_col_:
    {
        editor = color_combo_box_;
        break;
    }
    case style_col_:
    {
        editor = style_combo_box_;
        break;
    }
    case yaxis_col_:
    {
        editor = yaxis_combo_box_;
        break;
    }
    case yfield_col_:
        editor = yfield_line_edit_;
        yfield_line_edit_->selectAll();
        break;
    case sma_period_col_:
    {
        editor = sma_combo_box_;
        break;
    }
    default:
        return;
    }

    QList<QWidget *>editors = QList<QWidget *>() << name_line_edit_ << dfilter_line_edit_ <<
                                                  color_combo_box_ << style_combo_box_ <<
                                                  yaxis_combo_box_ << yfield_line_edit_ <<
                                                  sma_combo_box_;
    int cur_col = name_col_;
    QWidget *prev_widget = ui->graphTreeWidget;
    foreach (QWidget *editor, editors) {
        QFrame *edit_frame = new QFrame();
        QHBoxLayout *hb = new QHBoxLayout();
        QSpacerItem *spacer = new QSpacerItem(5, 10);

        hb->addWidget(editor, 0);
        hb->addSpacerItem(spacer);
        hb->setStretch(1, 1);
        hb->setContentsMargins(0, 0, 0, 0);

        edit_frame->setLineWidth(0);
        edit_frame->setFrameStyle(QFrame::NoFrame);
        edit_frame->setLayout(hb);
        ui->graphTreeWidget->setItemWidget(item, cur_col, edit_frame);
        setTabOrder(prev_widget, editor);
        prev_widget = editor;
        cur_col++;
    }

//    setTabOrder(prev_widget, ui->graphTreeWidget);
    editor->setFocus();
}

void IOGraphDialog::on_graphTreeWidget_itemSelectionChanged()
{
    if (ui->graphTreeWidget->selectedItems().length() > 0) {
        ui->deleteToolButton->setEnabled(true);
        ui->copyToolButton->setEnabled(true);
    } else {
        ui->deleteToolButton->setEnabled(false);
        ui->copyToolButton->setEnabled(false);
    }
}

void IOGraphDialog::on_graphTreeWidget_itemChanged(QTreeWidgetItem *item, int column)
{
    if (!item) {
        return;
    }

    if (column == name_col_ && !name_line_edit_) {
        syncGraphSettings(item);
    }

}

void IOGraphDialog::on_resetButton_clicked()
{
    resetAxes();
}

void IOGraphDialog::on_newToolButton_clicked()
{
    addGraph();
}

void IOGraphDialog::on_deleteToolButton_clicked()
{
    QTreeWidgetItem *item = ui->graphTreeWidget->currentItem();
    if (!item) return;

    IOGraph *iog = qvariant_cast<IOGraph *>(item->data(name_col_, Qt::UserRole));
    delete iog;

    delete item;

    // We should probably be smarter about this.
    hint_err_.clear();
    mouseMoved(NULL);
}

void IOGraphDialog::on_copyToolButton_clicked()
{
    addGraph(true);
}

void IOGraphDialog::on_dragRadioButton_toggled(bool checked)
{
    if (checked) mouse_drags_ = true;
    ui->ioPlot->setInteractions(
                QCP::iRangeDrag |
                QCP::iRangeZoom
                );
}

void IOGraphDialog::on_zoomRadioButton_toggled(bool checked)
{
    if (checked) mouse_drags_ = false;
    ui->ioPlot->setInteractions(0);
}

void IOGraphDialog::on_logCheckBox_toggled(bool checked)
{
    QCustomPlot *iop = ui->ioPlot;

    iop->yAxis->setScaleType(checked ? QCPAxis::stLogarithmic : QCPAxis::stLinear);
    iop->replot();
}

void IOGraphDialog::on_actionReset_triggered()
{
    on_resetButton_clicked();
}

void IOGraphDialog::on_actionZoomIn_triggered()
{
    zoomAxes(true);
}

void IOGraphDialog::on_actionZoomInX_triggered()
{
    zoomXAxis(true);
}

void IOGraphDialog::on_actionZoomInY_triggered()
{
    zoomYAxis(true);
}

void IOGraphDialog::on_actionZoomOut_triggered()
{
    zoomAxes(false);
}

void IOGraphDialog::on_actionZoomOutX_triggered()
{
    zoomXAxis(false);
}

void IOGraphDialog::on_actionZoomOutY_triggered()
{
    zoomYAxis(false);
}

void IOGraphDialog::on_actionMoveUp10_triggered()
{
    panAxes(0, 10);
}

void IOGraphDialog::on_actionMoveLeft10_triggered()
{
    panAxes(-10, 0);
}

void IOGraphDialog::on_actionMoveRight10_triggered()
{
    panAxes(10, 0);
}

void IOGraphDialog::on_actionMoveDown10_triggered()
{
    panAxes(0, -10);
}

void IOGraphDialog::on_actionMoveUp1_triggered()
{
    panAxes(0, 1);
}

void IOGraphDialog::on_actionMoveLeft1_triggered()
{
    panAxes(-1, 0);
}

void IOGraphDialog::on_actionMoveRight1_triggered()
{
    panAxes(1, 0);
}

void IOGraphDialog::on_actionMoveDown1_triggered()
{
    panAxes(0, -1);
}

void IOGraphDialog::on_actionGoToPacket_triggered()
{
    if (tracer_->visible() && !file_closed_ && packet_num_ > 0) {
        emit goToPacket(packet_num_);
    }
}

void IOGraphDialog::on_actionDragZoom_triggered()
{
    if (mouse_drags_) {
        ui->zoomRadioButton->toggle();
    } else {
        ui->dragRadioButton->toggle();
    }
}

void IOGraphDialog::on_actionToggleTimeOrigin_triggered()
{

}

void IOGraphDialog::on_actionCrosshairs_triggered()
{

}

void IOGraphDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_STATS_IO_GRAPH_DIALOG);
}

// XXX - Copied from tcp_stream_dialog. This should be common code.
void IOGraphDialog::on_buttonBox_accepted()
{
    QString file_name, extension;
    QDir path(wsApp->lastOpenDir());
    QString pdf_filter = tr("Portable Document Format (*.pdf)");
    QString png_filter = tr("Portable Network Graphics (*.png)");
    QString bmp_filter = tr("Windows Bitmap (*.bmp)");
    // Gaze upon my beautiful graph with lossy artifacts!
    QString jpeg_filter = tr("JPEG File Interchange Format (*.jpeg *.jpg)");
    QString csv_filter = tr("Comma Separated Values (*.csv)");
    QString filter = QString("%1;;%2;;%3;;%4;;%5")
            .arg(pdf_filter)
            .arg(png_filter)
            .arg(bmp_filter)
            .arg(jpeg_filter)
            .arg(csv_filter);

    QString save_file = path.canonicalPath();
    if (!file_closed_) {
        save_file += QString("/%1").arg(cap_file_.fileTitle());
    }
    file_name = QFileDialog::getSaveFileName(this, wsApp->windowTitleString(tr("Save Graph As" UTF8_HORIZONTAL_ELLIPSIS)),
                                             save_file, filter, &extension);

    if (file_name.length() > 0) {
        bool save_ok = false;
        if (extension.compare(pdf_filter) == 0) {
            save_ok = ui->ioPlot->savePdf(file_name);
        } else if (extension.compare(png_filter) == 0) {
            save_ok = ui->ioPlot->savePng(file_name);
        } else if (extension.compare(bmp_filter) == 0) {
            save_ok = ui->ioPlot->saveBmp(file_name);
        } else if (extension.compare(jpeg_filter) == 0) {
            save_ok = ui->ioPlot->saveJpg(file_name);
        } else if (extension.compare(csv_filter) == 0) {
            save_ok = saveCsv(file_name);
        }
        // else error dialog?
        if (save_ok) {
            path = QDir(file_name);
            wsApp->setLastOpenDir(path.canonicalPath().toUtf8().constData());
        }
    }
}

void IOGraphDialog::makeCsv(QTextStream &stream) const
{
    QList<IOGraph *> activeGraphs;

    int ui_interval = ui->intervalComboBox->itemData(ui->intervalComboBox->currentIndex()).toInt();
    int max_interval = 0;

    stream << "\"Interval start\"";
    for (int i = 0; i < ui->graphTreeWidget->topLevelItemCount(); i++) {
        QTreeWidgetItem *ti = ui->graphTreeWidget->topLevelItem(i);
        if (ti && ti->checkState(name_col_) == Qt::Checked) {
            IOGraph *iog = ti->data(name_col_, Qt::UserRole).value<IOGraph *>();
            activeGraphs.append(iog);
            if (max_interval < iog->maxInterval()) {
                max_interval = iog->maxInterval();
            }
            QString name = iog->name().toUtf8();
            name = QString("\"%1\"").arg(name.replace("\"", "\"\""));  // RFC 4180
            stream << "," << name;
        }
    }
    stream << endl;

    for (int interval = 0; interval <= max_interval; interval++) {
        double interval_start = (double)interval * ((double)ui_interval / 1000.0);
        stream << interval_start;
        foreach (IOGraph *iog, activeGraphs) {
            double value = 0.0;
            if (interval <= iog->maxInterval()) {
                value = iog->getItemValue(interval, cap_file_.capFile());
            }
            stream << "," << value;
        }
        stream << endl;
    }
}

void IOGraphDialog::copyAsCsvClicked()
{
    QString csv;
    QTextStream stream(&csv, QIODevice::Text);
    makeCsv(stream);
    wsApp->clipboard()->setText(stream.readAll());
}

bool IOGraphDialog::saveCsv(const QString &file_name) const
{
    QFile save_file(file_name);
    save_file.open(QFile::WriteOnly);
    QTextStream out(&save_file);
    makeCsv(out);

    return true;
}

// IOGraph

IOGraph::IOGraph(QCustomPlot *parent) :
    parent_(parent),
    visible_(false),
    graph_(NULL),
    bars_(NULL),
    hf_index_(-1),
    cur_idx_(-1)
{
    Q_ASSERT(parent_ != NULL);
    graph_ = parent_->addGraph(parent_->xAxis, parent_->yAxis);
    Q_ASSERT(graph_ != NULL);

    GString *error_string;
    error_string = register_tap_listener("frame",
                          this,
                          "",
                          TL_REQUIRES_PROTO_TREE,
                          tapReset,
                          tapPacket,
                          tapDraw);
    if (error_string) {
//        QMessageBox::critical(this, tr("%1 failed to register tap listener").arg(name_),
//                             error_string->str);
        g_string_free(error_string, TRUE);
    }

    setFilter(QString());
}

IOGraph::~IOGraph() {
    remove_tap_listener(this);
    if (graph_) {
        parent_->removeGraph(graph_);
    }
    if (bars_) {
        parent_->removePlottable(bars_);
    }
}

// Construct a full filter string from the display filter and value unit / Y axis.
// Check for errors and sets config_err_ if any are found.
void IOGraph::setFilter(const QString &filter)
{
    GString *error_string;
    QString full_filter(filter.trimmed());

    config_err_.clear();

    // Make sure we have a good display filter
    if (!full_filter.isEmpty()) {
        dfilter_t *dfilter;
        bool status;
        gchar *err_msg;
        status = dfilter_compile(full_filter.toUtf8().constData(), &dfilter, &err_msg);
        dfilter_free(dfilter);
        if (!status) {
            config_err_ = QString::fromUtf8(err_msg);
            g_free(err_msg);
            filter_ = full_filter;
            return;
        }
    }

    // Check our value unit + field combo.
    error_string = check_field_unit(vu_field_.toUtf8().constData(), NULL, val_units_);
    if (error_string) {
        config_err_ = error_string->str;
        g_string_free(error_string, TRUE);
        return;
    }

    // Make sure vu_field_ survives edt tree pruning by adding it to our filter
    // expression.
    if (val_units_ >= IOG_ITEM_UNIT_CALC_SUM && !vu_field_.isEmpty() && hf_index_ >= 0) {
        if (full_filter.isEmpty()) {
            full_filter = vu_field_;
        } else {
            full_filter += QString(" && (%1)").arg(vu_field_);
        }
    }

    error_string = set_tap_dfilter(this, full_filter.toUtf8().constData());
    if (error_string) {
        config_err_ = error_string->str;
        g_string_free(error_string, TRUE);
        return;
    } else {
        if (filter_.compare(filter) && visible_) {
            emit requestRetap();
        }
        filter_ = filter;
    }
}

void IOGraph::applyCurrentColor()
{
    if (graph_) {
        graph_->setPen(QPen(color_, graph_line_width_));
    } else if (bars_) {
        bars_->setPen(QPen(QBrush(ColorUtils::graphColor(0)), graph_line_width_)); // ...or omit it altogether?
        bars_->setBrush(color_);
    }
}

void IOGraph::setVisible(bool visible)
{
    bool old_visibility = visible_;
    visible_ = visible;
    if (graph_) {
        graph_->setVisible(visible_);
    }
    if (bars_) {
        bars_->setVisible(visible_);
    }
    if (old_visibility != visible_) {
        emit requestReplot();
    }
}

void IOGraph::setName(const QString &name)
{
    name_ = name;
    if (graph_) {
        graph_->setName(name_);
    }
    if (bars_) {
        bars_->setName(name_);
    }
}

QRgb IOGraph::color()
{
    return color_.color().rgb();
}

void IOGraph::setColor(const QRgb color)
{
    color_ = QBrush(color);
    applyCurrentColor();
}

void IOGraph::setPlotStyle(int style)
{
    // Switch plottable if needed
    switch (style) {
    case psBar:
    case psStackedBar:
        if (graph_) {
            bars_ = new QCPBars(parent_->xAxis, parent_->yAxis);
            parent_->addPlottable(bars_);
            parent_->removeGraph(graph_);
            graph_ = NULL;
        }
        break;
    default:
        if (bars_) {
            graph_ = parent_->addGraph(parent_->xAxis, parent_->yAxis);
            parent_->removePlottable(bars_);
            bars_ = NULL;
        }
        break;
    }
    setValueUnits(val_units_);

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
    case psBar:
    case IOGraph::psStackedBar:
        // Stacking set in scanGraphs
        bars_->moveBelow(NULL);
        break;
    }

    setName(name_);
    applyCurrentColor();
}

const QString IOGraph::valueUnitLabel()
{
    if (val_units_ >= IOG_ITEM_UNIT_FIRST && val_units_ <= IOG_ITEM_UNIT_LAST) {
        return value_unit_to_name_[val_units_];
    }
    return tr("Unknown");
}

void IOGraph::setValueUnits(int val_units)
{
    if (val_units >= IOG_ITEM_UNIT_FIRST && val_units <= IOG_ITEM_UNIT_LAST) {
        int old_val_units = val_units_;
        val_units_ = (io_graph_item_unit_t)val_units;

        if (old_val_units != val_units) {
            setFilter(filter_); // Check config & prime vu field
            if (val_units < IOG_ITEM_UNIT_CALC_SUM) {
                emit requestRecalc();
            }
        }
    }
}

void IOGraph::setValueUnitField(const QString &vu_field)
{
    int old_hf_index = hf_index_;

    vu_field_ = vu_field.trimmed();
    hf_index_ = -1;

    header_field_info *hfi = proto_registrar_get_byname(vu_field_.toUtf8().constData());
    if (hfi) {
        hf_index_ = hfi->id;
    }

    if (old_hf_index != hf_index_) {
        setFilter(filter_); // Check config & prime vu field
    }
}

bool IOGraph::addToLegend()
{
    if (graph_) {
        return graph_->addToLegend();
    }
    if (bars_) {
        return bars_->addToLegend();
    }
    return false;
}

bool IOGraph::removeFromLegend()
{
    if (graph_) {
        return graph_->removeFromLegend();
    }
    if (bars_) {
        return bars_->removeFromLegend();
    }
    return false;
}

double IOGraph::startOffset()
{
    if (graph_ && graph_->keyAxis()->tickLabelType() == QCPAxis::ltDateTime && graph_->data()->size() > 0) {
        return graph_->data()->keys()[0];
    }
    if (bars_ && bars_->keyAxis()->tickLabelType() == QCPAxis::ltDateTime && bars_->data()->size() > 0) {
        return bars_->data()->keys()[0];
    }
    return 0.0;
}

int IOGraph::packetFromTime(double ts)
{
    int idx = ts * 1000 / interval_;
    if (idx >= 0 && idx < (int) cur_idx_) {
        return items_[idx].last_frame_in_invl;
    }
    return -1;
}

void IOGraph::clearAllData()
{
    cur_idx_ = -1;
    reset_io_graph_items(items_, max_io_items_);
    if (graph_) {
        graph_->clearData();
    }
    if (bars_) {
        bars_->clearData();
    }
    start_time_ = 0.0;
}

QMap<io_graph_item_unit_t, QString> IOGraph::valueUnitsToNames()
{
    QMap<io_graph_item_unit_t, QString> vuton;

    vuton[IOG_ITEM_UNIT_PACKETS] = QObject::tr("Packets");
    vuton[IOG_ITEM_UNIT_BYTES] = QObject::tr("Bytes");
    vuton[IOG_ITEM_UNIT_BITS] = QObject::tr("Bits");
    vuton[IOG_ITEM_UNIT_CALC_SUM] = QObject::tr("SUM(Y Field)");
    vuton[IOG_ITEM_UNIT_CALC_FRAMES] = QObject::tr("COUNT FRAMES(Y Field)");
    vuton[IOG_ITEM_UNIT_CALC_FIELDS] = QObject::tr("COUNT FIELDS(Y Field)");
    vuton[IOG_ITEM_UNIT_CALC_MAX] = QObject::tr("MAX(Y Field)");
    vuton[IOG_ITEM_UNIT_CALC_MIN] = QObject::tr("MIN(Y Field)");
    vuton[IOG_ITEM_UNIT_CALC_AVERAGE] = QObject::tr("AVG(Y Field)");
    vuton[IOG_ITEM_UNIT_CALC_LOAD] = QObject::tr("LOAD(Y Field)");

    return vuton;
}

QMap<IOGraph::PlotStyles, QString> IOGraph::plotStylesToNames()
{
    QMap<IOGraph::PlotStyles, QString> pston;

    pston[psLine] = QObject::tr("Line");
    pston[psImpulse] = QObject::tr("Impulse");
    pston[psBar] = QObject::tr("Bar");
    pston[psStackedBar] = QObject::tr("Stacked Bar");
    pston[psDot] = QObject::tr("Dot");
    pston[psSquare] = QObject::tr("Square");
    pston[psDiamond] = QObject::tr("Diamond");

    return pston;
}

QMap<int, QString> IOGraph::movingAveragesToNames()
{
    QMap<int, QString> maton;
    QList<int> averages = QList<int>()
            /* << 8 */ << 10 /* << 16 */ << 20 << 50 << 100 << 200 << 500 << 1000; // Arbitrarily chosen

    maton[0] = QObject::tr("None");
    foreach (int avg, averages) {
        maton[avg] = QString(QObject::tr("%1 interval SMA")).arg(avg);
    }

    return maton;
}

void IOGraph::recalcGraphData(capture_file *cap_file)
{
    /* Moving average variables */
    unsigned int mavg_in_average_count = 0, mavg_left = 0, mavg_right = 0;
    unsigned int mavg_to_remove = 0, mavg_to_add = 0;
    double mavg_cumulated = 0;
    QCPAxis *x_axis = NULL;

    if (graph_) {
        graph_->clearData();
        x_axis = graph_->keyAxis();
    }
    if (bars_) {
        bars_->clearData();
        x_axis = bars_->keyAxis();
    }

    if (moving_avg_period_ > 0 && cur_idx_ >= 0) {
        /* "Warm-up phase" - calculate average on some data not displayed;
         * just to make sure average on leftmost and rightmost displayed
         * values is as reliable as possible
         */
        guint64 warmup_interval = 0;

//        for (; warmup_interval < first_interval; warmup_interval += interval_) {
//            mavg_cumulated += get_it_value(io, i, (int)warmup_interval/interval_);
//            mavg_in_average_count++;
//            mavg_left++;
//        }
        mavg_cumulated += getItemValue((int)warmup_interval/interval_, cap_file);
        mavg_in_average_count++;
        for (warmup_interval = interval_;
            ((warmup_interval < (0 + (moving_avg_period_ / 2) * (guint64)interval_)) &&
             (warmup_interval <= (cur_idx_ * (guint64)interval_)));
             warmup_interval += interval_) {

            mavg_cumulated += getItemValue((int)warmup_interval / interval_, cap_file);
            mavg_in_average_count++;
            mavg_right++;
        }
        mavg_to_add = warmup_interval;
    }

    for (int i = 0; i <= cur_idx_; i++) {
        double ts = (double) i * interval_ / 1000;
        if (x_axis && x_axis->tickLabelType() == QCPAxis::ltDateTime) {
            ts += start_time_;
        }
        double val = getItemValue(i, cap_file);

        if (moving_avg_period_ > 0) {
            if (i != 0) {
                mavg_left++;
                if (mavg_left > moving_avg_period_ / 2) {
                    mavg_left--;
                    mavg_in_average_count--;
                    mavg_cumulated -= getItemValue((int)mavg_to_remove / interval_, cap_file);
                    mavg_to_remove += interval_;
                }
                if (mavg_to_add <= (unsigned int) cur_idx_ * interval_) {
                    mavg_in_average_count++;
                    mavg_cumulated += getItemValue((int)mavg_to_add / interval_, cap_file);
                    mavg_to_add += interval_;
                } else {
                    mavg_right--;
                }
            }
            if (mavg_in_average_count > 0) {
                val = mavg_cumulated / mavg_in_average_count;
            }
        }

        if (graph_) {
            graph_->addData(ts, val);
        }
        if (bars_) {
            bars_->addData(ts, val);
        }
//        qDebug() << "=rgd i" << i << ts << val;
    }
    emit requestReplot();
}

void IOGraph::captureFileClosing()
{
    remove_tap_listener(this);
}

void IOGraph::reloadValueUnitField()
{
    if (vu_field_.length() > 0) {
        setValueUnitField(vu_field_);
    }
}

void IOGraph::setInterval(int interval)
{
    interval_ = interval;
}

// Get the value at the given interval (idx) for the current value unit.
// Adapted from get_it_value in gtk/io_stat.c.
double IOGraph::getItemValue(int idx, const capture_file *cap_file) const
{
    double     value = 0;          /* FIXME: loss of precision, visible on the graph for small values */
    int        adv_type;
    const io_graph_item_t *item;
    guint32    interval;

    g_assert(idx < max_io_items_);

    item = &items_[idx];

    // Basic units
    switch (val_units_) {
    case IOG_ITEM_UNIT_PACKETS:
        return item->frames;
    case IOG_ITEM_UNIT_BYTES:
        return item->bytes;
    case IOG_ITEM_UNIT_BITS:
        return (item->bytes * 8);
    case IOG_ITEM_UNIT_CALC_FRAMES:
        return item->frames;
    case IOG_ITEM_UNIT_CALC_FIELDS:
        return item->fields;
    default:
        /* If it's COUNT_TYPE_ADVANCED but not one of the
         * generic ones we'll get it when we switch on the
         * adv_type below. */
        break;
    }

    if (hf_index_ < 0) {
        return 0;
    }
    // Advanced units
    adv_type = proto_registrar_get_ftype(hf_index_);
    switch (adv_type) {
    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
    case FT_UINT64:
    case FT_INT8:
    case FT_INT16:
    case FT_INT24:
    case FT_INT32:
    case FT_INT64:
        switch (val_units_) {
        case IOG_ITEM_UNIT_CALC_SUM:
            value = item->int_tot;
            break;
        case IOG_ITEM_UNIT_CALC_MAX:
            value = item->int_max;
            break;
        case IOG_ITEM_UNIT_CALC_MIN:
            value = item->int_min;
            break;
        case IOG_ITEM_UNIT_CALC_AVERAGE:
            if (item->fields) {
                value = (double)item->int_tot / item->fields;
            } else {
                value = 0;
            }
            break;
        default:
            break;
        }
        break;
    case FT_FLOAT:
        switch (val_units_) {
        case IOG_ITEM_UNIT_CALC_SUM:
            value = (guint64)item->float_tot;
            break;
        case IOG_ITEM_UNIT_CALC_MAX:
            value = (guint64)item->float_max;
            break;
        case IOG_ITEM_UNIT_CALC_MIN:
            value = (guint64)item->float_min;
            break;
        case IOG_ITEM_UNIT_CALC_AVERAGE:
            if (item->fields) {
                value = (guint64)item->float_tot / item->fields;
            } else {
                value = 0;
            }
            break;
        default:
            break;
        }
        break;
    case FT_DOUBLE:
        switch (val_units_) {
        case IOG_ITEM_UNIT_CALC_SUM:
            value = (guint64)item->double_tot;
            break;
        case IOG_ITEM_UNIT_CALC_MAX:
            value = (guint64)item->double_max;
            break;
        case IOG_ITEM_UNIT_CALC_MIN:
            value = (guint64)item->double_min;
            break;
        case IOG_ITEM_UNIT_CALC_AVERAGE:
            if (item->fields) {
                value = (guint64)item->double_tot / item->fields;
            } else {
                value = 0;
            }
            break;
        default:
            break;
        }
        break;
    case FT_RELATIVE_TIME:
        switch (val_units_) {
        case IOG_ITEM_UNIT_CALC_MAX:
            value = (guint64) (item->time_max.secs*1000000 + item->time_max.nsecs/1000);
            break;
        case IOG_ITEM_UNIT_CALC_MIN:
            value = (guint64) (item->time_min.secs*1000000 + item->time_min.nsecs/1000);
            break;
        case IOG_ITEM_UNIT_CALC_SUM:
            value = (guint64) (item->time_tot.secs*1000000 + item->time_tot.nsecs/1000);
            break;
        case IOG_ITEM_UNIT_CALC_AVERAGE:
            if (item->fields) {
                guint64 t; /* time in us */

                t = item->time_tot.secs;
                t = t*1000000+item->time_tot.nsecs/1000;
                value = (guint64) (t/item->fields);
            } else {
                value = 0;
            }
            break;
        case IOG_ITEM_UNIT_CALC_LOAD:
            if (idx == (int)cur_idx_ && cap_file) {
                interval = (guint32)((cap_file->elapsed_time.secs*1000) +
                       ((cap_file->elapsed_time.nsecs+500000)/1000000));
                interval -= (interval_ * idx);
            } else {
                interval = interval_;
            }
            value = (guint64) ((item->time_tot.secs*1000000 + item->time_tot.nsecs/1000) / interval);
            break;
        default:
            break;
        }
        break;
    default:
        break;
    }
    return value;
}

// "tap_reset" callback for register_tap_listener
void IOGraph::tapReset(void *iog_ptr)
{
    IOGraph *iog = static_cast<IOGraph *>(iog_ptr);
    if (!iog) return;

//    qDebug() << "=tapReset" << iog->name_;
    iog->clearAllData();
}

// "tap_packet" callback for register_tap_listener
gboolean IOGraph::tapPacket(void *iog_ptr, packet_info *pinfo, epan_dissect_t *edt, const void *)
{
    IOGraph *iog = static_cast<IOGraph *>(iog_ptr);
    if (!pinfo || !iog) {
        return FALSE;
    }

    int idx = get_io_graph_index(pinfo, iog->interval_);
    bool recalc = false;

    /* some sanity checks */
    if ((idx < 0) || (idx >= max_io_items_)) {
        iog->cur_idx_ = max_io_items_ - 1;
        return FALSE;
    }

    /* update num_items */
    if (idx > iog->cur_idx_) {
        iog->cur_idx_ = (guint32) idx;
        recalc = true;
    }

    /* set start time */
    if (iog->start_time_ == 0.0) {
        nstime_t start_nstime;
        nstime_set_zero(&start_nstime);
        nstime_delta(&start_nstime, &pinfo->abs_ts, &pinfo->rel_ts);
        iog->start_time_ = nstime_to_sec(&start_nstime);
    }

    epan_dissect_t *adv_edt = NULL;
    /* For ADVANCED mode we need to keep track of some more stuff than just frame and byte counts */
    if (iog->val_units_ >= IOG_ITEM_UNIT_CALC_SUM) {
        adv_edt = edt;
    }

    if (!update_io_graph_item(iog->items_, idx, pinfo, adv_edt, iog->hf_index_, iog->val_units_, iog->interval_)) {
        return FALSE;
    }

//    qDebug() << "=tapPacket" << iog->name_ << idx << iog->hf_index_ << iog->val_units_ << iog->num_items_;

    if (recalc) {
        emit iog->requestRecalc();
    }
    return TRUE;
}

// "tap_draw" callback for register_tap_listener
void IOGraph::tapDraw(void *iog_ptr)
{
    IOGraph *iog = static_cast<IOGraph *>(iog_ptr);
    if (!iog) return;
    emit iog->requestRecalc();

    if (iog->graph_) {
//        qDebug() << "=tapDraw g" << iog->name_ << iog->graph_->data()->keys().size();
    }
    if (iog->bars_) {
//        qDebug() << "=tapDraw b" << iog->name_ << iog->bars_->data()->keys().size();
    }
}

// Stat command + args

static void
io_graph_init(const char *, void*) {
    wsApp->emitStatCommandSignal("IOGraph", NULL, NULL);
}

static stat_tap_ui io_stat_ui = {
    REGISTER_STAT_GROUP_GENERIC,
    NULL,
    "io,stat",
    io_graph_init,
    0,
    NULL
};

extern "C" {
void
register_tap_listener_qt_iostat(void)
{
    register_stat_tap_ui(&io_stat_ui, NULL);
}
}

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
