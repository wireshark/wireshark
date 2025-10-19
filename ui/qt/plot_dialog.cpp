/* plot_dialog.cpp
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

#define WS_LOG_DOMAIN LOG_DOMAIN_QTUI
#include "plot_dialog.h"
#include <ui_plot_dialog.h>

#include <epan/uat-int.h>

#include <app/application_flavor.h>
#include <wsutil/report_message.h>
#include <ui/preference_utils.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/color_utils.h>
#include <ui/qt/widgets/resize_header_view.h>

#include <ui/qt/widgets/qcp_spacer_legend_item.h>
#include <ui/qt/widgets/qcp_string_legend_item.h>
#include <ui/qt/widgets/copy_from_profile_button.h>
#include <ui/qt/widgets/wireshark_file_dialog.h>
#include <ui/qt/main_window.h>

#include "progress_frame.h"
#include "main_application.h"

#include <QPushButton>
#include <QRubberBand>
#include <QTimer>
#include <QVariant>

// XXX - Multiple UatModels with the same uat can crash if one is
// edited, because the underlying uat_t* data changes but the
// record_errors and dirty_records lists do not.
static QPointer<UatModel> static_uat_model_;
static uat_t* plot_uat_;
static plot_settings_t* plot_settings_;
static unsigned num_plots_;

static const char* plot_uat_defaults_[] = {
    "TRUE", 0, NULL, NULL, NULL, NULL, NULL, "1"
};

// Don't accidentally zoom into a 1x1 rect
static const int min_zoom_pixels_ = 20;
static const double pixel_pad = 10.0;   // per side
static const int stat_update_interval_ = 200;   // ms

#define MAX_PLOT_NUM    20

extern "C" {
    UAT_BOOL_CB_DEF(plot, enabled, plot_settings_t)
    UAT_DEC_CB_DEF(plot, group, plot_settings_t)
    UAT_CSTRING_CB_DEF(plot, name, plot_settings_t)
    UAT_DISPLAY_FILTER_CB_DEF(plot, dfilter, plot_settings_t)
    UAT_COLOR_CB_DEF(plot, color, plot_settings_t)
    UAT_VS_DEF(plot, style, plot_settings_t, uint32_t, 0, "Line")
    UAT_PROTO_FIELD_CB_DEF(plot, yfield, plot_settings_t)
    UAT_DBL_CB_DEF(plot, y_axis_factor, plot_settings_t)

    static uat_field_t plot_packet_fields[] = {
        UAT_FLD_BOOL(plot, enabled, "Enabled", "Graph visibility"),
        UAT_FLD_DEC(plot, group, "Group #", "Which group the plot belongs to"),
        UAT_FLD_CSTRING(plot, name, "Plot Name", "The name of the plot"),
        UAT_FLD_DISPLAY_FILTER(plot, dfilter, "Display Filter", "Plot packets matching this display filter"),
        UAT_FLD_COLOR(plot, color, "Color", "Plot color (#RRGGBB)"),
        UAT_FLD_VS(plot, style, "Style", plot_graph_style_vs, "Plot style"),
        UAT_FLD_PROTO_FIELD(plot, yfield, "Y Field", "Field to plot"),
        UAT_FLD_DBL(plot, y_axis_factor, "Y Axis Factor", "Y Axis Factor"),

        UAT_END_FIELDS
    };

    static uat_field_t plot_event_fields[] = {
        UAT_FLD_BOOL(plot, enabled, "Enabled", "Graph visibility"),
        UAT_FLD_DEC(plot, group, "Group #", "Which group the plot belongs to"),
        UAT_FLD_CSTRING(plot, name, "Plot Name", "The name of the plot"),
        UAT_FLD_DISPLAY_FILTER(plot, dfilter, "Display Filter", "Plot events matching this display filter"),
        UAT_FLD_COLOR(plot, color, "Color", "Plot color (#RRGGBB)"),
        UAT_FLD_VS(plot, style, "Style", plot_graph_style_vs, "Plot style"),
        UAT_FLD_PROTO_FIELD(plot, yfield, "Y Field", "Field to plot"),
        UAT_FLD_DBL(plot, y_axis_factor, "Y Axis Factor", "Y Axis Factor"),

        UAT_END_FIELDS
    };

    static void* plot_copy_cb(void* dst_ptr, const void* src_ptr, size_t) {
        plot_settings_t* dst = (plot_settings_t*)dst_ptr;
        const plot_settings_t* src = (const plot_settings_t*)src_ptr;

        dst->enabled = src->enabled;
        dst->group = src->group;
        dst->name = g_strdup(src->name);
        dst->dfilter = g_strdup(src->dfilter);
        dst->color = src->color;
        dst->style = src->style;
        dst->yfield = g_strdup(src->yfield);
        dst->y_axis_factor = src->y_axis_factor;

        return dst;
    }

    static bool plot_update_cb(void* p, char** err) {
        plot_settings_t* plot = (plot_settings_t*)p;
        if (plot->group < 1 || plot->group > MAX_PLOT_NUM) {
            *err = ws_strdup_printf("Please enter a plot number between 1 and %u. You entered %u", MAX_PLOT_NUM, plot->group);
            return false;
        }

        return true;
    }

    static void plot_free_cb(void* p) {
        plot_settings_t* plot = (plot_settings_t*)p;
        g_free(plot->name);
        g_free(plot->dfilter);
        g_free(plot->yfield);
    }

    // If the uat changes outside the model, e.g. when changing profiles,
    // we need to tell the UatModel.
    static void plot_post_update_cb() {
        if (static_uat_model_) {
            static_uat_model_->reloadUat();
        }
    }
} // extern "C"

PlotDialog::PlotDialog(QWidget& parent, CaptureFile& cf, bool show_default) :
    WiresharkDialog(parent, cf),
    ui(new Ui::PlotDialog),
    uat_model_(nullptr),
    uat_delegate_(nullptr),
    base_graph_(nullptr),
    start_time_(qQNaN()),
    legend_alignment_(Qt::AlignTop | Qt::AlignRight),
    need_replot_(false),
    need_recalc_(false),
    need_retap_(false),
    auto_axes_(true),
    abs_time_(false),
    last_right_clicked_pos_(0.0)
{
    ui->setupUi(this);
    ui->hintLabel->setSmallText();
    loadGeometry();

    setWindowSubtitle(tr("Plots"));
    setAttribute(Qt::WA_DeleteOnClose, true);

    ui->newToolButton->setStockIcon("list-add");
    ui->deleteToolButton->setStockIcon("list-remove");
    ui->copyToolButton->setStockIcon("list-copy");
    ui->clearToolButton->setStockIcon("list-clear");
    ui->moveUpwardsToolButton->setStockIcon("list-move-up");
    ui->moveDownwardsToolButton->setStockIcon("list-move-down");

#ifdef Q_OS_MAC
    ui->newToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->deleteToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->copyToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->clearToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->moveUpwardsToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->moveDownwardsToolButton->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    QPushButton* save_bt = ui->rightButtonBox->button(QDialogButtonBox::Save);
    if (save_bt) save_bt->setText(tr("Save As…"));

    copy_bt_ = ui->rightButtonBox->addButton(tr("Copy"), QDialogButtonBox::ActionRole);
    connect(copy_bt_, SIGNAL(clicked()), this, SLOT(copyAsCsvClicked()));

    copy_profile_bt_ = new CopyFromProfileButton(this, "plots", tr("Copy plots from another profile."));
    ui->rightButtonBox->addButton(copy_profile_bt_, QDialogButtonBox::ActionRole);
    connect(copy_profile_bt_, &CopyFromProfileButton::copyProfile, this, &PlotDialog::copyFromProfile);

    QPushButton* close_bt = ui->rightButtonBox->button(QDialogButtonBox::Close);
    if (close_bt) close_bt->setDefault(true);

    ui->automaticUpdateCheckBox->setChecked(prefs.gui_plot_automatic_update);
    ui->actionLegend->setChecked(prefs.gui_plot_enable_legend);
    ui->actionAutoScroll->setChecked(prefs.gui_plot_enable_auto_scroll);

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
    ctx_menu_.addAction(ui->actionToggleTimeOrigin);
    ctx_menu_.addAction(ui->actionLogScale);
    ctx_menu_.addAction(ui->actionCrosshairs);
    ctx_menu_.addAction(ui->actionTopAxis);
    ctx_menu_.addAction(ui->actionEnableMultiYAxes);
    ctx_menu_.addAction(ui->actionAutoScroll);
    ctx_menu_.addAction(ui->actionLegend);
    QMenu* markerMenu = new QMenu(tr("Markers"), &ctx_menu_);
    markerMenu->addAction(ui->actionAddMarker);
    markerMenu->addAction(ui->actionMoveMarker);
    markerMenu->addAction(ui->actionShowPosMarker);
    markerMenu->addAction(ui->actionShowMarkersDifference);
    markerMenu->addAction(ui->actionShowDataPointMarker);
    markerMenu->addAction(ui->actionDeleteMarker);
    markerMenu->addAction(ui->actionDeleteAllMarkers);
    ctx_menu_.addMenu(markerMenu);
    set_action_shortcuts_visible_in_context_menu(ctx_menu_.actions());

    // Let's try to explain the layout of this QCustomPlot.
    // First of all, we have two degenerate plots that are always kept at the
    // top and at the bottom. They only feature the top and bottom x axes
    // respectively, and they are always at index 0 and axisRectCount() - 1.
    // This is a workaround to avoid plots of different sizes when keeping the
    // top and bottom axes on only one of them, as described here:
    // https://www.qcustomplot.com/index.php/support/forum/2770
    // Then we have one or more "real" plots. We always keep at least one plot,
    // even if it's empty. They have their tick labels removed, and top and
    // bottom margins set to 0, in order to leave zero gap between them.
    // A margin group keeps the left and right side of each plot aligned, and
    // all the x axes are connected to make them move and scale in sync.
    //
    // Side note: we use the default ticker for the x axes (QCPAxisTicker),
    // but QCPAxisTickerTime would be more appropriate. Unfortunately, it only
    // has millisecond precision.
    QCustomPlot* plot = ui->plot;
    plot->setEnabled(true);
    plot->setMouseTracking(true);
    plot->setInteractions(QCP::iRangeDrag | QCP::iRangeZoom);
    plot->setContextMenuPolicy(Qt::PreventContextMenu); // We handle right clicks manually
    plot->plotLayout()->setRowSpacing(0);
    plot->plotLayout()->setFillOrder(QCPLayoutGrid::FillOrder::foRowsFirst, false);

    margin_group_ = new QCPMarginGroup(plot);

    // Step 1: Hide the axes we don't need from the default plot.
    plot->xAxis->setVisible(false);
    plot->yAxis->setVisible(false);
    plot->yAxis2->setVisible(false);
    // Set the bottom margin to 0.
    plot->axisRect(0)->setAutoMargins(QCP::MarginSides(QCP::msAll).setFlag(QCP::msBottom, false));
    plot->axisRect(0)->setMargins(QMargins());
    plot->axisRect(0)->setBackground(QBrush(QColor::fromRgb(162, 210, 255)));
    // And make sure it uses as little vertical space as possible.
    plot->axisRect(0)->setMinimumSize(0, 0);
    plot->axisRect(0)->setMaximumSize(QWIDGETSIZE_MAX, 0);
    plot->axisRect(0)->setRangeZoom(Qt::Orientation::Horizontal);
    plot->axisRect(0)->setRangeDragAxes(NULL, NULL);
    // Add to margin group.
    plot->axisRect(0)->setMarginGroup(QCP::msLeft | QCP::msRight, margin_group_);
    // Make it visible, but leave the tick labels disabled.
    plot->xAxis2->setTickLabels(false);
    plot->xAxis2->setVisible(true);
    plot->xAxis2->setTicks(false);
    // We add the title for the entire plot as label to the top x axis, to use
    // the available space as best as we can (and to always have the number of
    // rows in the layout equal to the number of Axis Rects).
    if (application_flavor_is_wireshark()) {
        plot->xAxis2->setLabel(tr("Wireshark Plots: %1").arg(cap_file_.fileDisplayName()));
    } else {
        plot->xAxis2->setLabel(tr("Stratoshark Plots: %1").arg(cap_file_.fileDisplayName()));
    }

    // Step 2: Create the bottom "degenerate" plot, consisting only of the
    // bottom axis, and do the same as above.
    QCPAxisRect* axisRect = new QCPAxisRect(ui->plot, false);
    axisRect->setAutoMargins(QCP::MarginSides(QCP::msAll).setFlag(QCP::msTop, false));
    axisRect->setMargins(QMargins());
    axisRect->setMarginGroup(QCP::msLeft | QCP::msRight, margin_group_);
    axisRect->setMinimumSize(0, 0);
    axisRect->setMaximumSize(QWIDGETSIZE_MAX, 0);
    QCPAxis* bottomAxis = new QCPAxis(axisRect, QCPAxis::AxisType::atBottom);
    bottomAxis->setLayer("axes");
    bottomAxis->grid()->setLayer("grid");
    axisRect->addAxis(QCPAxis::AxisType::atBottom, bottomAxis);
    // Add it to the layout.
    ui->plot->plotLayout()->addElement(axisRect);
    // And set the x axis label
    updateXAxisLabel();

    // Step 3: Connect the top and bottom x axes, so that they move together.
    connect(plot->xAxis2, SIGNAL(rangeChanged(QCPRange)), bottomAxis, SLOT(setRange(QCPRange)));
    connect(bottomAxis, SIGNAL(rangeChanged(QCPRange)), plot->xAxis2, SLOT(setRange(QCPRange)));

    // Step 4: Create the default plot.
    getAxisRect(1);

    rubber_band_ = new QRubberBand(QRubberBand::Rectangle, plot);
    rubber_band_->setVisible(false);
    tracer_ = new QCPItemTracer(plot);

    loadProfileGraphs();
    if (uat_model_->rowCount() > 0) {
        for (int i = 0; i < uat_model_->rowCount(); i++) {
            createPlot(i);
        }
    }
    else if (show_default) {
        addDefaultPlot(true, false);
        addDefaultPlot(true, true);
    }

    updateLegendPos();
    on_actionCrosshairs_triggered(false);   // Set tracer style

    plot->setFocus();
    plot->rescaleAxes();

    ui->clearToolButton->setEnabled(uat_model_->rowCount() != 0);

    ui->splitter->setStretchFactor(0, 90);
    ui->splitter->setStretchFactor(1, 10);
    loadSplitterState(ui->splitter);

    ui->plotUat->header()->resizeSections(QHeaderView::ResizeToContents);

    ProgressFrame::addToButtonBox(ui->rightButtonBox, &parent);

    connect(plot, SIGNAL(mousePress(QMouseEvent*)), this, SLOT(graphClicked(QMouseEvent*)));
    connect(plot, SIGNAL(mouseMove(QMouseEvent*)), this, SLOT(mouseMoved(QMouseEvent*)));
    connect(plot, SIGNAL(mouseRelease(QMouseEvent*)), this, SLOT(mouseReleased(QMouseEvent*)));

    const MainWindow* main_window = mainApp->mainWindow();
    if (main_window) connect(main_window, &MainWindow::framesSelected, this, &PlotDialog::selectedFrameChanged);

    stat_timer_ = new QTimer(this);
    connect(stat_timer_, SIGNAL(timeout()), this, SLOT(updateStatistics()));
    stat_timer_->start(stat_update_interval_);
}

PlotDialog::~PlotDialog()
{
    cap_file_.stopLoading();
    foreach(Plot * plot, plots_) {
        if (plot) delete plot;
    }
    delete ui;
    ui = nullptr;
}

void PlotDialog::loadProfileGraphs()
{
    if (!plot_uat_) {
        uat_field_t* plot_fields = application_flavor_is_wireshark() ? plot_packet_fields : plot_event_fields;

        plot_uat_ = uat_new("Plots",
            sizeof(plot_settings_t),
            "plots",
            true,
            &plot_settings_,
            &num_plots_,
            0, /* doesn't affect anything that requires a GUI update */
            "ChStatPlots",
            plot_copy_cb,
            plot_update_cb,
            plot_free_cb,
            plot_post_update_cb,
            NULL,
            plot_fields);

        uat_set_default_values(plot_uat_, plot_uat_defaults_);

        char* err = NULL;
        if (!uat_load(plot_uat_, NULL, application_configuration_environment_prefix(), &err)) {
            // Some errors are non-fatal (records were added but failed
            // validation.) Since field names sometimes change between
            // versions, don't erase all the existing plots.
            if (plot_uat_->raw_data->len) {
                report_failure("Error while loading %s: %s.", plot_uat_->name, err);
                g_free(err);
            } else {
                report_failure("Error while loading %s: %s. Default plot values will be used.", plot_uat_->name, err);
                g_free(err);
                uat_clear(plot_uat_);
            }
        }

        static_uat_model_ = new UatModel(mainApp, plot_uat_);
        connect(mainApp, &MainApplication::profileChanging, PlotDialog::applyChanges);
    }

    uat_model_ = static_uat_model_;
    uat_delegate_ = new UatDelegate(ui->plotUat);
    ui->plotUat->setModel(uat_model_);
    ui->plotUat->setItemDelegate(uat_delegate_);
    ui->plotUat->setSelectionMode(QAbstractItemView::ContiguousSelection);

    ui->plotUat->setHeader(new ResizeHeaderView(Qt::Horizontal, ui->plotUat));

    connect(uat_model_, &UatModel::dataChanged, this, &PlotDialog::modelDataChanged);
    connect(uat_model_, &UatModel::modelReset, this, &PlotDialog::modelRowsReset);
    connect(uat_model_, &UatModel::rowsInserted, this, &PlotDialog::modelRowsInserted);
    connect(uat_model_, &UatModel::rowsRemoved, this, &PlotDialog::modelRowsRemoved);
    connect(uat_model_, &UatModel::rowsMoved, this, &PlotDialog::modelRowsMoved);

    connect(ui->plotUat->selectionModel(), &QItemSelectionModel::selectionChanged, this, &PlotDialog::plotUatSelectionChanged);
}

void PlotDialog::copyFromProfile(const QString& filename)
{
    if (!uat_model_) return;

    char* err = NULL;
    // uat_load appends rows to the current UAT, using filename.
    // We should let the UatModel handle it, and have the UatModel
    // call beginInsertRows() and endInsertRows(), so that we can
    // just add the new rows instead of resetting the information.
    if (uat_load(plot_uat_, filename.toUtf8().constData(), application_configuration_environment_prefix(), &err)) {
        plot_uat_->changed = true;
        // uat_load calls the post update cb, which reloads the Uat.
        //uat_model_->reloadUat();
    }
    else {
        report_failure("Error while loading %s: %s", plot_uat_->name, err);
        g_free(err);
        // On failure, uat_load does not call the post update cb.
        // Some errors are non-fatal (a record was still added but failed
        // validation.)
        uat_model_->reloadUat();
    }
}

void PlotDialog::applyChanges()
{
    if (!static_uat_model_)
        return;

    // Changes to the Plots settings are always saved,
    // there is no possibility for "rejection".
    QString error;
    if (static_uat_model_->applyChanges(error)) {
        if (!error.isEmpty()) {
            report_failure("%s", qPrintable(error));
        }
    }
}

void PlotDialog::reject()
{
    if (uat_model_) applyChanges();

    QDialog::reject();
}

void PlotDialog::createPlot(int currentRow)
{
    int groupIdx = uat_model_->data(uat_model_->index(currentRow, plotColIdx)).toInt();
    const QCPAxisRect* axisRect = getAxisRect(groupIdx);
    if (axisRect) {
        Plot* plot = new Plot(ui->plot, axisRect->axis(QCPAxis::AxisType::atBottom), axisRect->axis(QCPAxis::AxisType::atLeft));
        plots_.insert(currentRow, plot);

        connect(&cap_file_, &CaptureFile::captureEvent, plot, &Plot::captureEvent);
        connect(plot, &Plot::requestRetap, this, &PlotDialog::scheduleRetap);
        connect(plot, &Plot::requestRecalc, this, &PlotDialog::scheduleRecalc);
        connect(plot, &Plot::requestReplot, this, &PlotDialog::scheduleReplot);

        axisRect->axis(QCPAxis::atBottom)->setRange(ui->plot->xAxis->range());

        // Synchronize their ranges
        connect(axisRect->axis(QCPAxis::atBottom), QOverload<const QCPRange&>::of(&QCPAxis::rangeChanged),
            ui->plot->xAxis, QOverload<const QCPRange&>::of(&QCPAxis::setRange));
        connect(ui->plot->xAxis, QOverload<const QCPRange&>::of(&QCPAxis::rangeChanged),
            axisRect->axis(QCPAxis::atBottom), QOverload<const QCPRange&>::of(&QCPAxis::setRange));

        syncPlotSettings(currentRow);
    }
    else {
        // XXX - plots_ must always mirror the order of the entries in the UAT
        // model. That's why we insert null entries in place of invalid plots.
        plots_.insert(currentRow, Q_NULLPTR);
    }
}

QCPAxisRect* PlotDialog::getAxisRect(int idx) {
    QCPAxisRect* axisRect = Q_NULLPTR;

    if (idx <= 0 || idx > MAX_PLOT_NUM) return axisRect;

    if (idx < ui->plot->axisRectCount() - 1) {
        // The plot we're looking for already exists, return it.
        return ui->plot->axisRect(idx);
    }

    for (int i = ui->plot->axisRectCount() - 1; i <= idx; i++) {
        // Create all the plots up until the requested one, and make sure they
        // are added above the bottom one.
        ui->plot->plotLayout()->insertRow(i);

        // Create the plot and set everything we need.
        axisRect = new QCPAxisRect(ui->plot);
        foreach(QCPAxis * axis, axisRect->axes())
        {
            axis->setLayer("axes");
            axis->grid()->setLayer("grid");
        }
        axisRect->setAutoMargins(QCP::MarginSides(QCP::msLeft | QCP::msRight));
        axisRect->setMargins(QMargins());
        axisRect->setMarginGroup(QCP::msLeft | QCP::msRight, margin_group_);
        ui->plot->plotLayout()->addElement(axisRect);   // Fills the first empty row

        QCPAxis* xAxis = axisRect->axis(QCPAxis::AxisType::atBottom);
        xAxis->setTickLabels(false);
        // Connect the x axis of this plot to the top x axis
        connect(ui->plot->xAxis2, SIGNAL(rangeChanged(QCPRange)), xAxis, SLOT(setRange(QCPRange)));
        connect(xAxis, SIGNAL(rangeChanged(QCPRange)), ui->plot->xAxis2, SLOT(setRange(QCPRange)));

        // On the intermediate plots, we show both the top and bottom x axis,
        // so that ticks are symmetrical. This means we need to hide top tick
        // labels and connect the two x axis together.
        QCPAxis* xAxis2 = axisRect->axis(QCPAxis::AxisType::atTop);
        xAxis2->setTickLabels(false);
        xAxis2->setVisible(true);
        connect(xAxis, SIGNAL(rangeChanged(QCPRange)), xAxis2, SLOT(setRange(QCPRange)));
        connect(xAxis2, SIGNAL(rangeChanged(QCPRange)), xAxis, SLOT(setRange(QCPRange)));
    }

    return axisRect;
}

void PlotDialog::syncPlotSettings(int row)
{
    Plot* plot = plots_.value(row, Q_NULLPTR);

    if (!uat_model_ || !uat_model_->index(row, plotColEnabled).isValid() || !plot) {
        scheduleReplot();
        return;
    }

    bool visible = graphIsEnabled(row);

    plot->setName(uat_model_->data(uat_model_->index(row, plotColName)).toString());
    plot->setFilterField(uat_model_->data(uat_model_->index(row, plotColDFilter)).toString(),
        uat_model_->data(uat_model_->index(row, plotColYField)).toString());
    QRgb color = uat_model_->data(uat_model_->index(row, plotColColor), Qt::DecorationRole).value<QColor>().rgb();
    plot->setColor(color);
    Plot::setAxisColor(plot->graph()->valueAxis(),
        !ui->actionEnableMultiYAxes->isChecked() ? QPen(Qt::black) : QPen(color));
    QString data_str = uat_model_->data(uat_model_->index(row, plotColStyle)).toString();
    plot->setPlotStyle((Graph::PlotStyles)str_to_val(qUtf8Printable(data_str), plot_graph_style_vs, 0));
    plot->setYAxisFactor(uat_model_->data(uat_model_->index(row, plotColYAxisFactor)).toDouble());
    plot->setAbsoluteTime(abs_time_);

    if (!plot->configError().isEmpty()) {
        hint_err_ = plot->configError();
        visible = false;
    }
    else {
        hint_err_.clear();
    }

    plot->setVisible(visible);

    scheduleReplot();
}

int PlotDialog::getLastPlotIdx()
{
    int maxPlot = 0;

    if (!uat_model_) return maxPlot;

    for (int row = 0; row < uat_model_->rowCount(); row++) {
        int groupIdx = uat_model_->data(uat_model_->index(row, plotColIdx)).toInt();
        if (groupIdx <= MAX_PLOT_NUM) maxPlot = qMax(maxPlot, groupIdx);
    }

    return maxPlot;
}

void PlotDialog::addPlot(bool checked, const QString& name, const QString& dfilter,
    QRgb color_idx, Graph::PlotStyles style, const QString& yfield, double y_axis_factor)
{
    if (!uat_model_) return;

    QVariantList newRowData;
    newRowData.append(checked ? Qt::Checked : Qt::Unchecked);
    newRowData.append(getLastPlotIdx() + 1);
    newRowData.append(name);
    newRowData.append(dfilter);
    newRowData.append(QColor(color_idx));
    newRowData.append(val_to_str_const(style, plot_graph_style_vs, "None"));
    newRowData.append(yfield);
    newRowData.append(y_axis_factor);

    QModelIndex newIndex = uat_model_->appendEntry(newRowData);
    if (newIndex.isValid()) {
        ui->plotUat->setCurrentIndex(newIndex);
    }
    else {
        qDebug() << "Failed to add a new record";
    }
    // We don't need to update the plot right now, since modelRowsInserted()
    // will eventually be called.
}

void PlotDialog::addPlot(bool checked, const QString& dfilter, const QString& yfield)
{
    if (!uat_model_) return;

    QString graph_name;
    if (yfield.isEmpty()) {
        if (!dfilter.isEmpty()) {
            graph_name = application_flavor_is_wireshark() ? tr("Filtered packets") : tr("Filtered events");
        }
        else {
            graph_name = application_flavor_is_wireshark() ? tr("All packets") : tr("All events");
        }
    }
    else {
        graph_name = yfield;
    }
    addPlot(checked, std::move(graph_name), dfilter, ColorUtils::graphColor(uat_model_->rowCount()), Graph::psLine, yfield);
}

void PlotDialog::addDefaultPlot(bool enabled, bool filtered)
{
    if (filtered) {
        if (application_flavor_is_wireshark()) {
            addPlot(enabled, tr("Seq. num."), "tcp.srcport == 80", ColorUtils::graphColor(0), Graph::psDotStepLine, "tcp.seq");
        }
        else {
            addPlot(enabled, tr("Event latency"), "evt.type == \"read\"", ColorUtils::graphColor(0), Graph::psDotStepLine, "evt.latency");
        }
    }
    else {
        addPlot(enabled, tr("Frame num."), QString(), ColorUtils::graphColor(4), Graph::psLine, "frame.number");
    }
}

void PlotDialog::captureFileClosing()
{
    ui->newToolButton->setEnabled(false);
    ui->deleteToolButton->setEnabled(false);
    ui->copyToolButton->setEnabled(false);
    ui->moveUpwardsToolButton->setEnabled(false);
    ui->moveDownwardsToolButton->setEnabled(false);
    ui->clearToolButton->setEnabled(false);
    copy_profile_bt_->setEnabled(false);
    copy_bt_->setEnabled(false);
    ctx_menu_.removeAction(ui->actionToggleTimeOrigin); // This action needs a recalc

    if (uat_model_) {
        applyChanges();
        disconnect(uat_model_, nullptr, this, nullptr);
    }
    // It would be nice to keep the information in the UAT about the graphs
    // visible in a read-only state after closing, but if the view is just
    // disabled, updating the model from elsewhere (e.g., other dialogs)
    // will still change it, so we'd need to copy the information into
    // a new model.
    uat_model_ = nullptr;
    ui->plotUat->setModel(nullptr);
    ui->plotUat->setVisible(false);

    WiresharkDialog::captureFileClosing();
}

void PlotDialog::removeExcessPlots()
{
    const int maxPlot = qMax(1, getLastPlotIdx());  // Make sure we don't remove first plot
    // We start from axisRectCount() - 2 to spare the bottom "degenerate" plot
    for (int i = (ui->plot->axisRectCount() - 2); i > maxPlot; i--) {
        QCPAxisRect* axisRect = ui->plot->axisRect(i);

        // Move the legend before deleting the Axis Rect it's on
        while (axisRect->insetLayout()->elementCount() > 0) {
            QCPLayoutElement* el = axisRect->insetLayout()->elementAt(0);
            Qt::Alignment align = axisRect->insetLayout()->insetAlignment(0);
            ui->plot->axisRect(i - 1)->insetLayout()->addElement(el, align);
        }

        ui->plot->plotLayout()->remove(axisRect);
    }

    ui->plot->plotLayout()->simplify(); // Remove empty elements
}

void PlotDialog::modelDataChanged(const QModelIndex& topLeft, const QModelIndex& bottomRight, const QVector<int>&)
{
    ui->plot->deleteMarkersElements();
    for (int row = topLeft.row(); row <= bottomRight.row(); row++) {
        Plot* plot = plots_.takeAt(row);
        if (plot) {
            if (plot->graph()) {
                int groupIdx = uat_model_->data(uat_model_->index(row, plotColIdx)).toInt();
                const QCPAxisRect* axisRect = getAxisRect(groupIdx);
                if (axisRect) {
                    // If we had a plot, and the index changed to a valid one, just
                    // move it to another group by setting the key and value axes.
                    plot->graph()->setKeyAxis(axisRect->axis(QCPAxis::AxisType::atBottom));
                    plot->graph()->setValueAxis(axisRect->axis(QCPAxis::AxisType::atLeft));
                }
                else {  // If the new index is not valid, destroy the plot.
                    delete plot;
                    plot = Q_NULLPTR;
                }
                plots_.insert(row, plot);
            }
            else {  // Should not happen, but try to fix it
                delete plot;
                createPlot(row);
            }
        }
        else {  // We didn't have a plot, just create a new one.
            createPlot(row);
        }
        syncPlotSettings(row);
    }

    removeExcessPlots();
    recreateMultiValueAxes();
    drawMarkers();
}

void PlotDialog::modelRowsReset()
{
    ui->plot->deleteMarkersElements();
    foreach(Plot * plot, plots_) {
        if (plot) delete plot;
    }
    plots_.clear();

    for (int i = 0; i < uat_model_->rowCount(); i++) {
        createPlot(i);
    }

    removeExcessPlots();
    recreateMultiValueAxes();

    ui->deleteToolButton->setEnabled(false);
    ui->copyToolButton->setEnabled(false);
    ui->clearToolButton->setEnabled(uat_model_->rowCount() != 0);
    drawMarkers();
}

void PlotDialog::modelRowsInserted(const QModelIndex&, int first, int last)
{
    ui->plot->deleteMarkersElements();
    // first to last is inclusive
    for (int i = first; i <= last; i++) {
        createPlot(i);
    }
    drawMarkers();
}

void PlotDialog::modelRowsRemoved(const QModelIndex&, int first, int last)
{
    ui->plot->deleteMarkersElements();
    // first to last is inclusive
    for (int i = last; i >= first; i--) {
        Plot* plot = plots_.takeAt(i);
        if (plot) delete plot;
    }

    removeExcessPlots();
    recreateMultiValueAxes();
    drawMarkers();
}

void PlotDialog::modelRowsMoved(const QModelIndex& source, int sourceStart, int sourceEnd, const QModelIndex& dest, int destinationRow)
{
    ui->plot->deleteMarkersElements();
    // The source and destination parent are always the same for UatModel.
    ws_assert(source == dest);
    // Either destinationRow < sourceStart, or destinationRow > sourceEnd.
    // When moving rows down the same parent, the rows are placed _before_
    // destinationRow, otherwise it's the row to which items are moved.
    if (destinationRow < sourceStart) {
        for (int i = 0; i <= sourceEnd - sourceStart; i++) {
            // When moving up the same parent, moving an earlier
            // item doesn't change the row.
            plots_.move(sourceStart + i, destinationRow + i);
        }
    }
    else {
        for (int i = 0; i <= sourceEnd - sourceStart; i++) {
            // When moving down the same parent, moving an earlier
            // item means the next items move up (so all the moved
            // rows are always at sourceStart.)
            plots_.move(sourceStart, destinationRow - 1);
        }
    }

    // setting a QCPLayerable to its current layer moves it to the end
    // as though it were the last added. Do that for all the plottables
    // starting with the first one that changed, so that the graphs appear
    // as though they were added in the current order.
    // (moveToLayer() is the same thing but with a parameter to prepend
    // instead, which would be faster if we're in the top half of the
    // list, except that's a protected function. There's no function
    // to swap layerables in a layer.)
    for (int row = qMin(sourceStart, destinationRow); row < uat_model_->rowCount(); row++) {
        const Plot* plot = plots_.at(row);
        if (plot) {
            QCPGraph* graph = plot->graph();
            if (graph) graph->setLayer(graph->layer());
        }
    }

    updateLegend(); // Change order of the plots in the legend
    drawMarkers();
}

void PlotDialog::updateStatistics()
{
    if (!isVisible()) return;

    /* XXX - If we're currently retapping, what we really want to do is
     * abort the current tap and start over. process_specified_records()
     * in file.c doesn't let us do that, because it doesn't know whether
     * it's holding cf->read_lock for something that could be restarted
     * (like tapping or dissection) or something that needs to run to
     * completion (saving, printing.)
     *
     * So we wait and see if we're no longer tapping the next check.
     */
    if (need_retap_ && !file_closed_ && !retapDepth() && prefs.gui_plot_automatic_update) {
        need_retap_ = false;
        need_recalc_ = false;
        need_replot_ = false;
        //cap_file_.stopLoading();
        cap_file_.delayedRetapPackets();
        // The user might have closed the window while tapping, which means
        // we might no longer exist.
    }
    else {
        if (need_recalc_ && !file_closed_) {
            need_recalc_ = false;
            need_replot_ = true;
            start_time_ = qQNaN();

            for (int row = 0; row < uat_model_->rowCount(); row++) {
                const Plot* plot = plots_.value(row, Q_NULLPTR);
                if (plot && graphIsEnabled(row) && plot->visible()) {
                    double plot_start = plot->startTime();
                    if ((!qIsFinite(start_time_) || plot_start < start_time_) && qIsFinite(plot_start)) {
                        start_time_ = plot_start;
                    }
                }
            }
            for (int row = 0; row < uat_model_->rowCount(); row++) {
                Plot* plot = plots_.value(row, Q_NULLPTR);
                if (plot && graphIsEnabled(row) && plot->visible()) {
                    plot->setPlotStartTime(start_time_);
                }
            }
        }
        if (need_replot_) {
            need_replot_ = false;
            getGraphInfo();
            updateHint();
            if (auto_axes_)
            {
                resetAxes();
            }
            else
            {
                addDataPointsMarkers();
                autoScroll();
                ui->plot->replot();
            }
        }
    }
}

bool PlotDialog::graphIsEnabled(int row) const
{
    if (uat_model_) {
        Qt::CheckState state = static_cast<Qt::CheckState>(uat_model_->data(uat_model_->index(row, plotColEnabled), Qt::CheckStateRole).toInt());
        return state == Qt::Checked;
    }
    else {
        const Plot* plot = plots_.value(row, Q_NULLPTR);
        return (plot && plot->visible());
    }
}

Plot* PlotDialog::currentActiveGraph() const
{
    QModelIndex index = ui->plotUat->currentIndex();
    if (index.isValid() && graphIsEnabled(index.row())) {
        return plots_.value(index.row(), Q_NULLPTR);
    }

    return Q_NULLPTR;
}

// Scan through our graphs and gather information.
// QCPItemTracers can only be associated with QCPGraphs.
// Find the active one and associate it with our tracer.
void PlotDialog::getGraphInfo()
{
    base_graph_ = Q_NULLPTR;
    tracer_->setGraph(Q_NULLPTR);
    tracer_->setClipAxisRect(Q_NULLPTR);

    if (uat_model_) {
        const Plot* plot = currentActiveGraph();
        if (plot) {
            QCPGraph* graph = plot->graph();
            if (graph) base_graph_ = graph;
        }
    }

    if (base_graph_ && base_graph_->data()->size() > 0) {
        tracer_->setGraph(base_graph_);
        tracer_->setClipAxisRect(base_graph_->valueAxis()->axisRect());
        setTracerColor();
        tracer_->setVisible(true);
    }
    else {
        tracer_->setVisible(false);
    }

    updateLegend();
}

void PlotDialog::updateHint()
{
    QString hint;

    // XXX: ElidedLabel doesn't support rich text / HTML, we
    // used to bold this error
    if (!hint_err_.isEmpty()) {
        hint += QStringLiteral("%1 ").arg(hint_err_);
    }

    if (rubber_band_->isVisible()) {
        // We're trying to zoom
        QRectF zoom_ranges = getZoomRanges(rubber_band_->geometry());
        if (zoom_ranges.width() > 0.0 && zoom_ranges.height() > 0.0) {
            hint += tr("Release to zoom, x = %1 to %2, y = %3 to %4")
                .arg(zoom_ranges.x())
                .arg(zoom_ranges.x() + zoom_ranges.width())
                .arg(zoom_ranges.y())
                .arg(zoom_ranges.y() + zoom_ranges.height());
        }
        else {
            hint += tr("Unable to select range.");
        }
    }
    else {
        packet_num_ = 0;

        if (tracer_->graph()) {
            double ts = tracer_->position->key();
            if (qIsFinite(start_time_)) ts += start_time_;
            const Plot* plot = currentActiveGraph();
            if (plot) packet_num_ = plot->packetFromTime(ts);
        }

        if (packet_num_ == 0) {
            hint += tr("Select a plot for details.");
        }
        else {
            QString msg;
            QString val = QStringLiteral(" = %1").arg(tracer_->position->value(), 0, 'g', QLocale::FloatingPointShortest);
            if (application_flavor_is_wireshark()) {
                msg = QStringLiteral("%1 %2")
                    .arg(!file_closed_ ? tr("Click to select packet") : tr("Packet"))
                    .arg(packet_num_);
            }
            else {
                msg = QStringLiteral("%1 %2")
                    .arg(!file_closed_ ? tr("Click to select event") : tr("Event"))
                    .arg(packet_num_);
            }
            hint += tr("%1 (%2s%3).").arg(msg).arg(QString::number(tracer_->position->key(), 'f', 9)).arg(val);
        }
        ui->plot->replot(QCustomPlot::rpQueuedReplot);
    }

    ui->hintLabel->setText(hint);
}

void PlotDialog::showContextMenu(const QPoint& pos)
{
    if (const QCPAxisRect* rect = axisRectFromPos(pos)) {
        if (rect->axis(QCPAxis::AxisType::atBottom))
            last_right_clicked_pos_ = rect->axis(QCPAxis::AxisType::atBottom)->pixelToCoord(pos.x());
    }
    QString actionDeleteTxt = QStringLiteral("Delete Marker %1")
        .arg(ui->plot->selectedMarker(Marker::index(ui->plot->posMarker())));
    ui->actionDeleteMarker->setText(actionDeleteTxt);
    if (ui->plot->legend->visible() && ui->plot->legend->selectTest(pos, false) >= 0) {
        QMenu* menu = new QMenu(this);
        menu->setAttribute(Qt::WA_DeleteOnClose);
        menu->addAction(ui->actionLegend);
        menu->addSeparator();
#if QT_VERSION >= QT_VERSION_CHECK(6, 2, 0)
        menu->addAction(tr("Move to top left"), this, &PlotDialog::moveLegend)->setData((Qt::AlignTop | Qt::AlignLeft).toInt());
        menu->addAction(tr("Move to top center"), this, &PlotDialog::moveLegend)->setData((Qt::AlignTop | Qt::AlignHCenter).toInt());
        menu->addAction(tr("Move to top right"), this, &PlotDialog::moveLegend)->setData((Qt::AlignTop | Qt::AlignRight).toInt());
        menu->addAction(tr("Move to bottom left"), this, &PlotDialog::moveLegend)->setData((Qt::AlignBottom | Qt::AlignLeft).toInt());
        menu->addAction(tr("Move to bottom center"), this, &PlotDialog::moveLegend)->setData((Qt::AlignBottom | Qt::AlignHCenter).toInt());
        menu->addAction(tr("Move to bottom right"), this, &PlotDialog::moveLegend)->setData((Qt::AlignBottom | Qt::AlignRight).toInt());
#else
        menu->addAction(tr("Move to top left"), this, &PlotDialog::moveLegend)->setData(static_cast<Qt::Alignment::Int>(Qt::AlignTop | Qt::AlignLeft));
        menu->addAction(tr("Move to top center"), this, &PlotDialog::moveLegend)->setData(static_cast<Qt::Alignment::Int>(Qt::AlignTop | Qt::AlignHCenter));
        menu->addAction(tr("Move to top right"), this, &PlotDialog::moveLegend)->setData(static_cast<Qt::Alignment::Int>(Qt::AlignTop | Qt::AlignRight));
        menu->addAction(tr("Move to bottom left"), this, &PlotDialog::moveLegend)->setData(static_cast<Qt::Alignment::Int>(Qt::AlignBottom | Qt::AlignLeft));
        menu->addAction(tr("Move to bottom center"), this, &PlotDialog::moveLegend)->setData(static_cast<Qt::Alignment::Int>(Qt::AlignBottom | Qt::AlignHCenter));
        menu->addAction(tr("Move to bottom right"), this, &PlotDialog::moveLegend)->setData(static_cast<Qt::Alignment::Int>(Qt::AlignBottom | Qt::AlignRight));
#endif
        menu->popup(ui->plot->mapToGlobal(pos));
    }
    else if (ui->plot->xAxis2->selectTest(pos, false) >= 0) {
        QMenu* menu = new QMenu(this);
        menu->setAttribute(Qt::WA_DeleteOnClose);
        menu->addAction(ui->actionTopAxis);
        menu->popup(ui->plot->mapToGlobal(pos));
    }
    else {
        if (!file_closed_) {    // actionToggleTimeOrigin needs a recalc
            const QCPAxis* bottomAxis = ui->plot->axisRect(ui->plot->axisRectCount() - 1)->axis(QCPAxis::AxisType::atBottom);
            if (bottomAxis && bottomAxis->selectTest(pos, false) >= 0) {
                QMenu* menu = new QMenu(this);
                menu->setAttribute(Qt::WA_DeleteOnClose);
                menu->addAction(ui->actionToggleTimeOrigin);
                menu->popup(ui->plot->mapToGlobal(pos));
                return;
            }
        }

        foreach(const QCPAxisRect * axisRect, axisRects()) {
            foreach(const QCPAxis* yAxis, axisRect->axes(QCPAxis::atLeft | QCPAxis::atRight)) {
                if (yAxis->selectTest(pos, false) >= 0) {
                    QMenu* menu = new QMenu(this);
                    menu->setAttribute(Qt::WA_DeleteOnClose);
                    menu->addAction(ui->actionLogScale);
                    menu->popup(ui->plot->mapToGlobal(pos));
                    return;
                }
            }
        }

        ctx_menu_.popup(ui->plot->mapToGlobal(pos));
    }
}

void PlotDialog::moveLegend()
{
    if (QAction* contextAction = qobject_cast<QAction*>(sender())) {
        if (contextAction->data().canConvert<Qt::Alignment::Int>()) {
#if QT_VERSION >= QT_VERSION_CHECK(6, 2, 0)
            Qt::Alignment alignment = Qt::Alignment::fromInt(contextAction->data().value<Qt::Alignment::Int>());
#else
            Qt::Alignment alignment = static_cast<Qt::Alignment>(contextAction->data().value<Qt::Alignment::Int>());
#endif
            legend_alignment_ = alignment;
            updateLegendPos();
            ui->plot->replot();
        }
    }
}

void PlotDialog::updateLegend()
{
    if (!prefs.gui_plot_enable_legend) return;
    QCPLegend* legend = ui->plot->legend;

    legend->setVisible(false);

    // Create a legend with a Title label at top.
    // Legend Title thanks to: https://www.qcustomplot.com/index.php/support/forum/443
    legend->clearItems();
    legend->setRowSpacing(0);
    legend->addElement(0, 0, new QCPStringLegendItem(legend, tr("Plots")));

    QModelIndexList selectedRows = ui->plotUat->selectionModel()->selectedRows();
    int selRow = selectedRows.size() == 1 ? selectedRows.begin()->row() : -1;

    for (int i = 1; i < ui->plot->axisRectCount() - 1; i++) {
        const QCPAxisRect* axisRect = ui->plot->axisRect(i);
        bool first = true;
        for (int row = 0; row < plots_.size(); row++) {
            Plot* plot = plots_.at(row);
            if (plot) {
                QCPGraph* graph = plot->graph();
                if (graph && graph->visible() && axisRect->graphs().contains(graph)) {
                    if (first) {    // Add spacer
                        first = false;
                        legend->addElement(legend->rowCount(), 0, new QCPSpacerLegendItem(legend, 8));
                    }
                    graph->addToLegend();
                    if (selRow == row) {
                        QCPAbstractLegendItem* item = legend->item(legend->itemCount() - 1);
                        if (item) item->setSelected(true);
                    }
                }
            }
        }
    }

    updateLegendPos();

    // Only show legend if the user requested it
    legend->setVisible(prefs.gui_plot_enable_legend);

    ui->plot->replot();
}

void PlotDialog::updateLegendPos()
{
    const QCPAxisRect* axisRect;
    if (legend_alignment_.testFlag(Qt::AlignBottom)) {
        axisRect = ui->plot->axisRect(ui->plot->axisRectCount() - 2);
    }
    else {
        axisRect = ui->plot->axisRect(1);
    }
    axisRect->insetLayout()->addElement(ui->plot->legend, legend_alignment_);
}

QCPAxisRect* PlotDialog::axisRectFromPos(const QPoint& pos)
{
    foreach(QCPAxisRect * axisRect, ui->plot->axisRects()) {
        if (axisRect->rect().contains(pos)) {
            return axisRect;
        }
    }
    return Q_NULLPTR;
}

void PlotDialog::addMarkerDifference()
{
    if (ui->plot->markers().isEmpty() || !ui->actionShowMarkersDifference->isChecked()) {
        return;
    }
    ui->plot->clearMarkerDifferences();
    ui->plot->showMarkerDifferences();
    ui->plot->replot();
}

int PlotDialog::visibleMarker(const bool first) const
{
    int idx = -1;
    for (const Marker* m : ui->plot->visibleMarkers()) {
        if (first || idx != -1) {
            return m->index();
        }
        idx = m->index();
    }
    return -1;
}

void PlotDialog::graphClicked(QMouseEvent* event)
{
    bool movePosMarker = !ui->plot->mousePressed(event->pos());
    switch (event->button()) {
    case Qt::LeftButton:
        if (const QCPAxisRect* axisRect = axisRectFromPos(event->pos())) {
            if (movePosMarker && ui->plot->axisRect(0) == axisRect) {
                Marker* m = addMarker(true);
                m->setXCoord(ui->plot->xAxis->pixelToCoord(event->pos().x()));
                ui->plot->markerMoved(m);
            }
            ui->plot->setCursor(QCursor(Qt::ClosedHandCursor));
            if (base_graph_ && axisRect->graphs().contains(base_graph_)) {
                on_actionGoToPacket_triggered();
            }
        }
        break;

    case Qt::RightButton:
        ui->plot->setCursor(QCursor(Qt::CrossCursor));
        rb_origin_ = event->pos();
        break;

    default:
        break;
    }

    ui->plot->setFocus();
}

void PlotDialog::mouseMoved(QMouseEvent* event)
{
    if (event->buttons().testFlag(Qt::RightButton)) {
        rubber_band_->setGeometry(QRect(rb_origin_, event->pos()).normalized());
        rubber_band_->show();
    }
    else if (!event->buttons().testFlag(Qt::LeftButton)) {
        // If the left button is pressed, it means we are dragging, so we want
        // to keep the closed hand cursor we already set before. Otherwise, set
        // the default cursor for the position we're at.
        ui->plot->setCursor(QCursor(axisRectFromPos(event->pos()) ? Qt::OpenHandCursor : Qt::ArrowCursor));

        if (tracer_->graph() && tracer_->graph()->keyAxis()) {
            tracer_->setGraphKey(tracer_->graph()->keyAxis()->pixelToCoord(event->pos().x()));
            ui->plot->replot();
        }
    }

    updateHint();
}

void PlotDialog::mouseReleased(QMouseEvent* event)
{
    bool old_auto_axes = auto_axes_;
    auto_axes_ = false;

    // QCustomPlot iRangeDrag controls dragging, and it stops dragging when a
    // button other than LeftButton is released (even if LeftButton is still
    // held down). If the right button is currently being pressed, we set the
    // the cross cursor again, since it might have been overwritten by a left
    // click. Otherwise set the default cursor for the position we're at.
    if (event->buttons().testFlag(Qt::RightButton)) {
        ui->plot->setCursor(QCursor(Qt::CrossCursor));
    }
    else {
        ui->plot->setCursor(QCursor(axisRectFromPos(event->pos()) ? Qt::OpenHandCursor : Qt::ArrowCursor));
    }

    if (event->button() == Qt::RightButton) {
        if (!rubber_band_->isVisible()) {
            // That was just a click
            showContextMenu(event->pos());
            auto_axes_ = old_auto_axes;
        }
        else {
            rubber_band_->hide();
            QCPAxisRect* axisRect = Q_NULLPTR;
            QRectF zoom_ranges = getZoomRanges(QRect(rb_origin_, event->pos()), &axisRect);

            if (zoom_ranges.isValid() && axisRect) {
                axisRect->axis(QCPAxis::AxisType::atBottom)->setRange(
                    QCPRange(zoom_ranges.x(), zoom_ranges.x() + zoom_ranges.width()));
                if (axisRect != ui->plot->axisRect(0)) {
                    axisRect->axis(QCPAxis::AxisType::atLeft)->setRange(
                        QCPRange(zoom_ranges.y(), zoom_ranges.y() + zoom_ranges.height()));
                }
                ui->plot->replot();
            }
            else {
                // Wrong range, interpret it as a simple right click
                showContextMenu(event->pos());
                auto_axes_ = old_auto_axes;
            }
        }
    }

    ui->plot->mouseReleased();
}

QRectF PlotDialog::getZoomRanges(QRect zoom_rect, QCPAxisRect** matchedAxisRect)
{
    QRectF zoom_ranges = QRectF();

    if (zoom_rect.width() < min_zoom_pixels_ && zoom_rect.height() < min_zoom_pixels_) {
        return zoom_ranges;
    }

    QRect zr = zoom_rect.normalized();
    foreach(QCPAxisRect * axisRect, ui->plot->axisRects()) {
        QRect ar = axisRect->rect();
        if (ar.intersects(zr)) {
            QRect zsr = ar.intersected(zr);
            const QCPAxis* xAxis = axisRect->axis(QCPAxis::AxisType::atBottom);
            const QCPAxis* yAxis = axisRect->axis(QCPAxis::AxisType::atLeft);

            if (xAxis && yAxis) {
                zoom_ranges.setX(xAxis->range().lower + xAxis->range().size() * (zsr.left() - ar.left()) / ar.width());
                zoom_ranges.setWidth(xAxis->range().size() * zsr.width() / ar.width());

                // QRects grow down
                zoom_ranges.setY(yAxis->range().lower + yAxis->range().size() * (ar.bottom() - zsr.bottom()) / ar.height());
                zoom_ranges.setHeight(yAxis->range().size() * zsr.height() / ar.height());

                if (matchedAxisRect) *matchedAxisRect = axisRect;
                break;
            }
        }
    }

    return zoom_ranges;
}

void PlotDialog::resetAxes()
{
    if (!ui->actionAutoScroll->isChecked()) {
        ui->plot->rescaleAxes(true);

        QCPRange x_range = ui->plot->xAxis2->scaleType() == QCPAxis::stLogarithmic ?
            ui->plot->xAxis2->range().sanitizedForLogScale() : ui->plot->xAxis2->range();
        double axis_pixels = ui->plot->xAxis2->axisRect()->width();
        ui->plot->xAxis2->scaleRange((axis_pixels + (pixel_pad * 2)) / axis_pixels, x_range.center());
    }
    for (const QCPAxisRect* axisRect : axisRects()) {
        for (QCPAxis* yAxis : axisRect->axes(QCPAxis::atLeft | QCPAxis::atRight)) {
            if (ui->actionAutoScroll->isChecked()) {
                yAxis->rescale(true);
            }
            QCPRange y_range = yAxis->scaleType() == QCPAxis::stLogarithmic ?
                yAxis->range().sanitizedForLogScale() : yAxis->range();
            double axis_pixels = yAxis->axisRect()->height();
            yAxis->scaleRange((axis_pixels + (pixel_pad * 2)) / axis_pixels, y_range.center());
        }
    }

    auto_axes_ = true;
    autoScroll();
    addDataPointsMarkers();
    ui->plot->replot();
}

void PlotDialog::doZoom(bool in, bool y)
{
    if (y) {
        foreach(QCPAxisRect* axisRect, axisRects()) {
            foreach(QCPAxis * yAxis, axisRect->axes(QCPAxis::atLeft | QCPAxis::atRight)) {
                double v_factor = axisRect->rangeZoomFactor(Qt::Vertical);
                if (!in) v_factor = pow(v_factor, -1);
                yAxis->scaleRange(v_factor, yAxis->range().center());
            }
        }
    }
    else {
        double h_factor = ui->plot->axisRect()->rangeZoomFactor(Qt::Horizontal);
        if (!in) h_factor = pow(h_factor, -1);
        ui->plot->xAxis2->scaleRange(h_factor, ui->plot->xAxis2->range().center());
    }
}

void PlotDialog::zoomAxes(bool in)
{
    auto_axes_ = false;
    doZoom(in, false);
    doZoom(in, true);
    ui->plot->replot();
}

void PlotDialog::zoomXAxis(bool in)
{
    auto_axes_ = false;
    doZoom(in, false);
    ui->plot->replot();
}

void PlotDialog::zoomYAxis(bool in)
{
    auto_axes_ = false;
    doZoom(in, true);
    ui->plot->replot();
}

void PlotDialog::panAxes(int x_pixels, int y_pixels)
{
    auto_axes_ = false;

    double h_pan = ui->plot->xAxis2->range().size() * x_pixels / ui->plot->xAxis2->axisRect()->width();
    if (h_pan) ui->plot->xAxis2->moveRange(h_pan);

    foreach(const QCPAxisRect * axisRect, axisRects()) {
        foreach(QCPAxis * yAxis, axisRect->axes(QCPAxis::atLeft | QCPAxis::atRight)) {
            double v_pan = yAxis->range().size() * y_pixels / yAxis->axisRect()->height();
            if (v_pan) yAxis->moveRange(v_pan);
        }
    }

    ui->plot->replot();
}

Marker* PlotDialog::addMarker(const bool isPosMarker)
{
    Marker* m = Q_NULLPTR;
    if (isPosMarker || ui->plot->markers().isEmpty()) {
        m = ui->plot->addMarker(last_right_clicked_pos_, true);
    }
    if (!isPosMarker) {
        m = ui->plot->addMarker(last_right_clicked_pos_, false);
        drawMarker(m);
    }
    return m;
}

void PlotDialog::drawMarker(const Marker* marker)
{
    ui->plot->addMarkerElements(marker);
    if (marker->isPosMarker()) {
        ui->plot->markerVisibilityChanged(marker);
    }
    addDataPointsMarkers();
    addMarkerDifference();
}

void PlotDialog::drawMarkers() {
    for (const Marker* m : ui->plot->markers()) {
        drawMarker(m);
    }
}

void PlotDialog::updateFirstAxisRectHeight() {
    int minHeight = 0;
    qsizetype nbVisibleMarkers = ui->plot->visibleMarkers().size();
    if (ui->actionShowMarkersDifference->isChecked() && nbVisibleMarkers > 1) {
        minHeight = 40;
    }
    else if (nbVisibleMarkers > 0) {
        minHeight = 20;
    }
    if (ui->plot->axisRectCount() >= 2 && getAxisRect(1)->axis(QCPAxis::AxisType::atTop)->tickLabels()) {
        minHeight += 18;
    }
    ui->plot->axisRect(0)->setMinimumSize(0, minHeight);
    ui->plot->replot();
}

void PlotDialog::recreateMultiValueAxes() {
    if (ui->actionEnableMultiYAxes->isChecked()) {
        on_actionEnableMultiYAxes_triggered(false);
        on_actionEnableMultiYAxes_triggered(true);
    }
}

QList<QCPAxisRect*> PlotDialog::axisRects() const {
    QList<QCPAxisRect*> list;
    for (qsizetype i = 1; i < ui->plot->axisRects().size(); i++) {
        QCPAxisRect* axisRect = ui->plot->axisRects()[i];
        if (axisRect->axisCount(QCPAxis::AxisType::atLeft) > 0) {
            list << axisRect;
        }
    }
    return list;
}

void PlotDialog::autoScroll() const {
    if (!ui->actionAutoScroll->isChecked()) return;

    // Number of the max data points shown when auto-scrolling to the end
    constexpr int last_data_nb = 100; // TODO: Make this configurable if needed
    QCPRange range;
    for (const Plot* plot : plots_) {
        if (plot) {
            QCPRange plotRange = plot->recentDrawnDataRange(last_data_nb);
            if (QCPRange::validRange(plotRange) && plotRange.upper > range.upper) {
                range = plotRange;
            }
        }
    }
    if (QCPRange::validRange(range)) {
        ui->plot->xAxis->setRange(range);
        ui->plot->replot();
    }
}

void PlotDialog::on_actionCrosshairs_triggered(bool checked)
{
    QPen newPen = QPen(tracer_->pen());
    QColor newColor = newPen.color();
    QCPItemTracer::TracerStyle newStyle;

    if (checked) {
        newPen.setWidthF(1.0);
        newColor.setAlphaF(0.5);
        newStyle = QCPItemTracer::tsCrosshair;
    }
    else {
        newPen.setWidthF(1.5);
        newColor.setAlphaF(1);
        newStyle = QCPItemTracer::tsCircle;
    }

    newPen.setColor(newColor);
    tracer_->setPen(newPen);
    tracer_->setStyle(newStyle);
    ui->plot->replot();
}

void PlotDialog::on_actionTopAxis_triggered(bool checked)
{
    if (ui->plot->axisRectCount() >= 2) {
        getAxisRect(1)->axis(QCPAxis::AxisType::atTop)->setTickLabels(checked);
    }
    updateFirstAxisRectHeight();
}

void PlotDialog::setTracerColor()
{
    if (!base_graph_) return;

    QPen newPen = QPen(tracer_->pen());
    QColor newColor = base_graph_->pen().color();
    // Alpha is set by on_actionCrosshairs_triggered(), don't lose it
    newColor.setAlpha(tracer_->pen().color().alpha());
    newPen.setColor(newColor);
    tracer_->setPen(newPen);
}

void PlotDialog::keyPressEvent(QKeyEvent* event)
{
    bool shift_pressed = event->modifiers() & Qt::ShiftModifier;

    switch (event->key()) {
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
        if (event->modifiers() & Qt::ShiftModifier) {
            zoomXAxis(false);   // upper case X -> Zoom out
        }
        else {
            zoomXAxis(true);    // lower case x -> Zoom in
        }
        break;
    case Qt::Key_Y:             // Zoom Y axis only
        if (event->modifiers() & Qt::ShiftModifier) {
            zoomYAxis(false);   // upper case Y -> Zoom out
        }
        else {
            zoomYAxis(true);    // lower case y -> Zoom in
        }
        break;
    case Qt::Key_Right:
    case Qt::Key_L:
        panAxes(shift_pressed ? 1 : 10, 0);
        break;
    case Qt::Key_Left:
    case Qt::Key_H:
        panAxes(shift_pressed ? -1 : -10, 0);
        break;
    case Qt::Key_Up:
    case Qt::Key_K:
        panAxes(0, shift_pressed ? 1 : 10);
        break;
    case Qt::Key_Down:
    case Qt::Key_J:
        panAxes(0, shift_pressed ? -1 : -10);
        break;
    case Qt::Key_Space:
        ui->actionCrosshairs->trigger();
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
        if (!file_closed_) {
            on_actionToggleTimeOrigin_triggered();
        }
        break;
    case Qt::Key_A:
        ui->actionTopAxis->trigger();
        break;
    default:
        break;
    }

    QDialog::keyPressEvent(event);
}

void PlotDialog::selectedFrameChanged(const QList<int>& frames)
{
    if (frames.count() == 1 && cap_file_.isValid() && !file_closed_ && tracer_->graph() && cap_file_.packetInfo()) {
        packet_info* pinfo = cap_file_.packetInfo();
        if (pinfo->num != packet_num_) {
            // This prevents being triggered by the Plot's own GoToPacketAction,
            // although that is mostly harmless.
            double key = nstime_to_sec(&pinfo->abs_ts);
            if (qIsFinite(start_time_)) key -= start_time_;
            tracer_->setGraphKey(key);
            ui->plot->replot();
            updateHint();
        }
    }
}

void PlotDialog::plotUatSelectionChanged(const QItemSelection&, const QItemSelection&)
{
    QModelIndexList selectedRows = ui->plotUat->selectionModel()->selectedRows();
    qsizetype num_selected = selectedRows.size();
    if (num_selected > 0) {
        std::sort(selectedRows.begin(), selectedRows.end());
        ui->deleteToolButton->setEnabled(true);
        ui->copyToolButton->setEnabled(true);
        ui->moveUpwardsToolButton->setEnabled(selectedRows.first().row() > 0);
        ui->moveDownwardsToolButton->setEnabled(selectedRows.last().row() < uat_model_->rowCount() - 1);
    }
    else {
        ui->deleteToolButton->setEnabled(false);
        ui->copyToolButton->setEnabled(false);
        ui->moveUpwardsToolButton->setEnabled(false);
        ui->moveDownwardsToolButton->setEnabled(false);
    }
    copy_bt_->setEnabled(num_selected == 1);    // We can export one plot at a time
    updateLegend(); // Update selected item in the legend
}

void PlotDialog::on_leftButtonBox_clicked(QAbstractButton* button)
{
    if (ui->leftButtonBox->buttonRole(button) == QDialogButtonBox::ResetRole) {
        resetAxes();
    }
}

void PlotDialog::on_actionLegend_triggered(bool checked)
{
    prefs.gui_plot_enable_legend = checked;
    prefs_main_write();

    ui->plot->legend->setVisible(checked);
    ui->plot->legend->layer()->replot();
}

void PlotDialog::on_actionLogScale_triggered(bool checked)
{
    foreach(const QCPAxisRect * axisRect, axisRects()) {
        foreach(QCPAxis* yAxis, axisRect->axes(QCPAxis::atLeft | QCPAxis::atRight)) {
            if (checked) {
                yAxis->setScaleType(QCPAxis::stLogarithmic);
                yAxis->setTicker(QSharedPointer<QCPAxisTickerLog>(new QCPAxisTickerLog));
            }
            else {
                yAxis->setScaleType(QCPAxis::stLinear);
                yAxis->setTicker(QSharedPointer<QCPAxisTicker>(new QCPAxisTicker));
            }
        }
    }

    auto_axes_ ? resetAxes() : ui->plot->replot();
}

void PlotDialog::on_automaticUpdateCheckBox_toggled(bool checked)
{
    prefs.gui_plot_automatic_update = checked;
    prefs_main_write();

    if (prefs.gui_plot_automatic_update) updateStatistics();
}

void PlotDialog::on_plotUat_currentItemChanged(const QModelIndex& current, const QModelIndex&)
{
    ui->clearToolButton->setEnabled(current.isValid());
    getGraphInfo();
    updateHint();
}

void PlotDialog::on_actionGoToPacket_triggered()
{
    if (tracer_->visible() && !file_closed_ && packet_num_ > 0) {
        const Plot* plot = currentActiveGraph();
        emit goToPacket(packet_num_, plot ? plot->hfIndex() : -1);
    }
}

void PlotDialog::on_newToolButton_clicked()
{
    addDefaultPlot(false, false);
}

void PlotDialog::on_deleteToolButton_clicked()
{
    if (!uat_model_) return;

    int topRow = uat_model_->rowCount();

    for (const auto& range : ui->plotUat->selectionModel()->selection()) {
        // Each QItemSelectionRange is contiguous
        if (!range.isEmpty()) {
            topRow = qMin(topRow, range.top());
            if (!uat_model_->removeRows(range.top(), range.bottom() - range.top() + 1)) {
                qDebug() << "Failed to remove rows " << range.top() << " to " << range.bottom();
            }
        }
    }

    recreateMultiValueAxes();
    ui->plotUat->setCurrentIndex(uat_model_->index(qMax(0, topRow - 1), plotColEnabled));
    getGraphInfo();
    // We should probably be smarter about this.
    hint_err_.clear();
    updateHint();
}

void PlotDialog::on_copyToolButton_clicked()
{
    if (!uat_model_) return;

    QModelIndexList selectedRows = ui->plotUat->selectionModel()->selectedRows();
    if (selectedRows.size() > 0) {
        std::sort(selectedRows.begin(), selectedRows.end());

        const int lastIdx = getLastPlotIdx();

        for (const auto& idx : selectedRows) {
            QModelIndex copyIdx = uat_model_->copyRow(idx);
            if (copyIdx.isValid()) {
                // Probably the user wants to edit the copy, so we disable it
                uat_model_->setData(copyIdx.siblingAtColumn(plotColEnabled), false);
                // And also move it to a new group to avoid overlaps
                uat_model_->setData(copyIdx.siblingAtColumn(plotColIdx), lastIdx + 1);
                ui->plotUat->setCurrentIndex(copyIdx);
            }
            else {
                qDebug() << "Failed to copy row " << idx.row();
            }
        }
    }
}

void PlotDialog::on_clearToolButton_clicked()
{
    if (uat_model_) uat_model_->clearAll();

    tracer_->setVisible(false);

    hint_err_.clear();
    updateHint();
    getGraphInfo();
}

void PlotDialog::on_moveUpwardsToolButton_clicked()
{
    if (!uat_model_) return;

    for (const auto& range : ui->plotUat->selectionModel()->selection()) {
        // Each QItemSelectionRange is contiguous
        if (!range.isEmpty() && range.top() > 0) {
            // Swap range of rows with the row above the top
            if (!uat_model_->moveRows(QModelIndex(), range.top(), range.bottom() - range.top() + 1, QModelIndex(), range.top() - 1)) {
                qDebug() << "Failed to move up rows " << range.top() << " to " << range.bottom();
            }
            // Our moveRows implementation calls begin/endMoveRows(), so
            // range.top() already has the new row number.
            ui->moveUpwardsToolButton->setEnabled(range.top() > 0);
            ui->moveDownwardsToolButton->setEnabled(true);
        }
    }
}

void PlotDialog::on_moveDownwardsToolButton_clicked()
{
    if (!uat_model_) return;

    for (const auto& range : ui->plotUat->selectionModel()->selection()) {
        // Each QItemSelectionRange is contiguous
        if (!range.isEmpty() && range.bottom() + 1 < uat_model_->rowCount()) {
            // Swap range of rows with the row below the top
            if (!uat_model_->moveRows(QModelIndex(), range.top(), range.bottom() - range.top() + 1, QModelIndex(), range.bottom() + 1)) {
                qDebug() << "Failed to move down rows " << range.top() << " to " << range.bottom();
            }
            // Our moveRows implementation calls begin/endMoveRows, so
            // range.bottom() already has the new row number.
            ui->moveUpwardsToolButton->setEnabled(true);
            ui->moveDownwardsToolButton->setEnabled(range.bottom() < uat_model_->rowCount() - 1);
        }
    }
}

void PlotDialog::on_rightButtonBox_helpRequested()
{
    mainApp->helpTopicAction(HELP_STATS_PLOT_DIALOG);
}

void PlotDialog::on_actionToggleTimeOrigin_triggered()
{
    abs_time_ = !abs_time_;
    foreach(Plot * plot, plots_) {
        if (plot) plot->setAbsoluteTime(abs_time_);
    }
    updateXAxisLabel();
    updateHint();
}

void PlotDialog::on_actionAddMarker_triggered()
{
    addMarker(false);
    updateFirstAxisRectHeight();
}

void PlotDialog::on_actionMoveMarker_triggered()
{
    MarkerDialog dialog(this, true, ui->plot->markers());
    dialog.adjustSize();
    if (dialog.exec() == QDialog::Accepted) {
        bool ok;
        double newPos = dialog.getText().toDouble(&ok);
        Marker* m = ui->plot->marker(dialog.selectedMarker());
        if (ok && m)
        {
            m->setXCoord(newPos);
            ui->plot->markerMoved(m);
        }
    }
}

void PlotDialog::on_actionShowPosMarker_triggered()
{
    Marker* pos = addMarker(true);
    pos->setVisibility(!pos->visible());
    drawMarker(pos);
    ui->plot->markerVisibilityChanged(pos);
    addMarkerDifference();
    updateFirstAxisRectHeight();
}

void PlotDialog::on_actionShowMarkersDifference_triggered()
{
    ui->plot->showMarkersDifference(ui->actionShowMarkersDifference->isChecked());
    ui->plot->clearMarkerDifferences();
    ui->plot->replot();
    addMarkerDifference();
    updateFirstAxisRectHeight();
}

void PlotDialog::on_actionDeleteMarker_triggered()
{
    const int idx = ui->plot->selectedMarker();
    if (Marker* m = ui->plot->marker(idx)) {
        if(m->isPosMarker()){
            ui->actionShowPosMarker->setChecked(false);
        }
        ui->plot->deleteMarkerElements(m->index());
        ui->plot->deleteMarker(m);
        addMarkerDifference();
    }
    updateFirstAxisRectHeight();
}

void PlotDialog::on_actionDeleteAllMarkers_triggered()
{
    ui->actionShowPosMarker->setChecked(false);
    if (ui->plot->markers().isEmpty())
        return;
    ui->plot->deleteMarkersElements();
    ui->plot->deleteAllMarkers();
    updateFirstAxisRectHeight();
}

void PlotDialog::on_actionShowDataPointMarker_triggered()
{
    ui->plot->setDataPointVisibility(ui->actionShowDataPointMarker->isChecked());
}

void PlotDialog::updateXAxisLabel()
{
    QCPAxis* axis = ui->plot->axisRect(ui->plot->axisRectCount() - 1)->axis(QCPAxis::AxisType::atBottom);

    if (axis) axis->setLabel(QStringLiteral("%1 [%2]")
        .arg(tr("Time (s)"))
        .arg(abs_time_ ? tr("relative to capture start") : tr("relative to first data point")));
}

// XXX - We have similar code in IO/Graph, tcp_stream_dialog and packet_diagram. Should this be a common routine?
void PlotDialog::on_rightButtonBox_accepted()
{
    QString file_name;
    QDir path(mainApp->openDialogInitialDir());
    QString pdf_filter = tr("Portable Document Format (*.pdf)");
    QString png_filter = tr("Portable Network Graphics (*.png)");
    QString bmp_filter = tr("Windows Bitmap (*.bmp)");
    // Gaze upon my beautiful plot with lossy artifacts!
    QString jpeg_filter = tr("JPEG File Interchange Format (*.jpeg *.jpg)");
    //QString csv_filter = tr("Comma Separated Values (*.csv)");
    //QString filter = QStringLiteral("%1;;%2;;%3;;%4;;%5")
    QString filter = QStringLiteral("%1;;%2;;%3;;%4;;%5").arg(
        pdf_filter,
        png_filter,
        bmp_filter,
        jpeg_filter
        // csv_filter
    );
    QString extension = png_filter;

    QString save_file = path.canonicalPath();
    if (!file_closed_) {
        save_file += QStringLiteral("/%1").arg(cap_file_.fileBaseName());
    }
    file_name = WiresharkFileDialog::getSaveFileName(this, mainApp->windowTitleString(tr("Save Graph As…")),
        save_file, filter, &extension);

    if (file_name.length() > 0) {
        bool save_ok = false;
        if (extension.compare(pdf_filter) == 0) {
            save_ok = ui->plot->savePdf(file_name);
        }
        else if (extension.compare(png_filter) == 0) {
            save_ok = ui->plot->savePng(file_name);
        }
        else if (extension.compare(bmp_filter) == 0) {
            save_ok = ui->plot->saveBmp(file_name);
        }
        else if (extension.compare(jpeg_filter) == 0) {
            save_ok = ui->plot->saveJpg(file_name);
        }
        //else if (extension.compare(csv_filter) == 0) {
        //    save_ok = saveCsv(file_name);
        //}
        // else error dialog?
        if (save_ok) {
            mainApp->setLastOpenDirFromFilename(file_name);
        }
    }
}

void PlotDialog::on_actionAutoScroll_triggered(bool checked) {
    ui->actionAutoScroll->setChecked(checked);
    prefs.gui_plot_enable_auto_scroll = checked;
    if (checked) {
        autoScroll();
        ui->plot->replot();
    }
}

void PlotDialog::on_actionEnableMultiYAxes_triggered(bool checked)
{
    ui->actionEnableMultiYAxes->setChecked(checked);
    for (QCPAxisRect* axisRect : axisRects()) {
        QCPAxis* defaultValueAxis = axisRect->axis(QCPAxis::atLeft, 0);
        QList<QCPGraph*> graphs;
        for (QCPGraph* graph : axisRect->graphs()) {
            if (graph->visible()) graphs << graph;
        }
        QList<QCPAxis*> axes;
        for (qsizetype i = 0; i < graphs.count(); i++) {
            QCPGraph* graph = graphs.at(i);
            if (checked && i != 0) {
                QCPAxis::AxisType type = (i % 2 == 1) ? QCPAxis::atRight : QCPAxis::atLeft;
                QCPAxis* y_axis = axisRect->addAxis(type);
                y_axis->setLayer("axes");
                y_axis->grid()->setLayer("grid");
                graph->setValueAxis(y_axis);
                axes << y_axis;
            } else {
                graph->setValueAxis(defaultValueAxis);
            }
            Plot::setAxisColor(graph->valueAxis(), !checked ? QPen(Qt::black) : graph->pen());
        }
        for (QCPAxis* axis : axisRect->axes(QCPAxis::atLeft | QCPAxis::atRight)) {
            if (!axes.contains(axis) && axis->visible() && axis != defaultValueAxis) { // keep the default y axis
                axisRect->removeAxis(axis);
            }
        }
        if (graphs.isEmpty()) {
            Plot::setAxisColor(defaultValueAxis, QPen(Qt::black));
        }
        QList<QCPAxis*> bottomAxes = axisRect->axes(QCPAxis::atBottom);
        QList<QCPAxis*> leftRightAxes = axisRect->axes(QCPAxis::atLeft | QCPAxis::atRight);
        axisRect->setRangeDragAxes(bottomAxes, leftRightAxes);
        axisRect->setRangeZoomAxes(bottomAxes, leftRightAxes);
        getGraphInfo();
    }
    if (ui->actionLogScale->isChecked()) {
        on_actionLogScale_triggered(true);
    }
    else {
        auto_axes_ ? resetAxes() : ui->plot->replot();
    }
}

void PlotDialog::copyAsCsvClicked()
{
    QString csv;
    QTextStream stream(&csv, QIODevice::Text);
    if (makeCsv(stream)) {
        mainApp->clipboard()->setText(stream.readAll());
    }
    else {
        report_warning("Error exporting plot as CSV. Please select one visible plot.");
    }
}

bool PlotDialog::makeCsv(QTextStream& stream) const
{
    QModelIndexList selectedRows = ui->plotUat->selectionModel()->selectedRows();
    if (selectedRows.size() == 1) { // We can only export one plot at a time
        const Plot* plot = plots_.value(selectedRows.constFirst().row(), Q_NULLPTR);
        if (plot && plot->visible()) {
            plot->makeCsv(stream);
            return true;
        }
    }
    return false;
}

void PlotDialog::addDataPointsMarkers()
{
    if (ui->actionShowDataPointMarker->isChecked()) {
        for (const Plot* plot : plots_) {
            if(plot)
                ui->plot->addDataPointsMarker(plot->graph());
        }
    }
}
