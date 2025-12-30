/* io_graph_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define WS_LOG_DOMAIN LOG_DOMAIN_QTUI
#include "io_graph_dialog.h"
#include <ui_io_graph_dialog.h>

#include "file.h"
#include "locale.h"

#include <epan/uat-int.h>
#include <epan/stat_tap_ui.h>

#include <wsutil/utf8_entities.h>
#include <wsutil/ws_assert.h>
#include <app/application_flavor.h>
#include <wsutil/report_message.h>
#include <wsutil/nstime.h>
#include <wsutil/to_str.h>

#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/variant_pointer.h>
#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/tango_colors.h> //provides some default colors
#include <ui/qt/widgets/qcustomplot.h>
#include <ui/qt/widgets/qcp_string_legend_item.h>
#include <ui/qt/widgets/qcp_axis_ticker_si.h>
#include <ui/qt/widgets/copy_from_profile_button.h>
#include <ui/qt/widgets/wireshark_file_dialog.h>
#include <ui/qt/main_window.h>

#include "progress_frame.h"
#include "main_application.h"

#include <QPushButton>
#include <QRubberBand>
#include <QTimer>
#include <QVariant>

// Bugs and uncertainties:
// - Regular (non-stacked) bar graphs are drawn on top of each other on the Z axis.
//   The QCP forum suggests drawing them side by side:
//   https://www.qcustomplot.com/index.php/support/forum/62
// - We retap and redraw more than we should.
// - Smoothing doesn't seem to match GTK+
// - Closing the color picker on macOS sends the dialog to the background.
// - X-axis time buckets are based on the file relative time, even in
//   Time of Day / absolute time mode. (See io_graph_item.c/get_io_graph_index)
//   Changing this would mean retapping when switching to ToD mode, though.

// To do:
// - Use scroll bars?
//   https://www.qcustomplot.com/index.php/tutorials/specialcases/scrollbar
// - Scroll during live captures (currently the graph auto rescales instead)
// - Set ticks per pixel (e.g. pressing "2" sets 2 tpp).
// - Explicitly handle missing values, e.g. via NAN.
// - Add a "show missing" or "show zero" option to the UAT?
//   It would add yet another graph configuration column.
// - Increase max number of items (or make configurable)
// - Dark Mode support, e.g.
//   https://www.qcustomplot.com/index.php/demos/barchartdemo
// - Multiple y-axes?
//   https://www.qcustomplot.com/index.php/demos/multiaxisdemo
//   https://www.qcustomplot.com/index.php/tutorials/specialcases/axistags

// Don't accidentally zoom into a 1x1 rect if you happen to click on the graph
// in zoom mode.
const int min_zoom_pixels_ = 20;

const int stat_update_interval_ = 200; // ms

const value_string moving_avg_vs[] = {
    { 0, "None" },
    { 10, "10 interval SMA" },
    { 20, "20 interval SMA" },
    { 50, "50 interval SMA" },
    { 100, "100 interval SMA" },
    { 200, "200 interval SMA" },
    { 500, "500 interval SMA" },
    { 1000, "1000 interval SMA" },
    { 0, NULL }
};

static io_graph_settings_t *iog_settings_;
static unsigned num_io_graphs_;
static uat_t *iog_uat_;
// XXX - Multiple UatModels with the same uat can crash if one is
// edited, because the underlying uat_t* data changes but the
// record_errors and dirty_records lists do not.
static QPointer<UatModel> static_uat_model_;

// y_axis_factor was added in 3.6. asAOT in 4.6/5.0 Provide backward compatibility.
static const char *iog_uat_defaults_[] = {
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "1", "false"
};

static char *decimal_point;

extern "C" {

//"Custom" handler for sma_period enumeration for backwards compatibility
void io_graph_sma_period_set_cb(void* rec, const char* buf, unsigned len, const void* vs, const void* u2 _U_)
{
    unsigned i;
    char* str = g_strndup(buf,len);
    const char* cstr;
    ((io_graph_settings_t*)rec)->sma_period = 0;

    //Original UAT had just raw numbers and not enumerated values with "interval SMA"
    if (strstr(str, "interval SMA") == NULL) {
        if (strcmp(str, "None") == 0) {    //Valid enumerated value
        } else if (strcmp(str, "0") == 0) {
            g_free(str);
            str = g_strdup("None");
        } else {
            char *str2 = ws_strdup_printf("%s interval SMA", str);
            g_free(str);
            str = str2;
        }
    }

    for (i=0; (cstr = ((const value_string*)vs)[i].strptr) ;i++) {
        if (g_str_equal(cstr,str)) {
            ((io_graph_settings_t*)rec)->sma_period = (uint32_t)((const value_string*)vs)[i].value;
            g_free(str);
            return;
        }
    }
    g_free(str);
}
//Duplicated because macro covers both functions
void io_graph_sma_period_tostr_cb(void* rec, char** out_ptr, unsigned* out_len, const void* vs, const void* u2 _U_)
{
    unsigned i;
    for (i=0;((const value_string*)vs)[i].strptr;i++) {
        if (((const value_string*)vs)[i].value == ((io_graph_settings_t*)rec)->sma_period) {
            *out_ptr = g_strdup(((const value_string*)vs)[i].strptr);
            *out_len = (unsigned)strlen(*out_ptr);
            return;
        }
    }
    *out_ptr = g_strdup("None");
    *out_len = (unsigned)strlen("None");
}

bool sma_period_chk_enum(void* u1 _U_, const char* strptr, unsigned len, const void* v, const void* u3 _U_, char** err) {
    char *str = g_strndup(strptr,len);
    unsigned i;
    const value_string* vs = (const value_string *)v;

    //Original UAT had just raw numbers and not enumerated values with "interval SMA"
    if (strstr(str, "interval SMA") == NULL) {
        if (strcmp(str, "None") == 0) {    //Valid enumerated value
        } else if (strcmp(str, "0") == 0) {
            g_free(str);
            str = g_strdup("None");
        } else {
            char *str2 = ws_strdup_printf("%s interval SMA", str);
            g_free(str);
            str = str2;
        }
    }

    for (i=0;vs[i].strptr;i++) {
        if (g_strcmp0(vs[i].strptr,str) == 0) {
            *err = NULL;
            g_free(str);
            return true;
        }
    }

    *err = ws_strdup_printf("invalid value: %s",str);
    g_free(str);
    return false;
}

static void* io_graph_copy_cb(void* dst_ptr, const void* src_ptr, size_t) {
    io_graph_settings_t* dst = (io_graph_settings_t *)dst_ptr;
    const io_graph_settings_t* src = (const io_graph_settings_t *)src_ptr;

    dst->enabled = src->enabled;
    dst->asAOT = src->asAOT;
    dst->name = g_strdup(src->name);
    dst->dfilter = g_strdup(src->dfilter);
    dst->color = src->color;
    dst->style = src->style;
    dst->yaxis = src->yaxis;
    dst->yfield = g_strdup(src->yfield);
    dst->sma_period = src->sma_period;
    dst->y_axis_factor = src->y_axis_factor;

    return dst;
}

static void io_graph_free_cb(void* p) {
    io_graph_settings_t *iogs = (io_graph_settings_t *)p;
    g_free(iogs->name);
    g_free(iogs->dfilter);
    g_free(iogs->yfield);
}

// If the uat changes outside the model, e.g. when changing profiles,
// we need to tell the UatModel.
static void io_graph_post_update_cb() {
    if (static_uat_model_) {
        static_uat_model_->reloadUat();
    }
}

} // extern "C"

IOGraphDialog::IOGraphDialog(QWidget &parent, CaptureFile &cf, const char* type_unit_name) :
    WiresharkDialog(parent, cf),
    ui(new Ui::IOGraphDialog),
    uat_model_(nullptr),
    uat_delegate_(nullptr),
    base_graph_(nullptr),
    tracer_(nullptr),
    start_time_(NSTIME_INIT_ZERO),
    mouse_drags_(true),
    rubber_band_(nullptr),
    stat_timer_(nullptr),
    need_replot_(false),
    need_retap_(false),
    auto_axes_(true),
    type_unit_name_(type_unit_name),
    number_ticker_(new QCPAxisTicker),
    datetime_ticker_(new QCPAxisTickerDateTime)
{
    ui->setupUi(this);
    ui->hintLabel->setSmallText();
    loadGeometry();

    setWindowSubtitle(tr("I/O Graphs"));
    setAttribute(Qt::WA_DeleteOnClose, true);
    QCustomPlot *iop = ui->ioPlot;

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

    QPushButton *save_bt = ui->buttonBox->button(QDialogButtonBox::Save);
    save_bt->setText(tr("Save As…"));

    QPushButton *copy_bt = ui->buttonBox->addButton(tr("Copy"), QDialogButtonBox::ActionRole);
    connect (copy_bt, SIGNAL(clicked()), this, SLOT(copyAsCsvClicked()));

    copy_profile_bt_ = new CopyFromProfileButton(this, "io_graphs", tr("Copy graphs from another profile."));
    ui->buttonBox->addButton(copy_profile_bt_, QDialogButtonBox::ActionRole);
    connect(copy_profile_bt_, &CopyFromProfileButton::copyProfile, this, &IOGraphDialog::copyFromProfile);

    QPushButton *close_bt = ui->buttonBox->button(QDialogButtonBox::Close);
    if (close_bt) {
        close_bt->setDefault(true);
    }

    connect(ui->buttonBox, &QDialogButtonBox::clicked, this, &IOGraphDialog::buttonBoxClicked);

    ui->automaticUpdateCheckBox->setChecked(prefs.gui_io_graph_automatic_update ? true : false);

    ui->actionLegend->setChecked(prefs.gui_io_graph_enable_legend);
    connect(ui->actionLegend, &QAction::triggered, this, &IOGraphDialog::actionLegendTriggered);
    connect(ui->actionTimeOfDay, &QAction::triggered, this, &IOGraphDialog::actionTimeOfDayTriggered);
    connect(ui->actionLogScale, &QAction::triggered, this, &IOGraphDialog::actionLogScaleTriggered);

    stat_timer_ = new QTimer(this);
    connect(stat_timer_, SIGNAL(timeout()), this, SLOT(updateStatistics()));
    stat_timer_->start(stat_update_interval_);

    // Intervals (ms)
    // #6441 asks for arbitrary values. We could probably do that with
    // a QSpinBox, e.g. using QAbstractSpinBox::AdaptiveDecimalStepType
    // or similar (it only exists starting in Qt 5.12) and suffix(),
    // or something fancier with valueFromText() and textFromValue() to
    // convert to and from SI prefixes.
    ui->intervalComboBox->addItem(tr("1 μs"),   SCALE / 1000000);
    ui->intervalComboBox->addItem(tr("2 μs"),   SCALE / 500000);
    ui->intervalComboBox->addItem(tr("5 μs"),   SCALE / 200000);
    ui->intervalComboBox->addItem(tr("10 μs"),  SCALE / 100000);
    ui->intervalComboBox->addItem(tr("20 μs"),  SCALE / 50000);
    ui->intervalComboBox->addItem(tr("50 μs"),  SCALE / 20000);
    ui->intervalComboBox->addItem(tr("100 μs"), SCALE / 10000);
    ui->intervalComboBox->addItem(tr("200 μs"), SCALE / 5000);
    ui->intervalComboBox->addItem(tr("500 μs"), SCALE / 2000);
    ui->intervalComboBox->addItem(tr("1 ms"),   SCALE / 1000);
    ui->intervalComboBox->addItem(tr("2 ms"),   SCALE / 500);
    ui->intervalComboBox->addItem(tr("5 ms"),   SCALE / 200);
    ui->intervalComboBox->addItem(tr("10 ms"),  SCALE / 100);
    ui->intervalComboBox->addItem(tr("20 ms"),  SCALE / 50);
    ui->intervalComboBox->addItem(tr("50 ms"),  SCALE / 20);
    ui->intervalComboBox->addItem(tr("100 ms"), SCALE / 10);
    ui->intervalComboBox->addItem(tr("200 ms"), SCALE / 5);
    ui->intervalComboBox->addItem(tr("500 ms"), SCALE / 2);
    ui->intervalComboBox->addItem(tr("1 sec"),  SCALE);
    ui->intervalComboBox->addItem(tr("2 sec"),  SCALE * 2);
    ui->intervalComboBox->addItem(tr("5 sec"),  SCALE * 5);
    ui->intervalComboBox->addItem(tr("10 sec"), SCALE * 10);
    ui->intervalComboBox->addItem(tr("1 min"),  SCALE * 60);
    ui->intervalComboBox->addItem(tr("2 min"),  SCALE * 120);
    ui->intervalComboBox->addItem(tr("5 min"),  SCALE * 300);
    ui->intervalComboBox->addItem(tr("10 min"), SCALE * 600);
    ui->intervalComboBox->setCurrentIndex(18);

    iop->xAxis->setTicker(number_ticker_);

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
    ctx_menu_.addAction(ui->actionTimeOfDay);
    ctx_menu_.addAction(ui->actionLogScale);
    ctx_menu_.addAction(ui->actionCrosshairs);
    ctx_menu_.addAction(ui->actionLegend);
    set_action_shortcuts_visible_in_context_menu(ctx_menu_.actions());

    iop->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(iop, &QCustomPlot::customContextMenuRequested, this, &IOGraphDialog::showContextMenu);

    iop->xAxis->setLabel(tr("Time (s)"));

    iop->setMouseTracking(true);
    iop->setEnabled(true);

    tracer_ = new QCPItemTracer(iop);
}

void IOGraphDialog::initialize(QWidget& parent, uat_field_t* io_graph_fields, QString displayFilter, io_graph_item_unit_t value_units, QString yfield, bool is_sibling_dialog, const QVector<QString> convFilters)
{
    QCustomPlot* iop = ui->ioPlot;

    QCPTextElement* title = new QCPTextElement(iop);
    iop->plotLayout()->insertRow(0);
    iop->plotLayout()->addElement(0, 0, title);
    title->setText(tr("%1 I/O Graphs: %2").arg(application_flavor_name_proper())
                                          .arg(cap_file_.fileDisplayName()));

    /* Depending on how the dialog was called (Main Window/Conversations),
     * we will display from the Profile & Display Filter or from selected convs.
     * This distinction is brought by is_sibling_dialog (True for dialogs).
     */
    loadProfileGraphs(io_graph_fields);
    if (!is_sibling_dialog) {
        bool filterExists = false;
        if (uat_model_->rowCount() > 0) {
            for (int i = 0; i < uat_model_->rowCount(); i++) {
                createIOGraph(i);
                IOGraph *iog = ioGraphs_.at(i);
                if (iog->filter().compare(displayFilter) == 0 &&
                    iog->valueUnitField().compare(yfield) == 0 &&
                    iog->valueUnits() == value_units) {
                    filterExists = true;
                }
            }
        } else {
            addDefaultGraph(true, 0);
            addDefaultGraph(true, 1);
        }

        if (! filterExists && (!displayFilter.isEmpty() || !yfield.isEmpty())) {
            addGraph(true, false, displayFilter, value_units, yfield);
        }
    }
    else {
        /* If the display filter was propagated up to here (presence of a display filter in the main window and
         * checkbox enabled on the conversation dialog), we are performing a 'graph disaggregation' : we are
         * displaying both the filtered packets and (some/all of) their related selected conversations.
         */
        if (uat_model_->rowCount() > 0) {
            for (int i = 0; i < uat_model_->rowCount(); i++) {
                createIOGraph(i);
            }
        }
        else {
            addDefaultGraph(true, 0);
            addDefaultGraph(true, 1);
        }
        /* Filtered packets */
        if (!displayFilter.isEmpty() || !yfield.isEmpty()) {
            addGraph(true, false, displayFilter, value_units, yfield);
        }
        /* selected conversations from a sibling dialog (typically conversations dialog) */
        for (int i = 0; i < convFilters.size(); ++i) {
            addGraph(true, false, convFilters.at(i), convFilters.at(i), ColorUtils::graphColor(uat_model_->rowCount()),
                IOGraph::psLine, IOG_ITEM_UNIT_PACKETS, QString(), DEFAULT_MOVING_AVERAGE, DEFAULT_Y_AXIS_FACTOR);
        }
    }

    toggleTracerStyle(true);
    iop->setFocus();

    iop->rescaleAxes();

    ui->clearToolButton->setEnabled(uat_model_->rowCount() != 0);

    ui->splitter->setStretchFactor(0, 95);
    ui->splitter->setStretchFactor(1, 5);
    loadSplitterState(ui->splitter);

    //XXX - resize columns?
    //ui->graphUat->header()->resizeSections(QHeaderView::ResizeToContents);

    ProgressFrame::addToButtonBox(ui->buttonBox, &parent);

    connect(iop, SIGNAL(mousePress(QMouseEvent*)), this, SLOT(graphClicked(QMouseEvent*)));
    connect(iop, SIGNAL(mouseMove(QMouseEvent*)), this, SLOT(mouseMoved(QMouseEvent*)));
    connect(iop, SIGNAL(mouseRelease(QMouseEvent*)), this, SLOT(mouseReleased(QMouseEvent*)));

    connect(iop, &QCustomPlot::beforeReplot, this, &IOGraphDialog::updateLegend);

    MainWindow *main_window = mainApp->mainWindow();
    if (main_window != nullptr) {
        connect(main_window, &MainWindow::framesSelected, this, &IOGraphDialog::selectedFrameChanged);
    }
}

IOGraphDialog::~IOGraphDialog()
{
    cap_file_.stopLoading();
    foreach(IOGraph* iog, ioGraphs_) {
        delete iog;
    }
    delete ui;
    ui = NULL;
}

void IOGraphDialog::copyFromProfile(QString filename)
{
    if (uat_model_ == nullptr)
        return;

    char *err = NULL;
    // uat_load appends rows to the current UAT, using filename.
    // We should let the UatModel handle it, and have the UatModel
    // call beginInsertRows() and endInsertRows(), so that we can
    // just add the new rows instead of resetting the information.
    if (uat_load(iog_uat_, filename.toUtf8().constData(), application_configuration_environment_prefix(), &err)) {
        iog_uat_->changed = true;
        // uat_load calls the post update cb, which reloads the Uat.
        //uat_model_->reloadUat();
    } else {
        report_failure("Error while loading %s: %s", iog_uat_->name, err);
        g_free(err);
        // On failure, uat_load does not call the post update cb.
        // Some errors are non-fatal (a record was added but failed
        // validation.)
        uat_model_->reloadUat();
    }
}

QString IOGraphDialog::getFilteredName() const
{
    return tr("Filtered packets");
}

QString IOGraphDialog::getXAxisName() const
{
    return tr("All packets");
}

const char* IOGraphDialog::getYAxisName(io_graph_item_unit_t value_units) const
{
    return val_to_str_const(value_units, y_axis_packet_vs, "Packets");
}

QString IOGraphDialog::getYFieldName(io_graph_item_unit_t value_units, const QString& yfield) const
{
    return QString(val_to_str_const(value_units, y_axis_packet_vs, "Unknown")).replace("Y Field", yfield);
}

void IOGraphDialog::addGraph(bool checked, bool asAOT, QString name, QString dfilter, QRgb color_idx, IOGraph::PlotStyles style, io_graph_item_unit_t value_units, QString yfield, int moving_average, double y_axis_factor)
{
    if (uat_model_ == nullptr)
        return;

    QVariantList newRowData;
    newRowData.append(checked ? Qt::Checked : Qt::Unchecked);
    newRowData.append(name);
    newRowData.append(dfilter);
    newRowData.append(QColor(color_idx));
    newRowData.append(val_to_str_const(style, io_graph_style_vs, "None"));
    newRowData.append(getYAxisName(value_units));
    newRowData.append(yfield);
    newRowData.append(val_to_str_const((uint32_t) moving_average, moving_avg_vs, "None"));
    newRowData.append(y_axis_factor);
    newRowData.append(asAOT ? Qt::Checked : Qt::Unchecked);

    QModelIndex newIndex = uat_model_->appendEntry(newRowData);
    if ( !newIndex.isValid() )
    {
        qDebug() << "Failed to add a new record";
        return;
    }
    ui->graphUat->setCurrentIndex(newIndex);
}

void IOGraphDialog::addGraph(bool checked, bool asAOT, QString dfilter, io_graph_item_unit_t value_units, QString yfield)
{
    if (uat_model_ == nullptr)
        return;

    QString graph_name;
    if (yfield.isEmpty()) {
        if (!dfilter.isEmpty()) {
            graph_name = getFilteredName();
        } else {
            graph_name = getXAxisName();
        }
    } else {
        graph_name = getYFieldName(value_units, yfield);
    }
    addGraph(checked, asAOT, std::move(graph_name), dfilter, ColorUtils::graphColor(uat_model_->rowCount()),
        IOGraph::psLine, value_units, yfield, DEFAULT_MOVING_AVERAGE, DEFAULT_Y_AXIS_FACTOR);
}

void IOGraphDialog::addGraph(bool copy_from_current)
{
    if (uat_model_ == nullptr)
        return;

    const QModelIndex &current = ui->graphUat->currentIndex();
    if (copy_from_current && !current.isValid())
        return;

    QModelIndex copyIdx;

    if (copy_from_current) {
        copyIdx = uat_model_->copyRow(current);
        if (!copyIdx.isValid())
        {
            qDebug() << "Failed to add a new record";
            return;
        }
        ui->graphUat->setCurrentIndex(copyIdx);
    } else {
        addDefaultGraph(false);
        copyIdx = uat_model_->index(uat_model_->rowCount() - 1, 0);
    }

    ui->graphUat->setCurrentIndex(copyIdx);
}

void IOGraphDialog::createIOGraph(int currentRow)
{
    // XXX - Should IOGraph have its own list that has to sync with UAT?
    ioGraphs_.insert(currentRow, new IOGraph(ui->ioPlot, type_unit_name_));
    IOGraph* iog = ioGraphs_[currentRow];

    connect(this, &IOGraphDialog::recalcGraphData, iog, &IOGraph::recalcGraphData);
    connect(this, &IOGraphDialog::reloadValueUnitFields, iog, &IOGraph::reloadValueUnitField);
    connect(&cap_file_, &CaptureFile::captureEvent, iog, &IOGraph::captureEvent);
    connect(iog, &IOGraph::requestRetap, this, [=]() { scheduleRetap(); });
    connect(iog, &IOGraph::requestRecalc, this, [=]() { scheduleRecalc(); });
    connect(iog, &IOGraph::requestReplot, this, [=]() { scheduleReplot(); });

    syncGraphSettings(currentRow);
    iog->setNeedRetap(true);
}

void IOGraphDialog::addDefaultGraph(bool enabled, int idx)
{
    switch (idx % 2) {
    case 0:
        addGraph(enabled, false, tr("All Packets"), QString(), ColorUtils::graphColor(idx),
                IOGraph::psLine, IOG_ITEM_UNIT_PACKETS, QString(), DEFAULT_MOVING_AVERAGE, DEFAULT_Y_AXIS_FACTOR);
        break;
    default:
        addGraph(enabled, false, tr("TCP Errors"), "tcp.analysis.flags", ColorUtils::graphColor(4), // 4 = red
                IOGraph::psBar, IOG_ITEM_UNIT_PACKETS, QString(), DEFAULT_MOVING_AVERAGE, DEFAULT_Y_AXIS_FACTOR);
        break;
    }
}

int IOGraphDialog::getYAxisValue(const QString& data)
{
    return (int) str_to_val(qUtf8Printable(data), y_axis_packet_vs, IOG_ITEM_UNIT_PACKETS);
}

// Sync the settings from UAT model to its IOGraph.
// Disables the graph if any errors are found.
//
// NOTE: Setting dfilter, yaxis and yfield here will all end up in setFilter() and this
//       has a chicken-and-egg problem because setFilter() depends on previous assigned
//       values for filter_, val_units_ and vu_field_.  Setting values in wrong order
//       may give unpredicted results because setFilter() does not always set filter_
//       on errors.
// TODO: The issues in the above note should be fixed and setFilter() should not be
//       called so frequently.

void IOGraphDialog::syncGraphSettings(int row)
{
    IOGraph *iog = ioGraphs_.value(row, Q_NULLPTR);

    if (!uat_model_ || !uat_model_->index(row, colEnabled).isValid() || !iog)
        return;

    bool visible = graphIsEnabled(row);
    QString data_str;

    iog->setName(uat_model_->data(uat_model_->index(row, colName)).toString());
    iog->setFilter(uat_model_->data(uat_model_->index(row, colDFilter)).toString());

    bool asAOT = graphAsAOT(row);
    iog->setAOT(asAOT);

    /* plot style depend on the value unit, so set it first. */
    data_str = uat_model_->data(uat_model_->index(row, colYAxis)).toString();
    iog->setValueUnits(getYAxisValue(data_str));
    iog->setValueUnitField(uat_model_->data(uat_model_->index(row, colYField)).toString());

    iog->setColor(uat_model_->data(uat_model_->index(row, colColor), Qt::DecorationRole).value<QColor>().rgb());
    data_str = uat_model_->data(uat_model_->index(row, colStyle)).toString();
    iog->setPlotStyle((IOGraph::PlotStyles) str_to_val(qUtf8Printable(data_str), io_graph_style_vs, 0));

    data_str = uat_model_->data(uat_model_->index(row, colSMAPeriod)).toString();
    iog->moving_avg_period_ = str_to_val(qUtf8Printable(data_str), moving_avg_vs, 0);

    iog->setYAxisFactor(uat_model_->data(uat_model_->index(row, colYAxisFactor)).toDouble());

    iog->setInterval(ui->intervalComboBox->itemData(ui->intervalComboBox->currentIndex()).toInt());

    if (!iog->configError().isEmpty()) {
        hint_err_ = iog->configError();
        visible = false;
    } else {
        hint_err_.clear();
    }

    iog->setVisible(visible);

    getGraphInfo();
    updateHint();

    if (visible) {
        scheduleReplot();
    }
}

qsizetype IOGraphDialog::graphCount() const
{
    return uat_model_ ? uat_model_->rowCount() : ioGraphs_.size();
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

void IOGraphDialog::captureFileClosing()
{
    // The other buttons will be disabled when the model is set to null.
    ui->newToolButton->setEnabled(false);
    ui->intervalComboBox->setEnabled(false);
    copy_profile_bt_->setEnabled(false);
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
    ui->graphUat->setModel(nullptr);
    ui->graphUat->setVisible(false);
    WiresharkDialog::captureFileClosing();
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
        if (event->modifiers() & Qt::ShiftModifier) {
            zoomXAxis(false);   // upper case X -> Zoom out
        } else {
            zoomXAxis(true);    // lower case x -> Zoom in
        }
        break;
    case Qt::Key_Y:             // Zoom Y axis only
        if (event->modifiers() & Qt::ShiftModifier) {
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

void IOGraphDialog::applyChanges()
{
    if (!static_uat_model_)
        return;

    // Changes to the I/O Graphs settings are always saved,
    // there is no possibility for "rejection".
    QString error;
    if (static_uat_model_->applyChanges(error)) {
        if (!error.isEmpty()) {
            report_failure("%s", qPrintable(error));
        }
    }
}

void IOGraphDialog::reject()
{
    if (uat_model_)
        applyChanges();

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

// Returns the IOGraph which is most likely to be used by the user. This is the
// currently selected, visible graph or the first visible graph otherwise.
IOGraph *IOGraphDialog::currentActiveGraph() const
{
    QModelIndex index = ui->graphUat->currentIndex();
    if (index.isValid() && graphIsEnabled(index.row())) {
        return ioGraphs_.value(index.row(), NULL);
    }

    //if no currently selected item, go with first item enabled
    for (int row = 0; row < graphCount(); row++)
    {
        if (graphIsEnabled(row)) {
            return ioGraphs_.value(row, NULL);
        }
    }

    return NULL;
}

bool IOGraphDialog::graphIsEnabled(int row) const
{
    if (uat_model_) {
        Qt::CheckState state = static_cast<Qt::CheckState>(uat_model_->data(uat_model_->index(row, colEnabled), Qt::CheckStateRole).toInt());
        return state == Qt::Checked;
    } else {
        IOGraph* iog = ioGraphs_.value(row, nullptr);
        return (iog && iog->visible());
    }
}

bool IOGraphDialog::graphAsAOT(int row) const
{
    if (uat_model_) {
        Qt::CheckState state = static_cast<Qt::CheckState>(uat_model_->data(uat_model_->index(row, colAOT), Qt::CheckStateRole).toInt());
        return state == Qt::Checked;
    } else {
        IOGraph* iog = ioGraphs_.value(row, nullptr);
        return (iog && iog->getAOT());
    }
}

// Scan through our graphs and gather information.
// QCPItemTracers can only be associated with QCPGraphs. Find the first one
// and associate it with our tracer. Set bar stacking order while we're here.
void IOGraphDialog::getGraphInfo()
{
    base_graph_ = NULL;
    QCPBars *prev_bars = NULL;
    nstime_set_zero(&start_time_);

    tracer_->setGraph(NULL);
    IOGraph *selectedGraph = currentActiveGraph();

    if (uat_model_ != NULL) {
        //all graphs may not be created yet, so bounds check the graph array
        for (int row = 0; row < uat_model_->rowCount(); row++) {
            IOGraph* iog = ioGraphs_.value(row, Q_NULLPTR);
            if (iog && graphIsEnabled(row)) {
                QCPGraph *graph = iog->graph();
                QCPBars *bars = iog->bars();
                if (graph && (!base_graph_ || iog == selectedGraph)) {
                    base_graph_ = graph;
                } else if (bars &&
                           (uat_model_->data(uat_model_->index(row, colStyle), Qt::DisplayRole).toString().compare(io_graph_style_vs[IOGraph::psStackedBar].strptr) == 0) &&
                           iog->visible()) {
                    bars->moveBelow(NULL); // Remove from existing stack
                    bars->moveBelow(prev_bars);
                    prev_bars = bars;
                }
                if (iog->visible() && iog->maxInterval() >= 0) {
                    nstime_t iog_start = iog->startTime();
                    if (nstime_is_zero(&start_time_) || nstime_cmp(&iog_start, &start_time_) < 0) {
                        nstime_copy(&start_time_, &iog_start);
                    }
                }

            }
        }
    }
    if (base_graph_ && base_graph_->data()->size() > 0) {
        tracer_->setGraph(base_graph_);
        tracer_->setVisible(true);
    }
}

QString IOGraphDialog::getNoDataHint() const
{
    return tr("No packets in interval");
}

QString IOGraphDialog::getHintText(unsigned num_items) const
{
    return QStringLiteral("%1 %2")
        .arg(!file_closed_ ? tr("Click to select packet") : tr("Packet"))
        .arg(num_items);
}

void IOGraphDialog::updateHint()
{
    QCustomPlot *iop = ui->ioPlot;
    QString hint;

    // XXX: ElidedLabel doesn't support rich text / HTML, we
    // used to bold this error
    if (!hint_err_.isEmpty()) {
        hint += QStringLiteral("%1 ").arg(hint_err_);
    }
    if (mouse_drags_) {
        double ts = 0;
        packet_num_ = 0;
        int interval_packet = -1;

        if (tracer_->graph()) {
            ts = tracer_->position->key();
            if (IOGraph *iog = currentActiveGraph()) {
                interval_packet = iog->packetFromTime(ts - nstime_to_sec(&start_time_));
            }
        }

        if (interval_packet < 0) {
            hint += tr("Hover over the graph for details.");
        } else {
            QString msg = getNoDataHint();
            QString val;
            if (interval_packet > 0) {
                packet_num_ = (uint32_t) interval_packet;
                msg = getHintText(packet_num_);
                val = QStringLiteral(" = %1").arg(tracer_->position->value(), 0, 'g', 4);
            }
            // XXX - If Time of Day is selected, should we use ISO 8601
            // timestamps or something similar here instead of epoch time?
            hint += tr("%1 (%2s%3).")
                    .arg(msg)
                    .arg(QString::number(ts, 'f', precision_))
                    .arg(val);
        }
        iop->replot(QCustomPlot::rpQueuedReplot);
    } else {
        if (rubber_band_ && rubber_band_->isVisible()) {
            QRectF zoom_ranges = getZoomRanges(rubber_band_->geometry());
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

    ui->hintLabel->setText(hint);
}

void IOGraphDialog::updateLegend()
{
    QCustomPlot *iop = ui->ioPlot;
    QSet<format_size_units_e> format_units_set;
    QSet<QString> vu_label_set;
    QString intervalText = ui->intervalComboBox->itemText(ui->intervalComboBox->currentIndex());
    QSet<bool> aot_set;

    iop->legend->setVisible(false);
    iop->yAxis->setLabel(QString());

    // Find unique labels
    for (int row = 0; row < graphCount(); row++) {
        IOGraph *iog = ioGraphs_.value(row, Q_NULLPTR);
        if (graphIsEnabled(row) && iog) {
            QString label(iog->valueUnitLabel());
            vu_label_set.insert(label);
            format_units_set.insert(iog->formatUnits());

            /* Track "as throughput" checkboxes values */
            io_graph_item_unit_t vu = iog->valueUnits();
            switch(vu) {
                case IOG_ITEM_UNIT_PACKETS:
                case IOG_ITEM_UNIT_BYTES:
                case IOG_ITEM_UNIT_BITS:
                    aot_set.insert(iog->getAOT());
                    break;
                default:
                    break;
            }
        }
    }

    // Nothing.
    if (vu_label_set.size() < 1) {
        iop->legend->layer()->replot();
        return;
    }

    format_size_units_e format_units = FORMAT_SIZE_UNIT_NONE;
    if (format_units_set.size() == 1) {
        format_units = format_units_set.values().constFirst();
    }

    QSharedPointer<QCPAxisTickerSi> si_ticker = qSharedPointerDynamicCast<QCPAxisTickerSi>(iop->yAxis->ticker());
    if (format_units != FORMAT_SIZE_UNIT_NONE) {
        if (si_ticker) {
            si_ticker->setUnit(format_units);
        } else {
            iop->yAxis->setTicker(QSharedPointer<QCPAxisTickerSi>(new QCPAxisTickerSi(format_units, QString(), ui->actionLogScale->isChecked())));
        }
    } else {
        if (si_ticker) {
            if (ui->actionLogScale->isChecked()) {
                iop->yAxis->setTicker(QSharedPointer<QCPAxisTickerLog>(new QCPAxisTickerLog));
            } else {
                iop->yAxis->setTicker(QSharedPointer<QCPAxisTicker>(new QCPAxisTicker));
            }
       }
    }

    // All the same. Use the Y Axis label.
    if ((vu_label_set.size() == 1) && (aot_set.size() == 1)) {
        if(aot_set.contains(1)) {
            // "as throughput" was requested
            iop->yAxis->setLabel(vu_label_set.values().constFirst() + "/s");
        }
        else {
            iop->yAxis->setLabel(vu_label_set.values().constFirst() + "/" + intervalText);
        }
    }

    // Create a legend with a Title label at top.
    // Legend Title thanks to: https://www.qcustomplot.com/index.php/support/forum/443
    iop->legend->clearItems();
    QCPStringLegendItem *legendTitle = new QCPStringLegendItem(iop->legend, tr("%1 Intervals ").arg(intervalText));
    iop->legend->insertRow(0);
    iop->legend->addElement(0, 0, legendTitle);

    for (int row = 0; row < graphCount(); row++) {
        IOGraph *iog = ioGraphs_.value(row, Q_NULLPTR);
        if (iog) {
            if (graphIsEnabled(row)) {
                iog->addToLegend();
            }
        }
    }

    // Only show legend if the user requested it
    if (prefs.gui_io_graph_enable_legend) {
        iop->legend->setVisible(true);
    }
    else {
        iop->legend->setVisible(false);
    }
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

void IOGraphDialog::showContextMenu(const QPoint &pos)
{
    if (ui->ioPlot->legend->selectTest(pos, false) >= 0) {
        // XXX - Should we check if the legend is visible before showing
        // its context menu instead of the main context menu?
        QMenu *menu = new QMenu(this);
        menu->setAttribute(Qt::WA_DeleteOnClose);
        menu->addAction(ui->actionLegend);
        menu->addSeparator();
#if QT_VERSION >= QT_VERSION_CHECK(6, 2, 0)
        menu->addAction(tr("Move to top left"), this, &IOGraphDialog::moveLegend)->setData((Qt::AlignTop|Qt::AlignLeft).toInt());
        menu->addAction(tr("Move to top center"), this, &IOGraphDialog::moveLegend)->setData((Qt::AlignTop|Qt::AlignHCenter).toInt());
        menu->addAction(tr("Move to top right"), this, &IOGraphDialog::moveLegend)->setData((Qt::AlignTop|Qt::AlignRight).toInt());
        menu->addAction(tr("Move to bottom left"), this, &IOGraphDialog::moveLegend)->setData((Qt::AlignBottom|Qt::AlignLeft).toInt());
        menu->addAction(tr("Move to bottom center"), this, &IOGraphDialog::moveLegend)->setData((Qt::AlignBottom|Qt::AlignHCenter).toInt());
        menu->addAction(tr("Move to bottom right"), this, &IOGraphDialog::moveLegend)->setData((Qt::AlignBottom|Qt::AlignRight).toInt());
#else
        menu->addAction(tr("Move to top left"), this, &IOGraphDialog::moveLegend)->setData(static_cast<Qt::Alignment::Int>(Qt::AlignTop|Qt::AlignLeft));
        menu->addAction(tr("Move to top center"), this, &IOGraphDialog::moveLegend)->setData(static_cast<Qt::Alignment::Int>(Qt::AlignTop|Qt::AlignHCenter));
        menu->addAction(tr("Move to top right"), this, &IOGraphDialog::moveLegend)->setData(static_cast<Qt::Alignment::Int>(Qt::AlignTop|Qt::AlignRight));
        menu->addAction(tr("Move to bottom left"), this, &IOGraphDialog::moveLegend)->setData(static_cast<Qt::Alignment::Int>(Qt::AlignBottom|Qt::AlignLeft));
        menu->addAction(tr("Move to bottom center"), this, &IOGraphDialog::moveLegend)->setData(static_cast<Qt::Alignment::Int>(Qt::AlignBottom|Qt::AlignHCenter));
        menu->addAction(tr("Move to bottom right"), this, &IOGraphDialog::moveLegend)->setData(static_cast<Qt::Alignment::Int>(Qt::AlignBottom|Qt::AlignRight));
#endif
        menu->popup(ui->ioPlot->mapToGlobal(pos));
    } else if (ui->ioPlot->xAxis->selectTest(pos, false, nullptr) >= 0) {
        QMenu *menu = new QMenu(this);
        menu->setAttribute(Qt::WA_DeleteOnClose);
        // XXX - actionToggleTimeOrigin doesn't actually work so don't add it
        menu->addAction(ui->actionTimeOfDay);
        menu->popup(ui->ioPlot->mapToGlobal(pos));
    } else if (ui->ioPlot->yAxis->selectTest(pos, false, nullptr) >= 0) {
        QMenu *menu = new QMenu(this);
        menu->setAttribute(Qt::WA_DeleteOnClose);
        menu->addAction(ui->actionLogScale);
        menu->popup(ui->ioPlot->mapToGlobal(pos));
    } else {
        ctx_menu_.popup(ui->ioPlot->mapToGlobal(pos));
    }
}

void IOGraphDialog::graphClicked(QMouseEvent *event)
{
    QCustomPlot *iop = ui->ioPlot;

    switch (event->button()) {

    case Qt::LeftButton:
        if (mouse_drags_) {
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
        break;

    default:
        if (mouse_drags_) {
            iop->setCursor(QCursor(Qt::OpenHandCursor));
        }
    }
    iop->setFocus();
}

void IOGraphDialog::mouseMoved(QMouseEvent *event)
{
    QCustomPlot *iop = ui->ioPlot;
    Qt::CursorShape shape = Qt::ArrowCursor;

    if (event->buttons().testFlag(Qt::LeftButton)) {
        if (mouse_drags_) {
            // XXX - We might not actually be dragging. QCustomPlot iRangeDrag
            // controls dragging, and it stops dragging when a button other
            // than LeftButton is released (even if LeftButton is held down.)
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

    if (mouse_drags_) {
        if (tracer_->graph()) {
            tracer_->setGraphKey(iop->xAxis->pixelToCoord(event->pos().x()));
        }

    } else {
        if (rubber_band_ && rubber_band_->isVisible()) {
            rubber_band_->setGeometry(QRect(rb_origin_, event->pos()).normalized());
        }
    }

    updateHint();
}

void IOGraphDialog::mouseReleased(QMouseEvent *event)
{
    QCustomPlot *iop = ui->ioPlot;
    auto_axes_ = false;
    if (rubber_band_ && event->button() == Qt::LeftButton) {
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
        // QCustomPlot iRangeDrag controls dragging, and it stops dragging
        // when a button other than LeftButton is released (even if
        // LeftButton is still held down.)
        iop->setCursor(QCursor(Qt::OpenHandCursor));
    }
}

void IOGraphDialog::moveLegend()
{
    if (QAction *contextAction = qobject_cast<QAction*>(sender())) {
        if (contextAction->data().canConvert<Qt::Alignment::Int>()) {
#if QT_VERSION >= QT_VERSION_CHECK(6, 2, 0)
            ui->ioPlot->axisRect()->insetLayout()->setInsetAlignment(0, Qt::Alignment::fromInt(contextAction->data().value<Qt::Alignment::Int>()));
#else
            ui->ioPlot->axisRect()->insetLayout()->setInsetAlignment(0, static_cast<Qt::Alignment>(contextAction->data().value<Qt::Alignment::Int>()));
#endif
            ui->ioPlot->replot();
        }
    }
}

void IOGraphDialog::resetAxes()
{
    QCustomPlot *iop = ui->ioPlot;
    double pixel_pad = 10.0; // per side

    iop->rescaleAxes(true);

    QCPRange x_range = iop->xAxis->scaleType() == QCPAxis::stLogarithmic ?
                iop->xAxis->range().sanitizedForLogScale() : iop->xAxis->range();
    double axis_pixels = iop->xAxis->axisRect()->width();
    iop->xAxis->scaleRange((axis_pixels + (pixel_pad * 2)) / axis_pixels, x_range.center());

    QCPRange y_range = iop->yAxis->scaleType() == QCPAxis::stLogarithmic ?
                iop->yAxis->range().sanitizedForLogScale() : iop->yAxis->range();
    axis_pixels = iop->yAxis->axisRect()->height();
    iop->yAxis->scaleRange((axis_pixels + (pixel_pad * 2)) / axis_pixels, y_range.center());

    auto_axes_ = true;
    iop->replot();
}

void IOGraphDialog::selectedFrameChanged(QList<int> frames)
{
    if (frames.count() == 1 && cap_file_.isValid() && !file_closed_ && tracer_->graph() && cap_file_.packetInfo() != nullptr) {
        packet_info *pinfo = cap_file_.packetInfo();
        if (pinfo->num != packet_num_) {
            // This prevents being triggered by the IOG's own GoToPacketAction,
            // although that is mostly harmless.
            int interval = ui->intervalComboBox->itemData(ui->intervalComboBox->currentIndex()).toInt();

            /*
             * setGraphKey (with Interpolation false, as it is by default)
             * finds the nearest point to the key. Our buckets are derived
             * from rounding down (XXX - which is appropriate for relative
             * time but less so when absolute time of day is selected.)
             * We could call get_io_graph_index() and then multiply to get
             * the exact ts for the bucket, but it's fewer math operations
             * operations simply to subtract half the interval.
             * XXX - Getting the exact value would be superior if we wished
             * to avoid doing anything in the case that the tracer is
             * already pointing at the correct bucket. (Is the hint always
             * correct in that case?)
             */
#if 0
            int64_t idx = get_io_graph_index(pinfo, interval);
            double ts = (double)idx * interval / SCALE_F + nstime_to_sec(&start_time);
#endif
            double key = nstime_to_sec(&pinfo->rel_ts) - (interval / (2 * SCALE_F)) + nstime_to_sec(&start_time_);
            tracer_->setGraphKey(key);
            ui->ioPlot->replot();
            updateHint();
        }
    }
}

void IOGraphDialog::updateStatistics()
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
    if (need_retap_ && !file_closed_ && !retapDepth() && prefs.gui_io_graph_automatic_update) {
        need_retap_ = false;
        QTimer::singleShot(0, &cap_file_, &CaptureFile::retapPackets);
        // The user might have closed the window while tapping, which means
        // we might no longer exist.
    } else {
        if (need_recalc_ && !file_closed_ && prefs.gui_io_graph_automatic_update) {
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

void IOGraphDialog::loadProfileGraphs(uat_field_t* io_graph_fields)
{
    if (iog_uat_ == NULL) {
        iog_uat_ = uat_new("I/O Graphs",
                           sizeof(io_graph_settings_t),
                           "io_graphs",
                           true,
                           &iog_settings_,
                           &num_io_graphs_,
                           0, /* doesn't affect anything that requires a GUI update */
                           "ChStatIOGraphs",
                           io_graph_copy_cb,
                           NULL,
                           io_graph_free_cb,
                           io_graph_post_update_cb,
                           NULL,
                           io_graph_fields);

        uat_set_default_values(iog_uat_, iog_uat_defaults_);

        char* err = NULL;
        if (!uat_load(iog_uat_, NULL, application_configuration_environment_prefix(), &err)) {
            // Some errors are non-fatals (records were added but failed
            // validation.) Since field names sometimes change between
            // verseions, don't erase all the existing graphs.
            if (iog_uat_->raw_data->len) {
                report_failure("Error while loading %s: %s.", iog_uat_->name, err);
                g_free(err);
            } else {
                report_failure("Error while loading %s: %s.  Default graph values will be used", iog_uat_->name, err);
                g_free(err);
                uat_clear(iog_uat_);
            }
        }

        static_uat_model_ = new UatModel(mainApp, iog_uat_);
        connect(mainApp, &MainApplication::profileChanging, IOGraphDialog::applyChanges);
    }

    uat_model_ = static_uat_model_;
    uat_delegate_ = new UatDelegate(ui->graphUat);
    ui->graphUat->setModel(uat_model_);
    ui->graphUat->setItemDelegate(uat_delegate_);
    ui->graphUat->setSelectionMode(QAbstractItemView::ContiguousSelection);

    ui->graphUat->setHeader(new ResizeHeaderView(Qt::Horizontal, ui->graphUat));

    // asAOT was added most recently, so it's in the last section (9).
    // This moves its visual location to the index immediately after Enabled
    // without sacrificing backwards compatibility. The user can move them
    // freely to override this. (We could parse through io_graph_packet_fields
    // to get the indices programmatically if necessary.)
    ui->graphUat->header()->moveSection(colAOT, 1);

    connect(uat_model_, &UatModel::dataChanged, this, &IOGraphDialog::modelDataChanged);
    connect(uat_model_, &UatModel::modelReset, this, &IOGraphDialog::modelRowsReset);
    connect(uat_model_, &UatModel::rowsInserted, this, &IOGraphDialog::modelRowsInserted);
    connect(uat_model_, &UatModel::rowsRemoved, this, &IOGraphDialog::modelRowsRemoved);
    connect(uat_model_, &UatModel::rowsMoved, this, &IOGraphDialog::modelRowsMoved);

    connect(ui->graphUat->selectionModel(), &QItemSelectionModel::selectionChanged, this, &IOGraphDialog::graphUatSelectionChanged);
}

// Slots

void IOGraphDialog::on_intervalComboBox_currentIndexChanged(int)
{
    int interval = ui->intervalComboBox->itemData(ui->intervalComboBox->currentIndex()).toInt();
    bool need_retap = false;

    precision_ = ceil(log10(SCALE_F / interval));
    if (precision_ < 0) {
        precision_ = 0;
    }

    // XXX - This is the default QCP date time format, but adding fractional
    // seconds when our interval is small. Should we make it something else,
    // like ISO 8601 (but still with a line break between time and date)?
    // Note this is local time, with no time zone offset displayed. Should
    // it be in UTC? (call setDateTimeSpec())
    if (precision_) {
        datetime_ticker_->setDateTimeFormat("hh:mm:ss.z\ndd.MM.yy");
    } else {
        datetime_ticker_->setDateTimeFormat("hh:mm:ss\ndd.MM.yy");
    }

    if (uat_model_ != NULL) {
        for (int row = 0; row < uat_model_->rowCount(); row++) {
            IOGraph *iog = ioGraphs_.value(row, NULL);
            if (iog) {
                iog->setInterval(interval);
                if (iog->visible()) {
                    need_retap = true;
                } else {
                    iog->setNeedRetap(true);
                }
            }
        }
    }

    if (need_retap) {
        scheduleRetap(true);
    }
}

void IOGraphDialog::modelRowsReset()
{
    foreach(IOGraph* iog, ioGraphs_) {
        delete iog;
    }
    ioGraphs_.clear();

    for (int i = 0; i < uat_model_->rowCount(); i++) {
        createIOGraph(i);
    }
    ui->deleteToolButton->setEnabled(false);
    ui->copyToolButton->setEnabled(false);
    ui->clearToolButton->setEnabled(uat_model_->rowCount() != 0);
}

void IOGraphDialog::modelRowsInserted(const QModelIndex &, int first, int last)
{
    // first to last is inclusive
    for (int i = first; i <= last; i++) {
        createIOGraph(i);
    }
}

void IOGraphDialog::modelRowsRemoved(const QModelIndex &, int first, int last)
{
    // first to last is inclusive
    for (int i = last; i >= first; i--) {
        IOGraph *iog = ioGraphs_.takeAt(i);
        delete iog;
    }
}

void IOGraphDialog::modelRowsMoved(const QModelIndex &source, int sourceStart, int sourceEnd, const QModelIndex &dest, int destinationRow)
{
    // The source and destination parent are always the same for UatModel.
    ws_assert(source == dest);
    // Either destinationRow < sourceStart, or destinationRow > sourceEnd.
    // When moving rows down the same parent, the rows are placed _before_
    // destinationRow, otherwise it's the row to which items are moved.
    if (destinationRow < sourceStart) {
        for (int i = 0; i <= sourceEnd - sourceStart; i++) {
            // When moving up the same parent, moving an earlier
            // item doesn't change the row.
            ioGraphs_.move(sourceStart + i, destinationRow + i);
        }
    } else {
        for (int i = 0; i <= sourceEnd - sourceStart; i++) {
            // When moving down the same parent, moving an earlier
            // item means the next items move up (so all the moved
            // rows are always at sourceStart.)
            ioGraphs_.move(sourceStart, destinationRow - 1);
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
    IOGraph *iog;
    for (int row = qMin(sourceStart, destinationRow); row < uat_model_->rowCount(); row++) {
        iog = ioGraphs_.at(row);
        if (iog->graph()) {
            iog->graph()->setLayer(iog->graph()->layer());
        } else if (iog->bars()) {
            iog->bars()->setLayer(iog->bars()->layer());
        }
    }
    ui->ioPlot->replot();
}

void IOGraphDialog::graphUatSelectionChanged(const QItemSelection&, const QItemSelection&)
{
    QModelIndexList selectedRows = ui->graphUat->selectionModel()->selectedRows();
    qsizetype num_selected = selectedRows.size();
    if (num_selected > 0) {
        std::sort(selectedRows.begin(), selectedRows.end());
        ui->deleteToolButton->setEnabled(true);
        ui->copyToolButton->setEnabled(true);
        ui->moveUpwardsToolButton->setEnabled(selectedRows.first().row() > 0);
        ui->moveDownwardsToolButton->setEnabled(selectedRows.last().row() < uat_model_->rowCount() - 1);
    } else {
        ui->deleteToolButton->setEnabled(false);
        ui->copyToolButton->setEnabled(false);
        ui->moveUpwardsToolButton->setEnabled(false);
        ui->moveDownwardsToolButton->setEnabled(false);
    }
}

void IOGraphDialog::on_graphUat_currentItemChanged(const QModelIndex &current, const QModelIndex&)
{
    if (current.isValid()) {
        ui->clearToolButton->setEnabled(true);
        if (graphIsEnabled(current.row())) {
            // Try to set the tracer to the new current graph.
            // If it's not enabled, don't try to switch from the
            // old graph to the one in the first row.
            getGraphInfo();
        }
    } else {
        ui->clearToolButton->setEnabled(false);
    }
}

void IOGraphDialog::modelDataChanged(const QModelIndex &topLeft, const QModelIndex &bottomRight, const QVector<int> &)
{
    bool recalc = false;

    for (int col = topLeft.column(); col <= bottomRight.column(); col++) {
        switch (col)
        {
        case colYAxis:
        case colSMAPeriod:
        case colYAxisFactor:
            recalc = true;
        }
    }

    for (int row = topLeft.row(); row <= bottomRight.row(); row++) {
        syncGraphSettings(row);
    }

    if (recalc) {
        scheduleRecalc(true);
    } else {
        scheduleReplot(true);
    }
}

void IOGraphDialog::on_newToolButton_clicked()
{
    addGraph();
}

void IOGraphDialog::on_deleteToolButton_clicked()
{
    if (uat_model_ == nullptr) {
        return;
    }

    for (const auto &range : ui->graphUat->selectionModel()->selection()) {
        // Each QItemSelectionRange is contiguous
        if (!range.isEmpty()) {
            if (!uat_model_->removeRows(range.top(), range.bottom() - range.top() + 1)) {
                qDebug() << "Failed to remove rows" << range.top() << "to" << range.bottom();
            }
        }
    }

    // We should probably be smarter about this.
    hint_err_.clear();
    updateHint();
}

void IOGraphDialog::on_copyToolButton_clicked()
{
    if (uat_model_ == nullptr) {
        return;
    }

    QModelIndexList selectedRows = ui->graphUat->selectionModel()->selectedRows();
    if (selectedRows.size() > 0) {
        std::sort(selectedRows.begin(), selectedRows.end());

        QModelIndex copyIdx;

        for (const auto &idx : selectedRows) {
            copyIdx = uat_model_->copyRow(idx);
            if (!copyIdx.isValid())
            {
                qDebug() << "Failed to copy row" << idx.row();
            }
        }
        ui->graphUat->setCurrentIndex(copyIdx);
    }
}

void IOGraphDialog::on_clearToolButton_clicked()
{
    if (uat_model_) {
        uat_model_->clearAll();
    }

    hint_err_.clear();
    updateHint();
}

void IOGraphDialog::on_moveUpwardsToolButton_clicked()
{
    if (uat_model_ == nullptr) {
        return;
    }

    for (const auto &range : ui->graphUat->selectionModel()->selection()) {
        // Each QItemSelectionRange is contiguous
        if (!range.isEmpty() && range.top() > 0) {
            // Swap range of rows with the row above the top
            if (! uat_model_->moveRows(QModelIndex(), range.top(), range.bottom() - range.top() + 1, QModelIndex(), range.top() - 1)) {
                qDebug() << "Failed to move up rows" << range.top() << "to" << range.bottom();
            }
            // Our moveRows implementation calls begin/endMoveRows(), so
            // range.top() already has the new row number.
            ui->moveUpwardsToolButton->setEnabled(range.top() > 0);
            ui->moveDownwardsToolButton->setEnabled(true);
        }
    }
}

void IOGraphDialog::on_moveDownwardsToolButton_clicked()
{
    if (uat_model_ == nullptr) {
        return;
    }

    for (const auto &range : ui->graphUat->selectionModel()->selection()) {
        // Each QItemSelectionRange is contiguous
        if (!range.isEmpty() && range.bottom() + 1 < uat_model_->rowCount()) {
            // Swap range of rows with the row below the top
            if (! uat_model_->moveRows(QModelIndex(), range.top(), range.bottom() - range.top() + 1, QModelIndex(), range.bottom() + 1)) {
                qDebug() << "Failed to move down rows" << range.top() << "to" << range.bottom();
            }
            // Our moveRows implementation calls begin/endMoveRows, so
            // range.bottom() already has the new row number.
            ui->moveUpwardsToolButton->setEnabled(true);
            ui->moveDownwardsToolButton->setEnabled(range.bottom() < uat_model_->rowCount() - 1);
        }
    }
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
    ui->ioPlot->setInteractions(QCP::Interactions());
}

void IOGraphDialog::on_automaticUpdateCheckBox_toggled(bool checked)
{
    prefs.gui_io_graph_automatic_update = checked ? true : false;

    prefs_main_write();

    if(prefs.gui_io_graph_automatic_update)
    {
        updateStatistics();
    }
}

void IOGraphDialog::on_actionReset_triggered()
{
    resetAxes();
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
    toggleTracerStyle();
}

void IOGraphDialog::on_buttonBox_helpRequested()
{
    mainApp->helpTopicAction(HELP_STATS_IO_GRAPH_DIALOG);
}

// XXX - We have similar code in tcp_stream_dialog and packet_diagram. Should this be a common routine?
void IOGraphDialog::on_buttonBox_accepted()
{
    QString file_name;
    QDir path(mainApp->openDialogInitialDir());
    QString pdf_filter = tr("Portable Document Format (*.pdf)");
    QString png_filter = tr("Portable Network Graphics (*.png)");
    QString bmp_filter = tr("Windows Bitmap (*.bmp)");
    // Gaze upon my beautiful graph with lossy artifacts!
    QString jpeg_filter = tr("JPEG File Interchange Format (*.jpeg *.jpg)");
    QString csv_filter = tr("Comma Separated Values (*.csv)");
    QString filter = QStringLiteral("%1;;%2;;%3;;%4;;%5").arg(
        pdf_filter,
        png_filter,
        bmp_filter,
        jpeg_filter,
        csv_filter
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
            mainApp->setLastOpenDirFromFilename(file_name);
        }
    }
}

void IOGraphDialog::buttonBoxClicked(QAbstractButton *button)
{
    switch (ui->buttonBox->buttonRole(button)) {
    case QDialogButtonBox::ResetRole:
        resetAxes();
        break;
    default:
        break;
    }
}

void IOGraphDialog::actionLegendTriggered(bool checked)
{
    prefs.gui_io_graph_enable_legend = checked ? true : false;

    prefs_main_write();

    ui->ioPlot->legend->layer()->replot();
}

void IOGraphDialog::actionLogScaleTriggered(bool checked)
{
    QCustomPlot *iop = ui->ioPlot;
    QSharedPointer<QCPAxisTickerSi> si_ticker = qSharedPointerDynamicCast<QCPAxisTickerSi>(iop->yAxis->ticker());
    if (si_ticker != nullptr) {
        si_ticker->setLog(checked);
    }

    if (checked) {
        iop->yAxis->setScaleType(QCPAxis::stLogarithmic);
        if (si_ticker == nullptr) {
            iop->yAxis->setTicker(QSharedPointer<QCPAxisTickerLog>(new QCPAxisTickerLog));
        }
    } else {
        iop->yAxis->setScaleType(QCPAxis::stLinear);
        if (si_ticker == nullptr) {
            iop->yAxis->setTicker(QSharedPointer<QCPAxisTicker>(new QCPAxisTicker));
        }
    }
    iop->replot();
}

void IOGraphDialog::actionTimeOfDayTriggered(bool checked)
{
    nstime_t orig_start;
    nstime_copy(&orig_start, &start_time_);
    bool orig_auto = auto_axes_;

    if (checked) {
        ui->ioPlot->xAxis->setTicker(datetime_ticker_);
    } else {
        ui->ioPlot->xAxis->setTicker(number_ticker_);
    }
    auto_axes_ = false;
    scheduleRecalc(true);
    auto_axes_ = orig_auto;
    getGraphInfo();
    nstime_delta(&orig_start, &start_time_, &orig_start);
    ui->ioPlot->xAxis->moveRange(nstime_to_sec(&orig_start));
    updateHint();
}

void IOGraphDialog::makeCsv(QTextStream &stream) const
{
    QList<IOGraph *> activeGraphs;

    int ui_interval = ui->intervalComboBox->itemData(ui->intervalComboBox->currentIndex()).toInt();
    int max_interval = 0;

    stream << "\"Interval start\"";
    for (int row = 0; row < graphCount(); row++) {
        if (graphIsEnabled(row) && ioGraphs_[row] != NULL) {
            activeGraphs.append(ioGraphs_[row]);
            if (max_interval < ioGraphs_[row]->maxInterval()) {
                max_interval = ioGraphs_[row]->maxInterval();
            }
            QString name = ioGraphs_[row]->name().toUtf8();
            name = QStringLiteral("\"%1\"").arg(name.replace("\"", "\"\""));  // RFC 4180
            stream << "," << name;
        }
    }

    stream << '\n';

    for (int interval = 0; interval <= max_interval; interval++) {
        int64_t interval_start = (int64_t)interval * ui_interval;
        if (qSharedPointerDynamicCast<QCPAxisTickerDateTime>(ui->ioPlot->xAxis->ticker()) != nullptr) {
            nstime_t interval_time = NSTIME_INIT_SECS_USECS((time_t)(interval_start / SCALE), (int)(interval_start % SCALE));

            nstime_add(&interval_time, &start_time_);

            static char time_string_buf[39];

            if (decimal_point == nullptr) {
                decimal_point = g_strdup(localeconv()->decimal_point);
            }
            // Should we convert to UTC for output, even if the graph axis has
            // local time?
            // The question of what precision to use is somewhat tricky.
            // The buckets are aligned to the relative time start, not to
            // absolute time, so the timestamp precision should be used instead
            // of the bucket precision. We can save the precision of the
            // start time timestamp for each graph, but we don't necessarily
            // have a guarantee that all timestamps in the file have the same
            // precision. Possibly nstime_t should store precision, cf. #15579
            format_nstime_as_iso8601(time_string_buf, sizeof time_string_buf, &interval_time, decimal_point, true, 9); // precision_);

            stream << time_string_buf;
        } else {
            stream << (double)interval_start / SCALE_F;
        }
        foreach (IOGraph *iog, activeGraphs) {
            double value = 0.0;
            if (interval <= iog->maxInterval()) {
                value = iog->getItemValue(interval, cap_file_.capFile());
            }
            stream << "," << value;
        }
        stream << '\n';
    }
}

void IOGraphDialog::copyAsCsvClicked()
{
    QString csv;
    QTextStream stream(&csv, QIODevice::Text);
    makeCsv(stream);
    mainApp->clipboard()->setText(stream.readAll());
}

bool IOGraphDialog::saveCsv(const QString &file_name) const
{
    QFile save_file(file_name);
    if (!save_file.open(QFile::WriteOnly | QFile::Text)) {
        return false;
    }
    QTextStream out(&save_file);
    makeCsv(out);

    return true;
}

// Stat command + args

static bool
io_graph_init(const char *, void*) {
    mainApp->emitStatCommandSignal("IOGraph", NULL, NULL);
    return true;
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

void register_tap_listener_qt_iostat(void);

void
register_tap_listener_qt_iostat(void)
{
    register_stat_tap_ui(&io_stat_ui, NULL);
}

}
