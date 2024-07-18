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

#include <epan/stat_tap_ui.h>
#include "epan/uat-int.h"

#include <wsutil/utf8_entities.h>
#include <wsutil/ws_assert.h>

#include <ui/qt/utils/qt_ui_utils.h>

#include <ui/qt/utils/variant_pointer.h>

#include <ui/qt/utils/color_utils.h>
#include <ui/qt/widgets/qcustomplot.h>
#include <ui/qt/widgets/qcp_string_legend_item.h>
#include <ui/qt/widgets/qcp_axis_ticker_si.h>
#include "progress_frame.h"
#include "main_application.h"
#include <ui/qt/main_window.h>

#include <wsutil/filesystem.h>
#include <wsutil/report_message.h>
#include <wsutil/nstime.h>
#include <wsutil/to_str.h>

#include <ui/qt/utils/tango_colors.h> //provides some default colors
#include <ui/qt/widgets/copy_from_profile_button.h>
#include "ui/qt/widgets/wireshark_file_dialog.h"

#include <QClipboard>
#include <QFontMetrics>
#include <QFrame>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QRubberBand>
#include <QSpacerItem>
#include <QTimer>
#include <QVariant>

#include <new> // std::bad_alloc

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

// Scale factor to convert the units the interval is stored in to seconds.
// Must match what get_io_graph_index() in io_graph_item expects.
// Increase this in order to make smaller intervals possible.
const int SCALE = 1000000;
const double SCALE_F = (double)SCALE;

const qreal graph_line_width_ = 1.0;

const int DEFAULT_MOVING_AVERAGE = 0;
const int DEFAULT_Y_AXIS_FACTOR = 1;

// Don't accidentally zoom into a 1x1 rect if you happen to click on the graph
// in zoom mode.
const int min_zoom_pixels_ = 20;

const int stat_update_interval_ = 200; // ms

// Saved graph settings
typedef struct _io_graph_settings_t {
    bool enabled;
    char* name;
    char* dfilter;
    unsigned color;
    uint32_t style;
    uint32_t yaxis;
    char* yfield;
    uint32_t sma_period;
    uint32_t y_axis_factor;
} io_graph_settings_t;

static const value_string graph_style_vs[] = {
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

static const value_string y_axis_packet_vs[] = {
    { IOG_ITEM_UNIT_PACKETS, "Packets" },
    { IOG_ITEM_UNIT_BYTES, "Bytes" },
    { IOG_ITEM_UNIT_BITS, "Bits" },
    { IOG_ITEM_UNIT_CALC_SUM, "SUM(Y Field)" },
    { IOG_ITEM_UNIT_CALC_FRAMES, "COUNT FRAMES(Y Field)" },
    { IOG_ITEM_UNIT_CALC_FIELDS, "COUNT FIELDS(Y Field)" },
    { IOG_ITEM_UNIT_CALC_MAX, "MAX(Y Field)" },
    { IOG_ITEM_UNIT_CALC_MIN, "MIN(Y Field)" },
    { IOG_ITEM_UNIT_CALC_AVERAGE, "AVG(Y Field)" },
    { IOG_ITEM_UNIT_CALC_THROUGHPUT, "THROUGHPUT(Y Field)" },
    { IOG_ITEM_UNIT_CALC_LOAD, "LOAD(Y Field)" },
    { 0, NULL }
};

static const value_string y_axis_event_vs[] = {
    { IOG_ITEM_UNIT_PACKETS, "Events" },
    y_axis_packet_vs[1],
    y_axis_packet_vs[2],
    y_axis_packet_vs[3],
    y_axis_packet_vs[4],
    y_axis_packet_vs[5],
    y_axis_packet_vs[6],
    y_axis_packet_vs[7],
    y_axis_packet_vs[8],
    y_axis_packet_vs[9],
    { 0, NULL }
};

static const value_string moving_avg_vs[] = {
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

// y_axis_factor was added in 3.6. Provide backward compatibility.
static const char *iog_uat_defaults_[] = {
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "1"
};

static char *decimal_point;

extern "C" {

//Allow the enable/disable field to be a checkbox, but for backwards
//compatibility with pre-2.6 versions, the strings are "Enabled"/"Disabled",
//not "true"/"false". (Pre-4.4 versions require "true" to be all-caps.)
#define UAT_BOOL_ENABLE_CB_DEF(basename,field_name,rec_t) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    char* tmp_str = g_strndup(buf,len); \
    if (tmp_str && ((g_strcmp0(tmp_str, "Enabled") == 0) || \
        (g_ascii_strcasecmp(tmp_str, "true") == 0))) \
        ((rec_t*)rec)->field_name = 1; \
    else \
        ((rec_t*)rec)->field_name = 0; \
    g_free(tmp_str); } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, char** out_ptr, unsigned* out_len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    *out_ptr = ws_strdup_printf("%s",((rec_t*)rec)->field_name ? "Enabled" : "Disabled"); \
    *out_len = (unsigned)strlen(*out_ptr); }

static bool uat_fld_chk_enable(void* u1 _U_, const char* strptr, unsigned len, const void* u2 _U_, const void* u3 _U_, char** err)
{
    char* str = g_strndup(strptr,len);

    if (str &&
       ((g_strcmp0(str, "Enabled") == 0) ||
        (g_strcmp0(str, "Disabled") == 0) ||
        (g_ascii_strcasecmp(str, "true") == 0) ||  //just for UAT functionality
        (g_ascii_strcasecmp(str, "false") == 0))) {
        *err = NULL;
        g_free(str);
        return true;
    }

    //User should never see this unless they are manually modifying UAT
    *err = ws_strdup_printf("invalid value: %s (must be Enabled or Disabled)", str);
    g_free(str);
    return false;
}

#define UAT_FLD_BOOL_ENABLE(basename,field_name,title,desc) \
{#field_name, title, PT_TXTMOD_BOOL,{uat_fld_chk_enable,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

//"Custom" handler for sma_period enumeration for backwards compatibility
static void io_graph_sma_period_set_cb(void* rec, const char* buf, unsigned len, const void* vs, const void* u2 _U_)
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
static void io_graph_sma_period_tostr_cb(void* rec, char** out_ptr, unsigned* out_len, const void* vs, const void* u2 _U_)
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

static bool sma_period_chk_enum(void* u1 _U_, const char* strptr, unsigned len, const void* v, const void* u3 _U_, char** err) {
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

#define UAT_FLD_SMA_PERIOD(basename,field_name,title,enum,desc) \
    {#field_name, title, PT_TXTMOD_ENUM,{sma_period_chk_enum,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{&(enum),&(enum),&(enum)},&(enum),desc,FLDFILL}


UAT_BOOL_ENABLE_CB_DEF(io_graph, enabled, io_graph_settings_t)
UAT_CSTRING_CB_DEF(io_graph, name, io_graph_settings_t)
UAT_DISPLAY_FILTER_CB_DEF(io_graph, dfilter, io_graph_settings_t)
UAT_COLOR_CB_DEF(io_graph, color, io_graph_settings_t)
UAT_VS_DEF(io_graph, style, io_graph_settings_t, uint32_t, 0, "Line")
// XXX Need to use "Events" where appropriate.
UAT_VS_DEF(io_graph, yaxis, io_graph_settings_t, uint32_t, 0, "Packets")
UAT_PROTO_FIELD_CB_DEF(io_graph, yfield, io_graph_settings_t)
UAT_DEC_CB_DEF(io_graph, y_axis_factor, io_graph_settings_t)

static uat_field_t io_graph_packet_fields[] = {
    UAT_FLD_BOOL_ENABLE(io_graph, enabled, "Enabled", "Graph visibility"),
    UAT_FLD_CSTRING(io_graph, name, "Graph Name", "The name of the graph"),
    UAT_FLD_DISPLAY_FILTER(io_graph, dfilter, "Display Filter", "Graph packets matching this display filter"),
    UAT_FLD_COLOR(io_graph, color, "Color", "Graph color (#RRGGBB)"),
    UAT_FLD_VS(io_graph, style, "Style", graph_style_vs, "Graph style (Line, Bars, etc.)"),
    UAT_FLD_VS(io_graph, yaxis, "Y Axis", y_axis_packet_vs, "Y Axis units"),
    UAT_FLD_PROTO_FIELD(io_graph, yfield, "Y Field", "Apply calculations to this field"),
    UAT_FLD_SMA_PERIOD(io_graph, sma_period, "SMA Period", moving_avg_vs, "Simple moving average period"),
    UAT_FLD_DEC(io_graph, y_axis_factor, "Y Axis Factor", "Y Axis Factor"),

    UAT_END_FIELDS
};

static uat_field_t io_graph_event_fields[] = {
    UAT_FLD_BOOL_ENABLE(io_graph, enabled, "Enabled", "Graph visibility"),
    UAT_FLD_CSTRING(io_graph, name, "Graph Name", "The name of the graph"),
    UAT_FLD_DISPLAY_FILTER(io_graph, dfilter, "Display Filter", "Graph packets matching this display filter"),
    UAT_FLD_COLOR(io_graph, color, "Color", "Graph color (#RRGGBB)"),
    UAT_FLD_VS(io_graph, style, "Style", graph_style_vs, "Graph style (Line, Bars, etc.)"),
    UAT_FLD_VS(io_graph, yaxis, "Y Axis", y_axis_event_vs, "Y Axis units"),
    UAT_FLD_PROTO_FIELD(io_graph, yfield, "Y Field", "Apply calculations to this field"),
    UAT_FLD_SMA_PERIOD(io_graph, sma_period, "SMA Period", moving_avg_vs, "Simple moving average period"),
    UAT_FLD_DEC(io_graph, y_axis_factor, "Y Axis Factor", "Y Axis Factor"),

    UAT_END_FIELDS
};

static void* io_graph_copy_cb(void* dst_ptr, const void* src_ptr, size_t) {
    io_graph_settings_t* dst = (io_graph_settings_t *)dst_ptr;
    const io_graph_settings_t* src = (const io_graph_settings_t *)src_ptr;

    dst->enabled = src->enabled;
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

IOGraphDialog::IOGraphDialog(QWidget &parent, CaptureFile &cf, QString displayFilter,
        io_graph_item_unit_t value_units, QString yfield) :
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

    ui->enableLegendCheckBox->setChecked(prefs.gui_io_graph_enable_legend ? true : false);

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

    ui->todCheckBox->setChecked(false);
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
    ctx_menu_.addAction(ui->actionCrosshairs);
    set_action_shortcuts_visible_in_context_menu(ctx_menu_.actions());

    iop->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(iop, &QCustomPlot::customContextMenuRequested, this, &IOGraphDialog::showContextMenu);

    iop->xAxis->setLabel(tr("Time (s)"));

    iop->setMouseTracking(true);
    iop->setEnabled(true);

    QCPTextElement *title = new QCPTextElement(iop);
    iop->plotLayout()->insertRow(0);
    iop->plotLayout()->addElement(0, 0, title);
    title->setText(tr("Wireshark I/O Graphs: %1").arg(cap_file_.fileDisplayName()));

    tracer_ = new QCPItemTracer(iop);

    loadProfileGraphs();
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
        addGraph(true, displayFilter, value_units, yfield);
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

    MainWindow *main_window = qobject_cast<MainWindow *>(mainApp->mainWindow());
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
    if (uat_load(iog_uat_, filename.toUtf8().constData(), &err)) {
        iog_uat_->changed = true;
        // uat_load calls the post update cb, which reloads the Uat.
        //uat_model_->reloadUat();
    } else {
        report_failure("Error while loading %s: %s", iog_uat_->name, err);
        g_free(err);
    }
}

void IOGraphDialog::addGraph(bool checked, QString name, QString dfilter, QRgb color_idx, IOGraph::PlotStyles style, io_graph_item_unit_t value_units, QString yfield, int moving_average, int y_axis_factor)
{
    if (uat_model_ == nullptr)
        return;

    QVariantList newRowData;
    newRowData.append(checked ? Qt::Checked : Qt::Unchecked);
    newRowData.append(name);
    newRowData.append(dfilter);
    newRowData.append(QColor(color_idx));
    newRowData.append(val_to_str_const(style, graph_style_vs, "None"));
    if (is_packet_configuration_namespace()) {
        newRowData.append(val_to_str_const(value_units, y_axis_packet_vs, "Packets"));
    } else {
        newRowData.append(val_to_str_const(value_units, y_axis_event_vs, "Events"));
    }
    newRowData.append(yfield);
    newRowData.append(val_to_str_const((uint32_t) moving_average, moving_avg_vs, "None"));
    newRowData.append(y_axis_factor);

    QModelIndex newIndex = uat_model_->appendEntry(newRowData);
    if ( !newIndex.isValid() )
    {
        qDebug() << "Failed to add a new record";
        return;
    }
    ui->graphUat->setCurrentIndex(newIndex);
}

void IOGraphDialog::addGraph(bool checked, QString dfilter, io_graph_item_unit_t value_units, QString yfield)
{
    if (uat_model_ == nullptr)
        return;

    QString graph_name;
    if (yfield.isEmpty()) {
        if (!dfilter.isEmpty()) {
            graph_name = is_packet_configuration_namespace() ? tr("Filtered packets") : tr("Filtered events");
        } else {
            graph_name = is_packet_configuration_namespace() ? tr("All packets") : tr("All events");
        }
    } else {
        if (is_packet_configuration_namespace()) {
            graph_name = QString(val_to_str_const(value_units, y_axis_packet_vs, "Unknown")).replace("Y Field", yfield);
        } else {
            graph_name = QString(val_to_str_const(value_units, y_axis_event_vs, "Unknown")).replace("Y Field", yfield);
        }
    }
    addGraph(checked, std::move(graph_name), dfilter, ColorUtils::graphColor(uat_model_->rowCount()),
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
    ioGraphs_.insert(currentRow, new IOGraph(ui->ioPlot));
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
    if (is_packet_configuration_namespace()) {
        switch (idx % 2) {
        case 0:
            addGraph(enabled, tr("All Packets"), QString(), ColorUtils::graphColor(idx),
                    IOGraph::psLine, IOG_ITEM_UNIT_PACKETS, QString(), DEFAULT_MOVING_AVERAGE, DEFAULT_Y_AXIS_FACTOR);
            break;
        default:
            addGraph(enabled, tr("TCP Errors"), "tcp.analysis.flags", ColorUtils::graphColor(4), // 4 = red
                    IOGraph::psBar, IOG_ITEM_UNIT_PACKETS, QString(), DEFAULT_MOVING_AVERAGE, DEFAULT_Y_AXIS_FACTOR);
            break;
        }
    } else {
        switch (idx % 2) {
        case 0:
            addGraph(enabled, tr("All Events"), QString(), ColorUtils::graphColor(idx),
                    IOGraph::psLine, IOG_ITEM_UNIT_PACKETS, QString(), DEFAULT_MOVING_AVERAGE, DEFAULT_Y_AXIS_FACTOR);
            break;
        default:
            addGraph(enabled, tr("All Execs"), "evt.type == \"execve\"", ColorUtils::graphColor(4), // 4 = red
                    IOGraph::psDot, IOG_ITEM_UNIT_PACKETS, QString(), DEFAULT_MOVING_AVERAGE, DEFAULT_Y_AXIS_FACTOR);
            break;
        }
    }
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

    /* plot style depend on the value unit, so set it first. */
    data_str = uat_model_->data(uat_model_->index(row, colYAxis)).toString();
    if (is_packet_configuration_namespace()) {
        iog->setValueUnits((int) str_to_val(qUtf8Printable(data_str), y_axis_packet_vs, IOG_ITEM_UNIT_PACKETS));
    } else {
        iog->setValueUnits((int) str_to_val(qUtf8Printable(data_str), y_axis_event_vs, IOG_ITEM_UNIT_PACKETS));
    }
    iog->setValueUnitField(uat_model_->data(uat_model_->index(row, colYField)).toString());

    iog->setColor(uat_model_->data(uat_model_->index(row, colColor), Qt::DecorationRole).value<QColor>().rgb());
    data_str = uat_model_->data(uat_model_->index(row, colStyle)).toString();
    iog->setPlotStyle((int) str_to_val(qUtf8Printable(data_str), graph_style_vs, 0));

    data_str = uat_model_->data(uat_model_->index(row, colSMAPeriod)).toString();
    iog->moving_avg_period_ = str_to_val(qUtf8Printable(data_str), moving_avg_vs, 0);

    iog->y_axis_factor_ = uat_model_->data(uat_model_->index(row, colYAxisFactor)).toInt();

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
                           (uat_model_->data(uat_model_->index(row, colStyle), Qt::DisplayRole).toString().compare(graph_style_vs[IOGraph::psStackedBar].strptr) == 0) &&
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

void IOGraphDialog::updateHint()
{
    QCustomPlot *iop = ui->ioPlot;
    QString hint;

    // XXX: ElidedLabel doesn't support rich text / HTML, we
    // used to bold this error
    if (!hint_err_.isEmpty()) {
        hint += QString("%1 ").arg(hint_err_);
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
            QString msg = is_packet_configuration_namespace() ? tr("No packets in interval") : tr("No events in interval");
            QString val;
            if (interval_packet > 0) {
                packet_num_ = (uint32_t) interval_packet;
                if (is_packet_configuration_namespace()) {
                    msg = QString("%1 %2")
                            .arg(!file_closed_ ? tr("Click to select packet") : tr("Packet"))
                            .arg(packet_num_);
                } else {
                    msg = QString("%1 %2")
                            .arg(!file_closed_ ? tr("Click to select event") : tr("Event"))
                            .arg(packet_num_);
                }
                val = " = " + QString::number(tracer_->position->value(), 'g', 4);
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

    iop->legend->setVisible(false);
    iop->yAxis->setLabel(QString());

    // Find unique labels
    for (int row = 0; row < graphCount(); row++) {
        IOGraph *iog = ioGraphs_.value(row, Q_NULLPTR);
        if (graphIsEnabled(row) && iog) {
            QString label(iog->valueUnitLabel());
            vu_label_set.insert(label);
            format_units_set.insert(iog->formatUnits());
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
            iop->yAxis->setTicker(QSharedPointer<QCPAxisTickerSi>(new QCPAxisTickerSi(format_units, QString(), ui->logCheckBox->isChecked())));
        }
    } else {
        if (si_ticker) {
            if (ui->logCheckBox->isChecked()) {
                iop->yAxis->setTicker(QSharedPointer<QCPAxisTickerLog>(new QCPAxisTickerLog));
            } else {
                iop->yAxis->setTicker(QSharedPointer<QCPAxisTicker>(new QCPAxisTicker));
            }
       }
    }

    // All the same. Use the Y Axis label.
    if (vu_label_set.size() == 1) {
        iop->yAxis->setLabel(vu_label_set.values().constFirst() + "/" + intervalText);
    }

    // Create a legend with a Title label at top.
    // Legend Title thanks to: https://www.qcustomplot.com/index.php/support/forum/443
    iop->legend->clearItems();
    QCPStringLegendItem *legendTitle = new QCPStringLegendItem(iop->legend, QString(tr("%1 Intervals ").arg(intervalText)));
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
        QMenu *menu = new QMenu(this);
        menu->setAttribute(Qt::WA_DeleteOnClose);
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
    } else {
        ctx_menu_.popup(ui->ioPlot->mapToGlobal(pos));
    }
}

void IOGraphDialog::graphClicked(QMouseEvent *event)
{
    QCustomPlot *iop = ui->ioPlot;

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
    iop->setFocus();
}

void IOGraphDialog::mouseMoved(QMouseEvent *event)
{
    QCustomPlot *iop = ui->ioPlot;
    Qt::CursorShape shape = Qt::ArrowCursor;

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

void IOGraphDialog::loadProfileGraphs()
{
    if (iog_uat_ == NULL) {
        uat_field_t *io_graph_fields = io_graph_packet_fields;
        if (!is_packet_configuration_namespace()) {
            io_graph_fields = io_graph_event_fields;
        }

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
        if (!uat_load(iog_uat_, NULL, &err)) {
            report_failure("Error while loading %s: %s.  Default graph values will be used", iog_uat_->name, err);
            g_free(err);
            uat_clear(iog_uat_);
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

void IOGraphDialog::on_todCheckBox_toggled(bool checked)
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

void IOGraphDialog::on_logCheckBox_toggled(bool checked)
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

void IOGraphDialog::on_automaticUpdateCheckBox_toggled(bool checked)
{
    prefs.gui_io_graph_automatic_update = checked ? true : false;

    prefs_main_write();

    if(prefs.gui_io_graph_automatic_update)
    {
        updateStatistics();
    }
}

void IOGraphDialog::on_enableLegendCheckBox_toggled(bool checked)
{
    prefs.gui_io_graph_enable_legend = checked ? true : false;

    prefs_main_write();

    ui->ioPlot->legend->layer()->replot();
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
    QString file_name, extension;
    QDir path(mainApp->openDialogInitialDir());
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
        save_file += QString("/%1").arg(cap_file_.fileBaseName());
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
            name = QString("\"%1\"").arg(name.replace("\"", "\"\""));  // RFC 4180
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
    save_file.open(QFile::WriteOnly | QFile::Text);
    QTextStream out(&save_file);
    makeCsv(out);

    return true;
}

// IOGraph

IOGraph::IOGraph(QCustomPlot *parent) :
    parent_(parent),
    tap_registered_(true),
    visible_(false),
    graph_(NULL),
    bars_(NULL),
    val_units_(IOG_ITEM_UNIT_FIRST),
    hf_index_(-1),
    interval_(0),
    start_time_(NSTIME_INIT_ZERO),
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
                          tapDraw,
                          NULL);
    if (error_string) {
//        QMessageBox::critical(this, tr("%1 failed to register tap listener").arg(name_),
//                             error_string->str);
//        config_err_ = error_string->str;
        g_string_free(error_string, TRUE);
        tap_registered_ = false;
    }
}

IOGraph::~IOGraph() {
    removeTapListener();
    if (graph_) {
        parent_->removeGraph(graph_);
    }
    if (bars_) {
        parent_->removePlottable(bars_);
    }
}

void IOGraph::removeTapListener()
{
    if (tap_registered_) {
        remove_tap_listener(this);
        tap_registered_ = false;
    }
}

// Construct a full filter string from the display filter and value unit / Y axis.
// Check for errors and sets config_err_ and returns false if any are found.
bool IOGraph::setFilter(const QString &filter)
{
    GString *error_string;
    QString full_filter(filter.trimmed());

    config_err_.clear();

    // Make sure we have a good display filter
    if (!full_filter.isEmpty()) {
        dfilter_t *dfilter;
        bool status;
        df_error_t *df_err = NULL;
        status = dfilter_compile(full_filter.toUtf8().constData(), &dfilter, &df_err);
        dfilter_free(dfilter);
        if (!status) {
            config_err_ = QString::fromUtf8(df_err->msg);
            df_error_free(&df_err);
            filter_ = full_filter;
            return false;
        }
    }

    // Check our value unit + field combo.
    error_string = check_field_unit(vu_field_.toUtf8().constData(), NULL, val_units_);
    if (error_string) {
        config_err_ = error_string->str;
        g_string_free(error_string, TRUE);
        return false;
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

    if (full_filter_.compare(full_filter)) {
        error_string = set_tap_dfilter(this, full_filter.toUtf8().constData());
        if (error_string) {
            config_err_ = error_string->str;
            g_string_free(error_string, TRUE);
            return false;
        }

        filter_ = filter;
        full_filter_ = full_filter;
        /* If we changed the tap filter the graph is visible, we need to
         * retap.
         * Note that setting the tap dfilter will mark the tap as needing a
         * redraw, which will cause a recalculation (via tapDraw) via the
         * (fairly long) main application timer.
         */
        /* XXX - When changing from an advanced graph to one that doesn't
         * use the field, we don't actually need to retap if filter and
         * full_filter produce the same results. (We do have to retap
         * regardless if changing _to_ an advanced graph, because the
         * extra fields in the io_graph_item_t aren't filled in from the
         * edt for the basic graph.)
         * Checking that in full generality would require more optimization
         * in the dfilter engine plus functions to compare filters, but
         * we could test the simple case where filter and vu_field are
         * the same string.
         */
        setNeedRetap(true);
    }
    return true;
}

void IOGraph::applyCurrentColor()
{
    if (graph_) {
        graph_->setPen(QPen(color_, graph_line_width_));
    } else if (bars_) {
        bars_->setPen(QPen(color_.color().darker(110), graph_line_width_));
        // ...or omit it altogether?
        // bars_->setPen(QPen(color_);
        // XXX - We should do something like
        // bars_->setPen(QPen(ColorUtils::alphaBlend(color_, palette().windowText(), 0.65));
        // to get a darker outline in light mode and a lighter outline in dark
        // mode, but we don't yet respect dark mode in IOGraph (or anything
        // that uses QCustomPlot) - see link below for how to set QCP colors:
        // https://www.qcustomplot.com/index.php/demos/barchartdemo
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
        if (visible_ && need_retap_) {
            need_retap_ = false;
            emit requestRetap();
        } else {
            // XXX - If the number of enabled graphs changed to or from 1, we
            // need to recalculate to possibly change the rescaling. (This is
            // why QCP recommends doing scaling in the axis ticker instead.)
            // If we can't determine the number of enabled graphs here, always
            // request a recalculation instead of a replot. (At least until we
            // change the scaling to be done in the ticker.)
            //emit requestReplot();
            emit requestRecalc();
        }
    }
}

void IOGraph::setNeedRetap(bool retap)
{
    if (visible_ && retap) {
        emit requestRetap();
    } else {
        need_retap_ = retap;
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

QRgb IOGraph::color() const
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
    bool recalc = false;
    bool shows_zero = showsZero();

    // Switch plottable if needed
    switch (style) {
    case psBar:
    case psStackedBar:
        if (graph_) {
            bars_ = new QCPBars(parent_->xAxis, parent_->yAxis);
            // default widthType is wtPlotCoords. Scale with the interval
            // size to prevent overlap. (Multiply this by a factor to have
            // a gap between bars; the QCustomPlot default is 0.75.)
            if (interval_) {
                bars_->setWidth(interval_ / SCALE_F);
            }
            parent_->removeGraph(graph_);
            graph_ = NULL;
            recalc = true;
        }
        break;
    default:
        if (bars_) {
            graph_ = parent_->addGraph(parent_->xAxis, parent_->yAxis);
            parent_->removePlottable(bars_);
            bars_ = NULL;
            recalc = true;
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
    case psDotLine:
        if (graph_) {
            graph_->setLineStyle(QCPGraph::lsLine);
            graph_->setScatterStyle(QCPScatterStyle::ssDisc);
        }
        break;
    case psStepLine:
        if (graph_) {
            graph_->setLineStyle(QCPGraph::lsStepLeft);
        }
        break;
    case psDotStepLine:
        if (graph_) {
            graph_->setLineStyle(QCPGraph::lsStepLeft);
            graph_->setScatterStyle(QCPScatterStyle::ssDisc);
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
    case psCross:
        if (graph_) {
            graph_->setScatterStyle(QCPScatterStyle::ssCross);
        }
        break;
    case psPlus:
        if (graph_) {
            graph_->setScatterStyle(QCPScatterStyle::ssPlus);
        }
        break;
    case psCircle:
        if (graph_) {
            graph_->setScatterStyle(QCPScatterStyle::ssCircle);
        }
        break;

    case psBar:
    case IOGraph::psStackedBar:
        // Stacking set in scanGraphs
        bars_->moveBelow(NULL);
        break;
    }

    if (shows_zero != showsZero()) {
        // recalculate if whether zero is added changed
        recalc = true;
    }

    setName(name_);
    applyCurrentColor();

    if (recalc) {
        // switching the plottable requires recalculation to add the data
        emit requestRecalc();
    }
}

QString IOGraph::valueUnitLabel() const
{
    if (is_packet_configuration_namespace()) {
        return val_to_str_const(val_units_, y_axis_packet_vs, "Unknown");
    }
    return val_to_str_const(val_units_, y_axis_event_vs, "Unknown");
}

void IOGraph::setValueUnits(int val_units)
{
    if (val_units >= IOG_ITEM_UNIT_FIRST && val_units <= IOG_ITEM_UNIT_LAST) {
        int old_val_units = val_units_;
        val_units_ = (io_graph_item_unit_t)val_units;

        if (old_val_units != val_units) {
            // If val_units changed, switching between a type that doesn't
            // use the vu_field/hfi/edt to one of the advanced graphs that
            // does requires a retap. setFilter will handle that, because
            // the full filter strings will be different.
            if (setFilter(filter_)) { // Check config & prime vu field
                if (val_units == IOG_ITEM_UNIT_CALC_LOAD ||
                    old_val_units == IOG_ITEM_UNIT_CALC_LOAD) {
                    // LOAD graphs fill in the io_graph_item_t differently
                    // than other advanced graphs, so we have to retap even
                    // if the filter is the same. (update_io_graph_item could
                    // instead calculate and store LOAD information for any
                    // advanced graph type, but the tradeoff might not be
                    // worth it.)
                    setNeedRetap(true);
                }
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
        // If the field changed, and val_units is a type that uses it,
        // we need to retap. setFilter will handle that.
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

// This returns what graph key offset corresponds with relative time 0.0,
// i.e. when absolute times are used the difference between abs_ts and
// rel_ts of the first tapped packet. Generally the same for all graphs
// that are displayed and have some data, unless they're on the opposite
// sides of time references.
// XXX - If the graph spans a time reference, it's not clear how we want
// to switch from relative to absolute times.
double IOGraph::startOffset() const
{
    if (graph_ && qSharedPointerDynamicCast<QCPAxisTickerDateTime>(graph_->keyAxis()->ticker())) {
        return nstime_to_sec(&start_time_);
    }
    if (bars_ && qSharedPointerDynamicCast<QCPAxisTickerDateTime>(bars_->keyAxis()->ticker())) {
        return nstime_to_sec(&start_time_);
    }
    return 0.0;
}

nstime_t IOGraph::startTime() const
{
    if (graph_ && qSharedPointerDynamicCast<QCPAxisTickerDateTime>(graph_->keyAxis()->ticker())) {
        return start_time_;
    }
    if (bars_ && qSharedPointerDynamicCast<QCPAxisTickerDateTime>(bars_->keyAxis()->ticker())) {
        return start_time_;
    }
    return nstime_t(NSTIME_INIT_ZERO);
}

int IOGraph::packetFromTime(double ts) const
{
    int idx = ts * SCALE_F / interval_;
    if (idx >= 0 && idx <= cur_idx_) {
        switch (val_units_) {
        case IOG_ITEM_UNIT_CALC_MAX:
            return items_[idx].max_frame_in_invl;
        case IOG_ITEM_UNIT_CALC_MIN:
            return items_[idx].min_frame_in_invl;
        default:
            return items_[idx].last_frame_in_invl;
        }
    }
    return -1;
}

void IOGraph::clearAllData()
{
    cur_idx_ = -1;
    if (items_.size()) {
        reset_io_graph_items(&items_[0], items_.size(), hf_index_);
    }
    if (graph_) {
        graph_->data()->clear();
    }
    if (bars_) {
        bars_->data()->clear();
    }
    nstime_set_zero(&start_time_);
}

void IOGraph::recalcGraphData(capture_file *cap_file)
{
    /* Moving average variables */
    unsigned int mavg_in_average_count = 0, mavg_left = 0;
    unsigned int mavg_to_remove = 0, mavg_to_add = 0;
    double mavg_cumulated = 0;

    if (graph_) {
        graph_->data()->clear();
    }
    if (bars_) {
        bars_->data()->clear();
    }

    if (moving_avg_period_ > 0 && cur_idx_ >= 0) {
        /* "Warm-up phase" - calculate average on some data not displayed;
         * just to make sure average on leftmost and rightmost displayed
         * values is as reliable as possible
         */
        uint64_t warmup_interval = 0;

//        for (; warmup_interval < first_interval; warmup_interval += interval_) {
//            mavg_cumulated += get_it_value(io, i, (int)warmup_interval/interval_);
//            mavg_in_average_count++;
//            mavg_left++;
//        }
        mavg_cumulated += getItemValue((int)warmup_interval/interval_, cap_file);
        mavg_in_average_count++;
        for (warmup_interval = interval_;
            ((warmup_interval < (0 + (moving_avg_period_ / 2) * (uint64_t)interval_)) &&
             (warmup_interval <= (cur_idx_ * (uint64_t)interval_)));
             warmup_interval += interval_) {

            mavg_cumulated += getItemValue((int)warmup_interval / interval_, cap_file);
            mavg_in_average_count++;
        }
        mavg_to_add = (unsigned int)warmup_interval;
    }

    double ts_offset = startOffset();
    for (int i = 0; i <= cur_idx_; i++) {
        double ts = (double) i * interval_ / SCALE_F + ts_offset;
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
                }
            }
            if (mavg_in_average_count > 0) {
                val = mavg_cumulated / mavg_in_average_count;
            }
        }

        val *= y_axis_factor_;

        if (hasItemToShow(i, val))
        {
            if (graph_) {
                graph_->addData(ts, val);
            }
            if (bars_) {
                bars_->addData(ts, val);
            }
        }
    }

    emit requestReplot();
}

format_size_units_e IOGraph::formatUnits() const
{
    switch (val_units_) {
    case IOG_ITEM_UNIT_PACKETS:
    case IOG_ITEM_UNIT_CALC_FRAMES:
        if (is_packet_configuration_namespace()) {
            return FORMAT_SIZE_UNIT_PACKETS;
        }
        return FORMAT_SIZE_UNIT_EVENTS;
    case IOG_ITEM_UNIT_BYTES:
        return FORMAT_SIZE_UNIT_BYTES;
    case IOG_ITEM_UNIT_BITS:
        return FORMAT_SIZE_UNIT_BITS;
    case IOG_ITEM_UNIT_CALC_LOAD:
        return FORMAT_SIZE_UNIT_ERLANGS;
    case IOG_ITEM_UNIT_CALC_FIELDS:
        return FORMAT_SIZE_UNIT_FIELDS;
    case IOG_ITEM_UNIT_CALC_SUM:
    case IOG_ITEM_UNIT_CALC_MAX:
    case IOG_ITEM_UNIT_CALC_MIN:
    case IOG_ITEM_UNIT_CALC_AVERAGE:
        // Unit is not yet known, continue detecting it.
        if (hf_index_ > 0) {
            if (proto_registrar_get_ftype(hf_index_) == FT_RELATIVE_TIME) {
                return FORMAT_SIZE_UNIT_SECONDS;
            }
            // Could we look if it's BASE_UNIT_STRING and use that?
            // One complication is that prefixes shouldn't be combined,
            // and some unit strings are already prefixed units.
        }
        return FORMAT_SIZE_UNIT_NONE;
    case IOG_ITEM_UNIT_CALC_THROUGHPUT:
        return FORMAT_SIZE_UNIT_BITS_S;
    default:
        return FORMAT_SIZE_UNIT_NONE;
    }
}

template<class DataMap>
double IOGraph::maxValueFromGraphData(const DataMap &map)
{
    double maxValue = 0;
    typename DataMap::const_iterator it = map.constBegin();
    while (it != map.constEnd()) {
        maxValue = MAX(fabs((*it).value), maxValue);
        ++it;
    }
    return maxValue;
}

template<class DataMap>
void IOGraph::scaleGraphData(DataMap &map, int scalar)
{
    if (scalar != 1) {
        typename DataMap::iterator it = map.begin();
        while (it != map.end()) {
            (*it).value *= scalar;
            ++it;
        }
    }
}

void IOGraph::captureEvent(CaptureEvent e)
{
    if ((e.captureContext() == CaptureEvent::File) &&
            (e.eventType() == CaptureEvent::Closing))
    {
        removeTapListener();
    }
}

void IOGraph::reloadValueUnitField()
{
    if (vu_field_.length() > 0) {
        setValueUnitField(vu_field_);
    }
}

// returns true if the current plot style shows zero values,
// false if null values are omitted.
bool IOGraph::showsZero() const
{
    switch (val_units_) {
    case IOG_ITEM_UNIT_PACKETS:
    case IOG_ITEM_UNIT_BYTES:
    case IOG_ITEM_UNIT_BITS:
    case IOG_ITEM_UNIT_CALC_FRAMES:
    case IOG_ITEM_UNIT_CALC_FIELDS:
        if (graph_ && graph_->lineStyle() == QCPGraph::lsNone) {
            return false;
        }
        else {
            return true;
        }
    case IOG_ITEM_UNIT_CALC_SUM:
    case IOG_ITEM_UNIT_CALC_MAX:
    case IOG_ITEM_UNIT_CALC_MIN:
    case IOG_ITEM_UNIT_CALC_AVERAGE:
    case IOG_ITEM_UNIT_CALC_LOAD:
    case IOG_ITEM_UNIT_CALC_THROUGHPUT:
        // These are not the same sort of "omitted zeros" as above,
        // but changing val_units_ always results in a recalculation
        // so it doesn't matter (see modelDataChanged)
        return false;

    default:
        return true;
    }
}

// Check if a packet is available at the given interval (idx).
bool IOGraph::hasItemToShow(int idx, double value) const
{
    ws_assert(idx < max_io_items_);

    bool result = false;

    const io_graph_item_t *item = &items_[idx];

    switch (val_units_) {
    case IOG_ITEM_UNIT_PACKETS:
    case IOG_ITEM_UNIT_BYTES:
    case IOG_ITEM_UNIT_BITS:
    case IOG_ITEM_UNIT_CALC_FRAMES:
    case IOG_ITEM_UNIT_CALC_FIELDS:
        if (value == 0.0 && (graph_ && graph_->lineStyle() == QCPGraph::lsNone)) {
            result = false;
        }
        else {
            result = true;
        }
        break;

    case IOG_ITEM_UNIT_CALC_SUM:
    case IOG_ITEM_UNIT_CALC_MAX:
    case IOG_ITEM_UNIT_CALC_MIN:
    case IOG_ITEM_UNIT_CALC_AVERAGE:
    case IOG_ITEM_UNIT_CALC_LOAD:
    case IOG_ITEM_UNIT_CALC_THROUGHPUT:
        if (item->fields) {
            result = true;
        }
        break;

    default:
        result = true;
        break;
    }

    return result;
}

void IOGraph::setInterval(int interval)
{
    interval_ = interval;
    if (bars_) {
        bars_->setWidth(interval_ / SCALE_F);
    }
}

// Get the value at the given interval (idx) for the current value unit.
double IOGraph::getItemValue(int idx, const capture_file *cap_file) const
{
    ws_assert(idx < max_io_items_);

    return get_io_graph_item(&items_[0], val_units_, idx, hf_index_, cap_file, interval_, cur_idx_);
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
tap_packet_status IOGraph::tapPacket(void *iog_ptr, packet_info *pinfo, epan_dissect_t *edt, const void *, tap_flags_t)
{
    IOGraph *iog = static_cast<IOGraph *>(iog_ptr);
    if (!pinfo || !iog) {
        return TAP_PACKET_DONT_REDRAW;
    }

    int64_t tmp_idx = get_io_graph_index(pinfo, iog->interval_);
    bool recalc = false;

    /* some sanity checks */
    if ((tmp_idx < 0) || (tmp_idx >= max_io_items_)) {
        iog->cur_idx_ = (int)iog->items_.size() - 1;
        return TAP_PACKET_DONT_REDRAW;
    }

    int idx = (int)tmp_idx;
    /* If the graph isn't visible, don't do the work or redraw, but mark
     * the graph in need of a retap if it is ever enabled. The alternative
     * is to do the work, but clear pending retaps when the taps are reset
     * (which indicates something else triggered a retap.) The tradeoff would
     * be more calculation and memory usage when a graph is disabled in
     * exchange for fewer scenarios that involve retaps when toggling the
     * enabled/disabled taps.
     */
    if (!iog->visible()) {
        if (idx > iog->cur_idx_) {
            iog->need_retap_ = true;
        }
        return TAP_PACKET_DONT_REDRAW;
    }

    if ((size_t)idx >= iog->items_.size()) {
        const size_t old_size = iog->items_.size();
        size_t new_size;
        if (old_size == 0) {
            new_size = 1024;
        } else {
            new_size = MIN((old_size * 3) / 2, max_io_items_);
        }
        new_size = MAX(new_size, (size_t)idx + 1);
        try {
            iog->items_.resize(new_size);
        } catch (std::bad_alloc&) {
            // std::vector.resize() has strong exception safety
            ws_warning("Failed memory allocation!");
            return TAP_PACKET_DONT_REDRAW;
        }
        // resize zero-initializes new items, which is what we want
        //reset_io_graph_items(&iog->items_[old_size], new_size - old_size);
    }

    /* update num_items */
    if (idx > iog->cur_idx_) {
        iog->cur_idx_ = idx;
        recalc = true;
    }

    /* set start time */
    if (nstime_is_zero(&iog->start_time_)) {
        nstime_delta(&iog->start_time_, &pinfo->abs_ts, &pinfo->rel_ts);
    }

    epan_dissect_t *adv_edt = NULL;
    /* For ADVANCED mode we need to keep track of some more stuff than just frame and byte counts */
    if (iog->val_units_ >= IOG_ITEM_UNIT_CALC_SUM) {
        adv_edt = edt;
    }

    if (!update_io_graph_item(&iog->items_[0], idx, pinfo, adv_edt, iog->hf_index_, iog->val_units_, iog->interval_)) {
        return TAP_PACKET_DONT_REDRAW;
    }

//    qDebug() << "=tapPacket" << iog->name_ << idx << iog->hf_index_ << iog->val_units_ << iog->num_items_;

    if (recalc) {
        emit iog->requestRecalc();
    }
    return TAP_PACKET_REDRAW;
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
    mainApp->emitStatCommandSignal("IOGraph", NULL, NULL);
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
