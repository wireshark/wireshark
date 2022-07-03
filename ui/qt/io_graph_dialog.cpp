/* io_graph_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "io_graph_dialog.h"
#include <ui_io_graph_dialog.h>

#include "file.h"

#include <epan/stat_tap_ui.h>
#include "epan/stats_tree_priv.h"
#include "epan/uat-int.h"

#include <wsutil/utf8_entities.h>
#include <wsutil/ws_assert.h>

#include <ui/qt/utils/qt_ui_utils.h>

#include <ui/qt/utils/variant_pointer.h>

#include <ui/qt/utils/color_utils.h>
#include <ui/qt/widgets/qcustomplot.h>
#include "progress_frame.h"
#include "main_application.h"
#include <wsutil/report_message.h>

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

// Bugs and uncertainties:
// - Regular (non-stacked) bar graphs are drawn on top of each other on the Z axis.
//   The QCP forum suggests drawing them side by side:
//   https://www.qcustomplot.com/index.php/support/forum/62
// - We retap and redraw more than we should.
// - Smoothing doesn't seem to match GTK+
// - Closing the color picker on macOS sends the dialog to the background.
// - The color picker triggers https://bugreports.qt.io/browse/QTBUG-58699.

// To do:
// - Use scroll bars?
// - Scroll during live captures
// - Set ticks per pixel (e.g. pressing "2" sets 2 tpp).
// - Explicitly handle missing values, e.g. via NAN.
// - Add a "show missing" or "show zero" option to the UAT?
//   It would add yet another graph configuration column.

const qreal graph_line_width_ = 1.0;

const int DEFAULT_MOVING_AVERAGE = 0;
const int DEFAULT_Y_AXIS_FACTOR = 1;

// Don't accidentally zoom into a 1x1 rect if you happen to click on the graph
// in zoom mode.
const int min_zoom_pixels_ = 20;

const int stat_update_interval_ = 200; // ms

// Saved graph settings
typedef struct _io_graph_settings_t {
    gboolean enabled;
    char* name;
    char* dfilter;
    guint color;
    guint32 style;
    guint32 yaxis;
    char* yfield;
    guint32 sma_period;
    guint32 y_axis_factor;
} io_graph_settings_t;

static const value_string graph_style_vs[] = {
    { IOGraph::psLine, "Line" },
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

static const value_string y_axis_vs[] = {
    { IOG_ITEM_UNIT_PACKETS, "Packets" },
    { IOG_ITEM_UNIT_BYTES, "Bytes" },
    { IOG_ITEM_UNIT_BITS, "Bits" },
    { IOG_ITEM_UNIT_CALC_SUM, "SUM(Y Field)" },
    { IOG_ITEM_UNIT_CALC_FRAMES, "COUNT FRAMES(Y Field)" },
    { IOG_ITEM_UNIT_CALC_FIELDS, "COUNT FIELDS(Y Field)" },
    { IOG_ITEM_UNIT_CALC_MAX, "MAX(Y Field)" },
    { IOG_ITEM_UNIT_CALC_MIN, "MIN(Y Field)" },
    { IOG_ITEM_UNIT_CALC_AVERAGE, "AVG(Y Field)" },
    { IOG_ITEM_UNIT_CALC_LOAD, "LOAD(Y Field)" },
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

static io_graph_settings_t *iog_settings_ = NULL;
static guint num_io_graphs_ = 0;
static uat_t *iog_uat_ = NULL;

// y_axis_factor was added in 3.6. Provide backward compatibility.
static const char *iog_uat_defaults_[] = {
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "1"
};

extern "C" {

//Allow the enable/disable field to be a checkbox, but for backwards compatibility,
//the strings have to be "Enabled"/"Disabled", not "TRUE"/"FALSE"
#define UAT_BOOL_ENABLE_CB_DEF(basename,field_name,rec_t) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, guint len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    char* tmp_str = g_strndup(buf,len); \
    if ((g_strcmp0(tmp_str, "Enabled") == 0) || \
        (g_strcmp0(tmp_str, "TRUE") == 0)) \
        ((rec_t*)rec)->field_name = 1; \
    else \
        ((rec_t*)rec)->field_name = 0; \
    g_free(tmp_str); } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, char** out_ptr, unsigned* out_len, const void* UNUSED_PARAMETER(u1), const void* UNUSED_PARAMETER(u2)) {\
    *out_ptr = ws_strdup_printf("%s",((rec_t*)rec)->field_name ? "Enabled" : "Disabled"); \
    *out_len = (unsigned)strlen(*out_ptr); }

static gboolean uat_fld_chk_enable(void* u1 _U_, const char* strptr, guint len, const void* u2 _U_, const void* u3 _U_, char** err)
{
    char* str = g_strndup(strptr,len);

    if ((g_strcmp0(str, "Enabled") == 0) ||
        (g_strcmp0(str, "Disabled") == 0) ||
        (g_strcmp0(str, "TRUE") == 0) ||    //just for UAT functionality
        (g_strcmp0(str, "FALSE") == 0)) {
        *err = NULL;
        g_free(str);
        return TRUE;
    }

    //User should never see this unless they are manually modifying UAT
    *err = ws_strdup_printf("invalid value: %s (must be Enabled or Disabled)", str);
    g_free(str);
    return FALSE;
}

#define UAT_FLD_BOOL_ENABLE(basename,field_name,title,desc) \
{#field_name, title, PT_TXTMOD_BOOL,{uat_fld_chk_enable,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}

//"Custom" handler for sma_period enumeration for backwards compatibility
static void io_graph_sma_period_set_cb(void* rec, const char* buf, guint len, const void* vs, const void* u2 _U_)
{
    guint i;
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
            ((io_graph_settings_t*)rec)->sma_period = (guint32)((const value_string*)vs)[i].value;
            g_free(str);
            return;
        }
    }
    g_free(str);
}
//Duplicated because macro covers both functions
static void io_graph_sma_period_tostr_cb(void* rec, char** out_ptr, unsigned* out_len, const void* vs, const void* u2 _U_)
{
    guint i;
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

static gboolean sma_period_chk_enum(void* u1 _U_, const char* strptr, guint len, const void* v, const void* u3 _U_, char** err) {
    char *str = g_strndup(strptr,len);
    guint i;
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
            return TRUE;
        }
    }

    *err = ws_strdup_printf("invalid value: %s",str);
    g_free(str);
    return FALSE;
}

#define UAT_FLD_SMA_PERIOD(basename,field_name,title,enum,desc) \
    {#field_name, title, PT_TXTMOD_ENUM,{sma_period_chk_enum,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{&(enum),&(enum),&(enum)},&(enum),desc,FLDFILL}


UAT_BOOL_ENABLE_CB_DEF(io_graph, enabled, io_graph_settings_t)
UAT_CSTRING_CB_DEF(io_graph, name, io_graph_settings_t)
UAT_DISPLAY_FILTER_CB_DEF(io_graph, dfilter, io_graph_settings_t)
UAT_COLOR_CB_DEF(io_graph, color, io_graph_settings_t)
UAT_VS_DEF(io_graph, style, io_graph_settings_t, guint32, 0, "Line")
UAT_VS_DEF(io_graph, yaxis, io_graph_settings_t, guint32, 0, "Packets")
UAT_PROTO_FIELD_CB_DEF(io_graph, yfield, io_graph_settings_t)
UAT_DEC_CB_DEF(io_graph, y_axis_factor, io_graph_settings_t)

static uat_field_t io_graph_fields[] = {
    UAT_FLD_BOOL_ENABLE(io_graph, enabled, "Enabled", "Graph visibility"),
    UAT_FLD_CSTRING(io_graph, name, "Graph Name", "The name of the graph"),
    UAT_FLD_DISPLAY_FILTER(io_graph, dfilter, "Display Filter", "Graph packets matching this display filter"),
    UAT_FLD_COLOR(io_graph, color, "Color", "Graph color (#RRGGBB)"),
    UAT_FLD_VS(io_graph, style, "Style", graph_style_vs, "Graph style (Line, Bars, etc.)"),
    UAT_FLD_VS(io_graph, yaxis, "Y Axis", y_axis_vs, "Y Axis units"),
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

} // extern "C"

IOGraphDialog::IOGraphDialog(QWidget &parent, CaptureFile &cf, QString displayFilter) :
    WiresharkDialog(parent, cf),
    ui(new Ui::IOGraphDialog),
    uat_model_(nullptr),
    uat_delegate_(nullptr),
    base_graph_(nullptr),
    tracer_(nullptr),
    start_time_(0.0),
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
    loadGeometry();

    setWindowSubtitle(tr("I/O Graphs"));
    setAttribute(Qt::WA_DeleteOnClose, true);
    QCustomPlot *iop = ui->ioPlot;

    ui->newToolButton->setStockIcon("list-add");
    ui->deleteToolButton->setStockIcon("list-remove");
    ui->copyToolButton->setStockIcon("list-copy");
    ui->clearToolButton->setStockIcon("list-clear");

#ifdef Q_OS_MAC
    ui->newToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->deleteToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->copyToolButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->clearToolButton->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    QPushButton *save_bt = ui->buttonBox->button(QDialogButtonBox::Save);
    save_bt->setText(tr("Save As…"));

    QPushButton *copy_bt = ui->buttonBox->addButton(tr("Copy"), QDialogButtonBox::ActionRole);
    connect (copy_bt, SIGNAL(clicked()), this, SLOT(copyAsCsvClicked()));

    CopyFromProfileButton * copy_button = new CopyFromProfileButton(this, "io_graphs", tr("Copy graphs from another profile."));
    ui->buttonBox->addButton(copy_button, QDialogButtonBox::ActionRole);
    connect(copy_button, &CopyFromProfileButton::copyProfile, this, &IOGraphDialog::copyFromProfile);

    QPushButton *close_bt = ui->buttonBox->button(QDialogButtonBox::Close);
    if (close_bt) {
        close_bt->setDefault(true);
    }

    ui->automaticUpdateCheckBox->setChecked(prefs.gui_io_graph_automatic_update ? true : false);

    stat_timer_ = new QTimer(this);
    connect(stat_timer_, SIGNAL(timeout()), this, SLOT(updateStatistics()));
    stat_timer_->start(stat_update_interval_);

    // Intervals (ms)
    ui->intervalComboBox->addItem(tr("1 ms"),        1);
    ui->intervalComboBox->addItem(tr("2 ms"),        2);
    ui->intervalComboBox->addItem(tr("5 ms"),        5);
    ui->intervalComboBox->addItem(tr("10 ms"),      10);
    ui->intervalComboBox->addItem(tr("20 ms"),      20);
    ui->intervalComboBox->addItem(tr("50 ms"),      50);
    ui->intervalComboBox->addItem(tr("100 ms"),    100);
    ui->intervalComboBox->addItem(tr("200 ms"),    200);
    ui->intervalComboBox->addItem(tr("500 ms"),    500);
    ui->intervalComboBox->addItem(tr("1 sec"),    1000);
    ui->intervalComboBox->addItem(tr("2 sec"),    2000);
    ui->intervalComboBox->addItem(tr("5 sec"),    5000);
    ui->intervalComboBox->addItem(tr("10 sec"),  10000);
    ui->intervalComboBox->addItem(tr("1 min"),   60000);
    ui->intervalComboBox->addItem(tr("10 min"), 600000);
    ui->intervalComboBox->setCurrentIndex(9);

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
            if (ioGraphs_.at(i)->filter().compare(displayFilter) == 0)
                filterExists = true;
        }
        if (! filterExists && displayFilter.length() > 0)
            addGraph(true, tr("Filtered packets"), displayFilter, ColorUtils::graphColor(uat_model_->rowCount()),
                IOGraph::psLine, IOG_ITEM_UNIT_PACKETS, QString(), DEFAULT_MOVING_AVERAGE, DEFAULT_Y_AXIS_FACTOR);
    } else {
        addDefaultGraph(true, 0);
        addDefaultGraph(true, 1);
        if (displayFilter.length() > 0)
            addGraph(true, tr("Filtered packets"), displayFilter, ColorUtils::graphColor(uat_model_->rowCount()),
                IOGraph::psLine, IOG_ITEM_UNIT_PACKETS, QString(), DEFAULT_MOVING_AVERAGE, DEFAULT_Y_AXIS_FACTOR);
    }

    toggleTracerStyle(true);
    iop->setFocus();

    iop->rescaleAxes();

    ui->clearToolButton->setEnabled(uat_model_->rowCount() != 0);

    ui->splitter->setStretchFactor(0, 95);
    ui->splitter->setStretchFactor(1, 5);

    //XXX - resize columns?

    ProgressFrame::addToButtonBox(ui->buttonBox, &parent);

    connect(iop, SIGNAL(mousePress(QMouseEvent*)), this, SLOT(graphClicked(QMouseEvent*)));
    connect(iop, SIGNAL(mouseMove(QMouseEvent*)), this, SLOT(mouseMoved(QMouseEvent*)));
    connect(iop, SIGNAL(mouseRelease(QMouseEvent*)), this, SLOT(mouseReleased(QMouseEvent*)));
    disconnect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
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
    guint orig_data_len = iog_uat_->raw_data->len;

    gchar *err = NULL;
    if (uat_load(iog_uat_, filename.toUtf8().constData(), &err)) {
        iog_uat_->changed = TRUE;
        uat_model_->reloadUat();
        for (guint i = orig_data_len; i < iog_uat_->raw_data->len; i++) {
            createIOGraph(i);
        }
    } else {
        report_failure("Error while loading %s: %s", iog_uat_->name, err);
        g_free(err);
    }
}

void IOGraphDialog::addGraph(bool checked, QString name, QString dfilter, QRgb color_idx, IOGraph::PlotStyles style, io_graph_item_unit_t value_units, QString yfield, int moving_average, int y_axis_factor)
{

    QVariantList newRowData;
    newRowData.append(checked ? Qt::Checked : Qt::Unchecked);
    newRowData.append(name);
    newRowData.append(dfilter);
    newRowData.append(QColor(color_idx));
    newRowData.append(val_to_str_const(style, graph_style_vs, "None"));
    newRowData.append(val_to_str_const(value_units, y_axis_vs, "Packets"));
    newRowData.append(yfield);
    newRowData.append(val_to_str_const((guint32) moving_average, moving_avg_vs, "None"));
    newRowData.append(y_axis_factor);

    QModelIndex newIndex = uat_model_->appendEntry(newRowData);
    if ( !newIndex.isValid() )
    {
        qDebug() << "Failed to add a new record";
        return;
    }
    ui->graphUat->setCurrentIndex(newIndex);
    createIOGraph(newIndex.row());
}

void IOGraphDialog::addGraph(bool copy_from_current)
{
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
        createIOGraph(copyIdx.row());

        ui->graphUat->setCurrentIndex(copyIdx);
    } else {
        addDefaultGraph(false);
        copyIdx = uat_model_->index(uat_model_->rowCount() - 1, 0);
    }

    ui->graphUat->setCurrentIndex(copyIdx);
}

void IOGraphDialog::createIOGraph(int currentRow)
{
    // XXX - Should IOGraph have it's own list that has to sync with UAT?
    ioGraphs_.append(new IOGraph(ui->ioPlot));
    IOGraph* iog = ioGraphs_[currentRow];

    connect(this, SIGNAL(recalcGraphData(capture_file *, bool)), iog, SLOT(recalcGraphData(capture_file *, bool)));
    connect(this, SIGNAL(reloadValueUnitFields()), iog, SLOT(reloadValueUnitField()));
    connect(&cap_file_, SIGNAL(captureEvent(CaptureEvent)),
            iog, SLOT(captureEvent(CaptureEvent)));
    connect(iog, SIGNAL(requestRetap()), this, SLOT(scheduleRetap()));
    connect(iog, SIGNAL(requestRecalc()), this, SLOT(scheduleRecalc()));
    connect(iog, SIGNAL(requestReplot()), this, SLOT(scheduleReplot()));

    syncGraphSettings(currentRow);
    if (iog->visible()) {
        scheduleRetap();
    }
}

void IOGraphDialog::addDefaultGraph(bool enabled, int idx)
{
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

    if (!uat_model_->index(row, colEnabled).isValid() || !iog)
        return;

    bool visible = graphIsEnabled(row);
    bool retap = !iog->visible() && visible;
    QString data_str;

    iog->setName(uat_model_->data(uat_model_->index(row, colName)).toString());
    iog->setFilter(uat_model_->data(uat_model_->index(row, colDFilter)).toString());

    /* plot style depend on the value unit, so set it first. */
    data_str = uat_model_->data(uat_model_->index(row, colYAxis)).toString();
    iog->setValueUnits((int) str_to_val(qUtf8Printable(data_str), y_axis_vs, IOG_ITEM_UNIT_PACKETS));
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
        retap = false;
    }

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
    // A plot finished, force an update of the legend now in case a time unit
    // was involved (which might append "(ms)" to the label).
    updateLegend();
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

void IOGraphDialog::reject()
{
    if (!uat_model_)
        return;

    // Changes to the I/O Graphs settings are always saved,
    // there is no possibility for "rejection".
    QString error;
    if (uat_model_->applyChanges(error)) {
        if (!error.isEmpty()) {
            report_failure("%s", qPrintable(error));
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
    if (index.isValid()) {
        return ioGraphs_.value(index.row(), NULL);
    }

    //if no currently selected item, go with first item enabled
    for (int row = 0; row < uat_model_->rowCount(); row++)
    {
        if (graphIsEnabled(row)) {
            return ioGraphs_.value(row, NULL);
        }
    }

    return NULL;
}

bool IOGraphDialog::graphIsEnabled(int row) const
{
    Qt::CheckState state = static_cast<Qt::CheckState>(uat_model_->data(uat_model_->index(row, colEnabled), Qt::CheckStateRole).toInt());
    return state == Qt::Checked;
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
                    double iog_start = iog->startOffset();
                    if (start_time_ == 0.0 || iog_start < start_time_) {
                        start_time_ = iog_start;
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

void IOGraphDialog::updateLegend()
{
    QCustomPlot *iop = ui->ioPlot;
    QSet<QString> vu_label_set;
    QString intervalText = ui->intervalComboBox->itemText(ui->intervalComboBox->currentIndex());

    iop->legend->setVisible(false);
    iop->yAxis->setLabel(QString());

    // Find unique labels
    if (uat_model_ != NULL) {
        for (int row = 0; row < uat_model_->rowCount(); row++) {
            IOGraph *iog = ioGraphs_.value(row, Q_NULLPTR);
            if (graphIsEnabled(row) && iog) {
                QString label(iog->valueUnitLabel());
                if (!iog->scaledValueUnit().isEmpty()) {
                    label += " (" + iog->scaledValueUnit() + ")";
                }
                vu_label_set.insert(label);
            }
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
    // Legend Title thanks to: https://www.qcustomplot.com/index.php/support/forum/443
    QCPTextElement* legendTitle = qobject_cast<QCPTextElement*>(iop->legend->elementAt(0));
    if (legendTitle == NULL) {
        legendTitle = new QCPTextElement(iop, QString(""));
        iop->legend->insertRow(0);
        iop->legend->addElement(0, 0, legendTitle);
    }
    legendTitle->setText(QString(intervalText + " Intervals "));

    if (uat_model_ != NULL) {
        for (int row = 0; row < uat_model_->rowCount(); row++) {
            IOGraph *iog = ioGraphs_.value(row, Q_NULLPTR);
            if (iog) {
                if (graphIsEnabled(row)) {
                    iog->addToLegend();
                } else {
                    iog->removeFromLegend();
                }
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
#if QT_VERSION >= QT_VERSION_CHECK(6, 0 ,0)
        ctx_menu_.popup(event->globalPosition().toPoint());
#else
        ctx_menu_.popup(event->globalPos());
#endif
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
            if (IOGraph *iog = currentActiveGraph()) {
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

    if (need_retap_ && !file_closed_ && prefs.gui_io_graph_automatic_update) {
        need_retap_ = false;
        cap_file_.retapPackets();
        // The user might have closed the window while tapping, which means
        // we might no longer exist.
    } else {
        if (need_recalc_ && !file_closed_ && prefs.gui_io_graph_automatic_update) {
            need_recalc_ = false;
            need_replot_ = true;
            int enabled_graphs = 0;

            if (uat_model_ != NULL) {
                for (int row = 0; row < uat_model_->rowCount(); row++) {
                    if (graphIsEnabled(row)) {
                        ++enabled_graphs;
                    }
                }
            }
            // With multiple visible graphs, disable Y scaling to avoid
            // multiple, distinct units.
            emit recalcGraphData(cap_file_.capFile(), enabled_graphs == 1);
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
                           NULL,
                           io_graph_fields);

        uat_set_default_values(iog_uat_, iog_uat_defaults_);

        char* err = NULL;
        if (!uat_load(iog_uat_, NULL, &err)) {
            report_failure("Error while loading %s: %s.  Default graph values will be used", iog_uat_->name, err);
            g_free(err);
            uat_clear(iog_uat_);
        }
    }

    uat_model_ = new UatModel(NULL, iog_uat_);
    uat_delegate_ = new UatDelegate;
    ui->graphUat->setModel(uat_model_);
    ui->graphUat->setItemDelegate(uat_delegate_);

    connect(uat_model_, SIGNAL(dataChanged(QModelIndex,QModelIndex)),
            this, SLOT(modelDataChanged(QModelIndex)));
    connect(uat_model_, SIGNAL(modelReset()), this, SLOT(modelRowsReset()));
}

// Slots

void IOGraphDialog::on_intervalComboBox_currentIndexChanged(int)
{
    int interval = ui->intervalComboBox->itemData(ui->intervalComboBox->currentIndex()).toInt();
    bool need_retap = false;

    if (uat_model_ != NULL) {
        for (int row = 0; row < uat_model_->rowCount(); row++) {
            IOGraph *iog = ioGraphs_.value(row, NULL);
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

    if (checked) {
        ui->ioPlot->xAxis->setTicker(datetime_ticker_);
    } else {
        ui->ioPlot->xAxis->setTicker(number_ticker_);
    }
    auto_axes_ = false;
    scheduleRecalc(true);
    auto_axes_ = orig_auto;
    getGraphInfo();
    ui->ioPlot->xAxis->moveRange(start_time_ - orig_start);
    mouseMoved(NULL); // Update hint
}

void IOGraphDialog::modelRowsReset()
{
    ui->deleteToolButton->setEnabled(false);
    ui->copyToolButton->setEnabled(false);
    ui->clearToolButton->setEnabled(uat_model_->rowCount() != 0);
}

void IOGraphDialog::on_graphUat_currentItemChanged(const QModelIndex &current, const QModelIndex&)
{
    if (current.isValid()) {
        ui->deleteToolButton->setEnabled(true);
        ui->copyToolButton->setEnabled(true);
        ui->clearToolButton->setEnabled(true);
    } else {
        ui->deleteToolButton->setEnabled(false);
        ui->copyToolButton->setEnabled(false);
        ui->clearToolButton->setEnabled(false);
    }
}

void IOGraphDialog::modelDataChanged(const QModelIndex &index)
{
    bool recalc = false;

    switch (index.column())
    {
    case colYAxis:
    case colSMAPeriod:
        recalc = true;
    }

    syncGraphSettings(index.row());

    if (recalc) {
        scheduleRecalc(true);
    } else {
        scheduleReplot(true);
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
    const QModelIndex &current = ui->graphUat->currentIndex();
    if (uat_model_ && current.isValid()) {
        delete ioGraphs_[current.row()];
        ioGraphs_.remove(current.row());

        if (!uat_model_->removeRows(current.row(), 1)) {
            qDebug() << "Failed to remove row";
        }
    }

    // We should probably be smarter about this.
    hint_err_.clear();
    mouseMoved(NULL);
}

void IOGraphDialog::on_copyToolButton_clicked()
{
    addGraph(true);
}

void IOGraphDialog::on_clearToolButton_clicked()
{
    if (uat_model_) {
        foreach(IOGraph* iog, ioGraphs_) {
            delete iog;
        }
        ioGraphs_.clear();
        uat_model_->clearAll();
    }

    hint_err_.clear();
    mouseMoved(NULL);
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

    iop->yAxis->setScaleType(checked ? QCPAxis::stLogarithmic : QCPAxis::stLinear);
    iop->replot();
}

void IOGraphDialog::on_automaticUpdateCheckBox_toggled(bool checked)
{
    prefs.gui_io_graph_automatic_update = checked ? TRUE : FALSE;

    prefs_main_write();

    if(prefs.gui_io_graph_automatic_update)
    {
        updateStatistics();
    }
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
    mainApp->helpTopicAction(HELP_STATS_IO_GRAPH_DIALOG);
}

// XXX - We have similar code in tcp_stream_dialog and packet_diagram. Should this be a common routine?
void IOGraphDialog::on_buttonBox_accepted()
{
    QString file_name, extension;
    QDir path(mainApp->lastOpenDir());
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

void IOGraphDialog::makeCsv(QTextStream &stream) const
{
    QList<IOGraph *> activeGraphs;

    int ui_interval = ui->intervalComboBox->itemData(ui->intervalComboBox->currentIndex()).toInt();
    int max_interval = 0;

    stream << "\"Interval start\"";
    if (uat_model_ != NULL) {
        for (int row = 0; row < uat_model_->rowCount(); row++) {
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
    }

    stream << '\n';

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
    visible_(false),
    graph_(NULL),
    bars_(NULL),
    val_units_(IOG_ITEM_UNIT_FIRST),
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
                          tapDraw,
                          NULL);
    if (error_string) {
//        QMessageBox::critical(this, tr("%1 failed to register tap listener").arg(name_),
//                             error_string->str);
//        config_err_ = error_string->str;
        g_string_free(error_string, TRUE);
    }
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

    setName(name_);
    applyCurrentColor();
}

const QString IOGraph::valueUnitLabel()
{
    return val_to_str_const(val_units_, y_axis_vs, "Unknown");
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
    if (graph_ && qSharedPointerDynamicCast<QCPAxisTickerDateTime>(graph_->keyAxis()->ticker()) && graph_->data()->size() > 0) {
        return graph_->data()->at(0)->key;
    }
    if (bars_ && qSharedPointerDynamicCast<QCPAxisTickerDateTime>(bars_->keyAxis()->ticker()) && bars_->data()->size() > 0) {
        return bars_->data()->at(0)->key;
    }
    return 0.0;
}

int IOGraph::packetFromTime(double ts)
{
    int idx = ts * 1000 / interval_;
    if (idx >= 0 && idx < (int) cur_idx_) {
        switch (val_units_) {
        case IOG_ITEM_UNIT_CALC_MAX:
        case IOG_ITEM_UNIT_CALC_MIN:
            return items_[idx].extreme_frame_in_invl;
        default:
            return items_[idx].last_frame_in_invl;
        }
    }
    return -1;
}

void IOGraph::clearAllData()
{
    cur_idx_ = -1;
    reset_io_graph_items(items_, max_io_items_);
    if (graph_) {
        graph_->data()->clear();
    }
    if (bars_) {
        bars_->data()->clear();
    }
    start_time_ = 0.0;
}

void IOGraph::recalcGraphData(capture_file *cap_file, bool enable_scaling)
{
    /* Moving average variables */
    unsigned int mavg_in_average_count = 0, mavg_left = 0, mavg_right = 0;
    unsigned int mavg_to_remove = 0, mavg_to_add = 0;
    double mavg_cumulated = 0;
    QCPAxis *x_axis = nullptr;

    if (graph_) {
        graph_->data()->clear();
        x_axis = graph_->keyAxis();
    }
    if (bars_) {
        bars_->data()->clear();
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
        mavg_to_add = (unsigned int)warmup_interval;
    }

    for (int i = 0; i <= cur_idx_; i++) {
        double ts = (double) i * interval_ / 1000;
        if (x_axis && qSharedPointerDynamicCast<QCPAxisTickerDateTime>(x_axis->ticker())) {
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
//        qDebug() << "=rgd i" << i << ts << val;
    }

    // attempt to rescale time values to specific units
    if (enable_scaling) {
        calculateScaledValueUnit();
    } else {
        scaled_value_unit_.clear();
    }

    emit requestReplot();
}

void IOGraph::calculateScaledValueUnit()
{
    // Reset unit and recalculate if needed.
    scaled_value_unit_.clear();

    // If there is no field, scaling is not possible.
    if (hf_index_ < 0) {
        return;
    }

    switch (val_units_) {
    case IOG_ITEM_UNIT_CALC_SUM:
    case IOG_ITEM_UNIT_CALC_MAX:
    case IOG_ITEM_UNIT_CALC_MIN:
    case IOG_ITEM_UNIT_CALC_AVERAGE:
        // Unit is not yet known, continue detecting it.
        break;
    default:
        // Unit is Packets, Bytes, Bits, etc.
        return;
    }

    if (proto_registrar_get_ftype(hf_index_) == FT_RELATIVE_TIME) {
        // find maximum absolute value and scale accordingly
        double maxValue = 0;
        if (graph_) {
            maxValue = maxValueFromGraphData(*graph_->data());
        } else if (bars_) {
            maxValue = maxValueFromGraphData(*bars_->data());
        }
        // If the maximum value is zero, then either we have no data or
        // everything is zero, do not scale the unit in this case.
        if (maxValue == 0) {
            return;
        }

        // XXX GTK+ always uses "ms" for log scale, should we do that too?
        int value_multiplier;
        if (maxValue >= 1.0) {
            scaled_value_unit_ = "s";
            value_multiplier = 1;
        } else if (maxValue >= 0.001) {
            scaled_value_unit_ = "ms";
            value_multiplier = 1000;
        } else {
            scaled_value_unit_ = "us";
            value_multiplier = 1000000;
        }

        if (graph_) {
            scaleGraphData(*graph_->data(), value_multiplier);
        } else if (bars_) {
            scaleGraphData(*bars_->data(), value_multiplier);
        }
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
         remove_tap_listener(this);
    }
}

void IOGraph::reloadValueUnitField()
{
    if (vu_field_.length() > 0) {
        setValueUnitField(vu_field_);
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
        if(value == 0.0 && (graph_ && graph_->scatterStyle().shape() != QCPScatterStyle::ssNone)) {
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
}

// Get the value at the given interval (idx) for the current value unit.
double IOGraph::getItemValue(int idx, const capture_file *cap_file) const
{
    ws_assert(idx < max_io_items_);

    return get_io_graph_item(items_, val_units_, idx, hf_index_, cap_file, interval_, cur_idx_);
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

    int idx = get_io_graph_index(pinfo, iog->interval_);
    bool recalc = false;

    /* some sanity checks */
    if ((idx < 0) || (idx >= max_io_items_)) {
        iog->cur_idx_ = max_io_items_ - 1;
        return TAP_PACKET_DONT_REDRAW;
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
