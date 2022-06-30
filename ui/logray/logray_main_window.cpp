/* logray_main_window.cpp
 *
 * Logray - Event log analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "main_application.h"
#include "logray_main_window.h"

/*
 * The generated Ui_LograyMainWindow::setupUi() can grow larger than our configured limit,
 * so turn off -Wframe-larger-than= for ui_main_window.h.
 */
DIAG_OFF(frame-larger-than=)
#include <ui_logray_main_window.h>
DIAG_ON(frame-larger-than=)

#include <epan/addr_resolv.h>
#include "epan/conversation_filter.h"
#include <epan/epan_dissect.h>
#include <wsutil/filesystem.h>
#include <wsutil/wslog.h>
#include <wsutil/ws_assert.h>
#include <ui/version_info.h>
#include <epan/prefs.h>
#include <epan/stats_tree_priv.h>
#include <epan/plugin_if.h>
#include <epan/export_object.h>
#include <frame_tvbuff.h>

#include "ui/iface_toolbar.h"

#ifdef HAVE_LIBPCAP
#include "ui/capture.h"
#include <capture/capture_session.h>
#endif

#include "ui/alert_box.h"
#ifdef HAVE_LIBPCAP
#include "ui/capture_ui_utils.h"
#endif
#include "ui/capture_globals.h"
#include "ui/main_statusbar.h"
#include "ui/recent.h"
#include "ui/recent_utils.h"
#include "ui/util.h"
#include "ui/preference_utils.h"

#include "byte_view_tab.h"
#ifdef HAVE_LIBPCAP
#include "capture_options_dialog.h"
#endif
#include "conversation_colorize_action.h"
#include "export_dissection_dialog.h"
#include "export_object_action.h"
#include "file_set_dialog.h"
#include "filter_dialog.h"
#include "funnel_statistics.h"
#include "import_text_dialog.h"
#include "interface_toolbar.h"
#include "packet_diagram.h"
#include "packet_list.h"
#include "proto_tree.h"
#include "simple_dialog.h"
#include "tap_parameter_dialog.h"

#include <ui/qt/widgets/additional_toolbar.h>
#include <ui/qt/widgets/display_filter_edit.h>
#include <ui/qt/widgets/filter_expression_toolbar.h>

#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/stock_icon.h>
#include <ui/qt/utils/variant_pointer.h>

#include <QAction>
#include <QActionGroup>
#include <QIntValidator>
#include <QKeyEvent>
#include <QList>
#include <QMessageBox>
#include <QMetaObject>
#include <QMimeData>
#include <QTabWidget>
#include <QTextCodec>
#include <QToolButton>
#include <QTreeWidget>
#include <QUrl>

//menu_recent_file_write_all

// If we ever add support for multiple windows this will need to be replaced.
static LograyMainWindow *gbl_cur_main_window_ = NULL;

void pipe_input_set_handler(gint source, gpointer user_data, ws_process_id *child_process, pipe_input_cb_t input_cb)
{
    gbl_cur_main_window_->setPipeInputHandler(source, user_data, child_process, input_cb);
}

static void plugin_if_mainwindow_apply_filter(GHashTable * data_set)
{
    if (!gbl_cur_main_window_ || !data_set)
        return;

    if (g_hash_table_lookup_extended(data_set, "filter_string", NULL, NULL)) {
        QString filter((const char *)g_hash_table_lookup(data_set, "filter_string"));
        gbl_cur_main_window_->filterPackets(filter);
    }
}

static void plugin_if_mainwindow_preference(GHashTable * data_set)
{
    if (!gbl_cur_main_window_ || !data_set)
        return;

    const char * module_name;
    const char * pref_name;
    const char * pref_value;

DIAG_OFF_CAST_AWAY_CONST
    if (g_hash_table_lookup_extended(data_set, "pref_module", NULL, (gpointer *)&module_name) &&
        g_hash_table_lookup_extended(data_set, "pref_key", NULL, (gpointer *)&pref_name) &&
        g_hash_table_lookup_extended(data_set, "pref_value", NULL, (gpointer *)&pref_value))
    {
        unsigned int changed_flags = prefs_store_ext(module_name, pref_name, pref_value);
        if (changed_flags) {
            mainApp->emitAppSignal(WiresharkApplication::PacketDissectionChanged);
            mainApp->emitAppSignal(WiresharkApplication::PreferencesChanged);
        }
    }
DIAG_ON_CAST_AWAY_CONST
}

static void plugin_if_mainwindow_gotoframe(GHashTable * data_set)
{
    if (!gbl_cur_main_window_ || !data_set)
        return;

    gpointer framenr;

    if (g_hash_table_lookup_extended(data_set, "frame_nr", NULL, &framenr)) {
        if (GPOINTER_TO_UINT(framenr) != 0)
            gbl_cur_main_window_->gotoFrame(GPOINTER_TO_UINT(framenr));
    }
}

#ifdef HAVE_LIBPCAP

static void plugin_if_mainwindow_get_ws_info(GHashTable * data_set)
{
    if (!gbl_cur_main_window_ || !data_set)
        return;

    ws_info_t *ws_info = NULL;

    if (!g_hash_table_lookup_extended(data_set, "ws_info", NULL, (void**)&ws_info))
        return;

    CaptureFile *cfWrap = gbl_cur_main_window_->captureFile();
    capture_file *cf = cfWrap->capFile();

    ws_info->ws_info_supported = true;

    /* If we have a filename attached to ws_info clear it */
    if (ws_info->cf_filename != NULL)
    {
        g_free(ws_info->cf_filename);
        ws_info->cf_filename = NULL;
    }

    /* Determine the true state of the capture file.  We return the true state in
    the ws_info structure and DON'T CHANGE the cf->state as we don't want to cause problems
    with code that follows this. */
    if (cf)
    {
        if (cf->filename)
        {
            /* As we have a cf->filename we'll use the name and the state */
            ws_info->cf_filename = g_strdup(cf->filename);
            ws_info->cf_state = cf->state;
        }
        else
        {
            /* When we come through here the cf->state can show FILE_READ_DONE even though the
            file is actually closed (no filename). A better fix would be to have a
            FILE_CLOSE_PENDING state but that involves a lot of code change elsewhere. */
            ws_info->cf_state = FILE_CLOSED;
        }
    }

    if (!ws_info->cf_filename)
    {
        /* We may have a filename associated with the main window so let's use it */
        QString fileNameString = gbl_cur_main_window_->getMwFileName();
        if (fileNameString.length())
        {
            QByteArray ba = fileNameString.toLatin1();
            const char *c_file_name = ba.data();
            ws_info->cf_filename = g_strdup(c_file_name);
        }
    }

    if (cf) {
        ws_info->cf_count = cf->count;

        QList<int> rows = gbl_cur_main_window_->selectedRows();
        frame_data * fdata = NULL;
        if (rows.count() > 0)
            fdata = gbl_cur_main_window_->frameDataForRow(rows.at(0));

        if (cf->state == FILE_READ_DONE && fdata) {
            ws_info->cf_framenr = fdata->num;
            ws_info->frame_passed_dfilter = (fdata->passed_dfilter == 1);
        }
        else {
            ws_info->cf_framenr = 0;
            ws_info->frame_passed_dfilter = FALSE;
        }
    }
    else
    {
        /* Initialise the other ws_info structure values */
        ws_info->cf_count = 0;
        ws_info->cf_framenr = 0;
        ws_info->frame_passed_dfilter = FALSE;
    }
}

#endif /* HAVE_LIBPCAP */

static void plugin_if_mainwindow_get_frame_data(GHashTable* data_set)
{
    if (!gbl_cur_main_window_ || !data_set)
        return;

    plugin_if_frame_data_cb extract_cb;
    void* user_data;
    void** ret_value_ptr;

    if (g_hash_table_lookup_extended(data_set, "extract_cb", NULL, (void**)&extract_cb) &&
        g_hash_table_lookup_extended(data_set, "user_data", NULL, (void**)&user_data) &&
        g_hash_table_lookup_extended(data_set, "ret_value_ptr", NULL, (void**)&ret_value_ptr))
    {
        QList<int> rows = gbl_cur_main_window_->selectedRows();
        if (rows.count() > 0) {
            frame_data* fdata = gbl_cur_main_window_->frameDataForRow(rows.at(0));
            if (fdata) {
                *ret_value_ptr = extract_cb(fdata, user_data);
            }
        }
    }
}

static void plugin_if_mainwindow_get_capture_file(GHashTable* data_set)
{
    if (!gbl_cur_main_window_ || !data_set)
        return;

    plugin_if_capture_file_cb extract_cb;
    void* user_data;
    void** ret_value_ptr;

    if (g_hash_table_lookup_extended(data_set, "extract_cb", NULL, (void**)&extract_cb) &&
        g_hash_table_lookup_extended(data_set, "user_data", NULL, (void**)&user_data) &&
        g_hash_table_lookup_extended(data_set, "ret_value_ptr", NULL, (void**)&ret_value_ptr))
    {
        CaptureFile* cfWrap = gbl_cur_main_window_->captureFile();
        capture_file* cf = cfWrap->capFile();
        if (cf) {
            *ret_value_ptr = extract_cb(cf, user_data);
        }
    }
}

static void plugin_if_mainwindow_update_toolbars(GHashTable * data_set)
{
    if (!gbl_cur_main_window_ || !data_set)
        return;

    if (g_hash_table_lookup_extended(data_set, "toolbar_name", NULL, NULL)) {
        QString toolbarName((const char *)g_hash_table_lookup(data_set, "toolbar_name"));
        gbl_cur_main_window_->removeAdditionalToolbar(toolbarName);

    }
}

static void mainwindow_add_toolbar(const iface_toolbar *toolbar_entry)
{
    if (gbl_cur_main_window_ && toolbar_entry)
    {
        gbl_cur_main_window_->addInterfaceToolbar(toolbar_entry);
    }
}

static void mainwindow_remove_toolbar(const gchar *menu_title)
{
    if (gbl_cur_main_window_ && menu_title)
    {
        gbl_cur_main_window_->removeInterfaceToolbar(menu_title);
    }
}

QMenu* LograyMainWindow::findOrAddMenu(QMenu *parent_menu, QString& menu_text) {
    QList<QAction *> actions = parent_menu->actions();
    QList<QAction *>::const_iterator i;
    for (i = actions.constBegin(); i != actions.constEnd(); ++i) {
        if ((*i)->text()==menu_text) {
            return (*i)->menu();
        }
    }
    // If we get here there menu entry was not found, add a sub menu
    return parent_menu->addMenu(menu_text);
}

LograyMainWindow::LograyMainWindow(QWidget *parent) :
    MainWindow(parent),
    main_ui_(new Ui::LograyMainWindow),
    previous_focus_(NULL),
    file_set_dialog_(NULL),
    show_hide_actions_(NULL),
    time_display_actions_(NULL),
    time_precision_actions_(NULL),
    funnel_statistics_(NULL),
    freeze_focus_(NULL),
    was_maximized_(false),
    capture_stopping_(false),
    capture_filter_valid_(false)
#ifdef HAVE_LIBPCAP
    , capture_options_dialog_(NULL)
    , info_data_()
#endif
    , display_filter_dlg_(NULL)
    , capture_filter_dlg_(NULL)
#ifdef _WIN32
    , pipe_timer_(NULL)
#else
    , pipe_notifier_(NULL)
#endif
#if defined(Q_OS_MAC)
    , dock_menu_(NULL)
#endif
{
    if (!gbl_cur_main_window_) {
        connect(mainApp, SIGNAL(openStatCommandDialog(QString, const char*, void*)),
                this, SLOT(openStatCommandDialog(QString, const char*, void*)));
        connect(mainApp, SIGNAL(openTapParameterDialog(QString, const QString, void*)),
                this, SLOT(openTapParameterDialog(QString, const QString, void*)));
    }
    gbl_cur_main_window_ = this;
#ifdef HAVE_LIBPCAP
    capture_input_init(&cap_session_, CaptureFile::globalCapFile());
#endif

    findTextCodecs();
    // setpUi calls QMetaObject::connectSlotsByName(this). connectSlotsByName
    // iterates over *all* of our children, looking for matching "on_" slots.
    // The fewer children we have at this point the better.
    main_ui_->setupUi(this);
#ifdef HAVE_SOFTWARE_UPDATE
    update_action_ = new QAction(tr("Check for Updates…"), main_ui_->menuHelp);
#endif

    menu_groups_ = QList<register_stat_group_t>()
            << REGISTER_LOG_ANALYZE_GROUP_UNSORTED
            << REGISTER_LOG_STAT_GROUP_UNSORTED;

    setWindowIcon(mainApp->normalIcon());
    setTitlebarForCaptureFile();
    setMenusForCaptureFile();
    setForCapturedPackets(false);
    setMenusForFileSet(false);
    interfaceSelectionChanged();
    loadWindowGeometry();

#ifndef HAVE_LUA
    main_ui_->actionAnalyzeReloadLuaPlugins->setVisible(false);
#endif

    qRegisterMetaType<FilterAction::Action>("FilterAction::Action");
    qRegisterMetaType<FilterAction::ActionType>("FilterAction::ActionType");
    connect(this, SIGNAL(filterAction(QString, FilterAction::Action, FilterAction::ActionType)),
            this, SLOT(queuedFilterAction(QString, FilterAction::Action, FilterAction::ActionType)),
            Qt::QueuedConnection);

    //To prevent users use features before initialization complete
    //Otherwise unexpected problems may occur
    setFeaturesEnabled(false);
    connect(mainApp, SIGNAL(appInitialized()), this, SLOT(setFeaturesEnabled()));
    connect(mainApp, SIGNAL(appInitialized()), this, SLOT(applyGlobalCommandLineOptions()));
    connect(mainApp, SIGNAL(appInitialized()), this, SLOT(zoomText()));
    connect(mainApp, SIGNAL(appInitialized()), this, SLOT(initViewColorizeMenu()));
    connect(mainApp, SIGNAL(appInitialized()), this, SLOT(addStatsPluginsToMenu()));
    connect(mainApp, SIGNAL(appInitialized()), this, SLOT(addDynamicMenus()));
    connect(mainApp, SIGNAL(appInitialized()), this, SLOT(addPluginIFStructures()));
    connect(mainApp, SIGNAL(appInitialized()), this, SLOT(initConversationMenus()));
    connect(mainApp, SIGNAL(appInitialized()), this, SLOT(initExportObjectsMenus()));

    connect(mainApp, SIGNAL(profileChanging()), this, SLOT(saveWindowGeometry()));
    connect(mainApp, SIGNAL(preferencesChanged()), this, SLOT(layoutPanes()));
    connect(mainApp, SIGNAL(preferencesChanged()), this, SLOT(layoutToolbars()));
    connect(mainApp, SIGNAL(preferencesChanged()), this, SLOT(updatePreferenceActions()));
    connect(mainApp, SIGNAL(preferencesChanged()), this, SLOT(zoomText()));
    connect(mainApp, SIGNAL(preferencesChanged()), this, SLOT(setTitlebarForCaptureFile()));

    connect(mainApp, SIGNAL(updateRecentCaptureStatus(const QString &, qint64, bool)), this, SLOT(updateRecentCaptures()));
    updateRecentCaptures();

#if defined(HAVE_SOFTWARE_UPDATE) && defined(Q_OS_WIN)
    connect(mainApp, SIGNAL(softwareUpdateRequested()), this, SLOT(softwareUpdateRequested()),
        Qt::BlockingQueuedConnection);
    connect(mainApp, SIGNAL(softwareUpdateClose()), this, SLOT(close()),
        Qt::BlockingQueuedConnection);
#endif

    df_combo_box_ = new DisplayFilterCombo(this);

    funnel_statistics_ = new FunnelStatistics(this, capture_file_);
    connect(df_combo_box_, &QComboBox::editTextChanged, funnel_statistics_, &FunnelStatistics::displayFilterTextChanged);
    connect(funnel_statistics_, &FunnelStatistics::setDisplayFilter, this, &LograyMainWindow::setDisplayFilter);
    connect(funnel_statistics_, SIGNAL(openCaptureFile(QString, QString)),
            this, SLOT(openCaptureFile(QString, QString)));

    file_set_dialog_ = new FileSetDialog(this);
    connect(file_set_dialog_, SIGNAL(fileSetOpenCaptureFile(QString)),
            this, SLOT(openCaptureFile(QString)));

    initMainToolbarIcons();

    main_ui_->displayFilterToolBar->insertWidget(main_ui_->actionNewDisplayFilterExpression, df_combo_box_);

    // Make sure filter expressions overflow into a menu instead of a
    // larger toolbar. We do this by adding them to a child toolbar.
    // https://bugreports.qt.io/browse/QTBUG-2472
    FilterExpressionToolBar *filter_expression_toolbar_ = new FilterExpressionToolBar(this);
    connect(filter_expression_toolbar_, &FilterExpressionToolBar::filterPreferences, this, &LograyMainWindow::onFilterPreferences);
    connect(filter_expression_toolbar_, &FilterExpressionToolBar::filterSelected, this, &LograyMainWindow::onFilterSelected);
    connect(filter_expression_toolbar_, &FilterExpressionToolBar::filterEdit, this, &LograyMainWindow::onFilterEdit);

    main_ui_->displayFilterToolBar->addWidget(filter_expression_toolbar_);

    main_ui_->goToFrame->hide();
    connect(main_ui_->goToFrame, SIGNAL(visibilityChanged(bool)),
            main_ui_->actionGoGoToPacket, SLOT(setChecked(bool)));

    // XXX For some reason the cursor is drawn funny with an input mask set
    // https://bugreports.qt-project.org/browse/QTBUG-7174

    main_ui_->searchFrame->hide();
    connect(main_ui_->searchFrame, SIGNAL(visibilityChanged(bool)),
            main_ui_->actionEditFindPacket, SLOT(setChecked(bool)));

    main_ui_->addressEditorFrame->hide();
    main_ui_->columnEditorFrame->hide();
    main_ui_->preferenceEditorFrame->hide();
    main_ui_->filterExpressionFrame->hide();

#ifndef HAVE_LIBPCAP
    main_ui_->menuCapture->setEnabled(false);
#endif

    // Set OS specific shortcuts for fullscreen mode
#if defined(Q_OS_MAC)
    main_ui_->actionViewFullScreen->setShortcut(QKeySequence::FullScreen);
#else
    main_ui_->actionViewFullScreen->setShortcut(QKeySequence(Qt::Key_F11));
#endif

#if defined(Q_OS_MAC)

    main_ui_->goToPacketLabel->setAttribute(Qt::WA_MacSmallSize, true);
    main_ui_->goToLineEdit->setAttribute(Qt::WA_MacSmallSize, true);
    main_ui_->goToGo->setAttribute(Qt::WA_MacSmallSize, true);
    main_ui_->goToCancel->setAttribute(Qt::WA_MacSmallSize, true);

    main_ui_->actionEditPreferences->setMenuRole(QAction::PreferencesRole);

#endif // Q_OS_MAC

// A billion-1 is equivalent to the inputMask 900000000 previously used
// Avoid QValidator::Intermediate values by using a top value of all 9's
#define MAX_GOTO_LINE 999999999

QIntValidator *goToLineQiv = new QIntValidator(0,MAX_GOTO_LINE,this);
main_ui_->goToLineEdit->setValidator(goToLineQiv);

#ifdef HAVE_SOFTWARE_UPDATE
    QAction *update_sep = main_ui_->menuHelp->insertSeparator(main_ui_->actionHelpAbout);
    main_ui_->menuHelp->insertAction(update_sep, update_action_);
    connect(update_action_, SIGNAL(triggered()), this, SLOT(checkForUpdates()));
#endif
    master_split_.setObjectName("splitterMaster");
    extra_split_.setObjectName("splitterExtra");
    master_split_.setChildrenCollapsible(false);
    extra_split_.setChildrenCollapsible(false);
    main_ui_->mainStack->addWidget(&master_split_);

    empty_pane_.setObjectName("emptyPane");
    empty_pane_.setVisible(false);

    packet_list_ = new PacketList(&master_split_);
    connect(packet_list_, SIGNAL(framesSelected(QList<int>)), this, SLOT(setMenusForSelectedPacket()));
    connect(packet_list_, SIGNAL(framesSelected(QList<int>)), this, SIGNAL(framesSelected(QList<int>)));

    connect(main_ui_->menuPacketComment, SIGNAL(aboutToShow()), this, SLOT(setEditCommentsMenu()));

    proto_tree_ = new ProtoTree(&master_split_);
    proto_tree_->installEventFilter(this);

    packet_list_->setProtoTree(proto_tree_);
    packet_list_->installEventFilter(this);

    packet_diagram_ = new PacketDiagram(&master_split_);

    main_stack_ = main_ui_->mainStack;
    welcome_page_ = main_ui_->welcomePage;
    main_status_bar_ = main_ui_->statusBar;

    connect(proto_tree_, &ProtoTree::fieldSelected,
            this, &LograyMainWindow::fieldSelected);
    connect(packet_list_, &PacketList::fieldSelected,
            this, &LograyMainWindow::fieldSelected);
    connect(this, &LograyMainWindow::fieldSelected,
            this, &LograyMainWindow::setMenusForSelectedTreeRow);
    connect(this, &LograyMainWindow::fieldSelected,
            main_ui_->statusBar, &MainStatusBar::selectedFieldChanged);

    connect(this, &LograyMainWindow::fieldHighlight,
            main_ui_->statusBar, &MainStatusBar::highlightedFieldChanged);
    connect(mainApp, &WiresharkApplication::captureActive,
            this, &LograyMainWindow::captureActive);

    byte_view_tab_ = new ByteViewTab(&master_split_);

    // Packet list and proto tree must exist before these are called.
    setMenusForSelectedPacket();
    setMenusForSelectedTreeRow();

    initShowHideMainWidgets();
    initTimeDisplayFormatMenu();
    initTimePrecisionFormatMenu();
    initFreezeActions();
    updatePreferenceActions();
    updateRecentActions();
    setForCaptureInProgress(false);

    setTabOrder(df_combo_box_->lineEdit(), packet_list_);
    setTabOrder(packet_list_, proto_tree_);

    connect(&capture_file_, SIGNAL(captureEvent(CaptureEvent)),
            this, SLOT(captureEventHandler(CaptureEvent)));
    connect(&capture_file_, SIGNAL(captureEvent(CaptureEvent)),
            mainApp, SLOT(captureEventHandler(CaptureEvent)));
    connect(&capture_file_, SIGNAL(captureEvent(CaptureEvent)),
            main_ui_->statusBar, SLOT(captureEventHandler(CaptureEvent)));

    connect(mainApp, SIGNAL(columnsChanged()),
            packet_list_, SLOT(columnsChanged()));
    connect(mainApp, SIGNAL(preferencesChanged()),
            packet_list_, SLOT(preferencesChanged()));
    connect(mainApp, SIGNAL(recentPreferencesRead()),
            this, SLOT(applyRecentPaneGeometry()));
    connect(mainApp, SIGNAL(recentPreferencesRead()),
            this, SLOT(updateRecentActions()));
    connect(mainApp, SIGNAL(packetDissectionChanged()),
            this, SLOT(redissectPackets()), Qt::QueuedConnection);

    connect(mainApp, SIGNAL(checkDisplayFilter()),
            this, SLOT(checkDisplayFilter()));
    connect(mainApp, SIGNAL(fieldsChanged()),
            this, SLOT(fieldsChanged()));
    connect(mainApp, SIGNAL(reloadLuaPlugins()),
            this, SLOT(reloadLuaPlugins()));

    connect(main_ui_->mainStack, SIGNAL(currentChanged(int)),
            this, SLOT(mainStackChanged(int)));

    connect(welcome_page_, SIGNAL(startCapture(QStringList)),
            this, SLOT(startCapture(QStringList)));
    connect(welcome_page_, SIGNAL(recentFileActivated(QString)),
            this, SLOT(openCaptureFile(QString)));

    connect(main_ui_->addressEditorFrame, &AddressEditorFrame::redissectPackets,
            this, &LograyMainWindow::redissectPackets);
    connect(main_ui_->addressEditorFrame, &AddressEditorFrame::showNameResolutionPreferences,
            this, &LograyMainWindow::showPreferencesDialog);
    connect(main_ui_->preferenceEditorFrame, &PreferenceEditorFrame::showProtocolPreferences,
            this, &LograyMainWindow::showPreferencesDialog);
    connect(main_ui_->filterExpressionFrame, &FilterExpressionFrame::showPreferencesDialog,
            this, &LograyMainWindow::showPreferencesDialog);
    connect(main_ui_->filterExpressionFrame, &FilterExpressionFrame::filterExpressionsChanged,
            filter_expression_toolbar_, &FilterExpressionToolBar::filterExpressionsChanged);

    /* Connect change of capture file */
    connect(this, &LograyMainWindow::setCaptureFile,
            main_ui_->searchFrame, &SearchFrame::setCaptureFile);
    connect(this, &LograyMainWindow::setCaptureFile,
            main_ui_->statusBar, &MainStatusBar::setCaptureFile);
    connect(this, &LograyMainWindow::setCaptureFile,
            packet_list_, &PacketList::setCaptureFile);
    connect(this, &LograyMainWindow::setCaptureFile,
            proto_tree_, &ProtoTree::setCaptureFile);

    connect(mainApp, SIGNAL(zoomMonospaceFont(QFont)),
            packet_list_, SLOT(setMonospaceFont(QFont)));
    connect(mainApp, SIGNAL(zoomMonospaceFont(QFont)),
            proto_tree_, SLOT(setMonospaceFont(QFont)));

    connect(main_ui_->actionGoNextPacket, SIGNAL(triggered()),
            packet_list_, SLOT(goNextPacket()));
    connect(main_ui_->actionGoPreviousPacket, SIGNAL(triggered()),
            packet_list_, SLOT(goPreviousPacket()));
    connect(main_ui_->actionGoFirstPacket, SIGNAL(triggered()),
            packet_list_, SLOT(goFirstPacket()));
    connect(main_ui_->actionGoLastPacket, SIGNAL(triggered()),
            packet_list_, SLOT(goLastPacket()));
    connect(main_ui_->actionGoNextHistoryPacket, SIGNAL(triggered()),
            packet_list_, SLOT(goNextHistoryPacket()));
    connect(main_ui_->actionGoPreviousHistoryPacket, SIGNAL(triggered()),
            packet_list_, SLOT(goPreviousHistoryPacket()));

    connect(main_ui_->actionViewExpandSubtrees, SIGNAL(triggered()),
            proto_tree_, SLOT(expandSubtrees()));
    connect(main_ui_->actionViewCollapseSubtrees, SIGNAL(triggered()),
            proto_tree_, SLOT(collapseSubtrees()));
    connect(main_ui_->actionViewExpandAll, SIGNAL(triggered()),
            proto_tree_, SLOT(expandAll()));
    connect(main_ui_->actionViewCollapseAll, SIGNAL(triggered()),
            proto_tree_, SLOT(collapseAll()));

    connect(packet_list_, SIGNAL(packetDissectionChanged()),
            this, SLOT(redissectPackets()));
    connect(packet_list_, SIGNAL(showColumnPreferences(QString)),
            this, SLOT(showPreferencesDialog(QString)));
    connect(packet_list_, SIGNAL(showProtocolPreferences(QString)),
            this, SLOT(showPreferencesDialog(QString)));
    connect(packet_list_, SIGNAL(editProtocolPreference(preference*, pref_module*)),
            main_ui_->preferenceEditorFrame, SLOT(editPreference(preference*, pref_module*)));
    connect(packet_list_, SIGNAL(editColumn(int)), this, SLOT(showColumnEditor(int)));
    connect(main_ui_->columnEditorFrame, SIGNAL(columnEdited()),
            packet_list_, SLOT(columnsChanged()));
    connect(packet_list_, SIGNAL(doubleClicked(QModelIndex)),
            this, SLOT(openPacketDialog()));
    connect(packet_list_, SIGNAL(packetListScrolled(bool)),
            main_ui_->actionGoAutoScroll, SLOT(setChecked(bool)));

    connect(proto_tree_, SIGNAL(openPacketInNewWindow(bool)),
            this, SLOT(openPacketDialog(bool)));
    connect(proto_tree_, SIGNAL(showProtocolPreferences(QString)),
            this, SLOT(showPreferencesDialog(QString)));
    connect(proto_tree_, SIGNAL(editProtocolPreference(preference*, pref_module*)),
            main_ui_->preferenceEditorFrame, SLOT(editPreference(preference*, pref_module*)));

    connect(main_ui_->statusBar, SIGNAL(showExpertInfo()),
            this, SLOT(on_actionAnalyzeExpertInfo_triggered()));

    connect(main_ui_->statusBar, SIGNAL(stopLoading()),
            &capture_file_, SLOT(stopLoading()));

    connect(main_ui_->statusBar, SIGNAL(editCaptureComment()),
            this, SLOT(on_actionStatisticsCaptureFileProperties_triggered()));

    connect(main_ui_->menuApplyAsFilter, &QMenu::aboutToShow,
            this, &LograyMainWindow::filterMenuAboutToShow);
    connect(main_ui_->menuPrepareAFilter, &QMenu::aboutToShow,
            this, &LograyMainWindow::filterMenuAboutToShow);

#ifdef HAVE_LIBPCAP
    QTreeWidget *iface_tree = findChild<QTreeWidget *>("interfaceTree");
    if (iface_tree) {
        connect(iface_tree, SIGNAL(itemSelectionChanged()),
                this, SLOT(interfaceSelectionChanged()));
    }
    connect(main_ui_->welcomePage, SIGNAL(captureFilterSyntaxChanged(bool)),
            this, SLOT(captureFilterSyntaxChanged(bool)));

    connect(this, SIGNAL(showExtcapOptions(QString&, bool)),
            this, SLOT(showExtcapOptionsDialog(QString&, bool)));
    connect(this->welcome_page_, SIGNAL(showExtcapOptions(QString&, bool)),
            this, SLOT(showExtcapOptionsDialog(QString&, bool)));

#endif // HAVE_LIBPCAP

    /* Create plugin_if hooks */
    plugin_if_register_gui_cb(PLUGIN_IF_FILTER_ACTION_APPLY, plugin_if_mainwindow_apply_filter);
    plugin_if_register_gui_cb(PLUGIN_IF_FILTER_ACTION_PREPARE, plugin_if_mainwindow_apply_filter);
    plugin_if_register_gui_cb(PLUGIN_IF_PREFERENCE_SAVE, plugin_if_mainwindow_preference);
    plugin_if_register_gui_cb(PLUGIN_IF_GOTO_FRAME, plugin_if_mainwindow_gotoframe);
#ifdef HAVE_LIBPCAP
    plugin_if_register_gui_cb(PLUGIN_IF_GET_WS_INFO, plugin_if_mainwindow_get_ws_info);
#endif
    plugin_if_register_gui_cb(PLUGIN_IF_GET_FRAME_DATA, plugin_if_mainwindow_get_frame_data);
    plugin_if_register_gui_cb(PLUGIN_IF_GET_CAPTURE_FILE, plugin_if_mainwindow_get_capture_file);
    plugin_if_register_gui_cb(PLUGIN_IF_REMOVE_TOOLBAR, plugin_if_mainwindow_update_toolbars);

    /* Register Interface Toolbar callbacks */
    iface_toolbar_register_cb(mainwindow_add_toolbar, mainwindow_remove_toolbar);

    /* Show tooltips on menu items that go to websites */
    main_ui_->actionHelpMPWireshark->setToolTip(gchar_free_to_qstring(topic_action_url(LOCALPAGE_MAN_WIRESHARK)));
    main_ui_->actionHelpMPWireshark_Filter->setToolTip(gchar_free_to_qstring(topic_action_url(LOCALPAGE_MAN_WIRESHARK_FILTER)));
    main_ui_->actionHelpMPCapinfos->setToolTip(gchar_free_to_qstring(topic_action_url(LOCALPAGE_MAN_CAPINFOS)));
    main_ui_->actionHelpMPDumpcap->setToolTip(gchar_free_to_qstring(topic_action_url(LOCALPAGE_MAN_DUMPCAP)));
    main_ui_->actionHelpMPEditcap->setToolTip(gchar_free_to_qstring(topic_action_url(LOCALPAGE_MAN_EDITCAP)));
    main_ui_->actionHelpMPMergecap->setToolTip(gchar_free_to_qstring(topic_action_url(LOCALPAGE_MAN_MERGECAP)));
    main_ui_->actionHelpMPRawshark->setToolTip(gchar_free_to_qstring(topic_action_url(LOCALPAGE_MAN_RAWSHARK)));
    main_ui_->actionHelpMPReordercap->setToolTip(gchar_free_to_qstring(topic_action_url(LOCALPAGE_MAN_REORDERCAP)));
    main_ui_->actionHelpMPText2pcap->setToolTip(gchar_free_to_qstring(topic_action_url(LOCALPAGE_MAN_TEXT2PCAP)));
    main_ui_->actionHelpMPTShark->setToolTip(gchar_free_to_qstring(topic_action_url(LOCALPAGE_MAN_TSHARK)));

    main_ui_->actionHelpContents->setToolTip(gchar_free_to_qstring(topic_action_url(ONLINEPAGE_USERGUIDE)));
    main_ui_->actionHelpWebsite->setToolTip(gchar_free_to_qstring(topic_action_url(ONLINEPAGE_HOME)));
    main_ui_->actionHelpFAQ->setToolTip(gchar_free_to_qstring(topic_action_url(ONLINEPAGE_FAQ)));
    main_ui_->actionHelpAsk->setToolTip(gchar_free_to_qstring(topic_action_url(ONLINEPAGE_ASK)));
    main_ui_->actionHelpDownloads->setToolTip(gchar_free_to_qstring(topic_action_url(ONLINEPAGE_DOWNLOAD)));
    main_ui_->actionHelpWiki->setToolTip(gchar_free_to_qstring(topic_action_url(ONLINEPAGE_WIKI)));
    main_ui_->actionHelpSampleCaptures->setToolTip(gchar_free_to_qstring(topic_action_url(ONLINEPAGE_SAMPLE_CAPTURES)));

    showWelcome();
}

LograyMainWindow::~LograyMainWindow()
{
    disconnect(main_ui_->mainStack, 0, 0, 0);

#ifndef Q_OS_MAC
    // Below dialogs inherit GeometryStateDialog
    // For reasons described in geometry_state_dialog.h no parent is set when
    // instantiating the dialogs and as a resul objects are not automatically
    // freed by its parent. Free then here explicitly to avoid leak and numerous
    // Valgrind complaints.
    delete file_set_dialog_;
    delete capture_filter_dlg_;
    delete display_filter_dlg_;
#ifdef HAVE_LIBPCAP
    delete capture_options_dialog_;
#endif

#endif
    delete main_ui_;
}

QMenu *LograyMainWindow::createPopupMenu()
{
    QMenu *menu = new QMenu();
    menu->addAction(main_ui_->actionViewMainToolbar);
    menu->addAction(main_ui_->actionViewFilterToolbar);

    if (!main_ui_->menuInterfaceToolbars->actions().isEmpty()) {
        QMenu *submenu = menu->addMenu(main_ui_->menuInterfaceToolbars->title());
        foreach(QAction *action, main_ui_->menuInterfaceToolbars->actions()) {
            submenu->addAction(action);
        }
    }

    if (!main_ui_->menuAdditionalToolbars->actions().isEmpty()) {
        QMenu *subMenu = menu->addMenu(main_ui_->menuAdditionalToolbars->title());
        foreach(QAction *action, main_ui_->menuAdditionalToolbars->actions()) {
            subMenu->addAction(action);
        }
    }

    menu->addAction(main_ui_->actionViewStatusBar);

    menu->addSeparator();
    menu->addAction(main_ui_->actionViewPacketList);
    menu->addAction(main_ui_->actionViewPacketDetails);
    menu->addAction(main_ui_->actionViewPacketBytes);
    menu->addAction(main_ui_->actionViewPacketDiagram);
    return menu;
}

void LograyMainWindow::addInterfaceToolbar(const iface_toolbar *toolbar_entry)
{
    QMenu *menu = main_ui_->menuInterfaceToolbars;
    bool visible = g_list_find_custom(recent.interface_toolbars, toolbar_entry->menu_title, (GCompareFunc)strcmp) ? true : false;

    QString title = QString().fromUtf8(toolbar_entry->menu_title);
    QAction *action = new QAction(title, menu);
    action->setEnabled(true);
    action->setCheckable(true);
    action->setChecked(visible);
    action->setToolTip(tr("Show or hide the toolbar"));

    QAction *before = NULL;
    foreach(QAction *action, menu->actions()) {
        // Ensure we add the menu entries in sorted order
        if (action->text().compare(title, Qt::CaseInsensitive) > 0) {
            before = action;
            break;
        }
    }
    menu->insertAction(before, action);

    InterfaceToolbar *interface_toolbar = new InterfaceToolbar(this, toolbar_entry);
    connect(mainApp, SIGNAL(appInitialized()), interface_toolbar, SLOT(interfaceListChanged()));
    connect(mainApp, SIGNAL(localInterfaceListChanged()), interface_toolbar, SLOT(interfaceListChanged()));

    QToolBar *toolbar = new QToolBar(this);
    toolbar->addWidget(interface_toolbar);
    toolbar->setMovable(false);
    toolbar->setVisible(visible);

    action->setData(QVariant::fromValue(toolbar));

    addToolBar(Qt::TopToolBarArea, toolbar);
    insertToolBarBreak(toolbar);

    if (show_hide_actions_) {
        show_hide_actions_->addAction(action);
    }

    menu->menuAction()->setVisible(true);
}

void LograyMainWindow::removeInterfaceToolbar(const gchar *menu_title)
{
    QMenu *menu = main_ui_->menuInterfaceToolbars;
    QAction *action = NULL;
    QMap<QAction *, QWidget *>::iterator i;

    QString title = QString().fromUtf8(menu_title);
    foreach(action, menu->actions()) {
        if (title.compare(action->text()) == 0) {
            break;
        }
    }

    if (action) {
        if (show_hide_actions_) {
            show_hide_actions_->removeAction(action);
        }
        menu->removeAction(action);

        QToolBar *toolbar = action->data().value<QToolBar *>();
        removeToolBar(toolbar);

        delete action;
        delete toolbar;
    }

    menu->menuAction()->setVisible(!menu->actions().isEmpty());
}

void LograyMainWindow::setPipeInputHandler(gint source, gpointer user_data, ws_process_id *child_process, pipe_input_cb_t input_cb)
{
    pipe_source_        = source;
    pipe_child_process_ = child_process;
    pipe_user_data_     = user_data;
    pipe_input_cb_      = input_cb;

#ifdef _WIN32
    /* Tricky to use pipes in win9x, as no concept of wait.  NT can
       do this but that doesn't cover all win32 platforms.  GTK can do
       this but doesn't seem to work over processes.  Attempt to do
       something similar here, start a timer and check for data on every
       timeout. */
       /*ws_log(NULL, LOG_LEVEL_DEBUG, "pipe_input_set_handler: new");*/

    if (pipe_timer_) {
        disconnect(pipe_timer_, SIGNAL(timeout()), this, SLOT(pipeTimeout()));
        delete pipe_timer_;
    }

    pipe_timer_ = new QTimer(this);
    connect(pipe_timer_, SIGNAL(timeout()), this, SLOT(pipeTimeout()));
    connect(pipe_timer_, SIGNAL(destroyed()), this, SLOT(pipeNotifierDestroyed()));
    pipe_timer_->start(200);
#else
    if (pipe_notifier_) {
        disconnect(pipe_notifier_, SIGNAL(activated(int)), this, SLOT(pipeActivated(int)));
        delete pipe_notifier_;
    }

    pipe_notifier_ = new QSocketNotifier(pipe_source_, QSocketNotifier::Read);
    // XXX ui/gtk/gui_utils.c sets the encoding. Do we need to do the same?
    connect(pipe_notifier_, SIGNAL(activated(int)), this, SLOT(pipeActivated(int)));
    connect(pipe_notifier_, SIGNAL(destroyed()), this, SLOT(pipeNotifierDestroyed()));
#endif
}

bool LograyMainWindow::eventFilter(QObject *obj, QEvent *event) {

    // The user typed some text. Start filling in a filter.
    // We may need to be more choosy here. We just need to catch events for the packet list,
    // proto tree, and main welcome widgets.
    if (event->type() == QEvent::KeyPress) {
        QKeyEvent *kevt = static_cast<QKeyEvent *>(event);
        if (kevt->text().length() > 0 && kevt->text()[0].isPrint() &&
            !(kevt->modifiers() & Qt::ControlModifier)) {
            df_combo_box_->lineEdit()->insert(kevt->text());
            df_combo_box_->lineEdit()->setFocus();
            return true;
        }
    }

    return QMainWindow::eventFilter(obj, event);
}

bool LograyMainWindow::event(QEvent *event)
{
    switch (event->type()) {
    case QEvent::ApplicationPaletteChange:
        initMainToolbarIcons();
        break;
    default:
        break;

    }
    return QMainWindow::event(event);
}

void LograyMainWindow::keyPressEvent(QKeyEvent *event) {

    // Explicitly focus on the display filter combo.
    if (event->modifiers() & Qt::ControlModifier && event->key() == Qt::Key_Slash) {
        df_combo_box_->setFocus(Qt::ShortcutFocusReason);
        return;
    }

    if (mainApp->focusWidget() == main_ui_->goToLineEdit) {
        if (event->modifiers() == Qt::NoModifier) {
            if (event->key() == Qt::Key_Escape) {
                on_goToCancel_clicked();
            } else if (event->key() == Qt::Key_Enter || event->key() == Qt::Key_Return) {
                on_goToGo_clicked();
            }
        }
        return; // goToLineEdit didn't want it and we don't either.
    }

    // Move up & down the packet list.
    if (event->key() == Qt::Key_F7) {
        packet_list_->goPreviousPacket();
    } else if (event->key() == Qt::Key_F8) {
        packet_list_->goNextPacket();
    }

    // Move along, citizen.
    QMainWindow::keyPressEvent(event);
}

void LograyMainWindow::closeEvent(QCloseEvent *event) {
    saveWindowGeometry();

    /* If we're in the middle of stopping a capture, don't do anything;
       the user can try deleting the window after the capture stops. */
    if (capture_stopping_) {
        event->ignore();
        return;
    }

    QString before_what(tr(" before quitting"));
    if (!testCaptureFileClose(before_what, Quit)) {
        event->ignore();
        return;
    }

#ifdef HAVE_LIBPCAP
    if (capture_options_dialog_) capture_options_dialog_->close();
#endif
    // Make sure we kill any open dumpcap processes.
    delete welcome_page_;

    // One of the many places we assume one main window.
    if (!mainApp->isInitialized()) {
        // If we're still initializing, QCoreApplication::quit() won't
        // exit properly because we are not in the event loop. This
        // means that the application won't clean up after itself. We
        // might want to call mainApp->processEvents() during startup
        // instead so that we can do a normal exit here.
        exit(0);
    }
    mainApp->quit();
    // When the main loop is not yet running (i.e. when openCaptureFile is
    // executing in main.cpp), the above quit action has no effect.
    // Schedule a quit action for the next execution of the main loop.
    QMetaObject::invokeMethod(mainApp, "quit", Qt::QueuedConnection);
}

// XXX On windows the drag description is "Copy". It should be "Open" or
// "Merge" as appropriate. It looks like we need access to IDataObject in
// order to set DROPDESCRIPTION.
void LograyMainWindow::dragEnterEvent(QDragEnterEvent *event)
{
    if (!event->mimeData()->hasUrls())
    {
        event->ignore();
        return;
    }

    if (!main_ui_->actionFileOpen->isEnabled()) {
        // We could alternatively call setAcceptDrops(!capture_in_progress)
        // in setMenusForCaptureInProgress but that wouldn't provide feedback.

        mainApp->pushStatus(WiresharkApplication::TemporaryStatus, tr("Unable to drop files during capture."));
        event->setDropAction(Qt::IgnoreAction);
        event->ignore();
        return;
    }

    bool have_files = false;
    foreach(QUrl drag_url, event->mimeData()->urls()) {
        if (!drag_url.toLocalFile().isEmpty()) {
            have_files = true;
            break;
        }
    }

    if (have_files) {
        event->acceptProposedAction();
    }
}

void LograyMainWindow::dropEvent(QDropEvent *event)
{
    if (!event->mimeData()->hasUrls())
    {
        event->ignore();
        return;
    }

    QList<QByteArray> local_files;
    int max_dropped_files = 100; // Arbitrary

    foreach(QUrl drop_url, event->mimeData()->urls()) {
        QString drop_file = drop_url.toLocalFile();
        if (!drop_file.isEmpty()) {
            local_files << drop_file.toUtf8();
            if (local_files.size() >= max_dropped_files) {
                break;
            }
        }
    }

    event->acceptProposedAction();

    if (local_files.size() < 1) {
        event->ignore();
        return;
    }

    event->accept();

    if (local_files.size() == 1) {
        openCaptureFile(local_files.at(0));
        return;
    }

    const char **in_filenames = g_new(const char *, local_files.size());
    char *tmpname = NULL;

    for (int i = 0; i < local_files.size(); i++) {
        in_filenames[i] = local_files.at(i).constData();
    }

    /* merge the files in chronological order */
    if (cf_merge_files_to_tempfile(this, global_capture_opts.temp_dir, &tmpname, static_cast<int>(local_files.size()),
                                   in_filenames,
                                   wtap_pcapng_file_type_subtype(),
                                   FALSE) == CF_OK) {
        /* Merge succeeded; close the currently-open file and try
           to open the merged capture file. */
        openCaptureFile(tmpname, QString(), WTAP_TYPE_AUTO, TRUE);
    }

    g_free(tmpname);
    g_free(in_filenames);
}

// Apply recent settings to the main window geometry.
// We haven't loaded the preferences at this point so we assume that the
// position and size preference are enabled.
// Note we might end up with unexpected screen geometries if the user
// unplugs or plugs in a monitor:
// https://bugreports.qt.io/browse/QTBUG-44213
void LograyMainWindow::loadWindowGeometry()
{
    int min_sensible_dimension = 200;

#ifndef Q_OS_MAC
    if (recent.gui_geometry_main_maximized) {
        setWindowState(Qt::WindowMaximized);
    } else
#endif
    {
        QRect recent_geom(recent.gui_geometry_main_x, recent.gui_geometry_main_y,
                          recent.gui_geometry_main_width, recent.gui_geometry_main_height);
        if (!rect_on_screen(recent_geom)) {
            // We're not visible on any screens. See if we can move onscreen
            // without resizing.
            recent_geom.moveTo(50, 50); // recent.c defaults to 20.
        }

        if (!rect_on_screen(recent_geom)) {
            // Give up and use the default geometry.
            return;
        }

//        if (prefs.gui_geometry_save_position) {
        move(recent_geom.topLeft());
//        }

        if (// prefs.gui_geometry_save_size &&
                recent_geom.width() > min_sensible_dimension &&
                recent_geom.height() > min_sensible_dimension) {
            resize(recent_geom.size());
        }
    }
}

void LograyMainWindow::saveWindowGeometry()
{
    if (prefs.gui_geometry_save_position) {
        recent.gui_geometry_main_x = pos().x();
        recent.gui_geometry_main_y = pos().y();
    }

    if (prefs.gui_geometry_save_size) {
        recent.gui_geometry_main_width = size().width();
        recent.gui_geometry_main_height = size().height();
    }

    if (prefs.gui_geometry_save_maximized) {
        // On macOS this is false when it shouldn't be
        recent.gui_geometry_main_maximized = isMaximized();
    }

    if (master_split_.sizes().length() > 0) {
        recent.gui_geometry_main_upper_pane = master_split_.sizes()[0];
    }

    if (master_split_.sizes().length() > 2) {
        recent.gui_geometry_main_lower_pane = master_split_.sizes()[1];
    } else if (extra_split_.sizes().length() > 0) {
        recent.gui_geometry_main_lower_pane = extra_split_.sizes()[0];
    }
}

// Our event loop becomes nested whenever we call update_progress_dlg, which
// includes several places in file.c. The GTK+ UI stays out of trouble by
// showing a modal progress dialog. We attempt to do the equivalent below by
// disabling parts of the main window. At a minumum the ProgressFrame in the
// main status bar must remain accessible.
//
// We might want to do this any time the main status bar progress frame is
// shown and hidden.
void LograyMainWindow::freeze()
{
    freeze_focus_ = mainApp->focusWidget();

    // XXX Alternatively we could just disable and enable the main menu.
    for (int i = 0; i < freeze_actions_.size(); i++) {
        QAction *action = freeze_actions_[i].first;
        freeze_actions_[i].second = action->isEnabled();
        action->setEnabled(false);
    }
    main_ui_->centralWidget->setEnabled(false);
}

void LograyMainWindow::thaw()
{
    main_ui_->centralWidget->setEnabled(true);
    for (int i = 0; i < freeze_actions_.size(); i++) {
        freeze_actions_[i].first->setEnabled(freeze_actions_[i].second);
    }

    if (freeze_focus_) freeze_focus_->setFocus();
    freeze_focus_ = NULL;
}

void LograyMainWindow::mergeCaptureFile()
{
    QString file_name = "";
    QString read_filter = "";
    dfilter_t *rfcode = NULL;
    int err;

    if (!capture_file_.capFile())
        return;

    if (prefs.gui_ask_unsaved) {
        if (cf_has_unsaved_data(capture_file_.capFile())) {
            QMessageBox msg_dialog;
            gchar *display_basename;
            int response;

            msg_dialog.setIcon(QMessageBox::Question);
            /* This file has unsaved data; ask the user whether to save
               the capture. */
            if (capture_file_.capFile()->is_tempfile) {
                msg_dialog.setText(tr("Save packets before merging?"));
                msg_dialog.setInformativeText(tr("A temporary capture file can't be merged."));
            } else {
                /*
                 * Format the message.
                 */
                display_basename = g_filename_display_basename(capture_file_.capFile()->filename);
                msg_dialog.setText(QString(tr("Save changes in \"%1\" before merging?")).arg(display_basename));
                g_free(display_basename);
                msg_dialog.setInformativeText(tr("Changes must be saved before the files can be merged."));
            }

            msg_dialog.setStandardButtons(QMessageBox::Save | QMessageBox::Cancel);
            msg_dialog.setDefaultButton(QMessageBox::Save);

            response = msg_dialog.exec();

            switch (response) {

            case QMessageBox::Save:
                /* Save the file but don't close it */
                saveCaptureFile(capture_file_.capFile(), false);
                break;

            case QMessageBox::Cancel:
            default:
                /* Don't do the merge. */
                return;
            }
        }
    }

    for (;;) {
        CaptureFileDialog merge_dlg(this, capture_file_.capFile());
        int file_type;
        cf_status_t  merge_status;
        char        *in_filenames[2];
        char        *tmpname;

        if (merge_dlg.merge(file_name, read_filter)) {
            gchar *err_msg;

            if (!dfilter_compile(qUtf8Printable(read_filter), &rfcode, &err_msg)) {
                /* Not valid. Tell the user, and go back and run the file
                   selection box again once they dismiss the alert. */
                // Similar to commandline_info.jfilter section in main().
                QMessageBox::warning(this, tr("Invalid Read Filter"),
                                     QString(tr("The filter expression %1 isn't a valid read filter. (%2).").arg(read_filter, err_msg)),
                                     QMessageBox::Ok);
                g_free(err_msg);
                continue;
            }
        } else {
            return;
        }

        file_type = capture_file_.capFile()->cd_t;

        /* Try to merge or append the two files */
        if (merge_dlg.mergeType() == 0) {
            /* chronological order */
            in_filenames[0] = g_strdup(capture_file_.capFile()->filename);
            in_filenames[1] = qstring_strdup(file_name);
            merge_status = cf_merge_files_to_tempfile(this, global_capture_opts.temp_dir, &tmpname, 2, in_filenames, file_type, FALSE);
        } else if (merge_dlg.mergeType() <= 0) {
            /* prepend file */
            in_filenames[0] = qstring_strdup(file_name);
            in_filenames[1] = g_strdup(capture_file_.capFile()->filename);
            merge_status = cf_merge_files_to_tempfile(this, global_capture_opts.temp_dir, &tmpname, 2, in_filenames, file_type, TRUE);
        } else {
            /* append file */
            in_filenames[0] = g_strdup(capture_file_.capFile()->filename);
            in_filenames[1] = qstring_strdup(file_name);
            merge_status = cf_merge_files_to_tempfile(this, global_capture_opts.temp_dir, &tmpname, 2, in_filenames, file_type, TRUE);
        }

        g_free(in_filenames[0]);
        g_free(in_filenames[1]);

        if (merge_status != CF_OK) {
            dfilter_free(rfcode);
            g_free(tmpname);
            continue;
        }

        cf_close(capture_file_.capFile());

        /* Try to open the merged capture file. */
        CaptureFile::globalCapFile()->window = this;
        if (cf_open(CaptureFile::globalCapFile(), tmpname, WTAP_TYPE_AUTO, TRUE /* temporary file */, &err) != CF_OK) {
            /* We couldn't open it; fail. */
            CaptureFile::globalCapFile()->window = NULL;
            dfilter_free(rfcode);
            g_free(tmpname);
            return;
        }

        /* Attach the new read filter to "cf" ("cf_open()" succeeded, so
           it closed the previous capture file, and thus destroyed any
           previous read filter attached to "cf"). */
        cf_set_rfcode(CaptureFile::globalCapFile(), rfcode);

        switch (cf_read(CaptureFile::globalCapFile(), FALSE)) {

        case CF_READ_OK:
        case CF_READ_ERROR:
            /* Just because we got an error, that doesn't mean we were unable
             to read any of the file; we handle what we could get from the
             file. */
            break;

        case CF_READ_ABORTED:
            /* The user bailed out of re-reading the capture file; the
             capture file has been closed - just free the capture file name
             string and return (without changing the last containing
             directory). */
            g_free(tmpname);
            return;
        }

        /* Save the name of the containing directory specified in the path name. */
        mainApp->setLastOpenDirFromFilename(tmpname);
        g_free(tmpname);
        main_ui_->statusBar->showExpert();
        return;
    }

}

void LograyMainWindow::importCaptureFile() {
    ImportTextDialog import_dlg;

    QString before_what(tr(" before importing a capture"));
    if (!testCaptureFileClose(before_what))
        return;

    import_dlg.exec();

    if (import_dlg.result() != QDialog::Accepted) {
        showWelcome();
        return;
    }

    openCaptureFile(import_dlg.capfileName());
}

bool LograyMainWindow::saveCaptureFile(capture_file *cf, bool dont_reopen) {
    QString file_name;
    gboolean discard_comments;

    if (cf->is_tempfile) {
        /* This is a temporary capture file, so saving it means saving
           it to a permanent file.  Prompt the user for a location
           to which to save it.  Don't require that the file format
           support comments - if it's a temporary capture file, it's
           probably pcapng, which supports comments and, if it's
           not pcapng, let the user decide what they want to do
           if they've added comments. */
        return saveAsCaptureFile(cf, FALSE, dont_reopen);
    } else {
        if (cf->unsaved_changes) {
            cf_write_status_t status;

            /* This is not a temporary capture file, but it has unsaved
               changes, so saving it means doing a "safe save" on top
               of the existing file, in the same format - no UI needed
               unless the file has comments and the file's format doesn't
               support them.

               If the file has comments, does the file's format support them?
               If not, ask the user whether they want to discard the comments
               or choose a different format. */
            switch (CaptureFileDialog::checkSaveAsWithComments(this, cf, cf->cd_t)) {

            case SAVE:
                /* The file can be saved in the specified format as is;
                   just drive on and save in the format they selected. */
                discard_comments = FALSE;
                break;

            case SAVE_WITHOUT_COMMENTS:
                /* The file can't be saved in the specified format as is,
                   but it can be saved without the comments, and the user
                   said "OK, discard the comments", so save it in the
                   format they specified without the comments. */
                discard_comments = TRUE;
                break;

            case SAVE_IN_ANOTHER_FORMAT:
                /* There are file formats in which we can save this that
                   support comments, and the user said not to delete the
                   comments.  Do a "Save As" so the user can select
                   one of those formats and choose a file name. */
                return saveAsCaptureFile(cf, TRUE, dont_reopen);

            case CANCELLED:
                /* The user said "forget it".  Just return. */
                return false;

            default:
                /* Squelch warnings that discard_comments is being used
                   uninitialized. */
                ws_assert_not_reached();
                return false;
            }

            /* XXX - cf->filename might get freed out from under us, because
               the code path through which cf_save_records() goes currently
               closes the current file and then opens and reloads the saved file,
               so make a copy and free it later. */
            file_name = cf->filename;
            status = cf_save_records(cf, qUtf8Printable(file_name), cf->cd_t, cf->compression_type,
                                     discard_comments, dont_reopen);
            switch (status) {

            case CF_WRITE_OK:
                /* The save succeeded; we're done.
                   If we discarded comments, redraw the packet list to reflect
                   any packets that no longer have comments. */
                if (discard_comments)
                    packet_list_->redrawVisiblePackets();

                cf->unsaved_changes = false; //we just saved so we signal that we have no unsaved changes
                updateForUnsavedChanges(); // we update the title bar to remove the *
                break;

            case CF_WRITE_ERROR:
                /* The write failed.
                   XXX - OK, what do we do now?  Let them try a
                   "Save As", in case they want to try to save to a
                   different directory or file system? */
                break;

            case CF_WRITE_ABORTED:
                /* The write was aborted; just drive on. */
                return false;
            }
        }
        /* Otherwise just do nothing. */
    }

    return true;
}

bool LograyMainWindow::saveAsCaptureFile(capture_file *cf, bool must_support_comments, bool dont_reopen) {
    QString file_name = "";
    int file_type;
    wtap_compression_type compression_type;
    cf_write_status_t status;
    gchar   *dirname;
    gboolean discard_comments = FALSE;

    if (!cf) {
        return false;
    }

    for (;;) {
        CaptureFileDialog save_as_dlg(this, cf);

        /* If the file has comments, does the format the user selected
           support them?  If not, ask the user whether they want to
           discard the comments or choose a different format. */
        switch (save_as_dlg.saveAs(file_name, must_support_comments)) {

        case SAVE:
            /* The file can be saved in the specified format as is;
               just drive on and save in the format they selected. */
            discard_comments = FALSE;
            break;

        case SAVE_WITHOUT_COMMENTS:
            /* The file can't be saved in the specified format as is,
               but it can be saved without the comments, and the user
               said "OK, discard the comments", so save it in the
               format they specified without the comments. */
            discard_comments = TRUE;
            break;

        case SAVE_IN_ANOTHER_FORMAT:
            /* There are file formats in which we can save this that
               support comments, and the user said not to delete the
               comments.  The combo box of file formats has had the
               formats that don't support comments trimmed from it,
               so run the dialog again, to let the user decide
               whether to save in one of those formats or give up. */
            must_support_comments = TRUE;
            continue;

        case CANCELLED:
            /* The user said "forget it".  Just get rid of the dialog box
               and return. */
            return false;
        }
        file_type = save_as_dlg.selectedFileType();
        if (file_type == WTAP_FILE_TYPE_SUBTYPE_UNKNOWN) {
            /* This "should not happen". */
            QMessageBox msg_dialog;

            msg_dialog.setIcon(QMessageBox::Critical);
            msg_dialog.setText(tr("Unknown file type returned by merge dialog."));
            msg_dialog.setInformativeText(tr("Please report this as a Wireshark issue at https://gitlab.com/wireshark/wireshark/-/issues."));
            msg_dialog.exec();
            return false;
	}
        compression_type = save_as_dlg.compressionType();

#ifdef Q_OS_WIN
        // the Windows dialog does not fixup extensions, do it manually here.
        fileAddExtension(file_name, file_type, compression_type);
#endif // Q_OS_WIN

//#ifndef _WIN32
//        /* If the file exists and it's user-immutable or not writable,
//                       ask the user whether they want to override that. */
//        if (!file_target_unwritable_ui(top_level, qUtf8Printable(file_name))) {
//            /* They don't.  Let them try another file name or cancel. */
//            continue;
//        }
//#endif

        /* Attempt to save the file */
        status = cf_save_records(cf, qUtf8Printable(file_name), file_type, compression_type,
                                 discard_comments, dont_reopen);
        switch (status) {

        case CF_WRITE_OK:
            /* The save succeeded; we're done. */
            /* Save the directory name for future file dialogs. */
            dirname = qstring_strdup(file_name);  /* Overwrites cf_name */
            set_last_open_dir(get_dirname(dirname));
            g_free(dirname);
            /* If we discarded comments, redraw the packet list to reflect
               any packets that no longer have comments. */
            if (discard_comments)
                packet_list_->redrawVisiblePackets();

            cf->unsaved_changes = false; //we just saved so we signal that we have no unsaved changes
            updateForUnsavedChanges(); // we update the title bar to remove the *
            /* Add this filename to the list of recent files in the "Recent Files" submenu */
            add_menu_recent_capture_file(qUtf8Printable(file_name));
            return true;

        case CF_WRITE_ERROR:
            /* The save failed; let the user try again. */
            continue;

        case CF_WRITE_ABORTED:
            /* The user aborted the save; just return. */
            return false;
        }
    }
    return true;
}

void LograyMainWindow::exportSelectedPackets() {
    QString file_name = "";
    int file_type;
    wtap_compression_type compression_type;
    packet_range_t range;
    cf_write_status_t status;
    gchar   *dirname;
    bool discard_comments = false;

    if (!capture_file_.capFile())
        return;

    /* Init the packet range */
    packet_range_init(&range, capture_file_.capFile());
    range.process_filtered = TRUE;
    range.include_dependents = TRUE;

    QList<int> rows = packet_list_->selectedRows(true);

    QStringList entries;
    foreach (int row, rows)
        entries << QString::number(row);
    QString selRange = entries.join(",");

    for (;;) {
        CaptureFileDialog esp_dlg(this, capture_file_.capFile());

        /* If the file has comments, does the format the user selected
           support them?  If not, ask the user whether they want to
           discard the comments or choose a different format. */
        switch (esp_dlg.exportSelectedPackets(file_name, &range, selRange)) {

        case SAVE:
            /* The file can be saved in the specified format as is;
               just drive on and save in the format they selected. */
            discard_comments = FALSE;
            break;

        case SAVE_WITHOUT_COMMENTS:
            /* The file can't be saved in the specified format as is,
               but it can be saved without the comments, and the user
               said "OK, discard the comments", so save it in the
               format they specified without the comments. */
            discard_comments = TRUE;
            break;

        case SAVE_IN_ANOTHER_FORMAT:
            /* There are file formats in which we can save this that
               support comments, and the user said not to delete the
               comments.  The combo box of file formats has had the
               formats that don't support comments trimmed from it,
               so run the dialog again, to let the user decide
               whether to save in one of those formats or give up. */
            continue;

        case CANCELLED:
            /* The user said "forget it".  Just get rid of the dialog box
               and return. */
            goto cleanup;
        }

        /*
         * Check that we're not going to save on top of the current
         * capture file.
         * We do it here so we catch all cases ...
         * Unfortunately, the file requester gives us an absolute file
         * name and the read file name may be relative (if supplied on
         * the command line). From Joerg Mayer.
         */
        if (files_identical(capture_file_.capFile()->filename, qUtf8Printable(file_name))) {
            QMessageBox msg_box;
            gchar *display_basename = g_filename_display_basename(qUtf8Printable(file_name));

            msg_box.setIcon(QMessageBox::Critical);
            msg_box.setText(QString(tr("Unable to export to \"%1\".").arg(display_basename)));
            msg_box.setInformativeText(tr("You cannot export packets to the current capture file."));
            msg_box.setStandardButtons(QMessageBox::Ok);
            msg_box.setDefaultButton(QMessageBox::Ok);
            msg_box.exec();
            g_free(display_basename);
            continue;
        }

        file_type = esp_dlg.selectedFileType();
        if (file_type == WTAP_FILE_TYPE_SUBTYPE_UNKNOWN) {
            /* This "should not happen". */
            QMessageBox msg_box;

            msg_box.setIcon(QMessageBox::Critical);
            msg_box.setText(tr("Unknown file type returned by export dialog."));
            msg_box.setInformativeText(tr("Please report this as a Wireshark issue at https://gitlab.com/wireshark/wireshark/-/issues."));
            msg_box.exec();
            goto cleanup;
	}
        compression_type = esp_dlg.compressionType();
#ifdef Q_OS_WIN
        // the Windows dialog does not fixup extensions, do it manually here.
        fileAddExtension(file_name, file_type, compression_type);
#endif // Q_OS_WIN

//#ifndef _WIN32
//        /* If the file exists and it's user-immutable or not writable,
//                       ask the user whether they want to override that. */
//        if (!file_target_unwritable_ui(top_level, qUtf8Printable(file_name))) {
//            /* They don't.  Let them try another file name or cancel. */
//            continue;
//        }
//#endif

        /* Attempt to save the file */
        status = cf_export_specified_packets(capture_file_.capFile(), qUtf8Printable(file_name), &range, file_type, compression_type);
        switch (status) {

        case CF_WRITE_OK:
            /* The save succeeded; we're done. */
            /* Save the directory name for future file dialogs. */
            dirname = qstring_strdup(file_name);  /* Overwrites cf_name */
            set_last_open_dir(get_dirname(dirname));
            g_free(dirname);
            /* If we discarded comments, redraw the packet list to reflect
               any packets that no longer have comments. */
            if (discard_comments)
                packet_list_->redrawVisiblePackets();
            /* Add this filename to the list of recent files in the "Recent Files" submenu */
            add_menu_recent_capture_file(qUtf8Printable(file_name));
            goto cleanup;

        case CF_WRITE_ERROR:
            /* The save failed; let the user try again. */
            continue;

        case CF_WRITE_ABORTED:
            /* The user aborted the save; just return. */
            goto cleanup;
        }
    }

cleanup:
    packet_range_cleanup(&range);
}

void LograyMainWindow::exportDissections(export_type_e export_type) {
    capture_file *cf = capture_file_.capFile();
    g_return_if_fail(cf);

    QList<int> rows = packet_list_->selectedRows(true);

    QStringList entries;
    foreach (int row, rows)
        entries << QString::number(row);
    QString selRange = entries.join(",");

    ExportDissectionDialog *ed_dlg = new ExportDissectionDialog(this, cf, export_type, selRange);
    ed_dlg->setWindowModality(Qt::ApplicationModal);
    ed_dlg->setAttribute(Qt::WA_DeleteOnClose);
    ed_dlg->show();
}

#ifdef Q_OS_WIN
/*
 * Ensure that:
 *
 * If the file is to be compressed:
 *
 *    if there is a set of extensions used by the file type to be used,
 *    the file name has one of those extensions followed by the extension
 *    for the compression type to be used;
 *
 *    otherwise, the file name has the extension for the compression type
 *    to be used;
 *
 * otherwise:
 *
 *    if there is a set of extensions used by the file type to be used,
 *    the file name has one of those extensions.
 */
void LograyMainWindow::fileAddExtension(QString &file_name, int file_type, wtap_compression_type compression_type) {
    QString file_name_lower;
    GSList  *extensions_list;
    const char *compressed_file_extension;
    gboolean add_extension_for_file_type;

    /* Lower-case the file name, so the extension matching is case-insensitive. */
    file_name_lower = file_name.toLower();

    /* Get a list of all extensions used for this file type; don't
       include the ones with compression type extensions, as we
       only want to check for the extension for the compression
       type we'll be using. */
    extensions_list = wtap_get_file_extensions_list(file_type, FALSE);

    /* Get the extension for the compression type we'll be using;
       NULL is returned if the type isn't supported or compression
       is not being done. */
    compressed_file_extension = wtap_compression_type_extension(compression_type);

    if (extensions_list != NULL) {
        GSList *extension;

        /* This file type has one or more extensions.
           Start out assuming we need to add the default one. */
        add_extension_for_file_type = TRUE;

        /* OK, see if the file has one of those extensions, followed
           by the appropriate compression type extension if it's to be
           compressed. */
        for (extension = extensions_list; extension != NULL;
             extension = g_slist_next(extension)) {
            QString file_suffix = QString(".") + (char *)extension->data;
            if (compressed_file_extension != NULL)
                file_suffix += QString(".") + compressed_file_extension;
            if (file_name_lower.endsWith(file_suffix)) {
                /*
                 * The file name has one of the extensions for this file
                 * type, followed by a compression type extension if
                 * appropriate, so we don't need to add an extension for
                 * the file type or the compression type.
                 */
                add_extension_for_file_type = FALSE;
                break;
            }
        }
    } else {
        /* We have no extensions for this file type.  Just check
           to see if we need to add an extension for the compressed
           file type.

           Start out assuming we do. */
        add_extension_for_file_type = TRUE;
        if (compressed_file_extension != NULL) {
            QString file_suffix = QString(".") + compressed_file_extension;
            if (file_name_lower.endsWith(file_suffix)) {
                /*
                 * The file name has the appropriate compressed file extension,
                 * so we don't need to add an extension for the compression
                 * type.
                 */
                add_extension_for_file_type = FALSE;
            }
        }
    }

    /*
     * If we need to add an extension for the file type or compressed
     * file type, do so.
     */
    if (add_extension_for_file_type) {
        if (wtap_default_file_extension(file_type) != NULL) {
            /* This file type has a default extension; append it. */
            file_name += QString(".") + wtap_default_file_extension(file_type);
        }
        if (compression_type != WTAP_UNCOMPRESSED) {
            /*
             * The file is to be compressed, so append the extension for
             * its compression type.
             */
            file_name += QString(".") + compressed_file_extension;
        }
    }
}
#endif // Q_OS_WIN

bool LograyMainWindow::testCaptureFileClose(QString before_what, FileCloseContext context) {
    bool capture_in_progress = false;
    bool do_close_file = false;

    if (!capture_file_.capFile() || capture_file_.capFile()->state == FILE_CLOSED)
        return true; /* Already closed, nothing to do */

    if (capture_file_.capFile()->read_lock) {
        /*
         * If the file is being redissected, we cannot stop the capture since
         * that would crash and burn "cf_read", so stop early. Ideally all
         * callers should be modified to check this condition and act
         * accordingly (ignore action or queue it up), so print a warning.
         */
        ws_warning("Refusing to close \"%s\" which is being read.", capture_file_.capFile()->filename);
        return false;
    }

#ifdef HAVE_LIBPCAP
    if (capture_file_.capFile()->state == FILE_READ_IN_PROGRESS) {
        /*
         * This (FILE_READ_IN_PROGRESS) is true if we're reading a capture file
         * *or* if we're doing a live capture. From the capture file itself we
         * cannot differentiate the cases, so check the current capture session.
         */
        capture_in_progress = captureSession()->state != CAPTURE_STOPPED;
    }
#endif

    if (prefs.gui_ask_unsaved) {
        if (cf_has_unsaved_data(capture_file_.capFile())) {
            QMessageBox msg_dialog;
            QString question;
            QString infotext;
            QPushButton *save_button;
            QPushButton *discard_button;

            msg_dialog.setIcon(QMessageBox::Question);
            msg_dialog.setWindowTitle("Unsaved packets" UTF8_HORIZONTAL_ELLIPSIS);

            /* This file has unsaved data or there's a capture in
               progress; ask the user whether to save the data. */
            if (capture_in_progress && context != Restart) {
                question = tr("Do you want to stop the capture and save the captured packets%1?").arg(before_what);
                infotext = tr("Your captured packets will be lost if you don't save them.");
            } else if (capture_file_.capFile()->is_tempfile) {
                if (context == Reload) {
                    // Reloading a tempfile will keep the packets, so this is not unsaved packets
                    question = tr("Do you want to save the changes you've made%1?").arg(before_what);
                    infotext = tr("Your changes will be lost if you don't save them.");
                } else {
                    question = tr("Do you want to save the captured packets%1?").arg(before_what);
                    infotext = tr("Your captured packets will be lost if you don't save them.");
                }
            } else {
                // No capture in progress and not a tempfile, so this is not unsaved packets
                gchar *display_basename = g_filename_display_basename(capture_file_.capFile()->filename);
                question = tr("Do you want to save the changes you've made to the capture file \"%1\"%2?").arg(display_basename, before_what);
                infotext = tr("Your changes will be lost if you don't save them.");
                g_free(display_basename);
            }

            msg_dialog.setText(question);
            msg_dialog.setInformativeText(infotext);

            // XXX Text comes from ui/gtk/stock_icons.[ch]
            // Note that the button roles differ from the GTK+ version.
            // Cancel = RejectRole
            // Save = AcceptRole
            // Don't Save = DestructiveRole
            msg_dialog.addButton(QMessageBox::Cancel);

            if (capture_in_progress) {
                QString save_button_text;
                if (context == Restart) {
                    save_button_text = tr("Save before Continue");
                } else {
                    save_button_text = tr("Stop and Save");
                }
                save_button = msg_dialog.addButton(save_button_text, QMessageBox::AcceptRole);
            } else {
                save_button = msg_dialog.addButton(QMessageBox::Save);
            }
            msg_dialog.setDefaultButton(save_button);

            QString discard_button_text;
            if (capture_in_progress) {
                switch (context) {
                case Quit:
                    discard_button_text = tr("Stop and Quit &without Saving");
                    break;
                case Restart:
                    discard_button_text = tr("Continue &without Saving");
                    break;
                default:
                    discard_button_text = tr("Stop and Continue &without Saving");
                    break;
                }
            } else {
                switch (context) {
                case Quit:
                    discard_button_text = tr("Quit &without Saving");
                    break;
                case Restart:
                default:
                    discard_button_text = tr("Continue &without Saving");
                    break;
                }
            }
            discard_button = msg_dialog.addButton(discard_button_text, QMessageBox::DestructiveRole);

#if defined(Q_OS_MAC)
            /*
             * In macOS, the "default button" is not necessarily the
             * button that has the input focus; Enter/Return activates
             * the default button, and the spacebar activates the button
             * that has the input focus, and they might be different
             * buttons.
             *
             * In a "do you want to save" dialog, for example, the
             * "save" button is the default button, and the "don't
             * save" button has the input focus, so you can press
             * Enter/Return to save or space not to save (or Escape
             * to dismiss the dialog).
             *
             * In Qt terms, this means "no auto-default", as auto-default
             * makes the button with the input focus the default button,
             * so that Enter/Return will activate it.
             */
            QList<QAbstractButton *> buttons = msg_dialog.buttons();
            for (int i = 0; i < buttons.size(); ++i) {
                QPushButton *button = static_cast<QPushButton *>(buttons.at(i));;
                button->setAutoDefault(false);
            }

            /*
             * It also means that the "don't save" button should be the one
             * initially given the focus.
             */
            discard_button->setFocus();
#endif

            msg_dialog.exec();
            /* According to the Qt doc:
             * when using QMessageBox with custom buttons, exec() function returns an opaque value.
             *
             * Therefore we should use clickedButton() to determine which button was clicked. */

            if (msg_dialog.clickedButton() == save_button) {
#ifdef HAVE_LIBPCAP
                /* If there's a capture in progress, we have to stop the capture
                   and then do the save. */
                if (capture_in_progress)
                    captureStop();
#endif
                /* Save the file and close it */
                // XXX if no packets were captured, any unsaved comments set by
                // the user are silently discarded because capFile() is null.
                if (capture_file_.capFile() && saveCaptureFile(capture_file_.capFile(), true) == false)
                    return false;
                do_close_file = true;
            } else if (msg_dialog.clickedButton() == discard_button) {
                /* Just close the file, discarding changes */
                do_close_file = true;
            } else {
                // cancelButton or some other unspecified button
                return false;
            }
        } else {
            /* Unchanged file or capturing with no packets */
            do_close_file = true;
        }
    } else {
        /* User asked not to be bothered by those prompts, just close it.
         XXX - should that apply only to saving temporary files? */
        do_close_file = true;
    }

    /*
     * Are we done with this file and should we close the file?
     */
    if (do_close_file) {
#ifdef HAVE_LIBPCAP
        /* If there's a capture in progress, we have to stop the capture
           and then do the close. */
        if (capture_in_progress)
            captureStop();
        else if (capture_file_.capFile() && capture_file_.capFile()->state == FILE_READ_IN_PROGRESS) {
            /*
             * When an offline capture is being read, mark it as aborted.
             * cf_read will be responsible for actually closing the capture.
             *
             * We cannot just invoke cf_close here since cf_read is up in the
             * call chain. (update_progress_dlg can end up processing the Quit
             * event from the user which then ends up here.)
             * See also the above "read_lock" check.
             */
            capture_file_.capFile()->state = FILE_READ_ABORTED;
            return true;
        }
#endif
        /* Clear MainWindow file name details */
        gbl_cur_main_window_->setMwFileName("");

        /* captureStop() will close the file if not having any packets */
        if (capture_file_.capFile() && context != Restart && context != Reload)
            // Don't really close if Restart or Reload
            cf_close(capture_file_.capFile());
    }

    return true; /* File closed */
}

void LograyMainWindow::captureStop() {
    stopCapture();

    while (capture_file_.capFile() && capture_file_.capFile()->state == FILE_READ_IN_PROGRESS) {
        WiresharkApplication::processEvents();
    }
}

void LograyMainWindow::findTextCodecs() {
    const QList<int> mibs = QTextCodec::availableMibs();
    QRegularExpression ibmRegExp("^IBM([0-9]+).*$");
    QRegularExpression iso8859RegExp("^ISO-8859-([0-9]+).*$");
    QRegularExpression windowsRegExp("^WINDOWS-([0-9]+).*$");
    QRegularExpressionMatch match;
    for (int mib : mibs) {
        QTextCodec *codec = QTextCodec::codecForMib(mib);
        // QTextCodec::availableMibs() returns a list of hard-coded MIB
        // numbers, it doesn't check if they are really available. ICU data may
        // not have been compiled with support for all encodings.
        if (!codec) {
            continue;
        }

        QString key = codec->name().toUpper();
        char rank;

        if (key.localeAwareCompare("IBM") < 0) {
            rank = 1;
        } else if ((match = ibmRegExp.match(key)).hasMatch()) {
            rank = match.captured(1).size(); // Up to 5
        } else if (key.localeAwareCompare("ISO-8859-") < 0) {
            rank = 6;
        } else if ((match = iso8859RegExp.match(key)).hasMatch()) {
            rank = 6 + match.captured(1).size(); // Up to 6 + 2
        } else if (key.localeAwareCompare("WINDOWS-") < 0) {
            rank = 9;
        } else if ((match = windowsRegExp.match(key)).hasMatch()) {
            rank = 9 + match.captured(1).size(); // Up to 9 + 4
        } else {
            rank = 14;
        }
        // This doesn't perfectly well order the IBM codecs because it's
        // annoying to properly place IBM00858 and IBM00924 in the middle of
        // code page numbers not zero padded to 5 digits.
        // We could manipulate the key further to have more commonly used
        // charsets earlier. IANA MIB ordering would be unxpected:
        // https://www.iana.org/assignments/character-sets/character-sets.xml
        // For data about use in HTTP (other protocols can be quite different):
        // https://w3techs.com/technologies/overview/character_encoding

        key.prepend(char('0' + rank));
        // We use a map here because, due to backwards compatibility,
        // the same QTextCodec may be returned for multiple MIBs, which
        // happens for GBK/GB2312, EUC-KR/windows-949/UHC, and others.
        text_codec_map_.insert(key, codec);
    }
}

void LograyMainWindow::initMainToolbarIcons()
{
    // Normally 16 px. Reflects current GTK+ behavior and other Windows apps.
    int icon_size = style()->pixelMetric(QStyle::PM_SmallIconSize);
#if !defined(Q_OS_WIN)
    // Force icons to 24x24 for now, otherwise actionFileOpen looks wonky.
    // The macOS HIG specifies 32-pixel icons but they're a little too
    // large IMHO.
    icon_size = icon_size * 3 / 2;
#endif
    main_ui_->mainToolBar->setIconSize(QSize(icon_size, icon_size));

    // Toolbar actions. The GNOME HIG says that we should have a menu icon for each
    // toolbar item but that clutters up our menu. Set menu icons sparingly.

    main_ui_->actionCaptureStart->setIcon(StockIcon("x-capture-start"));
    main_ui_->actionCaptureStop->setIcon(StockIcon("x-capture-stop"));
    main_ui_->actionCaptureRestart->setIcon(StockIcon("x-capture-restart"));
    main_ui_->actionCaptureOptions->setIcon(StockIcon("x-capture-options"));

    // Menu icons are disabled in main_window.ui for these items.
    main_ui_->actionFileOpen->setIcon(StockIcon("document-open"));
    main_ui_->actionFileSave->setIcon(StockIcon("x-capture-file-save"));
    main_ui_->actionFileClose->setIcon(StockIcon("x-capture-file-close"));
    main_ui_->actionViewReload->setIcon(StockIcon("x-capture-file-reload"));

    main_ui_->actionEditFindPacket->setIcon(StockIcon("edit-find"));
    main_ui_->actionGoPreviousPacket->setIcon(StockIcon("go-previous"));
    main_ui_->actionGoNextPacket->setIcon(StockIcon("go-next"));
    main_ui_->actionGoGoToPacket->setIcon(StockIcon("go-jump"));
    main_ui_->actionGoFirstPacket->setIcon(StockIcon("go-first"));
    main_ui_->actionGoLastPacket->setIcon(StockIcon("go-last"));
    main_ui_->actionGoPreviousConversationPacket->setIcon(StockIcon("go-previous"));
    main_ui_->actionGoNextConversationPacket->setIcon(StockIcon("go-next"));
#if defined(Q_OS_MAC)
    main_ui_->actionGoPreviousConversationPacket->setShortcut(QKeySequence(Qt::META | Qt::Key_Comma));
    main_ui_->actionGoNextConversationPacket->setShortcut(QKeySequence(Qt::META | Qt::Key_Period));
#endif
    main_ui_->actionGoPreviousHistoryPacket->setIcon(StockIcon("go-previous"));
    main_ui_->actionGoNextHistoryPacket->setIcon(StockIcon("go-next"));
    main_ui_->actionGoAutoScroll->setIcon(StockIcon("x-stay-last"));

    main_ui_->actionViewColorizePacketList->setIcon(StockIcon("x-colorize-packets"));

    QList<QKeySequence> zi_seq = main_ui_->actionViewZoomIn->shortcuts();
    zi_seq << QKeySequence(Qt::CTRL | Qt::Key_Equal);
    main_ui_->actionViewZoomIn->setIcon(StockIcon("zoom-in"));
    main_ui_->actionViewZoomIn->setShortcuts(zi_seq);
    main_ui_->actionViewZoomOut->setIcon(StockIcon("zoom-out"));
    main_ui_->actionViewNormalSize->setIcon(StockIcon("zoom-original"));
    main_ui_->actionViewResizeColumns->setIcon(StockIcon("x-resize-columns"));

    main_ui_->actionNewDisplayFilterExpression->setIcon(StockIcon("list-add"));
}

void LograyMainWindow::initShowHideMainWidgets()
{
    if (show_hide_actions_) {
        return;
    }

    show_hide_actions_ = new QActionGroup(this);
    QMap<QAction *, QWidget *> shmw_actions;

    show_hide_actions_->setExclusive(false);
    shmw_actions[main_ui_->actionViewMainToolbar] = main_ui_->mainToolBar;
    shmw_actions[main_ui_->actionViewFilterToolbar] = main_ui_->displayFilterToolBar;
    shmw_actions[main_ui_->actionViewStatusBar] = main_ui_->statusBar;
    shmw_actions[main_ui_->actionViewPacketList] = packet_list_;
    shmw_actions[main_ui_->actionViewPacketDetails] = proto_tree_;
    shmw_actions[main_ui_->actionViewPacketBytes] = byte_view_tab_;
    shmw_actions[main_ui_->actionViewPacketDiagram] = packet_diagram_;

    foreach(QAction *shmwa, shmw_actions.keys()) {
        shmwa->setData(QVariant::fromValue(shmw_actions[shmwa]));
        show_hide_actions_->addAction(shmwa);
    }

    // Initial hide the Interface Toolbar submenu
    main_ui_->menuInterfaceToolbars->menuAction()->setVisible(false);

    /* Initially hide the additional toolbars menus */
    main_ui_->menuAdditionalToolbars->menuAction()->setVisible(false);

    connect(show_hide_actions_, SIGNAL(triggered(QAction*)), this, SLOT(showHideMainWidgets(QAction*)));
}

void LograyMainWindow::initTimeDisplayFormatMenu()
{
    if (time_display_actions_) {
        return;
    }

    time_display_actions_ = new QActionGroup(this);

    td_actions[main_ui_->actionViewTimeDisplayFormatDateYMDandTimeOfDay] = TS_ABSOLUTE_WITH_YMD;
    td_actions[main_ui_->actionViewTimeDisplayFormatDateYDOYandTimeOfDay] = TS_ABSOLUTE_WITH_YDOY;
    td_actions[main_ui_->actionViewTimeDisplayFormatTimeOfDay] = TS_ABSOLUTE;
    td_actions[main_ui_->actionViewTimeDisplayFormatSecondsSinceEpoch] = TS_EPOCH;
    td_actions[main_ui_->actionViewTimeDisplayFormatSecondsSinceBeginningOfCapture] = TS_RELATIVE;
    td_actions[main_ui_->actionViewTimeDisplayFormatSecondsSincePreviousCapturedPacket] = TS_DELTA;
    td_actions[main_ui_->actionViewTimeDisplayFormatSecondsSincePreviousDisplayedPacket] = TS_DELTA_DIS;
    td_actions[main_ui_->actionViewTimeDisplayFormatUTCDateYMDandTimeOfDay] = TS_UTC_WITH_YMD;
    td_actions[main_ui_->actionViewTimeDisplayFormatUTCDateYDOYandTimeOfDay] = TS_UTC_WITH_YDOY;
    td_actions[main_ui_->actionViewTimeDisplayFormatUTCTimeOfDay] = TS_UTC;

    foreach(QAction* tda, td_actions.keys()) {
        tda->setData(QVariant::fromValue(td_actions[tda]));
        time_display_actions_->addAction(tda);
    }

    connect(time_display_actions_, SIGNAL(triggered(QAction*)), this, SLOT(setTimestampFormat(QAction*)));
}

void LograyMainWindow::initTimePrecisionFormatMenu()
{
    if (time_precision_actions_) {
        return;
    }

    time_precision_actions_ = new QActionGroup(this);

    tp_actions[main_ui_->actionViewTimeDisplayFormatPrecisionAutomatic] = TS_PREC_AUTO;
    tp_actions[main_ui_->actionViewTimeDisplayFormatPrecisionSeconds] = TS_PREC_FIXED_SEC;
    tp_actions[main_ui_->actionViewTimeDisplayFormatPrecisionDeciseconds] = TS_PREC_FIXED_DSEC;
    tp_actions[main_ui_->actionViewTimeDisplayFormatPrecisionCentiseconds] = TS_PREC_FIXED_CSEC;
    tp_actions[main_ui_->actionViewTimeDisplayFormatPrecisionMilliseconds] = TS_PREC_FIXED_MSEC;
    tp_actions[main_ui_->actionViewTimeDisplayFormatPrecisionMicroseconds] = TS_PREC_FIXED_USEC;
    tp_actions[main_ui_->actionViewTimeDisplayFormatPrecisionNanoseconds] = TS_PREC_FIXED_NSEC;

    foreach(QAction* tpa, tp_actions.keys()) {
        tpa->setData(QVariant::fromValue(tp_actions[tpa]));
        time_precision_actions_->addAction(tpa);
    }

    connect(time_precision_actions_, SIGNAL(triggered(QAction*)), this, SLOT(setTimestampPrecision(QAction*)));
}

// Menu items which will be disabled when we freeze() and whose state will
// be restored when we thaw(). Add to the list as needed.
void LograyMainWindow::initFreezeActions()
{
    QList<QAction *> freeze_actions = QList<QAction *>()
            << main_ui_->actionFileClose
            << main_ui_->actionViewReload
            << main_ui_->actionEditMarkPacket
            << main_ui_->actionEditMarkAllDisplayed
            << main_ui_->actionEditUnmarkAllDisplayed
            << main_ui_->actionEditIgnorePacket
            << main_ui_->actionEditIgnoreAllDisplayed
            << main_ui_->actionEditUnignoreAllDisplayed
            << main_ui_->actionEditSetTimeReference
            << main_ui_->actionEditUnsetAllTimeReferences;

    foreach(QAction *action, freeze_actions) {
        freeze_actions_ << QPair<QAction *, bool>(action, false);
    }
}

void LograyMainWindow::initConversationMenus()
{
    int i;

    QList<QAction *> cc_actions = QList<QAction *>()
            << main_ui_->actionViewColorizeConversation1 << main_ui_->actionViewColorizeConversation2
            << main_ui_->actionViewColorizeConversation3 << main_ui_->actionViewColorizeConversation4
            << main_ui_->actionViewColorizeConversation5 << main_ui_->actionViewColorizeConversation6
            << main_ui_->actionViewColorizeConversation7 << main_ui_->actionViewColorizeConversation8
            << main_ui_->actionViewColorizeConversation9 << main_ui_->actionViewColorizeConversation10;

    for (GList *conv_filter_list_entry = log_conv_filter_list; conv_filter_list_entry; conv_filter_list_entry = gxx_list_next(conv_filter_list_entry)) {
        // Main menu items
        conversation_filter_t* conv_filter = gxx_list_data(conversation_filter_t *, conv_filter_list_entry);
        ConversationAction *conv_action = new ConversationAction(main_ui_->menuConversationFilter, conv_filter);
        main_ui_->menuConversationFilter->addAction(conv_action);

        connect(this, SIGNAL(packetInfoChanged(_packet_info*)), conv_action, SLOT(setPacketInfo(_packet_info*)));
        connect(conv_action, SIGNAL(triggered()), this, SLOT(applyConversationFilter()));

        // Packet list context menu items
        packet_list_->conversationMenu()->addAction(conv_action);

        QMenu *submenu = packet_list_->colorizeMenu()->addMenu(conv_action->text());
        i = 1;

        foreach(QAction *cc_action, cc_actions) {
            conv_action = new ConversationAction(submenu, conv_filter);
            conv_action->setText(cc_action->text());
            conv_action->setIcon(cc_action->icon());
            conv_action->setColorNumber(i++);
            submenu->addAction(conv_action);
            connect(this, SIGNAL(packetInfoChanged(_packet_info*)), conv_action, SLOT(setPacketInfo(_packet_info*)));
            connect(conv_action, SIGNAL(triggered()), this, SLOT(colorizeActionTriggered()));
        }

        conv_action = new ConversationAction(submenu, conv_filter);
        conv_action->setText(main_ui_->actionViewColorizeNewColoringRule->text());
        submenu->addAction(conv_action);
        connect(this, SIGNAL(packetInfoChanged(_packet_info*)), conv_action, SLOT(setPacketInfo(_packet_info*)));
        connect(conv_action, SIGNAL(triggered()), this, SLOT(colorizeActionTriggered()));

        // Proto tree conversation menu is filled in in ProtoTree::contextMenuEvent.
        // We should probably do that here.
    }

    // Proto tree colorization items
    i = 1;
    ColorizeAction *colorize_action;
    foreach(QAction *cc_action, cc_actions) {
        colorize_action = new ColorizeAction(proto_tree_->colorizeMenu());
        colorize_action->setText(cc_action->text());
        colorize_action->setIcon(cc_action->icon());
        colorize_action->setColorNumber(i++);
        proto_tree_->colorizeMenu()->addAction(colorize_action);
        connect(this, SIGNAL(fieldFilterChanged(QByteArray)), colorize_action, SLOT(setFieldFilter(QByteArray)));
        connect(colorize_action, SIGNAL(triggered()), this, SLOT(colorizeActionTriggered()));
    }

    colorize_action = new ColorizeAction(proto_tree_->colorizeMenu());
    colorize_action->setText(main_ui_->actionViewColorizeNewColoringRule->text());
    proto_tree_->colorizeMenu()->addAction(colorize_action);
    connect(this, SIGNAL(fieldFilterChanged(QByteArray)), colorize_action, SLOT(setFieldFilter(QByteArray)));
    connect(colorize_action, SIGNAL(triggered()), this, SLOT(colorizeActionTriggered()));
}

gboolean LograyMainWindow::addExportObjectsMenuItem(const void *, void *value, void *userdata)
{
    register_eo_t *eo = (register_eo_t*)value;
    LograyMainWindow *window = (LograyMainWindow*)userdata;

    ExportObjectAction *export_action = new ExportObjectAction(window->main_ui_->menuFileExportObjects, eo);
    window->main_ui_->menuFileExportObjects->addAction(export_action);

    //initially disable until a file is loaded (then file signals will take over)
    export_action->setEnabled(false);

    connect(&window->capture_file_, SIGNAL(captureEvent(CaptureEvent)), export_action, SLOT(captureFileEvent(CaptureEvent)));
    connect(export_action, SIGNAL(triggered()), window, SLOT(applyExportObject()));
    return FALSE;
}

void LograyMainWindow::initExportObjectsMenus()
{
    eo_iterate_tables(addExportObjectsMenuItem, this);
}

// Titlebar
void LograyMainWindow::setTitlebarForCaptureFile()
{
    if (capture_file_.capFile() && capture_file_.capFile()->filename) {
        setWSWindowTitle(QString("[*]%1").arg(capture_file_.fileDisplayName()));
        //
        // XXX - on non-Mac platforms, put in the application
        // name?  Or do so only for temporary files?
        //
        if (!capture_file_.capFile()->is_tempfile) {
            //
            // Set the file path; that way, for macOS, it'll set the
            // "proxy icon".
            //
            setWindowFilePath(capture_file_.filePath());
        }
        setWindowModified(cf_has_unsaved_data(capture_file_.capFile()));
    } else {
        /* We have no capture file. */
        setWSWindowTitle();
    }
}

QString LograyMainWindow::replaceWindowTitleVariables(QString title)
{
    title.replace("%P", get_profile_name());
    title.replace("%V", get_ws_vcs_version_info());

    if (title.contains("%F")) {
        // %F is file path of the capture file.
        if (capture_file_.capFile()) {
            // get_dirname() will overwrite the argument so make a copy first
            char *filename = g_strdup(capture_file_.capFile()->filename);
            QString file(get_dirname(filename));
            g_free(filename);
#ifndef _WIN32
            // Substitute HOME with ~
            QString homedir(g_getenv("HOME"));
            if (!homedir.isEmpty()) {
                homedir.remove(QRegularExpression("[/]+$"));
                file.replace(homedir, "~");
            }
#endif
            title.replace("%F", file);
        } else {
            // No file loaded, no folder name
            title.remove("%F");
        }
    }

    if (title.contains("%S")) {
        // %S is a conditional separator (" - ") that only shows when surrounded by variables
        // with values or static text. Remove repeating, leading and trailing separators.
        title.replace(QRegularExpression("(%S)+"), "%S");
        title.remove(QRegularExpression("^%S|%S$"));
#ifdef __APPLE__
        // On macOS we separate with a unicode em dash
        title.replace("%S", " " UTF8_EM_DASH " ");
#else
        title.replace("%S", " - ");
#endif
    }

    return title;
}

void LograyMainWindow::setWSWindowTitle(QString title)
{
    if (title.isEmpty()) {
        title = tr("The Logray System Log Analyzer");
    }

    if (prefs.gui_prepend_window_title && prefs.gui_prepend_window_title[0]) {
        QString custom_title = replaceWindowTitleVariables(prefs.gui_prepend_window_title);
        if (custom_title.length() > 0) {
            title.prepend(QString("[%1] ").arg(custom_title));
        }
    }

    if (prefs.gui_window_title && prefs.gui_window_title[0]) {
        QString custom_title = replaceWindowTitleVariables(prefs.gui_window_title);
        if (custom_title.length() > 0) {
#ifdef __APPLE__
            // On macOS we separate the titles with a unicode em dash
            title.append(QString(" %1 %2").arg(UTF8_EM_DASH).arg(custom_title));
#else
            title.append(QString(" [%1]").arg(custom_title));
#endif
        }
    }

    setWindowTitle(title);
    setWindowFilePath(NULL);
}

void LograyMainWindow::setTitlebarForCaptureInProgress()
{
    if (capture_file_.capFile()) {
        setWSWindowTitle(tr("Capturing from %1").arg(cf_get_tempfile_source(capture_file_.capFile())));
    } else {
        /* We have no capture in progress. */
        setWSWindowTitle();
    }
}

// Menu state

/* Enable or disable menu items based on whether you have a capture file
   you've finished reading and, if you have one, whether it's been saved
   and whether it could be saved except by copying the raw packet data. */
void LograyMainWindow::setMenusForCaptureFile(bool force_disable)
{
    bool enable = true;
    bool can_write = false;
    bool can_save = false;
    bool can_save_as = false;

    if (force_disable || capture_file_.capFile() == NULL || capture_file_.capFile()->state == FILE_READ_IN_PROGRESS) {
        /* We have no capture file or we're currently reading a file */
        enable = false;
    } else {
        /* We have a capture file. Can we write or save? */
        can_write = cf_can_write_with_wiretap(capture_file_.capFile());
        can_save = cf_can_save(capture_file_.capFile());
        can_save_as = cf_can_save_as(capture_file_.capFile());
    }

    main_ui_->actionViewReload_as_File_Format_or_Capture->setEnabled(enable);
    main_ui_->actionFileMerge->setEnabled(can_write);
    main_ui_->actionFileClose->setEnabled(enable);
    main_ui_->actionFileSave->setEnabled(can_save);
    main_ui_->actionFileSaveAs->setEnabled(can_save_as);
    main_ui_->actionStatisticsCaptureFileProperties->setEnabled(enable);
    /*
     * "Export Specified Packets..." should be available only if
     * we can write the file out in at least one format.
     */
    main_ui_->actionFileExportPackets->setEnabled(can_write);

    main_ui_->actionFileExportAsCArrays->setEnabled(enable);
    main_ui_->actionFileExportAsCSV->setEnabled(enable);
    main_ui_->actionFileExportAsPDML->setEnabled(enable);
    main_ui_->actionFileExportAsPlainText->setEnabled(enable);
    main_ui_->actionFileExportAsPSML->setEnabled(enable);
    main_ui_->actionFileExportAsJSON->setEnabled(enable);

    main_ui_->actionFileExportPDU->setEnabled(enable);

    foreach(QAction *eo_action, main_ui_->menuFileExportObjects->actions()) {
        eo_action->setEnabled(enable);
    }

    main_ui_->actionViewReload->setEnabled(enable);

#ifdef HAVE_SOFTWARE_UPDATE
    // We might want to enable or disable automatic checks here as well.
    update_action_->setEnabled(!can_save);
#endif
}

void LograyMainWindow::setMenusForCaptureInProgress(bool capture_in_progress) {
    /* Either a capture was started or stopped; in either case, it's not
       in the process of stopping, so allow quitting. */

    main_ui_->actionFileOpen->setEnabled(!capture_in_progress);
    main_ui_->menuOpenRecentCaptureFile->setEnabled(!capture_in_progress);

    main_ui_->actionFileExportAsCArrays->setEnabled(capture_in_progress);
    main_ui_->actionFileExportAsCSV->setEnabled(capture_in_progress);
    main_ui_->actionFileExportAsPDML->setEnabled(capture_in_progress);
    main_ui_->actionFileExportAsPlainText->setEnabled(capture_in_progress);
    main_ui_->actionFileExportAsPSML->setEnabled(capture_in_progress);
    main_ui_->actionFileExportAsJSON->setEnabled(capture_in_progress);

    main_ui_->actionFileExportPDU->setEnabled(!capture_in_progress);

    foreach(QAction *eo_action, main_ui_->menuFileExportObjects->actions()) {
        eo_action->setEnabled(capture_in_progress);
    }

    main_ui_->menuFileSet->setEnabled(!capture_in_progress);
    main_ui_->actionFileQuit->setEnabled(true);
#ifdef HAVE_SOFTWARE_UPDATE
    // We might want to enable or disable automatic checks here as well.
    update_action_->setEnabled(!capture_in_progress);
#endif

    main_ui_->actionStatisticsCaptureFileProperties->setEnabled(capture_in_progress);

    // XXX Fix packet list heading menu sensitivity
    //    set_menu_sensitivity(ui_manager_packet_list_heading, "/PacketListHeadingPopup/SortAscending",
    //                         !capture_in_progress);
    //    set_menu_sensitivity(ui_manager_packet_list_heading, "/PacketListHeadingPopup/SortDescending",
    //                         !capture_in_progress);
    //    set_menu_sensitivity(ui_manager_packet_list_heading, "/PacketListHeadingPopup/NoSorting",
    //                         !capture_in_progress);

#ifdef HAVE_LIBPCAP
    main_ui_->actionCaptureOptions->setEnabled(!capture_in_progress);
    main_ui_->actionCaptureStart->setEnabled(!capture_in_progress);
    main_ui_->actionCaptureStart->setChecked(capture_in_progress);
    main_ui_->actionCaptureStop->setEnabled(capture_in_progress);
    main_ui_->actionCaptureRestart->setEnabled(capture_in_progress);
    main_ui_->actionCaptureRefreshInterfaces->setEnabled(!capture_in_progress);
#endif /* HAVE_LIBPCAP */

}

void LograyMainWindow::setMenusForCaptureStopping() {
    main_ui_->actionFileQuit->setEnabled(false);
#ifdef HAVE_SOFTWARE_UPDATE
    update_action_->setEnabled(false);
#endif
    main_ui_->actionStatisticsCaptureFileProperties->setEnabled(false);
#ifdef HAVE_LIBPCAP
    main_ui_->actionCaptureStart->setChecked(false);
    main_ui_->actionCaptureStop->setEnabled(false);
    main_ui_->actionCaptureRestart->setEnabled(false);
#endif /* HAVE_LIBPCAP */
}

void LograyMainWindow::setForCapturedPackets(bool have_captured_packets)
{
    main_ui_->actionFilePrint->setEnabled(have_captured_packets);

//    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/Print",
//                         have_captured_packets);

    main_ui_->actionEditFindPacket->setEnabled(have_captured_packets);
    main_ui_->actionEditFindNext->setEnabled(have_captured_packets);
    main_ui_->actionEditFindPrevious->setEnabled(have_captured_packets);

    main_ui_->actionGoGoToPacket->setEnabled(have_captured_packets);
    main_ui_->actionGoPreviousPacket->setEnabled(have_captured_packets);
    main_ui_->actionGoNextPacket->setEnabled(have_captured_packets);
    main_ui_->actionGoFirstPacket->setEnabled(have_captured_packets);
    main_ui_->actionGoLastPacket->setEnabled(have_captured_packets);
    main_ui_->actionGoNextConversationPacket->setEnabled(have_captured_packets);
    main_ui_->actionGoPreviousConversationPacket->setEnabled(have_captured_packets);

    main_ui_->actionViewZoomIn->setEnabled(have_captured_packets);
    main_ui_->actionViewZoomOut->setEnabled(have_captured_packets);
    main_ui_->actionViewNormalSize->setEnabled(have_captured_packets);
    main_ui_->actionViewResizeColumns->setEnabled(have_captured_packets);

    main_ui_->actionStatisticsCaptureFileProperties->setEnabled(have_captured_packets);
    main_ui_->actionStatisticsProtocolHierarchy->setEnabled(have_captured_packets);
    main_ui_->actionStatisticsIOGraph->setEnabled(have_captured_packets);
}

void LograyMainWindow::setMenusForFileSet(bool enable_list_files) {
    bool enable_next = fileset_get_next() != NULL && enable_list_files;
    bool enable_prev = fileset_get_previous() != NULL && enable_list_files;

    main_ui_->actionFileSetListFiles->setEnabled(enable_list_files);
    main_ui_->actionFileSetNextFile->setEnabled(enable_next);
    main_ui_->actionFileSetPreviousFile->setEnabled(enable_prev);
}

void LograyMainWindow::setWindowIcon(const QIcon &icon) {
    mainApp->setWindowIcon(icon);
    QMainWindow::setWindowIcon(icon);
}

void LograyMainWindow::updateForUnsavedChanges() {
    setTitlebarForCaptureFile();
    setMenusForCaptureFile();
}

void LograyMainWindow::changeEvent(QEvent* event)
{
    if (0 != event)
    {
        switch (event->type())
        {
        case QEvent::LanguageChange:
            main_ui_->retranslateUi(this);
            // make sure that the "Clear Menu" item is retranslated
            mainApp->emitAppSignal(WiresharkApplication::RecentCapturesChanged);
            break;
        case QEvent::LocaleChange: {
            QString locale = QLocale::system().name();
            locale.truncate(locale.lastIndexOf('_'));
            mainApp->loadLanguage(locale);
        }
        break;
        case QEvent::WindowStateChange:
            main_ui_->actionViewFullScreen->setChecked(this->isFullScreen());
            break;
        default:
            break;
        }
    }
    QMainWindow::changeEvent(event);
}

/* Update main window items based on whether there's a capture in progress. */
void LograyMainWindow::setForCaptureInProgress(bool capture_in_progress, bool handle_toolbars, GArray *ifaces)
{
    setMenusForCaptureInProgress(capture_in_progress);

#ifdef HAVE_LIBPCAP
    packet_list_->setCaptureInProgress(capture_in_progress);
    packet_list_->setVerticalAutoScroll(capture_in_progress && main_ui_->actionGoAutoScroll->isChecked());

//    set_capture_if_dialog_for_capture_in_progress(capture_in_progress);
#endif

    if (handle_toolbars) {
        QList<InterfaceToolbar *> toolbars = findChildren<InterfaceToolbar *>();
        foreach(InterfaceToolbar *toolbar, toolbars) {
            if (capture_in_progress) {
                toolbar->startCapture(ifaces);
            } else {
                toolbar->stopCapture();
            }
        }
    }
}

void LograyMainWindow::addMenuActions(QList<QAction *> &actions, int menu_group)
{
    foreach(QAction *action, actions) {
        switch (menu_group) {
        case REGISTER_LOG_ANALYZE_GROUP_UNSORTED:
        case REGISTER_LOG_STAT_GROUP_UNSORTED:
            main_ui_->menuStatistics->insertAction(
                            main_ui_->actionStatistics_REGISTER_STAT_GROUP_UNSORTED,
                            action);
            break;
//        case REGISTER_TOOLS_GROUP_UNSORTED:
//        {
//            // Allow the creation of submenus. Mimics the behavor of
//            // ui/gtk/main_menubar.c:add_menu_item_to_main_menubar
//            // and GtkUIManager.
//            //
//            // For now we limit the insanity to the "Tools" menu.
//            QStringList menu_path = action->text().split('/');
//            QMenu *cur_menu = main_ui_->menuTools;
//            while (menu_path.length() > 1) {
//                QString menu_title = menu_path.takeFirst();
//                QMenu *submenu = cur_menu->findChild<QMenu *>(menu_title.toLower(), Qt::FindDirectChildrenOnly);
//                if (!submenu) {
//                    submenu = cur_menu->addMenu(menu_title);
//                    submenu->setObjectName(menu_title.toLower());
//                }
//                cur_menu = submenu;
//            }
//            action->setText(menu_path.last());
//            cur_menu->addAction(action);
//            break;
//        }
        default:
            // Skip packet items.
            return;
        }

        // Connect each action type to its corresponding slot. We to
        // distinguish various types of actions. Setting their objectName
        // seems to work OK.
        if (action->objectName() == TapParameterDialog::actionName()) {
            connect(action, SIGNAL(triggered(bool)), this, SLOT(openTapParameterDialog()));
        } else if (action->objectName() == FunnelStatistics::actionName()) {
            connect(action, SIGNAL(triggered(bool)), funnel_statistics_, SLOT(funnelActionTriggered()));
        }
    }
}

void LograyMainWindow::removeMenuActions(QList<QAction *> &actions, int menu_group)
{
    foreach(QAction *action, actions) {
        switch (menu_group) {
        case REGISTER_LOG_ANALYZE_GROUP_UNSORTED:
        case REGISTER_LOG_STAT_GROUP_UNSORTED:
            main_ui_->menuStatistics->removeAction(action);
            break;
//        case REGISTER_TOOLS_GROUP_UNSORTED:
//        {
//            // Allow removal of submenus.
//            // For now we limit the insanity to the "Tools" menu.
//            QStringList menu_path = action->text().split('/');
//            QMenu *cur_menu = main_ui_->menuTools;
//            while (menu_path.length() > 1) {
//                QString menu_title = menu_path.takeFirst();
//                QMenu *submenu = cur_menu->findChild<QMenu *>(menu_title.toLower(), Qt::FindDirectChildrenOnly);
//                cur_menu = submenu;
//            }
//            cur_menu->removeAction(action);
//            break;
//        }
        default:
//            qDebug() << "FIX: Remove" << action->text() << "from the menu";
            break;
        }
    }
}

void LograyMainWindow::addDynamicMenus()
{
    // Fill in each menu
    foreach(register_stat_group_t menu_group, menu_groups_) {
        QList<QAction *>actions = mainApp->dynamicMenuGroupItems(menu_group);
        addMenuActions(actions, menu_group);
    }
}

void LograyMainWindow::reloadDynamicMenus()
{
    foreach(register_stat_group_t menu_group, menu_groups_) {
        QList<QAction *>actions = mainApp->removedMenuGroupItems(menu_group);
        removeMenuActions(actions, menu_group);

        actions = mainApp->addedMenuGroupItems(menu_group);
        addMenuActions(actions, menu_group);
    }

    mainApp->clearAddedMenuGroupItems();
    mainApp->clearRemovedMenuGroupItems();
}

void LograyMainWindow::externalMenuHelper(ext_menu_t * menu, QMenu  * subMenu, gint depth)
{
    QAction * itemAction = Q_NULLPTR;
    ext_menubar_t * item = Q_NULLPTR;
    GList * children = Q_NULLPTR;

    /* There must exists an xpath parent */
    Q_ASSERT(subMenu != NULL);

    /* If the depth counter exceeds, something must have gone wrong */
    Q_ASSERT(depth < EXT_MENUBAR_MAX_DEPTH);

    children = menu->children;
    /* Iterate the child entries */
    while (children && children->data) {
        item = gxx_list_data(ext_menubar_t *, children);

        if (item->type == EXT_MENUBAR_MENU) {
            /* Handle Submenu entry */
            this->externalMenuHelper(item, subMenu->addMenu(item->label), depth++);
        } else if (item->type == EXT_MENUBAR_SEPARATOR) {
            subMenu->addSeparator();
        } else if (item->type == EXT_MENUBAR_ITEM || item->type == EXT_MENUBAR_URL) {
            itemAction = subMenu->addAction(item->name);
            itemAction->setData(QVariant::fromValue(static_cast<void *>(item)));
            itemAction->setText(item->label);
            connect(itemAction, SIGNAL(triggered()),
                    this, SLOT(externalMenuItem_triggered()));
        }

        /* Iterate Loop */
        children = gxx_list_next(children);
    }
}

QMenu * LograyMainWindow::searchSubMenu(QString objectName)
{
    QList<QMenu*> lst;

    if (objectName.length() > 0) {
        QString searchName = QString("menu") + objectName;

        lst = main_ui_->menuBar->findChildren<QMenu*>();
        foreach(QMenu* m, lst) {
            if (QString::compare(m->objectName(), searchName) == 0)
                return m;
        }
    }

    return 0;
}

void LograyMainWindow::addPluginIFStructures()
{
    GList *user_menu = ext_menubar_get_entries();

    while (user_menu && user_menu->data) {
        QMenu *subMenu = Q_NULLPTR;
        ext_menu_t *menu = gxx_list_data(ext_menu_t *, user_menu);

        /* On this level only menu items should exist. Not doing an assert here,
         * as it could be an honest mistake */
        if (menu->type != EXT_MENUBAR_MENU) {
            user_menu = gxx_list_next(user_menu);
            continue;
        }

        /* Create main submenu and add it to the menubar */
        if (menu->parent_menu) {
            QMenu *sortUnderneath = searchSubMenu(QString(menu->parent_menu));
            if (sortUnderneath)
                subMenu = sortUnderneath->addMenu(menu->label);
        }

        if (!subMenu)
            subMenu = main_ui_->menuBar->addMenu(menu->label);

        /* This will generate the action structure for each menu. It is recursive,
         * therefore a sub-routine, and we have a depth counter to prevent endless loops. */
        this->externalMenuHelper(menu, subMenu, 0);

        /* Iterate Loop */
        user_menu = gxx_list_next(user_menu);
    }

    int cntToolbars = 0;

    QMenu *tbMenu = main_ui_->menuAdditionalToolbars;
    GList *if_toolbars = ext_toolbar_get_entries();
    while (if_toolbars && if_toolbars->data) {
        ext_toolbar_t *toolbar = gxx_list_data(ext_toolbar_t*, if_toolbars);

        if (toolbar->type != EXT_TOOLBAR_BAR) {
            if_toolbars = gxx_list_next(if_toolbars);
            continue;
        }

        bool visible = g_list_find_custom(recent.gui_additional_toolbars, toolbar->name, reinterpret_cast<GCompareFunc>(strcmp)) ? true : false;

        AdditionalToolBar *ifToolBar = AdditionalToolBar::create(this, toolbar);

        if (ifToolBar) {
            ifToolBar->setVisible(visible);

            QAction *iftbAction = new QAction(QString(toolbar->name), this);
            iftbAction->setToolTip(toolbar->tooltip);
            iftbAction->setEnabled(true);
            iftbAction->setCheckable(true);
            iftbAction->setChecked(visible);
            iftbAction->setToolTip(tr("Show or hide the toolbar"));
            iftbAction->setData(VariantPointer<ext_toolbar_t>::asQVariant(toolbar));

            QAction *before = Q_NULLPTR;

            foreach(QAction *action, tbMenu->actions()) {
                /* Ensure we add the menu entries in sorted order */
                if (action->text().compare(toolbar->name, Qt::CaseInsensitive) > 0) {
                    before = action;
                    break;
                }
            }

            tbMenu->insertAction(before, iftbAction);

            addToolBar(Qt::TopToolBarArea, ifToolBar);
            insertToolBarBreak(ifToolBar);

            if (show_hide_actions_)
                show_hide_actions_->addAction(iftbAction);

            cntToolbars++;
        }

        if_toolbars = gxx_list_next(if_toolbars);
    }

    if (cntToolbars)
        tbMenu->menuAction()->setVisible(true);
}

void LograyMainWindow::removeAdditionalToolbar(QString toolbarName)
{
    if (toolbarName.length() == 0)
        return;

    QList<QToolBar *> toolbars = findChildren<QToolBar *>();
    foreach(QToolBar *tb, toolbars) {
        AdditionalToolBar *ifToolBar = dynamic_cast<AdditionalToolBar *>(tb);

        if (ifToolBar && ifToolBar->menuName().compare(toolbarName)) {
            GList *entry = g_list_find_custom(recent.gui_additional_toolbars, qUtf8Printable(ifToolBar->menuName()), reinterpret_cast<GCompareFunc>(strcmp));
            if (entry) {
                recent.gui_additional_toolbars = g_list_remove(recent.gui_additional_toolbars, entry->data);
            }
            QList<QAction *> actions = main_ui_->menuAdditionalToolbars->actions();
            foreach(QAction *action, actions) {
                ext_toolbar_t *item = VariantPointer<ext_toolbar_t>::asPtr(action->data());
                if (item && ifToolBar->menuName().compare(item->name)) {
                    if (show_hide_actions_)
                        show_hide_actions_->removeAction(action);
                    main_ui_->menuAdditionalToolbars->removeAction(action);
                }
            }
            break;
        }
    }

}

QString LograyMainWindow::getMwFileName()
{
    return mwFileName_;
}

void LograyMainWindow::setMwFileName(QString fileName)
{
    mwFileName_ = fileName;
    return;
}

frame_data * LograyMainWindow::frameDataForRow(int row) const
{
    if (packet_list_)
        return packet_list_->getFDataForRow(row);

    return Q_NULLPTR;
}
