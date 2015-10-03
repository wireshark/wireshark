/* main_window.cpp
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

#include "main_window.h"
#include <ui_main_window.h>

#include <epan/addr_resolv.h>
#include <epan/epan_dissect.h>
#include <wsutil/filesystem.h>
#include <epan/prefs.h>
#include <epan/stats_tree_priv.h>
#include <epan/plugin_if.h>

#ifdef HAVE_LIBPCAP
#include "ui/capture.h"
#include <capchild/capture_session.h>
#endif

#include "ui/alert_box.h"
#ifdef HAVE_LIBPCAP
#include "ui/capture_ui_utils.h"
#endif
#include "ui/capture_globals.h"
#include "ui/main_statusbar.h"
#include "ui/recent.h"
#include "ui/util.h"
#include "ui/preference_utils.h"

#include "byte_view_tab.h"
#include "display_filter_edit.h"
#include "export_dissection_dialog.h"
#include "funnel_statistics.h"
#include "import_text_dialog.h"
#include "packet_list.h"
#include "proto_tree.h"
#include "simple_dialog.h"
#include "stock_icon.h"
#include "tap_parameter_dialog.h"
#include "wireless_frame.h"
#include "wireshark_application.h"

#include "qt_ui_utils.h"

#include <QAction>
#include <QActionGroup>
#include <QDesktopWidget>
#include <QKeyEvent>
#include <QMessageBox>
#include <QMetaObject>
#include <QMimeData>
#include <QTabWidget>
#include <QToolButton>
#include <QTreeWidget>
#include <QUrl>

#if defined(QT_MACEXTRAS_LIB) && QT_VERSION < QT_VERSION_CHECK(5, 2, 1)
#include <QtMacExtras/QMacNativeToolBar>
#endif


//menu_recent_file_write_all

// If we ever add support for multiple windows this will need to be replaced.
static MainWindow *gbl_cur_main_window_ = NULL;

void pipe_input_set_handler(gint source, gpointer user_data, ws_process_id *child_process, pipe_input_cb_t input_cb)
{
    gbl_cur_main_window_->setPipeInputHandler(source, user_data, child_process, input_cb);
}

static void plugin_if_mainwindow_apply_filter(gconstpointer user_data)
{
    if ( gbl_cur_main_window_ != NULL && user_data != NULL )
    {
        GHashTable * dataSet = (GHashTable *) user_data;

        if ( g_hash_table_lookup_extended(dataSet, "filter_string", NULL, NULL ) )
        {
            QString filter((const char *)g_hash_table_lookup(dataSet, "filter_string"));
            gbl_cur_main_window_->filterPackets(filter);
        }
    }
}

static void plugin_if_mainwindow_preference(gconstpointer user_data)
{
    if ( gbl_cur_main_window_ != NULL && user_data != NULL )
    {
        GHashTable * dataSet = (GHashTable *) user_data;
        const char * module_name;
        const char * pref_name;
        const char * pref_value;
        if ( g_hash_table_lookup_extended(dataSet, "pref_module", NULL, (void**)&module_name ) &&
                g_hash_table_lookup_extended(dataSet, "pref_key", NULL, (void**)&pref_name ) &&
                g_hash_table_lookup_extended(dataSet, "pref_value", NULL, (void**)&pref_value ) )
        {
            if ( prefs_store_ext(module_name, pref_name, pref_value) )
            {
                wsApp->emitAppSignal(WiresharkApplication::PacketDissectionChanged);
                wsApp->emitAppSignal(WiresharkApplication::PreferencesChanged);
            }
        }
    }
}

void plugin_if_mainwindow_gotoframe(gconstpointer user_data)
{
    if ( gbl_cur_main_window_ != NULL && user_data != NULL )
    {
        GHashTable * dataSet = (GHashTable *) user_data;
        gpointer framenr;

        if ( g_hash_table_lookup_extended(dataSet, "frame_nr", NULL, &framenr ) )
        {
            if ( GPOINTER_TO_UINT(framenr) != 0 )
                gbl_cur_main_window_->gotoFrame(GPOINTER_TO_UINT(framenr));
        }
    }
}

gpointer
simple_dialog(ESD_TYPE_E type, gint btn_mask, const gchar *msg_format, ...)
{
    va_list ap;

    va_start(ap, msg_format);
    SimpleDialog sd(gbl_cur_main_window_, type, btn_mask, msg_format, ap);
    va_end(ap);

    sd.exec();
    return NULL;
}

/*
 * Alert box, with optional "don't show this message again" variable
 * and checkbox, and optional secondary text.
 */
void
simple_message_box(ESD_TYPE_E type, gboolean *notagain,
                   const char *secondary_msg, const char *msg_format, ...)
{
    if (notagain && *notagain) {
        return;
    }

    va_list ap;

    va_start(ap, msg_format);
    SimpleDialog sd(gbl_cur_main_window_, type, ESD_BTN_OK, msg_format, ap);
    va_end(ap);

    sd.setDetailedText(secondary_msg);

#if (QT_VERSION > QT_VERSION_CHECK(5, 2, 0))
    QCheckBox *cb = NULL;
    if (notagain) {
        cb = new QCheckBox();
        cb->setChecked(true);
        cb->setText(QObject::tr("Don't show this message again."));
        sd.setCheckBox(cb);
    }
#endif

    sd.exec();

#if (QT_VERSION > QT_VERSION_CHECK(5, 2, 0))
    if (notagain && cb) {
        *notagain = cb->isChecked();
    }
#endif
}

/*
 * Error alert box, taking a format and a va_list argument.
 */
void
vsimple_error_message_box(const char *msg_format, va_list ap)
{
    SimpleDialog sd(gbl_cur_main_window_, ESD_TYPE_ERROR, ESD_BTN_OK, msg_format, ap);
    sd.exec();
}


QMenu* MainWindow::findOrAddMenu(QMenu *parent_menu, QString& menu_text) {
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

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    main_ui_(new Ui::MainWindow),
    cur_layout_(QVector<unsigned>()),
    df_combo_box_(new DisplayFilterCombo()),
    packet_list_(NULL),
    proto_tree_(NULL),
    previous_focus_(NULL),
    show_hide_actions_(NULL),
    time_display_actions_(NULL),
    time_precision_actions_(NULL),
    funnel_statistics_(new FunnelStatistics(this, capture_file_)),
    capture_stopping_(false),
    capture_filter_valid_(false),
#ifdef _WIN32
    pipe_timer_(NULL)
#else
    pipe_notifier_(NULL)
#endif
{
    if (!gbl_cur_main_window_) {
        connect(wsApp, SIGNAL(openStatCommandDialog(QString,const char*,void*)),
                this, SLOT(openStatCommandDialog(QString,const char*,void*)));
        connect(wsApp, SIGNAL(openTapParameterDialog(QString,const QString,void*)),
                this, SLOT(openTapParameterDialog(QString,const QString,void*)));
    }
    gbl_cur_main_window_ = this;
#ifdef HAVE_LIBPCAP
    capture_session_init(&cap_session_, CaptureFile::globalCapFile());
#endif
    main_ui_->setupUi(this);
    setWindowIcon(wsApp->normalIcon());
    setTitlebarForCaptureFile();
    setMenusForCaptureFile();
    setForCapturedPackets(false);
    setMenusForFileSet(false);
    interfaceSelectionChanged();
    loadWindowGeometry();

    //To prevent users use features before initialization complete
    //Otherwise unexpected problems may occur
    setFeaturesEnabled(false);
    connect(wsApp, SIGNAL(appInitialized()), this, SLOT(setFeaturesEnabled()));
    connect(wsApp, SIGNAL(appInitialized()), this, SLOT(zoomText()));
    connect(wsApp, SIGNAL(appInitialized()), this, SLOT(initViewColorizeMenu()));
    connect(wsApp, SIGNAL(appInitialized()), this, SLOT(addStatsPluginsToMenu()));
    connect(wsApp, SIGNAL(appInitialized()), this, SLOT(addDynamicMenus()));
    connect(wsApp, SIGNAL(appInitialized()), this, SLOT(addExternalMenus()));

    connect(wsApp, SIGNAL(profileChanging()), this, SLOT(saveWindowGeometry()));
    connect(wsApp, SIGNAL(preferencesChanged()), this, SLOT(layoutPanes()));
    connect(wsApp, SIGNAL(preferencesChanged()), this, SLOT(layoutToolbars()));
    connect(wsApp, SIGNAL(preferencesChanged()), this, SLOT(updatePreferenceActions()));
    connect(wsApp, SIGNAL(preferencesChanged()), this, SLOT(zoomText()));

    connect(wsApp, SIGNAL(updateRecentItemStatus(const QString &, qint64, bool)), this, SLOT(updateRecentFiles()));
    updateRecentFiles();

#ifdef HAVE_LIBPCAP
    connect(&capture_interfaces_dialog_, SIGNAL(startCapture()), this, SLOT(startCapture()));
    connect(&capture_interfaces_dialog_, SIGNAL(stopCapture()), this, SLOT(stopCapture()));
#endif

    const DisplayFilterEdit *df_edit = dynamic_cast<DisplayFilterEdit *>(df_combo_box_->lineEdit());
    connect(df_edit, SIGNAL(pushFilterSyntaxStatus(const QString&)),
            main_ui_->statusBar, SLOT(pushFilterStatus(const QString&)));
    connect(df_edit, SIGNAL(popFilterSyntaxStatus()), main_ui_->statusBar, SLOT(popFilterStatus()));
    connect(df_edit, SIGNAL(pushFilterSyntaxWarning(const QString&)),
            main_ui_->statusBar, SLOT(pushTemporaryStatus(const QString&)));
    connect(df_edit, SIGNAL(filterPackets(QString,bool)), this, SLOT(filterPackets(QString,bool)));
    connect(wsApp, SIGNAL(preferencesChanged()), df_edit, SLOT(checkFilter()));

    connect(df_edit, SIGNAL(textChanged(QString)), funnel_statistics_, SLOT(displayFilterTextChanged(QString)));
    connect(funnel_statistics_, SIGNAL(setDisplayFilter(QString)), df_edit, SLOT(setText(QString)));
    connect(funnel_statistics_, SIGNAL(applyDisplayFilter()), df_combo_box_, SLOT(applyDisplayFilter()));
    connect(funnel_statistics_, SIGNAL(openCaptureFile(QString,QString)),
            this, SLOT(openCaptureFile(QString,QString)));
    connect(this, SIGNAL(displayFilterSuccess(bool)), df_edit, SLOT(displayFilterSuccess(bool)));

    initMainToolbarIcons();

    // In Qt4 multiple toolbars and "pretty" are mutually exculsive on OS X. If
    // unifiedTitleAndToolBarOnMac is enabled everything ends up in the same row.
    // https://bugreports.qt-project.org/browse/QTBUG-22433
    // This property is obsolete in Qt5 so this issue may be fixed in that version.
    main_ui_->displayFilterToolBar->insertWidget(main_ui_->actionDisplayFilterExpression, df_combo_box_);

    wireless_frame_ = new WirelessFrame(this);
    main_ui_->wirelessToolBar->addWidget(wireless_frame_);
    connect(wireless_frame_, SIGNAL(pushAdapterStatus(const QString&)),
            main_ui_->statusBar, SLOT(pushTemporaryStatus(const QString&)));
    connect (wireless_frame_, SIGNAL(showWirelessPreferences(QString)),
             this, SLOT(showPreferencesDialog(QString)));

    main_ui_->goToFrame->hide();
    connect(main_ui_->goToFrame, SIGNAL(visibilityChanged(bool)),
            main_ui_->actionGoGoToPacket, SLOT(setChecked(bool)));

    // XXX For some reason the cursor is drawn funny with an input mask set
    // https://bugreports.qt-project.org/browse/QTBUG-7174

    main_ui_->searchFrame->hide();
    connect(main_ui_->searchFrame, SIGNAL(pushFilterSyntaxStatus(const QString&)),
            main_ui_->statusBar, SLOT(pushTemporaryStatus(const QString&)));
    connect(main_ui_->searchFrame, SIGNAL(visibilityChanged(bool)),
            main_ui_->actionEditFindPacket, SLOT(setChecked(bool)));

    main_ui_->addressEditorFrame->hide();
    main_ui_->columnEditorFrame->hide();
    main_ui_->preferenceEditorFrame->hide();

#ifndef HAVE_LIBPCAP
    main_ui_->menuCapture->setEnabled(false);
#endif

#if defined(Q_OS_MAC)
#if defined(QT_MACEXTRAS_LIB) && QT_VERSION < QT_VERSION_CHECK(5, 2, 1)
    QMacNativeToolBar *ntb = QtMacExtras::setNativeToolBar(main_ui_->mainToolBar);
    ntb->setIconSize(QSize(24, 24));
#endif // QT_MACEXTRAS_LIB

    main_ui_->goToLineEdit->setAttribute(Qt::WA_MacSmallSize, true);
    main_ui_->goToGo->setAttribute(Qt::WA_MacSmallSize, true);
    main_ui_->goToCancel->setAttribute(Qt::WA_MacSmallSize, true);

    main_ui_->actionEditPreferences->setMenuRole(QAction::PreferencesRole);

#endif // Q_OS_MAC

#ifdef HAVE_SOFTWARE_UPDATE
    QAction *update_sep = main_ui_->menuHelp->insertSeparator(main_ui_->actionHelpAbout);
    QAction *update_action = new QAction(tr("Check for Updates" UTF8_HORIZONTAL_ELLIPSIS), main_ui_->menuHelp);
    main_ui_->menuHelp->insertAction(update_sep, update_action);
    connect(update_action, SIGNAL(triggered()), this, SLOT(checkForUpdates()));
#endif
    master_split_.setObjectName("splitterMaster");
    extra_split_.setObjectName("splitterExtra");
    main_ui_->mainStack->addWidget(&master_split_);

    empty_pane_.setObjectName("emptyPane");

    packet_list_ = new PacketList(&master_split_);

    proto_tree_ = new ProtoTree(&master_split_);
    proto_tree_->installEventFilter(this);

    byte_view_tab_ = new ByteViewTab(&master_split_);

    packet_list_->setProtoTree(proto_tree_);
    packet_list_->setByteViewTab(byte_view_tab_);
    packet_list_->installEventFilter(this);

    main_welcome_ = main_ui_->welcomePage;

    // Packet list and proto tree must exist before these are called.
    setMenusForSelectedPacket();
    setMenusForSelectedTreeRow();

    initShowHideMainWidgets();
    initTimeDisplayFormatMenu();
    initTimePrecisionFormatMenu();
    updatePreferenceActions();
    setForCaptureInProgress(false);

    setTabOrder(df_combo_box_, packet_list_);

    connect(&capture_file_, SIGNAL(captureCapturePrepared(capture_session *)),
            this, SLOT(captureCapturePrepared(capture_session *)));
    connect(&capture_file_, SIGNAL(captureCaptureUpdateStarted(capture_session *)),
            this, SLOT(captureCaptureUpdateStarted(capture_session *)));
    connect(&capture_file_, SIGNAL(captureCaptureUpdateFinished(capture_session *)),
            this, SLOT(captureCaptureUpdateFinished(capture_session *)));
    connect(&capture_file_, SIGNAL(captureCaptureFixedStarted(capture_session *)),
            this, SLOT(captureCaptureFixedStarted(capture_session *)));
    connect(&capture_file_, SIGNAL(captureCaptureFixedContinue(capture_session *)),
            main_ui_->statusBar, SLOT(updateCaptureFixedStatistics(capture_session*)));
    connect(&capture_file_, SIGNAL(captureCaptureFixedFinished(capture_session *)),
            this, SLOT(captureCaptureFixedFinished(capture_session *)));
    connect(&capture_file_, SIGNAL(captureCaptureStopping(capture_session *)),
            this, SLOT(captureCaptureStopping(capture_session *)));
    connect(&capture_file_, SIGNAL(captureCaptureFailed(capture_session *)),
            this, SLOT(captureCaptureFailed(capture_session *)));
    connect(&capture_file_, SIGNAL(captureCaptureUpdateContinue(capture_session*)),
            main_ui_->statusBar, SLOT(updateCaptureStatistics(capture_session*)));

    connect(&capture_file_, SIGNAL(captureCaptureUpdateStarted(capture_session *)),
            wsApp, SLOT(captureStarted()));
    connect(&capture_file_, SIGNAL(captureCaptureUpdateFinished(capture_session *)),
            wsApp, SLOT(captureFinished()));
    connect(&capture_file_, SIGNAL(captureCaptureFixedStarted(capture_session *)),
            wsApp, SLOT(captureStarted()));
    connect(&capture_file_, SIGNAL(captureCaptureFixedFinished(capture_session *)),
            wsApp, SLOT(captureFinished()));

    connect(&capture_file_, SIGNAL(captureFileOpened()),
            this, SLOT(captureFileOpened()));
    connect(&capture_file_, SIGNAL(captureFileReadStarted()),
            this, SLOT(captureFileReadStarted()));
    connect(&capture_file_, SIGNAL(captureFileReadFinished()),
            this, SLOT(captureFileReadFinished()));
    connect(&capture_file_, SIGNAL(captureFileReloadStarted()),
            this, SLOT(captureFileReloadStarted()));
    connect(&capture_file_, SIGNAL(captureFileReloadFinished()),
            this, SLOT(captureFileReadFinished()));
    connect(&capture_file_, SIGNAL(captureFileRescanStarted()),
            this, SLOT(captureFileRescanStarted()));
    connect(&capture_file_, SIGNAL(captureFileRescanFinished()),
            this, SLOT(captureFileReadFinished()));
    connect(&capture_file_, SIGNAL(captureFileRetapStarted()),
            this, SLOT(captureFileRetapStarted()));
    connect(&capture_file_, SIGNAL(captureFileRetapFinished()),
            this, SLOT(captureFileRetapFinished()));
    connect(&capture_file_, SIGNAL(captureFileClosing()),
            this, SLOT(captureFileClosing()));
    connect(&capture_file_, SIGNAL(captureFileClosed()),
            this, SLOT(captureFileClosed()));

    connect(&capture_file_, SIGNAL(captureFileSaveStarted(QString)),
            this, SLOT(captureFileSaveStarted(QString)));
    connect(&capture_file_, SIGNAL(captureFileSaveFinished()),
            main_ui_->statusBar, SLOT(popFileStatus()));
    connect(&capture_file_, SIGNAL(captureFileSaveFailed()),
            main_ui_->statusBar, SLOT(popFileStatus()));
    connect(&capture_file_, SIGNAL(captureFileSaveStopped()),
            main_ui_->statusBar, SLOT(popFileStatus()));

    connect(&capture_file_, SIGNAL(captureFileReadStarted()),
            wsApp, SLOT(captureFileReadStarted()));
    connect(&capture_file_, SIGNAL(captureFileReadFinished()),
            wsApp, SLOT(updateTaps()));

    connect(wsApp, SIGNAL(recentFilesRead()),
            packet_list_, SLOT(applyRecentColumnWidths()));
    connect(wsApp, SIGNAL(columnsChanged()),
            packet_list_, SLOT(columnsChanged()));
    connect(wsApp, SIGNAL(preferencesChanged()),
            packet_list_, SLOT(elideModeChanged()));
    connect(wsApp, SIGNAL(recentFilesRead()),
            this, SLOT(applyRecentPaneGeometry()));
    connect(wsApp, SIGNAL(packetDissectionChanged()),
            this, SLOT(redissectPackets()));
    connect(wsApp, SIGNAL(appInitialized()),
            this, SLOT(filterExpressionsChanged()));
    connect(wsApp, SIGNAL(filterExpressionsChanged()),
            this, SLOT(filterExpressionsChanged()));
    connect(wsApp, SIGNAL(fieldsChanged()),
            this, SLOT(fieldsChanged()));

    connect(main_ui_->mainStack, SIGNAL(currentChanged(int)),
            this, SLOT(mainStackChanged(int)));

    connect(main_welcome_, SIGNAL(startCapture()),
            this, SLOT(startCapture()));
    connect(main_welcome_, SIGNAL(recentFileActivated(QString)),
            this, SLOT(openCaptureFile(QString)));
    connect(main_welcome_, SIGNAL(pushFilterSyntaxStatus(const QString&)),
            main_ui_->statusBar, SLOT(pushFilterStatus(const QString&)));
    connect(main_welcome_, SIGNAL(popFilterSyntaxStatus()),
            main_ui_->statusBar, SLOT(popFilterStatus()));

    connect(main_ui_->addressEditorFrame, SIGNAL(editAddressStatus(QString)),
            main_ui_->statusBar, SLOT(pushTemporaryStatus(QString)));
    connect(main_ui_->addressEditorFrame, SIGNAL(redissectPackets()),
            this, SLOT(redissectPackets()));
    connect(main_ui_->addressEditorFrame, SIGNAL(showNameResolutionPreferences(QString)),
            this, SLOT(showPreferencesDialog(QString)));
    connect(main_ui_->preferenceEditorFrame, SIGNAL(showProtocolPreferences(QString)),
            this, SLOT(showPreferencesDialog(QString)));

    connect(this, SIGNAL(setCaptureFile(capture_file*)),
            main_ui_->searchFrame, SLOT(setCaptureFile(capture_file*)));
    connect(this, SIGNAL(setCaptureFile(capture_file*)),
            main_ui_->statusBar, SLOT(setCaptureFile(capture_file*)));
    connect(this, SIGNAL(setCaptureFile(capture_file*)),
            packet_list_, SLOT(setCaptureFile(capture_file*)));
    connect(this, SIGNAL(setCaptureFile(capture_file*)),
            byte_view_tab_, SLOT(setCaptureFile(capture_file*)));

    connect(this, SIGNAL(monospaceFontChanged(QFont)),
            packet_list_, SLOT(setMonospaceFont(QFont)));
    connect(this, SIGNAL(monospaceFontChanged(QFont)),
            proto_tree_, SLOT(setMonospaceFont(QFont)));
    connect(this, SIGNAL(monospaceFontChanged(QFont)),
            byte_view_tab_, SLOT(setMonospaceFont(QFont)));

    connect(main_ui_->actionGoNextPacket, SIGNAL(triggered()),
            packet_list_, SLOT(goNextPacket()));
    connect(main_ui_->actionGoPreviousPacket, SIGNAL(triggered()),
            packet_list_, SLOT(goPreviousPacket()));
    connect(main_ui_->actionGoFirstPacket, SIGNAL(triggered()),
            packet_list_, SLOT(goFirstPacket()));
    connect(main_ui_->actionGoLastPacket, SIGNAL(triggered()),
            packet_list_, SLOT(goLastPacket()));

    connect(main_ui_->actionViewExpandSubtrees, SIGNAL(triggered()),
            proto_tree_, SLOT(expandSubtrees()));
    connect(main_ui_->actionViewExpandAll, SIGNAL(triggered()),
            proto_tree_, SLOT(expandAll()));
    connect(main_ui_->actionViewCollapseAll, SIGNAL(triggered()),
            proto_tree_, SLOT(collapseAll()));

    connect(packet_list_, SIGNAL(packetSelectionChanged()),
            this, SLOT(setMenusForSelectedPacket()));
    connect(packet_list_, SIGNAL(packetDissectionChanged()),
            this, SLOT(redissectPackets()));
    connect(packet_list_, SIGNAL(showColumnPreferences(PreferencesDialog::PreferencesPane)),
            this, SLOT(showPreferencesDialog(PreferencesDialog::PreferencesPane)));
    connect(packet_list_, SIGNAL(showProtocolPreferences(QString)),
            this, SLOT(showPreferencesDialog(QString)));
    connect(packet_list_, SIGNAL(editProtocolPreference(preference*,pref_module*)),
            main_ui_->preferenceEditorFrame, SLOT(editPreference(preference*,pref_module*)));
    connect(packet_list_, SIGNAL(editColumn(int)), this, SLOT(showColumnEditor(int)));
    connect(main_ui_->columnEditorFrame, SIGNAL(columnEdited()),
            packet_list_, SLOT(columnsChanged()));
    connect(packet_list_, SIGNAL(doubleClicked(QModelIndex)),
            this, SLOT(openPacketDialog()));
    connect(packet_list_, SIGNAL(packetListScrolled(bool)),
            main_ui_->actionGoAutoScroll, SLOT(setChecked(bool)));
    connect(packet_list_->packetListModel(), SIGNAL(pushBusyStatus(QString)),
            main_ui_->statusBar, SLOT(pushBusyStatus(QString)));
    connect(packet_list_->packetListModel(), SIGNAL(popBusyStatus()),
            main_ui_->statusBar, SLOT(popBusyStatus()));
    connect(packet_list_->packetListModel(), SIGNAL(pushProgressStatus(QString,bool,bool,gboolean*)),
            main_ui_->statusBar, SLOT(pushProgressStatus(QString,bool,bool,gboolean*)));
    connect(packet_list_->packetListModel(), SIGNAL(updateProgressStatus(int)),
            main_ui_->statusBar, SLOT(updateProgressStatus(int)));
    connect(packet_list_->packetListModel(), SIGNAL(popProgressStatus()),
            main_ui_->statusBar, SLOT(popProgressStatus()));

    connect(proto_tree_, SIGNAL(protoItemSelected(const QString&)),
            main_ui_->statusBar, SLOT(pushFieldStatus(const QString&)));
    connect(proto_tree_, SIGNAL(protoItemSelected(field_info *)),
            this, SLOT(setMenusForSelectedTreeRow(field_info *)));
    connect(proto_tree_, SIGNAL(openPacketInNewWindow(bool)),
            this, SLOT(openPacketDialog(bool)));
    connect(proto_tree_, SIGNAL(showProtocolPreferences(QString)),
            this, SLOT(showPreferencesDialog(QString)));
    connect(proto_tree_, SIGNAL(editProtocolPreference(preference*,pref_module*)),
            main_ui_->preferenceEditorFrame, SLOT(editPreference(preference*,pref_module*)));

    connect(byte_view_tab_, SIGNAL(byteFieldHovered(const QString&)),
            main_ui_->statusBar, SLOT(pushByteStatus(const QString&)));

    connect(main_ui_->statusBar, SIGNAL(showExpertInfo()),
            this, SLOT(on_actionAnalyzeExpertInfo_triggered()));

    connect(main_ui_->statusBar, SIGNAL(stopLoading()),
            &capture_file_, SLOT(stopLoading()));

    connect(main_ui_->statusBar, SIGNAL(editCaptureComment()),
            this, SLOT(on_actionStatisticsCaptureFileProperties_triggered()));

    connect(&file_set_dialog_, SIGNAL(fileSetOpenCaptureFile(QString)),
            this, SLOT(openCaptureFile(QString)));

#ifdef HAVE_LIBPCAP
    QTreeWidget *iface_tree = findChild<QTreeWidget *>("interfaceTree");
    if (iface_tree) {
        connect(iface_tree, SIGNAL(itemSelectionChanged()),
                this, SLOT(interfaceSelectionChanged()));
    }
    connect(main_ui_->welcomePage, SIGNAL(captureFilterSyntaxChanged(bool)),
            this, SLOT(captureFilterSyntaxChanged(bool)));

#if HAVE_EXTCAP
        connect(this->main_welcome_, SIGNAL(showExtcapOptions(QString&)),
                this, SLOT(showExtcapOptionsDialog(QString&)));
#endif

    connect(&capture_interfaces_dialog_, SIGNAL(getPoints(int,PointList*)),
            this->main_welcome_->getInterfaceTree(), SLOT(getPoints(int,PointList*)));
    connect(&capture_interfaces_dialog_, SIGNAL(setSelectedInterfaces()),
            this->main_welcome_->getInterfaceTree(), SLOT(setSelectedInterfaces()));
    connect(&capture_interfaces_dialog_, SIGNAL(interfaceListChanged()),
            this->main_welcome_->getInterfaceTree(), SLOT(interfaceListChanged()));
#endif

    /* Create plugin_if hooks */
    plugin_if_register_gui_cb(PLUGIN_IF_FILTER_ACTION_APPLY, plugin_if_mainwindow_apply_filter );
    plugin_if_register_gui_cb(PLUGIN_IF_FILTER_ACTION_PREPARE, plugin_if_mainwindow_apply_filter );
    plugin_if_register_gui_cb(PLUGIN_IF_PREFERENCE_SAVE, plugin_if_mainwindow_preference);
    plugin_if_register_gui_cb(PLUGIN_IF_GOTO_FRAME, plugin_if_mainwindow_gotoframe);

    main_ui_->mainStack->setCurrentWidget(main_welcome_);
}

MainWindow::~MainWindow()
{
    delete main_ui_;
}

QString MainWindow::getFilter()
{
    return df_combo_box_->itemText(df_combo_box_->count());
}

QMenu *MainWindow::createPopupMenu()
{
    QMenu *menu = new QMenu();
    menu->addAction(main_ui_->actionViewMainToolbar);
    menu->addAction(main_ui_->actionViewFilterToolbar);
    menu->addAction(main_ui_->actionViewWirelessToolbar);
    menu->addAction(main_ui_->actionViewStatusBar);
    menu->addSeparator();
    menu->addAction(main_ui_->actionViewPacketList);
    menu->addAction(main_ui_->actionViewPacketDetails);
    menu->addAction(main_ui_->actionViewPacketBytes);
    return menu;
}

void MainWindow::setPipeInputHandler(gint source, gpointer user_data, ws_process_id *child_process, pipe_input_cb_t input_cb)
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
       /*g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_input_set_handler: new");*/

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

bool MainWindow::eventFilter(QObject *obj, QEvent *event) {

    // The user typed some text. Start filling in a filter.
    // We may need to be more choosy here. We just need to catch events for the packet list,
    // proto tree, and main welcome widgets.
    if (event->type() == QEvent::KeyPress) {
        QKeyEvent *kevt = static_cast<QKeyEvent *>(event);
        if (kevt->text().length() > 0 && kevt->text()[0].isPrint()) {
            df_combo_box_->lineEdit()->insert(kevt->text());
            df_combo_box_->lineEdit()->setFocus();
            return true;
        }
    }

    return QMainWindow::eventFilter(obj, event);
}

void MainWindow::keyPressEvent(QKeyEvent *event) {

    // Explicitly focus on the display filter combo.
    if (event->modifiers() & Qt::ControlModifier && event->key() == Qt::Key_Slash) {
        df_combo_box_->setFocus(Qt::ShortcutFocusReason);
        return;
    }

    if (wsApp->focusWidget() == main_ui_->goToLineEdit) {
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

void MainWindow::closeEvent(QCloseEvent *event) {
    saveWindowGeometry();

    /* If we're in the middle of stopping a capture, don't do anything;
       the user can try deleting the window after the capture stops. */
    if (capture_stopping_) {
        event->ignore();
        return;
    }

    QString before_what(tr(" before quitting"));
    if (!testCaptureFileClose(TRUE, before_what)) {
        event->ignore();
        return;
    }

#ifdef HAVE_LIBPCAP
    capture_interfaces_dialog_.close();
#endif
    // Make sure we kill any open dumpcap processes.
    delete main_welcome_;

    // One of the many places we assume one main window.
    if(!wsApp->isInitialized()) {
        // If we're still initializing, QCoreApplication::quit() won't
        // exit properly because we are not in the event loop. This
        // means that the application won't clean up after itself. We
        // might want to call wsApp->processEvents() during startup
        // instead so that we can do a normal exit here.
        exit(0);
    }
    wsApp->quit();
}

void MainWindow::dragEnterEvent(QDragEnterEvent *event)
{
    bool accept = false;
    foreach (QUrl drag_url, event->mimeData()->urls()) {
        if (!drag_url.toLocalFile().isEmpty()) {
            accept = true;
            break;
        }
    }
    if (accept) event->acceptProposedAction();
}

void MainWindow::dropEvent(QDropEvent *event)
{
    foreach (QUrl drop_url, event->mimeData()->urls()) {
        QString local_file = drop_url.toLocalFile();
        if (!local_file.isEmpty()) {
            event->acceptProposedAction();
            openCaptureFile(local_file);
            break;
        }
    }
}

// Apply recent settings to the main window geometry.
// We haven't loaded the preferences at this point so we assume that the
// position and size preference are enabled.
void MainWindow::loadWindowGeometry()
{
    int min_sensible_dimension_ = 200;

#ifndef Q_OS_MAC
    if (recent.gui_geometry_main_maximized) {
        setWindowState(Qt::WindowMaximized);
    } else
#endif
    {
//        if (prefs.gui_geometry_save_position) {
            move(recent.gui_geometry_main_x, recent.gui_geometry_main_y);
//        }

        if (// prefs.gui_geometry_save_size &&
                recent.gui_geometry_main_width > min_sensible_dimension_ &&
                recent.gui_geometry_main_height > min_sensible_dimension_) {
            resize(recent.gui_geometry_main_width, recent.gui_geometry_main_height);
        }
    }
}

void MainWindow::saveWindowGeometry()
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
        // On OS X this is false when it shouldn't be
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

QWidget* MainWindow::getLayoutWidget(layout_pane_content_e type) {
    switch (type) {
        case layout_pane_content_none:
            return &empty_pane_;
        case layout_pane_content_plist:
            return packet_list_;
        case layout_pane_content_pdetails:
            return proto_tree_;
        case layout_pane_content_pbytes:
            return byte_view_tab_;
        default:
            g_assert_not_reached();
            return NULL;
    }
}

void MainWindow::mergeCaptureFile()
{
    QString file_name = "";
    QString display_filter = "";
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
                saveCaptureFile(capture_file_.capFile(), FALSE);
                break;

            case QMessageBox::Cancel:
            default:
                /* Don't do the merge. */
                return;
            }
        }
    }

    for (;;) {
        CaptureFileDialog merge_dlg(this, capture_file_.capFile(), display_filter);
        int file_type;
        cf_status_t  merge_status;
        char        *in_filenames[2];
        char        *tmpname;

        switch (prefs.gui_fileopen_style) {

        case FO_STYLE_LAST_OPENED:
            /* The user has specified that we should start out in the last directory
           we looked in.  If we've already opened a file, use its containing
           directory, if we could determine it, as the directory, otherwise
           use the "last opened" directory saved in the preferences file if
           there was one. */
            /* This is now the default behaviour in file_selection_new() */
            break;

        case FO_STYLE_SPECIFIED:
            /* The user has specified that we should always start out in a
           specified directory; if they've specified that directory,
           start out by showing the files in that dir. */
            if (prefs.gui_fileopen_dir[0] != '\0')
                merge_dlg.setDirectory(prefs.gui_fileopen_dir);
            break;
        }

        if (merge_dlg.merge(file_name)) {
            gchar *err_msg;

            if (dfilter_compile(display_filter.toUtf8().constData(), &rfcode, &err_msg)) {
                cf_set_rfcode(capture_file_.capFile(), rfcode);
            } else {
                /* Not valid.  Tell the user, and go back and run the file
                   selection box again once they dismiss the alert. */
                //bad_dfilter_alert_box(top_level, display_filter->str);
                QMessageBox::warning(this, tr("Invalid Display Filter"),
                                     QString(tr("The filter expression %1 isn't a valid display filter. (%2).").arg(display_filter, err_msg)),
                                     QMessageBox::Ok);
                g_free(err_msg);
                continue;
            }
        } else {
            return;
        }

        file_type = capture_file_.capFile()->cd_t;

        /* Try to merge or append the two files */
        tmpname = NULL;
        if (merge_dlg.mergeType() == 0) {
            /* chronological order */
            in_filenames[0] = g_strdup(capture_file_.capFile()->filename);
            in_filenames[1] = qstring_strdup(file_name);
            merge_status = cf_merge_files(&tmpname, 2, in_filenames, file_type, FALSE);
        } else if (merge_dlg.mergeType() <= 0) {
            /* prepend file */
            in_filenames[0] = qstring_strdup(file_name);
            in_filenames[1] = g_strdup(capture_file_.capFile()->filename);
            merge_status = cf_merge_files(&tmpname, 2, in_filenames, file_type, TRUE);
        } else {
            /* append file */
            in_filenames[0] = g_strdup(capture_file_.capFile()->filename);
            in_filenames[1] = qstring_strdup(file_name);
            merge_status = cf_merge_files(&tmpname, 2, in_filenames, file_type, TRUE);
        }

        g_free(in_filenames[0]);
        g_free(in_filenames[1]);

        if (merge_status != CF_OK) {
            if (rfcode != NULL)
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
            if (rfcode != NULL)
                dfilter_free(rfcode);
            g_free(tmpname);
            return;
        }

        /* Attach the new read filter to "cf" ("cf_open()" succeeded, so
           it closed the previous capture file, and thus destroyed any
           previous read filter attached to "cf"). */
        CaptureFile::globalCapFile()->rfcode = rfcode;

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

        /* Save the name of the containing directory specified in the path name,
           if any; we can write over cf_merged_name, which is a good thing, given that
           "get_dirname()" does write over its argument. */
        wsApp->setLastOpenDir(get_dirname(tmpname));
        g_free(tmpname);
        df_combo_box_->setEditText(display_filter);
        main_ui_->statusBar->showExpert();
        return;
    }

}

void MainWindow::importCaptureFile() {
    ImportTextDialog import_dlg;

    QString before_what(tr(" before importing a new capture"));
    if (!testCaptureFileClose(FALSE, before_what))
        return;

    import_dlg.exec();

    if (import_dlg.result() != QDialog::Accepted) {
        main_ui_->mainStack->setCurrentWidget(main_welcome_);
        return;
    }

    openCaptureFile(import_dlg.capfileName());
}

void MainWindow::saveCaptureFile(capture_file *cf, bool dont_reopen) {
    QString file_name;
    gboolean discard_comments;

    if (cf->is_tempfile) {
        /* This is a temporary capture file, so saving it means saving
           it to a permanent file.  Prompt the user for a location
           to which to save it.  Don't require that the file format
           support comments - if it's a temporary capture file, it's
           probably pcap-ng, which supports comments and, if it's
           not pcap-ng, let the user decide what they want to do
           if they've added comments. */
        saveAsCaptureFile(cf, FALSE, dont_reopen);
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
                saveAsCaptureFile(cf, TRUE, dont_reopen);
                return;

            case CANCELLED:
                /* The user said "forget it".  Just return. */
                return;

            default:
                /* Squelch warnings that discard_comments is being used
                   uninitialized. */
                g_assert_not_reached();
                return;
            }

            /* XXX - cf->filename might get freed out from under us, because
               the code path through which cf_save_records() goes currently
               closes the current file and then opens and reloads the saved file,
               so make a copy and free it later. */
            file_name = cf->filename;
            status = cf_save_records(cf, file_name.toUtf8().constData(), cf->cd_t, cf->iscompressed,
                                     discard_comments, dont_reopen);
            switch (status) {

            case CF_WRITE_OK:
                /* The save succeeded; we're done.
                   If we discarded comments, redraw the packet list to reflect
                   any packets that no longer have comments. */
                if (discard_comments)
                    packet_list_queue_draw();

                cf->unsaved_changes = false; //we just saved so we signal that we have no unsaved changes
                updateForUnsavedChanges(); // we update the title bar to remove the *
                break;

            case CF_WRITE_ERROR:
                /* The write failed.
                   XXX - OK, what do we do now?  Let them try a
                   "Save As", in case they want to try to save to a
                   different directory r file system? */
                break;

            case CF_WRITE_ABORTED:
                /* The write was aborted; just drive on. */
                break;
            }
        }
        /* Otherwise just do nothing. */
    }
}

void MainWindow::saveAsCaptureFile(capture_file *cf, bool must_support_comments, bool dont_reopen) {
    QString file_name = "";
    int file_type;
    gboolean compressed;
    cf_write_status_t status;
    gchar   *dirname;
    gboolean discard_comments = FALSE;

    if (!cf) {
        return;
    }

    for (;;) {
        CaptureFileDialog save_as_dlg(this, cf);

        switch (prefs.gui_fileopen_style) {

        case FO_STYLE_LAST_OPENED:
            /* The user has specified that we should start out in the last directory
               we looked in.  If we've already opened a file, use its containing
               directory, if we could determine it, as the directory, otherwise
               use the "last opened" directory saved in the preferences file if
               there was one. */
            /* This is now the default behaviour in file_selection_new() */
            break;

        case FO_STYLE_SPECIFIED:
            /* The user has specified that we should always start out in a
               specified directory; if they've specified that directory,
               start out by showing the files in that dir. */
            if (prefs.gui_fileopen_dir[0] != '\0')
                save_as_dlg.setDirectory(prefs.gui_fileopen_dir);
            break;
        }

        /* If the file has comments, does the format the user selected
           support them?  If not, ask the user whether they want to
           discard the comments or choose a different format. */
        switch(save_as_dlg.saveAs(file_name, must_support_comments)) {

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
            return;
        }
        file_type = save_as_dlg.selectedFileType();
        compressed = save_as_dlg.isCompressed();

        fileAddExtension(file_name, file_type, compressed);

//#ifndef _WIN32
//        /* If the file exists and it's user-immutable or not writable,
//                       ask the user whether they want to override that. */
//        if (!file_target_unwritable_ui(top_level, file_name.toUtf8().constData())) {
//            /* They don't.  Let them try another file name or cancel. */
//            continue;
//        }
//#endif

        /* Attempt to save the file */
        status = cf_save_records(cf, file_name.toUtf8().constData(), file_type, compressed,
                                 discard_comments, dont_reopen);
        switch (status) {

        case CF_WRITE_OK:
            /* The save succeeded; we're done. */
            /* Save the directory name for future file dialogs. */
            dirname = get_dirname(qstring_strdup(file_name));  /* Overwrites cf_name */
            set_last_open_dir(dirname);
            g_free(dirname);
            /* If we discarded comments, redraw the packet list to reflect
               any packets that no longer have comments. */
            if (discard_comments)
                packet_list_queue_draw();

            cf->unsaved_changes = false; //we just saved so we signal that we have no unsaved changes
            updateForUnsavedChanges(); // we update the title bar to remove the *
            return;

        case CF_WRITE_ERROR:
            /* The save failed; let the user try again. */
            continue;

        case CF_WRITE_ABORTED:
            /* The user aborted the save; just return. */
            return;
        }
    }
    return;
}

void MainWindow::exportSelectedPackets() {
    QString file_name = "";
    int file_type;
    gboolean compressed;
    packet_range_t range;
    cf_write_status_t status;
    gchar   *dirname;
    gboolean discard_comments = FALSE;

    if (!capture_file_.capFile())
        return;

    /* Init the packet range */
    packet_range_init(&range, capture_file_.capFile());
    range.process_filtered = TRUE;
    range.include_dependents = TRUE;

    for (;;) {
        CaptureFileDialog esp_dlg(this, capture_file_.capFile());

        switch (prefs.gui_fileopen_style) {

        case FO_STYLE_LAST_OPENED:
            /* The user has specified that we should start out in the last directory
               we looked in.  If we've already opened a file, use its containing
               directory, if we could determine it, as the directory, otherwise
               use the "last opened" directory saved in the preferences file if
               there was one. */
            /* This is now the default behaviour in file_selection_new() */
            break;

        case FO_STYLE_SPECIFIED:
            /* The user has specified that we should always start out in a
               specified directory; if they've specified that directory,
               start out by showing the files in that dir. */
            if (prefs.gui_fileopen_dir[0] != '\0')
                esp_dlg.setDirectory(prefs.gui_fileopen_dir);
            break;
        }

        /* If the file has comments, does the format the user selected
           support them?  If not, ask the user whether they want to
           discard the comments or choose a different format. */
        switch(esp_dlg.exportSelectedPackets(file_name, &range)) {

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
            return;
        }

        /*
         * Check that we're not going to save on top of the current
         * capture file.
         * We do it here so we catch all cases ...
         * Unfortunately, the file requester gives us an absolute file
         * name and the read file name may be relative (if supplied on
         * the command line). From Joerg Mayer.
         */
        if (files_identical(capture_file_.capFile()->filename, file_name.toUtf8().constData())) {
            QMessageBox msg_box;
            gchar *display_basename = g_filename_display_basename(file_name.toUtf8().constData());

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
        compressed = esp_dlg.isCompressed();
        fileAddExtension(file_name, file_type, compressed);

//#ifndef _WIN32
//        /* If the file exists and it's user-immutable or not writable,
//                       ask the user whether they want to override that. */
//        if (!file_target_unwritable_ui(top_level, file_name.toUtf8().constData())) {
//            /* They don't.  Let them try another file name or cancel. */
//            continue;
//        }
//#endif

        /* Attempt to save the file */
        status = cf_export_specified_packets(capture_file_.capFile(), file_name.toUtf8().constData(), &range, file_type, compressed);
        switch (status) {

        case CF_WRITE_OK:
            /* The save succeeded; we're done. */
            /* Save the directory name for future file dialogs. */
            dirname = get_dirname(qstring_strdup(file_name));  /* Overwrites cf_name */
            set_last_open_dir(dirname);
            g_free(dirname);
            /* If we discarded comments, redraw the packet list to reflect
               any packets that no longer have comments. */
            if (discard_comments)
                packet_list_queue_draw();
            return;

        case CF_WRITE_ERROR:
            /* The save failed; let the user try again. */
            continue;

        case CF_WRITE_ABORTED:
            /* The user aborted the save; just return. */
            return;
        }
    }
    return;
}

void MainWindow::exportDissections(export_type_e export_type) {
    ExportDissectionDialog ed_dlg(this, capture_file_.capFile(), export_type);
    packet_range_t range;

    if (!capture_file_.capFile())
        return;

    /* Init the packet range */
    packet_range_init(&range, capture_file_.capFile());
    range.process_filtered = TRUE;
    range.include_dependents = TRUE;

    ed_dlg.exec();
}

void MainWindow::fileAddExtension(QString &file_name, int file_type, bool compressed) {
    QString file_name_lower;
    QString file_suffix;
    GSList  *extensions_list;
    gboolean add_extension;

    /*
     * Append the default file extension if there's none given by
     * the user or if they gave one that's not one of the valid
     * extensions for the file type.
     */
    file_name_lower = file_name.toLower();
    extensions_list = wtap_get_file_extensions_list(file_type, FALSE);
    if (extensions_list != NULL) {
        GSList *extension;

        /* We have one or more extensions for this file type.
           Start out assuming we need to add the default one. */
        add_extension = TRUE;

        /* OK, see if the file has one of those extensions. */
        for (extension = extensions_list; extension != NULL;
             extension = g_slist_next(extension)) {
            file_suffix += tr(".") + (char *)extension->data;
            if (file_name_lower.endsWith(file_suffix)) {
                /*
                 * The file name has one of the extensions for
                 * this file type.
                 */
                add_extension = FALSE;
                break;
            }
            file_suffix += ".gz";
            if (file_name_lower.endsWith(file_suffix)) {
                /*
                 * The file name has one of the extensions for
                 * this file type.
                 */
                add_extension = FALSE;
                break;
            }
        }
    } else {
        /* We have no extensions for this file type.  Don't add one. */
        add_extension = FALSE;
    }
    if (add_extension) {
        if (wtap_default_file_extension(file_type) != NULL) {
            file_name += tr(".") + wtap_default_file_extension(file_type);
            if (compressed) {
                file_name += ".gz";
            }
        }
    }
}

bool MainWindow::testCaptureFileClose(bool from_quit, QString before_what) {
    bool capture_in_progress = FALSE;

    if (!capture_file_.capFile() || capture_file_.capFile()->state == FILE_CLOSED)
        return true; /* Already closed, nothing to do */

#ifdef HAVE_LIBPCAP
    if (capture_file_.capFile()->state == FILE_READ_IN_PROGRESS && capture_file_.capFile()->count>0) {
        /* This is true if we're reading a capture file *or* if we're doing
         a live capture.  If we're reading a capture file, the main loop
         is busy reading packets, and only accepting input from the
         progress dialog, so we can't get here, so this means we're
         doing a capture. */
        capture_in_progress = TRUE;
    }
#endif

    if (prefs.gui_ask_unsaved) {
        if (cf_has_unsaved_data(capture_file_.capFile()) || capture_in_progress) {
            QMessageBox msg_dialog;
            QString question;
            QPushButton *saveButton;
            QPushButton *discardButton;

            msg_dialog.setIcon(QMessageBox::Question);
            msg_dialog.setWindowTitle("Unsaved packets" UTF8_HORIZONTAL_ELLIPSIS);
            /* This file has unsaved data or there's a capture in
               progress; ask the user whether to save the data. */
            if (capture_file_.capFile()->is_tempfile) {

                msg_dialog.setText(tr("You have unsaved packets"));
                msg_dialog.setInformativeText(tr("They will be lost if you don't save them."));

                if (capture_in_progress) {
                    question.append(tr("Do you want to stop the capture and save the captured packets"));
                } else {
                    question.append(tr("Do you want to save the captured packets"));
                }
                question.append(before_what).append(tr("?"));
                msg_dialog.setInformativeText(question);


            } else {
                /*
                 * Format the message.
                 */
                if (capture_in_progress) {
                    question.append(tr("Do you want to stop the capture and save the captured packets"));
                    question.append(before_what).append(tr("?"));
                    msg_dialog.setText(question);
                    msg_dialog.setInformativeText(tr("Your captured packets will be lost if you don't save them."));
                } else {
                    gchar *display_basename = g_filename_display_basename(capture_file_.capFile()->filename);
                    question.append(QString(tr("Do you want to save the changes you've made to the capture file \"%1\"%2?"))
                                    .arg(display_basename)
                                    .arg(before_what)
                                    );
                    g_free(display_basename);
                    msg_dialog.setText(question);
                    msg_dialog.setInformativeText(tr("Your changes will be lost if you don't save them."));
                }
            }

            // XXX Text comes from ui/gtk/stock_icons.[ch]
            // Note that the button roles differ from the GTK+ version.
            // Cancel = RejectRole
            // Save = AcceptRole
            // Don't Save = DestructiveRole
            msg_dialog.addButton(QMessageBox::Cancel);

            if (capture_in_progress) {
                saveButton = msg_dialog.addButton(tr("Stop and Save"), QMessageBox::AcceptRole);
            } else {
                saveButton = msg_dialog.addButton(QMessageBox::Save);
            }
            msg_dialog.setDefaultButton(saveButton);

            if (from_quit) {
                if (capture_file_.capFile()->state == FILE_READ_IN_PROGRESS) {
                    discardButton = msg_dialog.addButton(tr("Stop and Quit without Saving"),
                                                         QMessageBox::DestructiveRole);
                } else {
                    discardButton = msg_dialog.addButton(tr("Quit without Saving"),
                                                         QMessageBox::DestructiveRole);
                }
            } else {
                if (capture_in_progress) {
                    discardButton = msg_dialog.addButton(tr("Stop and Continue without Saving"),
                                                         QMessageBox::DestructiveRole);
                } else {
                    discardButton = msg_dialog.addButton(tr("Continue &without Saving"), QMessageBox::DestructiveRole);
                }
            }

            msg_dialog.exec();
            /* According to the Qt doc:
             * when using QMessageBox with custom buttons, exec() function returns an opaque value.
             *
             * Therefore we should use clickedButton() to determine which button was clicked. */

            if(msg_dialog.clickedButton() == saveButton)
            {
#ifdef HAVE_LIBPCAP
                /* If there's a capture in progress, we have to stop the capture
             and then do the save. */
                if (capture_in_progress)
                    captureStop();
#endif
                /* Save the file and close it */
                saveCaptureFile(capture_file_.capFile(), TRUE);
            }
            else if(msg_dialog.clickedButton() == discardButton)
            {
#ifdef HAVE_LIBPCAP
                /*
                 * If there's a capture in progress; we have to stop the capture
                 * and then do the close.
                 */
                if (capture_in_progress)
                    captureStop();
#endif
                /* Just close the file, discarding changes */
                cf_close(capture_file_.capFile());
                return true;
            }
            else    //cancelButton or some other unspecified button
            {
                return false;
            }

        } else {
            /* Unchanged file, just close it */
            capture_file_.capFile()->state = FILE_READ_ABORTED;
            cf_close(capture_file_.capFile());
        }
    } else {
        /* User asked not to be bothered by those prompts, just close it.
         XXX - should that apply only to saving temporary files? */
#ifdef HAVE_LIBPCAP
        /* If there's a capture in progress, we have to stop the capture
           and then do the close. */
        if (capture_in_progress)
            captureStop();
#endif
        cf_close(capture_file_.capFile());
    }

    return true; /* File closed */
}

void MainWindow::captureStop() {
    stopCapture();

    while(capture_file_.capFile() && capture_file_.capFile()->state == FILE_READ_IN_PROGRESS) {
        WiresharkApplication::processEvents();
    }
}

void MainWindow::initMainToolbarIcons()
{
#if defined(Q_OS_WIN)
    // Current GTK+ and other Windows app behavior.
    main_ui_->mainToolBar->setIconSize(QSize(16, 16));
#else
    // Force icons to 24x24 for now, otherwise actionFileOpen looks wonky.
    main_ui_->mainToolBar->setIconSize(QSize(24, 24));
#endif

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
    main_ui_->actionGoAutoScroll->setIcon(StockIcon("x-stay-last"));

    main_ui_->actionViewColorizePacketList->setIcon(StockIcon("x-colorize-packets"));
    main_ui_->actionViewColorizePacketList->setChecked(recent.packet_list_colorize);
//    main_ui_->actionViewAutoScroll->setIcon(StockIcon("x-stay-last"));

    QList<QKeySequence> zi_seq = main_ui_->actionViewZoomIn->shortcuts();
    zi_seq << QKeySequence(Qt::CTRL + Qt::Key_Equal);
    main_ui_->actionViewZoomIn->setIcon(StockIcon("zoom-in"));
    main_ui_->actionViewZoomIn->setShortcuts(zi_seq);
    main_ui_->actionViewZoomOut->setIcon(StockIcon("zoom-out"));
    main_ui_->actionViewNormalSize->setIcon(StockIcon("zoom-original"));
    main_ui_->actionViewResizeColumns->setIcon(StockIcon("x-resize-columns"));
}

void MainWindow::initShowHideMainWidgets()
{
    if (show_hide_actions_) {
        return;
    }

    show_hide_actions_ = new QActionGroup(this);
    QMap<QAction *, QWidget *> shmw_actions;

    show_hide_actions_->setExclusive(false);
    shmw_actions[main_ui_->actionViewMainToolbar] = main_ui_->mainToolBar;
    shmw_actions[main_ui_->actionViewFilterToolbar] = main_ui_->displayFilterToolBar;
    shmw_actions[main_ui_->actionViewWirelessToolbar] = main_ui_->wirelessToolBar;
    shmw_actions[main_ui_->actionViewStatusBar] = main_ui_->statusBar;
    shmw_actions[main_ui_->actionViewPacketList] = packet_list_;
    shmw_actions[main_ui_->actionViewPacketDetails] = proto_tree_;
    shmw_actions[main_ui_->actionViewPacketBytes] = byte_view_tab_;

    main_ui_->actionViewMainToolbar->setChecked(recent.main_toolbar_show);
    main_ui_->actionViewFilterToolbar->setChecked(recent.filter_toolbar_show);
    main_ui_->actionViewWirelessToolbar->setChecked(recent.wireless_toolbar_show);
    main_ui_->actionViewStatusBar->setChecked(recent.statusbar_show);
    main_ui_->actionViewPacketList->setChecked(recent.packet_list_show);
    main_ui_->actionViewPacketDetails->setChecked(recent.tree_view_show);
    main_ui_->actionViewPacketBytes->setChecked(recent.byte_view_show);

    foreach (QAction *shmwa, shmw_actions.keys()) {
        shmwa->setData(qVariantFromValue(shmw_actions[shmwa]));
        show_hide_actions_->addAction(shmwa);
        showHideMainWidgets(shmwa);
    }

    connect(show_hide_actions_, SIGNAL(triggered(QAction*)), this, SLOT(showHideMainWidgets(QAction*)));
}

Q_DECLARE_METATYPE(ts_type)

void MainWindow::initTimeDisplayFormatMenu()
{
    if (time_display_actions_) {
        return;
    }

    time_display_actions_ = new QActionGroup(this);
    QMap<QAction *, ts_type> td_actions;

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

    foreach (QAction* tda, td_actions.keys()) {
        tda->setData(qVariantFromValue(td_actions[tda]));
        time_display_actions_->addAction(tda);
        if (recent.gui_time_format == td_actions[tda]) {
            tda->setChecked(true);
        }
    }

    connect(time_display_actions_, SIGNAL(triggered(QAction*)), this, SLOT(setTimestampFormat(QAction*)));

    main_ui_->actionViewTimeDisplaySecondsWithHoursAndMinutes->setChecked(recent.gui_seconds_format == TS_SECONDS_HOUR_MIN_SEC);
}

Q_DECLARE_METATYPE(ts_precision)

void MainWindow::initTimePrecisionFormatMenu()
{
    if (time_precision_actions_) {
        return;
    }

    time_precision_actions_ = new QActionGroup(this);
    QMap<QAction *, ts_precision> tp_actions;
    tp_actions[main_ui_->actionViewTimeDisplayFormatPrecisionAutomatic] = TS_PREC_AUTO;
    tp_actions[main_ui_->actionViewTimeDisplayFormatPrecisionSeconds] = TS_PREC_FIXED_SEC;
    tp_actions[main_ui_->actionViewTimeDisplayFormatPrecisionDeciseconds] = TS_PREC_FIXED_DSEC;
    tp_actions[main_ui_->actionViewTimeDisplayFormatPrecisionCentiseconds] = TS_PREC_FIXED_CSEC;
    tp_actions[main_ui_->actionViewTimeDisplayFormatPrecisionMilliseconds] = TS_PREC_FIXED_MSEC;
    tp_actions[main_ui_->actionViewTimeDisplayFormatPrecisionMicroseconds] = TS_PREC_FIXED_USEC;
    tp_actions[main_ui_->actionViewTimeDisplayFormatPrecisionNanoseconds] = TS_PREC_FIXED_NSEC;

    foreach (QAction* tpa, tp_actions.keys()) {
        tpa->setData(qVariantFromValue(tp_actions[tpa]));
        time_precision_actions_->addAction(tpa);
        if (recent.gui_time_precision == tp_actions[tpa]) {
            tpa->setChecked(true);
        }
    }

    connect(time_precision_actions_, SIGNAL(triggered(QAction*)), this, SLOT(setTimestampPrecision(QAction*)));
}

// Titlebar
void MainWindow::setTitlebarForCaptureFile()
{
    if (capture_file_.capFile() && capture_file_.capFile()->filename) {
        //
        // Qt *REALLY* doesn't like windows that sometimes have a
        // title set with setWindowTitle() and other times have a
        // file path set; apparently, once you've set the title
        // with setWindowTitle(), it sticks, and setWindowFilePath()
        // has no effect.  It appears to can clear the title with
        // setWindowTitle(NULL), but that clears the actual title in
        // the title bar, and setWindowFilePath() then, I guess, sees
        // that there's already a file path, and does nothing, leaving
        // the title bar empty.  So you then have to clear the file path
        // with setWindowFilePath(NULL), and then set it.
        //
        // Maybe there's a #include "you're holding it wrong" here.
        // However, I really don't want to hear from people who think
        // that a window can never be associated with something other
        // than a user file at time T1 and with a user file at time T2,
        // given that, in Wireshark, a window can be associated with a
        // live capture at time T1 and then, after you've saved the live
        // capture to a user file, associated with a user file at time T2.
        //
        if (capture_file_.capFile()->is_tempfile) {
            //
            // For a temporary file, put the source of the data
            // in the window title, not whatever random pile
            // of characters is the last component of the path
            // name.
            //
            // XXX - on non-Mac platforms, put in the application
            // name?
            //
            // XXX - Use setWindowModified
            gchar *window_name;
            setWindowFilePath(NULL);
            window_name = g_strdup_printf("[*]%s", cf_get_tempfile_source(capture_file_.capFile())); //TODO : Fix Translate
            setWindowTitle(window_name);
            g_free(window_name);
        } else {
            //
            // For a user file, set the full path; that way,
            // for OS X, it'll set the "proxy icon".  Qt
            // handles extracting the last component.
            //
            // Sadly, some UN*Xes don't necessarily use UTF-8
            // for their file names, so we have to map the
            // file path to UTF-8.  If that fails, we're somewhat
            // stuck.
            //
            char *utf8_filename = g_filename_to_utf8(capture_file_.capFile()->filename,
                                                     -1,
                                                     NULL,
                                                     NULL,
                                                     NULL);
            if (utf8_filename == NULL) {
            	// So what the heck else can we do here?
                setWindowTitle(tr("(File name can't be mapped to UTF-8)"));
            } else {
                setWindowTitle(NULL);
                setWindowFilePath(NULL);
                setWindowFilePath(utf8_filename);
                g_free(utf8_filename);
            }
        }
        setWindowModified(cf_has_unsaved_data(capture_file_.capFile()));
    } else {
        /* We have no capture file. */
        setWindowFilePath(NULL);
        setWindowTitle(tr("The Wireshark Network Analyzer"));
    }
}

void MainWindow::setTitlebarForSelectedTreeRow()
{
    setWindowTitle(tr("The Wireshark Network Analyzer"));
}


void MainWindow::setTitlebarForCaptureInProgress()
{
    gchar *window_name;

    setWindowFilePath(NULL);
    if (capture_file_.capFile()) {
        window_name = g_strdup_printf("Capturing from %s", cf_get_tempfile_source(capture_file_.capFile())); //TODO : Fix Translate
        setWindowTitle(window_name);
        g_free(window_name);
    } else {
        /* We have no capture in progress. */
        setWindowTitle(tr("The Wireshark Network Analyzer"));
    }
}

// Menu state

/* Enable or disable menu items based on whether you have a capture file
   you've finished reading and, if you have one, whether it's been saved
   and whether it could be saved except by copying the raw packet data. */
void MainWindow::setMenusForCaptureFile(bool force_disable)
{
    if (force_disable || capture_file_.capFile() == NULL || capture_file_.capFile()->state == FILE_READ_IN_PROGRESS) {
        /* We have no capture file or we're currently reading a file */
        main_ui_->actionFileMerge->setEnabled(false);
        main_ui_->actionFileClose->setEnabled(false);
        main_ui_->actionFileSave->setEnabled(false);
        main_ui_->actionFileSaveAs->setEnabled(false);
        main_ui_->actionStatisticsCaptureFileProperties->setEnabled(false);
        main_ui_->actionFileExportPackets->setEnabled(false);
        main_ui_->menuFileExportPacketDissections->setEnabled(false);
        main_ui_->actionFileExportPacketBytes->setEnabled(false);
        main_ui_->actionFileExportPDU->setEnabled(false);
        main_ui_->actionFileExportSSLSessionKeys->setEnabled(false);
        main_ui_->menuFileExportObjects->setEnabled(false);
        main_ui_->actionViewReload->setEnabled(false);
    } else {
        main_ui_->actionFileMerge->setEnabled(cf_can_write_with_wiretap(capture_file_.capFile()));

        main_ui_->actionFileClose->setEnabled(true);
        main_ui_->actionFileSave->setEnabled(cf_can_save(capture_file_.capFile()));
        main_ui_->actionFileSaveAs->setEnabled(cf_can_save_as(capture_file_.capFile()));
        main_ui_->actionStatisticsCaptureFileProperties->setEnabled(true);
        /*
         * "Export Specified Packets..." should be available only if
         * we can write the file out in at least one format.
         */
        main_ui_->actionFileExportPackets->setEnabled(cf_can_write_with_wiretap(capture_file_.capFile()));
        main_ui_->menuFileExportPacketDissections->setEnabled(true);
        main_ui_->actionFileExportPacketBytes->setEnabled(true);
        main_ui_->actionFileExportPDU->setEnabled(true);
        main_ui_->actionFileExportSSLSessionKeys->setEnabled(true);
        main_ui_->menuFileExportObjects->setEnabled(true);
        main_ui_->actionViewReload->setEnabled(true);
    }
}

void MainWindow::setMenusForCaptureInProgress(bool capture_in_progress) {
    /* Either a capture was started or stopped; in either case, it's not
       in the process of stopping, so allow quitting. */

    main_ui_->actionFileOpen->setEnabled(!capture_in_progress);
    main_ui_->menuOpenRecentCaptureFile->setEnabled(!capture_in_progress);
    main_ui_->menuFileExportPacketDissections->setEnabled(capture_in_progress);
    main_ui_->actionFileExportPacketBytes->setEnabled(capture_in_progress);
    main_ui_->actionFileExportPDU->setEnabled(capture_in_progress);
    main_ui_->actionFileExportSSLSessionKeys->setEnabled(capture_in_progress);
    main_ui_->menuFileExportObjects->setEnabled(capture_in_progress);
    main_ui_->menuFileSet->setEnabled(!capture_in_progress);
    main_ui_->actionFileQuit->setEnabled(true);

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

void MainWindow::setMenusForCaptureStopping() {
    main_ui_->actionFileQuit->setEnabled(false);
    main_ui_->actionStatisticsCaptureFileProperties->setEnabled(false);
#ifdef HAVE_LIBPCAP
    main_ui_->actionCaptureStart->setChecked(false);
    main_ui_->actionCaptureStop->setEnabled(false);
    main_ui_->actionCaptureRestart->setEnabled(false);
#endif /* HAVE_LIBPCAP */
}

void MainWindow::setForCapturedPackets(bool have_captured_packets)
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

    main_ui_->actionViewZoomIn->setEnabled(have_captured_packets);
    main_ui_->actionViewZoomOut->setEnabled(have_captured_packets);
    main_ui_->actionViewNormalSize->setEnabled(have_captured_packets);
    main_ui_->actionViewResizeColumns->setEnabled(have_captured_packets);

//    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/GoMenu/PreviousPacketInConversation",
//                         have_captured_packets);
//    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/GoMenu/NextPacketInConversation",
//                         have_captured_packets);
    main_ui_->actionStatisticsCaptureFileProperties->setEnabled(have_captured_packets);
    main_ui_->actionStatisticsProtocolHierarchy->setEnabled(have_captured_packets);
    main_ui_->actionStatisticsIOGraph->setEnabled(have_captured_packets);
}

void MainWindow::setMenusForFileSet(bool enable_list_files) {
    bool enable_next = fileset_get_next() != NULL && enable_list_files;
    bool enable_prev = fileset_get_previous() != NULL && enable_list_files;

    main_ui_->actionFileSetListFiles->setEnabled(enable_list_files);
    main_ui_->actionFileSetNextFile->setEnabled(enable_next);
    main_ui_->actionFileSetPreviousFile->setEnabled(enable_prev);
}

void MainWindow::updateForUnsavedChanges() {
    setTitlebarForCaptureFile();
    setMenusForCaptureFile();
}

void MainWindow::changeEvent(QEvent* event)
{
    if (0 != event)
    {
        switch (event->type())
        {
        case QEvent::LanguageChange:
            main_ui_->retranslateUi(this);
            break;
        case QEvent::LocaleChange:{
            QString locale = QLocale::system().name();
            locale.truncate(locale.lastIndexOf('_'));
            wsApp->loadLanguage(locale);
            }
            break;
        default:
            break;
        }
    }
    QMainWindow::changeEvent(event);
}

/* Update main window items based on whether there's a capture in progress. */
void MainWindow::setForCaptureInProgress(gboolean capture_in_progress)
{
    setMenusForCaptureInProgress(capture_in_progress);

    wireless_frame_->setCaptureInProgress(capture_in_progress);

#ifdef HAVE_LIBPCAP
    packet_list_->setCaptureInProgress(capture_in_progress);
//    set_toolbar_for_capture_in_progress(capture_in_progress);

//    set_capture_if_dialog_for_capture_in_progress(capture_in_progress);
#endif
}

static QList<register_stat_group_t> menu_groups = QList<register_stat_group_t>()
            << REGISTER_ANALYZE_GROUP_UNSORTED
            << REGISTER_ANALYZE_GROUP_CONVERSATION_FILTER
            << REGISTER_STAT_GROUP_UNSORTED
            << REGISTER_STAT_GROUP_GENERIC
            << REGISTER_STAT_GROUP_CONVERSATION_LIST
            << REGISTER_STAT_GROUP_ENDPOINT_LIST
            << REGISTER_STAT_GROUP_RESPONSE_TIME
            << REGISTER_STAT_GROUP_TELEPHONY
            << REGISTER_STAT_GROUP_TELEPHONY_ANSI
            << REGISTER_STAT_GROUP_TELEPHONY_GSM
            << REGISTER_STAT_GROUP_TELEPHONY_LTE
            << REGISTER_STAT_GROUP_TELEPHONY_MTP3
            << REGISTER_STAT_GROUP_TELEPHONY_SCTP
            << REGISTER_TOOLS_GROUP_UNSORTED;

void MainWindow::addMenuActions(QList<QAction *> &actions, int menu_group)
{
    foreach (QAction *action, actions) {
        switch (menu_group) {
        case REGISTER_ANALYZE_GROUP_UNSORTED:
        case REGISTER_STAT_GROUP_UNSORTED:
            main_ui_->menuStatistics->insertAction(
                            main_ui_->actionStatistics_REGISTER_STAT_GROUP_UNSORTED,
                            action);
            break;
        case REGISTER_STAT_GROUP_RESPONSE_TIME:
            main_ui_->menuServiceResponseTime->addAction(action);
            break;
        case REGISTER_STAT_GROUP_TELEPHONY:
            main_ui_->menuTelephony->addAction(action);
            break;
        case REGISTER_STAT_GROUP_TELEPHONY_ANSI:
            main_ui_->menuANSI->addAction(action);
            break;
        case REGISTER_STAT_GROUP_TELEPHONY_GSM:
            main_ui_->menuGSM->addAction(action);
            break;
        case REGISTER_STAT_GROUP_TELEPHONY_LTE:
            main_ui_->menuLTE->addAction(action);
            break;
        case REGISTER_STAT_GROUP_TELEPHONY_MTP3:
            main_ui_->menuMTP3->addAction(action);
            break;
        case REGISTER_TOOLS_GROUP_UNSORTED:
        {
            // Allow the creation of submenus. Mimics the behavor of
            // ui/gtk/main_menubar.c:add_menu_item_to_main_menubar
            // and GtkUIManager.
            //
            // For now we limit the insanity to the "Tools" menu.
            QStringList menu_path = action->text().split('/');
            QMenu *cur_menu = main_ui_->menuTools;
            while (menu_path.length() > 1) {
                QString menu_title = menu_path.takeFirst();
#if (QT_VERSION > QT_VERSION_CHECK(5, 0, 0))
                QMenu *submenu = cur_menu->findChild<QMenu *>(menu_title.toLower(), Qt::FindDirectChildrenOnly);
#else
                QMenu *submenu = cur_menu->findChild<QMenu *>(menu_title.toLower());
                if (submenu && submenu->parent() != cur_menu) submenu = NULL;
#endif
                if (!submenu) {
                    submenu = cur_menu->addMenu(menu_title);
                    submenu->setObjectName(menu_title.toLower());
                }
                cur_menu = submenu;
            }
            action->setText(menu_path.last());
            cur_menu->addAction(action);
            break;
        }
        default:
//            qDebug() << "FIX: Add" << action->text() << "to the menu";
            break;
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
void MainWindow::removeMenuActions(QList<QAction *> &actions, int menu_group)
{
    foreach (QAction *action, actions) {
        switch (menu_group) {
        case REGISTER_ANALYZE_GROUP_UNSORTED:
        case REGISTER_STAT_GROUP_UNSORTED:
            main_ui_->menuStatistics->removeAction(action);
            break;
        case REGISTER_STAT_GROUP_RESPONSE_TIME:
            main_ui_->menuServiceResponseTime->removeAction(action);
            break;
        case REGISTER_STAT_GROUP_TELEPHONY:
            main_ui_->menuTelephony->removeAction(action);
            break;
        case REGISTER_STAT_GROUP_TELEPHONY_ANSI:
            main_ui_->menuANSI->removeAction(action);
            break;
        case REGISTER_STAT_GROUP_TELEPHONY_GSM:
            main_ui_->menuGSM->removeAction(action);
            break;
        case REGISTER_STAT_GROUP_TELEPHONY_LTE:
            main_ui_->menuLTE->removeAction(action);
            break;
        case REGISTER_STAT_GROUP_TELEPHONY_MTP3:
            main_ui_->menuMTP3->removeAction(action);
            break;
        case REGISTER_TOOLS_GROUP_UNSORTED:
        {
            // Allow removal of submenus.
            // For now we limit the insanity to the "Tools" menu.
            QStringList menu_path = action->text().split('/');
            QMenu *cur_menu = main_ui_->menuTools;
            while (menu_path.length() > 1) {
                QString menu_title = menu_path.takeFirst();
#if (QT_VERSION > QT_VERSION_CHECK(5, 0, 0))
                QMenu *submenu = cur_menu->findChild<QMenu *>(menu_title.toLower(), Qt::FindDirectChildrenOnly);
#else
                QMenu *submenu = cur_menu->findChild<QMenu *>(menu_title.toLower());
                if (submenu && submenu->parent() != cur_menu) submenu = NULL;
#endif
                cur_menu = submenu;
            }
            cur_menu->removeAction(action);
            break;
        }
        default:
//            qDebug() << "FIX: Remove" << action->text() << "from the menu";
            break;
        }
    }
}

void MainWindow::addDynamicMenus()
{
    // Manual additions
    wsApp->addDynamicMenuGroupItem(REGISTER_STAT_GROUP_TELEPHONY_GSM, main_ui_->actionTelephonyGsmMapSummary);
    wsApp->addDynamicMenuGroupItem(REGISTER_STAT_GROUP_TELEPHONY_LTE, main_ui_->actionTelephonyLteMacStatistics);
    wsApp->addDynamicMenuGroupItem(REGISTER_STAT_GROUP_TELEPHONY_LTE, main_ui_->actionTelephonyLteRlcStatistics);
    wsApp->addDynamicMenuGroupItem(REGISTER_STAT_GROUP_TELEPHONY_MTP3, main_ui_->actionTelephonyMtp3Summary);

    // Fill in each menu
    foreach (register_stat_group_t menu_group, menu_groups) {
        QList<QAction *>actions = wsApp->dynamicMenuGroupItems(menu_group);
        addMenuActions(actions, menu_group);
    }

    // Empty menus don't show up: https://bugreports.qt.io/browse/QTBUG-33728
    // We've added a placeholder in order to make sure the "Tools" menu is
    // visible. Hide it as needed.
    if (wsApp->dynamicMenuGroupItems(REGISTER_TOOLS_GROUP_UNSORTED).length() > 0) {
        main_ui_->actionToolsPlaceholder->setVisible(false);
    }
    if (wsApp->dynamicMenuGroupItems(REGISTER_STAT_GROUP_TELEPHONY_ANSI).length() > 0) {
        main_ui_->actionTelephonyANSIPlaceholder->setVisible(false);
    }
    if (wsApp->dynamicMenuGroupItems(REGISTER_STAT_GROUP_TELEPHONY_GSM).length() > 0) {
        main_ui_->actionTelephonyGSMPlaceholder->setVisible(false);
    }
    if (wsApp->dynamicMenuGroupItems(REGISTER_STAT_GROUP_TELEPHONY_LTE).length() > 0) {
        main_ui_->actionTelephonyLTEPlaceholder->setVisible(false);
    }
    if (wsApp->dynamicMenuGroupItems(REGISTER_STAT_GROUP_TELEPHONY_MTP3).length() > 0) {
        main_ui_->actionTelephonyMTP3Placeholder->setVisible(false);
    }
}

void MainWindow::reloadDynamicMenus()
{
    foreach (register_stat_group_t menu_group, menu_groups) {
        QList<QAction *>actions = wsApp->removedMenuGroupItems(menu_group);
        removeMenuActions(actions, menu_group);

        actions = wsApp->addedMenuGroupItems(menu_group);
        addMenuActions(actions, menu_group);
    }

    wsApp->clearAddedMenuGroupItems();
    wsApp->clearRemovedMenuGroupItems();
}

void MainWindow::externalMenuHelper(ext_menu_t * menu, QMenu  * subMenu, gint depth)
{
    QAction * itemAction = NULL;
    ext_menubar_t * item = NULL;
    GList * children = NULL;

    /* There must exists an xpath parent */
    g_assert(subMenu != NULL);

    /* If the depth counter exceeds, something must have gone wrong */
    g_assert(depth < EXT_MENUBAR_MAX_DEPTH);

    children = menu->children;
    /* Iterate the child entries */
    while ( children != NULL && children->data != NULL )
    {
        item = (ext_menubar_t *) children->data;

        if ( item->type == EXT_MENUBAR_MENU )
        {
            /* Handle Submenu entry */
            this->externalMenuHelper(item, subMenu->addMenu(item->label), depth++ );
        }
        else if ( item->type == EXT_MENUBAR_SEPARATOR )
        {
            subMenu->addSeparator();
        }
        else if ( item->type == EXT_MENUBAR_ITEM || item->type == EXT_MENUBAR_URL )
        {
            itemAction = subMenu->addAction(item->name);
            itemAction->setData(QVariant::fromValue((void *)item));
            itemAction->setText(item->label);
            connect(itemAction, SIGNAL(triggered()),
                    this, SLOT(externalMenuItem_triggered()));
        }

        /* Iterate Loop */
        children = g_list_next(children);
    }
}

QMenu * MainWindow::searchSubMenu(QString objectName)
{
    QList<QMenu*> lst;

    if ( objectName.length() > 0 )
    {
        QString searchName = QString("menu") + objectName;

        lst = main_ui_->menuBar->findChildren<QMenu*>();
        foreach (QMenu* m, lst)
        {
            if ( QString::compare( m->objectName(), searchName ) == 0 )
                return m;
        }
    }

    return 0;
}

void MainWindow::addExternalMenus()
{
    QMenu * subMenu = NULL;
    GList * user_menu = NULL;
    ext_menu_t * menu = NULL;

    user_menu = ext_menubar_get_entries();

    while ( ( user_menu != NULL ) && ( user_menu->data != NULL ) )
    {
        menu = (ext_menu_t *) user_menu->data;

        /* On this level only menu items should exist. Not doing an assert here,
         * as it could be an honest mistake */
        if ( menu->type != EXT_MENUBAR_MENU )
        {
            user_menu = g_list_next(user_menu);
            continue;
        }

        /* Create main submenu and add it to the menubar */
        if ( menu->parent_menu != NULL )
        {
            QMenu * sortUnderneath = searchSubMenu(QString(menu->parent_menu));
            if ( sortUnderneath != NULL)
                subMenu = sortUnderneath->addMenu(menu->label);
        }

        if ( subMenu == NULL )
            subMenu = main_ui_->menuBar->addMenu(menu->label);

        /* This will generate the action structure for each menu. It is recursive,
         * therefore a sub-routine, and we have a depth counter to prevent endless loops. */
        this->externalMenuHelper(menu, subMenu, 0);

        /* Iterate Loop */
        user_menu = g_list_next (user_menu);
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
