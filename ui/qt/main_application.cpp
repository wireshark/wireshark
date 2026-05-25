/* main_application.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

// warning C4267: 'argument' : conversion from 'size_t' to 'int', possible loss of data
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4267)
#endif

#define WS_LOG_DOMAIN  LOG_DOMAIN_MAIN

#include "main_application.h"

#include <algorithm>
#include <errno.h>

#include "wsutil/filesystem.h"
#include "app/application_flavor.h"

#include "epan/addr_resolv.h"
#include "epan/column-utils.h"
#include "epan/disabled_protos.h"
#include "epan/ftypes/ftypes.h"
#include "epan/prefs.h"
#include "epan/proto.h"
#include "epan/tap.h"
#include "epan/timestamp.h"
#include "epan/decode_as.h"
#include "epan/dfilter/dfilter-macro.h"

#include "ui/commandline.h"
#include "ui/decode_as_utils.h"
#include "ui/preference_utils.h"
#include "ui/language.h"
#include "ui/recent.h"
#include "ui/simple_dialog.h"
#include "ui/util.h"

#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/software_update.h>
#include <ui/qt/utils/theme_manager.h>
#include "coloring_rules_dialog.h"

#include "epan/color_filters.h"

#include "extcap.h"
#ifdef HAVE_LIBPCAP
#include <capture/iface_monitor.h>
#endif

#include "wsutil/filter_files.h"
#include "ui/capture_globals.h"
#include "ui/file_dialog.h"
#include "ui/recent_utils.h"

#ifdef HAVE_LIBPCAP
#include "ui/capture.h"
#endif

#include "wsutil/utf8_entities.h"

#ifdef _WIN32
#  include "wsutil/file_util.h"
#  include <QMessageBox>
#  include <QSettings>
#endif /* _WIN32 */

#include <ui/qt/capture_file.h>

#include <ui/qt/main_window.h>
#include <ui/qt/manager/interface_list_manager.h>
#include <ui/qt/main_status_bar.h>
#include <ui/qt/utils/workspace_state.h>
#include <ui/qt/utils/theme_styler.h>

#include <QAction>
#include <QApplication>
#include <QColorDialog>
#include <QDesktopServices>
#include <QDir>
#include <QEvent>
#include <QFileOpenEvent>
#include <QFontInfo>
#include <QFontMetrics>
#include <QLibraryInfo>
#include <QLocale>
#include <QMainWindow>
#include <QMutableListIterator>
#include <QProxyStyle>
#include <QSocketNotifier>
#include <QThreadPool>
#include <QUrl>
#include <qmath.h>

#include <QMimeDatabase>

#include <QStyleHints>

#if QT_VERSION >= QT_VERSION_CHECK(6, 5, 0) && defined(Q_OS_WIN)
#include <QStyleFactory>
#endif

#ifdef _MSC_VER
#pragma warning(pop)
#endif

MainApplication *mainApp;

// XXX - Copied from ui/gtk/file_dlg.c

static QHash<int, QList<QAction *> > dynamic_menu_groups_;
static QHash<int, QList<QAction *> > added_menu_groups_;
static QHash<int, QList<QAction *> > removed_menu_groups_;

QString MainApplication::window_title_separator_ = QString::fromUtf8(" " UTF8_MIDDLE_DOT " ");

// QMimeDatabase parses a large-ish XML file and can be slow to initialize.
// Do so in a worker thread as early as possible.
// https://github.com/lxde/pcmanfm-qt/issues/415
class MimeDatabaseInitThread : public QRunnable
{
private:
    void run() override
    {
        QMimeDatabase mime_db;
        mime_db.mimeTypeForData(QByteArray());
    }
};

void
topic_action(topic_action_e action)
{
    if (mainApp) mainApp->helpTopicAction(action);
}

/* write all capture filenames of the menu to the user's recent file */
extern "C" void menu_recent_file_write_all(FILE *rf) {

    const QList<RecentFileInfo>& recentFiles = WorkspaceState::instance()->recentCaptureFiles();
    int rFSize = static_cast<int>(recentFiles.size());
    for (int i = 0; i < rFSize; i++) {
        const RecentFileInfo& rfi = recentFiles.at(i);

        QString cf_name = rfi.filename;
        if (!cf_name.isNull()) {
            fprintf (rf, RECENT_KEY_CAPTURE_FILE ": %s\n", qUtf8Printable(cf_name));
        }
    }
}

void MainApplication::refreshPacketData()
{
    if (host_name_lookup_process()) {
        emit addressResolutionChanged();
    } else if (col_data_changed()) {
        emit columnDataChanged();
    }
}

void MainApplication::updateTaps()
{
    draw_tap_listeners(false);
}

QDir MainApplication::openDialogInitialDir() {
    return QDir(get_open_dialog_initial_dir());
}

void MainApplication::setLastOpenDirFromFilename(const QString file_name)
{
    /* XXX - Use canonicalPath() instead of absolutePath()? */
    QString directory = QDir::toNativeSeparators(QFileInfo(file_name).absolutePath());
    /* XXX - printable? */
    set_last_open_dir(qUtf8Printable(directory));
}

void MainApplication::helpTopicAction(topic_action_e action)
{
    QString url = gchar_free_to_qstring(topic_action_url(action));

    if (!url.isEmpty()) {
        QDesktopServices::openUrl(QUrl(QDir::fromNativeSeparators(url)));
    }
}

void MainApplication::setConfigurationProfile(const char *profile_name, bool write_recent_file)
{
    char  *rf_path;
    int    rf_open_errno;
    char *err_msg = NULL;
    const char* env_prefix = application_configuration_environment_prefix();

    /* First check if profile exists */
    if (!profile_exists(env_prefix, profile_name, false)) {
        if (profile_exists(env_prefix, profile_name, true)) {
            char  *pf_dir_path, *pf_dir_path2, *pf_filename;
            /* Copy from global profile */
            if (create_persconffile_profile(env_prefix, profile_name, &pf_dir_path) == -1) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                    "Can't create directory\n\"%s\":\n%s.",
                    pf_dir_path, g_strerror(errno));

                g_free(pf_dir_path);
            }

            if (copy_persconffile_profile(env_prefix, profile_name, profile_name, true, &pf_filename,
                    &pf_dir_path, &pf_dir_path2) == -1) {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                    "Can't copy file \"%s\" in directory\n\"%s\" to\n\"%s\":\n%s.",
                    pf_filename, pf_dir_path2, pf_dir_path, g_strerror(errno));

                g_free(pf_filename);
                g_free(pf_dir_path);
                g_free(pf_dir_path2);
            }
        } else {
            /* No personal and no global profile exists */
            return;
        }
    }

    /* Then check if changing to another profile */
    if (profile_name && strcmp (profile_name, get_profile_name()) == 0) {
        return;
    }

    /* Get the current geometry, before writing it to disk */
    emit profileChanging();

    if (write_recent_file && profile_exists(env_prefix, get_profile_name(), false))
    {
        /* Write recent file for profile we are leaving, if it still exists */
        write_profile_recent();
    }

    // Freeze the packet list early to avoid updating column data before doing a
    // full redissection. The packet list will be thawed when redissection is done.
    emit freezePacketList(true);

    /* Set profile name and update the status bar */
    set_profile_name (profile_name);
    emit profileNameChanged(profile_name);

    /* Apply new preferences */
    readConfigurationFiles(true);

    /* Apply command-line preferences */
    commandline_options_reapply();
    extcap_register_preferences(NULL, NULL);

    /* Switching profile requires reloading the macro list. */
    reloadDisplayFilterMacros();

    if (!recent_read_profile_static(&rf_path, &rf_open_errno)) {
        simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK,
            "Could not open common recent file\n\"%s\": %s.",
            rf_path, g_strerror(rf_open_errno));
        g_free(rf_path);
    }
    if (recent.gui_fileopen_remembered_dir &&
        test_for_directory(recent.gui_fileopen_remembered_dir) == EISDIR) {
        set_last_open_dir(recent.gui_fileopen_remembered_dir);
    }
    timestamp_set_type(recent.gui_time_format);
    timestamp_set_precision(recent.gui_time_precision);
    timestamp_set_seconds_type (recent.gui_seconds_format);

    prefs_to_capture_opts(&global_capture_opts);
    prefs_apply_all();
#ifdef HAVE_LIBPCAP
    /* Re-apply interface display attributes from the new profile's prefs before
       the preferencesChanged() emit below, so its listeners see fresh data. The
       manager owns interface enumeration/attributes now. */
    if (MainWindow *mw = mainWindow())
        if (InterfaceListManager *mgr = mw->interfaceListManager())
            mgr->reapplyInterfacePreferences();
#endif

    emit columnsChanged();
    emit preferencesChanged();
    emit recentPreferencesRead();
    emit filterExpressionsChanged();
    emit checkDisplayFilter();
    emit captureFilterListChanged();
    emit displayFilterListChanged();

    /* Reload color filters */
    if (!color_filters_reload(&err_msg, color_filter_add_cb, application_configuration_environment_prefix())) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err_msg);
        g_free(err_msg);
    }

    /* Capture-interface prefs are now watched by InterfaceListManager, which
       rescans when capture_no_interface_load / capture_no_extcap flips. A profile
       switch can also change interface display attributes, so notify subscribers
       (the manager owns the interface-list-changed signal now). */
    MainWindow *mw = mainWindow();
    if (mw && mw->interfaceListManager())
        mw->interfaceListManager()->notifyListChanged();
    emit packetDissectionChanged();

    /* Write recent_common file to ensure last used profile setting is stored. */
    write_recent();
}

void MainApplication::reloadLuaPluginsDelayed()
{
    QTimer::singleShot(0, this, [this]() {
        /* Clear the reloading flag so the re-triggered reload
         * is not blocked by the isReloadingLua() guard. */
        setReloadingLua(false);
        emit reloadLuaPlugins();
    });
}

const QIcon &MainApplication::normalIcon()
{
    if (normal_icon_.isNull()) {
        initializeIcons();
    }
    return normal_icon_;
}

const QIcon &MainApplication::captureIcon()
{
    if (capture_icon_.isNull()) {
        initializeIcons();
    }
    return capture_icon_;
}

const QString MainApplication::windowTitleString(QStringList title_parts)
{
    QMutableStringListIterator tii(title_parts);
    while (tii.hasNext()) {
        QString ti = tii.next();
        if (ti.isEmpty()) tii.remove();
    }
    title_parts.prepend(applicationName());
    return title_parts.join(window_title_separator_);
}

void MainApplication::applyCustomColorsFromRecent()
{
    int i = 0;
    bool ok;
    for (GList *custom_color = recent.custom_colors; custom_color; custom_color = custom_color->next) {
        QRgb rgb = QString((const char *)custom_color->data).toUInt(&ok, 16);
        if (ok) {
            QColorDialog::setCustomColor(i++, QColor(rgb));
        }
    }
}

// Return the first top-level MainWindow.
MainWindow *MainApplication::mainWindow()
{
    foreach (QWidget *tlw, topLevelWidgets()) {
        MainWindow *tlmw = qobject_cast<MainWindow *>(tlw);
        if (tlmw && tlmw->isVisible()) {
            return tlmw;
        }
    }
    return nullptr;
}

void MainApplication::storeCustomColorsInRecent()
{
    if (QColorDialog::customCount()) {
        prefs_clear_string_list(recent.custom_colors);
        recent.custom_colors = NULL;
        for (int i = 0; i < QColorDialog::customCount(); i++) {
            QRgb rgb = QColorDialog::customColor(i).rgb();
            recent.custom_colors = g_list_append(recent.custom_colors, ws_strdup_printf("%08x", rgb));
        }
    }
}

bool MainApplication::event(QEvent *event)
{
    QString display_filter = NULL;
    if (event->type() == QEvent::FileOpen) {
        QFileOpenEvent *foe = static_cast<QFileOpenEvent *>(event);
        if (foe && foe->file().length() > 0) {
            QString cf_path(foe->file());
            if (initialized_) {
                emit openCaptureFile(cf_path, display_filter, WTAP_TYPE_AUTO);
            } else {
                pending_open_files_.append(cf_path);
            }
        }
        return true;
    }
    return QApplication::event(event);
}

void MainApplication::cleanup()
{
    SoftwareUpdate::instance()->cleanup();
    storeCustomColorsInRecent();
    // Write the user's recent file(s) to disk.
    write_profile_recent();
    write_recent();

    // We might end up here via exit_application.
    QThreadPool::globalInstance()->waitForDone();
}

MainApplication::MainApplication(int &argc,  char **argv) :
    QApplication(argc, argv),
    initialized_(false),
    is_reloading_lua_(false),
    if_notifier_(NULL),
    active_captures_(0)
#if defined(Q_OS_MAC) || defined(Q_OS_WIN)
    , normal_icon_(windowIcon())
#endif
{
    mainApp = this;

    MimeDatabaseInitThread *mime_db_init_thread = new(MimeDatabaseInitThread);
    QThreadPool::globalInstance()->start(mime_db_init_thread);

    Q_INIT_RESOURCE(about);
    Q_INIT_RESOURCE(i18n);
    Q_INIT_RESOURCE(layout);
    Q_INIT_RESOURCE(stock_icons);
    Q_INIT_RESOURCE(languages);

    // Initialize the ThemeManager as early as possible so that any
    // widget constructed afterwards can resolve themed stylesheets and
    // color tokens.  This must run after QApplication's base ctor (so
    // that the palette is queryable for light/dark detection) but
    // before any UI is built.  recent_common has already been read in
    // main()/stratoshark_main() prior to constructing this application
    // object, so we can read any configured themes as well.
    // Theme selection is persisted in recent_common (recent.gui_theme_name),
    // not in the preferences file — so it survives profile switches and
    // stays global to the install.  Empty / missing value, or the legacy
    // "default" sentinel, get resolved by ThemeManager itself to the
    // current flavor's preferred default (wireshark / stratoshark).
    ThemeManager::init(ThemeManager::resolveThemeName(
            QString::fromUtf8(recent.gui_theme_name)));

#ifdef Q_OS_WIN
    /* RichEd20.DLL is needed for native file dialog filter entries. */
    ws_load_library("riched20.dll");
#endif // Q_OS_WIN

    // We use a lot of style sheets that base their colors on the main
    // application palette, so this works better.
    setAttribute(Qt::AA_UseStyleSheetPropagationInWidgetStyles, true);

    // Throw various settings at the wall with the hope that one of them will
    // enable context menu shortcuts QTBUG-69452, QTBUG-109590
    setAttribute(Qt::AA_DontShowShortcutsInContextMenus, false);
    styleHints()->setShowShortcutsInContextMenus(true);

    packet_data_timer_.setParent(this);
    connect(&packet_data_timer_, &QTimer::timeout, this, &MainApplication::refreshPacketData);
    packet_data_timer_.start(1000);

    tap_update_timer_.setParent(this);
    // tap_update_timer interval is set when preferences are set before init
    connect(this, &MainApplication::appInitialized, &tap_update_timer_, [&]() { tap_update_timer_.start(); });
    connect(&tap_update_timer_, &QTimer::timeout, this, &MainApplication::updateTaps);

    setStyle(new ThemeStyler);

    connect(qApp, &QApplication::aboutToQuit, this, &MainApplication::cleanup);
}

MainApplication::~MainApplication()
{
    mainApp = NULL;
    clearDynamicMenuGroupItems();
}

void MainApplication::emitAppSignal(AppSignal signal)
{
    switch (signal) {
    case ColumnsChanged:
        emit columnsChanged();
        break;
    case CaptureFilterListChanged:
        emit captureFilterListChanged();
        break;
    case DisplayFilterListChanged:
        emit displayFilterListChanged();
        break;
    case FilterExpressionsChanged:
        emit filterExpressionsChanged();
        break;
    case NameResolutionChanged:
        emit addressResolutionChanged();
        break;
    case PreferencesChanged:
        tap_update_timer_.setInterval(prefs.tap_update_interval);
        emit preferencesChanged();
        break;
    case PacketDissectionChanged:
        emit packetDissectionChanged();
        break;
    case RecentPreferencesRead:
        emit recentPreferencesRead();
        break;
    case FieldsChanged:
        emit fieldsChanged();
        break;
    case FreezePacketList:
        emit freezePacketList(false);
        break;
    case AggregationChanged:
        emit aggregationChanged();
        break;
    default:
        break;
    }
}

// Flush any collected app signals.
//
// On macOS emitting PacketDissectionChanged from a dialog can
// render the application unusable:
// https://gitlab.com/wireshark/wireshark/-/issues/11361
// https://gitlab.com/wireshark/wireshark/-/issues/11448
// Work around the problem by queueing up app signals and emitting them
// after the dialog is closed.
//
// The following bugs might be related although they don't describe the
// exact behavior we're working around here:
// https://bugreports.qt.io/browse/QTBUG-38512
// https://bugreports.qt.io/browse/QTBUG-38600
void MainApplication::flushAppSignals()
{
    while (!app_signals_.isEmpty()) {
        mainApp->emitAppSignal(app_signals_.takeFirst());
    }
}

void MainApplication::emitStatCommandSignal(const QString &menu_path, const char *arg, void *userdata)
{
    emit openStatCommandDialog(menu_path, arg, userdata);
}

void MainApplication::emitTapParameterSignal(const QString cfg_abbr, const QString arg, void *userdata)
{
    emit openTapParameterDialog(cfg_abbr, arg, userdata);
}

// XXX Combine statistics and funnel routines into addGroupItem + groupItems?
void MainApplication::addDynamicMenuGroupItem(int group, QAction *sg_action)
{
    if (!dynamic_menu_groups_.contains(group)) {
        dynamic_menu_groups_[group] = QList<QAction *>();
    }
    dynamic_menu_groups_[group] << sg_action;
}

void MainApplication::appendDynamicMenuGroupItem(int group, QAction *sg_action)
{
    if (!added_menu_groups_.contains(group)) {
        added_menu_groups_[group] = QList<QAction *>();
    }
    added_menu_groups_[group] << sg_action;
    addDynamicMenuGroupItem(group, sg_action);
}

void MainApplication::removeDynamicMenuGroupItem(int group, QAction *sg_action)
{
    if (!removed_menu_groups_.contains(group)) {
        removed_menu_groups_[group] = QList<QAction *>();
    }
    removed_menu_groups_[group] << sg_action;
    dynamic_menu_groups_[group].removeAll(sg_action);
}

void MainApplication::clearDynamicMenuGroupItems()
{
    foreach (int group, dynamic_menu_groups_.keys()) {
        dynamic_menu_groups_[group].clear();
    }
}

QList<QAction *> MainApplication::dynamicMenuGroupItems(int group)
{
    if (!dynamic_menu_groups_.contains(group)) {
        return QList<QAction *>();
    }

    QList<QAction *> sgi_list = dynamic_menu_groups_[group];
    std::sort(sgi_list.begin(), sgi_list.end(), qActionLessThan);
    return sgi_list;
}

QList<QAction *> MainApplication::addedMenuGroupItems(int group)
{
    if (!added_menu_groups_.contains(group)) {
        return QList<QAction *>();
    }

    QList<QAction *> sgi_list = added_menu_groups_[group];
    std::sort(sgi_list.begin(), sgi_list.end(), qActionLessThan);
    return sgi_list;
}

QList<QAction *> MainApplication::removedMenuGroupItems(int group)
{
    if (!removed_menu_groups_.contains(group)) {
        return QList<QAction *>();
    }

    QList<QAction *> sgi_list = removed_menu_groups_[group];
    std::sort(sgi_list.begin(), sgi_list.end(), qActionLessThan);
    return sgi_list;
}

void MainApplication::clearAddedMenuGroupItems()
{
    foreach (int group, added_menu_groups_.keys()) {
        added_menu_groups_[group].clear();
    }
}

void MainApplication::clearRemovedMenuGroupItems()
{
    foreach (int group, removed_menu_groups_.keys()) {
        foreach (QAction *action, removed_menu_groups_[group]) {
            delete action;
        }
        removed_menu_groups_[group].clear();
    }
}

#ifdef HAVE_LIBPCAP

static void
iface_mon_event_cb(const char *iface, int added, int up)
{
    int present = 0;
    unsigned ifs, j;
    interface_t *device;
    interface_options *interface_opts;

    for (ifs = 0; ifs < global_capture_opts.all_ifaces->len; ifs++) {
        device = &g_array_index(global_capture_opts.all_ifaces, interface_t, ifs);
        if (strcmp(device->name, iface) == 0) {
            present = 1;
            if (!up) {
                /*
                 * Interface went down or disappeared; remove all instances
                 * of it from the current list of interfaces selected
                 * for capturing.
                 */
                for (j = 0; j < global_capture_opts.ifaces->len; j++) {
                    interface_opts = &g_array_index(global_capture_opts.ifaces, interface_options, j);
                    if (strcmp(interface_opts->name, device->name) == 0) {
                        capture_opts_del_iface(&global_capture_opts, j);
                }
             }
          }
        }
    }

    mainApp->emitLocalInterfaceEvent(iface, added, up);
    if (present != up) {
        /*
         * We've been told that there's a new interface or that an old
         * interface is gone; reload the local interface list.
         *
         * XXX: We also want to reload the local interface list if [what
         * we can retrieve about] the capabilities of the device have changed.
         * Ideally we'd update the capabilities of just the one device in
         * the cache and signal that the list has been updated, instead of
         * freeing the entire cache and scanning again - but some extcaps
         * depend on other interfaces being up; e.g. by default androiddump
         * tries to connect to the loopback interface to look for adb running,
         * so if the loopback interface changes so does the status of
         * androiddump.
         *
         * On Linux, at least, you can't get the capabilities from a down
         * interface, but it's still present in all_ifaces - dumpcap returns
         * it in the list, and we show it so the user can get a status / error
         * message when trying to capture on it instead of it vanishing.
         * So if both present and up are true, then we still want to refresh
         * to update the capabilities and restart the stats.
         *
         * We also store the address in all_ifaces and show them to the user,
         * so we probably should monitor those events as well and update
         * the interface list appropriately when those change.
         */
        MainWindow *mainWindow = mainApp->mainWindow();
        if (mainWindow && mainWindow->interfaceListManager())
            mainWindow->interfaceListManager()->requestRefresh();
    }
}

#endif

void MainApplication::ifChangeEventsAvailable()
{
#ifdef HAVE_LIBPCAP
    /*
     * Something's readable from the descriptor for interface
     * monitoring.
     *
     * Have the interface-monitoring code Read whatever interface-change
     * events are available, and call the callback for them.
     */
    iface_mon_event();
#endif
}

void MainApplication::emitLocalInterfaceEvent(const char *ifname, int added, int up)
{
    emit localInterfaceEvent(ifname, added, up);
}

void MainApplication::whenInitializedDispatch(const QObject *context, std::function<void()> fn)
{
    // POLICY DECISION (your input shapes behavior here):
    //
    // We get here only when a caller registers via whenInitialized() *after*
    // appInitialized() has already fired. The not-yet-initialized path runs the
    // callback later, from the event loop, once construction is long finished.
    // How should the already-initialized path behave?
    //
    //   A) Synchronous: fn(); right now. Simplest. But the callback runs while
    //      the caller's constructor is still on the stack -- the object may be
    //      only partly built, and any code after the whenInitialized() call in
    //      that constructor runs *after* the callback. Timing differs from the
    //      deferred path.
    //
    //   B) Deferred to the event loop (e.g. QTimer::singleShot(0, context, fn)
    //      or QMetaObject::invokeMethod(..., Qt::QueuedConnection)): callback
    //      always runs after the current call returns, matching the signal path
    //      exactly, so callers see one consistent ordering. Costs one event-loop
    //      turn and needs the context-still-alive guarantee.
    //
    // Option A (current behavior) is intentional for now: it exactly reproduces
    // the old open-coded `if (isInitialized()) doThing();` -- a synchronous call
    // on the caller's stack -- so routing those sites through whenInitialized()
    // is a pure no-op refactor. Option B is the intended end state, but it
    // shifts the already-initialized callback by one event-loop turn and so
    // changes ordering for every converted site at once; switch to it only
    // behind broader ordering/lifetime tests (dialogs opened mid-session,
    // welcome/interface frames at cold start, context destroyed same-turn).
    //
    // To switch, delete the fn() below and enable the deferred dispatch:
    //
    //     QTimer::singleShot(0, const_cast<QObject *>(context), std::move(fn));
    //
    // (context is the receiver, so the call is dropped if it dies first, and
    // runs on context's thread -- matching the connect() branch.)
    Q_UNUSED(context) // option A ignores context; option B uses it.
    fn(); // option A: synchronous, matches legacy behavior.
}

void MainApplication::allSystemsGo()
{
    QString display_filter = NULL;
    initialized_ = true;
    emit appInitialized();
    while (pending_open_files_.length() > 0) {
        emit openCaptureFile(pending_open_files_.front(), display_filter, WTAP_TYPE_AUTO);
        pending_open_files_.pop_front();
    }

    bool sideBarVisible = recent.gui_welcome_page_sidebar_tips_visible ||
                           recent.gui_welcome_page_sidebar_learn_visible;
    SoftwareUpdate::instance()->init(!sideBarVisible);

#ifdef HAVE_LIBPCAP
    int err;
    err = iface_mon_start(&iface_mon_event_cb);
    if (err == 0) {
        if_notifier_ = new QSocketNotifier(iface_mon_get_sock(),
                                           QSocketNotifier::Read, this);
        connect(if_notifier_, &QSocketNotifier::activated, this, &MainApplication::ifChangeEventsAvailable);
    }
#endif
}

_e_prefs *MainApplication::readConfigurationFiles(bool reset)
{
    e_prefs             *prefs_p;

    if (reset) {
        //
        // Reset current preferences and enabled/disabled protocols and
        // heuristic dissectors before reading.
        // (Needed except when this is called at startup.)
        //
        prefs_reset(application_configuration_environment_prefix(), application_columns(), application_num_columns());
        proto_reenable_all();
    }

    /* Load libwireshark settings from the current profile. */
    prefs_p = epan_load_settings();

    return prefs_p;
}

static void switchTranslator(QTranslator& myTranslator, const QLocale &locale, const QString& filename, const QStringList &searchPath)
{
    mainApp->removeTranslator(&myTranslator);
    for (const QString &path : searchPath) {
        if (myTranslator.load(locale, filename, QStringLiteral("_"), path)) {
            mainApp->installTranslator(&myTranslator);
            return;
        }
    }
    if (locale.language() != QLocale::C) {
        /* Don't compare the locale itself, see:
         * https://doc.qt.io/qt-6/qlocale.html#operator-eq-eq
         *
         * Note that the ordered list of languages that were tried is that of
         * locale.uiLanguages(); the first language in that list is not
         * necessarily locale.language(), especially on Windows (See #17221.)
         */
        qWarning() << "Couldn't load" << filename << "translations!" << "Searched:" << searchPath;
    }
}

void MainApplication::loadLanguage(const QString newLanguage)
{
    QLocale locale;
    const char* env_prefix = application_configuration_environment_prefix();

    if (newLanguage.isEmpty() || newLanguage == USE_SYSTEM_LANGUAGE) {
        locale = QLocale::system();
    } else {
        locale = QLocale(newLanguage);
    }

    QLocale::setDefault(locale);

    // Search path list ordered by priority. Prefer personal configuration
    // to global datadir to embedded resources to Qt global directory.
    QStringList searchPath;
    searchPath.emplaceBack(gchar_free_to_qstring(get_persconffile_path("languages", false, env_prefix)));
    searchPath.emplaceBack(QStringLiteral("%1/languages").arg(get_datafile_dir(env_prefix)));
    searchPath.emplaceBack(QStringLiteral(":/i18n/"));

#if QT_VERSION >= QT_VERSION_CHECK(6, 8, 0)
    searchPath.append(QLibraryInfo::paths(QLibraryInfo::TranslationsPath));
#else
    searchPath.emplaceBack(QLibraryInfo::path(QLibraryInfo::TranslationsPath));
#endif

    // Translations are searched for in the reverse order in which they were
    // installed, so install the Qt generic translator first and ours last.
    switchTranslator(mainApp->translatorQt, locale, QStringLiteral("qt"), searchPath);

    // XXX - Yes, the translation files are also wireshark_%1.qm for Stratoshark.
    // There is a stratoshark_en.[ts|qm] file too (for plurals?) though I'm
    // not sure if it's used properly.
    switchTranslator(mainApp->translator, locale, QStringLiteral("wireshark"), searchPath);
}

void MainApplication::doTriggerMenuItem(MainMenuItem menuItem)
{
    switch (menuItem)
    {
    case FileOpenDialog:
        emit openCaptureFile(QString(), QString(), WTAP_TYPE_AUTO);
        break;
    case CaptureOptionsDialog:
        emit openCaptureOptions();
        break;
    }
}

void MainApplication::captureEventHandler(CaptureEvent ev)
{
    switch(ev.captureContext())
    {
#ifdef HAVE_LIBPCAP
    case CaptureEvent::Update:
    case CaptureEvent::Fixed:
        switch (ev.eventType())
        {
        case CaptureEvent::Prepared:
            iface_mon_enable(true);
            break;
        case CaptureEvent::Started:
            active_captures_++;
            emit captureActive(active_captures_);
            break;
        case CaptureEvent::Finished:
            active_captures_--;
            emit captureActive(active_captures_);
            // A refresh requested during the capture was deferred by
            // InterfaceListManager (capture-active guard) and is serviced now via
            // the captureActive signal above; no explicit re-trigger needed.
            break;
        default:
            break;
        }
        break;
#endif
    case CaptureEvent::File:
    case CaptureEvent::Reload:
    case CaptureEvent::Rescan:
        switch (ev.eventType())
        {
        case CaptureEvent::Started:
            QTimer::singleShot(TAP_UPDATE_DEFAULT_INTERVAL / 5, this, SLOT(updateTaps()));
            QTimer::singleShot(TAP_UPDATE_DEFAULT_INTERVAL / 2, this, SLOT(updateTaps()));
            break;
        case CaptureEvent::Finished:
            updateTaps();
            break;
        default:
            break;
        }
        break;
    default:
        break;
    }
}

void MainApplication::pushStatus(StatusInfo status, const QString &message, const QString &messagetip)
{
    MainWindow * mw = mainWindow();
    if (! mw) {
        return;
    }

    MainStatusBar * bar = mw->statusBar();
    if (! bar) {
        return;
    }

    switch(status)
    {
        case FilterSyntax:
            bar->pushGenericStatus(MainStatusBar::STATUS_CTX_FILTER, message);
            break;
        case FieldStatus:
            bar->pushGenericStatus(MainStatusBar::STATUS_CTX_FIELD, message);
            break;
        case FileStatus:
            bar->pushGenericStatus(MainStatusBar::STATUS_CTX_FILE, message, messagetip);
            break;
        case ByteStatus:
            bar->pushGenericStatus(MainStatusBar::STATUS_CTX_BYTE, message);
            break;
        case BusyStatus:
            bar->pushGenericStatus(MainStatusBar::STATUS_CTX_PROGRESS, message, messagetip);
            break;
        case TemporaryStatus:
            bar->pushGenericStatus(MainStatusBar::STATUS_CTX_TEMPORARY, message);
            break;
    }
}

void MainApplication::popStatus(StatusInfo status)
{
    MainWindow * mw = mainWindow();
    if (! mw) {
        return;
    }

    MainStatusBar * bar = mw->statusBar();
    if (! bar) {
        return;
    }

    switch(status)
    {
        case FilterSyntax:
            bar->popGenericStatus(MainStatusBar::STATUS_CTX_FILTER);
            break;
        case FieldStatus:
            bar->popGenericStatus(MainStatusBar::STATUS_CTX_FIELD);
            break;
        case FileStatus:
            bar->popGenericStatus(MainStatusBar::STATUS_CTX_FILE);
            break;
        case ByteStatus:
            bar->popGenericStatus(MainStatusBar::STATUS_CTX_BYTE);
            break;
        case BusyStatus:
            bar->popGenericStatus(MainStatusBar::STATUS_CTX_PROGRESS);
            break;
        case TemporaryStatus:
            bar->popGenericStatus(MainStatusBar::STATUS_CTX_TEMPORARY);
            break;
    }
}

void MainApplication::gotoFrame(int frame)
{
    MainWindow * mw = mainWindow();
    if (! mw) {
        return;
    }

    mw->gotoFrame(frame);
}

void MainApplication::reloadDisplayFilterMacros()
{
    dfilter_macro_reload(application_configuration_environment_prefix());
    // The signal is needed when the display filter grammar changes for
    // any reason (not just "fields".)
    mainApp->emitAppSignal(MainApplication::FieldsChanged);
}
