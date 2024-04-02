/* funnel_statistics.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "epan/color_filters.h"
#include "file.h"

#include "epan/funnel.h"
#include "epan/prefs.h"

#include <wsutil/wslog.h>

#include "ui/progress_dlg.h"
#include "ui/simple_dialog.h"
#include <ui/qt/main_window.h>
#include <ui/qt/io_console_dialog.h>

#include "funnel_statistics.h"
#include "funnel_string_dialog.h"
#include "funnel_text_dialog.h"

#include <QAction>
#include <QClipboard>
#include <QDebug>
#include <QDesktopServices>
#include <QMenu>
#include <QUrl>

#include "main_application.h"

// To do:
// - Handle menu paths. Do we create a new path (GTK+) or use the base element?
// - Add a FunnelGraphDialog class?

extern "C" {
static struct _funnel_text_window_t* text_window_new(funnel_ops_id_t *ops_id, const char* title);
static void string_dialog_new(funnel_ops_id_t *ops_id, const char* title, const char** field_names, const char** field_values, funnel_dlg_cb_t dialog_cb, void* dialog_cb_data, funnel_dlg_cb_data_free_t dialog_cb_data_free);

static void funnel_statistics_retap_packets(funnel_ops_id_t *ops_id);
static void funnel_statistics_copy_to_clipboard(GString *text);
static const char *funnel_statistics_get_filter(funnel_ops_id_t *ops_id);
static void funnel_statistics_set_filter(funnel_ops_id_t *ops_id, const char* filter_string);
static char* funnel_statistics_get_color_filter_slot(uint8_t filter_num);
static void funnel_statistics_set_color_filter_slot(uint8_t filter_num, const char* filter_string);
static bool funnel_statistics_open_file(funnel_ops_id_t *ops_id, const char* fname, const char* filter, char**);
static void funnel_statistics_reload_packets(funnel_ops_id_t *ops_id);
static void funnel_statistics_redissect_packets(funnel_ops_id_t *ops_id);
static void funnel_statistics_reload_lua_plugins(funnel_ops_id_t *ops_id);
static void funnel_statistics_apply_filter(funnel_ops_id_t *ops_id);
static bool browser_open_url(const char *url);
static void browser_open_data_file(const char *filename);
static struct progdlg *progress_window_new(funnel_ops_id_t *ops_id, const char* title, const char* task, bool terminate_is_stop, bool *stop_flag);
static void progress_window_update(struct progdlg *progress_dialog, float percentage, const char* status);
static void progress_window_destroy(struct progdlg *progress_dialog);
}

FunnelAction::FunnelAction(QObject *parent) :
        QAction(parent),
        callback_(nullptr),
        callback_data_(NULL),
        retap_(false),
        packetCallback_(nullptr),
        packetData_(NULL)
{

}

FunnelAction::FunnelAction(QString title, funnel_menu_callback callback, void *callback_data, bool retap, QObject *parent = nullptr) :
        QAction(parent),
        title_(title),
        callback_(callback),
        callback_data_(callback_data),
        retap_(retap)
{
    // Use "&&" to get a real ampersand in the menu item.
    title.replace('&', "&&");

    setText(title);
    setObjectName(FunnelStatistics::actionName());
    packetRequiredFields_ = QSet<QString>();
}

FunnelAction::FunnelAction(QString title, funnel_packet_menu_callback callback, void *callback_data, bool retap, const char *packet_required_fields, QObject *parent = nullptr) :
        QAction(parent),
        title_(title),
        callback_data_(callback_data),
        retap_(retap),
        packetCallback_(callback),
        packetRequiredFields_(QSet<QString>())
{
    // Use "&&" to get a real ampersand in the menu item.
    title.replace('&', "&&");

    QStringList menuComponents = title.split(QString("/"));
    // Set the menu's text to the rightmost component, set the path to being everything to the left:
    setText("(empty)");
    packetSubmenu_ = "";
    if (!menuComponents.isEmpty())
    {
        setText(menuComponents.last());
        menuComponents.removeLast();
        packetSubmenu_ = menuComponents.join("/");
    }

    setObjectName(FunnelStatistics::actionName());
    setPacketRequiredFields(packet_required_fields);
}

FunnelAction::~FunnelAction(){
}

funnel_menu_callback FunnelAction::callback() const {
    return callback_;
}

QString FunnelAction::title() const {
    return title_;
}

void FunnelAction::triggerCallback() {
    if (callback_) {
        callback_(callback_data_);
    }
}

void FunnelAction::setPacketCallback(funnel_packet_menu_callback packet_callback) {
    packetCallback_ = packet_callback;
}

void FunnelAction::setPacketRequiredFields(const char *required_fields_str) {
    packetRequiredFields_.clear();
    // If multiple fields are required to be present, they're split by commas
    // Also remove leading and trailing spaces, in case someone writes
    // "http, dns" instead of "http,dns"
    QString requiredFieldsJoined = QString(required_fields_str);
#if QT_VERSION >= QT_VERSION_CHECK(5, 15, 0)
    QStringList requiredFieldsSplit = requiredFieldsJoined.split(",", Qt::SkipEmptyParts);
#else
    QStringList requiredFieldsSplit = requiredFieldsJoined.split(",", QString::SkipEmptyParts);
#endif
    foreach (QString requiredField, requiredFieldsSplit) {
        QString trimmedFieldName = requiredField.trimmed();
        if (! trimmedFieldName.isEmpty()) {
            packetRequiredFields_.insert(trimmedFieldName);
        }
    }
}

const QSet<QString> FunnelAction::getPacketRequiredFields() {
    return packetRequiredFields_;
}


void FunnelAction::setPacketData(GPtrArray* finfos) {
    packetData_ = finfos;
}

void FunnelAction::addToMenu(QMenu * ctx_menu, QHash<QString, QMenu *> &menuTextToMenus) {
    QString submenusText = this->getPacketSubmenus();
    if (submenusText.isEmpty()) {
        ctx_menu->addAction(this);
    } else {
        // If the action has a submenu, ensure that the
        // the full submenu chain exists:
        QStringList menuComponents = submenusText.split("/");
        QString menuSubComponentsStringPrior = NULL;
        for (int menuIndex=0; menuIndex < menuComponents.size(); menuIndex++) {
            QStringList menuSubComponents = menuComponents.mid(0, menuIndex+1);
            QString menuSubComponentsString = menuSubComponents.join("/");
            if (!menuTextToMenus.contains(menuSubComponentsString)) {
                // Create a new menu object under the prior object
                QMenu *previousSubmenu = menuTextToMenus.value(menuSubComponentsStringPrior);
                QMenu *submenu = previousSubmenu->addMenu(menuComponents.at(menuIndex));
                menuTextToMenus.insert(menuSubComponentsString, submenu);
            }
            menuSubComponentsStringPrior = menuSubComponentsString;
        }
        // Then add the action to the relevant submenu
        QMenu *parentMenu = menuTextToMenus.value(submenusText);
        parentMenu->addAction(this);
    }

}

void FunnelAction::triggerPacketCallback() {
    if (packetCallback_) {
        packetCallback_(callback_data_, packetData_);
    }
}

bool FunnelAction::retap() {
    if (retap_) return true;
    return false;
}

QString FunnelAction::getPacketSubmenus() {
    return packetSubmenu_;
}

FunnelConsoleAction::FunnelConsoleAction(QString name,
                        funnel_console_eval_cb_t eval_cb,
                        funnel_console_open_cb_t open_cb,
                        funnel_console_close_cb_t close_cb,
                        void *callback_data, QObject *parent = nullptr) :
        FunnelAction(parent),
        eval_cb_(eval_cb),
        open_cb_(open_cb),
        close_cb_(close_cb),
        callback_data_(callback_data)
{
    // Use "&&" to get a real ampersand in the menu item.
    QString title = QString("%1 Console").arg(name).replace('&', "&&");

    setText(title);
    setObjectName(FunnelStatistics::actionName());
}

FunnelConsoleAction::~FunnelConsoleAction()
{
}

void FunnelConsoleAction::triggerCallback() {
    if (!dialog_) {
        dialog_ = new IOConsoleDialog(*qobject_cast<QWidget *>(parent()),
                                            this->text(),
                                            eval_cb_, open_cb_, close_cb_, callback_data_);
        dialog_->setAttribute(Qt::WA_DeleteOnClose);
    }

    if (dialog_->isMinimized()) {
        dialog_->showNormal();
    }
    else {
        dialog_->show();
    }
    dialog_->raise();
    dialog_->activateWindow();
}

static QHash<int, QList<FunnelAction *> > funnel_actions_;
const QString FunnelStatistics::action_name_ = "FunnelStatisticsAction";
static bool menus_registered;

struct _funnel_ops_id_t {
    FunnelStatistics *funnel_statistics;
};

FunnelStatistics::FunnelStatistics(QObject *parent, CaptureFile &cf) :
    QObject(parent),
    capture_file_(cf),
    prepared_filter_(QString())
{
    funnel_ops_ = new(struct _funnel_ops_t);
    memset(funnel_ops_, 0, sizeof(struct _funnel_ops_t));
    funnel_ops_id_ = new(struct _funnel_ops_id_t);

    funnel_ops_id_->funnel_statistics = this;
    funnel_ops_->ops_id = funnel_ops_id_;
    funnel_ops_->new_text_window = text_window_new;
    funnel_ops_->set_text = text_window_set_text;
    funnel_ops_->append_text = text_window_append;
    funnel_ops_->prepend_text = text_window_prepend;
    funnel_ops_->clear_text = text_window_clear;
    funnel_ops_->get_text = text_window_get_text;
    funnel_ops_->set_close_cb = text_window_set_close_cb;
    funnel_ops_->set_editable = text_window_set_editable;
    funnel_ops_->destroy_text_window = text_window_destroy;
    funnel_ops_->add_button = text_window_add_button;
    funnel_ops_->new_dialog = string_dialog_new;
    funnel_ops_->close_dialogs = string_dialogs_close;
    funnel_ops_->retap_packets = funnel_statistics_retap_packets;
    funnel_ops_->copy_to_clipboard = funnel_statistics_copy_to_clipboard;
    funnel_ops_->get_filter = funnel_statistics_get_filter;
    funnel_ops_->set_filter = funnel_statistics_set_filter;
    funnel_ops_->get_color_filter_slot = funnel_statistics_get_color_filter_slot;
    funnel_ops_->set_color_filter_slot = funnel_statistics_set_color_filter_slot;
    funnel_ops_->open_file = funnel_statistics_open_file;
    funnel_ops_->reload_packets = funnel_statistics_reload_packets;
    funnel_ops_->redissect_packets = funnel_statistics_redissect_packets;
    funnel_ops_->reload_lua_plugins = funnel_statistics_reload_lua_plugins;
    funnel_ops_->apply_filter = funnel_statistics_apply_filter;
    funnel_ops_->browser_open_url = browser_open_url;
    funnel_ops_->browser_open_data_file = browser_open_data_file;
    funnel_ops_->new_progress_window = progress_window_new;
    funnel_ops_->update_progress = progress_window_update;
    funnel_ops_->destroy_progress_window = progress_window_destroy;

    funnel_set_funnel_ops(funnel_ops_);
}

FunnelStatistics::~FunnelStatistics()
{
    // At this point we're probably closing the program and will shortly
    // call epan_cleanup, which calls ProgDlg__gc and TextWindow__gc.
    // They in turn depend on funnel_ops_ being valid.
    memset(funnel_ops_id_, 0, sizeof(struct _funnel_ops_id_t));
    memset(funnel_ops_, 0, sizeof(struct _funnel_ops_t));
    // delete(funnel_ops_id_);
    // delete(funnel_ops_);
}

void FunnelStatistics::retapPackets()
{
    capture_file_.retapPackets();
}

struct progdlg *FunnelStatistics::progressDialogNew(const char *task_title, const char *item_title, bool terminate_is_stop, bool *stop_flag)
{
    return create_progress_dlg(parent(), task_title, item_title, terminate_is_stop, stop_flag);
}

const char *FunnelStatistics::displayFilter()
{
    return display_filter_.constData();
}

void FunnelStatistics::emitSetDisplayFilter(const QString filter)
{
    prepared_filter_ = filter;
    emit setDisplayFilter(filter, FilterAction::ActionPrepare, FilterAction::ActionTypePlain);
}

void FunnelStatistics::reloadPackets()
{
    capture_file_.reload();
}

void FunnelStatistics::redissectPackets()
{
    // This will trigger a packet redissection.
    mainApp->emitAppSignal(MainApplication::PacketDissectionChanged);
}

void FunnelStatistics::reloadLuaPlugins()
{
    mainApp->reloadLuaPluginsDelayed();
}

void FunnelStatistics::emitApplyDisplayFilter()
{
    emit setDisplayFilter(prepared_filter_, FilterAction::ActionApply, FilterAction::ActionTypePlain);
}

void FunnelStatistics::emitOpenCaptureFile(QString cf_path, QString filter)
{
    emit openCaptureFile(cf_path, filter);
}

void FunnelStatistics::funnelActionTriggered()
{
    FunnelAction *funnel_action = dynamic_cast<FunnelAction *>(sender());
    if (!funnel_action) return;

    funnel_action->triggerCallback();
}

void FunnelStatistics::displayFilterTextChanged(const QString &filter)
{
    display_filter_ = filter.toUtf8();
}

struct _funnel_text_window_t* text_window_new(funnel_ops_id_t *ops_id, const char* title)
{
    return FunnelTextDialog::textWindowNew(qobject_cast<QWidget *>(ops_id->funnel_statistics->parent()), title);
}

void string_dialog_new(funnel_ops_id_t *ops_id, const char* title, const char** field_names, const char** field_values, funnel_dlg_cb_t dialog_cb, void* dialog_cb_data, funnel_dlg_cb_data_free_t dialog_cb_data_free)
{
    QList<QPair<QString, QString>> field_list;
    for (int i = 0; field_names[i]; i++) {
        QPair<QString, QString> field = QPair<QString, QString>(QString(field_names[i]), QString(""));
        if (field_values != NULL && field_values[i])
        {
            field.second = QString(field_values[i]);
        }

        field_list << field;
    }
    FunnelStringDialog::stringDialogNew(qobject_cast<QWidget *>(ops_id->funnel_statistics->parent()), title, field_list, dialog_cb, dialog_cb_data, dialog_cb_data_free);
}

void funnel_statistics_retap_packets(funnel_ops_id_t *ops_id) {
    if (!ops_id || !ops_id->funnel_statistics) return;

    ops_id->funnel_statistics->retapPackets();
}

void funnel_statistics_copy_to_clipboard(GString *text) {
    mainApp->clipboard()->setText(text->str);
}

const char *funnel_statistics_get_filter(funnel_ops_id_t *ops_id) {
    if (!ops_id || !ops_id->funnel_statistics) return nullptr;

    return ops_id->funnel_statistics->displayFilter();
}

void funnel_statistics_set_filter(funnel_ops_id_t *ops_id, const char* filter_string) {
    if (!ops_id || !ops_id->funnel_statistics) return;

    ops_id->funnel_statistics->emitSetDisplayFilter(filter_string);
}

char* funnel_statistics_get_color_filter_slot(uint8_t filter_num) {
    return color_filters_get_tmp(filter_num);
}

void funnel_statistics_set_color_filter_slot(uint8_t filter_num, const char* filter_string) {
    char *err_msg = nullptr;
    if (!color_filters_set_tmp(filter_num, filter_string, false, &err_msg)) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err_msg);
        g_free(err_msg);
    }
}

bool funnel_statistics_open_file(funnel_ops_id_t *ops_id, const char* fname, const char* filter, char**) {
    // XXX We need to return a proper error value. We should probably move
    // MainWindow::openCaptureFile to CaptureFile and add error handling
    // there.
    if (!ops_id || !ops_id->funnel_statistics) return false;

    QString cf_name(fname);
    QString cf_filter(filter);
    ops_id->funnel_statistics->emitOpenCaptureFile(cf_name, cf_filter);
    return true;
}

void funnel_statistics_reload_packets(funnel_ops_id_t *ops_id) {
    if (!ops_id || !ops_id->funnel_statistics) return;

    ops_id->funnel_statistics->reloadPackets();
}

void funnel_statistics_redissect_packets(funnel_ops_id_t *ops_id) {
    if (!ops_id || !ops_id->funnel_statistics) return;

    ops_id->funnel_statistics->redissectPackets();
}

void funnel_statistics_reload_lua_plugins(funnel_ops_id_t *ops_id) {
    if (!ops_id || !ops_id->funnel_statistics) return;

    ops_id->funnel_statistics->reloadLuaPlugins();
}

void funnel_statistics_apply_filter(funnel_ops_id_t *ops_id) {
    if (!ops_id || !ops_id->funnel_statistics) return;

    ops_id->funnel_statistics->emitApplyDisplayFilter();
}

bool browser_open_url(const char *url) {
    return QDesktopServices::openUrl(QUrl(url)) ? true : false;
}

void browser_open_data_file(const char *filename) {
    QDesktopServices::openUrl(QUrl::fromLocalFile(filename));
}

struct progdlg *progress_window_new(funnel_ops_id_t *ops_id, const char* task_title, const char* item_title, bool terminate_is_stop, bool *stop_flag) {
    if (!ops_id || !ops_id->funnel_statistics) return nullptr;

    return ops_id->funnel_statistics->progressDialogNew(task_title, item_title, terminate_is_stop, stop_flag);
}

void progress_window_update(struct progdlg *progress_dialog, float percentage, const char* status) {
    update_progress_dlg(progress_dialog, percentage, status);
}

void progress_window_destroy(progdlg *progress_dialog) {
    destroy_progress_dlg(progress_dialog);
}

extern "C" {

void register_tap_listener_qt_funnel(void);

static void register_menu_cb(const char *name,
                             register_stat_group_t group,
                             funnel_menu_callback callback,
                             void *callback_data,
                             bool retap)
{
    FunnelAction *funnel_action = new FunnelAction(name, callback, callback_data, retap, mainApp);
    if (menus_registered) {
        mainApp->appendDynamicMenuGroupItem(group, funnel_action);
    } else {
        mainApp->addDynamicMenuGroupItem(group, funnel_action);
    }
    if (!funnel_actions_.contains(group)) {
        funnel_actions_[group] = QList<FunnelAction *>();
    }
    funnel_actions_[group] << funnel_action;
}

/*
 * Callback used to register packet menus in the GUI.
 *
 * Creates a new FunnelAction with the Lua
 * callback and stores it in the Wireshark GUI with
 * appendPacketMenu() so it can be retrieved when
 * the packet's context menu is open.
 *
 * @param name packet menu item's name
 * @param required_fields fields required to be present for the packet menu to be displayed
 * @param callback function called when the menu item is invoked. The function must take one argument and return nothing.
 * @param callback_data Lua state for the callback function
 * @param retap whether or not to rescan all packets
 */
static void register_packet_menu_cb(const char *name,
                             const char *required_fields,
                             funnel_packet_menu_callback callback,
                             void *callback_data,
                             bool retap)
{
    FunnelAction *funnel_action = new FunnelAction(name, callback, callback_data, retap, required_fields, mainApp);
    MainWindow * mainwindow = qobject_cast<MainWindow *>(mainApp->mainWindow());
    if (mainwindow) {
        mainwindow->appendPacketMenu(funnel_action);
    }
}

static void deregister_menu_cb(funnel_menu_callback callback)
{
    foreach (int group, funnel_actions_.keys()) {
        QList<FunnelAction *>::iterator it = funnel_actions_[group].begin();
        while (it != funnel_actions_[group].end()) {
            FunnelAction *funnel_action = *it;
            if (funnel_action->callback() == callback) {
                // Must set back to title to find the correct sub-menu in Tools
                funnel_action->setText(funnel_action->title());
                mainApp->removeDynamicMenuGroupItem(group, funnel_action);
                it = funnel_actions_[group].erase(it);
            } else {
                ++it;
            }
        }
    }
}

void
register_tap_listener_qt_funnel(void)
{
    funnel_register_all_menus(register_menu_cb);
    funnel_statistics_load_console_menus();
    menus_registered = true;
}

void
funnel_statistics_reload_menus(void)
{
    funnel_reload_menus(deregister_menu_cb, register_menu_cb);
    funnel_statistics_load_packet_menus();
}


/**
 * Returns whether the packet menus have been modified since they were last registered
 *
 * @return true if the packet menus were modified since the last registration
 */
bool
funnel_statistics_packet_menus_modified(void)
{
    return funnel_packet_menus_modified();
}

/*
 * Loads all registered_packet_menus into the
 * Wireshark GUI.
 */
void
funnel_statistics_load_packet_menus(void)
{
    funnel_register_all_packet_menus(register_packet_menu_cb);
}

static void register_console_menu_cb(const char *name,
                                         funnel_console_eval_cb_t eval_cb,
                                         funnel_console_open_cb_t open_cb,
                                         funnel_console_close_cb_t close_cb,
                                         void *callback_data)
{
    FunnelConsoleAction *funnel_action = new FunnelConsoleAction(name, eval_cb,
                                                                open_cb,
                                                                close_cb,
                                                                callback_data,
                                                                mainApp);
    if (menus_registered) {
        mainApp->appendDynamicMenuGroupItem(REGISTER_TOOLS_GROUP_UNSORTED, funnel_action);
    } else {
        mainApp->addDynamicMenuGroupItem(REGISTER_TOOLS_GROUP_UNSORTED, funnel_action);
    }
    if (!funnel_actions_.contains(REGISTER_TOOLS_GROUP_UNSORTED)) {
        funnel_actions_[REGISTER_TOOLS_GROUP_UNSORTED] = QList<FunnelAction *>();
    }
    funnel_actions_[REGISTER_TOOLS_GROUP_UNSORTED] << funnel_action;
}

/*
 * Loads all registered console menus into the
 * Wireshark GUI.
 */
void
funnel_statistics_load_console_menus(void)
{
    funnel_register_all_console_menus(register_console_menu_cb);
}

} // extern "C"
