/* funnel_statistics.cpp
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

#include "config.h"

#include <glib.h>

#include "epan/color_filters.h"
#include "file.h"

#include "epan/funnel.h"
#include "epan/prefs.h"

#include "ui/progress_dlg.h"
#include "ui/simple_dialog.h"

#include "funnel_statistics.h"
#include "funnel_string_dialog.h"
#include "funnel_text_dialog.h"

#include <QAction>
#include <QClipboard>
#include <QDebug>
#include <QDesktopServices>
#include <QUrl>

#include "wireshark_application.h"

// To do:
// - Handle menu paths. Do we create a new path (GTK+) or use the base element?
// - Add a FunnelGraphDialog class?

extern "C" {
static void funnel_statistics_logger(const gchar *, GLogLevelFlags, const gchar *message, gpointer);
static void funnel_statistics_retap_packets(funnel_ops_id_t *ops_id);
static void funnel_statistics_copy_to_clipboard(GString *text);
static const gchar *funnel_statistics_get_filter(funnel_ops_id_t *ops_id);
static void funnel_statistics_set_filter(funnel_ops_id_t *ops_id, const char* filter_string);
static void funnel_statistics_set_color_filter_slot(guint8 filter_num, const gchar* filter_string);
static gboolean funnel_statistics_open_file(funnel_ops_id_t *ops_id, const char* fname, const char* filter, char**);
static void funnel_statistics_reload_packets(funnel_ops_id_t *ops_id);
static void funnel_statistics_reload_lua_plugins(funnel_ops_id_t *ops_id);
static void funnel_statistics_apply_filter(funnel_ops_id_t *ops_id);
static gboolean browser_open_url(const gchar *url);
static void browser_open_data_file(const gchar *filename);
static struct progdlg *progress_window_new(funnel_ops_id_t *ops_id, const gchar* title, const gchar* task, gboolean terminate_is_stop, gboolean *stop_flag);
static void progress_window_update(struct progdlg *progress_dialog, float percentage, const gchar* status);
static void progress_window_destroy(struct progdlg *progress_dialog);
}

class FunnelAction : public QAction
{
public:
    FunnelAction(const QString title, funnel_menu_callback callback, gpointer callback_data, gboolean retap) :
        QAction(NULL),
        title_(title),
        callback_(callback),
        callback_data_(callback_data),
        retap_(retap)
    {
        setText(title);
        setObjectName(FunnelStatistics::actionName());
    }

    funnel_menu_callback callback() const {
        return callback_;
    }

    QString title() const {
        return title_;
    }

    void triggerCallback() {
        if (callback_) {
            callback_(callback_data_);
        }
    }

    bool retap() {
        if (retap_) return true;
        return false;
    }

private:
    QString title_;
    funnel_menu_callback callback_;
    gpointer callback_data_;
    gboolean retap_;
};

static QHash<int, QList<FunnelAction *> > funnel_actions_;
const QString FunnelStatistics::action_name_ = "FunnelStatisticsAction";
static gboolean menus_registered = FALSE;

FunnelStatistics::FunnelStatistics(QObject *parent, CaptureFile &cf) :
    QObject(parent),
    capture_file_(cf)
{
    funnel_ops_ = new(struct _funnel_ops_t);
    memset(funnel_ops_, 0, sizeof(struct _funnel_ops_t));

    funnel_ops_->ops_id = (funnel_ops_id_t*) this;
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
    funnel_ops_->logger = funnel_statistics_logger;
    funnel_ops_->retap_packets = funnel_statistics_retap_packets;
    funnel_ops_->copy_to_clipboard = funnel_statistics_copy_to_clipboard;
    funnel_ops_->get_filter = funnel_statistics_get_filter;
    funnel_ops_->set_filter = funnel_statistics_set_filter;
    funnel_ops_->set_color_filter_slot = funnel_statistics_set_color_filter_slot;
    funnel_ops_->open_file = funnel_statistics_open_file;
    funnel_ops_->reload_packets = funnel_statistics_reload_packets;
    funnel_ops_->reload_lua_plugins = funnel_statistics_reload_lua_plugins;
    funnel_ops_->apply_filter = funnel_statistics_apply_filter;
    funnel_ops_->browser_open_url = browser_open_url;
    funnel_ops_->browser_open_data_file = browser_open_data_file;
    funnel_ops_->new_progress_window = progress_window_new;
    funnel_ops_->update_progress = progress_window_update;
    funnel_ops_->destroy_progress_window = progress_window_destroy;

    funnel_set_funnel_ops(funnel_ops_);
}

void FunnelStatistics::retapPackets()
{
    capture_file_.retapPackets();
}

struct progdlg *FunnelStatistics::progressDialogNew(const gchar *task_title, const gchar *item_title, gboolean terminate_is_stop, gboolean *stop_flag)
{
    return create_progress_dlg(capture_file_.window(), task_title, item_title, terminate_is_stop, stop_flag);
}

const char *FunnelStatistics::displayFilter()
{
    return display_filter_.constData();
}

void FunnelStatistics::emitSetDisplayFilter(const QString filter)
{
    emit setDisplayFilter(filter);
}

void FunnelStatistics::reloadPackets()
{
    capture_file_.reload();
}

void FunnelStatistics::reloadLuaPlugins()
{
    wsApp->reloadLuaPluginsDelayed();
}

void FunnelStatistics::emitApplyDisplayFilter()
{
    emit applyDisplayFilter();
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


/* The GTK+ code says "finish this." We shall follow its lead */
// XXX Finish this.
void funnel_statistics_logger(const gchar *,
                          GLogLevelFlags,
                          const gchar *message,
                          gpointer) {
    qDebug() << message;
}

void funnel_statistics_retap_packets(funnel_ops_id_t *ops_id) {
    FunnelStatistics *funnel_statistics = dynamic_cast<FunnelStatistics *>((FunnelStatistics *)ops_id);
    if (!funnel_statistics) return;

    funnel_statistics->retapPackets();
}

void funnel_statistics_copy_to_clipboard(GString *text) {
    wsApp->clipboard()->setText(text->str);
}

const gchar *funnel_statistics_get_filter(funnel_ops_id_t *ops_id) {
    FunnelStatistics *funnel_statistics = dynamic_cast<FunnelStatistics *>((FunnelStatistics *)ops_id);
    if (!funnel_statistics) return NULL;

    return funnel_statistics->displayFilter();
}

void funnel_statistics_set_filter(funnel_ops_id_t *ops_id, const char* filter_string) {
    FunnelStatistics *funnel_statistics = dynamic_cast<FunnelStatistics *>((FunnelStatistics *)ops_id);
    if (!funnel_statistics) return;

    funnel_statistics->emitSetDisplayFilter(filter_string);
}

void funnel_statistics_set_color_filter_slot(guint8 filter_num, const gchar* filter_string) {
    gchar *err_msg = NULL;
    if (!color_filters_set_tmp(filter_num, (gchar *)filter_string, FALSE, &err_msg)) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err_msg);
        g_free(err_msg);
    }
}

gboolean funnel_statistics_open_file(funnel_ops_id_t *ops_id, const char* fname, const char* filter, char**) {
    // XXX We need to return a proper error value. We should probably move
    // MainWindow::openCaptureFile to CaptureFile and add error handling
    // there.
    FunnelStatistics *funnel_statistics = dynamic_cast<FunnelStatistics *>((FunnelStatistics *)ops_id);
    if (!funnel_statistics) return FALSE;

    QString cf_name(fname);
    QString cf_filter(filter);
    funnel_statistics->emitOpenCaptureFile(cf_name, cf_filter);
    return TRUE;
}

void funnel_statistics_reload_packets(funnel_ops_id_t *ops_id) {
    FunnelStatistics *funnel_statistics = dynamic_cast<FunnelStatistics *>((FunnelStatistics *)ops_id);
    if (!funnel_statistics) return;

    funnel_statistics->reloadPackets();
}

void funnel_statistics_reload_lua_plugins(funnel_ops_id_t *ops_id) {
    FunnelStatistics *funnel_statistics = dynamic_cast<FunnelStatistics *>((FunnelStatistics *)ops_id);
    if (!funnel_statistics) return;

    funnel_statistics->reloadLuaPlugins();
}

void funnel_statistics_apply_filter(funnel_ops_id_t *ops_id) {
    FunnelStatistics *funnel_statistics = dynamic_cast<FunnelStatistics *>((FunnelStatistics *)ops_id);
    if (!funnel_statistics) return;

    funnel_statistics->emitApplyDisplayFilter();
}

gboolean browser_open_url(const gchar *url) {
    return QDesktopServices::openUrl(QUrl(url)) ? TRUE : FALSE;
}

void browser_open_data_file(const gchar *filename) {
    QDesktopServices::openUrl(QUrl::fromLocalFile(filename));
}

struct progdlg *progress_window_new(funnel_ops_id_t *ops_id, const gchar* task_title, const gchar* item_title, gboolean terminate_is_stop, gboolean *stop_flag) {
    FunnelStatistics *funnel_statistics = dynamic_cast<FunnelStatistics *>((FunnelStatistics *)ops_id);
    if (!funnel_statistics) return NULL;

    return funnel_statistics->progressDialogNew(task_title, item_title, terminate_is_stop, stop_flag);
}

void progress_window_update(struct progdlg *progress_dialog, float percentage, const gchar* status) {
    update_progress_dlg(progress_dialog, percentage, status);
}

void progress_window_destroy(progdlg *progress_dialog) {
    destroy_progress_dlg(progress_dialog);
}

extern "C" {

static void register_menu_cb(const char *name,
                             register_stat_group_t group,
                             funnel_menu_callback callback,
                             gpointer callback_data,
                             gboolean retap)
{
    FunnelAction *funnel_action = new FunnelAction(name, callback, callback_data, retap);
    if (menus_registered) {
        wsApp->appendDynamicMenuGroupItem(group, funnel_action);
    } else {
        wsApp->addDynamicMenuGroupItem(group, funnel_action);
    }
    if (!funnel_actions_.contains(group)) {
        funnel_actions_[group] = QList<FunnelAction *>();
    }
    funnel_actions_[group] << funnel_action;
}

static void deregister_menu_cb(funnel_menu_callback callback)
{
    foreach (int group, funnel_actions_.uniqueKeys()) {
        QList<FunnelAction *>::iterator it = funnel_actions_[group].begin();
        while (it != funnel_actions_[group].end()) {
            FunnelAction *funnel_action = *it;
            if (funnel_action->callback() == callback) {
                // Must set back to title to find the correct sub-menu in Tools
                funnel_action->setText(funnel_action->title());
                wsApp->removeDynamicMenuGroupItem(group, funnel_action);
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
    menus_registered = TRUE;
}

void
funnel_statistics_reload_menus(void)
{
    funnel_reload_menus(deregister_menu_cb, register_menu_cb);
}

} // extern "C"

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
