/* wireshark_application.h
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

#ifndef WIRESHARK_APPLICATION_H
#define WIRESHARK_APPLICATION_H

#include <config.h>

#include <glib.h>

#include "register.h"

#include "ui/help_url.h"

#include <QApplication>
#include <QDir>
#include <QFont>
#include <QIcon>
#include <QTimer>
#include <QTranslator>

struct _e_prefs;

class QAction;
class QSocketNotifier;

// Recent items:
// - Read from prefs
// - Add from open file
// - Check current list
// - Signal updated item
// -
typedef struct _recent_item_status {
    QString filename;
    qint64 size;
    bool accessible;
    bool in_thread;
} recent_item_status;

class WiresharkApplication : public QApplication
{
    Q_OBJECT
public:
    explicit WiresharkApplication(int &argc,  char **argv);

    enum AppSignal {
        ColumnsChanged,
        CaptureFilterListChanged,
        DisplayFilterListChanged,
        FilterExpressionsChanged,
        NameResolutionChanged,
        PacketDissectionChanged,
        PreferencesChanged,
        RecentFilesRead,
        FieldsChanged
    };

    void registerUpdate(register_action_e action, const char *message);
    void emitAppSignal(AppSignal signal);
    // Emitting app signals (PacketDissectionChanged in particular) from
    // dialogs on OS X can be problematic. Dialogs should call queueAppSignal
    // instead.
    void queueAppSignal(AppSignal signal) { app_signals_ << signal; }
    // Flush queued app signals. Should be called from the main window after
    // each dialog that calls queueAppSignal closes.
    void flushAppSignals();
    void emitStatCommandSignal(const QString &menu_path, const char *arg, void *userdata);
    void emitTapParameterSignal(const QString cfg_abbr, const QString arg, void *userdata);
    void addDynamicMenuGroupItem(int group, QAction *sg_action);
    void appendDynamicMenuGroupItem(int group, QAction *sg_action);
    void removeDynamicMenuGroupItem(int group, QAction *sg_action);
    QList<QAction *> dynamicMenuGroupItems(int group);
    QList<QAction *> addedMenuGroupItems(int group);
    QList<QAction *> removedMenuGroupItems(int group);
    void clearAddedMenuGroupItems();
    void clearRemovedMenuGroupItems();

    void allSystemsGo();
    void refreshLocalInterfaces();
    struct _e_prefs * readConfigurationFiles(char **gdp_path, char **dp_path, bool reset);
    QList<recent_item_status *> recentItems() const;
    void addRecentItem(const QString filename, qint64 size, bool accessible);
    QDir lastOpenDir();
    void setLastOpenDir(const char *dir_name);
    void setLastOpenDir(QString *dir_str);
    void helpTopicAction(topic_action_e action);
    const QFont monospaceFont() const { return mono_font_; }
    void setMonospaceFont(const char *font_string);
    int monospaceTextSize(const char *str);
    void setConfigurationProfile(const gchar *profile_name);
    void reloadLuaPluginsDelayed();
    bool isInitialized() { return initialized_; }
    void setReloadingLua(bool is_reloading) { is_reloading_lua_ = is_reloading; }
    bool isReloadingLua() { return is_reloading_lua_; }
    const QIcon &normalIcon() const { return normal_icon_; }
    const QIcon &captureIcon() const { return capture_icon_; }
    const QString &windowTitleSeparator() const { return window_title_separator_; }
    const QString windowTitleString(QStringList title_parts);
    const QString windowTitleString(QString title_part) { return windowTitleString(QStringList() << title_part); }
    void applyCustomColorsFromRecent();

    QTranslator translator;
    QTranslator translatorQt;
    void loadLanguage(const QString language);

private:
    bool initialized_;
    bool is_reloading_lua_;
    QFont mono_font_;
    QTimer recent_timer_;
    QTimer addr_resolv_timer_;
    QTimer tap_update_timer_;
    QList<QString> pending_open_files_;
    QSocketNotifier *if_notifier_;
    QIcon normal_icon_;
    QIcon capture_icon_;
    static QString window_title_separator_;
    QList<AppSignal> app_signals_;
    int active_captures_;
    void storeCustomColorsInRecent();

protected:
    bool event(QEvent *event);

signals:
    void appInitialized();
    void localInterfaceListChanged();
    void openCaptureFile(QString cf_path, QString display_filter, unsigned int type);
    void recentFilesRead();
    void updateRecentItemStatus(const QString &filename, qint64 size, bool accessible);
    void splashUpdate(register_action_e action, const char *message);
    void profileChanging();
    void profileNameChanged(const gchar *profile_name);

    void columnsChanged(); // XXX This recreates the packet list. We might want to rename it accordingly.
    void captureFilterListChanged();
    void displayFilterListChanged();
    void filterExpressionsChanged();
    void packetDissectionChanged();
    void preferencesChanged();
    void addressResolutionChanged();
    void checkDisplayFilter();
    void fieldsChanged();
    void reloadLuaPlugins();

    void openStatCommandDialog(const QString &menu_path, const char *arg, void *userdata);
    void openTapParameterDialog(const QString cfg_str, const QString arg, void *userdata);

public slots:
    void clearRecentItems();
    void captureFileReadStarted();
    void captureStarted() { active_captures_++; }
    void captureFinished() { active_captures_--; }
    void updateTaps();

private slots:
    void cleanup();
    void ifChangeEventsAvailable();
    void itemStatusFinished(const QString filename = "", qint64 size = 0, bool accessible = false);
    void refreshRecentFiles(void);
    void refreshAddressResolution(void);
};

extern WiresharkApplication *wsApp;

/** Global compile time version string */
extern void get_wireshark_qt_compiled_info(GString *str);
extern void get_gui_compiled_info(GString *str);
/** Global runtime version string */
extern void get_wireshark_runtime_info(GString *str);
#endif // WIRESHARK_APPLICATION_H

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
