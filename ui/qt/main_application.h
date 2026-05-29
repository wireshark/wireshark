/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MAIN_APPLICATION_H
#define MAIN_APPLICATION_H

#include <config.h>

#include "wsutil/feature_list.h"

#include "ui/help_url.h"

#include <QApplication>
#include <QDir>
#include <QFont>
#include <QIcon>
#include <QTimer>
#include <QTranslator>

#include "capture_event.h"

struct _e_prefs;

class QAction;
class QSocketNotifier;

class MainWindow;

/**
 * @brief Core application class handling global state, signals, and configurations.
 */
class MainApplication : public QApplication
{
    Q_OBJECT
public:
    /**
     * @brief Constructs the MainApplication.
     * @param argc Reference to the argument count.
     * @param argv Array of argument strings.
     */
    explicit MainApplication(int &argc,  char **argv);

    /**
     * @brief Destroys the MainApplication.
     */
    ~MainApplication();

    /**
     * @brief Enumeration of application-wide signals.
     */
    enum AppSignal {
        /** @brief Capture filter list changed. */
        CaptureFilterListChanged,
        /** @brief Packet list columns changed. */
        ColumnsChanged,
        /** @brief Display filter list changed. */
        DisplayFilterListChanged,
        /** @brief Protocol fields changed. */
        FieldsChanged,
        /** @brief Filter expressions changed. */
        FilterExpressionsChanged,
        /** @brief Local interfaces changed. */
        LocalInterfacesChanged,
        /** @brief Name resolution configuration changed. */
        NameResolutionChanged,
        /** @brief Packet dissection preferences changed. */
        PacketDissectionChanged,
        /** @brief General preferences changed. */
        PreferencesChanged,
        /** @brief Recent preferences have been read. */
        RecentPreferencesRead,
        /** @brief Freeze the packet list updates. */
        FreezePacketList,
        /** @brief Aggregation logic or values changed. */
        AggregationChanged
    };

    /**
     * @brief Enumeration for standard main menu items.
     */
    enum MainMenuItem {
        /** @brief The file open dialog action. */
        FileOpenDialog,
        /** @brief The capture options dialog action. */
        CaptureOptionsDialog
    };

    /**
     * @brief Enumeration for status bar information types.
     */
    enum StatusInfo {
        /** @brief Filter syntax status. */
        FilterSyntax,
        /** @brief Protocol field status. */
        FieldStatus,
        /** @brief File operations status. */
        FileStatus,
        /** @brief Application busy status. */
        BusyStatus,
        /** @brief Byte loading/processing status. */
        ByteStatus,
        /** @brief General temporary status message. */
        TemporaryStatus
    };

    /**
     * @brief Emits a specific application signal.
     * @param signal The AppSignal to emit.
     */
    void emitAppSignal(AppSignal signal);

    /**
     * @brief Queues an application signal to be emitted later.
     *
     * Emitting app signals (PacketDissectionChanged in particular) from
     * dialogs on macOS can be problematic. Dialogs should call queueAppSignal
     * instead.
     * On macOS, nested event loops (e.g., calling a dialog with exec())
     * that call processEvents (e.g., from PacketDissectionChanged, or
     * anything with a ProgressFrame) caused issues off and on from 5.3.0
     * until 5.7.1/5.8.0. It appears to be solved after some false starts:
     * https://bugreports.qt.io/browse/QTBUG-53947
     * https://bugreports.qt.io/browse/QTBUG-56746
     * We also try to avoid exec / additional event loops as much as possible:
     * e.g., commit f67eccedd9836e6ced1f57ae9889f57a5400a3d7
     * (note it can show up in unexpected places, e.g. static functions like
     * WiresharkFileDialog::getOpenFileName())
     *
     * @param signal The AppSignal to queue.
     */
    void queueAppSignal(AppSignal signal) { app_signals_ << signal; }

    /**
     * @brief Emits a signal to execute a statistics command.
     * @param menu_path The menu path associated with the command.
     * @param arg The argument string for the command.
     * @param userdata Pointer to additional user data.
     */
    void emitStatCommandSignal(const QString &menu_path, const char *arg, void *userdata);

    /**
     * @brief Emits a signal indicating tap parameters changed.
     * @param cfg_abbr Configuration abbreviation string.
     * @param arg Tap argument string.
     * @param userdata Pointer to additional user data.
     */
    void emitTapParameterSignal(const QString cfg_abbr, const QString arg, void *userdata);

    /**
     * @brief Adds an action item to a dynamic menu group.
     * @param group The menu group ID.
     * @param sg_action The action to add.
     */
    void addDynamicMenuGroupItem(int group, QAction *sg_action);

    /**
     * @brief Appends an action item to a dynamic menu group.
     * @param group The menu group ID.
     * @param sg_action The action to append.
     */
    void appendDynamicMenuGroupItem(int group, QAction *sg_action);

    /**
     * @brief Removes an action item from a dynamic menu group.
     * @param group The menu group ID.
     * @param sg_action The action to remove.
     */
    void removeDynamicMenuGroupItem(int group, QAction *sg_action);

    /**
     * @brief Retrieves all action items for a dynamic menu group.
     * @param group The menu group ID.
     * @return A list of QAction pointers.
     */
    QList<QAction *> dynamicMenuGroupItems(int group);

    /**
     * @brief Retrieves items recently added to a dynamic menu group.
     * @param group The menu group ID.
     * @return A list of added QAction pointers.
     */
    QList<QAction *> addedMenuGroupItems(int group);

    /**
     * @brief Retrieves items recently removed from a dynamic menu group.
     * @param group The menu group ID.
     * @return A list of removed QAction pointers.
     */
    QList<QAction *> removedMenuGroupItems(int group);

    /**
     * @brief Clears the list of tracked added menu group items.
     */
    void clearAddedMenuGroupItems();

    /**
     * @brief Clears the list of tracked removed menu group items.
     */
    void clearRemovedMenuGroupItems();

    /**
     * @brief Indicates that initial setup is complete and all systems are operational.
     */
    void allSystemsGo();

    /**
     * @brief Emits a signal regarding local interface status changes.
     * @param ifname The name of the interface.
     * @param added Indicator if the interface was added.
     * @param up Indicator if the interface is up.
     */
    void emitLocalInterfaceEvent(const char *ifname, int added, int up);

    /**
     * @brief Refreshes the local interfaces list.
     */
    virtual void refreshLocalInterfaces();

#ifdef HAVE_LIBPCAP
    /**
     * @brief Retrieves the cached interface list.
     *
     * This returns a deep copy of the cached interface list that must
     * be freed with free_interface_list.
     *
     * @return A deep copy of the interface list.
     */
    GList * getInterfaceList() const;

    /**
     * @brief Sets the cached interface list.
     *
     * This sets the cached interface list to a deep copy of if_list.
     *
     * @param if_list The interface list to set.
     */
    void setInterfaceList(GList *if_list);
#endif

    /**
     * @brief Reads application configuration files.
     * @param reset Whether to reset preferences to defaults.
     * @return Pointer to the read preferences structure.
     */
    struct _e_prefs * readConfigurationFiles(bool reset);

    /**
     * @brief Retrieves the initial directory for open dialogs.
     * @return The QDir representing the initial directory.
     */
    QDir openDialogInitialDir();

    /**
     * @brief Sets the last opened directory from a given filename.
     * @param file_name The path to the file.
     */
    void setLastOpenDirFromFilename(QString file_name);

    /**
     * @brief Executes a help topic action.
     * @param action The specific topic action to execute.
     */
    void helpTopicAction(topic_action_e action);

    /**
     * @brief Retrieves the monospace font used by the application.
     * @param zoomed True if the zoomed font is requested.
     * @return The requested QFont.
     */
    const QFont monospaceFont(bool zoomed = false) const;

    /**
     * @brief Calculates the horizontal pixel size of a string using the monospace font.
     * @param str The string to measure.
     * @return The size in pixels.
     */
    int monospaceTextSize(const char *str);

    /**
     * @brief Sets the active configuration profile.
     * @param profile_name The name of the profile.
     * @param write_recent_file True to save the choice to recent files.
     */
    void setConfigurationProfile(const char *profile_name, bool write_recent_file = true);

    /**
     * @brief Triggers a delayed reload of Lua plugins.
     */
    void reloadLuaPluginsDelayed();

    /**
     * @brief Checks if the application is initialized.
     * @return True if initialized, false otherwise.
     */
    bool isInitialized() { return initialized_; }

    /**
     * @brief Sets the flag indicating if Lua is currently reloading.
     * @param is_reloading True if reloading, false otherwise.
     */
    void setReloadingLua(bool is_reloading) { is_reloading_lua_ = is_reloading; }

    /**
     * @brief Checks if Lua plugins are currently reloading.
     * @return True if reloading, false otherwise.
     */
    bool isReloadingLua() { return is_reloading_lua_; }

    /**
     * @brief Retrieves the normal application icon.
     * @return The normal QIcon.
     */
    const QIcon &normalIcon();

    /**
     * @brief Retrieves the capture application icon.
     * @return The capture QIcon.
     */
    const QIcon &captureIcon();

    /**
     * @brief Retrieves the window title separator string.
     * @return The separator string.
     */
    const QString &windowTitleSeparator() const { return window_title_separator_; }

    /**
     * @brief Generates a window title from parts.
     * @param title_parts The parts to combine into the title.
     * @return The combined window title string.
     */
    const QString windowTitleString(QStringList title_parts);

    /**
     * @brief Generates a window title with a single part.
     * @param title_part The part to prepend to the default title.
     * @return The combined window title string.
     */
    const QString windowTitleString(QString title_part) { return windowTitleString(QStringList() << title_part); }

    /**
     * @brief Applies custom colors stored in recent files.
     */
    void applyCustomColorsFromRecent();

    /**
     * @brief Retrieves the main window instance.
     * @return Pointer to the MainWindow.
     */
    MainWindow *mainWindow();

    /** Main Qt application translator. */
    QTranslator translator;

    /** Base Qt translator for standard strings. */
    QTranslator translatorQt;

    /**
     * @brief Loads a specific UI language.
     * @param language The language code to load.
     */
    void loadLanguage(const QString language);

    /**
     * @brief Triggers a specific main menu item.
     * @param menuItem The MainMenuItem to trigger.
     */
    void doTriggerMenuItem(MainMenuItem menuItem);

    /**
     * @brief Applies text zooming to application fonts.
     * @param zoomLevel The level to zoom by.
     */
    void zoomTextFont(int zoomLevel);

    /**
     * @brief Pushes a message to the specified status bar section.
     * @param sinfo The StatusInfo type.
     * @param message The text message to display.
     * @param messagetip Optional tooltip for the status.
     */
    void pushStatus(StatusInfo sinfo, const QString &message, const QString &messagetip = QString());

    /**
     * @brief Pops the most recent status message of a given type.
     * @param sinfo The StatusInfo type to clear.
     */
    void popStatus(StatusInfo sinfo);

    /**
     * @brief Triggers navigation to a specific frame number.
     * @param frameNum The frame number to navigate to.
     */
    void gotoFrame(int frameNum);

    /**
     * @brief Defines the maximum nested depth allowed for menus.
     * @return The maximum menu depth.
     */
    int maxMenuDepth(void) { return 5; }

private:
    /** Indicates if the application initialization has completed. */
    bool initialized_;

    /** Indicates if Lua plugins are currently in the process of reloading. */
    bool is_reloading_lua_;

    /** The actively zoomed monospace font. */
    QFont zoomed_font_;

    /** Timer for throttling packet data updates. */
    QTimer packet_data_timer_;

    /** Timer for throttling tap updates. */
    QTimer tap_update_timer_;

    /** List of file paths pending to be opened. */
    QList<QString> pending_open_files_;

    /** Notifier for interface socket events. */
    QSocketNotifier *if_notifier_;

    /** Separator used when constructing window titles. */
    static QString window_title_separator_;

    /** Queue of pending application signals to process. */
    QList<AppSignal> app_signals_;

    /** Count of currently active captures. */
    int active_captures_;

    /** Flag indicating a local interface refresh is pending. */
    bool refresh_interfaces_pending_;

    /**
     * @brief Stores the user's custom colors into the recent configuration.
     */
    void storeCustomColorsInRecent();

    /**
     * @brief Clears all dynamically added menu group items.
     */
    void clearDynamicMenuGroupItems();

protected:
    /**
     * @brief Core Qt event handler override.
     * @param event The event to process.
     * @return True if handled, false otherwise.
     */
    bool event(QEvent *event);

    /**
     * @brief Pure virtual method for initializing application icons.
     */
    virtual void initializeIcons() = 0;

    /** Icon for standard application state. */
    QIcon normal_icon_;

    /** Icon for active capture state. */
    QIcon capture_icon_;

#ifdef HAVE_LIBPCAP
    /** Cached pointer to the GList of interfaces. */
    GList *cached_if_list_;
#endif

signals:
    /** @brief Signal emitted when application is fully initialized. */
    void appInitialized();
    /** @brief Signal emitted for local interface events (add/remove/up/down). */
    void localInterfaceEvent(const char *ifname, int added, int up);
    /** @brief Signal emitted to request a scan of local interfaces. */
    void scanLocalInterfaces(GList *filter_list = nullptr);
    /** @brief Signal emitted when the local interface list changes. */
    void localInterfaceListChanged();
    /** @brief Signal emitted to open a specific capture file. */
    void openCaptureFile(QString cf_path, QString display_filter, unsigned int type);
    /** @brief Signal emitted to open the capture options dialog. */
    void openCaptureOptions();
    /** @brief Signal emitted when recent preferences are read. */
    void recentPreferencesRead();
    /** @brief Signal emitted while the configuration profile is changing. */
    void profileChanging();
    /** @brief Signal emitted when the configuration profile name has changed. */
    void profileNameChanged(const char *profile_name);

    /** @brief Signal emitted to freeze or unfreeze packet list updates. */
    void freezePacketList(bool changing_profile);
    /**
     * @brief Signal emitted when columns are changed (recreates packet list).
     *        XXX This recreates the packet list. We might want to rename it accordingly.
     */
    void columnsChanged();
    /** @brief Signal emitted when capture filters are changed. */
    void captureFilterListChanged();
    /** @brief Signal emitted when display filters are changed. */
    void displayFilterListChanged();
    /** @brief Signal emitted when filter expressions are changed. */
    void filterExpressionsChanged();
    /** @brief Signal emitted when packet dissection settings are changed. */
    void packetDissectionChanged();
    /** @brief Signal emitted when preferences are changed. */
    void preferencesChanged();
    /** @brief Signal emitted when address resolution settings change. */
    void addressResolutionChanged();
    /** @brief Signal emitted when column data definitions change. */
    void columnDataChanged();
    /** @brief Signal emitted to check display filter validity. */
    void checkDisplayFilter();
    /** @brief Signal emitted when protocol fields change. */
    void fieldsChanged();
    /** @brief Signal emitted to initiate a Lua plugin reload. */
    void reloadLuaPlugins();
    /** @brief Signal emitted when aggregation values change. */
    void aggregationChanged();

    /** @brief Signal emitted to open a specific stat command dialog. */
    void openStatCommandDialog(const QString &menu_path, const char *arg, void *userdata);
    /** @brief Signal emitted to open a tap parameter dialog. */
    void openTapParameterDialog(const QString cfg_str, const QString arg, void *userdata);

    /** @brief Signals activation and stop of a capture. The value provides the number of active captures. */
    void captureActive(int);

    /** @brief Signal emitted to apply a new zoomed regular font. */
    void zoomRegularFont(const QFont & font);
    /** @brief Signal emitted to apply a new zoomed monospace font. */
    void zoomMonospaceFont(const QFont & font);

public slots:
    /**
     * @brief Slot for handling capture events.
     * @param ev The capture event to process.
     */
    void captureEventHandler(CaptureEvent ev);

    /**
     * @brief Flushes queued app signals.
     *
     * Should be called from the main window after each dialog that calls
     * queueAppSignal closes.
     */
    void flushAppSignals();

    /**
     * @brief Reloads display filter macros.
     */
    void reloadDisplayFilterMacros();

private slots:
    /**
     * @brief Triggers an update on active taps.
     */
    void updateTaps();

    /**
     * @brief Cleans up application resources before closing.
     */
    void cleanup();

    /**
     * @brief Slot called when interface change events are available.
     */
    void ifChangeEventsAvailable();

    /**
     * @brief Refreshes data currently presented in the packet view.
     */
    void refreshPacketData();

};

extern MainApplication *mainApp;

/** Global compile time version info */

/**
 * @brief Gather compiled information for Wireshark Qt components.
 *
 * @param l Feature list to store the gathered information.
 */
extern void gather_wireshark_qt_compiled_info(feature_list l);
/** Global runtime version info */

/**
 * @brief Gather runtime information for Wireshark.
 *
 * @param l Feature list to store the gathered information.
 */
extern void gather_wireshark_runtime_info(feature_list l);
#endif // MAIN_APPLICATION_H
