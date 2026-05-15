/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FUNNELSTATISTICS_H
#define FUNNELSTATISTICS_H

#include <QObject>
#include <QAction>
#include <QSet>
#include <QPointer>

#include <epan/funnel.h>
#include "io_console_dialog.h"
#include "capture_file.h"
#include <ui/qt/filter_action.h>

struct _funnel_ops_t;
struct progdlg;

/**
 * Signature of function that can be called from a custom packet menu entry
 */
typedef void (* funnel_packet_menu_callback)(void *, GPtrArray*);

/**
 * @brief Manages statistics and user interface interactions for Lua-based funnel plugins.
 */
class FunnelStatistics : public QObject
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new FunnelStatistics object.
     * @param parent The parent QObject.
     * @param cf The capture file associated with the statistics.
     */
    explicit FunnelStatistics(QObject *parent, CaptureFile &cf);

    /**
     * @brief Destroys the FunnelStatistics object.
     */
    ~FunnelStatistics();

    /**
     * @brief Retaps all packets in the capture file.
     */
    void retapPackets();

    /**
     * @brief Creates a new progress dialog for funnel operations.
     * @param task_title The title of the overall task.
     * @param item_title The title of the current item being processed.
     * @param terminate_is_stop True if terminating the dialog implies stopping the task.
     * @param stop_flag Pointer to a boolean flag set when the user requests a stop.
     * @return A pointer to the created progress dialog structure.
     */
    struct progdlg *progressDialogNew(const char *task_title, const char *item_title, bool terminate_is_stop, bool *stop_flag);

    /**
     * @brief Retrieves the current display filter.
     * @return The display filter string.
     */
    const char *displayFilter();

    /**
     * @brief Emits a signal to set the display filter in the main UI.
     * @param filter The filter string to apply.
     */
    void emitSetDisplayFilter(const QString filter);

    /**
     * @brief Triggers a reload of the packets in the capture file.
     */
    void reloadPackets();

    /**
     * @brief Triggers redissection of the packets.
     */
    void redissectPackets();

    /**
     * @brief Reloads all registered Lua plugins.
     */
    void reloadLuaPlugins();

    /**
     * @brief Emits a signal to apply the prepared display filter.
     */
    void emitApplyDisplayFilter();

    /**
     * @brief Emits a signal to open a new capture file.
     * @param cf_path The path to the capture file.
     * @param filter An optional display filter to apply upon opening.
     */
    void emitOpenCaptureFile(QString cf_path, QString filter);

    /**
     * @brief Retrieves the standard action name for the funnel statistics.
     * @return The action name string.
     */
    static const QString &actionName() { return action_name_; }

    /**
     * @brief Loads and initializes the funnel menus based on registered plugins.
     */
    void loadInitFunnelMenus();

signals:
    /**
     * @brief Signal emitted to request opening a capture file.
     * @param cf_path The path to the capture file.
     * @param filter The filter to apply.
     */
    void openCaptureFile(QString cf_path, QString filter);

    /**
     * @brief Signal emitted to request setting a display filter.
     * @param filter The filter string.
     * @param action The filter action to perform.
     * @param filterType The type of the filter action.
     */
    void setDisplayFilter(QString filter, FilterAction::Action action, FilterAction::ActionType filterType);

public slots:
    /**
     * @brief Slot triggered when a funnel action is executed from the UI.
     */
    void funnelActionTriggered();

    /**
     * @brief Slot triggered when the text in the display filter field changes.
     * @param filter The new filter string.
     */
    void displayFilterTextChanged(const QString &filter);

private:
    /** The standard action name identifier. */
    static const QString action_name_;

    /** Pointer to the core funnel operations structure. */
    struct _funnel_ops_t *funnel_ops_;

    /** Pointer to the funnel operations ID structure. */
    struct _funnel_ops_id_t *funnel_ops_id_;

    /** Reference to the underlying capture file. */
    CaptureFile &capture_file_;

    /** The active display filter stored as a byte array. */
    QByteArray display_filter_;

    /** The currently prepared but not necessarily applied filter. */
    QString prepared_filter_;
};

/**
 * @brief An action representing a specific funnel menu or packet menu command.
 */
class FunnelAction : public QAction
{
    Q_OBJECT
public:
    /**
     * @brief Constructs an empty FunnelAction.
     * @param parent The parent QObject, defaults to nullptr.
     */
    FunnelAction(QObject *parent = nullptr);

    /**
     * @brief Constructs a FunnelAction for a general menu callback.
     * @param title The title of the action.
     * @param callback The callback function to execute.
     * @param callback_data User data to pass to the callback.
     * @param retap True if execution requires retapping packets.
     * @param parent The parent QObject.
     */
    FunnelAction(QString title, funnel_menu_callback callback, void *callback_data, bool retap, QObject *parent);

    /**
     * @brief Constructs a FunnelAction for a packet-specific menu callback.
     * @param title The title of the action.
     * @param callback The packet-specific callback function to execute.
     * @param callback_data User data to pass to the callback.
     * @param retap True if execution requires retapping packets.
     * @param packet_required_fields Comma-separated list of required fields.
     * @param parent The parent QObject.
     */
    FunnelAction(QString title, funnel_packet_menu_callback callback, void *callback_data, bool retap, const char *packet_required_fields, QObject *parent);

    /**
     * @brief Destroys the FunnelAction.
     */
    ~FunnelAction();

    /**
     * @brief Retrieves the standard menu callback.
     * @return The callback function pointer.
     */
    funnel_menu_callback callback() const;

    /**
     * @brief Retrieves the title of the action.
     * @return The title string.
     */
    QString title() const;

    /**
     * @brief Triggers the associated callback based on the action type.
     */
    virtual void triggerCallback();

    /**
     * @brief Sets the packet-specific menu callback.
     * @param packet_callback The callback function pointer.
     */
    void setPacketCallback(funnel_packet_menu_callback packet_callback);

    /**
     * @brief Sets the packet data required by the packet callback.
     * @param finfos Pointer array containing field info data.
     */
    void setPacketData(GPtrArray* finfos);

    /**
     * @brief Adds this action to a specific context menu hierarchy.
     * @param ctx_menu The root context menu.
     * @param menuTextToMenus Map tracking submenus to build the hierarchy.
     */
    void addToMenu(QMenu * ctx_menu, QHash<QString, QMenu *> &menuTextToMenus);

    /**
     * @brief Sets the fields required for the packet callback to be active.
     * @param required_fields_str Comma-separated list of required fields.
     */
    void setPacketRequiredFields(const char *required_fields_str);

    /**
     * @brief Retrieves the set of required packet fields.
     * @return A set of required field name strings.
     */
    const QSet<QString> getPacketRequiredFields();

    /**
     * @brief Checks if executing this action requires a retap.
     * @return True if retap is required, false otherwise.
     */
    bool retap();

    /**
     * @brief Retrieves the path/hierarchy for packet submenus.
     * @return The packet submenu string.
     */
    QString getPacketSubmenus();

public slots:
    /**
     * @brief Slot triggered to execute the packet-specific callback.
     */
    void triggerPacketCallback();

private:
    /** The title of the action. */
    QString title_;

    /** The submenu hierarchy path for packet context menus. */
    QString packetSubmenu_;

    /** The standard menu callback function. */
    funnel_menu_callback callback_;

    /** User data passed to the callback. */
    void *callback_data_;

    /** Flag indicating whether the action requires a packet retap. */
    bool retap_;

    /** The packet-specific menu callback function. */
    funnel_packet_menu_callback packetCallback_;

    /** Pointer array holding specific packet field information. */
    GPtrArray* packetData_;

    /** The set of required fields for this action to be valid on a packet. */
    QSet<QString> packetRequiredFields_;
};

/**
 * @brief An action that opens and manages a funnel console dialog.
 */
class FunnelConsoleAction : public FunnelAction
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new FunnelConsoleAction.
     * @param name The title or name of the console action.
     * @param eval_cb The callback used to evaluate console input.
     * @param open_cb The callback used when the console is opened.
     * @param close_cb The callback used when the console is closed.
     * @param callback_data User data to pass to the callbacks.
     * @param parent The parent QObject.
     */
    FunnelConsoleAction(QString name, funnel_console_eval_cb_t eval_cb,
                        funnel_console_open_cb_t open_cb,
                        funnel_console_close_cb_t close_cb,
                        void *callback_data, QObject *parent);

    /**
     * @brief Destroys the FunnelConsoleAction.
     */
    ~FunnelConsoleAction();

    /**
     * @brief Triggers the console action, initializing and displaying the dialog.
     */
    virtual void triggerCallback();

private:
    /** The title of the console action. */
    QString title_;

    /** Callback function to handle evaluating console text input. */
    funnel_console_eval_cb_t eval_cb_;

    /** Callback function executed upon opening the console. */
    funnel_console_open_cb_t open_cb_;

    /** Callback function executed upon closing the console. */
    funnel_console_close_cb_t close_cb_;

    /** User data pointer passed to the callbacks. */
    void *callback_data_;

    /** Smart pointer to the associated IO console dialog. */
    QPointer<IOConsoleDialog> dialog_;
};

extern "C" {

    /**
     * @brief Reloads the menus for funnel statistics.
     *
     * This function reloads the menus by deregistering and registering them using the provided callbacks.
     */
    void funnel_statistics_reload_menus(void);

    /**
     * @brief Loads the packet menus for funnel statistics.
     */
    void funnel_statistics_load_packet_menus(void);

    /**
     * @brief Checks if the packet menus for funnel statistics have been modified.
     *
     * @return true if the packet menus have been modified, false otherwise.
     */
    bool funnel_statistics_packet_menus_modified(void);
} // extern "C"

#endif // FUNNELSTATISTICS_H
