/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WIRESHARK_MAIN_WINDOW_H
#define WIRESHARK_MAIN_WINDOW_H

/** @defgroup main_window_group Main window
 * The main window has the following submodules:
   @dot
  digraph main_dependencies {
      node [shape=record, fontname=Helvetica, fontsize=10];
      main [ label="main window" URL="\ref main.h"];
      menu [ label="menubar" URL="\ref menus.h"];
      toolbar [ label="toolbar" URL="\ref main_toolbar.h"];
      packet_list [ label="packet list pane" URL="\ref packet_list.h"];
      proto_draw [ label="packet details & bytes panes" URL="\ref main_proto_draw.h"];
      recent [ label="recent user settings" URL="\ref recent.h"];
      main -> menu [ arrowhead="open", style="solid" ];
      main -> toolbar [ arrowhead="open", style="solid" ];
      main -> packet_list [ arrowhead="open", style="solid" ];
      main -> proto_draw [ arrowhead="open", style="solid" ];
      main -> recent [ arrowhead="open", style="solid" ];
  }
  @enddot
 */

/** @file
 *  The Wireshark main window
 *  @ingroup main_window_group
 *  @ingroup windows_group
 */

#include <stdio.h>

#include <config.h>

#include "ui/ws_ui_util.h"
#include "ui/iface_toolbar.h"
#ifdef HAVE_LIBPCAP
#include "ui/capture_opts.h"
#endif
#include "ui/plugins/include/plugin_if.h"

#include <epan/timestamp.h>

#include <capture/capture_session.h>

#include <QMainWindow>
#include <QPointer>

#ifdef _WIN32
# include <QTimer>
#else
# include <QSocketNotifier>
#endif

#include "capture_file_dialog.h"
#include "capture_file_properties_dialog.h"
#include <ui/qt/utils/field_information.h>
#include <ui/qt/widgets/display_filter_entry.h>
#include "main_window.h"
#include "rtp_stream_dialog.h"
#include "rtp_analysis_dialog.h"
#include "tlskeylog_launcher_dialog.h"

class AccordionFrame;
class DataSourceTab;
class CaptureOptionsDialog;
class DisStreamDialog;
class PrintDialog;
class FileSetDialog;
class FilterDialog;
class FunnelStatistics;
class WelcomePage;
class PacketCommentDialog;
class PacketDiagram;
class PacketList;
class ProtoTree;
#if defined(HAVE_LIBNL) && defined(HAVE_NL80211)
class WirelessFrame;
#endif
class FilterExpressionToolBar;
class WiresharkApplication;

class QAction;
class QActionGroup;

namespace Ui {
    class WiresharkMainWindow;
}

Q_DECLARE_METATYPE(ts_type)
Q_DECLARE_METATYPE(ts_precision)

/**
 * @brief Wireshark main application window, extending MainWindow with the full
 *        Wireshark feature set including live capture, telephony analysis,
 *        RTP stream handling, wireless tools, and plugin/Lua integration.
 */
class WiresharkMainWindow : public MainWindow
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the Wireshark main window and initialises all menus,
     *        toolbars, and UI components.
     * @param parent Optional parent widget.
     */
    explicit WiresharkMainWindow(QWidget *parent = nullptr);

    /**
     * @brief Destroys the main window and releases all associated resources.
     */
    ~WiresharkMainWindow();

#ifdef HAVE_LIBPCAP
    /**
     * @brief Returns a pointer to the active capture session.
     * @return Pointer to the internal capture_session structure.
     */
    capture_session *captureSession() { return &cap_session_; }

    /**
     * @brief Returns a pointer to the live capture info data structure.
     * @return Pointer to the internal info_data_t structure.
     */
    info_data_t *captureInfoData() { return &info_data_; }
#endif

    /**
     * @brief Creates and returns the window's right-click popup menu.
     * @return Pointer to the newly created QMenu; caller takes ownership.
     */
    QMenu *createPopupMenu() override;

    /**
     * @brief Returns a pointer to the current capture file object.
     * @return Pointer to the internal CaptureFile instance.
     */
    CaptureFile *captureFile() { return &capture_file_; }

    /**
     * @brief Rebuilds the Lua funnel statistics menus from registered funnel entries.
     */
    void setFunnelMenus(void);

    /**
     * @brief Removes an additional (plugin/interface) toolbar by name.
     * @param toolbarName Display name of the toolbar to remove.
     */
    void removeAdditionalToolbar(QString toolbarName);

    /**
     * @brief Adds an interface toolbar for the given toolbar descriptor.
     * @param toolbar_entry Descriptor of the interface toolbar to add.
     */
    void addInterfaceToolbar(const iface_toolbar *toolbar_entry);

    /**
     * @brief Removes the interface toolbar with the given menu title.
     * @param menu_title NUL-terminated display title of the toolbar to remove.
     */
    void removeInterfaceToolbar(const char *menu_title);

    /**
     * @brief Returns the file path currently shown in the main window title bar.
     * @return File path string, or an empty string if no file is open.
     */
    QString getMwFileName();

    /**
     * @brief Sets the file path shown in the main window title bar.
     * @param fileName New file path string.
     */
    void setMwFileName(QString fileName);

protected:
    /**
     * @brief Filters events on watched objects (e.g. focus changes on child widgets).
     * @param obj   Object that received the event.
     * @param event The event to inspect.
     * @return @c true to suppress the event; @c false to pass it on.
     */
    bool eventFilter(QObject *obj, QEvent *event) override;

    /**
     * @brief Handles window-level events such as activation changes.
     * @param event The event to process.
     * @return @c true if the event was handled; @c false otherwise.
     */
    bool event(QEvent *event) override;

    /**
     * @brief Handles key press events for global keyboard shortcuts.
     * @param event The key event to process.
     */
    void keyPressEvent(QKeyEvent *event) override;

    /**
     * @brief Prompts the user to save unsaved changes before closing the window.
     * @param event The close event; call ignore() to cancel.
     */
    void closeEvent(QCloseEvent *event) override;

    /**
     * @brief Accepts drag-enter events for capture files dragged onto the window.
     * @param event The drag-enter event.
     */
    void dragEnterEvent(QDragEnterEvent *event) override;

    /**
     * @brief Opens a capture file dropped onto the window.
     * @param event The drop event carrying the file URL(s).
     */
    void dropEvent(QDropEvent *event) override;

    /**
     * @brief Responds to locale or palette changes by retranslating the UI.
     * @param event The change event.
     */
    void changeEvent(QEvent *event) override;

    /**
     * @brief Opens the given recent capture file, handling any necessary prompts.
     * @param filename Absolute path of the recent capture file to open.
     */
    void openRecentCaptureFile(const QString &filename) override;

    /**
     * @brief Attempts to close the current capture file, prompting the user to
     *        save if there are unsaved changes.
     * @param before_what Human-readable description of the action requiring the close.
     * @param context     Context hint that affects the save prompt behaviour.
     * @return @c true if the file was closed or had no unsaved changes; @c false if cancelled.
     */
    bool tryClosingCaptureFile(QString before_what, FileCloseContext context = Default) override;

private:
    /**
     * @brief Controls how a selected field's display-filter expression is combined
     *        with the current filter when "match selected" actions are triggered.
     */
    enum MatchSelected {
        MatchSelectedReplace,  /**< Replace the current filter entirely. */
        MatchSelectedAnd,      /**< AND the new expression with the current filter. */
        MatchSelectedOr,       /**< OR the new expression with the current filter. */
        MatchSelectedNot,      /**< Negate the new expression only. */
        MatchSelectedAndNot,   /**< AND the negated expression with the current filter. */
        MatchSelectedOrNot     /**< OR the negated expression with the current filter. */
    };

    Ui::WiresharkMainWindow   *main_ui_;              /**< Qt Designer-generated UI object. */
    QFont                      mono_font_;             /**< Monospace font used for hex/byte displays. */
#if defined(HAVE_LIBNL) && defined(HAVE_NL80211)
    WirelessFrame             *wireless_frame_;        /**< Wireless toolbar frame for 802.11 channel control. */
#endif
    QWidget                   *previous_focus_;        /**< Widget that held focus before an overlay or dialog was shown. */
    FileSetDialog             *file_set_dialog_;       /**< Modeless file-set management dialog. */
    QActionGroup              *show_hide_actions_;     /**< Action group for show/hide main-widget toggle actions. */
    QActionGroup              *time_display_actions_;  /**< Action group for timestamp display format actions. */
    QActionGroup              *time_precision_actions_;/**< Action group for timestamp precision actions. */
    FunnelStatistics          *funnel_statistics_;     /**< Lua funnel statistics manager. */
    QAction                   *action_telephony_dis_streams_; /**< Telephony → DIS Streams menu action. */
    QList<QPair<QAction *, bool>> freeze_actions_;     /**< Actions whose enabled state is saved and restored around freeze/thaw. */
    QPointer<QWidget>          freeze_focus_;          /**< Widget to restore focus to after thawing. */
    QMap<QAction *, ts_type>   td_actions;             /**< Map from timestamp-display menu actions to ts_type values. */
    QMap<QAction *, ts_precision> tp_actions;          /**< Map from timestamp-precision menu actions to ts_precision values. */
    bool                       was_maximized_;         /**< @c true if the window was maximised before going full-screen. */

    /* the following values are maintained so that the capture file name and status
    is available when there is no cf structure available */

    QString mwFileName_; /**< Cached capture file path used when no cf structure is available. */

    bool capture_stopping_;     /**< @c true while a live capture stop is in progress. */
    bool capture_filter_valid_; /**< @c true if the current capture filter expression is syntactically valid. */
#ifdef HAVE_LIBPCAP
    capture_session            cap_session_;             /**< Active libpcap capture session. */
    CaptureOptionsDialog      *capture_options_dialog_;  /**< Modeless capture options dialog. */
    info_data_t                info_data_;               /**< Live capture statistics updated during capture. */
#endif

    QPoint dragStartPosition; /**< Mouse position recorded at the start of a drag operation. */

    QPointer<TLSKeylogDialog> tlskeylog_dialog_; /**< Modeless TLS keylog dialog; null when not open. */

    /**
     * @brief Freezes the packet list and disables UI elements during long operations.
     */
    void freeze();

    /**
     * @brief Restores the packet list and re-enables UI elements after freeze().
     */
    void thaw();

    /**
     * @brief Opens the merge-capture-file dialog and merges the selected file
     *        into the current capture.
     */
    void mergeCaptureFile();

    /**
     * @brief Opens the import-capture-file dialog and imports packets from a
     *        hex dump or other non-native format.
     */
    void importCaptureFile();

    /**
     * @brief Saves the capture file to its current path.
     * @param cf           Capture file to save.
     * @param dont_reopen  @c true to skip reopening the file after saving.
     * @return @c true on success.
     */
    bool saveCaptureFile(capture_file *cf, bool dont_reopen);

    /**
     * @brief Opens a save-as dialog and saves the capture file to a new path.
     * @param cf                    Capture file to save.
     * @param must_support_comments @c true to restrict the format list to formats
     *                              that support packet comments.
     * @param dont_reopen           @c true to skip reopening the file after saving.
     * @return @c true on success.
     */
    bool saveAsCaptureFile(capture_file *cf, bool must_support_comments = false, bool dont_reopen = false);

    /**
     * @brief Opens the export-selected-packets dialog and exports the current
     *        selection to a new capture file.
     */
    void exportSelectedPackets();

    /**
     * @brief Opens the export-dissections dialog for the given format.
     * @param export_type Target export format (CSV, JSON, plain text, etc.).
     */
    void exportDissections(export_type_e export_type);

    /**
     * @brief Enables or disables the packet aggregation view.
     * @param enable @c true to enable; @c false to disable.
     */
    void enableAggregationView(bool enable) const;

#ifdef Q_OS_WIN
    /**
     * @brief Appends the appropriate file extension for the given file type and
     *        compression type to @p file_name on Windows.
     * @param file_name        File name string to modify in-place.
     * @param file_type        Wiretap file type subtype.
     * @param compression_type Compression type to apply.
     */
    void fileAddExtension(QString &file_name, int file_type, ws_compression_type compression_type);
#endif

    /**
     * @brief Sends a stop-capture request to the capture engine.
     * @param discard @c true to discard all captured packets after stopping.
     */
    void captureStop(bool discard = false);

    /** @brief Loads and assigns icons to the main toolbar actions. */
    void initMainToolbarIcons();

    /** @brief Connects show/hide actions for main UI panels (packet list, tree, bytes). */
    void initShowHideMainWidgets();

    /** @brief Populates and connects the View → Time Display Format submenu. */
    void initTimeDisplayFormatMenu();

    /** @brief Populates and connects the View → Time Display Precision submenu. */
    void initTimePrecisionFormatMenu();

    /** @brief Saves the enabled state of UI actions that must be disabled during freeze. */
    void initFreezeActions();

    /**
     * @brief Updates File and related menu item states for the current capture file.
     * @param force_disable @c true to disable all file-related actions unconditionally.
     */
    void setMenusForCaptureFile(bool force_disable = false) override;

    /**
     * @brief Updates menu and toolbar states for a capture in progress.
     * @param capture_in_progress @c true while a live capture is running.
     */
    void setMenusForCaptureInProgress(bool capture_in_progress = false);

    /** @brief Updates menu states for a capture that is being stopped. */
    void setMenusForCaptureStopping();

    /**
     * @brief Enables or disables actions that require at least one captured packet.
     * @param have_captured_packets @c true if the capture file contains packets.
     */
    void setForCapturedPackets(bool have_captured_packets);

    /**
     * @brief Enables or disables file-set related menu items.
     * @param enable_list_files @c true to enable the "List Files" action.
     */
    void setMenusForFileSet(bool enable_list_files);

    /**
     * @brief Forces a full QSS stylesheet reload, e.g. after theme changes.
     */
    void updateStyleSheet();

    /**
     * @brief Recursively populates @p subMenu from an ext_menu_t tree.
     * @param menu    Root of the external menu descriptor tree.
     * @param subMenu Qt menu to populate.
     * @param depth   Current recursion depth; used to cap nesting.
     */
    void externalMenuHelper(ext_menu_t *menu, QMenu *subMenu, int depth);

    /**
     * @brief Updates toolbar visibility and interface-toolbar state for
     *        capture-in-progress transitions.
     * @param capture_in_progress @c true while a live capture is running.
     * @param handle_toolbars     @c true to also update interface toolbar states.
     * @param ifaces              Array of active interfaces; may be @c NULL.
     */
    void setForCaptureInProgress(bool capture_in_progress = false, bool handle_toolbars = false, GArray *ifaces = NULL);

    /**
     * @brief Finds an existing submenu matching the given path parts under
     *        @p parent_menu, or creates it if it does not exist.
     * @param parent_menu Parent menu to search or extend.
     * @param menu_parts  Ordered list of submenu title components.
     * @return Pointer to the found or newly created QMenu.
     */
    QMenu *findOrAddMenu(QMenu *parent_menu, const QStringList &menu_parts);

    /**
     * @brief Finds a top-level menu bar entry by display text, or creates it
     *        if it does not already exist.
     * @param menu_text Display text of the menu bar entry to find or create.
     * @return Pointer to the found or newly created QMenu.
     */
    QMenu *findOrAddMenubar(const QString menu_text);

    /**
     * @brief Updates status bar and UI elements when a capture file read begins.
     * @param action Human-readable description of the read action (e.g. "Opening").
     */
    void captureFileReadStarted(const QString &action);

    /**
     * @brief Recursively adds @p action and all its children to @p cur_menu.
     * @param action   Action (and sub-tree) to add.
     * @param cur_menu Target menu to insert into.
     */
    void addMenusandSubmenus(QAction *action, QMenu *cur_menu);

    /**
     * @brief Recursively removes @p action and all its children from @p cur_menu.
     * @param action   Action (and sub-tree) to remove.
     * @param cur_menu Source menu to remove from.
     */
    void removeMenusandSubmenus(QAction *action, QMenu *cur_menu);

    /**
     * @brief Adds a list of actions to the menu group identified by @p menu_group.
     * @param actions    Actions to insert.
     * @param menu_group Target menu group identifier.
     */
    void addMenuActions(QList<QAction *> &actions, int menu_group);

    /**
     * @brief Removes a list of actions from the menu group identified by @p menu_group.
     * @param actions    Actions to remove.
     * @param menu_group Source menu group identifier.
     */
    void removeMenuActions(QList<QAction *> &actions, int menu_group);

    /**
     * @brief Navigates to the next or previous packet in the same conversation.
     * @param go_next       @c true to go forward; @c false to go backward.
     * @param start_current @c true to include the current packet as the search origin.
     */
    void goToConversationFrame(bool go_next, bool start_current = true);

    /**
     * @brief Applies a colouring rule with the given filter expression to matching packets.
     * @param filter       Display-filter expression for the colouring rule.
     * @param color_number Colour slot index (1–10); -1 for a temporary rule.
     */
    void colorizeWithFilter(QByteArray filter, int color_number = -1);

signals:
    /**
     * @brief Emitted when a dissected capture file becomes the active file.
     * @param cf Pointer to the newly active capture file.
     */
    void setDissectedCaptureFile(capture_file *cf);

    /** @brief Emitted to request that all packet-detail dialogs close themselves. */
    void closePacketDialogs();

    /** @brief Emitted to request that all views reload their field definitions. */
    void reloadFields();

    /**
     * @brief Emitted when the selected packet changes, providing the new packet info.
     * @param pinfo Packet info for the newly selected packet.
     */
    void packetInfoChanged(struct _packet_info *pinfo);

    /**
     * @brief Emitted when the field-based display filter changes.
     * @param field_filter New field filter expression as a byte array.
     */
    void fieldFilterChanged(const QByteArray field_filter);

    /**
     * @brief Emitted to request that an RTP stream be selected in all interested dialogs.
     * @param id RTP stream identifier to select.
     */
    void selectRtpStream(rtpstream_id_t *id);

    /**
     * @brief Emitted to request that an RTP stream be deselected in all interested dialogs.
     * @param id RTP stream identifier to deselect.
     */
    void deselectRtpStream(rtpstream_id_t *id);

#ifdef HAVE_LIBPCAP
    /**
     * @brief Emitted to open the extcap options dialog for a specific interface.
     * @param device_name         Name of the extcap interface.
     * @param startCaptureOnClose @c true to start capturing when the dialog is accepted.
     */
    void showExtcapOptions(QString &device_name, bool startCaptureOnClose);
#endif

public slots:
    // Qt lets you connect signals and slots using functors (new, manual style)
    // and strings (old style). Functors are preferred since they're connected at
    // compile time and less error prone.
    //
    // If you're manually connecting a signal to a slot, don't prefix its name
    // with "on_". Otherwise Qt will try to automatically connect it and you'll
    // get runtime warnings.

    // in main_window_slots.cpp

    /**
     * @brief Opens a capture file.
     * @param cf_path        Path to the capture file to open.
     * @param display_filter Display filter to apply after opening; may be empty.
     * @param type           Wiretap file type hint (use WTAP_TYPE_AUTO for auto-detection).
     * @param is_tempfile    @c true if the file is a temporary capture file.
     * @return @c true on success; @c false on failure.
     */
    bool openCaptureFile(QString cf_path, QString display_filter, unsigned int type, bool is_tempfile = false);

    /**
     * @brief Convenience overload that auto-detects file type.
     * @param cf_path        Path to the capture file; empty opens a file dialog.
     * @param display_filter Display filter to apply; may be empty.
     * @return @c true on success; @c false on failure.
     */
    bool openCaptureFile(QString cf_path = QString(), QString display_filter = QString()) { return openCaptureFile(cf_path, display_filter, WTAP_TYPE_AUTO); }

    /**
     * @brief Applies a new display filter to the open capture file.
     * @param new_filter New filter expression; empty string shows all packets.
     * @param force      @c true to reapply even if the filter is unchanged.
     */
    void filterPackets(QString new_filter = QString(), bool force = false) override;

    /** @brief Repositions and resizes toolbars according to current layout settings. */
    void layoutToolbars();

    /** @brief Refreshes menu items that reflect preference values. */
    void updatePreferenceActions();

    /** @brief Rebuilds the File → Open Recent submenu from the recent-files list. */
    void updateRecentActions();

    /**
     * @brief Refreshes the packet aggregation view to reflect the current capture state.
     */
    void updateAggregationView() const;

    /** @brief Updates the window title bar to reflect the current capture file name and state. */
    void setTitlebarForCaptureFile();

    /** @brief Opens the capture options dialog (interface selection, filters, etc.). */
    void showCaptureOptionsDialog();

#ifdef HAVE_LIBPCAP
    /**
     * @brief Called when the capture engine has finished preparing a new capture session.
     * @param session The newly prepared capture session.
     */
    void captureCapturePrepared(capture_session *session);

    /**
     * @brief Called when a live capture session starts delivering packets.
     * @param session The active capture session.
     */
    void captureCaptureUpdateStarted(capture_session *session);

    /**
     * @brief Called when a live (updating) capture session finishes.
     * @param session The finished capture session.
     */
    void captureCaptureUpdateFinished(capture_session *session);

    /**
     * @brief Called when a fixed-length capture session finishes.
     * @param cap_session The finished capture session.
     */
    void captureCaptureFixedFinished(capture_session *cap_session);

    /**
     * @brief Called when a capture session fails to start or terminates with an error.
     */
    void captureCaptureFailed(capture_session *);
#endif

    /** @brief Updates UI state when a capture file is first opened. */
    void captureFileOpened();

    /** @brief Updates UI state after a capture file has been fully read. */
    void captureFileReadFinished();

    /** @brief Updates UI state while a capture file is being closed. */
    void captureFileClosing();

    /** @brief Resets UI state after a capture file has been fully closed. */
    void captureFileClosed();

    /**
     * @brief Opens the LTE RLC graph dialog for a specific channel.
     * @param channelKnown @c true if all channel parameters are known and should be applied immediately.
     * @param RAT          Radio access technology (e.g. LTE).
     * @param ueid         UE identifier.
     * @param rlcMode      RLC mode (TM, UM, or AM).
     * @param channelType  Logical channel type.
     * @param channelId    Logical channel ID.
     * @param direction    Traffic direction (uplink or downlink).
     */
    void launchRLCGraph(bool channelKnown, uint8_t RAT, uint16_t ueid, uint8_t rlcMode,
                        uint16_t channelType, uint16_t channelId, uint8_t direction);

#ifdef HAVE_LUA
    /** @brief Opens the Lua debugger dialog. */
    void openLuaDebuggerDialog();
#endif

    /**
     * @brief Replaces all streams in the RTP Player dialog with the given stream list.
     * @param stream_ids Vector of RTP stream identifiers to set.
     */
    void rtpPlayerDialogReplaceRtpStreams(QVector<rtpstream_id_t *> stream_ids);

    /**
     * @brief Adds streams to the RTP Player dialog.
     * @param stream_ids Vector of RTP stream identifiers to add.
     */
    void rtpPlayerDialogAddRtpStreams(QVector<rtpstream_id_t *> stream_ids);

    /**
     * @brief Removes streams from the RTP Player dialog.
     * @param stream_ids Vector of RTP stream identifiers to remove.
     */
    void rtpPlayerDialogRemoveRtpStreams(QVector<rtpstream_id_t *> stream_ids);

    /**
     * @brief Replaces all streams in the RTP Analysis dialog with the given stream list.
     * @param stream_ids Vector of RTP stream identifiers to set.
     */
    void rtpAnalysisDialogReplaceRtpStreams(QVector<rtpstream_id_t *> stream_ids);

    /**
     * @brief Adds streams to the RTP Analysis dialog.
     * @param stream_ids Vector of RTP stream identifiers to add.
     */
    void rtpAnalysisDialogAddRtpStreams(QVector<rtpstream_id_t *> stream_ids);

    /**
     * @brief Removes streams from the RTP Analysis dialog.
     * @param stream_ids Vector of RTP stream identifiers to remove.
     */
    void rtpAnalysisDialogRemoveRtpStreams(QVector<rtpstream_id_t *> stream_ids);

    /**
     * @brief Selects the given streams in the RTP Streams dialog.
     * @param stream_ids Vector of RTP stream identifiers to select.
     */
    void rtpStreamsDialogSelectRtpStreams(QVector<rtpstream_id_t *> stream_ids);

    /**
     * @brief Deselects the given streams in the RTP Streams dialog.
     * @param stream_ids Vector of RTP stream identifiers to deselect.
     */
    void rtpStreamsDialogDeselectRtpStreams(QVector<rtpstream_id_t *> stream_ids);

private slots:
    /**
     * @brief Dispatches capture lifecycle events to the appropriate UI update methods.
     * @param ev The capture event to handle.
     */
    void captureEventHandler(CaptureEvent ev);

    /** @brief Populates the View → Colorize Conversation submenu with colour rules. */
    void initViewColorizeMenu();

    /** @brief Populates the Statistics → Conversations submenu with protocol entries. */
    void initConversationMenus();

    /**
     * @brief QHash foreach callback that adds a single "Export Objects" menu item.
     * @param key      Protocol key (unused).
     * @param value    Protocol value providing the menu item details.
     * @param userdata Pointer to the target QMenu.
     * @return @c false to continue iteration.
     */
    static bool addExportObjectsMenuItem(const void *key, void *value, void *userdata);

    /** @brief Populates the File → Export Objects submenu with registered dissectors. */
    void initExportObjectsMenus();

    /**
     * @brief QHash foreach callback that adds a single "Follow Stream" menu item.
     * @param key      Protocol key (unused).
     * @param value    Protocol value providing the menu item details.
     * @param userdata Pointer to the target QMenu.
     * @return @c false to continue iteration.
     */
    static bool addFollowStreamMenuItem(const void *key, void *value, void *userdata);

    /** @brief Populates the Analyze → Follow submenu with registered stream followers. */
    void initFollowStreamMenus();

    /**
     * @brief Starts a live capture on the given interfaces.
     * @param interfaces List of interface names to capture on.
     */
    void startCapture(QStringList interfaces);

    /** @brief Starts a live capture using the currently selected interfaces and filter. */
    void startCapture();

    /** @brief Pushes a "capture in progress" indicator onto the status bar. */
    void pushLiveCaptureInProgress();

    /** @brief Pops the "capture in progress" indicator from the status bar. */
    void popLiveCaptureInProgress();

    /** @brief Sends a stop-capture request and updates UI state. */
    void stopCapture();

    /**
     * @brief Responds to aggregation view enable/disable toggle.
     * @param enable @c true if the aggregation view was enabled.
     */
    void aggregationViewChanged(bool enable) const;

    /** @brief Restores window geometry (position, size, maximised state) from preferences. */
    void loadWindowGeometry();

    /** @brief Saves current window geometry to preferences. */
    void saveWindowGeometry();

    /**
     * @brief Switches the central stacked widget to a new page.
     */
    void mainStackChanged(int);

    /** @brief Rebuilds the File → Open Recent submenu. */
    void updateRecentCaptures();

    /** @brief Opens the add-packet-comment dialog for the selected packet. */
    void addPacketComment();

    /** @brief Opens the edit-packet-comment dialog for the selected packet. */
    void editPacketComment();

    /** @brief Deletes the selected comment from the selected packet. */
    void deletePacketComment();

    /** @brief Deletes all comments from all packets in the capture file. */
    void deleteCommentsFromPackets();

    /**
     * @brief Returns a truncated version of @p text suitable for a menu item label.
     * @param text    Comment text to truncate.
     * @param max_len Maximum character length before truncation with ellipsis.
     * @return Truncated comment string.
     */
    QString commentToMenuText(QString text, int max_len = 40);

    /** @brief Rebuilds the Edit → Packet Comment submenu from the selected packet's comments. */
    void setEditCommentsMenu();

    /** @brief Updates menu and toolbar items that depend on the selected packet. */
    void setMenusForSelectedPacket();

    /**
     * @brief Updates menu and toolbar items that depend on the selected protocol-tree row.
     * @param fi FieldInformation for the selected row; @c NULL if no row is selected.
     */
    void setMenusForSelectedTreeRow(FieldInformation *fi = NULL);

    /** @brief Updates capture-start availability when the interface selection changes. */
    void interfaceSelectionChanged();

    /**
     * @brief Updates the start-capture button and menu item based on filter validity.
     * @param valid @c true if the current capture filter is syntactically valid.
     */
    void captureFilterSyntaxChanged(bool valid);

    /** @brief Forces a full re-dissection of all packets in the capture file. */
    void redissectPackets();

    /** @brief Validates the current display filter and updates the filter bar state. */
    void checkDisplayFilter();

    /** @brief Responds to protocol-field registration changes by refreshing dependent UI. */
    void fieldsChanged();

    /** @brief Reloads all Lua plugins and re-dissects the capture file. */
    void reloadLuaPlugins();

    /**
     * @brief Shows or toggles an AccordionFrame panel.
     * @param show_frame The AccordionFrame to show.
     * @param toggle     @c true to hide the frame if it is already visible.
     */
    void showAccordionFrame(AccordionFrame *show_frame, bool toggle = false);

    /**
     * @brief Opens the column editor for the given packet-list column.
     * @param column Zero-based column index to edit.
     */
    void showColumnEditor(int column);

    /** @brief Opens the preferences editor for the most-recently-selected protocol preference. */
    void showPreferenceEditor();

    /** @brief Adds registered statistics plugin menu items to the Statistics menu. */
    void addStatsPluginsToMenu();

    /** @brief Adds all dynamic (plugin/Lua) menu items to the appropriate menus. */
    void addDynamicMenus();

    /** @brief Removes and re-adds all dynamic menu items to pick up registration changes. */
    void reloadDynamicMenus();

    /** @brief Adds plugin interface toolbar and menu structures to the UI. */
    void addPluginIFStructures();

    /**
     * @brief Searches the menu hierarchy for a submenu with the given object name.
     * @param objectName Qt object name to search for.
     * @return Pointer to the matching QMenu, or @c nullptr if not found.
     */
    QMenu *searchSubMenu(QString objectName);

    /**
     * @brief Activates or deactivates a plugin interface toolbar.
     */
    void activatePluginIFToolbar(bool);

    /**
     * @brief Initiates a capture on a single interface once the filter has been validated.
     * @param valid          @c true if the capture filter is valid.
     * @param capture_filter Capture filter expression to apply.
     */
    void startInterfaceCapture(bool valid, const QString capture_filter);

    /** @brief Applies command-line options (filter, read file, etc.) that were deferred
     *         until the main window was fully constructed. */
    void applyGlobalCommandLineOptions();

    /**
     * @brief Enables or disables the majority of UI actions as a group.
     * @param enabled @c true to enable all feature actions; @c false to disable them.
     */
    void setFeaturesEnabled(bool enabled = true);

    /** @brief Opens the "New Display Filter Expression" editor dialog. */
    void on_actionNewDisplayFilterExpression_triggered();

    /**
     * @brief Applies or prepends a filter selected from the filter toolbar drop-down.
     * @param filterText  The selected filter expression.
     * @param prepare      @c true if the filter should be prepared for editing rather than applied immediately.
     */
    void onFilterSelected(QString filterText, bool prepare);

    /** @brief Opens the display-filter preferences page. */
    void onFilterPreferences();

    /**
     * @brief Opens the UAT editor for the display filter at the given index.
     * @param uatIndex Row index within the display-filter UAT.
     */
    void onFilterEdit(int uatIndex);

    /**
     * @brief Handles a queued FilterAction by applying it to the current display filter.
     * @param filter The filter expression to apply.
     * @param action The action to perform (apply, prepare, etc.).
     * @param type   The action type (selected, not selected, etc.).
     */
    void queuedFilterAction(QString filter, FilterAction::Action action, FilterAction::ActionType type);

    /**
     * @brief Opens a statistics dialog identified by a menu path and "-z" argument.
     * @param menu_path Partial menu/slot path identifying the statistics dialog.
     * @param arg       The "-z" argument string for the statistics tap.
     * @param userdata  Optional user data passed to the dialog constructor.
     */
    void openStatCommandDialog(const QString &menu_path, const char *arg, void *userdata);

    /**
     * @brief Opens a tap parameter dialog identified by configuration and argument strings.
     * @param cfg_str  Configuration string identifying the registered tap dialog.
     * @param arg      The "-z" argument string for the tap.
     * @param userdata Optional user data passed to the dialog constructor.
     */
    void openTapParameterDialog(const QString cfg_str, const QString arg, void *userdata);

    /** @brief Opens the tap parameter dialog for the action that triggered this slot. */
    void openTapParameterDialog();

    /** @brief Connects File menu actions to their implementation slots. */
    void connectFileMenuActions();

    /** @brief Opens the export-packet-bytes dialog to save raw field bytes to disk. */
    void exportPacketBytes();

    /** @brief Opens the Export PDU dialog to export reassembled PDUs to a new capture file. */
    void exportPDU();

    /** @brief Opens the Strip Headers dialog to remove encapsulation layers from packets. */
    void stripPacketHeaders();

    /** @brief Exports TLS session keys from the current capture to a keylog file. */
    void exportTLSSessionKeys();

    /** @brief Opens the print dialog for the current capture file. */
    void printFile();

    /** @brief Connects Edit menu actions to their implementation slots. */
    void connectEditMenuActions();

    /**
     * @brief Copies the selected packet item(s) in the format specified by @p selection_type.
     * @param selection_type Enum value controlling what is copied (summary, bytes, etc.).
     */
    void copySelectedItems(WiresharkMainWindow::CopySelected selection_type);

    /** @brief Opens the Find Packet dialog or focuses it if already open. */
    void findPacket();

    /** @brief Opens the Time Shift dialog for adjusting packet timestamps. */
    void editTimeShift();

    /** @brief Opens the Configuration Profiles management dialog. */
    void editConfigurationProfiles();

    /**
     * @brief Applies or discards a time-shift operation when the dialog closes.
     * @param result QDialog::Accepted to apply; QDialog::Rejected to discard.
     */
    void editTimeShiftFinished(int result);

    /**
     * @brief Applies or discards a new packet comment when the dialog closes.
     * @param pc_dialog The PacketCommentDialog that finished.
     * @param result    QDialog::Accepted to save; QDialog::Rejected to discard.
     */
    void addPacketCommentFinished(PacketCommentDialog *pc_dialog, int result);

    /**
     * @brief Applies or discards an edited packet comment when the dialog closes.
     * @param pc_dialog The PacketCommentDialog that finished.
     * @param result    QDialog::Accepted to save; QDialog::Rejected to discard.
     * @param nComment  Zero-based index of the comment that was edited.
     */
    void editPacketCommentFinished(PacketCommentDialog *pc_dialog, int result, unsigned nComment);

    /** @brief Prompts the user to confirm deletion of all packet comments. */
    void deleteAllPacketComments();

    /**
     * @brief Performs the deletion of all packet comments after user confirmation.
     * @param result QDialog::Accepted to proceed; QDialog::Rejected to cancel.
     */
    void deleteAllPacketCommentsFinished(int result);

    /**
     * @brief Injects a secrets block (e.g. TLS keylog) into the current capture file.
     * @param proto_name Protocol name identifying the secrets type.
     * @param wiki_link  URL of the Wireshark wiki page describing the secrets format.
     */
    void injectSecrets(const char *proto_name, const char *wiki_link);

    /** @brief Prompts the user to confirm discarding all injected secrets. */
    void discardAllSecrets();

    /**
     * @brief Discards all injected secrets after user confirmation.
     * @param result QDialog::Accepted to proceed; QDialog::Rejected to cancel.
     */
    void discardAllSecretsFinished(int result);

    /**
     * @brief Opens the preferences dialog and navigates to the given module.
     * @param module_name Preferences module name to display (e.g. "nameres").
     */
    void showPreferencesDialog(QString module_name) override;

    /** @brief Connects View menu actions to their implementation slots. */
    void connectViewMenuActions();

    /**
     * @brief Shows or hides a main UI widget in response to a toggle action.
     * @param action The triggered show/hide action.
     */
    void showHideMainWidgets(QAction *action);

    /**
     * @brief Changes the timestamp display format in response to a menu action.
     * @param action The triggered timestamp-format action.
     */
    void setTimestampFormat(QAction *action);

    /**
     * @brief Changes the timestamp precision in response to a menu action.
     * @param action The triggered timestamp-precision action.
     */
    void setTimestampPrecision(QAction *action);

    /**
     * @brief Enables or disables display of seconds as HH:MM:SS.
     * @param checked @c true to show seconds with hours and minutes.
     */
    void setTimeDisplaySecondsWithHoursAndMinutes(bool checked);

    /** @brief Opens the edit-resolved-name dialog for the field under the cursor. */
    void editResolvedName();

    /** @brief Applies current name-resolution preference changes to the packet list. */
    void setNameResolution();

    /** @brief Opens the Coloring Rules management dialog. */
    void showColoringRulesDialog();

    /**
     * @brief Colorizes packets matching the current conversation, optionally
     *        creating a permanent colouring rule.
     * @param create_rule @c true to add a permanent colouring rule.
     */
    void colorizeConversation(bool create_rule = false);

    /** @brief Handles a triggered colorize action from the context menu. */
    void colorizeActionTriggered();

    /**
     * @brief Opens the packet details dialog for the selected packet.
     * @param from_reference @c true to open the referenced packet rather than the selected one.
     */
    void openPacketDialog(bool from_reference = false);

    /** @brief Reloads the current capture file, offering a format-change dialog if appropriate. */
    void reloadCaptureFileAsFormatOrCapture();

    /** @brief Reloads the current capture file from disk without prompting. */
    void reloadCaptureFile();

    /** @brief Connects Go menu actions to their implementation slots. */
    void connectGoMenuActions();

    /** @brief Saves and clears the previous-focus pointer when focus moves away. */
    void setPreviousFocus();

    /** @brief Restores keyboard focus to the widget saved by setPreviousFocus(). */
    void resetPreviousFocus();

    /** @brief Connects Capture menu actions to their implementation slots. */
    void connectCaptureMenuActions();

    /** @brief Handles the start-capture menu/toolbar action trigger. */
    void startCaptureTriggered();

    /** @brief Connects Analyze menu actions to their implementation slots. */
    void connectAnalyzeMenuActions();

    /**
     * @brief Constructs a filter expression from the selected protocol-tree field
     *        and applies the given action and type.
     * @param action      Action to perform (apply, prepare, etc.).
     * @param filter_type Combination type (replace, and, or, etc.).
     */
    void matchFieldFilter(FilterAction::Action action, FilterAction::ActionType filter_type);

    /** @brief Adds the currently selected protocol-tree field as a custom column. */
    void applyFieldAsColumn();

    /** @brief Updates filter-menu item states just before the filter menu is shown. */
    void filterMenuAboutToShow();

    /** @brief Applies a conversation filter derived from the selected packet to the display filter. */
    void applyConversationFilter();

    /** @brief Opens an Export Objects dialog for the protocol associated with the triggering action. */
    void applyExportObject();

    /**
     * @brief Opens a Follow Stream dialog for the specified protocol and stream.
     * @param proto_id        Protocol ID of the stream to follow.
     * @param stream_num      Stream index within the protocol.
     * @param sub_stream_num  Sub-stream index (e.g. for HTTP/2 streams).
     * @param use_stream_index @c true to filter by stream index; @c false to filter by endpoints.
     */
    void openFollowStreamDialog(int proto_id, unsigned stream_num, unsigned sub_stream_num, bool use_stream_index = true);

    /**
     * @brief Opens a Follow Stream dialog for the stream containing the selected packet.
     * @param proto_id Protocol ID of the stream to follow.
     */
    void openFollowStreamDialog(int proto_id);

    /**
     * @brief Opens the I/O Graph dialog, optionally pre-populated with conversation filters.
     * @param filtered   @c true to restrict initial series to displayed packets.
     * @param conv_ids   Conversation IDs to pre-populate as graph series.
     * @param conv_agg   Aggregation settings corresponding to each entry in @p conv_ids.
     */
    void openIOGraph(bool filtered, QVector<uint> conv_ids, QVector<QVariant> conv_agg);

    /**
     * @brief Opens the Expert Info statistics dialog.
     */
    void statCommandExpertInfo(const char *, void *);

    /** @brief Connects Help menu actions to their implementation slots. */
    void connectHelpMenuActions();

    /** @brief Handles the Go To dialog Cancel button by dismissing the overlay. */
    void goToCancelClicked();

    /** @brief Handles the Go To dialog Go button by navigating to the entered frame number. */
    void goToGoClicked();

    /** @brief Handles Return/Enter in the Go To line edit by triggering navigation. */
    void goToLineEditReturnPressed();

    /** @brief Connects Statistics menu actions to their implementation slots. */
    void connectStatisticsMenuActions();

    /** @brief Opens the Resolved Addresses dialog. */
    void showResolvedAddressesDialog();

    /** @brief Opens the Conversations statistics dialog. */
    void showConversationsDialog();

    /** @brief Opens the Endpoints statistics dialog. */
    void showEndpointsDialog();

    /**
     * @brief Opens a TCP stream graph dialog for the given graph type.
     * @param graph_type TCP stream graph type constant (e.g. time-sequence, throughput).
     */
    void openTcpStreamDialog(int graph_type);

    /** @brief Opens the SCTP All Associations dialog. */
    void openSCTPAllAssocsDialog();

    /** @brief Triggered by the Show All Associations SCTP menu action. */
    void on_actionSCTPShowAllAssociations_triggered();

    /** @brief Triggered by the Analyse This Association SCTP menu action. */
    void on_actionSCTPAnalyseThisAssociation_triggered();

    /** @brief Triggered by the Filter This Association SCTP menu action. */
    void on_actionSCTPFilterThisAssociation_triggered();

    /**
     * @brief Opens the Multicast Statistics dialog via the stat-command mechanism.
     */
    void statCommandMulticastStatistics(const char *, void *);

    /**
     * @brief Opens the WLAN Statistics dialog via the stat-command mechanism.
     */
    void statCommandWlanStatistics(const char *, void *);

    /**
     * @brief Opens a registered statistics tree dialog by abbreviation.
     * @param abbr Short name of the statistics tree (e.g. "http_tree").
     */
    void openStatisticsTreeDialog(const char *abbr);

    /**
     * @brief Opens the I/O Graph dialog via the stat-command mechanism.
     */
    void statCommandIOGraph(const char *, void *);

    /**
     * @brief Opens the I/O Graph dialog with the specified Y-axis unit and field.
     * @param value_units Y-axis unit type for the initial graph series.
     * @param yfield      Y-axis field name; empty uses the unit's default field.
     */
    void showIOGraphDialog(io_graph_item_unit_t value_units, QString yfield) override;

    /**
     * @brief Opens the Plot dialog for a specific field.
     * @param y_field  Y-axis field name; empty opens the dialog with no pre-set field.
     * @param filtered @c true to restrict the plot to currently displayed packets.
     */
    void showPlotDialog(const QString &y_field = QString(), bool filtered = false) override;

    /** @brief Connects Telephony menu actions to their implementation slots. */
    void connectTelephonyMenuActions();

    /**
     * @brief Opens the DIS Streams telephony dialog.
     * @return Pointer to the opened DisStreamDialog.
     */
    DisStreamDialog *openTelephonyDisStreamsDialog();

    /**
     * @brief Opens the RTP Streams telephony dialog.
     * @return Pointer to the opened RtpStreamDialog.
     */
    RtpStreamDialog *openTelephonyRtpStreamsDialog();

    /**
     * @brief Opens the RTP Player telephony dialog.
     * @return Pointer to the opened RtpPlayerDialog.
     */
    RtpPlayerDialog *openTelephonyRtpPlayerDialog();

    /**
     * @brief Opens the RTP Analysis telephony dialog.
     * @return Pointer to the opened RtpAnalysisDialog.
     */
    RtpAnalysisDialog *openTelephonyRtpAnalysisDialog();

    /**
     * @brief Opens the LTE MAC Statistics dialog via the stat-command mechanism.
     * @param arg      The "-z" argument string.
     */
    void statCommandLteMacStatistics(const char *arg, void *);

    /**
     * @brief Opens the LTE RLC Statistics dialog via the stat-command mechanism.
     * @param arg      The "-z" argument string.
     */
    void statCommandLteRlcStatistics(const char *arg, void *);

    /** @brief Opens the RTP Stream Analysis dialog for the selected RTP stream. */
    void openRtpStreamAnalysisDialog();

    /** @brief Opens the RTP Player dialog. */
    void openRtpPlayerDialog();

    /** @brief Connects Wireless menu actions to their implementation slots. */
    void connectWirelessMenuActions();

    /** @brief Connects Tools menu actions to their implementation slots. */
    void connectToolsMenuActions();

    /** @brief Handles a triggered external (plugin) menu item by invoking its callback. */
    void externalMenuItemTriggered();

    /** @brief Opens the Wireshark Wiki page for the protocol under the cursor. */
    void on_actionContextWikiProtocolPage_triggered();

    /** @brief Opens the Wireshark display-filter field reference for the selected field. */
    void on_actionContextFilterFieldReference_triggered();

    /**
     * @brief Handles the result of an extcap options dialog.
     * @param result QDialog::Accepted to start the capture; QDialog::Rejected to cancel.
     */
    void extcap_options_finished(int result);

    /**
     * @brief Opens the extcap options dialog for a specific interface.
     * @param device_name         Name of the extcap interface.
     * @param startCaptureOnClose @c true to start capturing when the dialog is accepted.
     */
    void showExtcapOptionsDialog(QString device_name, bool startCaptureOnClose);

    /**
     * @brief Searches the open capture file for RTP streams matching a heuristic,
     *        returning both forward and reverse stream identifiers.
     * @param stream_ids Populated with the discovered RTP stream identifiers.
     * @param reverse    @c true to also search for the reverse stream direction.
     * @return Human-readable summary of the streams found, or an error description.
     */
    QString findRtpStreams(QVector<rtpstream_id_t *> *stream_ids, bool reverse);

    /** @brief Opens the TLS Keylog dialog, creating it if it does not already exist. */
    void openTLSKeylogDialog();

    /** @brief Friend class allowing access to private members. */
    friend class MainApplication;
};

#endif // WIRESHARK_MAIN_WINDOW_H
