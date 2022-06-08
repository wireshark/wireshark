/** @file
 *
 * Logwolf - Event log analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef LOGWOLF_MAIN_WINDOW_H
#define LOGWOLF_MAIN_WINDOW_H

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
 *  The Logwolf main window
 *  @ingroup main_window_group
 *  @ingroup windows_group
 */

#include <stdio.h>

#include <config.h>

#include <glib.h>

#include "file.h"

#include "ui/ws_ui_util.h"
#include "ui/iface_toolbar.h"

#include <epan/plugin_if.h>
#include <epan/timestamp.h>

#ifdef HAVE_LIBPCAP
#include "capture_opts.h"
#endif
#include <capture/capture_session.h>

#include <QMainWindow>
#include <QPointer>
#include <QTextCodec>

#ifdef _WIN32
# include <QTimer>
#else
# include <QSocketNotifier>
#endif

#include "capture_file.h"
#include "capture_file_dialog.h"
#include "print_dialog.h"
#include "capture_file_properties_dialog.h"
#include <ui/qt/utils/field_information.h>
#include <ui/qt/widgets/display_filter_combo.h>
#include "follow_stream_dialog.h"
#include "main_window.h"

class AccordionFrame;
class ByteViewTab;
class CaptureOptionsDialog;
class PrintDialog;
class FileSetDialog;
class FilterDialog;
class FunnelStatistics;
class WelcomePage;
class PacketCommentDialog;
class PacketDiagram;
class PacketList;
class ProtoTree;
class FilterExpressionToolBar;
class WiresharkApplication;

class QAction;
class QActionGroup;

namespace Ui {
    class LogwolfMainWindow;
}

Q_DECLARE_METATYPE(ts_type)
Q_DECLARE_METATYPE(ts_precision)

class LogwolfMainWindow : public MainWindow
{
    Q_OBJECT

public:
    explicit LogwolfMainWindow(QWidget *parent = nullptr);
    ~LogwolfMainWindow();
    void setPipeInputHandler(gint source, gpointer user_data, ws_process_id *child_process, pipe_input_cb_t input_cb);

#ifdef HAVE_LIBPCAP
    capture_session *captureSession() { return &cap_session_; }
    info_data_t *captureInfoData() { return &info_data_; }
#endif

    virtual QMenu *createPopupMenu();

    CaptureFile *captureFile() { return &capture_file_; }

    void removeAdditionalToolbar(QString toolbarName);

    void addInterfaceToolbar(const iface_toolbar *toolbar_entry);
    void removeInterfaceToolbar(const gchar *menu_title);

    QString getMwFileName();
    void setMwFileName(QString fileName);

    frame_data * frameDataForRow(int row) const;

protected:
    virtual bool eventFilter(QObject *obj, QEvent *event);
    virtual bool event(QEvent *event);
    virtual void keyPressEvent(QKeyEvent *event);
    virtual void closeEvent(QCloseEvent *event);
    virtual void dragEnterEvent(QDragEnterEvent *event);
    virtual void dropEvent(QDropEvent *event);
    virtual void changeEvent(QEvent* event);

private:
    // XXX Move to FilterUtils
    enum MatchSelected {
        MatchSelectedReplace,
        MatchSelectedAnd,
        MatchSelectedOr,
        MatchSelectedNot,
        MatchSelectedAndNot,
        MatchSelectedOrNot
    };

    enum CopySelected {
        CopyAllVisibleItems,
        CopyAllVisibleSelectedTreeItems,
        CopySelectedDescription,
        CopySelectedFieldName,
        CopySelectedValue,
        CopyListAsText,
        CopyListAsCSV,
        CopyListAsYAML
    };

    enum FileCloseContext {
        Default,
        Quit,
        Restart,
        Reload
    };

    Ui::LogwolfMainWindow *main_ui_;
    CaptureFile capture_file_;
    QFont mono_font_;
    QMap<QString, QTextCodec *> text_codec_map_;
    QWidget *previous_focus_;
    FileSetDialog *file_set_dialog_;
    QActionGroup *show_hide_actions_;
    QActionGroup *time_display_actions_;
    QActionGroup *time_precision_actions_;
    FunnelStatistics *funnel_statistics_;
    QList<QPair<QAction *, bool> > freeze_actions_;
    QPointer<QWidget> freeze_focus_;
    QMap<QAction *, ts_type> td_actions;
    QMap<QAction *, ts_precision> tp_actions;
    bool was_maximized_;

    /* the following values are maintained so that the capture file name and status
    is available when there is no cf structure available */
    QString mwFileName_;

    bool capture_stopping_;
    bool capture_filter_valid_;
#ifdef HAVE_LIBPCAP
    capture_session cap_session_;
    CaptureOptionsDialog *capture_options_dialog_;
    info_data_t info_data_;
#endif
    FilterDialog *display_filter_dlg_;
    FilterDialog *capture_filter_dlg_;

    // Pipe input
    gint                pipe_source_;
    gpointer            pipe_user_data_;
    ws_process_id      *pipe_child_process_;
    pipe_input_cb_t     pipe_input_cb_;
#ifdef _WIN32
    QTimer *pipe_timer_;
#else
    QSocketNotifier *pipe_notifier_;
#endif

#if defined(Q_OS_MAC)
    QMenu *dock_menu_;
#endif

#ifdef HAVE_SOFTWARE_UPDATE
    QAction *update_action_;
#endif

    QPoint dragStartPosition;

    void freeze();
    void thaw();

    void mergeCaptureFile();
    void importCaptureFile();
    bool saveCaptureFile(capture_file *cf, bool dont_reopen);
    bool saveAsCaptureFile(capture_file *cf, bool must_support_comments = false, bool dont_reopen = false);
    void exportSelectedPackets();
    void exportDissections(export_type_e export_type);

#ifdef Q_OS_WIN
    void fileAddExtension(QString &file_name, int file_type, wtap_compression_type compression_type);
#endif // Q_OS_WIN
    bool testCaptureFileClose(QString before_what, FileCloseContext context = Default);
    void captureStop();

    void findTextCodecs();

    void initMainToolbarIcons();
    void initShowHideMainWidgets();
    void initTimeDisplayFormatMenu();
    void initTimePrecisionFormatMenu();
    void initFreezeActions();

    void setTitlebarForCaptureInProgress();
    void setMenusForCaptureFile(bool force_disable = false);
    void setMenusForCaptureInProgress(bool capture_in_progress = false);
    void setMenusForCaptureStopping();
    void setForCapturedPackets(bool have_captured_packets);
    void setMenusForFileSet(bool enable_list_files);
    void setWindowIcon(const QIcon &icon);
    QString replaceWindowTitleVariables(QString title);

    void externalMenuHelper(ext_menu_t * menu, QMenu  * subMenu, gint depth);

    void setForCaptureInProgress(bool capture_in_progress = false, bool handle_toolbars = false, GArray *ifaces = NULL);
    QMenu* findOrAddMenu(QMenu *parent_menu, QString& menu_text);

    void captureFileReadStarted(const QString &action);

    void addMenuActions(QList<QAction *> &actions, int menu_group);
    void removeMenuActions(QList<QAction *> &actions, int menu_group);
    void goToConversationFrame(bool go_next);
    void colorizeWithFilter(QByteArray filter, int color_number = -1);

signals:
    void setDissectedCaptureFile(capture_file *cf);
    void displayFilterSuccess(bool success);
    void closePacketDialogs();
    void reloadFields();
    void packetInfoChanged(struct _packet_info *pinfo);
    void fieldFilterChanged(const QByteArray field_filter);

    void fieldHighlight(FieldInformation *);

    void captureActive(int);

#ifdef HAVE_LIBPCAP
    void showExtcapOptions(QString &device_name, bool startCaptureOnClose);
#endif

public slots:
    // in main_window_slots.cpp
    /**
     * Open a capture file.
     * @param cf_path Path to the file.
     * @param display_filter Display filter to apply. May be empty.
     * @param type File type.
     * @param is_tempfile TRUE/FALSE.
     * @return True on success, false on failure.
     */
    // XXX We might want to return a cf_read_status_t or a CaptureFile.
    bool openCaptureFile(QString cf_path, QString display_filter, unsigned int type, gboolean is_tempfile = FALSE);
    bool openCaptureFile(QString cf_path = QString(), QString display_filter = QString()) { return openCaptureFile(cf_path, display_filter, WTAP_TYPE_AUTO); }
    void filterPackets(QString new_filter = QString(), bool force = false);
    void updateForUnsavedChanges();
    void layoutToolbars();
    void updatePreferenceActions();
    void updateRecentActions();

    void setTitlebarForCaptureFile();
    void setWSWindowTitle(QString title = QString());

#ifdef HAVE_LIBPCAP
    void captureCapturePrepared(capture_session *);
    void captureCaptureUpdateStarted(capture_session *);
    void captureCaptureUpdateFinished(capture_session *);
    void captureCaptureFixedFinished(capture_session *cap_session);
    void captureCaptureFailed(capture_session *);
#endif

    void captureFileOpened();
    void captureFileReadFinished();
    void captureFileClosing();
    void captureFileClosed();

    void on_actionViewFullScreen_triggered(bool checked);

private slots:

    void captureEventHandler(CaptureEvent ev);

    // Manually connected slots (no "on_<object>_<signal>").

    void initViewColorizeMenu();
    void initConversationMenus();
    static gboolean addExportObjectsMenuItem(const void *key, void *value, void *userdata);
    void initExportObjectsMenus();

    // in main_window_slots.cpp
    /**
     * @brief startCapture
     * Start capturing from the selected interfaces using the capture filter
     * shown in the main welcome screen.
     */
    void startCapture(QStringList);
    void startCapture();
    void pipeTimeout();
    void pipeActivated(int source);
    void pipeNotifierDestroyed();
    void stopCapture();

    void loadWindowGeometry();
    void saveWindowGeometry();
    void mainStackChanged(int);
    void updateRecentCaptures();
    void recentActionTriggered();
    void actionAddPacketComment();
    void actionEditPacketComment();
    void actionDeletePacketComment();
    void actionDeleteCommentsFromPackets();
    QString commentToMenuText(QString text, int max_len = 40);
    void setEditCommentsMenu();
    void setMenusForSelectedPacket();
    void setMenusForSelectedTreeRow(FieldInformation *fi = NULL);
    void interfaceSelectionChanged();
    void captureFilterSyntaxChanged(bool valid);
    void redissectPackets();
    void checkDisplayFilter();
    void fieldsChanged();
    void reloadLuaPlugins();
    void showAccordionFrame(AccordionFrame *show_frame, bool toggle = false);
    void showColumnEditor(int column);
    void showPreferenceEditor(); // module_t *, pref *
    void addStatsPluginsToMenu();
    void addDynamicMenus();
    void reloadDynamicMenus();
    void addPluginIFStructures();
    QMenu * searchSubMenu(QString objectName);
    void activatePluginIFToolbar(bool);

    void startInterfaceCapture(bool valid, const QString capture_filter);

    void applyGlobalCommandLineOptions();
    void setFeaturesEnabled(bool enabled = true);

    void on_actionDisplayFilterExpression_triggered();
    void on_actionNewDisplayFilterExpression_triggered();
    void onFilterSelected(QString, bool);
    void onFilterPreferences();
    void onFilterEdit(int uatIndex);

    // Handle FilterAction signals
    void queuedFilterAction(QString filter, FilterAction::Action action, FilterAction::ActionType type);

    /** Pass stat cmd arguments to a slot.
     * @param menu_path slot Partial slot name, e.g. "StatisticsIOGraph".
     * @param arg "-z" argument, e.g. "io,stat".
     * @param userdata Optional user data.
     */
    void openStatCommandDialog(const QString &menu_path, const char *arg, void *userdata);

    /** Pass tap parameter arguments to a slot.
     * @param cfg_str slot Partial slot name, e.g. "StatisticsAFPSrt".
     * @param arg "-z" argument, e.g. "afp,srt".
     * @param userdata Optional user data.
     */
    void openTapParameterDialog(const QString cfg_str, const QString arg, void *userdata);
    void openTapParameterDialog();

#if defined(HAVE_SOFTWARE_UPDATE) && defined(Q_OS_WIN)
    void softwareUpdateRequested();
#endif

    // Automatically connected slots ("on_<object>_<signal>").
    //
    // The slots below follow the naming conventaion described in
    // https://doc.qt.io/archives/qt-4.8/qmetaobject.html#connectSlotsByName
    // and are automatically connected at initialization time via
    // main_ui_->setupUi, which in turn calls connectSlotsByName.
    //
    // If you're manually connecting a signal to a slot, don't prefix its name
    // with "on_". Otherwise you'll get runtime warnings.

    // We might want move these to main_window_actions.cpp similar to
    // gtk/main_menubar.c

    void on_actionFileOpen_triggered();
    void on_actionFileMerge_triggered();
    void on_actionFileImportFromHexDump_triggered();
    void on_actionFileClose_triggered();
    void on_actionFileSave_triggered();
    void on_actionFileSaveAs_triggered();
    void on_actionFileSetListFiles_triggered();
    void on_actionFileSetNextFile_triggered();
    void on_actionFileSetPreviousFile_triggered();
    void on_actionFileExportPackets_triggered();
    void on_actionFileExportAsPlainText_triggered();
    // We're dropping PostScript exports
    void on_actionFileExportAsCSV_triggered();
    void on_actionFileExportAsCArrays_triggered();
    void on_actionFileExportAsPSML_triggered();
    void on_actionFileExportAsPDML_triggered();
    void on_actionFileExportAsJSON_triggered();
    void on_actionFileExportPacketBytes_triggered();
    void on_actionFilePrint_triggered();

    void on_actionFileExportPDU_triggered();

    void actionEditCopyTriggered(LogwolfMainWindow::CopySelected selection_type);
    void on_actionCopyAllVisibleItems_triggered();
    void on_actionCopyAllVisibleSelectedTreeItems_triggered();
    void on_actionCopyListAsText_triggered();
    void on_actionCopyListAsCSV_triggered();
    void on_actionCopyListAsYAML_triggered();
    void on_actionEditCopyDescription_triggered();
    void on_actionEditCopyFieldName_triggered();
    void on_actionEditCopyValue_triggered();
    void on_actionEditCopyAsFilter_triggered();
    void on_actionEditFindPacket_triggered();
    void on_actionEditFindNext_triggered();
    void on_actionEditFindPrevious_triggered();
    void on_actionEditMarkPacket_triggered();
    void on_actionEditMarkAllDisplayed_triggered();
    void on_actionEditUnmarkAllDisplayed_triggered();
    void on_actionEditNextMark_triggered();
    void on_actionEditPreviousMark_triggered();
    void on_actionEditIgnorePacket_triggered();
    void on_actionEditIgnoreAllDisplayed_triggered();
    void on_actionEditUnignoreAllDisplayed_triggered();
    void on_actionEditSetTimeReference_triggered();
    void on_actionEditUnsetAllTimeReferences_triggered();
    void on_actionEditNextTimeReference_triggered();
    void on_actionEditPreviousTimeReference_triggered();
    void on_actionEditTimeShift_triggered();
    void editTimeShiftFinished(int);
    void addPacketCommentFinished(PacketCommentDialog* pc_dialog, int result);
    void editPacketCommentFinished(PacketCommentDialog* pc_dialog, int result, guint nComment);
    void on_actionDeleteAllPacketComments_triggered();
    void deleteAllPacketCommentsFinished(int result);
    void on_actionEditConfigurationProfiles_triggered();
    void showPreferencesDialog(QString module_name);
    void on_actionEditPreferences_triggered();

    void showHideMainWidgets(QAction *action);
    void setTimestampFormat(QAction *action);
    void setTimestampPrecision(QAction *action);
    void on_actionViewTimeDisplaySecondsWithHoursAndMinutes_triggered(bool checked);
    void on_actionViewEditResolvedName_triggered();
    void setNameResolution();
    void on_actionViewNameResolutionPhysical_triggered();
    void on_actionViewNameResolutionNetwork_triggered();
    void on_actionViewNameResolutionTransport_triggered();
    // XXX We're not porting the concurrency action from GTK+ on purpose.
    void zoomText();
    void on_actionViewZoomIn_triggered();
    void on_actionViewZoomOut_triggered();
    void on_actionViewNormalSize_triggered();
    void on_actionViewColorizePacketList_triggered(bool checked);
    void on_actionViewColoringRules_triggered();
    void colorizeConversation(bool create_rule = false);
    void colorizeActionTriggered();
    void on_actionViewColorizeResetColorization_triggered();
    void on_actionViewColorizeNewColoringRule_triggered();
    void on_actionViewResetLayout_triggered();
    void on_actionViewResizeColumns_triggered();

    void on_actionViewInternalsConversationHashTables_triggered();
    void on_actionViewInternalsDissectorTables_triggered();
    void on_actionViewInternalsSupportedProtocols_triggered();

    void openPacketDialog(bool from_reference = false);
    void on_actionViewShowPacketInNewWindow_triggered();
    void on_actionContextShowLinkedPacketInNewWindow_triggered();
    void on_actionViewReload_triggered();
    void on_actionViewReload_as_File_Format_or_Capture_triggered();

    void on_actionGoGoToPacket_triggered();
    void on_actionGoGoToLinkedPacket_triggered();
    void on_actionGoNextConversationPacket_triggered();
    void on_actionGoPreviousConversationPacket_triggered();
    void on_actionGoAutoScroll_toggled(bool checked);
    void resetPreviousFocus();

    void on_actionCaptureOptions_triggered();
#ifdef HAVE_LIBPCAP
    void on_actionCaptureRefreshInterfaces_triggered();
#endif
    void on_actionCaptureCaptureFilters_triggered();

    void on_actionAnalyzeDisplayFilters_triggered();
    void on_actionAnalyzeDisplayFilterMacros_triggered();
    void matchFieldFilter(FilterAction::Action action, FilterAction::ActionType filter_type);
    void on_actionAnalyzeCreateAColumn_triggered();

    void filterMenuAboutToShow();

    void applyConversationFilter();
    void applyExportObject();

    void on_actionAnalyzeEnabledProtocols_triggered();
    void on_actionAnalyzeDecodeAs_triggered();
    void on_actionAnalyzeReloadLuaPlugins_triggered();

    void openFollowStreamDialog(follow_type_t type, guint stream_num, guint sub_stream_num, bool use_stream_index = true);
    void openFollowStreamDialogForType(follow_type_t type);

    void statCommandExpertInfo(const char *, void *);
    void on_actionAnalyzeExpertInfo_triggered();

    void on_actionHelpContents_triggered();
    void on_actionHelpMPWireshark_triggered();
    void on_actionHelpMPWireshark_Filter_triggered();
    void on_actionHelpMPCapinfos_triggered();
    void on_actionHelpMPDumpcap_triggered();
    void on_actionHelpMPEditcap_triggered();
    void on_actionHelpMPMergecap_triggered();
    void on_actionHelpMPRawshark_triggered();
    void on_actionHelpMPReordercap_triggered();
    void on_actionHelpMPText2pcap_triggered();
    void on_actionHelpMPTShark_triggered();
    void on_actionHelpWebsite_triggered();
    void on_actionHelpFAQ_triggered();
    void on_actionHelpAsk_triggered();
    void on_actionHelpDownloads_triggered();
    void on_actionHelpWiki_triggered();
    void on_actionHelpSampleCaptures_triggered();
    void on_actionHelpAbout_triggered();

#ifdef HAVE_SOFTWARE_UPDATE
    void checkForUpdates();
#endif

    void on_goToCancel_clicked();
    void on_goToGo_clicked();
    void on_goToLineEdit_returnPressed();
    void on_actionCaptureStart_triggered();
    void on_actionCaptureStop_triggered();
    void on_actionCaptureRestart_triggered();

    void on_actionStatisticsCaptureFileProperties_triggered();
    void on_actionStatisticsResolvedAddresses_triggered();
    void on_actionStatisticsProtocolHierarchy_triggered();
    void on_actionStatisticsFlowGraph_triggered();

    void openStatisticsTreeDialog(const gchar *abbr);
    void on_actionStatisticsConversations_triggered();
    void on_actionStatisticsEndpoints_triggered();
    void on_actionStatisticsPacketLengths_triggered();
    void on_actionStatisticsIOGraph_triggered();
    void actionStatisticsPlugin_triggered();

    void externalMenuItem_triggered();

    void on_actionAnalyzeShowPacketBytes_triggered();

    void on_actionContextWikiProtocolPage_triggered();
    void on_actionContextFilterFieldReference_triggered();

    void extcap_options_finished(int result);
    void showExtcapOptionsDialog(QString & device_name, bool startCaptureOnClose);

    friend class MainApplication;
};

#endif // LOGWOLF_MAIN_WINDOW_H
