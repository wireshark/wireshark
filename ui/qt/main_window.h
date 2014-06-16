/* main_window.h
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

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <stdio.h>

#include "config.h"

#include <glib.h>

#include "file.h"

#include "ui/ui_util.h"

#include <epan/prefs.h>

#ifdef HAVE_LIBPCAP
#include "capture_opts.h"
#endif
#include "capture_session.h"

#include <QMainWindow>
#include <QSplitter>

#ifdef _WIN32
# include <QTimer>
#else
# include <QSocketNotifier>
#endif

#include "main_welcome.h"
#include "packet_list.h"
#include "display_filter_combo.h"
#include "progress_bar.h"
#include "file_set_dialog.h"
#include "capture_file_dialog.h"
#include "summary_dialog.h"
#include "follow_stream_dialog.h"
#include "capture_interfaces_dialog.h"
#include "about_dialog.h"

class QAction;

namespace Ui {
    class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    void setPipeInputHandler(gint source, gpointer user_data, int *child_process, pipe_input_cb_t input_cb);

    QString getFilter();

protected:
    bool eventFilter(QObject *obj, QEvent *event);
    void keyPressEvent(QKeyEvent *event);
    void closeEvent (QCloseEvent *event);

private:
    enum MatchSelected {
        MatchSelectedReplace,
        MatchSelectedAnd,
        MatchSelectedOr,
        MatchSelectedNot,
        MatchSelectedAndNot,
        MatchSelectedOrNot
    };

    enum CopySelected {
        CopySelectedDescription,
        CopySelectedFieldName,
        CopySelectedValue
    };

    Ui::MainWindow *main_ui_;
    QMenu *open_recent_menu_;
    QSplitter master_split_;
    QSplitter extra_split_;
    MainWelcome *main_welcome_;
    DisplayFilterCombo *df_combo_box_;
    capture_file *cap_file_;
    // XXX - packet_list_, proto_tree_, and byte_view_tab_ should
    // probably be full-on values instead of pointers.
    PacketList *packet_list_;
    ProtoTree *proto_tree_;
    QWidget *previous_focus_;
    FileSetDialog file_set_dialog_;
    SummaryDialog summary_dialog_;
    ByteViewTab *byte_view_tab_;
    QWidget empty_pane_;

    bool capture_stopping_;
    bool capture_filter_valid_;
#ifdef HAVE_LIBPCAP
    CaptureInterfacesDialog capture_interfaces_dialog_;
#endif

    // Pipe input
    gint                pipe_source_;
    gpointer            pipe_user_data_;
    int                 *pipe_child_process_;
    pipe_input_cb_t     pipe_input_cb_;
#ifdef _WIN32
    QTimer *pipe_timer_;
#else
    QSocketNotifier *pipe_notifier_;
#endif

    void saveWindowGeometry();
    QWidget* getLayoutWidget(layout_pane_content_e type);

    void mergeCaptureFile();
    void importCaptureFile();
    void saveCaptureFile(capture_file *cf, bool stay_closed);
    void saveAsCaptureFile(capture_file *cf, bool must_support_comments, bool stay_closed);
    void exportSelectedPackets();
    void exportDissections(export_type_e export_type);

    void fileAddExtension(QString &file_name, int file_type, bool compressed);
    bool testCaptureFileClose(bool from_quit = false, QString& before_what = *new QString());
    void captureStop();

    void setTitlebarForSelectedTreeRow();
    void setTitlebarForCaptureFile();
    void setTitlebarForCaptureInProgress();
    void setMenusForCaptureFile(bool force_disable = false);
    void setMenusForCaptureInProgress(bool capture_in_progress = false);
    void setMenusForCaptureStopping();
    void setForCapturedPackets(bool have_captured_packets);
    void setMenusForFileSet(bool enable_list_files);

    void setForCaptureInProgress(gboolean capture_in_progress = false);

signals:
    void showProgress(progdlg_t **dlg_p, bool animate, const QString message, bool terminate_is_stop, bool *stop_flag, float pct);
    void setCaptureFile(capture_file *cf);
    void setDissectedCaptureFile(capture_file *cf);
    void displayFilterSuccess(bool success);

public slots:
    // in main_window_slots.cpp
    void openCaptureFile(QString& cf_path = *new QString(), QString& display_filter = *new QString(), unsigned int type = WTAP_TYPE_AUTO);
    void filterPackets(QString& new_filter = *new QString(), bool force = false);
    void updateForUnsavedChanges();
    void layoutPanes();

    void captureCapturePrepared(capture_session *cap_session);
    void captureCaptureUpdateStarted(capture_session *cap_session);
    void captureCaptureUpdateFinished(capture_session *cap_session);
    void captureCaptureFixedStarted(capture_session *cap_session);
    void captureCaptureFixedFinished(capture_session *cap_session);
    void captureCaptureStopping(capture_session *cap_session);
    void captureCaptureFailed(capture_session *cap_session);

    void captureFileOpened(const capture_file *cf);
    void captureFileReadStarted(const capture_file *cf);
    void captureFileReadFinished(const capture_file *cf);
    void captureFileClosing(const capture_file *cf);
    void captureFileClosed(const capture_file *cf);

    void configurationProfileChanged(const gchar *profile_name);
    void filterExpressionsChanged();

private slots:
    // in main_window_slots.cpp
    void startCapture();
    void pipeTimeout();
    void pipeActivated(int source);
    void pipeNotifierDestroyed();
    void stopCapture();

    void loadWindowGeometry();
    void updateRecentFiles();
    void recentActionTriggered();
    void setMenusForFollowStream();
    void setMenusForSelectedPacket();
    void setMenusForSelectedTreeRow(field_info *fi = NULL);
    void interfaceSelectionChanged();
    void captureFilterSyntaxChanged(bool valid);
    void redissectPackets();
    void recreatePacketList();

    void startInterfaceCapture(bool valid);

    void setFeaturesEnabled(bool enabled = true);

    void addDisplayFilterButton(QString df_text);
    void displayFilterButtonClicked();

    // We should probably move these to main_window_actions.cpp similar to
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
    void on_actionFileExportPacketBytes_triggered();
    void on_actionFileExportObjectsDICOM_triggered();
    void on_actionFileExportObjectsHTTP_triggered();
    void on_actionFileExportObjectsSMB_triggered();
    void on_actionFileExportObjectsTFTP_triggered();
    void on_actionFilePrint_triggered();

    void on_actionFileExportPDU_triggered();
    void on_actionFileExportSSLSessionKeys_triggered();

    void actionEditCopyTriggered(MainWindow::CopySelected selection_type);
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
    void on_actionEditPacketComment_triggered();
    void on_actionEditConfigurationProfiles_triggered();
    void on_actionEditPreferences_triggered();

    void on_actionViewReload_triggered();
    void on_actionViewToolbarMainToolbar_triggered();
    void on_actionViewToolbarDisplayFilter_triggered();

    void on_actionGoGoToPacket_triggered();
    void resetPreviousFocus();

#ifdef HAVE_LIBPCAP
    void on_actionCaptureOptions_triggered();
#endif

    void matchSelectedFilter(MainWindow::MatchSelected filter_type, bool apply = false, bool copy_only = false);
    void on_actionAnalyzeAAFSelected_triggered();
    void on_actionAnalyzeAAFNotSelected_triggered();
    void on_actionAnalyzeAAFAndSelected_triggered();
    void on_actionAnalyzeAAFOrSelected_triggered();
    void on_actionAnalyzeAAFAndNotSelected_triggered();
    void on_actionAnalyzeAAFOrNotSelected_triggered();
    void on_actionAnalyzePAFSelected_triggered();
    void on_actionAnalyzePAFNotSelected_triggered();
    void on_actionAnalyzePAFAndSelected_triggered();
    void on_actionAnalyzePAFOrSelected_triggered();
    void on_actionAnalyzePAFAndNotSelected_triggered();
    void on_actionAnalyzePAFOrNotSelected_triggered();

    void on_actionAnalyzeDecodeAs_triggered();

    void openFollowStreamDialog(follow_type_t type);
    void on_actionAnalyzeFollowTCPStream_triggered();
    void on_actionAnalyzeFollowUDPStream_triggered();
    void on_actionAnalyzeFollowSSLStream_triggered();

    void on_actionHelpContents_triggered();
    void on_actionHelpMPWireshark_triggered();
    void on_actionHelpMPWireshark_Filter_triggered();
    void on_actionHelpMPCapinfos_triggered();
    void on_actionHelpMPDumpcap_triggered();
    void on_actionHelpMPEditcap_triggered();
    void on_actionHelpMPMergecap_triggered();
    void on_actionHelpMPRawShark_triggered();
    void on_actionHelpMPReordercap_triggered();
    void on_actionHelpMPText2cap_triggered();
    void on_actionHelpMPTShark_triggered();
    void on_actionHelpWebsite_triggered();
    void on_actionHelpFAQ_triggered();
    void on_actionHelpAsk_triggered();
    void on_actionHelpDownloads_triggered();
    void on_actionHelpWiki_triggered();
    void on_actionHelpSampleCaptures_triggered();
    void on_actionHelpAbout_triggered();

#ifdef HAVE_SOFTWARE_UPDATE
    void on_actionHelpCheckForUpdates_triggered();
#endif

    void on_goToCancel_clicked();
    void on_goToGo_clicked();
    void on_goToLineEdit_returnPressed();
    void on_actionStartCapture_triggered();
    void on_actionStopCapture_triggered();

    void on_actionSummary_triggered();
    void on_actionStatisticsFlowGraph_triggered();
    void openTcpStreamDialog(int graph_type);
    void on_actionStatisticsTcpStreamStevens_triggered();
    void on_actionStatisticsTcpStreamTcptrace_triggered();
    void on_actionStatisticsTcpStreamThroughput_triggered();
    void on_actionStatisticsTcpStreamRoundTripTime_triggered();
    void on_actionStatisticsTcpStreamWindowScaling_triggered();
    void openSCTPAllAssocsDialog();
    void on_actionSCTPShowAllAssociations_triggered();
    void on_actionSCTPAnalyseThisAssociation_triggered();
    void on_actionSCTPFilterThisAssociation_triggered();

#ifdef HAVE_LIBPCAP
    void on_actionCaptureInterfaces_triggered();
#endif

    void openStatisticsTreeDialog(const gchar *abbr);
    void on_actionStatistics29WestTopics_Advertisements_by_Topic_triggered();
    void on_actionStatistics29WestTopics_Advertisements_by_Source_triggered();
    void on_actionStatistics29WestTopics_Advertisements_by_Transport_triggered();
    void on_actionStatistics29WestTopics_Queries_by_Topic_triggered();
    void on_actionStatistics29WestTopics_Queries_by_Receiver_triggered();
    void on_actionStatistics29WestTopics_Wildcard_Queries_by_Pattern_triggered();
    void on_actionStatistics29WestTopics_Wildcard_Queries_by_Receiver_triggered();
    void on_actionStatistics29WestQueues_Advertisements_by_Queue_triggered();
    void on_actionStatistics29WestQueues_Advertisements_by_Source_triggered();
    void on_actionStatistics29WestQueues_Queries_by_Queue_triggered();
    void on_actionStatistics29WestQueues_Queries_by_Receiver_triggered();
    void on_actionStatistics29WestUIM_Streams_triggered();
    void on_actionStatistics29WestUIM_Stream_Flow_Graph_triggered();
    void on_actionStatistics29WestLBTRM_triggered();
    void on_actionStatistics29WestLBTRU_triggered();
    void on_actionStatisticsANCP_triggered();
    void on_actionStatisticsBACappInstanceId_triggered();
    void on_actionStatisticsBACappIP_triggered();
    void on_actionStatisticsBACappObjectId_triggered();
    void on_actionStatisticsBACappService_triggered();
    void on_actionStatisticsCollectd_triggered();
    void on_actionStatisticsHART_IP_triggered();
    void on_actionStatisticsHTTPPacketCounter_triggered();
    void on_actionStatisticsHTTPRequests_triggered();
    void on_actionStatisticsHTTPLoadDistribution_triggered();
    void on_actionStatisticsPacketLen_triggered();
    void on_actionStatisticsIOGraph_triggered();
    void on_actionStatisticsSametime_triggered();

    void on_actionTelephonyISUPMessages_triggered();
    void on_actionTelephonyRTSPPacketCounter_triggered();
    void on_actionTelephonySMPPOperations_triggered();
    void on_actionTelephonyUCPMessages_triggered();

    void changeEvent(QEvent* event);
};

#endif // MAINWINDOW_H

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
