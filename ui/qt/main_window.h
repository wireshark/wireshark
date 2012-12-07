/* main_window.h
 *
 * $Id$
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

#ifdef HAVE_LIBPCAP
#include "capture_opts.h"
#endif

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
    QSplitter *packet_splitter_;
    MainWelcome *main_welcome_;
    DisplayFilterCombo *df_combo_box_;
    capture_file *cap_file_;
    PacketList *packet_list_;
    ProtoTree *proto_tree_;
    QWidget *previous_focus_;
    FileSetDialog file_set_dialog_;
    bool capture_stopping_;

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

    void mergeCaptureFile();
    void importCaptureFile();
    void saveCaptureFile(capture_file *cf, bool stay_closed);
    void saveAsCaptureFile(capture_file *cf, bool must_support_comments, bool stay_closed);
    void exportSelectedPackets();
    void exportDissections(export_type_e export_type);

    void fileAddExtension(QString &file_name, int file_type, bool compressed);
    bool testCaptureFileClose(bool from_quit = false, QString& before_what = *new QString());
    void captureStop();

    void setMenusForCaptureFile(bool force_disable = false);
    void setMenusForCaptureInProgress(bool capture_in_progress = false);
    void setMenusForCaptureStopping();
    void setForCapturedPackets(bool have_captured_packets);
    void setMenusForFileSet(bool enable_list_files);
    void updateForUnsavedChanges();
    void setForCaptureInProgress(gboolean capture_in_progress = false);

signals:
    void showProgress(progdlg_t **dlg_p, bool animate, const QString message, bool terminate_is_stop, bool *stop_flag, float pct);
    void setCaptureFile(capture_file *cf);
    void displayFilterSuccess(bool success);

public slots:
    // in main_window_slots.cpp
    void openCaptureFile(QString& cf_path = *new QString(), QString &display_filter = *new QString());
    void filterPackets(QString& new_filter = *new QString(), bool force = false);

#ifdef HAVE_LIBPCAP
    void captureCapturePrepared(capture_options *capture_opts);
    void captureCaptureUpdateStarted(capture_options *capture_opts);
    void captureCaptureUpdateFinished(capture_options *capture_opts);
    void captureCaptureFixedStarted(capture_options *capture_opts);
    void captureCaptureFixedFinished(capture_options *capture_opts);
    void captureCaptureStopping(capture_options *capture_opts);
    void captureCaptureFailed(capture_options *capture_opts);
#endif

    void captureFileOpened(const capture_file *cf);
    void captureFileReadStarted(const capture_file *cf);
    void captureFileReadFinished(const capture_file *cf);
    void captureFileClosing(const capture_file *cf);
    void captureFileClosed(const capture_file *cf);

private slots:
    // in main_window_slots.cpp
    void startCapture();
    void pipeTimeout();
    void pipeActivated(int source);
    void pipeNotifierDestroyed();
    void stopCapture();

    void updateRecentFiles();
    void recentActionTriggered();
    void setMenusForSelectedTreeRow(field_info *fi = NULL);
    void interfaceSelectionChanged();

    void on_actionFileOpen_triggered();
    void on_actionFileMerge_triggered();
    void on_actionFileImport_triggered();
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
    void on_actionFilePrint_triggered();

    void on_actionFileExportSSLSessionKeys_triggered();

    void actionEditCopyTriggered(MainWindow::CopySelected selection_type);
    void on_actionEditCopyDescription_triggered();
    void on_actionEditCopyFieldName_triggered();
    void on_actionEditCopyValue_triggered();
    void on_actionEditCopyAsFilter_triggered();

    void on_actionGoGoToPacket_triggered();
    void resetPreviousFocus();

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

    void on_actionHelpContents_triggered();
    void on_actionHelpMPWireshark_triggered();
    void on_actionHelpMPWireshark_Filter_triggered();
    void on_actionHelpMPTShark_triggered();
    void on_actionHelpMPRawShark_triggered();
    void on_actionHelpMPDumpcap_triggered();
    void on_actionHelpMPMergecap_triggered();
    void on_actionHelpMPEditcap_triggered();
    void on_actionHelpMPText2cap_triggered();
    void on_actionHelpWebsite_triggered();
    void on_actionHelpFAQ_triggered();
    void on_actionHelpAsk_triggered();
    void on_actionHelpDownloads_triggered();
    void on_actionHelpWiki_triggered();
    void on_actionHelpSampleCaptures_triggered();
    void on_goToCancel_clicked();
    void on_goToGo_clicked();
    void on_goToLineEdit_returnPressed();
    void on_actionStartCapture_triggered();
    void on_actionStopCapture_triggered();
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
