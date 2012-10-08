/* main_window.cpp
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

#include "main_window.h"
#include "ui_main_window.h"

#include "globals.h"

#include <epan/filesystem.h>
#include <epan/prefs.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#endif

#ifdef HAVE_LIBPCAP
#include "capture.h"
#include "capture-pcap-util.h"
#include "capture_ui_utils.h"
#endif

#include "ui/main_statusbar.h"
#include "ui/capture_globals.h"
#include "ui/help_url.h"

#include "wireshark_application.h"
#include "capture_file_dialog.h"

// Copied from gtk/help_dlg.[ch]. Need to move to qt/help_dlg.[ch].
// Required for on_actionHelp* below.
static void
topic_action(topic_action_e action)
{
    char *url;

    url = topic_action_url(action);

    if(url != NULL) {
        QDesktopServices::openUrl(QUrl(url));
        g_free(url);
    }
}

//
// Public slots
//

void MainWindow::openCaptureFile(QString &cf_path)
{
    QString file_name = "";
    QString display_filter = "";
    dfilter_t *rfcode = NULL;
    int err;

    testCaptureFileClose(false);

    for (;;) {

        if (cf_path.isEmpty()) {
            CaptureFileDialog open_dlg(this, cap_file_, display_filter);

            switch (prefs.gui_fileopen_style) {

            case FO_STYLE_LAST_OPENED:
                /* The user has specified that we should start out in the last directory
                   we looked in.  If we've already opened a file, use its containing
                   directory, if we could determine it, as the directory, otherwise
                   use the "last opened" directory saved in the preferences file if
                   there was one. */
                /* This is now the default behaviour in file_selection_new() */
                break;

            case FO_STYLE_SPECIFIED:
                /* The user has specified that we should always start out in a
                   specified directory; if they've specified that directory,
                   start out by showing the files in that dir. */
                if (prefs.gui_fileopen_dir[0] != '\0')
                    open_dlg.setDirectory(prefs.gui_fileopen_dir);
                break;
            }

            if (open_dlg.open(file_name)) {
                if (dfilter_compile(display_filter.toUtf8().constData(), &rfcode)) {
                    cf_set_rfcode(&cfile, rfcode);
                } else {
                    /* Not valid.  Tell the user, and go back and run the file
                       selection box again once they dismiss the alert. */
                    //bad_dfilter_alert_box(top_level, display_filter->str);
                    QMessageBox::warning(this, tr("Invalid Display Filter"),
                                         QString("The filter expression ") +
                                         display_filter +
                                         QString(" isn't a valid display filter. (") +
                                         dfilter_error_msg + QString(")."),
                                         QMessageBox::Ok);
                    continue;
                }
                cf_path = file_name;
            } else {
                return;
            }
        }

        /* Try to open the capture file. */
        cfile.window = this;
        if (cf_open(&cfile, cf_path.toUtf8().constData(), FALSE, &err) != CF_OK) {
            /* We couldn't open it; don't dismiss the open dialog box,
               just leave it around so that the user can, after they
               dismiss the alert box popped up for the open error,
               try again. */
            cfile.window = NULL;
            if (rfcode != NULL)
                dfilter_free(rfcode);
            cf_path.clear();
            continue;
        }

        switch (cf_read(&cfile, FALSE)) {

        case CF_READ_OK:
        case CF_READ_ERROR:
            /* Just because we got an error, that doesn't mean we were unable
               to read any of the file; we handle what we could get from the
               file. */
            break;

        case CF_READ_ABORTED:
            /* The user bailed out of re-reading the capture file; the
               capture file has been closed - just free the capture file name
               string and return (without changing the last containing
               directory). */
            cap_file_ = NULL;
            return;
        }
        break;
    }
    // get_dirname overwrites its path. Hopefully this isn't a problem.
    wsApp->setLastOpenDir(get_dirname(cf_path.toUtf8().data()));
    df_combo_box_->setEditText(display_filter);

    main_ui_->statusBar->showExpert();
}

// Capture callbacks

#ifdef HAVE_LIBPCAP
void MainWindow::captureCapturePrepared(capture_options *capture_opts) {
    qDebug() << "FIX captureCapturePrepared";
//    main_capture_set_main_window_title(capture_opts);

//    if(icon_list == NULL) {
//        icon_list = icon_list_create(wsiconcap16_xpm, wsiconcap32_xpm, wsiconcap48_xpm, NULL);
//    }
//    gtk_window_set_icon_list(GTK_WINDOW(top_level), icon_list);

    /* Disable menu items that make no sense if you're currently running
       a capture. */
    setForCaptureInProgress(true);
//    set_capture_if_dialog_for_capture_in_progress(TRUE);

//    /* Don't set up main window for a capture file. */
//    main_set_for_capture_file(FALSE);
    main_ui_->mainStack->setCurrentWidget(packet_splitter_);
    cap_file_ = (capture_file *) capture_opts->cf;
}
void MainWindow::captureCaptureUpdateStarted(capture_options *capture_opts) {
    Q_UNUSED(capture_opts);

    qDebug() << "captureCaptureUpdateStarted";
    setForCaptureInProgress(true);
}
void MainWindow::captureCaptureUpdateFinished(capture_options *capture_opts) {
    Q_UNUSED(capture_opts);

    /* The capture isn't stopping any more - it's stopped. */
    capture_stopping_ = false;

    /* Update the main window as appropriate */
    updateForUnsavedChanges();

    /* Enable menu items that make sense if you're not currently running
     a capture. */
    setForCaptureInProgress(false);

}
void MainWindow::captureCaptureFixedStarted(capture_options *capture_opts) {
    Q_UNUSED(capture_opts);
    qDebug() << "captureCaptureFixedStarted";
}
void MainWindow::captureCaptureFixedFinished(capture_options *capture_opts) {
    Q_UNUSED(capture_opts);
    qDebug() << "captureCaptureFixedFinished";

    /* The capture isn't stopping any more - it's stopped. */
    capture_stopping_ = false;

    /* Enable menu items that make sense if you're not currently running
     a capture. */
    setForCaptureInProgress(false);

}
void MainWindow::captureCaptureStopping(capture_options *capture_opts) {
    Q_UNUSED(capture_opts);

    capture_stopping_ = true;
    setMenusForCaptureStopping();
}
void MainWindow::captureCaptureFailed(capture_options *capture_opts) {
    Q_UNUSED(capture_opts);
    qDebug() << "captureCaptureFailed";
    /* Capture isn't stopping any more. */
    capture_stopping_ = false;

    setForCaptureInProgress(false);
}
#endif // HAVE_LIBPCAP


// Callbacks from cfile.c via WiresharkApplication::captureFileCallback

void MainWindow::captureFileOpened(const capture_file *cf) {
    if (cf->window != this) return;
    cap_file_ = (capture_file *) cf;

    file_set_dialog_.fileOpened(cf);
    setMenusForFileSet(true);
}

void MainWindow::captureFileReadStarted(const capture_file *cf) {
    if (cf != cap_file_) return;
//    tap_param_dlg_update();

    /* Set up main window for a capture file. */
//    main_set_for_capture_file(TRUE);

    main_ui_->statusBar->popFileStatus();
    QString msg = QString(tr("Loading: %1")).arg(get_basename(cf->filename));
    main_ui_->statusBar->pushFileStatus(msg);
    main_ui_->mainStack->setCurrentWidget(packet_splitter_);
    WiresharkApplication::processEvents();
}

void MainWindow::captureFileReadFinished(const capture_file *cf) {
    if (cf != cap_file_) return;

//    gchar *dir_path;

//    if (!cf->is_tempfile && cf->filename) {
//        /* Add this filename to the list of recent files in the "Recent Files" submenu */
//        add_menu_recent_capture_file(cf->filename);

//        /* Remember folder for next Open dialog and save it in recent */
//	dir_path = get_dirname(g_strdup(cf->filename));
//        wsApp->setLastOpenDir(dir_path);
//        g_free(dir_path);
//    }
//    set_display_filename(cf);

    /* Update the appropriate parts of the main window. */
    updateForUnsavedChanges();

//    /* Enable menu items that make sense if you have some captured packets. */
//    set_menus_for_captured_packets(TRUE);

    main_ui_->statusBar->popFileStatus();
    QString msg = QString().sprintf("%s", get_basename(cf->filename));
    main_ui_->statusBar->pushFileStatus(msg);
}

void MainWindow::captureFileClosing(const capture_file *cf) {
    if (cf != cap_file_) return;

    setMenusForCaptureFile(true);
    setForCaptureInProgress(false);

    // Reset expert info indicator
    main_ui_->statusBar->hideExpert();
//    gtk_widget_show(expert_info_none);
}

void MainWindow::captureFileClosed(const capture_file *cf) {
    if (cf != cap_file_) return;
    packets_bar_update();

    file_set_dialog_.fileClosed();
    setMenusForFileSet(false);

    // Reset expert info indicator
    main_ui_->statusBar->hideExpert();

    main_ui_->statusBar->popFileStatus();
    cap_file_ = NULL;
}

//
// Private slots
//

// ui/gtk/capture_dlg.c:start_capture_confirmed

void MainWindow::startCapture() {
    interface_options interface_opts;
    guint i;

    /* did the user ever select a capture interface before? */
    if(global_capture_opts.num_selected == 0 &&
            ((prefs.capture_device == NULL) || (*prefs.capture_device != '\0'))) {
        QString msg = QString("No interface selected");
        main_ui_->statusBar->pushTemporaryStatus(msg);
        return;
    }

    /* XXX - we might need to init other pref data as well... */
//    main_auto_scroll_live_changed(auto_scroll_live);

    /* XXX - can this ever happen? */
    if (global_capture_opts.state != CAPTURE_STOPPED)
      return;

    /* close the currently loaded capture file */
    cf_close((capture_file *) global_capture_opts.cf);

    /* Copy the selected interfaces to the set of interfaces to use for
       this capture. */
    collect_ifaces(&global_capture_opts);

    if (capture_start(&global_capture_opts)) {
        /* The capture succeeded, which means the capture filter syntax is
         valid; add this capture filter to the recent capture filter list. */
        for (i = 0; i < global_capture_opts.ifaces->len; i++) {
            interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, i);
            if (interface_opts.cfilter) {
//              cfilter_combo_add_recent(interface_opts.cfilter);
            }
        }
    }
}

// Copied from ui/gtk/gui_utils.c
void MainWindow::pipeTimeout() {
#ifdef _WIN32
    HANDLE handle;
    DWORD avail = 0;
    gboolean result, result1;
    DWORD childstatus;
    gint iterations = 0;


    /* try to read data from the pipe only 5 times, to avoid blocking */
    while(iterations < 5) {
        /*g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_timer_cb: new iteration");*/

        /* Oddly enough although Named pipes don't work on win9x,
           PeekNamedPipe does !!! */
        handle = (HANDLE) _get_osfhandle (pipe_source_);
        result = PeekNamedPipe(handle, NULL, 0, NULL, &avail, NULL);

        /* Get the child process exit status */
        result1 = GetExitCodeProcess((HANDLE)*(pipe_child_process_),
                                     &childstatus);

        /* If the Peek returned an error, or there are bytes to be read
           or the childwatcher thread has terminated then call the normal
           callback */
        if (!result || avail > 0 || childstatus != STILL_ACTIVE) {

            /*g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_timer_cb: data avail");*/

            /* And call the real handler */
            if (!pipe_input_cb_(pipe_source_, pipe_user_data_)) {
                g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_timer_cb: input pipe closed, iterations: %u", iterations);
                /* pipe closed, return false so that the old timer is not run again */
                delete pipe_timer_;
                return;
            }
        }
        else {
            /*g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_timer_cb: no data avail");*/
            /* No data, stop now */
            break;
        }

        iterations++;
    }
#endif // _WIN32
}

void MainWindow::pipeActivated(int source) {
#ifdef _WIN32
    Q_UNUSED(source);
#else
    g_assert(source == pipe_source_);

    pipe_notifier_->setEnabled(false);
    if (pipe_input_cb_(pipe_source_, pipe_user_data_)) {
        pipe_notifier_->setEnabled(true);
    } else {
        delete pipe_notifier_;
    }
#endif // _WIN32
}

void MainWindow::pipeNotifierDestroyed() {
#ifdef _WIN32
    pipe_timer_ = NULL;
#else
    pipe_notifier_ = NULL;
#endif // _WIN32
}

void MainWindow::stopCapture() {
//#ifdef HAVE_AIRPCAP
//  if (airpcap_if_active)
//    airpcap_set_toolbar_stop_capture(airpcap_if_active);
//#endif

    capture_stop(&global_capture_opts);
}

// XXX - Copied from ui/gtk/menus.c

/**
 * Add the capture filename (with an absolute path) to the "Recent Files" menu.
 *
 * @param cf_name Absolute path to the file.
 * @param first Prepend the filename if true, otherwise append it. Default is false (append).
 */
// XXX - We should probably create a RecentFile class.
void MainWindow::updateRecentFiles() {
    QAction *ra;
    QMenu *recentMenu = main_ui_->menuOpenRecentCaptureFile;
    QString action_cf_name;

    if (!recentMenu) {
        return;
    }

    recentMenu->clear();

    /* Iterate through the actions in menuOpenRecentCaptureFile,
     * removing special items, a maybe duplicate entry and every item above count_max */
    int shortcut = Qt::Key_0;
    foreach (recent_item_status *ri, wsApp->recent_item_list()) {
        // Add the new item
        ra = new QAction(recentMenu);
        ra->setData(ri->filename);
        // XXX - Needs get_recent_item_status or equivalent
        ra->setEnabled(ri->accessible);
        recentMenu->insertAction(NULL, ra);
        action_cf_name = ra->data().toString();
        if (shortcut <= Qt::Key_9) {
            ra->setShortcut(Qt::META | shortcut);
            shortcut++;
        }
        ra->setText(action_cf_name);
        connect(ra, SIGNAL(triggered()), this, SLOT(recentActionTriggered()));
    }

    if (recentMenu->actions().count() > 0) {
        // Separator + "Clear"
        // XXX - Do we really need this?
        ra = new QAction(recentMenu);
        ra->setSeparator(true);
        recentMenu->insertAction(NULL, ra);

        ra = new QAction(recentMenu);
        ra->setText(tr("Clear Menu"));
        recentMenu->insertAction(NULL, ra);
        connect(ra, SIGNAL(triggered()), wsApp, SLOT(clearRecentItems()));
    } else {
        if (main_ui_->actionDummyNoFilesFound) {
            recentMenu->addAction(main_ui_->actionDummyNoFilesFound);
        }
    }
}

void MainWindow::recentActionTriggered() {
    QAction *ra = qobject_cast<QAction*>(sender());

    if (ra) {
        QString cfPath = ra->data().toString();
        openCaptureFile(cfPath);
    }
}



// File Menu

void MainWindow::on_actionFileOpen_triggered()
{
    openCaptureFile();
}

void MainWindow::on_actionFileMerge_triggered()
{
    mergeCaptureFile();
}

void MainWindow::on_actionFileImport_triggered()
{
    importCaptureFile();
}

void MainWindow::on_actionFileClose_triggered() {
    if (testCaptureFileClose())
        main_ui_->mainStack->setCurrentWidget(main_welcome_);
}

void MainWindow::on_actionFileSave_triggered()
{
    saveCaptureFile(cap_file_, FALSE);
}

void MainWindow::on_actionFileSaveAs_triggered()
{
    saveAsCaptureFile(cap_file_, FALSE, TRUE);
}

void MainWindow::on_actionFileExportPackets_triggered()
{
    exportSelectedPackets();
}

void MainWindow::on_actionFileSetListFiles_triggered()
{
    file_set_dialog_.exec();
}

void MainWindow::on_actionFileSetNextFile_triggered()
{
    fileset_entry *entry = fileset_get_next();

    if (entry) {
        QString new_cf_path = entry->fullname;
        openCaptureFile(new_cf_path);
    }
}

void MainWindow::on_actionFileSetPreviousFile_triggered()
{
    fileset_entry *entry = fileset_get_previous();

    if (entry) {
        QString new_cf_path = entry->fullname;
        openCaptureFile(new_cf_path);
    }
}

// View Menu

// Expand / collapse slots in proto_tree

// Go Menu

// Next / previous / first / last slots in packet_list

// Help Menu
void MainWindow::on_actionHelpContents_triggered() {

    topic_action(HELP_CONTENT);
}

void MainWindow::on_actionHelpMPWireshark_triggered() {

    topic_action(LOCALPAGE_MAN_WIRESHARK);
}
void MainWindow::on_actionHelpMPWireshark_Filter_triggered() {

    topic_action(LOCALPAGE_MAN_WIRESHARK_FILTER);
}
void MainWindow::on_actionHelpMPTShark_triggered() {

    topic_action(LOCALPAGE_MAN_TSHARK);
}
void MainWindow::on_actionHelpMPRawShark_triggered() {

    topic_action(LOCALPAGE_MAN_RAWSHARK);
}
void MainWindow::on_actionHelpMPDumpcap_triggered() {

    topic_action(LOCALPAGE_MAN_DUMPCAP);
}
void MainWindow::on_actionHelpMPMergecap_triggered() {

    topic_action(LOCALPAGE_MAN_MERGECAP);
}
void MainWindow::on_actionHelpMPEditcap_triggered() {

    topic_action(LOCALPAGE_MAN_EDITCAP);
}
void MainWindow::on_actionHelpMPText2cap_triggered() {

    topic_action(LOCALPAGE_MAN_TEXT2PCAP);
}

void MainWindow::on_actionHelpWebsite_triggered() {

    topic_action(ONLINEPAGE_HOME);
}

void MainWindow::on_actionHelpFAQ_triggered() {

    topic_action(ONLINEPAGE_FAQ);
}

void MainWindow::on_actionHelpAsk_triggered() {

    topic_action(ONLINEPAGE_ASK);
}

void MainWindow::on_actionHelpDownloads_triggered() {

    topic_action(ONLINEPAGE_DOWNLOAD);
}

void MainWindow::on_actionHelpWiki_triggered() {

    topic_action(ONLINEPAGE_WIKI);
}

void MainWindow::on_actionHelpSampleCaptures_triggered() {

    topic_action(ONLINEPAGE_SAMPLE_FILES);
}

void MainWindow::on_actionGoGoToPacket_triggered() {
    if (packet_list_->model()->rowCount() < 1) {
        return;
    }
    previous_focus_ = wsApp->focusWidget();
    connect(previous_focus_, SIGNAL(destroyed()), this, SLOT(resetPreviousFocus()));
    main_ui_->goToFrame->show();
    main_ui_->goToLineEdit->setFocus();
}

void MainWindow::resetPreviousFocus() {
    previous_focus_ = NULL;
}

void MainWindow::on_goToCancel_clicked()
{
    main_ui_->goToFrame->hide();
    if (previous_focus_) {
        disconnect(previous_focus_, SIGNAL(destroyed()), this, SLOT(resetPreviousFocus()));
        previous_focus_->setFocus();
        resetPreviousFocus();
    }
}

void MainWindow::on_goToGo_clicked()
{
    int packet_num = main_ui_->goToLineEdit->text().toInt();

    if (packet_num > 0) {
        packet_list_->goToPacket(packet_num);
    }
    on_goToCancel_clicked();
}

void MainWindow::on_goToLineEdit_returnPressed()
{
    on_goToGo_clicked();
}

void MainWindow::on_actionStartCapture_triggered()
{
//#ifdef HAVE_AIRPCAP
//  airpcap_if_active = airpcap_if_selected;
//  if (airpcap_if_active)
//    airpcap_set_toolbar_start_capture(airpcap_if_active);
//#endif

//  if (cap_open_w) {
//    /*
//     * There's an options dialog; get the values from it and close it.
//     */
//    gboolean success;

//    /* Determine if "capture start" while building of the "capture options" window */
//    /*  is in progress. If so, ignore the "capture start.                          */
//    /* XXX: Would it be better/cleaner for the "capture options" window code to    */
//    /*      disable the capture start button temporarily ?                         */
//    if (cap_open_complete == FALSE) {
//      return;  /* Building options window: ignore "capture start" */
//    }
//    success = capture_dlg_prep(cap_open_w);
//    window_destroy(GTK_WIDGET(cap_open_w));
//    if (!success)
//      return;   /* error in options dialog */
//  }

    main_ui_->mainStack->setCurrentWidget(packet_splitter_);

    if (global_capture_opts.num_selected == 0) {
        QMessageBox::critical(
                    this,
                    tr("No Interface Selected"),
                    tr("You didn't specify an interface on which to capture packets."),
                    QMessageBox::Ok
                    );
        return;
    }

    /* XXX - will closing this remove a temporary file? */
    if (testCaptureFileClose(FALSE, *new QString(" before starting a new capture")))
        startCapture();
}

void MainWindow::on_actionStopCapture_triggered()
{
    stopCapture();
}

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
