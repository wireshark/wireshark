/* main_window_slots.cpp
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

#include <config.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "main_window.h"
#include "ui_main_window.h"

#include "globals.h"

#include <wsutil/filesystem.h>
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

#include "wsutil/file_util.h"

#include "epan/column.h"
#include <epan/epan_dissect.h>
#include "epan/filter_expressions.h"
#include <epan/value_string.h>

#include "ui/alert_box.h"
#include "ui/ui_util.h"
#include "ui/capture_globals.h"
#include "ui/help_url.h"
#include "ui/main_statusbar.h"
#include "ui/preference_utils.h"
#include "ui/ssl_key_export.h"

#ifdef HAVE_SOFTWARE_UPDATE
#include "ui/software_update.h"
#endif

#include "capture_file_dialog.h"
#include "decode_as_dialog.h"
#include "export_object_dialog.h"
#include "export_pdu_dialog.h"
#include "io_graph_dialog.h"
#include "lbm_stream_dialog.h"
#include "lbm_uimflow_dialog.h"
#include "lbm_lbtrm_transport_dialog.h"
#include "lbm_lbtru_transport_dialog.h"
#include "packet_comment_dialog.h"
#include "preferences_dialog.h"
#include "print_dialog.h"
#include "profile_dialog.h"
#include "qt_ui_utils.h"
#include "sctp_all_assocs_dialog.h"
#include "sctp_assoc_analyse_dialog.h"
#include "sctp_graph_dialog.h"
#include "sequence_dialog.h"
#include "stats_tree_dialog.h"
#include "tcp_stream_dialog.h"
#include "time_shift_dialog.h"
#include "wireshark_application.h"

#include <QClipboard>
#include <QMessageBox>

#include <QDebug>

//
// Public slots
//

const char *dfe_property_ = "display filter expression"; //TODO : Fix Translate

void MainWindow::openCaptureFile(QString& cf_path, QString& display_filter, unsigned int type)
{
    QString file_name = "";
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

            if (open_dlg.open(file_name, type)) {
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

        /* Try to open the capture file. This closes the current file if it succeeds. */
        cfile.window = this;
        if (cf_open(&cfile, cf_path.toUtf8().constData(), type, FALSE, &err) != CF_OK) {
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
    if(display_filter != NULL)
    {
        df_combo_box_->setEditText(display_filter);
    }

    main_ui_->statusBar->showExpert();
}

void MainWindow::filterPackets(QString& new_filter, bool force)
{
    cf_status_t cf_status;

    cf_status = cf_filter_packets(&cfile, new_filter.toUtf8().data(), force);

    if (cf_status == CF_OK) {
        emit displayFilterSuccess(true);
        if (new_filter.length() > 0) {
            int index = df_combo_box_->findText(new_filter);
            if (index == -1) {
                df_combo_box_->insertItem(0, new_filter);
                df_combo_box_->setCurrentIndex(0);
            }
            else {
                df_combo_box_->setCurrentIndex(index);
            }
        }
    } else {
        emit displayFilterSuccess(false);
    }
}

void MainWindow::layoutPanes()
{
    QSplitter *parents[3];

    // Reparent all widgets and add them back in the proper order below.
    // This hides each widget as well.
    packet_list_->setParent(main_ui_->mainStack);
    proto_tree_->setParent(main_ui_->mainStack);
    byte_view_tab_->setParent(main_ui_->mainStack);
    empty_pane_.setParent(main_ui_->mainStack);
    extra_split_.setParent(main_ui_->mainStack);

    switch(prefs.gui_layout_type) {
    case(layout_type_2):
    case(layout_type_1):
        extra_split_.setOrientation(Qt::Horizontal);
    case(layout_type_5):
        master_split_.setOrientation(Qt::Vertical);
        break;

    case(layout_type_4):
    case(layout_type_3):
        extra_split_.setOrientation(Qt::Vertical);
    case(layout_type_6):
        master_split_.setOrientation(Qt::Horizontal);
        break;

    default:
        g_assert_not_reached();
    }

    switch(prefs.gui_layout_type) {
    case(layout_type_5):
    case(layout_type_6):
        parents[0] = &master_split_;
        parents[1] = &master_split_;
        parents[2] = &master_split_;
        break;
    case(layout_type_2):
    case(layout_type_4):
        parents[0] = &master_split_;
        parents[1] = &extra_split_;
        parents[2] = &extra_split_;
        break;
    case(layout_type_1):
    case(layout_type_3):
        parents[0] = &extra_split_;
        parents[1] = &extra_split_;
        parents[2] = &master_split_;
        break;
    default:
        g_assert_not_reached();
    }

    if (parents[0] == &extra_split_) {
        master_split_.addWidget(&extra_split_);
    }

    parents[0]->addWidget(getLayoutWidget(prefs.gui_layout_content_1));

    if (parents[2] == &extra_split_) {
        master_split_.addWidget(&extra_split_);
    }

    parents[1]->addWidget(getLayoutWidget(prefs.gui_layout_content_2));
    parents[2]->addWidget(getLayoutWidget(prefs.gui_layout_content_3));

    for (int i = 0; i < master_split_.count(); i++) {
        master_split_.widget(i)->show();
    }
    for (int i = 0; i < extra_split_.count(); i++) {
        extra_split_.widget(i)->show();
    }
}

// Capture callbacks

void MainWindow::captureCapturePrepared(capture_session *cap_session) {
#ifdef HAVE_LIBPCAP
    qDebug() << "FIX captureCapturePrepared";
    setTitlebarForCaptureInProgress();

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
    main_ui_->mainStack->setCurrentWidget(&master_split_);
    cap_file_ = (capture_file *) cap_session->cf;
#else
    Q_UNUSED(cap_session)
#endif // HAVE_LIBPCAP
}
void MainWindow::captureCaptureUpdateStarted(capture_session *cap_session) {
    Q_UNUSED(cap_session);
#ifdef HAVE_LIBPCAP

    /* We've done this in "prepared" above, but it will be cleared while
       switching to the next multiple file. */
    setTitlebarForCaptureInProgress();

    setForCaptureInProgress(true);

    setForCapturedPackets(true);
#endif // HAVE_LIBPCAP
}
void MainWindow::captureCaptureUpdateFinished(capture_session *cap_session) {
    Q_UNUSED(cap_session);
#ifdef HAVE_LIBPCAP

    /* The capture isn't stopping any more - it's stopped. */
    capture_stopping_ = false;

    /* Update the main window as appropriate */
    updateForUnsavedChanges();

    /* Enable menu items that make sense if you're not currently running
     a capture. */
    setForCaptureInProgress(false);
#endif // HAVE_LIBPCAP
}
void MainWindow::captureCaptureFixedStarted(capture_session *cap_session) {
    Q_UNUSED(cap_session);
#ifdef HAVE_LIBPCAP
    qDebug() << "captureCaptureFixedStarted";
#endif // HAVE_LIBPCAP
}
void MainWindow::captureCaptureFixedFinished(capture_session *cap_session) {
    Q_UNUSED(cap_session);
#ifdef HAVE_LIBPCAP
    qDebug() << "captureCaptureFixedFinished";

    /* The capture isn't stopping any more - it's stopped. */
    capture_stopping_ = false;

    /* Enable menu items that make sense if you're not currently running
     a capture. */
    setForCaptureInProgress(false);
#endif // HAVE_LIBPCAP
}
void MainWindow::captureCaptureStopping(capture_session *cap_session) {
    Q_UNUSED(cap_session);
#ifdef HAVE_LIBPCAP

    capture_stopping_ = true;
    setMenusForCaptureStopping();
#endif // HAVE_LIBPCAP
}
void MainWindow::captureCaptureFailed(capture_session *cap_session) {
    Q_UNUSED(cap_session);
#ifdef HAVE_LIBPCAP
    qDebug() << "captureCaptureFailed";
    /* Capture isn't stopping any more. */
    capture_stopping_ = false;

    setForCaptureInProgress(false);
#endif // HAVE_LIBPCAP
}


// Callbacks from cfile.c via WiresharkApplication::captureFileCallback

void MainWindow::captureFileOpened(const capture_file *cf) {
    if (cf->window != this) return;
    cap_file_ = (capture_file *) cf;

    file_set_dialog_.fileOpened(cf);
    setMenusForFileSet(true);
    emit setCaptureFile(cap_file_);
}

void MainWindow::captureFileReadStarted(const capture_file *cf) {
    if (cf != cap_file_) return;
//    tap_param_dlg_update();

    /* Set up main window for a capture file. */
//    main_set_for_capture_file(TRUE);

    main_ui_->statusBar->popFileStatus();
    QString msg = QString(tr("Loading: %1")).arg(get_basename(cf->filename));
    main_ui_->statusBar->pushFileStatus(msg);
    main_ui_->mainStack->setCurrentWidget(&master_split_);
    WiresharkApplication::processEvents();
}

void MainWindow::captureFileReadFinished(const capture_file *cf) {
    if (cf != cap_file_) return;

//    gchar *dir_path;

//    if (!cf->is_tempfile && cf->filename) {
//        /* Add this filename to the list of recent files in the "Recent Files" submenu */
//        add_menu_recent_capture_file(cf->filename);

//        /* Remember folder for next Open dialog and save it in recent */
//  dir_path = get_dirname(g_strdup(cf->filename));
//        wsApp->setLastOpenDir(dir_path);
//        g_free(dir_path);
//    }

    /* Update the appropriate parts of the main window. */
    updateForUnsavedChanges();

    /* Enable menu items that make sense if you have some captured packets. */
    setForCapturedPackets(true);

    main_ui_->statusBar->popFileStatus();
    QString msg = QString().sprintf("%s", get_basename(cf->filename));
    main_ui_->statusBar->pushFileStatus(msg);
    emit setDissectedCaptureFile(cap_file_);
}

void MainWindow::captureFileClosing(const capture_file *cf) {
    if (cf != cap_file_) return;

    setMenusForCaptureFile(true);
    setForCapturedPackets(false);
    setMenusForSelectedPacket();
    setForCaptureInProgress(false);

    // Reset expert info indicator
    main_ui_->statusBar->hideExpert();
    main_ui_->searchFrame->animatedHide();
//    gtk_widget_show(expert_info_none);
    emit setCaptureFile(NULL);
    emit setDissectedCaptureFile(NULL);
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

    summary_dialog_.close();

    if (df_combo_box_)
    {
        df_combo_box_->lineEdit()->setText("");
        df_combo_box_->applyDisplayFilter();
    }

    setTitlebarForSelectedTreeRow();
    setMenusForSelectedTreeRow();
}

void MainWindow::configurationProfileChanged(const gchar *profile_name) {
    Q_UNUSED(profile_name);
    /* Update window view and redraw the toolbar */
//    main_titlebar_update();
    filterExpressionsChanged();
//    toolbar_redraw_all();

    /* Reload list of interfaces on welcome page */
//    welcome_if_panel_reload();

    /* Recreate the packet list according to new preferences */
    recreatePacketList();

    /* Reload pane geometry, must be done after recreating the list */
    //    main_pane_load_window_geometry();
}

void MainWindow::filterExpressionsChanged()
{
    // Recreate filter buttons
    foreach (QAction *act, main_ui_->displayFilterToolBar->actions()) {
        // Permanent actions shouldn't have data
        if (act->property(dfe_property_).isValid()) {
            main_ui_->displayFilterToolBar->removeAction(act);
            delete act;
        }
    }

    for (struct filter_expression *fe = *pfilter_expression_head; fe != NULL; fe = fe->next) {
        if (!fe->enabled) continue;
        QAction *dfb_action = new QAction(fe->label, main_ui_->displayFilterToolBar);
        dfb_action->setToolTip(fe->expression);
        dfb_action->setData(fe->expression);
        dfb_action->setProperty(dfe_property_, true);
        main_ui_->displayFilterToolBar->addAction(dfb_action);
        connect(dfb_action, SIGNAL(triggered()), this, SLOT(displayFilterButtonClicked()));
    }
}

//
// Private slots
//

// ui/gtk/capture_dlg.c:start_capture_confirmed

void MainWindow::startCapture() {
#ifdef HAVE_LIBPCAP
    interface_options interface_opts;
    guint i;

    /* did the user ever select a capture interface before? */
    if(global_capture_opts.num_selected == 0) {
        QString msg = QString("No interface selected");
        main_ui_->statusBar->pushTemporaryStatus(msg);
        return;
    }

    // Ideally we should have disabled the start capture
    // toolbar buttons and menu items. This may not be the
    // case, e.g. with QtMacExtras.
    if(!capture_filter_valid_) {
        QString msg = QString("Invalid capture filter");
        main_ui_->statusBar->pushTemporaryStatus(msg);
        return;
    }

    /* XXX - we might need to init other pref data as well... */
//    main_auto_scroll_live_changed(auto_scroll_live);

    /* XXX - can this ever happen? */
    if (global_capture_session.state != CAPTURE_STOPPED)
      return;

    /* close the currently loaded capture file */
    cf_close((capture_file *) global_capture_session.cf);

    /* Copy the selected interfaces to the set of interfaces to use for
       this capture. */
    collect_ifaces(&global_capture_opts);

    cfile.window = this;
    if (capture_start(&global_capture_opts, &global_capture_session, main_window_update)) {
        /* The capture succeeded, which means the capture filter syntax is
         valid; add this capture filter to the recent capture filter list. */
        for (i = 0; i < global_capture_opts.ifaces->len; i++) {
            interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, i);
            if (interface_opts.cfilter) {
//              cfilter_combo_add_recent(interface_opts.cfilter);
            }
        }
    } else {
        cfile.window = NULL;
    }
#endif // HAVE_LIBPCAP
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

#ifdef HAVE_LIBPCAP
    capture_stop(&global_capture_session);
#endif // HAVE_LIBPCAP
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
    foreach (recent_item_status *ri, wsApp->recentItems()) {
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

void MainWindow::setMenusForSelectedPacket()
{
//    GList      *list_entry = dissector_filter_list;
//    guint       i          = 0;
//    gboolean    properties = FALSE;
//    const char *abbrev     = NULL;
//    char       *prev_abbrev;
#if 0
    gboolean is_ip = FALSE, is_tcp = FALSE, is_udp = FALSE, is_sctp = FALSE;
#else
    gboolean is_tcp = FALSE, is_sctp = FALSE;
#endif

//    /* Making the menu context-sensitive allows for easier selection of the
//       desired item and has the added benefit, with large captures, of
//       avoiding needless looping through huge lists for marked, ignored,
//       or time-referenced packets. */
//    gboolean is_ssl = epan_dissect_packet_contains_field(cf->edt, "ssl");

    /* We have one or more items in the packet list */
    gboolean have_frames = FALSE;
    /* A frame is selected */
    gboolean frame_selected = FALSE;
    /* We have marked frames.  (XXX - why check frame_selected?) */
    gboolean have_marked = FALSE;
    /* We have a marked frame other than the current frame (i.e.,
       we have at least one marked frame, and either there's more
       than one marked frame or the current frame isn't marked). */
    gboolean another_is_marked = FALSE;
    /* One or more frames are hidden by a display filter */
    gboolean have_filtered = FALSE;
    /* One or more frames have been ignored */
    gboolean have_ignored = FALSE;
    gboolean have_time_ref = FALSE;
    /* We have a time reference frame other than the current frame (i.e.,
       we have at least one time reference frame, and either there's more
       than one time reference frame or the current frame isn't a
       time reference frame). (XXX - why check frame_selected?) */
    gboolean another_is_time_ref = FALSE;

    if (cap_file_) {
        frame_selected = cap_file_->current_frame != NULL;
        have_frames = cap_file_->count > 0;
        have_marked = frame_selected && cap_file_->marked_count > 0;
        another_is_marked = have_marked &&
                !(cap_file_->marked_count == 1 && cap_file_->current_frame->flags.marked);
        have_filtered = cap_file_->displayed_count > 0 && cap_file_->displayed_count != cap_file_->count;
        have_ignored = cap_file_->ignored_count > 0;
        have_time_ref = cap_file_->ref_time_count > 0;
        another_is_time_ref = frame_selected && have_time_ref &&
                !(cap_file_->ref_time_count == 1 && cap_file_->current_frame->flags.ref_time);

        if (cap_file_->edt)
        {
            proto_get_frame_protocols(cap_file_->edt->pi.layers, NULL, &is_tcp, NULL, &is_sctp, NULL);
        }
    }
//    if (cfile.edt && cfile.edt->tree) {
//        GPtrArray          *ga;
//        header_field_info  *hfinfo;
//        field_info         *v;
//        guint              ii;

//        ga = proto_all_finfos(cfile.edt->tree);

//        for (ii = ga->len - 1; ii > 0 ; ii -= 1) {

//            v = g_ptr_array_index (ga, ii);
//            hfinfo =  v->hfinfo;

//            if (!g_str_has_prefix(hfinfo->abbrev, "text") &&
//                !g_str_has_prefix(hfinfo->abbrev, "_ws.expert") &&
//                !g_str_has_prefix(hfinfo->abbrev, "_ws.malformed")) {

//                if (hfinfo->parent == -1) {
//                    abbrev = hfinfo->abbrev;
//                } else {
//                    abbrev = proto_registrar_get_abbrev(hfinfo->parent);
//                }
//                properties = prefs_is_registered_protocol(abbrev);
//                break;
//            }
//        }
//    }

    main_ui_->actionEditMarkPacket->setEnabled(frame_selected);
    main_ui_->actionEditMarkAllDisplayed->setEnabled(have_frames);
    /* Unlike un-ignore, do not allow unmark of all frames when no frames are displayed  */
    main_ui_->actionEditUnmarkAllDisplayed->setEnabled(have_marked);
    main_ui_->actionEditNextMark->setEnabled(another_is_marked);
    main_ui_->actionEditPreviousMark->setEnabled(another_is_marked);

//#ifdef WANT_PACKET_EDITOR
//    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/EditMenu/EditPacket",
//                         frame_selected);
//#endif /* WANT_PACKET_EDITOR */
    main_ui_->actionEditPacketComment->setEnabled(frame_selected && wtap_dump_can_write(cap_file_->linktypes, WTAP_COMMENT_PER_PACKET));

    main_ui_->actionEditIgnorePacket->setEnabled(frame_selected);
    main_ui_->actionEditIgnoreAllDisplayed->setEnabled(have_filtered);
    /* Allow un-ignore of all frames even with no frames currently displayed */
    main_ui_->actionEditUnignoreAllDisplayed->setEnabled(have_ignored);

    main_ui_->actionEditSetTimeReference->setEnabled(frame_selected);
    main_ui_->actionEditUnsetAllTimeReferences->setEnabled(have_time_ref);
    main_ui_->actionEditNextTimeReference->setEnabled(another_is_time_ref);
    main_ui_->actionEditPreviousTimeReference->setEnabled(another_is_time_ref);
    main_ui_->actionEditTimeShift->setEnabled(have_frames);

//    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/ViewMenu/ResizeAllColumns",
//                         frame_selected);
//    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/ViewMenu/CollapseAll",
//                         frame_selected);
//    set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/CollapseAll",
//                         frame_selected);
//    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/ViewMenu/ExpandAll",
//                         frame_selected);
//    set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/ExpandAll",
//                         frame_selected);
//    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/ViewMenu/ColorizeConversation",
//                         frame_selected);
//    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/ViewMenu/ResetColoring1-10",
//                         tmp_color_filters_used());
//    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/ViewMenu/ShowPacketinNewWindow",
//                         frame_selected);
//    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ShowPacketinNewWindow",
//                         frame_selected);
//    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ManuallyResolveAddress",
//                         frame_selected ? is_ip : FALSE);
//    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/SCTP",
//                         frame_selected ? is_sctp : FALSE);
//    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/FollowTCPStream",
//                         frame_selected ? is_tcp : FALSE);
//    set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/FollowTCPStream",
//                         frame_selected ? is_tcp : FALSE);
//    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/FollowUDPStream",
//                         frame_selected ? is_udp : FALSE);
//    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/FollowSSLStream",
//                         frame_selected ? is_ssl : FALSE);
//    set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/FollowSSLStream",
//                         frame_selected ? is_ssl : FALSE);
//    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ConversationFilter",
//                         frame_selected);
//    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ConversationFilter/Ethernet",
//                         frame_selected ? (cf->edt->pi.dl_src.type == AT_ETHER) : FALSE);
//    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ConversationFilter/IP",
//                         frame_selected ? is_ip : FALSE);
//    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ConversationFilter/TCP",
//                         frame_selected ? is_tcp : FALSE);
//    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ConversationFilter/UDP",
//                         frame_selected ? is_udp : FALSE);
//    set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/FollowUDPStream",
//                         frame_selected ? is_udp : FALSE);
//    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ConversationFilter/PN-CBA",
//                         frame_selected ? (cf->edt->pi.profinet_type != 0 && cf->edt->pi.profinet_type < 10) : FALSE);
//    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ColorizeConversation",
//                         frame_selected);
//    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ColorizeConversation/Ethernet",
//                         frame_selected ? (cf->edt->pi.dl_src.type == AT_ETHER) : FALSE);
//    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ColorizeConversation/IP",
//                         frame_selected ? is_ip : FALSE);
//    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ColorizeConversation/TCP",
//                         frame_selected ? is_tcp : FALSE);
//    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ColorizeConversation/UDP",
//                         frame_selected ? is_udp : FALSE);
//    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ColorizeConversation/PN-CBA",
//                         frame_selected ? (cf->edt->pi.profinet_type != 0 && cf->edt->pi.profinet_type < 10) : FALSE);

//    if (properties) {
//        prev_abbrev = g_object_get_data(G_OBJECT(ui_manager_packet_list_menu), "menu_abbrev");
//        if (!prev_abbrev || (strcmp(prev_abbrev, abbrev) != 0)) {
//          /*No previous protocol or protocol changed - update Protocol Preferences menu*/
//            module_t *prefs_module_p = prefs_find_module(abbrev);
//            rebuild_protocol_prefs_menu(prefs_module_p, properties, ui_manager_packet_list_menu, "/PacketListMenuPopup/ProtocolPreferences");

//            g_object_set_data(G_OBJECT(ui_manager_packet_list_menu), "menu_abbrev", g_strdup(abbrev));
//            g_free (prev_abbrev);
//        }
//    }

//    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ProtocolPreferences",
//                             properties);
//    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/Copy",
//                         frame_selected);
//    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/ApplyAsFilter",
//                         frame_selected);
//    set_menu_sensitivity(ui_manager_packet_list_menu, "/PacketListMenuPopup/PrepareaFilter",
//                         frame_selected);
//    set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/ResolveName",
//                         frame_selected && (gbl_resolv_flags.mac_name || gbl_resolv_flags.network_name ||
//                                            gbl_resolv_flags.transport_name || gbl_resolv_flags.concurrent_dns));
//    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/AnalyzeMenu/FollowTCPStream",
//                         frame_selected ? is_tcp : FALSE);
//    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/AnalyzeMenu/FollowUDPStream",
//                         frame_selected ? is_udp : FALSE);
//    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/AnalyzeMenu/FollowSSLStream",
//                         frame_selected ? is_ssl : FALSE);
//    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/ViewMenu/NameResolution/ResolveName",
//                         frame_selected && (gbl_resolv_flags.mac_name || gbl_resolv_flags.network_name ||
//                                            gbl_resolv_flags.transport_name || gbl_resolv_flags.concurrent_dns));
//    set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/ToolsMenu/FirewallACLRules",
//                         frame_selected);
    main_ui_->menuTcpStreamGraphs->setEnabled(is_tcp);
    main_ui_->menuSCTP->setEnabled(is_sctp);
    main_ui_->actionSCTPAnalyseThisAssociation->setEnabled(is_sctp);
    main_ui_->actionSCTPShowAllAssociations->setEnabled(is_sctp);
    main_ui_->actionSCTPFilterThisAssociation->setEnabled(is_sctp);

//    while (list_entry != NULL) {
//        dissector_filter_t *filter_entry;
//        gchar *path;

//        filter_entry = list_entry->data;
//        path = g_strdup_printf("/Menubar/AnalyzeMenu/ConversationFilterMenu/Filters/filter-%u", i);

//        set_menu_sensitivity(ui_manager_main_menubar, path,
//            menu_dissector_filter_spe_cb(/* frame_data *fd _U_*/ NULL, cf->edt, filter_entry));
//        g_free(path);
//        i++;
//        list_entry = g_list_next(list_entry);
//    }
}

void MainWindow::setMenusForSelectedTreeRow(field_info *fi) {
    //gboolean properties;
    //gint id;

    // XXX Add commented items below

    if (cap_file_) {
        cap_file_->finfo_selected = fi;
    }

    if (cap_file_ != NULL && fi != NULL) {
        /*
        header_field_info *hfinfo = fi->hfinfo;
        const char *abbrev;
        char *prev_abbrev;

        if (hfinfo->parent == -1) {
            abbrev = hfinfo->abbrev;
            id = (hfinfo->type == FT_PROTOCOL) ? proto_get_id((protocol_t *)hfinfo->strings) : -1;
        } else {
            abbrev = proto_registrar_get_abbrev(hfinfo->parent);
            id = hfinfo->parent;
        }
        properties = prefs_is_registered_protocol(abbrev);
        */
        bool can_match_selected = proto_can_match_selected(cap_file_->finfo_selected, cap_file_->edt);
//        set_menu_sensitivity(ui_manager_tree_view_menu,
//                             "/TreeViewPopup/GotoCorrespondingPacket", hfinfo->type == FT_FRAMENUM);
//        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/Copy",
//                             TRUE);

//        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/ApplyasColumn",
//                             hfinfo->type != FT_NONE);
//        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/ColorizewithFilter",
//                             proto_can_match_selected(cf->finfo_selected, cf->edt));
//        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/ProtocolPreferences",
//                             properties);
//        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/DisableProtocol",
//                             (id == -1) ? FALSE : proto_can_toggle_protocol(id));
//        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/ExpandSubtrees",
//                             cf->finfo_selected->tree_type != -1);
//        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/WikiProtocolPage",
//                             (id == -1) ? FALSE : TRUE);
//        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/FilterFieldReference",
//                             (id == -1) ? FALSE : TRUE);
//        set_menu_sensitivity(ui_manager_main_menubar,
        main_ui_->actionFileExportPacketBytes->setEnabled(true);

//        set_menu_sensitivity(ui_manager_main_menubar,
//                             "/Menubar/GoMenu/GotoCorrespondingPacket", hfinfo->type == FT_FRAMENUM);

        main_ui_->actionEditCopyDescription->setEnabled(can_match_selected);
        main_ui_->actionEditCopyFieldName->setEnabled(can_match_selected);
        main_ui_->actionEditCopyValue->setEnabled(can_match_selected);
        main_ui_->actionEditCopyAsFilter->setEnabled(can_match_selected);
//        set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/EditMenu/Copy/Description",
//                             proto_can_match_selected(cf->finfo_selected, cf->edt));
//        set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/EditMenu/Copy/Fieldname",
//                             proto_can_match_selected(cf->finfo_selected, cf->edt));
//        set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/EditMenu/Copy/Value",
//                             proto_can_match_selected(cf->finfo_selected, cf->edt));
//        set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/EditMenu/Copy/AsFilter",
//                             proto_can_match_selected(cf->finfo_selected, cf->edt));

//        set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/AnalyzeMenu/ApplyasColumn",
//                             hfinfo->type != FT_NONE);
        main_ui_->actionAnalyzeAAFSelected->setEnabled(can_match_selected);
        main_ui_->actionAnalyzeAAFNotSelected->setEnabled(can_match_selected);
        main_ui_->actionAnalyzeAAFAndSelected->setEnabled(can_match_selected);
        main_ui_->actionAnalyzeAAFOrSelected->setEnabled(can_match_selected);
        main_ui_->actionAnalyzeAAFAndNotSelected->setEnabled(can_match_selected);
        main_ui_->actionAnalyzeAAFOrNotSelected->setEnabled(can_match_selected);

        main_ui_->actionAnalyzePAFSelected->setEnabled(can_match_selected);
        main_ui_->actionAnalyzePAFNotSelected->setEnabled(can_match_selected);
        main_ui_->actionAnalyzePAFAndSelected->setEnabled(can_match_selected);
        main_ui_->actionAnalyzePAFOrSelected->setEnabled(can_match_selected);
        main_ui_->actionAnalyzePAFAndNotSelected->setEnabled(can_match_selected);
        main_ui_->actionAnalyzePAFOrNotSelected->setEnabled(can_match_selected);

        main_ui_->actionViewExpandSubtrees->setEnabled(cap_file_->finfo_selected->tree_type != -1);
//        prev_abbrev = g_object_get_data(G_OBJECT(ui_manager_tree_view_menu), "menu_abbrev");
//        if (!prev_abbrev || (strcmp (prev_abbrev, abbrev) != 0)) {
//            /* No previous protocol or protocol changed - update Protocol Preferences menu */
//            module_t *prefs_module_p = prefs_find_module(abbrev);
//            rebuild_protocol_prefs_menu (prefs_module_p, properties);

//            g_object_set_data(G_OBJECT(ui_manager_tree_view_menu), "menu_abbrev", g_strdup(abbrev));
//            g_free (prev_abbrev);
//        }
    } else {
//        set_menu_sensitivity(ui_manager_tree_view_menu,
//                             "/TreeViewPopup/GotoCorrespondingPacket", FALSE);
//        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/Copy", FALSE);
//        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/ApplyasColumn", FALSE);
//        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/ApplyAsFilter", FALSE);
//        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/PrepareaFilter", FALSE);
//        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/ColorizewithFilter", FALSE);
//        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/ProtocolPreferences",
//                             FALSE);
//        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/DisableProtocol", FALSE);
//        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/ExpandSubtrees", FALSE);
//        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/WikiProtocolPage",
//                             FALSE);
//        set_menu_sensitivity(ui_manager_tree_view_menu, "/TreeViewPopup/FilterFieldReference",
//                             FALSE);
        main_ui_->actionFileExportPacketBytes->setEnabled(false);
//        set_menu_sensitivity(ui_manager_main_menubar,
//                             "/Menubar/GoMenu/GotoCorrespondingPacket", FALSE);
        main_ui_->actionEditCopyDescription->setEnabled(false);
        main_ui_->actionEditCopyFieldName->setEnabled(false);
        main_ui_->actionEditCopyValue->setEnabled(false);
        main_ui_->actionEditCopyAsFilter->setEnabled(false);
//        set_menu_sensitivity(ui_manager_main_menubar, "/Menubar/AnalyzeMenu/ApplyasColumn", FALSE);

        main_ui_->actionAnalyzeAAFSelected->setEnabled(false);
        main_ui_->actionAnalyzeAAFNotSelected->setEnabled(false);
        main_ui_->actionAnalyzeAAFAndSelected->setEnabled(false);
        main_ui_->actionAnalyzeAAFOrSelected->setEnabled(false);
        main_ui_->actionAnalyzeAAFAndNotSelected->setEnabled(false);
        main_ui_->actionAnalyzeAAFOrNotSelected->setEnabled(false);

        main_ui_->actionAnalyzePAFSelected->setEnabled(false);
        main_ui_->actionAnalyzePAFNotSelected->setEnabled(false);
        main_ui_->actionAnalyzePAFAndSelected->setEnabled(false);
        main_ui_->actionAnalyzePAFOrSelected->setEnabled(false);
        main_ui_->actionAnalyzePAFAndNotSelected->setEnabled(false);
        main_ui_->actionAnalyzePAFOrNotSelected->setEnabled(false);

        main_ui_->actionViewExpandSubtrees->setEnabled(false);
    }
}

void MainWindow::interfaceSelectionChanged()
{
#ifdef HAVE_LIBPCAP
    // XXX This doesn't disable the toolbar button when using
    // QtMacExtras.
    if (global_capture_opts.num_selected > 0 && capture_filter_valid_) {
        main_ui_->actionStartCapture->setEnabled(true);
    } else {
        main_ui_->actionStartCapture->setEnabled(false);
    }
#endif // HAVE_LIBPCAP
}

void MainWindow::captureFilterSyntaxChanged(bool valid)
{
    capture_filter_valid_ = valid;
    interfaceSelectionChanged();
}

void MainWindow::startInterfaceCapture(bool valid)
{
    capture_filter_valid_ = valid;
    startCapture();
}

void MainWindow::redissectPackets()
{
    if (cap_file_)
        cf_redissect_packets(cap_file_);
    main_ui_->statusBar->expertUpdate();
}

void MainWindow::recreatePacketList()
{
    prefs.num_cols = g_list_length(prefs.col_list);

    col_cleanup(&cfile.cinfo);
    build_column_format_array(&cfile.cinfo, prefs.num_cols, FALSE);

    packet_list_->updateAll();
    packet_list_->hide();
    packet_list_->show();

    cfile.columns_changed = FALSE; /* Reset value */
}

void MainWindow::setFeaturesEnabled(bool enabled)
{
    main_ui_->menuBar->setEnabled(enabled);
    main_ui_->mainToolBar->setEnabled(enabled);
    main_ui_->displayFilterToolBar->setEnabled(enabled);
    if(enabled)
    {
        main_ui_->statusBar->clearMessage();
    }
    else
    {
        main_ui_->statusBar->showMessage(tr("Please wait while Wireshark is initializing . . ."));
    }
}

// On Qt4 + OS X with unifiedTitleAndToolBarOnMac set it's possible to make
// the main window obnoxiously wide.

// We might want to do something different here. We should probably merge
// the dfilter and gui.filter_expressions code first.
void MainWindow::addDisplayFilterButton(QString df_text)
{
    struct filter_expression *cur_fe = *pfilter_expression_head;
    struct filter_expression *fe = g_new0(struct filter_expression, 1);

    QFontMetrics fm = main_ui_->displayFilterToolBar->fontMetrics();
    QString label = fm.elidedText(df_text, Qt::ElideMiddle, fm.height() * 15);

    fe->enabled = TRUE;
    fe->label = qstring_strdup(label);
    fe->expression = qstring_strdup(df_text);

    if (!cur_fe) {
        *pfilter_expression_head = fe;
    } else {
        while (cur_fe->next) {
            cur_fe = cur_fe->next;
        }
        cur_fe->next = fe;
    }

    prefs_main_write();
    filterExpressionsChanged();
}

void MainWindow::displayFilterButtonClicked()
{
    QAction *dfb_action = qobject_cast<QAction*>(sender());

    if (dfb_action) {
        df_combo_box_->lineEdit()->setText(dfb_action->data().toString());
        df_combo_box_->applyDisplayFilter();
        df_combo_box_->lineEdit()->setFocus();
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

void MainWindow::on_actionFileImportFromHexDump_triggered()
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

void MainWindow::on_actionFileExportPackets_triggered()
{
    exportSelectedPackets();
}

void MainWindow::on_actionFileExportAsPlainText_triggered()
{
    exportDissections(export_type_text);
}

void MainWindow::on_actionFileExportAsCSV_triggered()
{
    exportDissections(export_type_csv);
}

void MainWindow::on_actionFileExportAsCArrays_triggered()
{
    exportDissections(export_type_carrays);
}

void MainWindow::on_actionFileExportAsPSML_triggered()
{
    exportDissections(export_type_psml);
}

void MainWindow::on_actionFileExportAsPDML_triggered()
{
    exportDissections(export_type_pdml);
}

void MainWindow::on_actionFileExportPacketBytes_triggered()
{
    QString file_name;

    if (!cap_file_ || !cap_file_->finfo_selected) return;

    file_name = QFileDialog::getSaveFileName(this,
                                             tr("Wireshark: Export Selected Packet Bytes"),
                                             wsApp->lastOpenDir().canonicalPath(),
                                             tr("Raw data (*.bin *.dat *.raw);;Any File (*.*)")
                                             );

    if (file_name.length() > 0) {
        const guint8 *data_p;
        int fd;

        data_p = tvb_get_ptr(cap_file_->finfo_selected->ds_tvb, 0, -1) +
                cap_file_->finfo_selected->start;
        fd = ws_open(file_name.toUtf8().constData(), O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, 0666);
        if (fd == -1) {
            open_failure_alert_box(file_name.toUtf8().constData(), errno, TRUE);
            return;
        }
        if (write(fd, data_p, cfile.finfo_selected->length) < 0) {
            write_failure_alert_box(file_name.toUtf8().constData(), errno);
            ::close(fd);
            return;
        }
        if (::close(fd) < 0) {
            write_failure_alert_box(file_name.toUtf8().constData(), errno);
            return;
        }

        /* Save the directory name for future file dialogs. */
        wsApp->setLastOpenDir(&file_name);
    }
}
void MainWindow::on_actionFileExportPDU_triggered()
{
    ExportPDUDialog *exportpdu_dialog = new ExportPDUDialog(this);

    if (exportpdu_dialog->isMinimized() == true)
    {
        exportpdu_dialog->showNormal();
    }
    else
    {
        exportpdu_dialog->show();
    }

    exportpdu_dialog->raise();
    exportpdu_dialog->activateWindow();
}

void MainWindow::on_actionFileExportSSLSessionKeys_triggered()
{
    QString file_name;
    QString save_title;
    int keylist_len;

    keylist_len = ssl_session_key_count();
    /* don't show up the dialog, if no data has to be saved */
    if (keylist_len < 1) {
        /* shouldn't happen as the menu item should have been greyed out */
        QMessageBox::warning(
                    this,
                    tr("No Keys"),
                    tr("There are no SSL Session Keys to save."),
                    QMessageBox::Ok
                    );
        return;
    }

    save_title.append(QString("Wireshark: Export SSL Session Keys (%1 key%2").
            arg(keylist_len).arg(plurality(keylist_len, "", "s")));
    file_name = QFileDialog::getSaveFileName(this,
                                             save_title,
                                             wsApp->lastOpenDir().canonicalPath(),
                                             tr("SSL Session Keys (*.keys *.txt);;Any File (*.*)")
                                             );
    if (file_name.length() > 0) {
        gchar *keylist;
        int fd;

        keylist = ssl_export_sessions();
        fd = ws_open(file_name.toUtf8().constData(), O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, 0666);
        if (fd == -1) {
            open_failure_alert_box(file_name.toUtf8().constData(), errno, TRUE);
            g_free(keylist);
            return;
        }
        /*
         * Thanks, Microsoft, for not using size_t for the third argument to
         * _write().  Presumably this string will be <= 4GiB long....
         */
        if (ws_write(fd, keylist, (unsigned int)strlen(keylist)) < 0) {
            write_failure_alert_box(file_name.toUtf8().constData(), errno);
            ::close(fd);
            g_free(keylist);
            return;
        }
        if (::close(fd) < 0) {
            write_failure_alert_box(file_name.toUtf8().constData(), errno);
            g_free(keylist);
            return;
        }

        /* Save the directory name for future file dialogs. */
        wsApp->setLastOpenDir(&file_name);
        g_free(keylist);
    }
}

void MainWindow::on_actionFileExportObjectsDICOM_triggered()
{
    new ExportObjectDialog(this, cap_file_, ExportObjectDialog::Dicom);
}

void MainWindow::on_actionFileExportObjectsHTTP_triggered()
{
    new ExportObjectDialog(this, cap_file_, ExportObjectDialog::Http);
}

void MainWindow::on_actionFileExportObjectsSMB_triggered()
{
    new ExportObjectDialog(this, cap_file_, ExportObjectDialog::Smb);
}

void MainWindow::on_actionFileExportObjectsTFTP_triggered()
{
    new ExportObjectDialog(this, cap_file_, ExportObjectDialog::Tftp);
}

void MainWindow::on_actionFilePrint_triggered()
{
    PrintDialog pdlg(this, cap_file_);

    pdlg.exec();
}

// Edit Menu

// XXX This should probably be somewhere else.
void MainWindow::actionEditCopyTriggered(MainWindow::CopySelected selection_type)
{
    char label_str[ITEM_LABEL_LENGTH];
    QString clip;

    if (!cap_file_) return;

    switch(selection_type) {
    case CopySelectedDescription:
        if (cap_file_->finfo_selected->rep &&
                strlen (cap_file_->finfo_selected->rep->representation) > 0) {
            clip.append(cap_file_->finfo_selected->rep->representation);
        }
        break;
    case CopySelectedFieldName:
        if (cap_file_->finfo_selected->hfinfo->abbrev != 0) {
            clip.append(cap_file_->finfo_selected->hfinfo->abbrev);
        }
        break;
    case CopySelectedValue:
        if (cap_file_->edt != 0) {
            gchar* field_str = get_node_field_value(cap_file_->finfo_selected, cap_file_->edt);
            clip.append(field_str);
            g_free(field_str);
        }
        break;
    }

    if (clip.length() == 0) {
        /* If no representation then... Try to read the value */
        proto_item_fill_label(cap_file_->finfo_selected, label_str);
        clip.append(label_str);
    }

    if (clip.length()) {
        wsApp->clipboard()->setText(clip);
    } else {
        QString err = tr("Couldn't copy text. Try another item.");
        main_ui_->statusBar->pushTemporaryStatus(err);
    }
}

void MainWindow::on_actionEditCopyDescription_triggered()
{
    actionEditCopyTriggered(CopySelectedDescription);
}

void MainWindow::on_actionEditCopyFieldName_triggered()
{
    actionEditCopyTriggered(CopySelectedFieldName);
}

void MainWindow::on_actionEditCopyValue_triggered()
{
    actionEditCopyTriggered(CopySelectedValue);
}

void MainWindow::on_actionEditCopyAsFilter_triggered()
{
    matchSelectedFilter(MatchSelectedReplace, false, true);
}

void MainWindow::on_actionEditFindPacket_triggered()
{
    if (packet_list_->model()->rowCount() < 1) {
        return;
    }
    previous_focus_ = wsApp->focusWidget();
    connect(previous_focus_, SIGNAL(destroyed()), this, SLOT(resetPreviousFocus()));
    main_ui_->goToFrame->animatedHide();
    if (main_ui_->searchFrame->isVisible()) {
        main_ui_->searchFrame->animatedHide();
    } else {
        main_ui_->searchFrame->animatedShow();
    }
}

void MainWindow::on_actionEditFindNext_triggered()
{
    main_ui_->searchFrame->findNext();
}

void MainWindow::on_actionEditFindPrevious_triggered()
{
    main_ui_->searchFrame->findPrevious();
}

void MainWindow::on_actionEditMarkPacket_triggered()
{
    packet_list_->markFrame();
}

void MainWindow::on_actionEditMarkAllDisplayed_triggered()
{
    packet_list_->markAllDisplayedFrames(true);
}

void MainWindow::on_actionEditUnmarkAllDisplayed_triggered()
{
    packet_list_->markAllDisplayedFrames(false);
}

void MainWindow::on_actionEditNextMark_triggered()
{
    if (cap_file_)
        cf_find_packet_marked(cap_file_, SD_FORWARD);
}

void MainWindow::on_actionEditPreviousMark_triggered()
{
    if (cap_file_)
        cf_find_packet_marked(cap_file_, SD_BACKWARD);
}

void MainWindow::on_actionEditIgnorePacket_triggered()
{
    packet_list_->ignoreFrame();
}

void MainWindow::on_actionEditIgnoreAllDisplayed_triggered()
{
    packet_list_->ignoreAllDisplayedFrames(true);
}

void MainWindow::on_actionEditUnignoreAllDisplayed_triggered()
{
    packet_list_->ignoreAllDisplayedFrames(false);
}

void MainWindow::on_actionEditSetTimeReference_triggered()
{
    packet_list_->setTimeReference();
}

void MainWindow::on_actionEditUnsetAllTimeReferences_triggered()
{
    packet_list_->unsetAllTimeReferences();
}

void MainWindow::on_actionEditNextTimeReference_triggered()
{
    if (!cap_file_) return;
    cf_find_packet_time_reference(cap_file_, SD_FORWARD);
}

void MainWindow::on_actionEditPreviousTimeReference_triggered()
{
    if (!cap_file_) return;
    cf_find_packet_time_reference(cap_file_, SD_BACKWARD);
}

void MainWindow::on_actionEditTimeShift_triggered()
{
    TimeShiftDialog ts_dialog(this, cap_file_);
    connect(this, SIGNAL(setCaptureFile(capture_file*)),
            &ts_dialog, SLOT(setCaptureFile(capture_file*)));
    ts_dialog.exec();
}

void MainWindow::on_actionEditPacketComment_triggered()
{
    PacketCommentDialog pc_dialog(this, packet_list_->packetComment());
    if (pc_dialog.exec() == QDialog::Accepted) {
        packet_list_->setPacketComment(pc_dialog.text());
        updateForUnsavedChanges();
    }
}

void MainWindow::on_actionEditConfigurationProfiles_triggered()
{
    ProfileDialog cp_dialog;

    cp_dialog.exec();
}

void MainWindow::on_actionEditPreferences_triggered()
{
    PreferencesDialog pref_dialog;

    pref_dialog.exec();
}

// View Menu

void MainWindow::on_actionViewReload_triggered()
{
    cf_reload(&cfile);
}

// gets called when user checks/unchecks the View->Toolbar->Main Toolbar
void MainWindow::on_actionViewToolbarMainToolbar_triggered()
{
    // just checking for isChecked() was sufficient here, but I was worried about a loop
    // so I'm checking both conditions
    if (main_ui_->actionViewToolbarMainToolbar->isChecked() && !main_ui_->mainToolBar->isVisible()) {
        main_ui_->mainToolBar->show();
    } else if (!main_ui_->actionViewToolbarMainToolbar->isChecked() && main_ui_->mainToolBar->isVisible()) {
        main_ui_->mainToolBar->hide();
    }
}

// gets called when user checks/unchecks the View->Toolbar->Display Filter
void MainWindow::on_actionViewToolbarDisplayFilter_triggered()
{
    // just checking for isChecked() was sufficient here, but I was worried about a loop
    // so I'm checking both conditions
    if (main_ui_->actionViewToolbarDisplayFilter->isChecked() && !main_ui_->displayFilterToolBar->isVisible()) {
        main_ui_->displayFilterToolBar->show();
    } else if (!main_ui_->actionViewToolbarDisplayFilter->isChecked() && main_ui_->displayFilterToolBar->isVisible()) {
        main_ui_->displayFilterToolBar->hide();
    }
}

// Expand / collapse slots in proto_tree

// Go Menu

// Analyze Menu

// XXX This should probably be somewhere else.
void MainWindow::matchSelectedFilter(MainWindow::MatchSelected filter_type, bool apply, bool copy_only)
{
    QString field_filter;
    QString cur_filter;
    QString new_filter;

    if (packet_list_->contextMenuActive()) {
        field_filter = packet_list_->getFilterFromRowAndColumn();
    } else if (cap_file_ && cap_file_->finfo_selected) {
        field_filter = proto_construct_match_selected_string(cap_file_->finfo_selected,
                                                       cap_file_->edt);
    } else {
        return;
    }

    if (field_filter.isEmpty()) {
        QString err = tr("No filter available. Try another ");
        err.append(packet_list_->contextMenuActive() ? "column" : "item");
        err.append(".");
        main_ui_->statusBar->pushTemporaryStatus(err);
        return;
    }

    if (!df_combo_box_) return;

    cur_filter = df_combo_box_->lineEdit()->text();

    switch (filter_type) {
    case MatchSelectedReplace:
        new_filter = field_filter;
        break;
    case MatchSelectedAnd:
        if (cur_filter.length()) {
            new_filter = "(" + cur_filter + ") && (" + field_filter + ")";
        } else {
            new_filter = field_filter;
        }
        break;
    case MatchSelectedOr:
        if (cur_filter.length()) {
            new_filter = "(" + cur_filter + ") || (" + field_filter + ")";
        } else {
            new_filter = field_filter;
        }
        break;
    case MatchSelectedNot:
        new_filter = "!(" + field_filter + ")";
        break;
    case MatchSelectedAndNot:
        if (cur_filter.length()) {
            new_filter = "(" + cur_filter + ") && !(" + field_filter + ")";
        } else {
            new_filter = "!(" + field_filter + ")";
        }
        break;
    case MatchSelectedOrNot:
        if (cur_filter.length()) {
            new_filter = "(" + cur_filter + ") || !(" + field_filter + ")";
        } else {
            new_filter = "!(" + field_filter + ")";
        }
        break;
    default:
        g_assert_not_reached();
        break;
    }

    if (copy_only) {
        wsApp->clipboard()->setText(new_filter);
    } else {
        df_combo_box_->lineEdit()->setText(new_filter);
        if (apply) {
            df_combo_box_->applyDisplayFilter();
        } else {
            df_combo_box_->lineEdit()->setFocus();
        }
    }

}

void MainWindow::on_actionAnalyzeAAFSelected_triggered()
{
    matchSelectedFilter(MatchSelectedReplace, true, false);
}

void MainWindow::on_actionAnalyzeAAFNotSelected_triggered()
{
    matchSelectedFilter(MatchSelectedNot, true, false);
}

void MainWindow::on_actionAnalyzeAAFAndSelected_triggered()
{
    matchSelectedFilter(MatchSelectedAnd, true, false);
}

void MainWindow::on_actionAnalyzeAAFOrSelected_triggered()
{
    matchSelectedFilter(MatchSelectedOr, true, false);
}

void MainWindow::on_actionAnalyzeAAFAndNotSelected_triggered()
{
    matchSelectedFilter(MatchSelectedAndNot, true, false);
}

void MainWindow::on_actionAnalyzeAAFOrNotSelected_triggered()
{
    matchSelectedFilter(MatchSelectedOrNot, true, false);
}

void MainWindow::on_actionAnalyzePAFSelected_triggered()
{
    matchSelectedFilter(MatchSelectedReplace, false, false);
}

void MainWindow::on_actionAnalyzePAFNotSelected_triggered()
{
    matchSelectedFilter(MatchSelectedNot, false, false);
}

void MainWindow::on_actionAnalyzePAFAndSelected_triggered()
{
    matchSelectedFilter(MatchSelectedAnd, false, false);
}

void MainWindow::on_actionAnalyzePAFOrSelected_triggered()
{
    matchSelectedFilter(MatchSelectedOr, false, false);
}

void MainWindow::on_actionAnalyzePAFAndNotSelected_triggered()
{
    matchSelectedFilter(MatchSelectedAndNot, false, false);
}

void MainWindow::on_actionAnalyzePAFOrNotSelected_triggered()
{
    matchSelectedFilter(MatchSelectedOrNot, false, false);
}

void MainWindow::on_actionAnalyzeDecodeAs_triggered()
{
    QAction *da_action = qobject_cast<QAction*>(sender());
    bool create_new = false;
    if (da_action && da_action->data().toBool() == true) {
        create_new = true;
    }

    DecodeAsDialog da_dialog(this, cap_file_, create_new);
    connect(this, SIGNAL(setCaptureFile(capture_file*)),
            &da_dialog, SLOT(setCaptureFile(capture_file*)));
    da_dialog.exec();
}

void MainWindow::openFollowStreamDialog(follow_type_t type) {
    FollowStreamDialog *fsd = new FollowStreamDialog(this, type, cap_file_);
    connect(fsd, SIGNAL(updateFilter(QString&, bool)), this, SLOT(filterPackets(QString&, bool)));
    connect(fsd, SIGNAL(goToPacket(int)), packet_list_, SLOT(goToPacket(int)));

    fsd->follow(getFilter());
    fsd->show();
}

void MainWindow::on_actionAnalyzeFollowTCPStream_triggered()
{
    openFollowStreamDialog(FOLLOW_TCP);
}

void MainWindow::on_actionAnalyzeFollowUDPStream_triggered()
{
    openFollowStreamDialog(FOLLOW_UDP);
}

void MainWindow::on_actionAnalyzeFollowSSLStream_triggered()
{
    openFollowStreamDialog(FOLLOW_SSL);
}

void MainWindow::openSCTPAllAssocsDialog()
{
    SCTPAllAssocsDialog *sctp_dialog = new SCTPAllAssocsDialog(this, cap_file_);
    connect(sctp_dialog, SIGNAL(filterPackets(QString&,bool)),
            this, SLOT(filterPackets(QString&,bool)));
    connect(this, SIGNAL(setCaptureFile(capture_file*)),
            sctp_dialog, SLOT(setCaptureFile(capture_file*)));
    sctp_dialog->fillTable();

    if (sctp_dialog->isMinimized() == true)
    {
        sctp_dialog->showNormal();
    }
    else
    {
        sctp_dialog->show();
    }

    sctp_dialog->raise();
    sctp_dialog->activateWindow();
}

void MainWindow::on_actionSCTPShowAllAssociations_triggered()
{
    openSCTPAllAssocsDialog();
}

void MainWindow::on_actionSCTPAnalyseThisAssociation_triggered()
{
    SCTPAssocAnalyseDialog *sctp_analyse = new SCTPAssocAnalyseDialog(this, NULL, cap_file_);
    connect(sctp_analyse, SIGNAL(filterPackets(QString&,bool)),
            this, SLOT(filterPackets(QString&,bool)));

    if (sctp_analyse->isMinimized() == true)
    {
        sctp_analyse->showNormal();
    }
    else
    {
        sctp_analyse->show();
    }

    sctp_analyse->raise();
    sctp_analyse->activateWindow();
}

void MainWindow::on_actionSCTPFilterThisAssociation_triggered()
{
    sctp_assoc_info_t* assoc = SCTPAssocAnalyseDialog::findAssocForPacket(cap_file_);
    if (assoc) {
        QString newFilter = QString("sctp.assoc_index==%1").arg(assoc->assoc_id);
        assoc = NULL;
        emit filterPackets(newFilter, false);
    }
}


// Next / previous / first / last slots in packet_list

// Statistics Menu

void MainWindow::on_actionStatisticsFlowGraph_triggered()
{
    SequenceDialog *sequence_dialog = new SequenceDialog(this, cap_file_);
    connect(sequence_dialog, SIGNAL(goToPacket(int)),
            packet_list_, SLOT(goToPacket(int)));
    connect(this, SIGNAL(setCaptureFile(capture_file*)),
            sequence_dialog, SLOT(setCaptureFile(capture_file*)));
    sequence_dialog->show();
}

void MainWindow::openTcpStreamDialog(int graph_type)
{
    TCPStreamDialog *stream_dialog = new TCPStreamDialog(this, cap_file_, (tcp_graph_type)graph_type);
    connect(stream_dialog, SIGNAL(goToPacket(int)),
            packet_list_, SLOT(goToPacket(int)));
    connect(this, SIGNAL(setCaptureFile(capture_file*)),
            stream_dialog, SLOT(setCaptureFile(capture_file*)));
    stream_dialog->show();
}

void MainWindow::on_actionStatisticsTcpStreamStevens_triggered()
{
    openTcpStreamDialog(GRAPH_TSEQ_STEVENS);
}

void MainWindow::on_actionStatisticsTcpStreamTcptrace_triggered()
{
    openTcpStreamDialog(GRAPH_TSEQ_TCPTRACE);
}

void MainWindow::on_actionStatisticsTcpStreamThroughput_triggered()
{
    openTcpStreamDialog(GRAPH_THROUGHPUT);
}

void MainWindow::on_actionStatisticsTcpStreamRoundTripTime_triggered()
{
    openTcpStreamDialog(GRAPH_RTT);
}

void MainWindow::on_actionStatisticsTcpStreamWindowScaling_triggered()
{
    openTcpStreamDialog(GRAPH_WSCALE);
}

void MainWindow::openStatisticsTreeDialog(const gchar *abbr)
{
    StatsTreeDialog *st_dialog = new StatsTreeDialog(this, cap_file_, abbr);
//    connect(st_dialog, SIGNAL(goToPacket(int)),
//            packet_list_, SLOT(goToPacket(int)));
    connect(this, SIGNAL(setCaptureFile(capture_file*)),
            st_dialog, SLOT(setCaptureFile(capture_file*)));
    st_dialog->show();
}

void MainWindow::on_actionStatistics29WestTopics_Advertisements_by_Topic_triggered()
{
    openStatisticsTreeDialog("lbmr_topic_ads_topic");
}

void MainWindow::on_actionStatistics29WestTopics_Advertisements_by_Source_triggered()
{
    openStatisticsTreeDialog("lbmr_topic_ads_source");
}

void MainWindow::on_actionStatistics29WestTopics_Advertisements_by_Transport_triggered()
{
    openStatisticsTreeDialog("lbmr_topic_ads_transport");
}

void MainWindow::on_actionStatistics29WestTopics_Queries_by_Topic_triggered()
{
    openStatisticsTreeDialog("lbmr_topic_queries_topic");
}

void MainWindow::on_actionStatistics29WestTopics_Queries_by_Receiver_triggered()
{
    openStatisticsTreeDialog("lbmr_topic_queries_receiver");
}

void MainWindow::on_actionStatistics29WestTopics_Wildcard_Queries_by_Pattern_triggered()
{
    openStatisticsTreeDialog("lbmr_topic_queries_pattern");
}

void MainWindow::on_actionStatistics29WestTopics_Wildcard_Queries_by_Receiver_triggered()
{
    openStatisticsTreeDialog("lbmr_topic_queries_pattern_receiver");
}

void MainWindow::on_actionStatistics29WestQueues_Advertisements_by_Queue_triggered()
{
    openStatisticsTreeDialog("lbmr_queue_ads_queue");
}

void MainWindow::on_actionStatistics29WestQueues_Advertisements_by_Source_triggered()
{
    openStatisticsTreeDialog("lbmr_queue_ads_source");
}

void MainWindow::on_actionStatistics29WestQueues_Queries_by_Queue_triggered()
{
    openStatisticsTreeDialog("lbmr_queue_queries_queue");
}

void MainWindow::on_actionStatistics29WestQueues_Queries_by_Receiver_triggered()
{
    openStatisticsTreeDialog("lbmr_queue_queries_receiver");
}

void MainWindow::on_actionStatistics29WestUIM_Streams_triggered()
{
    LBMStreamDialog *stream_dialog = new LBMStreamDialog(this, cap_file_);
//    connect(stream_dialog, SIGNAL(goToPacket(int)),
//            packet_list_, SLOT(goToPacket(int)));
    connect(this, SIGNAL(setCaptureFile(capture_file*)),
            stream_dialog, SLOT(setCaptureFile(capture_file*)));
    stream_dialog->show();
}

void MainWindow::on_actionStatistics29WestUIM_Stream_Flow_Graph_triggered()
{
    LBMUIMFlowDialog * uimflow_dialog = new LBMUIMFlowDialog(this, cap_file_);
    connect(uimflow_dialog, SIGNAL(goToPacket(int)),
            packet_list_, SLOT(goToPacket(int)));
    connect(this, SIGNAL(setCaptureFile(capture_file*)),
            uimflow_dialog, SLOT(setCaptureFile(capture_file*)));
    uimflow_dialog->show();
}

void MainWindow::on_actionStatistics29WestLBTRM_triggered()
{
    LBMLBTRMTransportDialog * lbtrm_dialog = new LBMLBTRMTransportDialog(this, cap_file_);
    connect(lbtrm_dialog, SIGNAL(goToPacket(int)),
            packet_list_, SLOT(goToPacket(int)));
    connect(this, SIGNAL(setCaptureFile(capture_file*)),
            lbtrm_dialog, SLOT(setCaptureFile(capture_file*)));
    lbtrm_dialog->show();
}
void MainWindow::on_actionStatistics29WestLBTRU_triggered()
{
    LBMLBTRUTransportDialog * lbtru_dialog = new LBMLBTRUTransportDialog(this, cap_file_);
    connect(lbtru_dialog, SIGNAL(goToPacket(int)),
            packet_list_, SLOT(goToPacket(int)));
    connect(this, SIGNAL(setCaptureFile(capture_file*)),
            lbtru_dialog, SLOT(setCaptureFile(capture_file*)));
    lbtru_dialog->show();
}

void MainWindow::on_actionStatisticsANCP_triggered()
{
    openStatisticsTreeDialog("ancp");
}

void MainWindow::on_actionStatisticsBACappInstanceId_triggered()
{
    openStatisticsTreeDialog("bacapp_instanceid");
}

void MainWindow::on_actionStatisticsBACappIP_triggered()
{
    openStatisticsTreeDialog("bacapp_ip");
}

void MainWindow::on_actionStatisticsBACappObjectId_triggered()
{
    openStatisticsTreeDialog("bacapp_objectid");
}

void MainWindow::on_actionStatisticsBACappService_triggered()
{
    openStatisticsTreeDialog("bacapp_service");
}

void MainWindow::on_actionStatisticsCollectd_triggered()
{
    openStatisticsTreeDialog("collectd");
}

void MainWindow::on_actionStatisticsHART_IP_triggered()
{
    openStatisticsTreeDialog("hart_ip");
}

void MainWindow::on_actionStatisticsHTTPPacketCounter_triggered()
{
    openStatisticsTreeDialog("http");
}

void MainWindow::on_actionStatisticsHTTPRequests_triggered()
{
    openStatisticsTreeDialog("http_req");
}

void MainWindow::on_actionStatisticsHTTPLoadDistribution_triggered()
{
    openStatisticsTreeDialog("http_srv");
}

void MainWindow::on_actionStatisticsPacketLen_triggered()
{
    openStatisticsTreeDialog("plen");
}

void MainWindow::on_actionStatisticsIOGraph_triggered()
{
    IOGraphDialog *iog_dialog = new IOGraphDialog(this, cap_file_);
    connect(iog_dialog, SIGNAL(goToPacket(int)), packet_list_, SLOT(goToPacket(int)));
    connect(this, SIGNAL(setCaptureFile(capture_file*)),
            iog_dialog, SLOT(setCaptureFile(capture_file*)));
    iog_dialog->show();
}

void MainWindow::on_actionStatisticsSametime_triggered()
{
    openStatisticsTreeDialog("sametime");
}

// Telephony Menu

void MainWindow::on_actionTelephonyISUPMessages_triggered()
{
    openStatisticsTreeDialog("isup_msg");
}

void MainWindow::on_actionTelephonyRTSPPacketCounter_triggered()
{
    openStatisticsTreeDialog("rtsp");
}

void MainWindow::on_actionTelephonySMPPOperations_triggered()
{
    openStatisticsTreeDialog("smpp_commands");
}

void MainWindow::on_actionTelephonyUCPMessages_triggered()
{
    openStatisticsTreeDialog("ucp_messages");
}

// Help Menu
void MainWindow::on_actionHelpContents_triggered() {

    wsApp->helpTopicAction(HELP_CONTENT);
}

void MainWindow::on_actionHelpMPWireshark_triggered() {

    wsApp->helpTopicAction(LOCALPAGE_MAN_WIRESHARK);
}

void MainWindow::on_actionHelpMPWireshark_Filter_triggered() {
    wsApp->helpTopicAction(LOCALPAGE_MAN_WIRESHARK_FILTER);
}

void MainWindow::on_actionHelpMPCapinfos_triggered() {
    wsApp->helpTopicAction(LOCALPAGE_MAN_CAPINFOS);
}

void MainWindow::on_actionHelpMPDumpcap_triggered() {
    wsApp->helpTopicAction(LOCALPAGE_MAN_DUMPCAP);
}

void MainWindow::on_actionHelpMPEditcap_triggered() {
    wsApp->helpTopicAction(LOCALPAGE_MAN_EDITCAP);
}

void MainWindow::on_actionHelpMPMergecap_triggered() {
    wsApp->helpTopicAction(LOCALPAGE_MAN_MERGECAP);
}

void MainWindow::on_actionHelpMPRawShark_triggered() {
    wsApp->helpTopicAction(LOCALPAGE_MAN_RAWSHARK);
}

void MainWindow::on_actionHelpMPReordercap_triggered() {
    wsApp->helpTopicAction(LOCALPAGE_MAN_REORDERCAP);
}

 void MainWindow::on_actionHelpMPText2cap_triggered() {
    wsApp->helpTopicAction(LOCALPAGE_MAN_TEXT2PCAP);
}

void MainWindow::on_actionHelpMPTShark_triggered() {
    wsApp->helpTopicAction(LOCALPAGE_MAN_TSHARK);
}

void MainWindow::on_actionHelpWebsite_triggered() {

    wsApp->helpTopicAction(ONLINEPAGE_HOME);
}

void MainWindow::on_actionHelpFAQ_triggered() {

    wsApp->helpTopicAction(ONLINEPAGE_FAQ);
}

void MainWindow::on_actionHelpAsk_triggered() {

    wsApp->helpTopicAction(ONLINEPAGE_ASK);
}

void MainWindow::on_actionHelpDownloads_triggered() {

    wsApp->helpTopicAction(ONLINEPAGE_DOWNLOAD);
}

void MainWindow::on_actionHelpWiki_triggered() {

    wsApp->helpTopicAction(ONLINEPAGE_WIKI);
}

void MainWindow::on_actionHelpSampleCaptures_triggered() {

    wsApp->helpTopicAction(ONLINEPAGE_SAMPLE_FILES);
}

#ifdef HAVE_SOFTWARE_UPDATE
void MainWindow::on_actionHelpCheckForUpdates_triggered()
{
    software_update_check();
}
#endif

void MainWindow::on_actionHelpAbout_triggered()
{
    AboutDialog *about_dialog = new AboutDialog(this);

    if (about_dialog->isMinimized() == true)
    {
        about_dialog->showNormal();
    }
    else
    {
        about_dialog->show();
    }

    about_dialog->raise();
    about_dialog->activateWindow();
}

void MainWindow::on_actionGoGoToPacket_triggered() {
    if (packet_list_->model()->rowCount() < 1) {
        return;
    }
    previous_focus_ = wsApp->focusWidget();
    connect(previous_focus_, SIGNAL(destroyed()), this, SLOT(resetPreviousFocus()));

    main_ui_->searchFrame->animatedHide();
    if (main_ui_->goToFrame->isVisible()) {
        main_ui_->goToFrame->animatedHide();
    } else {
        main_ui_->goToFrame->animatedShow();
    }
    main_ui_->goToLineEdit->setFocus();
}

void MainWindow::resetPreviousFocus() {
    previous_focus_ = NULL;
}

void MainWindow::on_goToCancel_clicked()
{
    main_ui_->goToFrame->animatedHide();
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

    main_ui_->mainStack->setCurrentWidget(&master_split_);

#ifdef HAVE_LIBPCAP
    if (global_capture_opts.num_selected == 0) {
        QString err_msg = tr("No Interface Selected");
        main_ui_->statusBar->pushTemporaryStatus(err_msg);
        return;
    }

    /* XXX - will closing this remove a temporary file? */
    if (testCaptureFileClose(FALSE, *new QString(" before starting a new capture")))
        startCapture();
#endif // HAVE_LIBPCAP
}

void MainWindow::on_actionStopCapture_triggered()
{
    stopCapture();
}

void MainWindow::on_actionSummary_triggered()
{
    summary_dialog_.UpdateValues();

    if (summary_dialog_.isMinimized() == true)
    {
        summary_dialog_.showNormal();
    }
    else
    {
        summary_dialog_.show();
    }

    summary_dialog_.raise();
    summary_dialog_.activateWindow();
}

#ifdef HAVE_LIBPCAP
void MainWindow::on_actionCaptureInterfaces_triggered()
{
    connect(&capture_interfaces_dialog_, SIGNAL(setFilterValid(bool)), this, SLOT(startInterfaceCapture(bool)));
    capture_interfaces_dialog_.SetTab(0);
    capture_interfaces_dialog_.UpdateInterfaces();

    if (capture_interfaces_dialog_.isMinimized() == true)
    {
        capture_interfaces_dialog_.showNormal();
    }
    else
    {
        capture_interfaces_dialog_.show();
    }

    capture_interfaces_dialog_.raise();
    capture_interfaces_dialog_.activateWindow();
}

void MainWindow::on_actionCaptureOptions_triggered()
{
    capture_interfaces_dialog_.SetTab(2);
    capture_interfaces_dialog_.UpdateInterfaces();

    if (capture_interfaces_dialog_.isMinimized() == true)
    {
        capture_interfaces_dialog_.showNormal();
    }
    else
    {
        capture_interfaces_dialog_.show();
    }

    capture_interfaces_dialog_.raise();
    capture_interfaces_dialog_.activateWindow();
}
#endif


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
