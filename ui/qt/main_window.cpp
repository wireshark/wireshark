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

//#include <wiretap/wtap.h>

#ifdef HAVE_LIBPCAP
#include "capture.h"
#include "capture-pcap-util.h"
#include "capture_ui_utils.h"
#endif

#include "ui/alert_box.h"
#include "ui/main_statusbar.h"
#include "ui/capture_globals.h"

#include "wireshark_application.h"
#include "proto_tree.h"
#include "byte_view_tab.h"
#include "capture_file_dialog.h"
#include "display_filter_edit.h"
#include "import_text_dialog.h"

#include "qt_ui_utils.h"

#include <QTreeWidget>
#include <QTabWidget>
#include <QAction>
#include <QToolButton>
#include <QKeyEvent>
#include <QMetaObject>
#include <QMessageBox>

//menu_recent_file_write_all

// If we ever add support for multiple windows this will need to be replaced.
static MainWindow *gbl_cur_main_window = NULL;

void pipe_input_set_handler(gint source, gpointer user_data, int *child_process, pipe_input_cb_t input_cb)
{
    gbl_cur_main_window->setPipeInputHandler(source, user_data, child_process, input_cb);
}

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    main_ui_(new Ui::MainWindow),
    df_combo_box_(new DisplayFilterCombo()),
    cap_file_(NULL),
    previous_focus_(NULL),
    capture_stopping_(false),
#ifdef _WIN32
    pipe_timer_(NULL)
#else
    pipe_notifier_(NULL)
#endif
{
    QMargins go_to_margins;

    gbl_cur_main_window = this;
    main_ui_->setupUi(this);
    setMenusForCaptureFile();
    setForCaptureInProgress(false);
    setMenusForFileSet(false);

    connect(wsApp, SIGNAL(updateRecentItemStatus(const QString &, qint64, bool)), this, SLOT(updateRecentFiles()));
    updateRecentFiles();

    const DisplayFilterEdit *df_edit = dynamic_cast<DisplayFilterEdit *>(df_combo_box_->lineEdit());
    connect(df_edit, SIGNAL(pushFilterSyntaxStatus(QString&)), main_ui_->statusBar, SLOT(pushFilterStatus(QString&)));
    connect(df_edit, SIGNAL(popFilterSyntaxStatus()), main_ui_->statusBar, SLOT(popFilterStatus()));
    connect(df_edit, SIGNAL(pushFilterSyntaxWarning(QString&)), main_ui_->statusBar, SLOT(pushTemporaryStatus(QString&)));

    main_ui_->mainToolBar->addWidget(df_combo_box_);

    main_ui_->utilityToolBar->hide();

    main_ui_->goToFrame->hide();
    go_to_margins = main_ui_->goToHB->contentsMargins();
    go_to_margins.setTop(0);
    go_to_margins.setBottom(0);
    main_ui_->goToHB->setContentsMargins(go_to_margins);
    // XXX For some reason the cursor is drawn funny with an input mask set
    // https://bugreports.qt-project.org/browse/QTBUG-7174
    main_ui_->goToFrame->setStyleSheet(
                "QFrame {"
                "  background: palette(window);"
                "  padding-top: 0.1em;"
                "  padding-bottom: 0.1em;"
                "  border-bottom: 0.1em solid palette(shadow);"
                "}"
                "QLineEdit {"
                "  max-width: 5em;"
                "}"
                );
#if defined(Q_WS_MAC)
    main_ui_->goToLineEdit->setAttribute(Qt::WA_MacSmallSize, true);
    main_ui_->goToGo->setAttribute(Qt::WA_MacSmallSize, true);
    main_ui_->goToCancel->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    packet_splitter_ = new QSplitter(main_ui_->mainStack);
    packet_splitter_->setObjectName(QString::fromUtf8("splitterV"));
    packet_splitter_->setOrientation(Qt::Vertical);

    packet_list_ = new PacketList(packet_splitter_);

    ProtoTree *proto_tree = new ProtoTree(packet_splitter_);
    proto_tree->setHeaderHidden(true);
    proto_tree->installEventFilter(this);

    ByteViewTab *byte_view_tab = new ByteViewTab(packet_splitter_);
    byte_view_tab->setTabPosition(QTabWidget::South);
    byte_view_tab->setDocumentMode(true);

    packet_list_->setProtoTree(proto_tree);
    packet_list_->setByteViewTab(byte_view_tab);
    packet_list_->installEventFilter(this);

    packet_splitter_->addWidget(packet_list_);
    packet_splitter_->addWidget(proto_tree);
    packet_splitter_->addWidget(byte_view_tab);

    main_ui_->mainStack->addWidget(packet_splitter_);

    main_welcome_ = main_ui_->welcomePage;

#ifdef HAVE_LIBPCAP
    connect(wsApp, SIGNAL(captureCapturePrepared(capture_options *)),
            this, SLOT(captureCapturePrepared(capture_options *)));
    connect(wsApp, SIGNAL(captureCaptureUpdateStarted(capture_options *)),
            this, SLOT(captureCaptureUpdateStarted(capture_options *)));
    connect(wsApp, SIGNAL(captureCaptureUpdateFinished(capture_options *)),
            this, SLOT(captureCaptureUpdateFinished(capture_options *)));
    connect(wsApp, SIGNAL(captureCaptureFixedStarted(capture_options *)),
            this, SLOT(captureCaptureFixedStarted(capture_options *)));
    connect(wsApp, SIGNAL(captureCaptureFixedFinished(capture_options *)),
            this, SLOT(captureCaptureFixedFinished(capture_options *)));
    connect(wsApp, SIGNAL(captureCaptureStopping(capture_options *)),
            this, SLOT(captureCaptureStopping(capture_options *)));
    connect(wsApp, SIGNAL(captureCaptureFailed(capture_options *)),
            this, SLOT(captureCaptureFailed(capture_options *)));
#endif

    connect(wsApp, SIGNAL(captureFileOpened(const capture_file*)),
            this, SLOT(captureFileOpened(const capture_file*)));
    connect(wsApp, SIGNAL(captureFileReadStarted(const capture_file*)),
            this, SLOT(captureFileReadStarted(const capture_file*)));
    connect(wsApp, SIGNAL(captureFileReadFinished(const capture_file*)),
            this, SLOT(captureFileReadFinished(const capture_file*)));
    connect(wsApp, SIGNAL(captureFileClosing(const capture_file*)),
            this, SLOT(captureFileClosing(const capture_file*)));
    connect(wsApp, SIGNAL(captureFileClosed(const capture_file*)),
            this, SLOT(captureFileClosed(const capture_file*)));

    connect(main_welcome_, SIGNAL(recentFileActivated(QString&)),
            this, SLOT(openCaptureFile(QString&)));

    connect(main_ui_->actionGoNextPacket, SIGNAL(triggered()),
            packet_list_, SLOT(goNextPacket()));
    connect(main_ui_->actionGoPreviousPacket, SIGNAL(triggered()),
            packet_list_, SLOT(goPreviousPacket()));
    connect(main_ui_->actionGoFirstPacket, SIGNAL(triggered()),
            packet_list_, SLOT(goFirstPacket()));
    connect(main_ui_->actionGoLastPacket, SIGNAL(triggered()),
            packet_list_, SLOT(goLastPacket()));

    connect(main_ui_->actionViewExpandSubtrees, SIGNAL(triggered()),
            proto_tree, SLOT(expandSubtrees()));
    connect(main_ui_->actionViewExpandAll, SIGNAL(triggered()),
            proto_tree, SLOT(expandAll()));
    connect(main_ui_->actionViewCollapseAll, SIGNAL(triggered()),
            proto_tree, SLOT(collapseAll()));

    connect(proto_tree, SIGNAL(protoItemSelected(QString&)),
            main_ui_->statusBar, SLOT(pushFieldStatus(QString&)));

    connect(proto_tree, SIGNAL(protoItemSelected(bool)),
            main_ui_->actionViewExpandSubtrees, SLOT(setEnabled(bool)));

    connect(&file_set_dialog_, SIGNAL(fileSetOpenCaptureFile(QString&)),
            this, SLOT(openCaptureFile(QString&)));

    main_ui_->mainStack->setCurrentWidget(main_welcome_);
}

MainWindow::~MainWindow()
{
    delete main_ui_;
}

#include <QDebug>
void MainWindow::setPipeInputHandler(gint source, gpointer user_data, int *child_process, pipe_input_cb_t input_cb)
{
    pipe_source_        = source;
    pipe_child_process_ = child_process;
    pipe_user_data_     = user_data;
    pipe_input_cb_      = input_cb;

#ifdef _WIN32
    /* Tricky to use pipes in win9x, as no concept of wait.  NT can
       do this but that doesn't cover all win32 platforms.  GTK can do
       this but doesn't seem to work over processes.  Attempt to do
       something similar here, start a timer and check for data on every
       timeout. */
       /*g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_input_set_handler: new");*/

    if (pipe_timer_) {
        disconnect(pipe_timer_, SIGNAL(timeout()), this, SLOT(pipeTimeout()));
        delete pipe_timer_;
    }

    pipe_timer_ = new QTimer(this);
    connect(pipe_timer_, SIGNAL(timeout()), this, SLOT(pipeTimeout()));
    connect(pipe_timer_, SIGNAL(destroyed()), this, SLOT(pipeNotifierDestroyed()));
    pipe_timer_->start(200);
#else
    if (pipe_notifier_) {
        disconnect(pipe_notifier_, SIGNAL(activated(int)), this, SLOT(pipeActivated(int)));
        delete pipe_notifier_;
    }

    pipe_notifier_ = new QSocketNotifier(pipe_source_, QSocketNotifier::Read);
    // XXX ui/gtk/gui_utils.c sets the encoding. Do we need to do the same?
    connect(pipe_notifier_, SIGNAL(activated(int)), this, SLOT(pipeActivated(int)));
    connect(pipe_notifier_, SIGNAL(destroyed()), this, SLOT(pipeNotifierDestroyed()));
#endif
}


bool MainWindow::eventFilter(QObject *obj, QEvent *event) {

    // The user typed some text. Start filling in a filter.
    // We may need to be more choosy here. We just need to catch events for the packet list,
    // proto tree, and main welcome widgets.
    if (event->type() == QEvent::KeyPress) {
        QKeyEvent *kevt = static_cast<QKeyEvent *>(event);
        if (kevt->text().length() > 0 && kevt->text()[0].isPrint()) {
            df_combo_box_->lineEdit()->insert(kevt->text());
            df_combo_box_->lineEdit()->setFocus();
            return true;
        }
    }

    return QObject::eventFilter(obj, event);
}

void MainWindow::keyPressEvent(QKeyEvent *event) {

    // Explicitly focus on the display filter combo.
    if (event->modifiers() & Qt::ControlModifier && event->key() == Qt::Key_Slash) {
        df_combo_box_->setFocus(Qt::ShortcutFocusReason);
        return;
    }

    if (wsApp->focusWidget() == main_ui_->goToLineEdit) {
        if (event->modifiers() == Qt::NoModifier) {
            if (event->key() == Qt::Key_Escape) {
                on_goToCancel_clicked();
            } else if (event->key() == Qt::Key_Enter || event->key() == Qt::Key_Return) {
                on_goToGo_clicked();
            }
        }
        return; // goToLineEdit didn't want it and we don't either.
    }

    // Move up & down the packet list.
    if (event->key() == Qt::Key_F7) {
        packet_list_->goPreviousPacket();
    } else if (event->key() == Qt::Key_F8) {
        packet_list_->goNextPacket();
    }

    // Move along, citizen.
    QMainWindow::keyPressEvent(event);
}

void MainWindow::closeEvent(QCloseEvent *event) {
   /* If we're in the middle of stopping a capture, don't do anything;
      the user can try deleting the window after the capture stops. */
    if (capture_stopping_) {
        event->ignore();
    }
}


void MainWindow::mergeCaptureFile()
{
    QString file_name = "";
    QString display_filter = "";
    dfilter_t *rfcode = NULL;
    int err;

    if (!cap_file_)
        return;

    if (prefs.gui_ask_unsaved) {
        if (cap_file_->is_tempfile || cap_file_->unsaved_changes) {
            QMessageBox msg_dialog;
            gchar *display_basename;
            int response;

            msg_dialog.setIcon(QMessageBox::Question);
            /* This is a temporary capture file or has unsaved changes; ask the
               user whether to save the capture. */
            if (cap_file_->is_tempfile) {
                msg_dialog.setText(tr("Save packets before merging?"));
                msg_dialog.setInformativeText(tr("A temporary capture file can't be merged."));
            } else {
                /*
                 * Format the message.
                 */
                display_basename = g_filename_display_basename(cap_file_->filename);
                msg_dialog.setText(QString(tr("Save changes in \"%1\" before merging?")).arg(display_basename));
                g_free(display_basename);
                msg_dialog.setInformativeText(tr("Changes must be saved before the files can be merged."));
            }

            msg_dialog.setStandardButtons(QMessageBox::Save | QMessageBox::Cancel);
            msg_dialog.setDefaultButton(QMessageBox::Save);

            response = msg_dialog.exec();

            switch (response) {

            case QMessageBox::Save:
                /* Save the file but don't close it */
                saveCaptureFile(cap_file_, FALSE);
                break;

            case QMessageBox::Cancel:
            default:
                /* Don't do the merge. */
                return;
            }
        }
    }

    for (;;) {
        CaptureFileDialog merge_dlg(this, cap_file_, display_filter);
        int file_type;
        cf_status_t  merge_status;
        char        *in_filenames[2];
        char        *tmpname;

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
                merge_dlg.setDirectory(prefs.gui_fileopen_dir);
            break;
        }

        if (merge_dlg.merge(file_name)) {
            if (dfilter_compile(display_filter.toUtf8().constData(), &rfcode)) {
                cf_set_rfcode(cap_file_, rfcode);
            } else {
                /* Not valid.  Tell the user, and go back and run the file
                   selection box again once they dismiss the alert. */
                //bad_dfilter_alert_box(top_level, display_filter->str);
                QMessageBox::warning(this, tr("Invalid Display Filter"),
                                     QString(tr("The filter expression %1 isn't a valid display filter. (%2).").arg(display_filter, dfilter_error_msg)),
                                     QMessageBox::Ok);
                continue;
            }
        } else {
            return;
        }

        file_type = cap_file_->cd_t;

        /* Try to merge or append the two files */
        tmpname = NULL;
        if (merge_dlg.mergeType() == 0) {
            /* chronological order */
            in_filenames[0] = cap_file_->filename;
            in_filenames[1] = file_name.toUtf8().data();
            merge_status = cf_merge_files(&tmpname, 2, in_filenames, file_type, FALSE);
        } else if (merge_dlg.mergeType() <= 0) {
            /* prepend file */
            in_filenames[0] = file_name.toUtf8().data();
            in_filenames[1] = cap_file_->filename;
            merge_status = cf_merge_files(&tmpname, 2, in_filenames, file_type, TRUE);
        } else {
            /* append file */
            in_filenames[0] = cap_file_->filename;
            in_filenames[1] = file_name.toUtf8().data();
            merge_status = cf_merge_files(&tmpname, 2, in_filenames, file_type, TRUE);
        }

        if (merge_status != CF_OK) {
            if (rfcode != NULL)
                dfilter_free(rfcode);
            g_free(tmpname);
            continue;
        }

        cf_close(cap_file_);

        /* Try to open the merged capture file. */
        if (cf_open(&cfile, tmpname, TRUE /* temporary file */, &err) != CF_OK) {
            /* We couldn't open it; fail. */
            if (rfcode != NULL)
                dfilter_free(rfcode);
            g_free(tmpname);
            return;
        }

        /* Attach the new read filter to "cf" ("cf_open()" succeeded, so
           it closed the previous capture file, and thus destroyed any
           previous read filter attached to "cf"). */
        cfile.rfcode = rfcode;

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
            g_free(tmpname);
            return;
        }

        /* Save the name of the containing directory specified in the path name,
           if any; we can write over cf_merged_name, which is a good thing, given that
           "get_dirname()" does write over its argument. */
        wsApp->setLastOpenDir(get_dirname(tmpname));
        g_free(tmpname);
        df_combo_box_->setEditText(display_filter);
        main_ui_->statusBar->showExpert();
        return;
    }

}

void MainWindow::importCaptureFile() {
    ImportTextDialog import_dlg;

    if (!testCaptureFileClose(FALSE, *new QString(tr(" before importing a new capture"))))
        return;

    import_dlg.exec();

    if (import_dlg.result() != QDialog::Accepted) {
        main_ui_->mainStack->setCurrentWidget(main_welcome_);
        return;
    }

    openCaptureFile(import_dlg.capfileName());
}

void MainWindow::saveCaptureFile(capture_file *cf, bool stay_closed) {
    QString file_name;
    gboolean discard_comments;
    cf_write_status_t status;

    if (cf->is_tempfile) {
        /* This is a temporary capture file, so saving it means saving
           it to a permanent file.  Prompt the user for a location
           to which to save it.  Don't require that the file format
           support comments - if it's a temporary capture file, it's
           probably pcap-ng, which supports comments and, if it's
           not pcap-ng, let the user decide what they want to do
           if they've added comments. */
        saveAsCaptureFile(cf, FALSE, stay_closed);
    } else {
        if (cf->unsaved_changes) {
            /* This is not a temporary capture file, but it has unsaved
               changes, so saving it means doing a "safe save" on top
               of the existing file, in the same format - no UI needed
               unless the file has comments and the file's format doesn't
               support them.

               If the file has comments, does the file's format support them?
               If not, ask the user whether they want to discard the comments
               or choose a different format. */
            switch (CaptureFileDialog::checkSaveAsWithComments(this, cf, cf->cd_t)) {

            case SAVE:
                /* The file can be saved in the specified format as is;
                   just drive on and save in the format they selected. */
                discard_comments = FALSE;
                break;

            case SAVE_WITHOUT_COMMENTS:
                /* The file can't be saved in the specified format as is,
                   but it can be saved without the comments, and the user
                   said "OK, discard the comments", so save it in the
                   format they specified without the comments. */
                discard_comments = TRUE;
                break;

            case SAVE_IN_ANOTHER_FORMAT:
                /* There are file formats in which we can save this that
                   support comments, and the user said not to delete the
                   comments.  Do a "Save As" so the user can select
                   one of those formats and choose a file name. */
                saveAsCaptureFile(cf, TRUE, stay_closed);
                return;

            case CANCELLED:
                /* The user said "forget it".  Just return. */
                return;

            default:
                /* Squelch warnings that discard_comments is being used
                   uninitialized. */
                g_assert_not_reached();
                return;
            }

            /* XXX - cf->filename might get freed out from under us, because
               the code path through which cf_save_packets() goes currently
               closes the current file and then opens and reloads the saved file,
               so make a copy and free it later. */
            file_name = cf->filename;
            status = cf_save_packets(cf, file_name.toUtf8().constData(), cf->cd_t, cf->iscompressed,
                                     discard_comments, stay_closed);
            switch (status) {

            case CF_WRITE_OK:
                /* The save succeeded; we're done.
                   If we discarded comments, redraw the packet list to reflect
                   any packets that no longer have comments. */
                if (discard_comments)
                    packet_list_queue_draw();
                break;

            case CF_WRITE_ERROR:
                /* The write failed.
                   XXX - OK, what do we do now?  Let them try a
                   "Save As", in case they want to try to save to a
                   different directory r file system? */
                break;

            case CF_WRITE_ABORTED:
                /* The write was aborted; just drive on. */
                break;
            }
        }
        /* Otherwise just do nothing. */
    }
}

void MainWindow::saveAsCaptureFile(capture_file *cf, bool must_support_comments, bool stay_closed) {
    QString file_name = "";
    int file_type;
    gboolean compressed;
    cf_write_status_t status;
    gchar   *dirname;
    gboolean discard_comments = FALSE;

    if (!cf) {
        return;
    }

    for (;;) {
        CaptureFileDialog save_as_dlg(this, cf);

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
                save_as_dlg.setDirectory(prefs.gui_fileopen_dir);
            break;
        }

        /* If the file has comments, does the format the user selected
           support them?  If not, ask the user whether they want to
           discard the comments or choose a different format. */
        switch(save_as_dlg.saveAs(file_name, must_support_comments)) {

        case SAVE:
            /* The file can be saved in the specified format as is;
               just drive on and save in the format they selected. */
            discard_comments = FALSE;
            break;

        case SAVE_WITHOUT_COMMENTS:
            /* The file can't be saved in the specified format as is,
               but it can be saved without the comments, and the user
               said "OK, discard the comments", so save it in the
               format they specified without the comments. */
            discard_comments = TRUE;
            break;

        case SAVE_IN_ANOTHER_FORMAT:
            /* There are file formats in which we can save this that
               support comments, and the user said not to delete the
               comments.  The combo box of file formats has had the
               formats that don't support comments trimmed from it,
               so run the dialog again, to let the user decide
               whether to save in one of those formats or give up. */
            discard_comments = FALSE;
            must_support_comments = TRUE;
            continue;

        case CANCELLED:
            /* The user said "forget it".  Just get rid of the dialog box
               and return. */
            return;
        }
        file_type = save_as_dlg.selectedFileType();
        compressed = save_as_dlg.isCompressed();

        fileAddExtension(file_name, file_type, compressed);

//#ifndef _WIN32
//        /* If the file exists and it's user-immutable or not writable,
//                       ask the user whether they want to override that. */
//        if (!file_target_unwritable_ui(top_level, file_name.toUtf8().constData())) {
//            /* They don't.  Let them try another file name or cancel. */
//            continue;
//        }
//#endif

        /* Attempt to save the file */
        status = cf_save_packets(cf, file_name.toUtf8().constData(), file_type, compressed,
                                 discard_comments, stay_closed);
        switch (status) {

        case CF_WRITE_OK:
            /* The save succeeded; we're done. */
            /* Save the directory name for future file dialogs. */
            dirname = get_dirname(file_name.toUtf8().data());  /* Overwrites cf_name */
            set_last_open_dir(dirname);
            /* If we discarded comments, redraw the packet list to reflect
               any packets that no longer have comments. */
            if (discard_comments)
                packet_list_queue_draw();
            return;

        case CF_WRITE_ERROR:
            /* The save failed; let the user try again. */
            continue;

        case CF_WRITE_ABORTED:
            /* The user aborted the save; just return. */
            return;
        }
    }
    return;
}

void MainWindow::exportSelectedPackets() {
    QString file_name = "";
    int file_type;
    gboolean compressed;
    packet_range_t range;
    cf_write_status_t status;
    gchar   *dirname;
    gboolean discard_comments = FALSE;

    if (!cap_file_)
        return;

    /* init the packet range */
    packet_range_init(&range, cap_file_);
    range.process_filtered = TRUE;
    range.include_dependents = TRUE;

    for (;;) {
        CaptureFileDialog esp_dlg(this, cap_file_);

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
                esp_dlg.setDirectory(prefs.gui_fileopen_dir);
            break;
        }

        /* If the file has comments, does the format the user selected
           support them?  If not, ask the user whether they want to
           discard the comments or choose a different format. */
        switch(esp_dlg.exportSelectedPackets(file_name, &range)) {

        case SAVE:
            /* The file can be saved in the specified format as is;
               just drive on and save in the format they selected. */
            discard_comments = FALSE;
            break;

        case SAVE_WITHOUT_COMMENTS:
            /* The file can't be saved in the specified format as is,
               but it can be saved without the comments, and the user
               said "OK, discard the comments", so save it in the
               format they specified without the comments. */
            discard_comments = TRUE;
            break;

        case SAVE_IN_ANOTHER_FORMAT:
            /* There are file formats in which we can save this that
               support comments, and the user said not to delete the
               comments.  The combo box of file formats has had the
               formats that don't support comments trimmed from it,
               so run the dialog again, to let the user decide
               whether to save in one of those formats or give up. */
            discard_comments = FALSE;
            continue;

        case CANCELLED:
            /* The user said "forget it".  Just get rid of the dialog box
               and return. */
            return;
        }

        /*
         * Check that we're not going to save on top of the current
         * capture file.
         * We do it here so we catch all cases ...
         * Unfortunately, the file requester gives us an absolute file
         * name and the read file name may be relative (if supplied on
         * the command line). From Joerg Mayer.
         */
        if (files_identical(cap_file_->filename, file_name.toUtf8().constData())) {
            QMessageBox msg_box;
            gchar *display_basename = g_filename_display_basename(file_name.toUtf8().constData());

            msg_box.setIcon(QMessageBox::Critical);
            msg_box.setText(QString(tr("Unable to export to \"%1\".").arg(display_basename)));
            msg_box.setInformativeText(tr("You cannot export packets to the current capture file."));
            msg_box.setStandardButtons(QMessageBox::Ok);
            msg_box.setDefaultButton(QMessageBox::Ok);
            msg_box.exec();
            g_free(display_basename);
            continue;
        }

        file_type = esp_dlg.selectedFileType();
        compressed = esp_dlg.isCompressed();
        fileAddExtension(file_name, file_type, compressed);

//#ifndef _WIN32
//        /* If the file exists and it's user-immutable or not writable,
//                       ask the user whether they want to override that. */
//        if (!file_target_unwritable_ui(top_level, file_name.toUtf8().constData())) {
//            /* They don't.  Let them try another file name or cancel. */
//            continue;
//        }
//#endif

        /* Attempt to save the file */
        status = cf_export_specified_packets(cap_file_, file_name.toUtf8().constData(), &range, file_type, compressed);
        switch (status) {

        case CF_WRITE_OK:
            /* The save succeeded; we're done. */
            /* Save the directory name for future file dialogs. */
            dirname = get_dirname(file_name.toUtf8().data());  /* Overwrites cf_name */
            set_last_open_dir(dirname);
            /* If we discarded comments, redraw the packet list to reflect
               any packets that no longer have comments. */
            if (discard_comments)
                packet_list_queue_draw();
            return;

        case CF_WRITE_ERROR:
            /* The save failed; let the user try again. */
            continue;

        case CF_WRITE_ABORTED:
            /* The user aborted the save; just return. */
            return;
        }
    }
    return;
}

void MainWindow::fileAddExtension(QString &file_name, int file_type, bool compressed) {
    QString file_name_lower;
    QString file_suffix;
    GSList  *extensions_list, *extension;
    gboolean add_extension;

    /*
     * Append the default file extension if there's none given by
     * the user or if they gave one that's not one of the valid
     * extensions for the file type.
     */
    file_name_lower = file_name.toLower();
    extensions_list = wtap_get_file_extensions_list(file_type, FALSE);
    if (extensions_list != NULL) {
        /* We have one or more extensions for this file type.
           Start out assuming we need to add the default one. */
        add_extension = TRUE;

        /* OK, see if the file has one of those extensions. */
        for (extension = extensions_list; extension != NULL;
             extension = g_slist_next(extension)) {
            file_suffix += tr(".") + (char *)extension->data;
            if (file_name_lower.endsWith(file_suffix)) {
                /*
                 * The file name has one of the extensions for
                 * this file type.
                 */
                add_extension = FALSE;
                break;
            }
            file_suffix += ".gz";
            if (file_name_lower.endsWith(file_suffix)) {
                /*
                 * The file name has one of the extensions for
                 * this file type.
                 */
                add_extension = FALSE;
                break;
            }
        }
    } else {
        /* We have no extensions for this file type.  Don't add one. */
        add_extension = FALSE;
    }
    if (add_extension) {
        if (wtap_default_file_extension(file_type) != NULL) {
            file_name += tr(".") + wtap_default_file_extension(file_type);
            if (compressed) {
                file_name += ".gz";
            }
        }
    }
}

bool MainWindow::testCaptureFileClose(bool from_quit, QString &before_what) {
    bool   capture_in_progress = FALSE;

    if (!cap_file_ || cap_file_->state == FILE_CLOSED)
        return true; /* Already closed, nothing to do */

#ifdef HAVE_LIBPCAP
    if (cap_file_->state == FILE_READ_IN_PROGRESS) {
        /* This is true if we're reading a capture file *or* if we're doing
         a live capture.  If we're reading a capture file, the main loop
         is busy reading packets, and only accepting input from the
         progress dialog, so we can't get here, so this means we're
         doing a capture. */
        capture_in_progress = TRUE;
    }
#endif

    if (prefs.gui_ask_unsaved) {
        if (cap_file_->is_tempfile || capture_in_progress || cap_file_->unsaved_changes) {
            QMessageBox msg_dialog;
            QString question;
            QPushButton *default_button;
            int response;

            msg_dialog.setIcon(QMessageBox::Question);

            /* This is a temporary capture file, or there's a capture in
               progress, or the file has unsaved changes; ask the user whether
               to save the data. */
            if (cap_file_->is_tempfile) {

                msg_dialog.setText(tr("You have unsaved packets"));
                msg_dialog.setInformativeText(tr("They will be lost if you don't save them."));

                if (capture_in_progress) {
                    question.append(tr("Do you want to stop the capture and save the captured packets"));
                } else {
                    question.append(tr("Do you want to save the captured packets"));
                }
                question.append(before_what).append(tr("?"));
                msg_dialog.setInformativeText(question);


            } else {
                /*
                 * Format the message.
                 */
                if (capture_in_progress) {
                    question.append(tr("Do you want to stop the capture and save the captured packets"));
                    question.append(before_what).append(tr("?"));
                    msg_dialog.setInformativeText(tr("Your captured packets will be lost if you don't save them."));
                } else {
                    gchar *display_basename = g_filename_display_basename(cap_file_->filename);
                    question.append(QString(tr("Do you want to save the changes you've made to the capture file \"%1\"%2?"))
                                    .arg(display_basename)
                                    .arg(before_what)
                                    );
                    g_free(display_basename);
                    msg_dialog.setInformativeText(tr("Your changes will be lost if you don't save them."));
                }
            }

            // XXX Text comes from ui/gtk/stock_icons.[ch]
            // Note that the button roles differ from the GTK+ version.
            // Cancel = RejectRole
            // Save = AcceptRole
            // Don't Save = DestructiveRole
            msg_dialog.setStandardButtons(QMessageBox::Cancel);

            if (capture_in_progress) {
                default_button = msg_dialog.addButton(tr("Stop and Save"), QMessageBox::AcceptRole);
            } else {
                default_button = msg_dialog.addButton(QMessageBox::Save);
            }
            msg_dialog.setDefaultButton(default_button);

            if (from_quit) {
                if (cap_file_->state == FILE_READ_IN_PROGRESS) {
                    msg_dialog.addButton(tr("Stop and Quit without Saving"), QMessageBox::DestructiveRole);
                } else {
                    msg_dialog.addButton(tr("Quit without Saving"), QMessageBox::DestructiveRole);
                }
            } else {
                if (capture_in_progress) {
                    msg_dialog.addButton(tr("Stop and Continue without Saving"), QMessageBox::DestructiveRole);
                } else {
                    msg_dialog.addButton(QMessageBox::Discard);
                }
            }

            response = msg_dialog.exec();

            switch (response) {

            case QMessageBox::Save:
#ifdef HAVE_LIBPCAP
                /* If there's a capture in progress, we have to stop the capture
             and then do the save. */
                if (capture_in_progress)
                    captureStop();
#endif
                /* Save the file and close it */
                saveCaptureFile(cap_file_, TRUE);
                break;

            case QMessageBox::Discard:
#ifdef HAVE_LIBPCAP
                /*
                 * If there's a capture in progress; we have to stop the capture
                 * and then do the close.
                 */
                if (capture_in_progress)
                    captureStop();
#endif
                /* Just close the file, discarding changes */
                cf_close(cap_file_);
                return true;
                break;

            case QMessageBox::Cancel:
            default:
                /* Don't close the file (and don't stop any capture in progress). */
                return false; /* file not closed */
                break;
            }
        } else {
            /* Unchanged file, just close it */
            cf_close(cap_file_);
        }
    } else {
        /* User asked not to be bothered by those prompts, just close it.
         XXX - should that apply only to saving temporary files? */
#ifdef HAVE_LIBPCAP
        /* If there's a capture in progress, we have to stop the capture
           and then do the close. */
        if (capture_in_progress)
            captureStop();
#endif
        cf_close(cap_file_);
    }

    return true; /* File closed */
}

void MainWindow::captureStop() {
    stopCapture();

    while(cap_file_ && cap_file_->state == FILE_READ_IN_PROGRESS) {
        WiresharkApplication::processEvents();
    }
}

// Menu state

/* Enable or disable menu items based on whether you have a capture file
   you've finished reading and, if you have one, whether it's been saved
   and whether it could be saved except by copying the raw packet data. */
void MainWindow::setMenusForCaptureFile(bool force_disable)
{
    if (force_disable || cap_file_ == NULL || cap_file_->state == FILE_READ_IN_PROGRESS) {
        /* We have no capture file or we're currently reading a file */
        main_ui_->actionFileMerge->setEnabled(false);
        main_ui_->actionFileClose->setEnabled(false);
        main_ui_->actionFileSave->setEnabled(false);
        main_ui_->actionFileSaveAs->setEnabled(false);
        main_ui_->actionFileExportPackets->setEnabled(false);
        main_ui_->actionFileExportPacketDissections->setEnabled(false);
        main_ui_->actionFileExportPacketBytes->setEnabled(false);
        main_ui_->actionFileExportSSLSessionKeys->setEnabled(false);
        main_ui_->actionFileExportObjects->setEnabled(false);
        main_ui_->actionViewReload->setEnabled(false);
    } else {
        main_ui_->actionFileMerge->setEnabled(cf_can_write_with_wiretap(cap_file_));

        main_ui_->actionFileClose->setEnabled(true);
        /*
         * "Save" should be available only if:
         *
         *  the file has unsaved changes, and we can save it in some
         *  format through Wiretap
         *
         * or
         *
         *  the file is a temporary file and has no unsaved changes (so
         *  that "saving" it just means copying it).
         */
        main_ui_->actionFileSave->setEnabled(
                    (cap_file_->unsaved_changes && cf_can_write_with_wiretap(cap_file_)) ||
                    (cap_file_->is_tempfile && !cap_file_->unsaved_changes));
        /*
         * "Save As..." should be available only if:
         *
         *  we can save it in some format through Wiretap
         *
         * or
         *
         *  the file is a temporary file and has no unsaved changes (so
         *  that "saving" it just means copying it).
         */
        main_ui_->actionFileSaveAs->setEnabled(
                    cf_can_write_with_wiretap(cap_file_) ||
                    (cap_file_->is_tempfile && !cap_file_->unsaved_changes));
        /*
         * "Export Specified Packets..." should be available only if
         * we can write the file out in at least one format.
         */
        main_ui_->actionFileExportPackets->setEnabled(cf_can_write_with_wiretap(cap_file_));
        main_ui_->actionFileExportPacketDissections->setEnabled(true);
        main_ui_->actionFileExportPacketBytes->setEnabled(true);
        main_ui_->actionFileExportSSLSessionKeys->setEnabled(true);
        main_ui_->actionFileExportObjects->setEnabled(true);
        main_ui_->actionViewReload->setEnabled(true);
    }
}

void MainWindow::setMenusForCaptureInProgress(bool capture_in_progress) {
    /* Either a capture was started or stopped; in either case, it's not
       in the process of stopping, so allow quitting. */

    main_ui_->actionFileOpen->setEnabled(!capture_in_progress);
    main_ui_->menuOpenRecentCaptureFile->setEnabled(!capture_in_progress);
    main_ui_->actionFileExportPacketDissections->setEnabled(capture_in_progress);
    main_ui_->actionFileExportPacketBytes->setEnabled(capture_in_progress);
    main_ui_->actionFileExportSSLSessionKeys->setEnabled(capture_in_progress);
    main_ui_->actionFileExportObjects->setEnabled(capture_in_progress);
    main_ui_->menuFileSet->setEnabled(!capture_in_progress);
    main_ui_->actionFileQuit->setEnabled(true);

    qDebug() << "FIX: packet list heading menu sensitivity";
    //    set_menu_sensitivity(ui_manager_packet_list_heading, "/PacketListHeadingPopup/SortAscending",
    //                         !capture_in_progress);
    //    set_menu_sensitivity(ui_manager_packet_list_heading, "/PacketListHeadingPopup/SortDescending",
    //                         !capture_in_progress);
    //    set_menu_sensitivity(ui_manager_packet_list_heading, "/PacketListHeadingPopup/NoSorting",
    //                         !capture_in_progress);

#ifdef HAVE_LIBPCAP
    main_ui_->actionCaptureOptions->setEnabled(!capture_in_progress);
    main_ui_->actionStartCapture->setEnabled(!capture_in_progress);
    main_ui_->actionStartCapture->setChecked(capture_in_progress);
    main_ui_->actionStopCapture->setEnabled(capture_in_progress);
    main_ui_->actionCaptureRestart->setEnabled(capture_in_progress);
#endif /* HAVE_LIBPCAP */

}

void MainWindow::setMenusForCaptureStopping() {
    main_ui_->actionFileQuit->setEnabled(false);
#ifdef HAVE_LIBPCAP
    main_ui_->actionStartCapture->setChecked(false);
    main_ui_->actionStopCapture->setEnabled(false);
    main_ui_->actionCaptureRestart->setEnabled(false);
#endif /* HAVE_LIBPCAP */
}

void MainWindow::setMenusForFileSet(bool enable_list_files) {
    bool enable_next = fileset_get_next() != NULL && enable_list_files;
    bool enable_prev = fileset_get_previous() != NULL && enable_list_files;

    main_ui_->actionFileSetListFiles->setEnabled(enable_list_files);
    main_ui_->actionFileSetNextFile->setEnabled(enable_next);
    main_ui_->actionFileSetPreviousFile->setEnabled(enable_prev);
}

void MainWindow::updateForUnsavedChanges() {
//    set_display_filename(cf);
    setMenusForCaptureFile();
//    set_toolbar_for_capture_file(cf);

}

/* Update main window items based on whether there's a capture in progress. */
void MainWindow::setForCaptureInProgress(gboolean capture_in_progress)
{
    setMenusForCaptureInProgress(capture_in_progress);

//#ifdef HAVE_LIBPCAP
//    set_toolbar_for_capture_in_progress(capture_in_progress);

//    set_capture_if_dialog_for_capture_in_progress(capture_in_progress);
//#endif
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
