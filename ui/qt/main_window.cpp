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

#include "ui/alert_box.h"
#include "ui/main_statusbar.h"

#include "wireshark_application.h"
#include "proto_tree.h"
#include "byte_view_tab.h"
#include "capture_file_dialog.h"
#include "display_filter_edit.h"

#include "qt_ui_utils.h"

#include <QTreeWidget>
#include <QTabWidget>
#include <QAction>
#include <QToolButton>
#include <QKeyEvent>
#include <QMetaObject>

//menu_recent_file_write_all

// If we ever add support for multiple windows this will need to be replaced.
static MainWindow *gbl_cur_main_window = NULL;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    main_ui_(new Ui::MainWindow)
{
    cap_file_ = NULL;
    gbl_cur_main_window = this;
    main_ui_->setupUi(this);

    connect(wsApp, SIGNAL(updateRecentItemStatus(const QString &, qint64, bool)), this, SLOT(updateRecentFiles()));
    updateRecentFiles();

    df_combo_box_ = new DisplayFilterCombo();
    const DisplayFilterEdit *dfEdit = dynamic_cast<DisplayFilterEdit *>(df_combo_box_->lineEdit());
    connect(dfEdit, SIGNAL(pushFilterSyntaxStatus(QString&)), main_ui_->statusBar, SLOT(pushFilterStatus(QString&)));
    connect(dfEdit, SIGNAL(popFilterSyntaxStatus()), main_ui_->statusBar, SLOT(popFilterStatus()));
    connect(dfEdit, SIGNAL(pushFilterSyntaxWarning(QString&)), main_ui_->statusBar, SLOT(pushTemporaryStatus(QString&)));

#ifdef _WIN32
    // Qt <= 4.7 doesn't seem to style Windows toolbars. If we wanted to be really fancy we could use Blur Behind:
    // http://labs.qt.nokia.com/2009/09/15/using-blur-behind-on-windows/
    setStyleSheet(
                "QToolBar {"
                "  background: qlineargradient(spread:pad, x1:0, y1:0, x2:0, y2:1, stop:0 rgba(255,255,255,127), stop:0.37 rgba(234,234,234,127), stop:1 rgba(155,155,155,91));"
                "}"
            );
#endif
    main_ui_->mainToolBar->addWidget(df_combo_box_);

    splitter_v_ = new QSplitter(main_ui_->mainStack);
    splitter_v_->setObjectName(QString::fromUtf8("splitterV"));
    splitter_v_->setOrientation(Qt::Vertical);

    packet_list_ = new PacketList(splitter_v_);

    ProtoTree *protoTree = new ProtoTree(splitter_v_);
    protoTree->setHeaderHidden(true);

    ByteViewTab *byteViewTab = new ByteViewTab(splitter_v_);
    byteViewTab->setTabPosition(QTabWidget::South);
    byteViewTab->setDocumentMode(true);

    packet_list_->setProtoTree(protoTree);
    packet_list_->setByteViewTab(byteViewTab);

    splitter_v_->addWidget(packet_list_);
    splitter_v_->addWidget(protoTree);
    splitter_v_->addWidget(byteViewTab);

    main_ui_->mainStack->addWidget(splitter_v_);

    main_welcome_ = main_ui_->welcomePage;
    connect(main_welcome_, SIGNAL(recentFileActivated(QString&)),
            this, SLOT(openRecentCaptureFile(QString&)));

    connect(wsApp, SIGNAL(captureFileReadStarted(const capture_file*)),
            this, SLOT(captureFileReadStarted(const capture_file*)));
    connect(wsApp, SIGNAL(captureFileReadFinished(const capture_file*)),
            this, SLOT(captureFileReadFinished(const capture_file*)));
    connect(wsApp, SIGNAL(captureFileClosing(const capture_file*)),
            this, SLOT(captureFileClosing(const capture_file*)));
    connect(wsApp, SIGNAL(captureFileClosed(const capture_file*)),
            this, SLOT(captureFileClosed(const capture_file*)));

    connect(main_ui_->actionGoNextPacket, SIGNAL(triggered()),
            packet_list_, SLOT(goNextPacket()));
    connect(main_ui_->actionGoPreviousPacket, SIGNAL(triggered()),
            packet_list_, SLOT(goPreviousPacket()));
    connect(main_ui_->actionGoFirstPacket, SIGNAL(triggered()),
            packet_list_, SLOT(goFirstPacket()));
    connect(main_ui_->actionGoLastPacket, SIGNAL(triggered()),
            packet_list_, SLOT(goLastPacket()));

    connect(main_ui_->actionViewExpandSubtrees, SIGNAL(triggered()),
            protoTree, SLOT(expandSubtrees()));
    connect(main_ui_->actionViewExpandAll, SIGNAL(triggered()),
            protoTree, SLOT(expandAll()));
    connect(main_ui_->actionViewCollapseAll, SIGNAL(triggered()),
            protoTree, SLOT(collapseAll()));

    connect(protoTree, SIGNAL(protoItemSelected(QString&)),
            main_ui_->statusBar, SLOT(pushFieldStatus(QString&)));

    connect(protoTree, SIGNAL(protoItemSelected(bool)),
            main_ui_->actionViewExpandSubtrees, SLOT(setEnabled(bool)));

    main_ui_->mainStack->setCurrentWidget(main_welcome_);
}

MainWindow::~MainWindow()
{
    delete main_ui_;
}

void MainWindow::keyPressEvent(QKeyEvent *event) {

    // Explicitly focus on the display filter combo.
    if (event->modifiers() & Qt::ControlModifier && event->key() == Qt::Key_Slash) {
        df_combo_box_->setFocus(Qt::ShortcutFocusReason);
        return;
    }

    // The user typed some text. Start filling in a filter.
    // XXX We need to install an event filter for the packet list and proto tree
    if ((event->modifiers() == Qt::NoModifier || event->modifiers() == Qt::ShiftModifier) && event->text().length() > 0) {
        QApplication::sendEvent(df_combo_box_, event);
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

void MainWindow::captureFileReadStarted(const capture_file *cf) {
    if (cf != cap_file_) return;
//    tap_param_dlg_update();

    /* Set up main window for a capture file. */
//    main_set_for_capture_file(TRUE);

    main_ui_->statusBar->popFileStatus();
    QString msg = QString(tr("Loading: %1")).arg(get_basename(cf->filename));
    main_ui_->statusBar->pushFileStatus(msg);
    main_ui_->mainStack->setCurrentWidget(splitter_v_);
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
//        set_last_open_dir(dir_path);
//        g_free(dir_path);
//    }
//    set_display_filename(cf);

//    /* Enable menu items that make sense if you have a capture file you've
//       finished reading. */
//    set_menus_for_capture_file(cf);

//    /* Enable menu items that make sense if you have some captured packets. */
//    set_menus_for_captured_packets(TRUE);

    main_ui_->statusBar->popFileStatus();
    QString msg = QString().sprintf("%s", get_basename(cf->filename));
    main_ui_->statusBar->pushFileStatus(msg);
}

void MainWindow::captureFileClosing(const capture_file *cf) {
    if (cf != cap_file_) return;

    // Reset expert info indicator
    main_ui_->statusBar->hideExpert();
//    gtk_widget_show(expert_info_none);
}

// View Menu

// Expand / collapse slots in proto_tree

// Go Menu

// Next / previous / first / last slots in packet_list

// Help Menu
void MainWindow::on_actionHelpWebsite_triggered() {
    QDesktopServices::openUrl(QUrl("http://www.wireshark.org"));
}

void MainWindow::on_actionHelpFAQ_triggered() {

    QDesktopServices::openUrl(QUrl("http://www.wireshark.org/faq.html"));
}

void MainWindow::on_actionHelpAsk_triggered() {

    QDesktopServices::openUrl(QUrl("http://ask.wireshark.org"));
}

void MainWindow::on_actionHelpDownloads_triggered() {

    QDesktopServices::openUrl(QUrl("http://www.wireshark.org/download.html"));
}

void MainWindow::on_actionHelpWiki_triggered() {

    QDesktopServices::openUrl(QUrl("http://wiki.wireshark.org"));
}

void MainWindow::on_actionHelpSampleCaptures_triggered() {

    QDesktopServices::openUrl(QUrl("http://wiki.wireshark.org/SampleCaptures"));
}

void MainWindow::captureFileClosed(const capture_file *cf) {
    if (cf != cap_file_) return;
    packets_bar_update();

    // Reset expert info indicator
    main_ui_->statusBar->hideExpert();

    main_ui_->statusBar->popFileStatus();
    cap_file_ = NULL;
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

void MainWindow::openRecentCaptureFile(QString &cfPath)
{
    QString fileName = "";
    QString displayFilter = "";
    dfilter_t *rfcode = NULL;
    int err;

    cap_file_ = NULL;

    for (;;) {

        if (cfPath.isEmpty()) {
            CaptureFileDialog cfDlg(this, fileName, displayFilter);

            if (cfDlg.exec()) {
                if (dfilter_compile(displayFilter.toUtf8().constData(), &rfcode)) {
                    cf_set_rfcode(&cfile, rfcode);
                } else {
                    /* Not valid.  Tell the user, and go back and run the file
                       selection box again once they dismiss the alert. */
                    //bad_dfilter_alert_box(top_level, display_filter->str);
                    QMessageBox::warning(this, tr("Invalid Display Filter"),
                                         QString("The filter expression ") +
                                         displayFilter +
                                         QString(" isn't a valid display filter. (") +
                                         dfilter_error_msg + QString(")."),
                                         QMessageBox::Ok);
                    continue;
                }
                cfPath = fileName;
            } else {
                return;
            }
        }

        /* Try to open the capture file. */
        if (cf_open(&cfile, cfPath.toUtf8().constData(), FALSE, &err) != CF_OK) {
            /* We couldn't open it; don't dismiss the open dialog box,
               just leave it around so that the user can, after they
               dismiss the alert box popped up for the open error,
               try again. */
            if (rfcode != NULL)
                dfilter_free(rfcode);
            cfPath.clear();
            continue;
        }

        cap_file_ = &cfile;
        cfile.window = this;

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
    set_last_open_dir(get_dirname(cfPath.toUtf8().data()));
    df_combo_box_->setEditText(displayFilter);

    main_ui_->statusBar->showExpert();
}

void MainWindow::on_actionFileClose_triggered() {
    cf_close(&cfile);
    main_ui_->mainStack->setCurrentWidget(main_welcome_);
}

void MainWindow::recentActionTriggered() {
    QAction *ra = qobject_cast<QAction*>(sender());

    if (ra) {
        QString cfPath = ra->data().toString();
        openRecentCaptureFile(cfPath);
    }
}
