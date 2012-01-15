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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include "main_window.h"
#include "ui_main_window.h"

#include "globals.h"

#include <epan/filesystem.h>
#include <epan/prefs.h>

#include "main_statusbar.h"

#include "wireshark_application.h"
#include "packet_list.h"
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

//menu_recent_file_write_all

// If we ever add support for multiple windows this will need to be replaced.
static MainWindow *cur_main_window = NULL;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    capFile = NULL;
    cur_main_window = this;
    ui->setupUi(this);

    connect(wsApp, SIGNAL(updateRecentItemStatus(const QString &, qint64, bool)), this, SLOT(updateRecentFiles()));
    updateRecentFiles();

    dfComboBox = new DisplayFilterCombo();
    const DisplayFilterEdit *dfEdit = dynamic_cast<DisplayFilterEdit *>(dfComboBox->lineEdit());
    connect(dfEdit, SIGNAL(pushFilterSyntaxStatus(QString&)), ui->statusBar, SLOT(pushFilterStatus(QString&)));
    connect(dfEdit, SIGNAL(popFilterSyntaxStatus()), ui->statusBar, SLOT(popFilterStatus()));
    connect(dfEdit, SIGNAL(pushFilterSyntaxWarning(QString&)), ui->statusBar, SLOT(pushTemporaryStatus(QString&)));

#ifdef _WIN32
    // Qt <= 4.7 doesn't seem to style Windows toolbars. If we wanted to be really fancy we could use Blur Behind:
    // http://labs.qt.nokia.com/2009/09/15/using-blur-behind-on-windows/
    setStyleSheet(
                "QToolBar {"
                "  background: qlineargradient(spread:pad, x1:0, y1:0, x2:0, y2:1, stop:0 rgba(255,255,255,127), stop:0.37 rgba(234,234,234,127), stop:1 rgba(155,155,155,91));"
                "}"
            );
#endif
    ui->mainToolBar->addWidget(dfComboBox);

    splitterV = new QSplitter(ui->mainStack);
    splitterV->setObjectName(QString::fromUtf8("splitterV"));
    splitterV->setOrientation(Qt::Vertical);

    PacketList *packetList = new PacketList(splitterV);

    ProtoTree *protoTree = new ProtoTree(splitterV);
    protoTree->setHeaderHidden(true);

    ByteViewTab *byteViewTab = new ByteViewTab(splitterV);
    byteViewTab->setTabPosition(QTabWidget::South);
    byteViewTab->setDocumentMode(true);

    packetList->setProtoTree(protoTree);
    packetList->setByteViewTab(byteViewTab);

    splitterV->addWidget(packetList);
    splitterV->addWidget(protoTree);
    splitterV->addWidget(byteViewTab);

    ui->mainStack->addWidget(splitterV);

    mainWelcome = new MainWelcome(ui->mainStack);
    ui->mainStack->addWidget(mainWelcome);
    connect(mainWelcome, SIGNAL(recentFileActivated(QString&)),
            this, SLOT(openCaptureFile(QString&)));

    connect(wsApp, SIGNAL(captureFileReadStarted(const capture_file*)),
            this, SLOT(captureFileReadStarted(const capture_file*)));
    connect(wsApp, SIGNAL(captureFileReadFinished(const capture_file*)),
            this, SLOT(captureFileReadFinished(const capture_file*)));
    connect(wsApp, SIGNAL(captureFileClosing(const capture_file*)),
            this, SLOT(captureFileClosing(const capture_file*)));
    connect(wsApp, SIGNAL(captureFileClosed(const capture_file*)),
            this, SLOT(captureFileClosed(const capture_file*)));

    connect(protoTree, SIGNAL(protoItemSelected(QString&)),
            ui->statusBar, SLOT(pushFieldStatus(QString&)));
    connect(protoTree, SIGNAL(protoItemUnselected()),
            ui->statusBar, SLOT(popFieldStatus()));

    ui->mainStack->setCurrentWidget(mainWelcome);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::keyPressEvent(QKeyEvent *event) {

    if (event->modifiers() & Qt::ControlModifier && event->key() == Qt::Key_Slash) {
        dfComboBox->setFocus(Qt::ShortcutFocusReason);
        return;
    }

    QMainWindow::keyPressEvent(event);
}

void MainWindow::captureFileReadStarted(const capture_file *cf) {
    if (cf != capFile) return;
//    tap_param_dlg_update();

    /* Set up main window for a capture file. */
//    main_set_for_capture_file(TRUE);

    ui->statusBar->popFileStatus();
    QString msg = QString().sprintf("Loading: %s", get_basename(cf->filename));
    ui->statusBar->pushFileStatus(msg);
}

void MainWindow::captureFileReadFinished(const capture_file *cf) {
    if (cf != capFile) return;

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

    ui->statusBar->popFileStatus();
    QString msg = QString().sprintf("%s", get_basename(cf->filename));
    ui->statusBar->pushFileStatus(msg);
}

void MainWindow::captureFileClosing(const capture_file *cf) {
    if (cf != capFile) return;

    /* reset expert info indicator */
//    status_expert_hide();
//    gtk_widget_show(expert_info_none);
}

void MainWindow::captureFileClosed(const capture_file *cf) {
    if (cf != capFile) return;
    packets_bar_update();

    ui->statusBar->popFileStatus();
    capFile = NULL;
}

void MainWindow::closeCaptureFile() {
    cf_close(&cfile);
    ui->mainStack->setCurrentWidget(mainWelcome);
}

void MainWindow::openCaptureFile(QString &cfPath)
 {
    dfilter_t   *rfcode = NULL;

    if (cfPath.isEmpty()) {
        QStringList cfNames;
        CaptureFileDialog cfDlg(this);

        cfDlg.setLabelText(QFileDialog::FileName, tr("Wireshark: Open Capture File"));
        cfDlg.setDirectory("/Users/gcombs/Documents/Captures");
        cfDlg.setNameFilter(tr("Capture Files (*.pcap *.pcapng)"));
        cfDlg.setFileMode(QFileDialog::ExistingFile);

        if (cfDlg.exec()) {
            cfNames = cfDlg.selectedFiles();
            if (cfNames.length() > 0) {
                cfPath = cfNames[0];
            }
        }
    }

    if (cfPath.length() > 0) {
        int err;

        /* Try to open the capture file. */
        if (cf_open(&cfile, cfPath.toUtf8().constData(), FALSE, &err) != CF_OK) {
            /* We couldn't open it; don't dismiss the open dialog box,
             just leave it around so that the user can, after they
             dismiss the alert box popped up for the open error,
             try again. */
            if (rfcode != NULL)
                dfilter_free(rfcode);
            capFile = NULL;
            return;
        } else {
            ui->mainStack->setCurrentWidget(splitterV);
            capFile = &cfile;
            cf_read(&cfile, FALSE);
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
    QMenu *recentMenu = ui->menuOpenRecentCaptureFile;
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
        ra->setText("Clear Menu");
        recentMenu->insertAction(NULL, ra);
        connect(ra, SIGNAL(triggered()), wsApp, SLOT(clearRecentItems()));
    } else {
        if (ui->actionDummyNoFilesFound) {
            recentMenu->addAction(ui->actionDummyNoFilesFound);
        }
    }
}
