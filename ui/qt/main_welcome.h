/* main_welcome.h
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

#ifndef MAIN_WELCOME_H
#define MAIN_WELCOME_H

#include <QFrame>

class QListWidget;
class QListWidgetItem;
class QTreeWidgetItem;
class QMenu;

#include "splash_overlay.h"
#include "interface_frame.h"

namespace Ui {
    class MainWelcome;
}

class MainWelcome : public QFrame
{
    Q_OBJECT
public:
    explicit MainWelcome(QWidget *parent = 0);
    virtual ~MainWelcome();
    InterfaceFrame *getInterfaceFrame();
    const QString captureFilter();
    void setCaptureFilter(const QString capture_filter);

public slots:
    void interfaceSelected();

protected:
    virtual void resizeEvent(QResizeEvent *event);
    virtual void changeEvent(QEvent* event);

protected slots:
    void on_recentLabel_clicked();
    void on_captureLabel_clicked();
    void on_helpLabel_clicked();

private:
    Ui::MainWelcome *welcome_ui_;
    QString flavor_;
    QString show_in_str_;

    SplashOverlay *splash_overlay_;
    // QListWidget doesn't activate items when the return or enter keys are pressed on macOS.
    // We may want to subclass it at some point.
    QListWidget *recent_files_;
//    MWOverlay *overlay;
    QMenu *recent_ctx_menu_;


signals:
    void startCapture();
    void recentFileActivated(QString cfile);
    void pushFilterSyntaxStatus(const QString&);
    void popFilterSyntaxStatus();
    void captureFilterSyntaxChanged(bool valid);
#ifdef HAVE_EXTCAP
    void showExtcapOptions(QString &device_name);
#endif
    void interfacesChanged();

public slots:
    void setCaptureFilterText(const QString capture_filter);

private slots:
    void appInitialized();
    void interfaceListChanged();
    void captureFilterTextEdited(const QString capture_filter);
    void updateRecentCaptures();
    void openRecentItem(QListWidgetItem *item);
    void showRecentContextMenu(QPoint pos);
    void showRecentFolder();
    void copyRecentPath();
    void removeRecentPath();

#ifdef HAVE_EXTCAP
    void on_interfaceFrame_showExtcapOptions(QString device_name);
#endif
    void on_interfaceFrame_startCapture();
};

#endif // MAIN_WELCOME_H

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
