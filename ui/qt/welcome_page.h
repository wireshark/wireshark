/* welcome_page.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WELCOME_PAGE_H
#define WELCOME_PAGE_H

#include <QFrame>

class QListWidget;
class QListWidgetItem;
class QMenu;

#include <ui/qt/widgets/splash_overlay.h>
#include "interface_frame.h"

namespace Ui {
    class WelcomePage;
}

class WelcomePage : public QFrame
{
    Q_OBJECT
public:
    explicit WelcomePage(QWidget *parent = 0);
    virtual ~WelcomePage();
    InterfaceFrame *getInterfaceFrame();
    const QString captureFilter();
    void setCaptureFilter(const QString capture_filter);

public slots:
    void interfaceSelected();

protected:
    virtual bool event(QEvent *event);
    virtual void resizeEvent(QResizeEvent *event);
    virtual void changeEvent(QEvent* event);

protected slots:
    void on_recentLabel_clicked();
    void on_captureLabel_clicked();
    void on_helpLabel_clicked();

private:
    void updateStyleSheets();

    Ui::WelcomePage *welcome_ui_;
    QString flavor_;
    QString show_in_str_;

    SplashOverlay *splash_overlay_;
    // QListWidget doesn't activate items when the return or enter keys are pressed on macOS.
    // We may want to subclass it at some point.
    QListWidget *recent_files_;

signals:
    void startCapture();
    void recentFileActivated(QString cfile);
    void captureFilterSyntaxChanged(bool valid);
    void showExtcapOptions(QString &device_name);
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

    void on_interfaceFrame_showExtcapOptions(QString device_name);
    void on_interfaceFrame_startCapture();
};

#endif // WELCOME_PAGE_H

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
