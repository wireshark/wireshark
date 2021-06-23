/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MAIN_STATUS_BAR_H
#define MAIN_STATUS_BAR_H

#include "config.h"

#include "cfile.h"

#include "capture/capture_session.h"

#include <ui/qt/utils/field_information.h>
#include <ui/qt/widgets/label_stack.h>
#include <ui/qt/widgets/clickable_label.h>
#include "progress_frame.h"
#include "wireshark_application.h"

#include <QLabel>
#include <QMenu>
#include <QStatusBar>

class CaptureFile;
class QToolButton;

class MainStatusBar : public QStatusBar
{
    Q_OBJECT
public:
    explicit MainStatusBar(QWidget *parent = 0);
    void showExpert();
    void captureFileClosing();
    void expertUpdate();
    void setFileName(CaptureFile &cf);

protected:

    enum StatusContext {
        STATUS_CTX_MAIN,
        STATUS_CTX_FILE,
        STATUS_CTX_FIELD,
        STATUS_CTX_BYTE,
        STATUS_CTX_FILTER,
        STATUS_CTX_PROGRESS,
        STATUS_CTX_TEMPORARY
    };

    virtual void changeEvent(QEvent* event);

private:
    QToolButton *expert_button_;
    QToolButton *comment_button_;
    LabelStack info_status_;
    ProgressFrame progress_frame_;
    LabelStack packet_status_;
    ClickableLabel profile_status_;
    capture_file *cap_file_;
    QString ready_msg_;

    // Capture statistics
    bool cs_fixed_;
    guint32 cs_count_;

    void showCaptureStatistics();
    void setStatusbarForCaptureFile();

    void pushGenericStatus(StatusContext status, const QString &message, const QString &messagetip = QString());
    void popGenericStatus(StatusContext status);

signals:
    void showExpertInfo();
    void editCaptureComment();
    void stopLoading();

public slots:
    void setCaptureFile(capture_file *cf);
    void selectedFieldChanged(FieldInformation *);
    void highlightedFieldChanged(FieldInformation *);
    void selectedFrameChanged(QList<int>);

    void updateCaptureStatistics(capture_session * cap_session);
    void updateCaptureFixedStatistics(capture_session * cap_session);

    void captureEventHandler(CaptureEvent ev);

private slots:
    void appInitialized();
    void toggleBackground(bool enabled);
    void setProfileName();
    void switchToProfile();
    void manageProfile();
    void showProfileMenu(const QPoint &global_pos, Qt::MouseButton button);

    friend MainApplication;
};

#endif // MAIN_STATUS_BAR_H
