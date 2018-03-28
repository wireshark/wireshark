/* main_status_bar.h
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

#include "capchild/capture_session.h"

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

signals:
    void showExpertInfo();
    void editCaptureComment();
    void stopLoading();

public slots:
    void setCaptureFile(capture_file *cf);
    void selectedFieldChanged(FieldInformation *);
    void highlightedFieldChanged(FieldInformation *);
    void pushTemporaryStatus(const QString &message);
    void popTemporaryStatus();
    void pushFileStatus(const QString &message, const QString &messagetip = QString());
    void popFileStatus();
    void pushFieldStatus(const QString &message);
    void popFieldStatus();
    void pushByteStatus(const QString &message);
    void popByteStatus();
    void pushFilterStatus(const QString &message);
    void popFilterStatus();
    void pushBusyStatus(const QString &message, const QString &messagetip = QString());
    void popBusyStatus();
    void pushProgressStatus(const QString &message, bool animate, bool terminate_is_stop = false, gboolean *stop_flag = NULL);
    void updateProgressStatus(int value);
    void popProgressStatus();
    void selectedFrameChanged(int);

    void updateCaptureStatistics(capture_session * cap_session);
    void updateCaptureFixedStatistics(capture_session * cap_session);

    void captureEventHandler(CaptureEvent ev);

private slots:
    void pushPacketStatus(const QString &message);
    void popPacketStatus();

    void toggleBackground(bool enabled);
    void setProfileName();
    void switchToProfile();
    void manageProfile();
    void showProfileMenu(const QPoint &global_pos, Qt::MouseButton button);
};

#endif // MAIN_STATUS_BAR_H

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
