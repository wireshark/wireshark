/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WELCOME_PAGE_PREFERENCES_FRAME_H
#define WELCOME_PAGE_PREFERENCES_FRAME_H

#include <QFrame>
#include <QAbstractButton>

namespace Ui {
class WelcomePagePreferencesFrame;
}

class WelcomePagePreferencesFrame : public QFrame
{
    Q_OBJECT

public:
    explicit WelcomePagePreferencesFrame(QWidget *parent = 0);
    ~WelcomePagePreferencesFrame();

    void unstash();

private:
    Ui::WelcomePagePreferencesFrame *ui;

    bool stashed_learn_visible_;
    bool stashed_tips_visible_;
    bool stashed_tips_events_;
    bool stashed_tips_sponsorship_;
    bool stashed_tips_tips_;
    unsigned stashed_tips_interval_;

    void updateTipsSubCheckboxes();

private slots:
    void on_learnVisibleCheckBox_toggled(bool checked);
    void on_tipsVisibleCheckBox_toggled(bool checked);
    void on_tipsEventsCheckBox_toggled(bool checked);
    void on_tipsSponsorshipCheckBox_toggled(bool checked);
    void on_tipsTipsCheckBox_toggled(bool checked);
    void on_tipsIntervalSpinBox_valueChanged(int value);
    void on_restoreButtonBox_clicked(QAbstractButton *button);
};

#endif // WELCOME_PAGE_PREFERENCES_FRAME_H
