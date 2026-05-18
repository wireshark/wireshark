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

/**
 * @brief Preferences frame for the Wireshark welcome page, managing visibility and
 *        behaviour of the "Learn" panel and "Tips" subsystem.
 */
class WelcomePagePreferencesFrame : public QFrame
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the frame and initialises its UI.
     * @param parent Optional parent widget.
     */
    explicit WelcomePagePreferencesFrame(QWidget *parent = 0);

    /** @brief Destroys the frame and releases the UI object. */
    ~WelcomePagePreferencesFrame();

    /**
     * @brief Restores all preference controls to the values that were
     *        saved when the frame was last stashed.
     */
    void unstash();

private:
    /** @brief Qt Designer–generated UI object. */
    Ui::WelcomePagePreferencesFrame *ui;

    /** @brief Stashed visibility state of the Learn panel. */
    bool stashed_learn_visible_;

    /** @brief Stashed visibility state of the Tips panel. */
    bool stashed_tips_visible_;

    /** @brief Stashed enabled state of the Tips events sub-option. */
    bool stashed_tips_events_;

    /** @brief Stashed enabled state of the Tips sponsorship sub-option. */
    bool stashed_tips_sponsorship_;

    /** @brief Stashed enabled state of the Tips tips sub-option. */
    bool stashed_tips_tips_;

    /** @brief Stashed enabled state of Tips auto-advance. */
    bool stashed_tips_auto_advance_;

    /** @brief Stashed auto-advance interval in seconds. */
    unsigned stashed_tips_interval_;

    /**
     * @brief Enables or disables the Tips sub-checkboxes based on
     *        whether the Tips panel is currently visible.
     */
    void updateTipsSubCheckboxes();

private slots:
    /**
     * @brief Handles toggling of the Learn panel visibility checkbox.
     * @param checked New checked state of the checkbox.
     */
    void learnVisibleToggled(bool checked);

    /**
     * @brief Handles toggling of the Tips panel visibility checkbox.
     * @param checked New checked state of the checkbox.
     */
    void tipsVisibleToggled(bool checked);

    /**
     * @brief Handles toggling of the Tips events sub-checkbox.
     * @param checked New checked state of the checkbox.
     */
    void tipsEventsToggled(bool checked);

    /**
     * @brief Handles toggling of the Tips sponsorship sub-checkbox.
     * @param checked New checked state of the checkbox.
     */
    void tipsSponsorshipToggled(bool checked);

    /**
     * @brief Handles toggling of the Tips tips sub-checkbox.
     * @param checked New checked state of the checkbox.
     */
    void tipsTipsToggled(bool checked);

    /**
     * @brief Handles toggling of the Tips auto-advance sub-checkbox.
     * @param checked New checked state of the checkbox.
     */
    void tipsAutoAdvanceToggled(bool checked);

    /**
     * @brief Handles changes to the Tips auto-advance interval spin-box.
     * @param value New interval value in seconds.
     */
    void tipsIntervalValueChanged(int value);

    /**
     * @brief Handles button clicks in the restore/default button box.
     * @param button The button that was clicked.
     */
    void restoreButtonBoxClicked(QAbstractButton *button);
};

#endif // WELCOME_PAGE_PREFERENCES_FRAME_H
