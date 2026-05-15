/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FONT_COLOR_PREFERENCES_FRAME_H
#define FONT_COLOR_PREFERENCES_FRAME_H

#include <QFrame>
#include <QFont>
#include <QComboBox>

#include <epan/prefs.h>

namespace Ui {
class FontColorPreferencesFrame;
}

/**
 * @brief A frame for configuring font and color preferences.
 */
class FontColorPreferencesFrame : public QFrame
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new FontColorPreferencesFrame.
     * @param parent The parent widget, defaults to 0.
     */
    explicit FontColorPreferencesFrame(QWidget *parent = 0);

    /**
     * @brief Destroys the FontColorPreferencesFrame.
     */
    ~FontColorPreferencesFrame();

protected:
    /**
     * @brief Handles the event when the frame is shown.
     * @param evt The show event to handle.
     */
    void showEvent(QShowEvent *evt);

private:
    /** Pointer to the generated UI elements. */
    Ui::FontColorPreferencesFrame *ui;

    /** Combo box for selecting the overall color scheme. */
    QComboBox *colorSchemeComboBox_;

    /** Preference for the color scheme. */
    pref_t *pref_color_scheme_;

    /** Preference for the Qt GUI font name. */
    pref_t *pref_qt_gui_font_name_;

    /** Preference for the active selected item foreground color. */
    pref_t *pref_active_fg_;

    /** Preference for the active selected item background color. */
    pref_t *pref_active_bg_;

    /** Preference for the active selected item style. */
    pref_t *pref_active_style_;

    /** Preference for the inactive selected item foreground color. */
    pref_t *pref_inactive_fg_;

    /** Preference for the inactive selected item background color. */
    pref_t *pref_inactive_bg_;

    /** Preference for the inactive selected item style. */
    pref_t *pref_inactive_style_;

    /** Preference for marked packet foreground color. */
    pref_t *pref_marked_fg_;

    /** Preference for marked packet background color. */
    pref_t *pref_marked_bg_;

    /** Preference for ignored packet foreground color. */
    pref_t *pref_ignored_fg_;

    /** Preference for ignored packet background color. */
    pref_t *pref_ignored_bg_;

    /** Preference for client traffic foreground color. */
    pref_t *pref_client_fg_;

    /** Preference for client traffic background color. */
    pref_t *pref_client_bg_;

    /** Preference for server traffic foreground color. */
    pref_t *pref_server_fg_;

    /** Preference for server traffic background color. */
    pref_t *pref_server_bg_;

    /** Preference for valid filter text foreground color. */
    pref_t* pref_valid_fg_;

    /** Preference for valid filter text background color. */
    pref_t *pref_valid_bg_;

    /** Preference for invalid filter text foreground color. */
    pref_t* pref_invalid_fg_;

    /** Preference for invalid filter text background color. */
    pref_t *pref_invalid_bg_;

    /** Preference for deprecated filter text foreground color. */
    pref_t* pref_deprecated_fg_;

    /** Preference for deprecated filter text background color. */
    pref_t *pref_deprecated_bg_;

    /** The currently selected font. */
    QFont cur_font_;

    /**
     * @brief Updates the UI widgets to reflect the current preferences.
     */
    void updateWidgets();

    /**
     * @brief Opens a color dialog to change a specific color preference.
     * @param pref Pointer to the preference to change.
     */
    void changeColor(pref_t *pref);

private slots:
    /**
     * @brief Slot triggered when a color preference is changed.
     * @param pref The preference that was modified.
     * @param cc The new color selected.
     */
    void colorChanged(pref_t *pref, const QColor &cc);

    /**
     * @brief Slot triggered when the color scheme combo box index changes.
     * @param index The index of the newly selected color scheme.
     */
    void colorSchemeIndexChanged(int index);

    /**
     * @brief Slot triggered when the font push button is clicked.
     */
    void on_fontPushButton_clicked();

    /**
     * @brief Slot triggered when the active foreground push button is clicked.
     */
    void on_activeFGPushButton_clicked();

    /**
     * @brief Slot triggered when the active background push button is clicked.
     */
    void on_activeBGPushButton_clicked();

    /**
     * @brief Slot triggered when the active style combo box index changes.
     * @param index The new index selected.
     */
    void on_activeStyleComboBox_currentIndexChanged(int index);

    /**
     * @brief Slot triggered when the inactive foreground push button is clicked.
     */
    void on_inactiveFGPushButton_clicked();

    /**
     * @brief Slot triggered when the inactive background push button is clicked.
     */
    void on_inactiveBGPushButton_clicked();

    /**
     * @brief Slot triggered when the inactive style combo box index changes.
     * @param index The new index selected.
     */
    void on_inactiveStyleComboBox_currentIndexChanged(int index);

    /**
     * @brief Slot triggered when the marked foreground push button is clicked.
     */
    void on_markedFGPushButton_clicked();

    /**
     * @brief Slot triggered when the marked background push button is clicked.
     */
    void on_markedBGPushButton_clicked();

    /**
     * @brief Slot triggered when the ignored foreground push button is clicked.
     */
    void on_ignoredFGPushButton_clicked();

    /**
     * @brief Slot triggered when the ignored background push button is clicked.
     */
    void on_ignoredBGPushButton_clicked();

    /**
     * @brief Slot triggered when the client foreground push button is clicked.
     */
    void on_clientFGPushButton_clicked();

    /**
     * @brief Slot triggered when the client background push button is clicked.
     */
    void on_clientBGPushButton_clicked();

    /**
     * @brief Slot triggered when the server foreground push button is clicked.
     */
    void on_serverFGPushButton_clicked();

    /**
     * @brief Slot triggered when the server background push button is clicked.
     */
    void on_serverBGPushButton_clicked();

    /**
     * @brief Slot triggered when the valid filter background push button is clicked.
     */
    void on_validFilterBGPushButton_clicked();

    /**
     * @brief Slot triggered when the valid filter foreground push button is clicked.
     */
    void on_validFilterFGPushButton_clicked();

    /**
     * @brief Slot triggered when the invalid filter background push button is clicked.
     */
    void on_invalidFilterBGPushButton_clicked();

    /**
     * @brief Slot triggered when the invalid filter foreground push button is clicked.
     */
    void on_invalidFilterFGPushButton_clicked();

    /**
     * @brief Slot triggered when the deprecated filter background push button is clicked.
     */
    void on_deprecatedFilterBGPushButton_clicked();

    /**
     * @brief Slot triggered when the deprecated filter foreground push button is clicked.
     */
    void on_deprecatedFilterFGPushButton_clicked();
};

#endif // FONT_COLOR_PREFERENCES_FRAME_H
