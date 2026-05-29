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
#include <QString>

#include <epan/prefs.h>

#include <ui/qt/widgets/theme_preview_widget.h>

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

    /**
     * Called by the preferences dialog when the user accepts changes.
     * Copies the stashed theme selection back to recent_common (the
     * color-scheme mode is persisted via the normal pref_stashed path
     * and does not need an explicit unstash).
     */
    void unstash();

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

    QComboBox *themeComboBox_;

    QString    stashed_theme_name_;

    /** Preference for the color scheme. */
    pref_t *pref_color_scheme_;

    /** Preference for the Qt GUI font name. */
    pref_t *pref_qt_gui_font_name_;

    /** Hand-painted theme mockup driven by ThemeManager::previewTheme(). */
    ThemePreviewWidget *previewWidget_ = nullptr;

    /** The currently selected font. */
    QFont cur_font_;

    /**
     * @brief Updates the UI widgets to reflect the current preferences.
     */
    void updateWidgets();

private slots:
    /**
     * @brief Slot triggered when the color scheme combo box index changes.
     * @param index The index of the newly selected color scheme.
     */
    void colorSchemeIndexChanged(int index);

    void themeIndexChanged(int index);

    /**
     * @brief Refreshes the theme preview. Stub in Task 8; wired in Task 12.
     */
    void refreshPreview();

    /**
     * @brief Slot triggered when the font push button is clicked.
     */
    void on_fontPushButton_clicked();
};

#endif // FONT_COLOR_PREFERENCES_FRAME_H
