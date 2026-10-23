/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FONT_PREFERENCES_FRAME_H
#define FONT_PREFERENCES_FRAME_H

#include <QFrame>

typedef struct preference pref_t;

namespace Ui {
class FontPreferencesFrame;
}

/**
 * @brief A frame for choosing the monospace font.
 *
 * Edits the gui.qt.font_name preference through the preference stash.
 */
class FontPreferencesFrame : public QFrame
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the frame and loads the stashed font.
     * @param parent Optional parent widget.
     */
    explicit FontPreferencesFrame(QWidget *parent = nullptr);

    /** @brief Destroys the frame and releases the UI object. */
    ~FontPreferencesFrame();

private:
    /** @brief Qt Designer generated UI object. */
    Ui::FontPreferencesFrame *ui;

    /** @brief The gui.qt.font_name preference. */
    pref_t *pref_qt_gui_font_name_;

    /**
     * @brief Show the hints that apply to the font that will be used.
     */
    void updateHints();

private slots:
    /** @brief Write the edited font to the preference stash. */
    void fontChanged();
};

#endif // FONT_PREFERENCES_FRAME_H
