/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FUNNEL_TEXT_DIALOG_H
#define FUNNEL_TEXT_DIALOG_H

#include "epan/funnel.h"
#include "geometry_state_dialog.h"

#include <QDialog>

namespace Ui {
class FunnelTextDialog;
}

class FunnelTextDialog;
struct _funnel_text_window_t {
    FunnelTextDialog* funnel_text_dialog;
};

/**
 * @brief A dialog displaying text output from a Lua funnel script.
 *
 * Provides a scrollable, optionally editable text area along with
 * script-defined buttons and a find bar.
 */
class FunnelTextDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    /** @brief Construct a FunnelTextDialog.
     *  @param parent The parent widget.
     *  @param title  The dialog title. */
    explicit FunnelTextDialog(QWidget *parent, const QString &title = QString());

    /** @brief Destroy the FunnelTextDialog. */
    ~FunnelTextDialog();

    /**
     * @brief Handle dialog rejection, invoking the close callback if set.
     */
    void reject() override;

    // Funnel ops
    /** @brief Create a new funnel text window.
     *  @param parent The parent widget.
     *  @param title  The window title.
     *  @return Pointer to the new funnel text window handle. */
    static struct _funnel_text_window_t *textWindowNew(QWidget *parent, const QString title);

    /** @brief Replace the dialog's text content.
     *  @param text The new text to display. */
    void setText(const QString text);

    /** @brief Append text to the end of the dialog's content.
     *  @param text The text to append. */
    void appendText(const QString text);

    /** @brief Prepend text to the beginning of the dialog's content.
     *  @param text The text to prepend. */
    void prependText(const QString text);

    /**
     * @brief Clear all text from the dialog.
     */
    void clearText();

    /** @brief Return the current text content as a C string.
     *  @return The current text content. */
    const char *getText();

    /** @brief Set the callback to invoke when the dialog is closed.
     *  @param close_cb      The close callback function.
     *  @param close_cb_data User data to pass to the callback. */
    void setCloseCallback(text_win_close_cb_t close_cb, void* close_cb_data);

    /** @brief Set whether the text area is editable by the user.
     *  @param editable true to allow editing, false to make it read-only. */
    void setTextEditable(bool editable);

    /** @brief Add a script-defined button to the dialog.
     *  @param button_cb The funnel button callback descriptor.
     *  @param label     The button label text. */
    void addButton(funnel_bt_t *button_cb, QString label);

private slots:
    /**
     * @brief Handle clicks on any script-defined button.
     */
    void buttonClicked();

    /** @brief Handle changes to the find bar search pattern.
     *  @param pattern The current search pattern. */
    void on_findLineEdit_textChanged(const QString &pattern);


private:
    Ui::FunnelTextDialog *ui;

    struct _funnel_text_window_t funnel_text_window_; /**< The funnel text window handle. */
    text_win_close_cb_t close_cb_;                    /**< Callback invoked when the dialog closes. */
    void *close_cb_data_;                             /**< User data for the close callback. */
};

extern "C" {

/**
 * @brief Set the text in a funnel text window.
 *
 * @param ftw Pointer to the funnel text window.
 * @param text The new text to set.
 */
void text_window_set_text(funnel_text_window_t* ftw, const char* text);

/**
 * @brief Append text to a funnel text window.
 *
 * @param ftw Pointer to the funnel text window structure.
 * @param text The text to append.
 */
void text_window_append(funnel_text_window_t *ftw, const char* text);
/**
 * @brief Prepend text to a funnel text window.
 *
 * @param ftw Pointer to the funnel text window structure.
 * @param text The text to prepend.
 */
void text_window_prepend(funnel_text_window_t* ftw, const char* text);

/**
 * @brief Clears the text in the funnel text window.
 *
 * @param ftw Pointer to the funnel text window structure.
 */
void text_window_clear(funnel_text_window_t *ftw);

/**
 * @brief Gets the text from a funnel text window.
 *
 * @param ftw Pointer to the funnel text window structure.
 * @return A pointer to the text in the window.
 */
const char *text_window_get_text(funnel_text_window_t* ftw);

/**
 * @brief Set the close callback for a funnel text window.
 *
 * @param ftw Pointer to the funnel text window structure.
 * @param close_cb The callback function to be called when the window is closed.
 * @param close_cb_data User data to be passed to the close callback function.
 */
void text_window_set_close_cb(funnel_text_window_t *ftw, text_win_close_cb_t close_cb, void* close_cb_data);

/**
 * @brief Set the editable state of the text window.
 *
 * @param ftw Pointer to the funnel text window structure.
 * @param editable Boolean indicating whether the text window should be editable.
 */
void text_window_set_editable(funnel_text_window_t* ftw, bool editable);

/**
 * @brief Destroys a funnel text window.
 *
 * @param ftw Pointer to the funnel text window structure.
 */
void text_window_destroy(funnel_text_window_t* ftw);

/**
 * @brief Adds a button to the text window.
 *
 * @param ftw Pointer to the funnel text window structure.
 * @param funnel_button Pointer to the funnel button structure.
 * @param label The label for the button.
 */
void text_window_add_button(funnel_text_window_t* ftw, funnel_bt_t* funnel_button, const char* label);
}


#endif // FUNNEL_TEXT_DIALOG_H
