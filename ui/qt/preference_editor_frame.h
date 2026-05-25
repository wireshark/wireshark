/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PREFERENCE_EDITOR_FRAME_H
#define PREFERENCE_EDITOR_FRAME_H

#include "accordion_frame.h"

#include <epan/prefs.h>
#include <epan/range.h>

namespace Ui {
class PreferenceEditorFrame;
}

/**
 * @brief Frame for editing a single Wireshark preference inline.
 */
class PreferenceEditorFrame : public AccordionFrame
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a PreferenceEditorFrame.
     * @param parent The parent widget.
     */
    explicit PreferenceEditorFrame(QWidget *parent = 0);

    /**
     * @brief Destroys the PreferenceEditorFrame.
     */
    ~PreferenceEditorFrame();

public slots:
    /**
     * @brief Edits the specified preference.
     * @param pref The preference to edit.
     * @param module The module containing the preference.
     */
    void editPreference(pref_t *pref = NULL, module_t *module = NULL);

signals:
    /**
     * @brief Signal emitted to show preferences for a specific protocol.
     * @param module_name The name of the protocol module.
     */
    void showProtocolPreferences(const QString module_name);

protected:
    /**
     * @brief Handles the show event for the frame.
     * @param event The show event.
     */
    virtual void showEvent(QShowEvent *event) override;

    /**
     * @brief Handles key press events within the frame.
     * @param event The key press event.
     */
    virtual void keyPressEvent(QKeyEvent *event) override;

private slots:
    /**
     * @brief Handles text editing for unsigned integer preferences.
     * @param new_str The newly entered string.
     */
    void uintLineEditTextEdited(const QString &new_str);

    /**
     * @brief Handles text editing for string preferences.
     * @param new_str The newly entered string.
     */
    void stringLineEditTextEdited(const QString &new_str);

    /**
     * @brief Handles text editing for range preferences.
     * @param new_str The newly entered string.
     */
    void rangeLineEditTextEdited(const QString &new_str);

    /**
     * @brief Handles clicks on the browse push button.
     */
    void browsePushButtonClicked();

    /**
     * @brief Handles clicks on the module preferences tool button.
     */
    void on_modulePreferencesToolButton_clicked();

    /**
     * @brief Handles the return key being pressed in the preference line edit.
     */
    void on_preferenceLineEdit_returnPressed();

    /**
     * @brief Handles the acceptance (OK/Save) of the dialog button box.
     */
    void on_buttonBox_accepted();

    /**
     * @brief Handles the rejection (Cancel) of the dialog button box.
     */
    void on_buttonBox_rejected();

private:
    Ui::PreferenceEditorFrame *ui; /**< Pointer to the user interface form elements. */

    module_t *module_; /**< Pointer to the module containing the preference being edited. */
    pref_t *pref_; /**< Pointer to the specific preference being edited. */

    unsigned int new_uint_; /**< The pending unsigned integer value being edited. */
    QString new_str_; /**< The pending string value being edited. */
    range_t *new_range_; /**< Pointer to the pending range value being edited. */
};

#endif // PREFERENCE_EDITOR_FRAME_H
