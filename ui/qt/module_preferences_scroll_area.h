/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MODULE_PREFERENCES_SCROLL_AREA_H
#define MODULE_PREFERENCES_SCROLL_AREA_H

#include <config.h>

#include <epan/prefs.h>

#include <QScrollArea>

namespace Ui {
class ModulePreferencesScrollArea;
}

/**
 * @brief A scroll area widget for displaying and editing module preferences.
 */
class ModulePreferencesScrollArea : public QScrollArea
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new ModulePreferencesScrollArea.
     * @param module The module associated with the preferences.
     * @param parent The parent widget, defaults to 0.
     */
    explicit ModulePreferencesScrollArea(module_t *module, QWidget *parent = 0);

    /**
     * @brief Destroys the ModulePreferencesScrollArea.
     */
    ~ModulePreferencesScrollArea();

    /**
     * @brief Gets the name of the module.
     * @return The module name as a string.
     */
    const QString name() const;

protected:
    /**
     * @brief Handles the show event.
     */
    void showEvent(QShowEvent *);

    /**
     * @brief Handles the resize event.
     * @param evt The resize event.
     */
    void resizeEvent(QResizeEvent *evt);

private:
    /** Pointer to the generated UI elements. */
    Ui::ModulePreferencesScrollArea *ui;

    /** Pointer to the associated module data. */
    module_t *module_;

    /**
     * @brief Updates the preference widgets to reflect current values.
     */
    void updateWidgets();

private slots:
    /**
     * @brief Slot triggered when an unsigned integer line edit is modified.
     * @param new_str The new string value.
     */
    void uintLineEditTextEdited(const QString &new_str);

    /**
     * @brief Slot triggered when an integer line edit is modified.
     * @param new_str The new string value.
     */
    void intLineEditTextEdited(const QString& new_str);

    /**
     * @brief Slot triggered when a float line edit is modified.
     * @param new_str The new string value.
     */
    void floatLineEditTextEdited(const QString& new_str);

    /**
     * @brief Slot triggered when a boolean checkbox is toggled.
     * @param checked True if checked, false otherwise.
     */
    void boolCheckBoxToggled(bool checked);

    /**
     * @brief Slot triggered when an enum radio button is toggled.
     * @param checked True if checked, false otherwise.
     */
    void enumRadioButtonToggled(bool checked);

    /**
     * @brief Slot triggered when an enum combo box index changes.
     * @param index The new index.
     */
    void enumComboBoxCurrentIndexChanged(int index);

    /**
     * @brief Slot triggered when a string line edit is modified.
     * @param new_str The new string value.
     */
    void stringLineEditTextEdited(const QString &new_str);

    /**
     * @brief Slot triggered when a range syntax line edit is modified.
     * @param new_str The new string value.
     */
    void rangeSyntaxLineEditTextEdited(const QString &new_str);

    /**
     * @brief Slot triggered when a UAT push button is clicked.
     */
    void uatPushButtonClicked();

    /**
     * @brief Slot triggered when a save filename push button is clicked.
     */
    void saveFilenamePushButtonClicked();

    /**
     * @brief Slot triggered when an open filename push button is clicked.
     */
    void openFilenamePushButtonClicked();

    /**
     * @brief Slot triggered when a directory name push button is clicked.
     */
    void dirnamePushButtonClicked();

    /**
     * @brief Slot triggered specifically when the PROTO TCP enum combo box index changes.
     * @param index The new index.
     */
    void enumComboBoxCurrentIndexChanged_PROTO_TCP(int index);
};

#endif // MODULE_PREFERENCES_SCROLL_AREA_H
