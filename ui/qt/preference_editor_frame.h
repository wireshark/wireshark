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

class PreferenceEditorFrame : public AccordionFrame
{
    Q_OBJECT

public:
    explicit PreferenceEditorFrame(QWidget *parent = 0);
    ~PreferenceEditorFrame();

public slots:
    void editPreference(pref_t *pref = NULL, module_t *module = NULL);

signals:
    void showProtocolPreferences(const QString module_name);

protected:
    virtual void showEvent(QShowEvent *event);
    virtual void keyPressEvent(QKeyEvent *event);

private slots:
    // Similar to ModulePreferencesScrollArea
    void uintLineEditTextEdited(const QString &new_str);
    void stringLineEditTextEdited(const QString &new_str);
    void rangeLineEditTextEdited(const QString &new_str);
    void browsePushButtonClicked();

    void on_modulePreferencesToolButton_clicked();
    void on_preferenceLineEdit_returnPressed();
    void on_buttonBox_accepted();
    void on_buttonBox_rejected();

private:
    Ui::PreferenceEditorFrame *ui;

    module_t *module_;
    pref_t *pref_;

    unsigned int new_uint_;
    QString new_str_;
    range_t *new_range_;
};

#endif // PREFERENCE_EDITOR_FRAME_H
