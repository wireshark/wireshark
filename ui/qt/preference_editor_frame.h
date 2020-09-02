/* preference_editor_frame.h
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

struct pref_module;
struct preference;
struct epan_range;

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
    void editPreference(struct preference *pref = NULL, struct pref_module *module = NULL);

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

    struct pref_module *module_;
    struct preference *pref_;

    unsigned int new_uint_;
    QString new_str_;
    struct epan_range *new_range_;
};

#endif // PREFERENCE_EDITOR_FRAME_H

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
