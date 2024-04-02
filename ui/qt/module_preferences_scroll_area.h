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
#include <epan/prefs-int.h>

#include <QScrollArea>

namespace Ui {
class ModulePreferencesScrollArea;
}

class ModulePreferencesScrollArea : public QScrollArea
{
    Q_OBJECT

public:
    explicit ModulePreferencesScrollArea(module_t *module, QWidget *parent = 0);
    ~ModulePreferencesScrollArea();
    const QString name() const { return QString(module_->name); }

protected:
    void showEvent(QShowEvent *);
    void resizeEvent(QResizeEvent *evt);

private:
    Ui::ModulePreferencesScrollArea *ui;

    module_t *module_;
    void updateWidgets();

private slots:
    void uintLineEditTextEdited(const QString &new_str);
    void boolCheckBoxToggled(bool checked);
    void enumRadioButtonToggled(bool checked);
    void enumComboBoxCurrentIndexChanged(int index);
    void stringLineEditTextEdited(const QString &new_str);
    void rangeSyntaxLineEditTextEdited(const QString &new_str);
    void uatPushButtonClicked();
    void saveFilenamePushButtonClicked();
    void openFilenamePushButtonClicked();
    void dirnamePushButtonClicked();
    void enumComboBoxCurrentIndexChanged_PROTO_TCP(int index);
};

#endif // MODULE_PREFERENCES_SCROLL_AREA_H
