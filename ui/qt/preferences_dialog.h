/* preferences_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef PREFERENCES_DIALOG_H
#define PREFERENCES_DIALOG_H

#include "config.h"

#include <glib.h>

#include "color.h"

#include <epan/prefs.h>

#include <QDialog>
#include <QTreeWidgetItem>
#include <QComboBox>

extern pref_t *prefFromPrefPtr(void *pref_ptr);
extern guint fill_advanced_prefs(module_t *module, gpointer root_ptr);

namespace Ui {
class PreferencesDialog;
}

class PreferencesDialog : public QDialog
{
    Q_OBJECT

public:
    explicit PreferencesDialog(QWidget *parent = 0);
    ~PreferencesDialog();

protected:
    void showEvent(QShowEvent *evt);
    void keyPressEvent(QKeyEvent *evt);

private:
    bool stashedPrefIsDefault(pref_t *pref);
    void updateItem(QTreeWidgetItem &item);

    Ui::PreferencesDialog *pd_ui_;
    int cur_pref_type_;
    QLineEdit *cur_line_edit_;
    QString saved_string_pref_;
    QComboBox *cur_combo_box_;
    int saved_combo_idx_;

private slots:
    void on_prefsTree_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous);
    void on_advancedSearchLineEdit_textEdited(const QString &search_str);
    void lineEditPrefDestroyed();
    void enumPrefDestroyed();
    void uintPrefEditingFinished();
    void enumPrefCurrentIndexChanged(int index);
    void stringPrefEditingFinished();
    void rangePrefTextChanged(const QString & text);
    void rangePrefEditingFinished();

    void on_advancedTree_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous);
    void on_advancedTree_itemActivated(QTreeWidgetItem *item, int column);

    void on_buttonBox_accepted();
    void on_buttonBox_helpRequested();
};

#endif // PREFERENCES_DIALOG_H
