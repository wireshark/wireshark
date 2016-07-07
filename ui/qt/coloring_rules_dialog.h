/* coloring_rules_dialog.h
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

#ifndef COLORING_RULES_DIALOG_H
#define COLORING_RULES_DIALOG_H

#include "geometry_state_dialog.h"

class QAbstractButton;
class QTreeWidget;

struct _color_filter;
struct _GSList; // This is a completely and totally safe forward declaration, right?

namespace Ui {
class ColoringRulesDialog;
}

#include <QStyledItemDelegate>

class ColoringRulesTreeDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    ColoringRulesTreeDelegate(QObject *parent = 0) : QStyledItemDelegate(parent), tree_(NULL) {}
    ~ColoringRulesTreeDelegate() {}

    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index) const;
    void setTree(QTreeWidget* tree) { tree_ = tree; }

private:
    QTreeWidget* tree_;

private slots:
    void ruleNameChanged(const QString name);
};

class ColoringRulesDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit ColoringRulesDialog(QWidget *parent = 0, QString add_filter = QString());
    ~ColoringRulesDialog();

    void addColor(struct _color_filter *colorf);

protected:
    void showEvent(QShowEvent *);

private slots:
    void updateWidgets();
    struct _GSList *createColorFilterList();
    void on_coloringRulesTreeWidget_itemSelectionChanged();
    void on_fGPushButton_clicked();
    void on_bGPushButton_clicked();
    void on_newToolButton_clicked();
    void on_deleteToolButton_clicked();
    void on_copyToolButton_clicked();
    void on_buttonBox_clicked(QAbstractButton *button);
    void on_buttonBox_accepted();
    void on_buttonBox_helpRequested();

private:
    Ui::ColoringRulesDialog *ui;
    QPushButton *import_button_;
    QPushButton *export_button_;
    ColoringRulesTreeDelegate coloring_rules_tree_delegate_;
    struct _GSList *conversation_colors_;

    void addColoringRule(bool disabled, QString name, QString filter, QColor foreground, QColor background, bool start_editing = false, bool at_top = true);
    void changeColor(bool foreground = true);
};

#endif // COLORING_RULES_DIALOG_H

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
