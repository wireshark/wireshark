/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FILTER_DIALOG_H
#define FILTER_DIALOG_H

#include "geometry_state_dialog.h"

#include <ui/qt/models/filter_list_model.h>

#include <QStyledItemDelegate>
#include <QValidator>

class QItemSelection;
class FilterTreeDelegate;

namespace Ui {
class FilterDialog;
}

class FilterDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    enum FilterType { CaptureFilter, DisplayFilter, DisplayMacro };
    explicit FilterDialog(QWidget *parent = 0, FilterType filter_type = CaptureFilter, const QString new_filter = QString());
    ~FilterDialog();

private:
    Ui::FilterDialog *ui;

    FilterListModel * model_;

    enum FilterType filter_type_;
    FilterTreeDelegate *filter_tree_delegate_;

    void addFilter(QString name, QString filter, bool start_editing = false);

private slots:
    void updateWidgets();

    void selectionChanged(const QItemSelection &selected, const QItemSelection &deselected);

    void on_newToolButton_clicked();
    void on_deleteToolButton_clicked();
    void on_copyToolButton_clicked();
    void on_buttonBox_accepted();
    void on_buttonBox_helpRequested();
};


//
// FilterTreeDelegate
// Delegate for editing capture and display filters.
//

class FilterTreeDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    FilterTreeDelegate(QObject *parent, FilterDialog::FilterType filter_type);

    virtual QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index) const override;
    virtual void setEditorData(QWidget *editor, const QModelIndex &index) const override;

private:
    FilterDialog::FilterType filter_type_;
};

class FilterValidator : public QValidator
{
public:
    virtual QValidator::State validate(QString & input, int & pos) const override;
};

class MacroNameValidator : public QValidator
{
public:
    virtual QValidator::State validate(QString & input, int & pos) const override;
};

#endif // FILTER_DIALOG_H
