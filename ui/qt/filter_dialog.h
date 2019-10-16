/* filter_dialog.cpp
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

//class CaptureFilterSyntaxWorker;
class FilterTreeDelegate;

namespace Ui {
class FilterDialog;
}

class FilterDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    enum FilterType { CaptureFilter, DisplayFilter };
    explicit FilterDialog(QWidget *parent = 0, FilterType filter_type = CaptureFilter, const QString new_filter = QString());
    ~FilterDialog();

protected:
    void showEvent(QShowEvent * event);

private:
    Ui::FilterDialog *ui;

    enum FilterType filter_type_;
//    CaptureFilterSyntaxWorker *syntax_worker_;
    FilterTreeDelegate *filter_tree_delegate_;
    QString new_filter_;

    void addFilter(QString name, QString filter, bool start_editing = false);

private slots:
    void updateWidgets();
//    void setFilterSyntaxState(QString filter, bool valid, QString err_msg);

    void on_filterTreeWidget_itemSelectionChanged();
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

#include <QStyledItemDelegate>

class FilterTreeDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    FilterTreeDelegate(QObject *parent, FilterDialog::FilterType filter_type) :
        QStyledItemDelegate(parent),
        filter_type_(filter_type)
    {}
    ~FilterTreeDelegate() {}

    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &index) const;

private:
    FilterDialog::FilterType filter_type_;

private slots:
};

#endif // FILTER_DIALOG_H

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
