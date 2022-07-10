/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DISPLAY_FILTER_EXPRESSION_DIALOG_H
#define DISPLAY_FILTER_EXPRESSION_DIALOG_H

#include "config.h"

#include <epan/ftypes/ftypes.h>

#include "geometry_state_dialog.h"

#include <QFutureWatcher>

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
/* Qt6 introduces QPromise interface that makes it possible to add tree entries
 * protocol by protocol instead of all at once.
 */
#define DISPLAY_FILTER_EXPRESSION_DIALOG_USE_QPROMISE
#endif

class QTreeWidgetItem;
struct true_false_string;
struct _value_string;
struct _val64_string;

namespace Ui {
class DisplayFilterExpressionDialog;
}

class DisplayFilterExpressionDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit DisplayFilterExpressionDialog(QWidget *parent = 0);
    ~DisplayFilterExpressionDialog();

signals:
    void insertDisplayFilter(const QString &filter);

private slots:
#ifdef DISPLAY_FILTER_EXPRESSION_DIALOG_USE_QPROMISE
    void addTreeItem(int result);
#endif
    void fillTree();
    void updateWidgets();

    void on_fieldTreeWidget_itemSelectionChanged();
    void on_relationListWidget_itemSelectionChanged();
    void on_enumListWidget_itemSelectionChanged();
    void on_searchLineEdit_textChanged(const QString &search_re);
    void on_buttonBox_accepted();
    void on_buttonBox_helpRequested();

private:
#ifdef DISPLAY_FILTER_EXPRESSION_DIALOG_USE_QPROMISE
    QFutureWatcher<QTreeWidgetItem *> *watcher;
#else
    QFutureWatcher<QList<QTreeWidgetItem *> *> *watcher;
#endif
    Ui::DisplayFilterExpressionDialog *ui;
    void fillEnumBooleanValues(const struct true_false_string *tfs);
    void fillEnumIntValues(const struct _value_string *vals, int base);
    void fillEnumInt64Values(const struct _val64_string *vals64, int base);
    void fillEnumRangeValues(const struct _range_string *rvals);

    enum ftenum ftype_;
    const char *field_;
    QString value_label_pfx_;
};

#endif // DISPLAY_FILTER_EXPRESSION_DIALOG_H
