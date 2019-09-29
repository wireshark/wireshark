/* coloring_rules_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef COLORING_RULES_DIALOG_H
#define COLORING_RULES_DIALOG_H

#include "geometry_state_dialog.h"
#include "filter_action.h"

#include <ui/qt/models/coloring_rules_model.h>
#include <ui/qt/models/coloring_rules_delegate.h>

#include <QMap>

class QAbstractButton;

namespace Ui {
class ColoringRulesDialog;
}

class ColoringRulesDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit ColoringRulesDialog(QWidget *parent = 0, QString add_filter = QString());
    ~ColoringRulesDialog();

signals:
    void filterAction(QString filter, FilterAction::Action action, FilterAction::ActionType type);

protected:
    void showEvent(QShowEvent *);

private slots:
    void copyFromProfile(QString fileName);
    void colorRuleSelectionChanged(const QItemSelection &selected, const QItemSelection &deselected);
    void colorChanged(bool foreground, const QColor &cc);
    void on_fGPushButton_clicked();
    void on_bGPushButton_clicked();
    void on_displayFilterPushButton_clicked();
    void on_newToolButton_clicked();
    void on_deleteToolButton_clicked();
    void on_copyToolButton_clicked();
    void on_clearToolButton_clicked();
    void on_buttonBox_clicked(QAbstractButton *button);
    void on_buttonBox_accepted();
    void on_buttonBox_helpRequested();
    void rowCountChanged();
    void invalidField(const QModelIndex &index, const QString& errMessage);
    void validField(const QModelIndex &index);
    void treeItemClicked(const QModelIndex &index);

private:
    Ui::ColoringRulesDialog *ui;
    QPushButton *import_button_;
    QPushButton *export_button_;
    ColoringRulesModel colorRuleModel_;
    ColoringRulesDelegate colorRuleDelegate_;

    QMap<QModelIndex, QString> errors_;

    void checkUnknownColorfilters();
    void setColorButtons(QModelIndex &index);
    void updateHint(QModelIndex idx = QModelIndex());

    void addRule(bool copy_from_current = false);
    void changeColor(bool foreground = true);

    bool isValidFilter(QString filter, QString *error);
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
