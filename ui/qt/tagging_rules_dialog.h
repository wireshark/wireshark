/* tagging_rules_dialog.h
 *
 * Dialog for managing tagging rules
 * Copyright 2026, Mark Stout <mark.stout@markstout.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TAGGING_RULES_DIALOG_H
#define TAGGING_RULES_DIALOG_H

#include "geometry_state_dialog.h"

class ColoringRulesDialog;

#include <epan/tag_rules.h>
#include <ui/qt/models/tagging_rules_model.h>
#include <ui/qt/models/tagging_rules_delegate.h>

#include <QItemSelection>
#include <QMap>
#include <functional>

class QAbstractButton;

namespace Ui {
class TaggingRulesDialog;
}

class TaggingRulesDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit TaggingRulesDialog(QWidget *parent = nullptr);
    ~TaggingRulesDialog();

    void setColoringAcceptedCallback(std::function<void()> cb) { coloring_accepted_cb_ = std::move(cb); }


private slots:
    void copyFromProfile(QString fileName);
    void tagRuleSelectionChanged(const QItemSelection &selected, const QItemSelection &deselected);
    void on_copyToColoringRuleButton_clicked();

    void on_newToolButton_clicked();
    void on_deleteToolButton_clicked();
    void on_copyToolButton_clicked();
    void on_clearToolButton_clicked();

    void on_buttonBox_clicked(QAbstractButton *button);
    void on_buttonBox_accepted();

    void rowCountChanged();
    void invalidField(const QModelIndex &index, const QString &errMessage);
    void validField(const QModelIndex &index);
    void treeItemClicked(const QModelIndex &index);

    void fontSizeChanged(int idx);
    void separatorChanged(const QString &text);
    void linkClickChanged(int idx);

private:
    Ui::TaggingRulesDialog *ui;

    QPushButton *import_button_;
    QPushButton *export_button_;

    tag_prefs_t originalPrefs_; // saved at open; restored if user cancels
    tag_prefs_t pendingPrefs_;
    QString profilePath_;   // path to the active profile's tagrules file

    TaggingRulesModel    tagRuleModel_;
    TaggingRulesDelegate tagRuleDelegate_;

    QMap<QModelIndex, QString> errors_;
    std::function<void()> coloring_accepted_cb_;

    void reject() override;
    void updateHint(QModelIndex idx = QModelIndex());
    void addRule(bool copy_from_current);
    bool isValidFilter(QString filter, QString *error);
};

#endif // TAGGING_RULES_DIALOG_H
