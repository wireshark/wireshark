/* path_chooser_delegate.h
 * Delegate to select a file path for a treeview entry
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PATH_CHOOSER_DELEGATE_H_
#define PATH_CHOOSER_DELEGATE_H_

#include <QStyledItemDelegate>

class PathChooserDelegate : public QStyledItemDelegate
{
    Q_OBJECT

public:
    PathChooserDelegate(QObject *parent = 0);

protected:
    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &idx) const;
    void updateEditorGeometry (QWidget * editor, const QStyleOptionViewItem & option, const QModelIndex & idx) const;
    void setEditorData(QWidget *editor, const QModelIndex &idx) const;
    void setModelData(QWidget *editor, QAbstractItemModel *model, const QModelIndex &idx) const;

private slots:
    void browseButtonClicked();
};

#endif /* PATH_CHOOSER_DELEGATE_H_ */

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
