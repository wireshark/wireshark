/* path_chooser_delegate.cpp
 * Delegate to select a file path for a treeview entry
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "epan/prefs.h"
#include "ui/last_open_dir.h"

#include <ui/qt/models/path_chooser_delegate.h>
#include "ui/qt/widgets/wireshark_file_dialog.h"

#include <QHBoxLayout>
#include <QPushButton>
#include <QWidget>
#include <QLineEdit>

PathChooserDelegate::PathChooserDelegate(QObject *parent)
    : QStyledItemDelegate(parent)
{
}

QWidget* PathChooserDelegate::createEditor(QWidget *parent, const QStyleOptionViewItem &option, const QModelIndex &) const
{
    QWidget * pathEditor = new QWidget(parent);
    QHBoxLayout *hbox = new QHBoxLayout(pathEditor);
    pathEditor->setLayout(hbox);
    QLineEdit * lineEdit = new QLineEdit(pathEditor);
    QPushButton *btnBrowse = new QPushButton(pathEditor);

    btnBrowse->setText(tr("Browse"));

    hbox->setContentsMargins(0, 0, 0, 0);
    hbox->addWidget(lineEdit);
    hbox->addWidget(btnBrowse);
    hbox->setSizeConstraint(QLayout::SetMinimumSize);

    // Grow the item to match the editor. According to the QAbstractItemDelegate
    // documenation we're supposed to reimplement sizeHint but this seems to work.
    QSize size = option.rect.size();
    size.setHeight(qMax(option.rect.height(), hbox->sizeHint().height()));

    lineEdit->selectAll();
    pathEditor->setFocusProxy(lineEdit);
    pathEditor->setFocusPolicy(lineEdit->focusPolicy());

    connect(btnBrowse, &QPushButton::clicked, this, &PathChooserDelegate::browseButtonClicked);
    return pathEditor;
}

void PathChooserDelegate::updateEditorGeometry(QWidget *editor, const QStyleOptionViewItem &option, const QModelIndex &) const
{
    QRect rect = option.rect;

    // Make sure the editor doesn't get squashed.
    editor->adjustSize();
    rect.setHeight(qMax(option.rect.height(), editor->height()));
    editor->setGeometry(rect);
}

void PathChooserDelegate::browseButtonClicked()
{
    char *open_dir = NULL;

    switch (prefs.gui_fileopen_style)
    {

    case FO_STYLE_LAST_OPENED:
        open_dir = get_last_open_dir();
        break;

    case FO_STYLE_SPECIFIED:
        if (prefs.gui_fileopen_dir[0] != '\0')
            open_dir = prefs.gui_fileopen_dir;
        break;
    }

    QWidget * qw = new QWidget();
    QString file_name = WiresharkFileDialog::getOpenFileName(qw, tr("Open Pipe"), open_dir);
    if (!file_name.isEmpty())
    {
        QWidget * parent = ((QPushButton *)sender())->parentWidget();
        QLineEdit * lineEdit = parent->findChild<QLineEdit*>();
        if (lineEdit)
        {
            lineEdit->setText(file_name);
            emit commitData(parent);
        }
    }
    delete(qw);
}

void PathChooserDelegate::setEditorData(QWidget *editor, const QModelIndex &idx) const
{
    if (idx.isValid())
    {
        QString content = idx.data().toString();
        QLineEdit * lineEdit = editor->findChild<QLineEdit*>();
        if (lineEdit)
        {
            lineEdit->setText(content);
        }
    }
    else
        QStyledItemDelegate::setEditorData(editor, idx);
}

void PathChooserDelegate::setModelData(QWidget *editor, QAbstractItemModel * model, const QModelIndex &idx) const
{
    if (idx.isValid())
    {
        QLineEdit * lineEdit = editor->findChild<QLineEdit*>();
        if (lineEdit)
        {
            model->setData(idx, lineEdit->text());
        }
    }
    else
    {
        QStyledItemDelegate::setModelData(editor, model, idx);
    }
}

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
