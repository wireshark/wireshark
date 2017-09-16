/* editor_color_dialog.h
 *
 * Color dialog that can be used as an "inline editor" in a table
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later*/

#ifndef EDITOR_COLOR_DIALOG_H_
#define EDITOR_COLOR_DIALOG_H_

#include <QLineEdit>
#include <QPushButton>
#include <QModelIndex>

class EditorColorDialog : public QLineEdit
{
    Q_OBJECT
public:
    EditorColorDialog(const QModelIndex& index, const QColor& initial, QWidget* parent = 0);

    QColor currentColor() { return current_; }
    virtual void focusInEvent(QFocusEvent *event);
    virtual void focusOutEvent(QFocusEvent *event);
    virtual bool eventFilter(QObject *obj, QEvent *event);

signals:
    void acceptEdit(const QModelIndex& index);

private slots:
    void applyColor();

protected:
    void resizeEvent(QResizeEvent *);

    QPushButton* color_button_;
    const QModelIndex index_; //saved index of table cell
    QColor current_; //initial color in edit
};

#endif /* EDITOR_COLOR_DIALOG_H_ */

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
