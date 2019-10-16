/* editor_file_dialog.h
 *
 * File dialog that can be used as an "inline editor" in a table
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef EDITOR_FILE_DIALOG_H_
#define EDITOR_FILE_DIALOG_H_

#include <QModelIndex>
#include <QLineEdit>
#include <QFileDialog>
#include <QPushButton>

class EditorFileDialog : public QLineEdit
{
    Q_OBJECT
public:
    enum FileMode { ExistingFile, Directory };

    explicit EditorFileDialog(const QModelIndex& index, enum FileMode mode, QWidget* parent = 0, const QString & caption = QString(), const QString & directory = QString(), const QString & filter = QString());

    void setOption(QFileDialog::Option option, bool on = true);
    virtual void focusInEvent(QFocusEvent *event);
    virtual void focusOutEvent(QFocusEvent *event);
    virtual bool eventFilter(QObject *obj, QEvent *event);

signals:
    void acceptEdit(const QModelIndex& index);

private slots:
    void applyFilename();

protected:
    void resizeEvent(QResizeEvent *);
    QPushButton* file_dialog_button_;
    const QModelIndex index_; //saved index of table cell
    enum FileMode mode_;
    QString caption_;
    QString directory_;
    QString filter_;
    QFileDialog::Options options_;
};

#endif /* EDITOR_FILE_DIALOG_H_ */

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
