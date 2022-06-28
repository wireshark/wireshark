/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef COLUMN_EDITOR_FRAME_H
#define COLUMN_EDITOR_FRAME_H

#include "accordion_frame.h"

namespace Ui {
class ColumnEditorFrame;
}

class ColumnEditorFrame : public AccordionFrame
{
    Q_OBJECT

public:
    explicit ColumnEditorFrame(QWidget *parent = nullptr);
    ~ColumnEditorFrame();
    void editColumn(int column);

signals:
    void columnEdited();

protected:
    virtual void showEvent(QShowEvent *event);
    virtual void keyPressEvent(QKeyEvent *event);

private slots:
    void on_typeComboBox_activated(int index);
    void on_fieldsNameLineEdit_textEdited(const QString &fields);
    void on_occurrenceLineEdit_textEdited(const QString &occurrence);
    void on_buttonBox_rejected();
    void on_buttonBox_accepted();
    void checkCanResolve(void);

private:
    bool syntaxIsValid(void);
    Ui::ColumnEditorFrame *ui;
    int cur_column_;
    QString saved_fields_;
    QString saved_occurrence_;
    void setFields(int index);
};

#endif // COLUMN_EDITOR_FRAME_H
