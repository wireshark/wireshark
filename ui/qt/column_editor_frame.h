/* column_editor_frame.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
    explicit ColumnEditorFrame(QWidget *parent = 0);
    ~ColumnEditorFrame();
    void editColumn(int column);

signals:
    void columnEdited();

private slots:
    void on_typeComboBox_activated(int index);
    void on_fieldsNameLineEdit_textEdited(const QString &fields);
    void on_occurrenceLineEdit_textEdited(const QString &occurrence);
    void on_buttonBox_rejected();
    void on_buttonBox_accepted();

private:
    Ui::ColumnEditorFrame *ui;
    int cur_column_;
    QString saved_fields_;
    QString saved_occurrence_;
    void setFields(int index);
};

#endif // COLUMN_EDITOR_FRAME_H

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
