/* apply_lineedit.h
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

#ifndef UI_QT_APPLY_LINE_EDIT_H_
#define UI_QT_APPLY_LINE_EDIT_H_

#include <QLineEdit>
#include <QString>

#include <ui/qt/stock_icon_tool_button.h>

class ApplyLineEdit : public QLineEdit
{
    Q_OBJECT

public:
    explicit ApplyLineEdit(QString linePlaceholderText, QWidget *parent = 0);
    ~ApplyLineEdit();

    Q_PROPERTY(QString regex READ regex WRITE setRegEx)
    Q_PROPERTY(bool emptyAllowed READ emptyAllowed WRITE setEmptyAllowed)

    QString regex();
    void setRegEx(QString);

    bool emptyAllowed();
    void setEmptyAllowed(bool);

signals:
    void textApplied();

protected:
    void resizeEvent(QResizeEvent *);

private:

    QString regex_;
    bool emptyAllowed_;

    StockIconToolButton *applyButton;

    bool isValidText(QString &, bool ignoreEmptyCheck = false);
    void handleValidation(QString newText);

private slots:
    void onTextEdited(const QString &);
    void onTextChanged(const QString &);
    void onSubmitContent();
};

#endif /* UI_QT_APPLY_LINE_EDIT_H_ */

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
