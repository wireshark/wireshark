/* search_frame.h
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

#ifndef SEARCH_FRAME_H
#define SEARCH_FRAME_H

#include <config.h>

#include "accordion_frame.h"

#include "cfile.h"

namespace Ui {
class SearchFrame;
}

class SearchFrame : public AccordionFrame
{
    Q_OBJECT

public:
    explicit SearchFrame(QWidget *parent = 0);
    ~SearchFrame();
    void animatedShow();
    void findNext();
    void findPrevious();
    void setFocus();

public slots:
    void setCaptureFile(capture_file *cf);
    void findFrameWithFilter(QString &filter);

signals:
    void pushFilterSyntaxStatus(const QString&);

protected:
    virtual void keyPressEvent(QKeyEvent *event);

private:
    bool regexCompile();
    void updateWidgets();

    Ui::SearchFrame *sf_ui_;
    capture_file *cap_file_;
    GRegex *regex_;
    QString regex_error_;

private slots:
    void on_caseCheckBox_toggled(bool);
    void on_searchTypeComboBox_currentIndexChanged(int);
    void on_searchLineEdit_textChanged(const QString &);
    void on_findButton_clicked();
    void on_cancelButton_clicked();
    void changeEvent(QEvent* event);
};

#endif // SEARCH_FRAME_H

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
