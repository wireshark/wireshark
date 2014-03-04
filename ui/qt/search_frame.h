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

public slots:
    void setCaptureFile(capture_file *cf);
    void findFrameWithFilter(QString &filter);

signals:
    void pushFilterSyntaxStatus(QString&);

protected:
    void keyPressEvent(QKeyEvent *event);

private:
    void enableWidgets();

    Ui::SearchFrame *sf_ui_;
    capture_file *cap_file_;

private slots:
    void on_searchTypeComboBox_currentIndexChanged(int index);

    void on_searchLineEdit_textChanged(const QString &search_string);

    void on_findButton_clicked();

    void on_cancelButton_clicked();
};

#endif // SEARCH_FRAME_H
