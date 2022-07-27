/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

protected:
    virtual void keyPressEvent(QKeyEvent *event);
    void changeEvent(QEvent* event);

private:
    bool regexCompile();
    void applyRecentSearchSettings();
    void updateWidgets();

    Ui::SearchFrame *sf_ui_;
    capture_file *cap_file_;
    ws_regex_t *regex_;
    QString regex_error_;

private slots:
    void on_searchInComboBox_currentIndexChanged(int idx);
    void on_charEncodingComboBox_currentIndexChanged(int idx);
    void on_caseCheckBox_toggled(bool checked);
    void on_searchTypeComboBox_currentIndexChanged(int idx);
    void on_searchLineEdit_textChanged(const QString &);
    void on_findButton_clicked();
    void on_cancelButton_clicked();
};

#endif // SEARCH_FRAME_H
