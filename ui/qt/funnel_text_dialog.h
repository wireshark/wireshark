/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FUNNEL_TEXT_DIALOG_H
#define FUNNEL_TEXT_DIALOG_H

#include "epan/funnel.h"
#include "geometry_state_dialog.h"

#include <QDialog>

namespace Ui {
class FunnelTextDialog;
}

class FunnelTextDialog;
struct _funnel_text_window_t {
    FunnelTextDialog* funnel_text_dialog;
};

class FunnelTextDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit FunnelTextDialog(QWidget *parent, const QString &title = QString());
    ~FunnelTextDialog();

    void reject();

    // Funnel ops
    static struct _funnel_text_window_t *textWindowNew(QWidget *parent, const QString title);
    void setText(const QString text);
    void appendText(const QString text);
    void prependText(const QString text);
    void clearText();
    const char *getText();
    void setCloseCallback(text_win_close_cb_t close_cb, void* close_cb_data);
    void setTextEditable(bool editable);
    void addButton(funnel_bt_t *button_cb, QString label);

private slots:
    void buttonClicked();
    void on_findLineEdit_textChanged(const QString &pattern);

private:
    Ui::FunnelTextDialog *ui;

    struct _funnel_text_window_t funnel_text_window_;
    text_win_close_cb_t close_cb_;
    void *close_cb_data_;
};

extern "C" {
void text_window_set_text(funnel_text_window_t* ftw, const char* text);
void text_window_append(funnel_text_window_t *ftw, const char* text);
void text_window_prepend(funnel_text_window_t* ftw, const char* text);
void text_window_clear(funnel_text_window_t *ftw);
const char *text_window_get_text(funnel_text_window_t* ftw);
void text_window_set_close_cb(funnel_text_window_t *ftw, text_win_close_cb_t close_cb, void* close_cb_data);
void text_window_set_editable(funnel_text_window_t* ftw, bool editable);
void text_window_destroy(funnel_text_window_t* ftw);
void text_window_add_button(funnel_text_window_t* ftw, funnel_bt_t* funnel_button, const char* label);
}


#endif // FUNNEL_TEXT_DIALOG_H
