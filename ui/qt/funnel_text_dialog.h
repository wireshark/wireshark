/* funnel_text_dialog.h
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

#ifndef FUNNEL_TEXT_DIALOG_H
#define FUNNEL_TEXT_DIALOG_H

#include <glib.h>

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
    explicit FunnelTextDialog(const QString &title = QString());
    ~FunnelTextDialog();

    void reject();

    // Funnel ops
    static struct _funnel_text_window_t *textWindowNew(const QString title);
    void setText(const QString text);
    void appendText(const QString text);
    void prependText(const QString text);
    void clearText();
    const char *getText();
    void setCloseCallback(text_win_close_cb_t close_cb, void* close_cb_data);
    void setTextEditable(gboolean editable);
    void addButton(funnel_bt_t *button_cb, const QString label);

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
struct _funnel_text_window_t* text_window_new(const char* title);
void text_window_set_text(funnel_text_window_t* ftw, const char* text);
void text_window_append(funnel_text_window_t *ftw, const char* text);
void text_window_prepend(funnel_text_window_t* ftw, const char* text);
void text_window_clear(funnel_text_window_t *ftw);
const char *text_window_get_text(funnel_text_window_t* ftw);
void text_window_set_close_cb(funnel_text_window_t *ftw, text_win_close_cb_t close_cb, void* close_cb_data);
void text_window_set_editable(funnel_text_window_t* ftw, gboolean editable);
void text_window_destroy(funnel_text_window_t* ftw);
void text_window_add_button(funnel_text_window_t* ftw, funnel_bt_t* funnel_button, const char* label);
}


#endif // FUNNEL_TEXT_DIALOG_H

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
