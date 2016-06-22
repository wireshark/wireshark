/* tap_parameter_dialog.h
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

#ifndef TAP_PARAMETER_DIALOG_H
#define TAP_PARAMETER_DIALOG_H

/*
 * @file Base class for statistics and analysis dialogs.
 * Provides convenience classes for command-line tap parameters ("-z ...")
 * and general tapping.
 */

#include "config.h"

#include <glib.h>

#include <epan/stat_groups.h>
#include <epan/stat_tap_ui.h>

#include <QMenu>

#include "filter_action.h"
#include "wireshark_dialog.h"

class QHBoxLayout;
class QLineEdit;
class QTreeWidget;
class QTreeWidgetItem;
class QVBoxLayout;

namespace Ui {
class TapParameterDialog;
}

class TapParameterDialog;
typedef TapParameterDialog* (*tpdCreator)(QWidget &parent, const QString cfg_str, const QString arg, CaptureFile &cf);

class TapParameterDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit TapParameterDialog(QWidget &parent, CaptureFile &cf, int help_topic = 0);
    ~TapParameterDialog();

    static const QString &actionName() { return action_name_; }
    static void registerDialog(const QString title, const char *cfg_abbr, register_stat_group_t group, stat_tap_init_cb tap_init_cb, tpdCreator creator);

    static TapParameterDialog *showTapParameterStatistics(QWidget &parent, CaptureFile &cf, const QString cfg_str, const QString arg, void *);
    // Needed by static member functions in subclasses. Should we just make
    // "ui" available instead?
    QTreeWidget *statsTreeWidget();
    QLineEdit *displayFilterLineEdit();
    QPushButton *applyFilterButton();
    QVBoxLayout *verticalLayout();
    QHBoxLayout *filterLayout();

    void drawTreeItems();

signals:
    void filterAction(QString filter, FilterAction::Action action, FilterAction::ActionType type);
    void updateFilter(QString filter);

public slots:

protected:
    void contextMenuEvent(QContextMenuEvent *event);
    void addFilterActions();
    QString displayFilter();
    void setDisplayFilter(const QString &filter);
    void setHint(const QString &hint);
    // Retap packets on first display. RPC stats need to disable this.
    void setRetapOnShow(bool retap);

protected slots:
    void filterActionTriggered();
    void updateWidgets();

private:
    Ui::TapParameterDialog *ui;
    QMenu ctx_menu_;
    QList<QAction *> filter_actions_;
    int help_topic_;
    static const QString action_name_;
    QTimer *show_timer_;

    virtual const QString filterExpression() { return QString(); }
    QString itemDataToPlain(QVariant var, int width = 0);
    virtual QList<QVariant> treeItemData(QTreeWidgetItem *) const;
    virtual QByteArray getTreeAsString(st_format_type format);

private slots:
    // Called by the constructor. The subclass should tap packets here.
    virtual void fillTree() = 0;

    void on_applyFilterButton_clicked();
    void on_actionCopyToClipboard_triggered();
    void on_actionSaveAs_triggered();
    void on_buttonBox_helpRequested();
};

#endif // TAP_PARAMETER_DIALOG_H

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
