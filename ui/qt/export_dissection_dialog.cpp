/* export_dissection_dialog.cpp
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

#include "export_dissection_dialog.h"

#ifdef Q_OS_WIN
#include <windows.h>
#include "epan/packet-range.h"
#include "ui/win32/file_dlg_win32.h"
#else // Q_OS_WIN

#include "ui/alert_box.h"
#include "ui/help_url.h"
#include "ui/util.h"

#include <epan/print.h>
#include <wsutil/filesystem.h>

#include "qt_ui_utils.h"


#include <QDialogButtonBox>
#include <QGridLayout>
#include <QPushButton>
#endif // Q_OS_WIN

#include <epan/prefs.h>
#include "wireshark_application.h"

ExportDissectionDialog::ExportDissectionDialog(QWidget *parent, capture_file *cap_file, export_type_e export_type):
    QFileDialog(parent),
    export_type_(export_type),
    cap_file_(cap_file)
#if !defined(Q_OS_WIN)
    , save_bt_(NULL)
#endif /* Q_OS_WIN */
{

    switch (prefs.gui_fileopen_style) {

    case FO_STYLE_LAST_OPENED:
        /* The user has specified that we should start out in the last directory
         * we looked in.  If we've already opened a file, use its containing
         * directory, if we could determine it, as the directory, otherwise
         * use the "last opened" directory saved in the preferences file if
         * there was one.
         */
        setDirectory(wsApp->lastOpenDir());
        break;

    case FO_STYLE_SPECIFIED:
        /* The user has specified that we should always start out in a
         * specified directory; if they've specified that directory,
         * start out by showing the files in that dir.
         */
        if (prefs.gui_fileopen_dir[0] != '\0')
            setDirectory(prefs.gui_fileopen_dir);
        break;
    }

#if !defined(Q_OS_WIN)
    QDialogButtonBox *button_box = findChild<QDialogButtonBox *>();
    // Add extra widgets
    // https://wiki.qt.io/Qt_project_org_faq#How_can_I_add_widgets_to_my_QFileDialog_instance.3F
    setOption(QFileDialog::DontUseNativeDialog, true);
    QGridLayout *fd_grid = qobject_cast<QGridLayout*>(layout());
    QHBoxLayout *h_box = new QHBoxLayout();
    QStringList name_filters;
    int last_row;

    setWindowTitle(wsApp->windowTitleString(tr("Export Packet Dissections")));
    setAcceptMode(QFileDialog::AcceptSave);
    setLabelText(FileType, tr("Export As:"));

    // export_type_map_keys() sorts alphabetically. We don't want that.
    name_filters
            << tr("Plain text (*.txt)")
            << tr("Comma Separated Values - summary (*.csv)")
            << tr("PSML - summary (*.psml, *.xml)")
            << tr("PDML - details (*.pdml, *.xml)")
            << tr("JSON (*.json)")
            << tr("C Arrays - bytes (*.c, *.h)");
    export_type_map_[name_filters[0]] = export_type_text;
    export_type_map_[name_filters[1]] = export_type_csv;
    export_type_map_[name_filters[2]] = export_type_psml;
    export_type_map_[name_filters[3]] = export_type_pdml;
    export_type_map_[name_filters[4]] = export_type_json;
    export_type_map_[name_filters[5]] = export_type_carrays;
    setNameFilters(name_filters);
    selectNameFilter(export_type_map_.key(export_type));
    exportTypeChanged(export_type_map_.key(export_type));

    last_row = fd_grid->rowCount();
    fd_grid->addItem(new QSpacerItem(1, 1), last_row, 0);
    fd_grid->addLayout(h_box, last_row, 1);

    print_args_.file = NULL;
    /* Init the export range */
    packet_range_init(&print_args_.range, cap_file_);
    /* Default to displayed packets */
    print_args_.range.process_filtered = TRUE;

    packet_range_group_box_.initRange(&print_args_.range);
    h_box->addWidget(&packet_range_group_box_);

    h_box->addWidget(&packet_format_group_box_, 0, Qt::AlignTop);

    if (button_box) {
        button_box->addButton(QDialogButtonBox::Help);
        connect(button_box, SIGNAL(helpRequested()), this, SLOT(on_buttonBox_helpRequested()));

        save_bt_ = button_box->button(QDialogButtonBox::Save);
    }

    if (save_bt_) {
        connect(&packet_range_group_box_, SIGNAL(validityChanged(bool)),
                this, SLOT(checkValidity()));
        connect(&packet_format_group_box_, SIGNAL(formatChanged()),
                this, SLOT(checkValidity()));
    }
    connect(this, SIGNAL(filterSelected(QString)), this, SLOT(exportTypeChanged(QString)));

    // Grow the dialog to account for the extra widgets.
    resize(width(), height() + (packet_range_group_box_.height() * 2 / 3));

#else // Q_OS_WIN
#endif // Q_OS_WIN
}

ExportDissectionDialog::~ExportDissectionDialog()
{
#if !defined(Q_OS_WIN)
    g_free(print_args_.file);
#endif
}

int ExportDissectionDialog::exec()
{
#if !defined(Q_OS_WIN)
    int retval;

    if (!cap_file_) return QDialog::Rejected;

    retval = QFileDialog::exec();

    if (retval ==  QDialog::Accepted && selectedFiles().length() > 0) {
        cf_print_status_t status;
        QString file_name = selectedFiles()[0];

        /* Fill in our print (and export) args */

        print_args_.file                = qstring_strdup(file_name);
        print_args_.format              = PR_FMT_TEXT;
        print_args_.to_file             = TRUE;
        print_args_.cmd                 = NULL;
        print_args_.print_summary       = TRUE;
        print_args_.print_dissections   = print_dissections_as_displayed;
        print_args_.print_hex           = FALSE;
        print_args_.print_formfeed      = FALSE;

        switch (export_type_) {
        case export_type_text:      /* Text */
            print_args_.print_summary = packet_format_group_box_.summaryEnabled();
            print_args_.print_dissections = print_dissections_none;
            if (packet_format_group_box_.detailsEnabled()) {
                if (packet_format_group_box_.allCollapsedEnabled())
                    print_args_.print_dissections = print_dissections_collapsed;
                else if (packet_format_group_box_.asDisplayedEnabled())
                    print_args_.print_dissections = print_dissections_as_displayed;
                else if (packet_format_group_box_.allExpandedEnabled())
                    print_args_.print_dissections = print_dissections_expanded;
            }
            print_args_.print_hex = packet_format_group_box_.bytesEnabled();
            print_args_.stream = print_stream_text_new(TRUE, print_args_.file);
            if (print_args_.stream == NULL) {
                open_failure_alert_box(print_args_.file, errno, TRUE);
                return QDialog::Rejected;
            }
            status = cf_print_packets(cap_file_, &print_args_, TRUE);
            break;
        case export_type_csv:       /* CSV */
            status = cf_write_csv_packets(cap_file_, &print_args_);
            break;
        case export_type_carrays:   /* C Arrays */
            status = cf_write_carrays_packets(cap_file_, &print_args_);
            break;
        case export_type_psml:      /* PSML */
            status = cf_write_psml_packets(cap_file_, &print_args_);
            break;
        case export_type_pdml:      /* PDML */
            status = cf_write_pdml_packets(cap_file_, &print_args_);
            break;
        case export_type_json:      /* JSON */
            status = cf_write_json_packets(cap_file_, &print_args_);
            break;
        default:
            return QDialog::Rejected;
        }

        switch (status) {
            case CF_PRINT_OK:
                break;
            case CF_PRINT_OPEN_ERROR:
                open_failure_alert_box(print_args_.file, errno, TRUE);
                break;
            case CF_PRINT_WRITE_ERROR:
                write_failure_alert_box(print_args_.file, errno);
                break;
        }

        if (selectedFiles().length() > 0) {
            gchar *dirname;
            /* Save the directory name for future file dialogs. */
            dirname = get_dirname(print_args_.file);  /* Overwrites file_name data */
            set_last_open_dir(dirname);
        }
    }

    return retval;
#else // Q_OS_WIN
    win32_export_file((HWND)parentWidget()->effectiveWinId(), cap_file_, export_type_);
    return QDialog::Accepted;
#endif // Q_OS_WIN
}

#ifndef Q_OS_WIN
void ExportDissectionDialog::exportTypeChanged(QString name_filter)
{
    export_type_ = export_type_map_.value(name_filter);
    if (export_type_ == export_type_text) {
        packet_format_group_box_.setEnabled(true);
        print_args_.format = PR_FMT_TEXT;
    } else {
        packet_format_group_box_.setEnabled(false);
    }

    checkValidity();
}

void ExportDissectionDialog::checkValidity()
{
    bool enable = true;

    if (!save_bt_) return;

    if (!packet_range_group_box_.isValid()) enable = false;

    if (export_type_ == export_type_text) {
        if (! packet_format_group_box_.summaryEnabled() &&
            ! packet_format_group_box_.detailsEnabled() &&
            ! packet_format_group_box_.bytesEnabled())
        {
            enable = false;
        }
    }

    save_bt_->setEnabled(enable);
}

void ExportDissectionDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_EXPORT_FILE_DIALOG);
}
#endif // Q_OS_WIN

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
