/* export_dissection_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "export_dissection_dialog.h"

#include "ui/alert_box.h"
#include "ui/help_url.h"
#include "ui/util.h"

#include <epan/print.h>
#include <wsutil/filesystem.h>

#include <ui/qt/utils/qt_ui_utils.h>


#include <QDialogButtonBox>
#include <QGridLayout>
#include <QPushButton>

#include "main_application.h"

static const QStringList export_extensions = QStringList()
    << ""
    << "txt"
    << ""
    << "csv"
    << "psml"
    << "pdml"
    << "c"
    << "json";

ExportDissectionDialog::ExportDissectionDialog(QWidget *parent, capture_file *cap_file, export_type_e export_type, QString selRange):
    WiresharkFileDialog(parent),
    export_type_(export_type),
    cap_file_(cap_file)
    , save_bt_(NULL)
{
    setWindowTitle(mainApp->windowTitleString(tr("Export Packet Dissections")));

    setDirectory(mainApp->openDialogInitialDir());

    setOption(QFileDialog::DontUseNativeDialog, true);
    QDialogButtonBox *button_box = findChild<QDialogButtonBox *>();
    QGridLayout *fd_grid = qobject_cast<QGridLayout*>(layout());
    QHBoxLayout *h_box = new QHBoxLayout();
    QStringList name_filters;
    int last_row;

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
    print_args_.range.process_filtered = true;

    packet_range_group_box_.initRange(&print_args_.range, selRange);
    h_box->addWidget(&packet_range_group_box_);

    h_box->addWidget(&packet_format_group_box_, 0, Qt::AlignTop);

    if (button_box) {
        button_box->addButton(QDialogButtonBox::Help);
        connect(button_box, &QDialogButtonBox::helpRequested, this, &ExportDissectionDialog::on_buttonBox_helpRequested);

        save_bt_ = button_box->button(QDialogButtonBox::Save);
    }

    if (save_bt_) {
        connect(&packet_range_group_box_, &PacketRangeGroupBox::validityChanged,
                this, &ExportDissectionDialog::checkValidity);
        connect(&packet_format_group_box_, &PacketFormatGroupBox::formatChanged,
                this, &ExportDissectionDialog::checkValidity);
        save_bt_->installEventFilter(this);
    }
    connect(this, &ExportDissectionDialog::filterSelected, this, &ExportDissectionDialog::exportTypeChanged);

    // Grow the dialog to account for the extra widgets.
    resize(width(), height() + (packet_range_group_box_.height() * 2 / 3));

    connect(this, &ExportDissectionDialog::filesSelected, this, &ExportDissectionDialog::dialogAccepted);
}

ExportDissectionDialog::~ExportDissectionDialog()
{
    g_free(print_args_.file);
    packet_range_cleanup(&print_args_.range);
}

void ExportDissectionDialog::show()
{
    if (cap_file_) {
        WiresharkFileDialog::show();
    }
}

void ExportDissectionDialog::dialogAccepted(const QStringList &selected)
{
    if (selected.length() > 0) {
        /* writing might take a while, so hide ourselves so the user
         * can't click on anything here (this dialog will be closed
         * and deleted once this function is done), but can access
         * the ProgressDialog in the main window to cancel the export.
         */
        hide();
        cf_print_status_t status;
        QString file_name = QDir::toNativeSeparators(selected[0]);

        /* Fill in our print (and export) args */

        print_args_.file                = qstring_strdup(file_name);
        print_args_.format              = PR_FMT_TEXT;
        print_args_.to_file             = true;
        print_args_.cmd                 = NULL;
        print_args_.print_summary       = true;
        print_args_.print_col_headings  = true;
        print_args_.print_dissections   = print_dissections_as_displayed;
        print_args_.print_hex           = false;
        print_args_.print_formfeed      = false;

        switch (export_type_) {
        case export_type_text:      /* Text */
            print_args_.print_summary = packet_format_group_box_.summaryEnabled();
            print_args_.print_col_headings = packet_format_group_box_.includeColumnHeadingsEnabled();
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
            print_args_.hexdump_options = packet_format_group_box_.getHexdumpOptions();
            print_args_.stream = print_stream_text_new(true, print_args_.file);
            if (print_args_.stream == NULL) {
                open_failure_alert_box(print_args_.file, errno, true);
                return;
            }
            status = cf_print_packets(cap_file_, &print_args_, true);
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
            return;
        }

        switch (status) {
            case CF_PRINT_OK:
                break;
            case CF_PRINT_OPEN_ERROR:
                open_failure_alert_box(print_args_.file, errno, true);
                break;
            case CF_PRINT_WRITE_ERROR:
                write_failure_alert_box(print_args_.file, errno);
                break;
        }

        char *dirname;
        /* Save the directory name for future file dialogs. */
        dirname = get_dirname(print_args_.file);  /* Overwrites file_name data */
        set_last_open_dir(dirname);
    }
}

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
    setDefaultSuffix(export_extensions[export_type_]);
}

bool ExportDissectionDialog::isValid()
{
    bool valid = true;

    if (!packet_range_group_box_.isValid()) valid = false;

    if (export_type_ == export_type_text) {
        if (! packet_format_group_box_.summaryEnabled() &&
            ! packet_format_group_box_.detailsEnabled() &&
            ! packet_format_group_box_.bytesEnabled())
        {
            valid = false;
        }
    }

    return valid;
}

void ExportDissectionDialog::checkValidity()
{
    if (!save_bt_) return;

    save_bt_->setEnabled(isValid());
}

void ExportDissectionDialog::on_buttonBox_helpRequested()
{
    mainApp->helpTopicAction(HELP_EXPORT_FILE_DIALOG);
}

bool ExportDissectionDialog::eventFilter(QObject *obj, QEvent *event)
{
    // The QFileDialogPrivate will enable the Ok (Open/Save) button when
    // anything is typed or selected. We can't catch that beforehand, so
    // watch for the enable status change and re-disable it if the
    // group boxes are invalid.
    // We could do extra work (here and elsewhere) not to disable the button
    // if what's selected in the dialog is a directory, but even with save_bt_
    // disabled clicking on the directory still opens it.
    if (event->type() == QEvent::EnabledChange) {
        QPushButton *button = qobject_cast<QPushButton *>(obj);
        if (button && button == save_bt_) {
            // The button is already changed by the time we get this event.
            if (button->isEnabled() && !isValid()) {
                button->setEnabled(false);
                return true;
            }
        }
    }

    return QObject::eventFilter(obj, event);
}
