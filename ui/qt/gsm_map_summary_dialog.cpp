/* gsm_map_summary_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#include "gsm_map_summary_dialog.h"
#include <ui_gsm_map_summary_dialog.h>

#include "config.h"

#include <glib.h>

#include "globals.h"
#include "summary.h"

#include <epan/packet.h>
#include <epan/tap.h>
#include <epan/asn1.h>
#include <epan/dissectors/packet-gsm_map.h>

#include "ui/capture_globals.h"
#include "ui/simple_dialog.h"

#include "qt_ui_utils.h"
#include "wireshark_application.h"

#include <QTextStream>

/** Gsm map statistic data */
typedef struct _gsm_map_stat_t {
    int                 opr_code[GSM_MAP_MAX_NUM_OPR_CODES];
    int                 size[GSM_MAP_MAX_NUM_OPR_CODES];
    int                 opr_code_rr[GSM_MAP_MAX_NUM_OPR_CODES];
    int                 size_rr[GSM_MAP_MAX_NUM_OPR_CODES];
} gsm_map_stat_t;

gsm_map_stat_t gsm_map_stat;

GsmMapSummaryDialog::GsmMapSummaryDialog(QWidget &parent, CaptureFile &capture_file) :
    WiresharkDialog(parent, capture_file),
    ui(new Ui::GsmMapSummaryDialog)
{
    ui->setupUi(this);

    setWindowSubtitle(tr("GSM MAP Summary"));
    updateWidgets();
}

GsmMapSummaryDialog::~GsmMapSummaryDialog()
{
    delete ui;
}

// Copied from capture_file_properties_dialog.cpp
QString GsmMapSummaryDialog::summaryToHtml()
{
    summary_tally summary;
    memset(&summary, 0, sizeof(summary_tally));

    QString section_tmpl;
    QString table_begin, table_end;
    QString table_row_begin, table_ul_row_begin, table_row_end;
    QString table_vheader_tmpl;
    QString table_data_tmpl;

    section_tmpl = "<p><strong>%1</strong></p>\n";
    table_begin = "<p><table>\n";
    table_end = "</table></p>\n";
    table_row_begin = "<tr>\n";
    table_ul_row_begin = "<tr style=\"border-bottom: 1px solid gray;\">\n";
    table_row_end = "</tr>\n";
    table_vheader_tmpl = "<td width=\"50%\">%1:</td>"; // <th align="left"> looked odd
    table_data_tmpl = "<td>%1</td>";

    if (cap_file_.isValid()) {
        /* initial computations */
        summary_fill_in(cap_file_.capFile(), &summary);
#ifdef HAVE_LIBPCAP
        summary_fill_in_capture(cap_file_.capFile(), &global_capture_opts, &summary);
#endif
    }

    QString summary_str;
    QTextStream out(&summary_str);

    // File Section
    out << section_tmpl.arg(tr("File"));
    out << table_begin;

    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Name"))
        << table_data_tmpl.arg(summary.filename)
        << table_row_end;

    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Length"))
        << table_data_tmpl.arg(file_size_to_qstring(summary.file_length))
        << table_row_end;

    QString format_str = wtap_file_type_subtype_string(summary.file_type);
    if (summary.iscompressed) {
        format_str.append(tr(" (gzip compressed)"));
    }
    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Format"))
        << table_data_tmpl.arg(format_str)
        << table_row_end;

    if (summary.has_snap) {
        out << table_row_begin
            << table_vheader_tmpl.arg(tr("Snapshot length"))
            << table_data_tmpl.arg(summary.snap)
            << table_row_end;
    }

    out << table_end;

    // Data Section
    out << section_tmpl.arg(tr("Data"));
    out << table_begin;

    if (summary.packet_count_ts == summary.packet_count &&
            summary.packet_count >= 1)
    {
        // start time
        out << table_row_begin
            << table_vheader_tmpl.arg(tr("First packet"))
            << table_data_tmpl.arg(time_t_to_qstring((time_t)summary.start_time))
            << table_row_end;

        // stop time
        out << table_row_begin
            << table_vheader_tmpl.arg(tr("Last packet"))
            << table_data_tmpl.arg(time_t_to_qstring((time_t)summary.stop_time))
            << table_row_end;

        // elapsed seconds (capture duration)
        if (summary.packet_count_ts > 1)
        {
            /* elapsed seconds */
            QString elapsed_str;
            unsigned int elapsed_time = (unsigned int)summary.elapsed_time;
            if (elapsed_time/86400)
            {
                elapsed_str = QString("%1 days ").arg(elapsed_time / 86400);
            }

            elapsed_str += QString("%1:%2:%3")
                    .arg(elapsed_time % 86400 / 3600, 2, 10, QChar('0'))
                    .arg(elapsed_time % 3600 / 60, 2, 10, QChar('0'))
                    .arg(elapsed_time % 60, 2, 10, QChar('0'));
            out << table_row_begin
                << table_vheader_tmpl.arg(tr("Elapsed"))
                << table_data_tmpl.arg(elapsed_str)
                << table_row_end;
        }
    }

    // count
    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Packets"))
        << table_data_tmpl.arg(summary.packet_count)
        << table_row_end;

    out << table_end;

    // TRANSLATOR Abbreviation for "not applicable"
    QString n_a = tr("N/A");
    QString invoke_rate_str, result_rate_str, total_rate_str;
    QString invoke_avg_size_str, result_avg_size_str, total_avg_size_str;

    // Message averages
    invoke_rate_str = result_rate_str = total_rate_str = n_a;
    invoke_avg_size_str = result_avg_size_str = total_avg_size_str = n_a;

    double seconds = summary.stop_time - summary.start_time;
    int invoke_count = 0, invoke_bytes = 0;
    int result_count = 0, result_bytes = 0;

    for (int i = 0; i < GSM_MAP_MAX_NUM_OPR_CODES; i++) {
        invoke_count += gsm_map_stat.opr_code[i];
        invoke_bytes += gsm_map_stat.size[i];
    }


    for (int i = 0; i < GSM_MAP_MAX_NUM_OPR_CODES; i++) {
        result_count += gsm_map_stat.opr_code_rr[i];
        result_bytes += gsm_map_stat.size_rr[i];
    }

    int total_count = invoke_count + result_count;
    int total_bytes = invoke_bytes + result_bytes;

    /*
     * We must have no un-time-stamped packets (i.e., the number of
     * time-stamped packets must be the same as the number of packets),
     * and at least two time-stamped packets, in order for the elapsed
     * time to be valid.
     */
    if (summary.packet_count_ts > 1 && seconds > 0.0) {
        /* Total number of invokes per second */
        invoke_rate_str = QString("%1").arg(invoke_count / seconds, 1, 'f', 1);
        result_rate_str = QString("%1").arg(result_count / seconds, 1, 'f', 1);
        total_rate_str = QString("%1").arg((total_count) / seconds, 1, 'f', 1);
    }

    /* Average message sizes */
    if (invoke_count > 0) {
        invoke_avg_size_str = QString("%1").arg((double) invoke_bytes / invoke_count, 1, 'f', 1);
    }
    if (result_count > 0) {
        result_avg_size_str = QString("%1").arg((double) result_bytes / result_count, 1, 'f', 1);
    }
    if (total_count > 0) {
        total_avg_size_str = QString("%1").arg((double) total_bytes / total_count, 1, 'f', 1);
    }

    // Invoke Section
    out << section_tmpl.arg(tr("Invokes"));
    out << table_begin;

    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Total number of Invokes"))
        << table_data_tmpl.arg(invoke_count)
        << table_row_end;

    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Average number of Invokes per second"))
        << table_data_tmpl.arg(invoke_rate_str)
        << table_row_end;

    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Total number of bytes for Invokes"))
        << table_data_tmpl.arg(invoke_bytes)
        << table_row_end;

    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Average number of bytes per Invoke"))
        << table_data_tmpl.arg(invoke_avg_size_str)
        << table_row_end;

    out << table_end;

    // Return Result Section
    out << section_tmpl.arg(tr("Return Results"));
    out << table_begin;

    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Total number of Return Results"))
        << table_data_tmpl.arg(result_count)
        << table_row_end;

    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Average number of Return Results per second"))
        << table_data_tmpl.arg(result_rate_str)
        << table_row_end;

    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Total number of bytes for Return Results"))
        << table_data_tmpl.arg(result_bytes)
        << table_row_end;

    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Average number of bytes per Return Result"))
        << table_data_tmpl.arg(result_avg_size_str)
        << table_row_end;

    out << table_end;

    // Total Section
    out << section_tmpl.arg(tr("Totals"));
    out << table_begin;

    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Total number of GSM MAP messages"))
        << table_data_tmpl.arg(total_count)
        << table_row_end;

    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Average number of GSM MAP messages per second"))
        << table_data_tmpl.arg(total_rate_str)
        << table_row_end;

    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Total number of bytes for GSM MAP messages"))
        << table_data_tmpl.arg(total_bytes)
        << table_row_end;

    out << table_row_begin
        << table_vheader_tmpl.arg(tr("Average number of bytes per GSM MAP message"))
        << table_data_tmpl.arg(total_avg_size_str)
        << table_row_end;

    out << table_end;

    return summary_str;
}

void GsmMapSummaryDialog::updateWidgets()
{
//    QPushButton *refresh_bt = ui->buttonBox->button(QDialogButtonBox::Reset);
//    QPushButton *save_bt = ui->buttonBox->button(QDialogButtonBox::Save);

//    if (file_closed_) {
//        if (refresh_bt) {
//            refresh_bt->setEnabled(false);
//        }
//        ui->commentsTextEdit->setReadOnly(true);
//        if (save_bt) {
//            save_bt->setEnabled(false);
//        }
//        return;
//    }

    ui->summaryTextEdit->setHtml(summaryToHtml());

    WiresharkDialog::updateWidgets();
}

extern "C" {

static void
gsm_map_summary_reset(void *tapdata)
{
    gsm_map_stat_t *gm_stat = (gsm_map_stat_t *)tapdata;

    memset(gm_stat, 0, sizeof(gsm_map_stat_t));
}


static gboolean
gsm_map_summary_packet(void *tapdata, packet_info *, epan_dissect_t *, const void *gmtr_ptr)
{
    gsm_map_stat_t *gm_stat = (gsm_map_stat_t *)tapdata;
    const gsm_map_tap_rec_t *gm_tap_rec = (const gsm_map_tap_rec_t *)gmtr_ptr;

    if (gm_tap_rec->invoke)
    {
        gm_stat->opr_code[gm_tap_rec->opcode]++;
        gm_stat->size[gm_tap_rec->opcode] += gm_tap_rec->size;
    }
    else
    {
        gm_stat->opr_code_rr[gm_tap_rec->opcode]++;
        gm_stat->size_rr[gm_tap_rec->opcode] += gm_tap_rec->size;
    }

    return(FALSE); /* We have no draw callback */
}

void
register_tap_listener_qt_gsm_map_summary(void)
{
    GString     *err_p;

    memset((void *) &gsm_map_stat, 0, sizeof(gsm_map_stat_t));

    err_p =
    register_tap_listener("gsm_map", &gsm_map_stat, NULL, 0,
        gsm_map_summary_reset,
        gsm_map_summary_packet,
        NULL);

    if (err_p != NULL)
    {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err_p->str);
        g_string_free(err_p, TRUE);

        exit(1);
    }
}

} // extern "C"

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
