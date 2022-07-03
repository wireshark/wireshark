/* sctp_chunk_statistics_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "sctp_chunk_statistics_dialog.h"
#include "sctp_assoc_analyse_dialog.h"
#include <ui_sctp_chunk_statistics_dialog.h>
#include "uat_dialog.h"

#include <wsutil/strtoi.h>
#include <wsutil/wslog.h>

#include "ui/tap-sctp-analysis.h"
#include <ui/qt/utils/qt_ui_utils.h>

SCTPChunkStatisticsDialog::SCTPChunkStatisticsDialog(QWidget *parent, const sctp_assoc_info_t *assoc,
        capture_file *cf) :
    QDialog(parent),
    ui(new Ui::SCTPChunkStatisticsDialog),
    cap_file_(cf)
{
    Q_ASSERT(assoc);
    selected_assoc_id = assoc->assoc_id;

    ui->setupUi(this);
    Qt::WindowFlags flags = Qt::Window | Qt::WindowSystemMenuHint
            | Qt::WindowMinimizeButtonHint
            | Qt::WindowMaximizeButtonHint
            | Qt::WindowCloseButtonHint;
    this->setWindowFlags(flags);
    ui->tableWidget->verticalHeader()->setSectionsClickable(true);
    ui->tableWidget->verticalHeader()->setSectionsMovable(true);


    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);

    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);

    this->setWindowTitle(QString(tr("SCTP Chunk Statistics: %1 Port1 %2 Port2 %3"))
            .arg(gchar_free_to_qstring(cf_get_display_name(cap_file_)))
            .arg(assoc->port1).arg(assoc->port2));
//    connect(ui->tableWidget->verticalHeader(), &QHeaderView::sectionMoved, this, &SCTPChunkStatisticsDialog::on_sectionMoved);

    ctx_menu_.addAction(ui->actionHideChunkType);
    ctx_menu_.addAction(ui->actionChunkTypePreferences);
    ctx_menu_.addAction(ui->actionShowAllChunkTypes);
    initializeChunkMap();
    fillTable(false, assoc);
}

SCTPChunkStatisticsDialog::~SCTPChunkStatisticsDialog()
{
    delete ui;
}

void SCTPChunkStatisticsDialog::initializeChunkMap()
{
    struct chunkTypes temp;
    gchar buf[16];

    for (int i = 0; i < 256; i++) {
        temp.id = i;
        temp.row = i;
        snprintf(buf, sizeof buf, "%d", i);
        (void) g_strlcpy(temp.name, val_to_str_const(i, chunk_type_values, "NA"), sizeof temp.name);
        if (strcmp(temp.name, "NA") == 0) {
            temp.hide = 1;
            (void) g_strlcpy(temp.name, buf, sizeof temp.name);
        } else {
            temp.hide = 0;
        }
        chunks.insert(i, temp);
    }
}

void SCTPChunkStatisticsDialog::fillTable(bool all, const sctp_assoc_info_t *selected_assoc)
{
    if (!selected_assoc) {
        selected_assoc = SCTPAssocAnalyseDialog::findAssoc(this, selected_assoc_id);
        if (!selected_assoc) return;
    }

    FILE* fp = NULL;

    pref_t *pref = prefs_find_preference(prefs_find_module("sctp"),"statistics_chunk_types");
    if (!pref) {
        ws_log(LOG_DOMAIN_QTUI, LOG_LEVEL_ERROR, "Can't find preference sctp/statistics_chunk_types");
        return;
    }
    uat_t *uat = prefs_get_uat_value(pref);
    gchar* fname = uat_get_actual_filename(uat,TRUE);
    bool init = false;

    if (!fname) {
        init = true;
    } else {
        fp = ws_fopen(fname,"r");

        if (!fp) {
            if (errno == ENOENT) {
                init = true;
            } else {
                ws_log(LOG_DOMAIN_QTUI, LOG_LEVEL_ERROR, "Can't open %s: %s", fname, g_strerror(errno));
                return;
            }
        }
    }
    g_free (fname);

    if (init || all) {
        int i, j = 0;

        for (i = 0; i < chunks.size(); i++) {
            if (!chunks.value(i).hide) {
                ui->tableWidget->setRowCount(ui->tableWidget->rowCount()+1);
                ui->tableWidget->setVerticalHeaderItem(j, new QTableWidgetItem(QString("%1").arg(chunks.value(i).name)));
                ui->tableWidget->setItem(j,0, new QTableWidgetItem(QString("%1").arg(selected_assoc->chunk_count[chunks.value(i).id])));
                ui->tableWidget->setItem(j,1, new QTableWidgetItem(QString("%1").arg(selected_assoc->ep1_chunk_count[chunks.value(i).id])));
                ui->tableWidget->setItem(j,2, new QTableWidgetItem(QString("%1").arg(selected_assoc->ep2_chunk_count[chunks.value(i).id])));
                j++;
            }
        }
        for (i = 0; i < chunks.size(); i++) {
            if (chunks.value(i).hide) {
                ui->tableWidget->setRowCount(ui->tableWidget->rowCount()+1);
                ui->tableWidget->setVerticalHeaderItem(j, new QTableWidgetItem(QString("%1").arg(chunks.value(i).name)));
                ui->tableWidget->setItem(j,0, new QTableWidgetItem(QString("%1").arg(selected_assoc->chunk_count[chunks.value(i).id])));
                ui->tableWidget->setItem(j,1, new QTableWidgetItem(QString("%1").arg(selected_assoc->ep1_chunk_count[chunks.value(i).id])));
                ui->tableWidget->setItem(j,2, new QTableWidgetItem(QString("%1").arg(selected_assoc->ep2_chunk_count[chunks.value(i).id])));
                ui->tableWidget->hideRow(j);
                j++;
            }
        }
    } else {
        char line[100];
        char *token, id[5];
        int i = 0, j = 0;
        struct chunkTypes temp;

        while (fgets(line, (int)sizeof line, fp)) {
            if (line[0] == '#')
                continue;
            token = strtok(line, ",");
            if (!token)
                continue;
            /* Get rid of the quotation marks */
            QString ch = QString(token).mid(1, (int)strlen(token)-2);
            (void) g_strlcpy(id, qPrintable(ch), sizeof id);
            if (!ws_strtoi32(id, NULL, &temp.id))
                continue;
            temp.hide = 0;
            temp.name[0] = '\0';
            while (token != NULL) {
                token = strtok(NULL, ",");
                if (token) {
                    if ((strstr(token, "Hide"))) {
                        temp.hide = 1;
                    } else if ((strstr(token, "Show"))) {
                        temp.hide = 0;
                    } else {
                        QString ch2 = QString(token).mid(1, (int)strlen(token)-2);
                        (void) g_strlcpy(temp.name, qPrintable(ch2), sizeof temp.name);
                    }
                }
            }
            if (!temp.hide) {
                ui->tableWidget->setRowCount(ui->tableWidget->rowCount()+1);
                ui->tableWidget->setVerticalHeaderItem(j, new QTableWidgetItem(QString("%1").arg(temp.name)));
                ui->tableWidget->setItem(j,0, new QTableWidgetItem(QString("%1").arg(selected_assoc->chunk_count[temp.id])));
                ui->tableWidget->setItem(j,1, new QTableWidgetItem(QString("%1").arg(selected_assoc->ep1_chunk_count[temp.id])));
                ui->tableWidget->setItem(j,2, new QTableWidgetItem(QString("%1").arg(selected_assoc->ep2_chunk_count[temp.id])));
                j++;
            }
            chunks.insert(i, temp);
            i++;
        }
        j = ui->tableWidget->rowCount();
        for (i = 0; i < chunks.size(); i++) {
            if (chunks.value(i).hide) {
                ui->tableWidget->setRowCount(ui->tableWidget->rowCount()+1);
                ui->tableWidget->setVerticalHeaderItem(j, new QTableWidgetItem(QString("%1").arg(chunks.value(i).name)));
                ui->tableWidget->setItem(j,0, new QTableWidgetItem(QString("%1").arg(selected_assoc->chunk_count[chunks.value(i).id])));
                ui->tableWidget->setItem(j,1, new QTableWidgetItem(QString("%1").arg(selected_assoc->ep1_chunk_count[chunks.value(i).id])));
                ui->tableWidget->setItem(j,2, new QTableWidgetItem(QString("%1").arg(selected_assoc->ep2_chunk_count[chunks.value(i).id])));
                ui->tableWidget->hideRow(j);
                j++;
            }
        }
    }
    if (fp)
        fclose(fp);
}

void SCTPChunkStatisticsDialog::contextMenuEvent(QContextMenuEvent * event)
{
    selected_point = event->pos();
    QTableWidgetItem *item = ui->tableWidget->itemAt(selected_point.x(), selected_point.y()-60);
    if (item) {
        ctx_menu_.popup(event->globalPos());
    }
}



void SCTPChunkStatisticsDialog::on_pushButton_clicked()
{
    FILE* fp;

    pref_t *pref = prefs_find_preference(prefs_find_module("sctp"),"statistics_chunk_types");
    if (!pref) {
        ws_log(LOG_DOMAIN_QTUI, LOG_LEVEL_ERROR, "Can't find preference sctp/statistics_chunk_types");
        return;
    }

    uat_t *uat = prefs_get_uat_value(pref);

    gchar* fname = uat_get_actual_filename(uat,TRUE);

    if (!fname) {
        return;
    }
    fp = ws_fopen(fname,"w");

    if (!fp && errno == ENOENT) {
        gchar *pf_dir_path = NULL;
        if (create_persconffile_dir(&pf_dir_path) != 0) {
            g_free (pf_dir_path);
            return;
        }
        fp = ws_fopen(fname,"w");
    }

    if (!fp) {
        return;
    }

    g_free (fname);

    fprintf(fp,"# This file is automatically generated, DO NOT MODIFY.\n");
    char str[40];
    struct chunkTypes tempChunk;

    for (int i = 0; i < chunks.size(); i++) {
        tempChunk = chunks.value(i);
        snprintf(str, sizeof str, "\"%d\",\"%s\",\"%s\"\n", tempChunk.id, tempChunk.name, tempChunk.hide==0?"Show":"Hide");
        fputs(str, fp);
        void *rec = g_malloc0(uat->record_size);
        uat_add_record(uat, rec, TRUE);
        if (uat->free_cb) {
            uat->free_cb(rec);
        }
        g_free(rec);
    }

    fclose(fp);
}

/*void SCTPChunkStatisticsDialog::on_sectionMoved(int logicalIndex, int oldVisualIndex, int newVisualIndex)
{
}*/

void SCTPChunkStatisticsDialog::on_actionHideChunkType_triggered()
{
    int row;

    QTableWidgetItem *itemPoint = ui->tableWidget->itemAt(selected_point.x(), selected_point.y()-60);
    if (itemPoint) {
        row = itemPoint->row();
        ui->tableWidget->hideRow(row);
        QTableWidgetItem *item = ui->tableWidget->verticalHeaderItem(row);
        QMap<int, struct chunkTypes>::iterator iter;
        for (iter = chunks.begin(); iter != chunks.end(); ++iter) {
            if (strcmp(iter.value().name, item->text().toUtf8().constData()) == 0) {
                iter.value().hide = true;
                break;
            }
        }
    }

}

void SCTPChunkStatisticsDialog::on_actionChunkTypePreferences_triggered()
{
    gchar* err = NULL;

    pref_t *pref = prefs_find_preference(prefs_find_module("sctp"),"statistics_chunk_types");
    if (!pref) {
        ws_log(LOG_DOMAIN_QTUI, LOG_LEVEL_ERROR, "Can't find preference sctp/statistics_chunk_types");
        return;
    }

    uat_t *uat = prefs_get_uat_value(pref);
    uat_clear(uat);

    if (!uat_load(uat, NULL, &err)) {
        /* XXX - report this through the GUI */
        ws_log(LOG_DOMAIN_QTUI, LOG_LEVEL_WARNING, "Error loading table '%s': %s", uat->name, err);
        g_free(err);
    }

    UatDialog *uatdialog = new UatDialog(this, uat);
    uatdialog->exec();
    // Emitting PacketDissectionChanged directly from a QDialog can cause
    // problems on macOS.
    mainApp->flushAppSignals();

    ui->tableWidget->clear();
    ui->tableWidget->setRowCount(0);
    ui->tableWidget->setHorizontalHeaderItem(0, new QTableWidgetItem(QString(tr("Association"))));
    ui->tableWidget->setHorizontalHeaderItem(1, new QTableWidgetItem(QString(tr("Endpoint 1"))));
    ui->tableWidget->setHorizontalHeaderItem(2, new QTableWidgetItem(QString(tr("Endpoint 2"))));
    fillTable();
}

void SCTPChunkStatisticsDialog::on_actionShowAllChunkTypes_triggered()
{
    ui->tableWidget->clear();
    ui->tableWidget->setRowCount(0);
    ui->tableWidget->setHorizontalHeaderItem(0, new QTableWidgetItem(QString(tr("Association"))));
    ui->tableWidget->setHorizontalHeaderItem(1, new QTableWidgetItem(QString(tr("Endpoint 1"))));
    ui->tableWidget->setHorizontalHeaderItem(2, new QTableWidgetItem(QString(tr("Endpoint 2"))));
    initializeChunkMap();
    fillTable(true);
}
