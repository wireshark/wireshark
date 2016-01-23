/* sctp_chunk_statistics_dialog.cpp
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

#include "sctp_chunk_statistics_dialog.h"
#include <ui_sctp_chunk_statistics_dialog.h>
#include "uat_dialog.h"

#include <string>


SCTPChunkStatisticsDialog::SCTPChunkStatisticsDialog(QWidget *parent, sctp_assoc_info_t *assoc, capture_file *cf) :
    QDialog(parent),
    ui(new Ui::SCTPChunkStatisticsDialog),
    selected_assoc(assoc),
    cap_file_(cf)
{
    ui->setupUi(this);
    Qt::WindowFlags flags = Qt::Window | Qt::WindowSystemMenuHint
            | Qt::WindowMinimizeButtonHint
            | Qt::WindowMaximizeButtonHint
            | Qt::WindowCloseButtonHint;
    this->setWindowFlags(flags);
#if (QT_VERSION < QT_VERSION_CHECK(5, 0, 0))
    ui->tableWidget->verticalHeader()->setClickable(true);
    ui->tableWidget->verticalHeader()->setMovable(true);
#else
    ui->tableWidget->verticalHeader()->setSectionsClickable(true);
    ui->tableWidget->verticalHeader()->setSectionsMovable(true);
#endif


    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);

#if (QT_VERSION < QT_VERSION_CHECK(5, 0, 0))
    ui->tableWidget->horizontalHeader()->setResizeMode(QHeaderView::ResizeToContents);
#else
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
#endif

    this->setWindowTitle(QString(tr("SCTP Chunk Statistics: %1 Port1 %2 Port2 %3")).arg(cf_get_display_name(cap_file_)).arg(selected_assoc->port1).arg(selected_assoc->port2));
 //   connect(ui->tableWidget->verticalHeader(), SIGNAL(sectionMoved(int,int,int)), this, SLOT(on_sectionMoved(int, int, int)));

    ctx_menu_.addAction(ui->actionHideChunkType);
    ctx_menu_.addAction(ui->actionChunkTypePreferences);
    ctx_menu_.addAction(ui->actionShowAllChunkTypes);
    initializeChunkMap();
    fillTable();
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
        g_snprintf(buf, sizeof buf, "%d", i);
        g_strlcpy(temp.name, val_to_str_const(i, chunk_type_values, "NA"), sizeof temp.name);
        if (strcmp(temp.name, "NA") == 0) {
            temp.hide = 1;
            g_strlcpy(temp.name, buf, sizeof temp.name);
        } else {
            temp.hide = 0;
        }
        chunks.insert(i, temp);
    }
}

void SCTPChunkStatisticsDialog::fillTable(bool all)
{
    FILE* fp = NULL;

    pref_t *pref = prefs_find_preference(prefs_find_module("sctp"),"statistics_chunk_types");
    uat_t *uat = pref->varp.uat;
    gchar* fname = uat_get_actual_filename(uat,TRUE);
    bool init = false;

    if (!fname) {
        init = true;
    } else {
        fp = ws_fopen(fname,"r");

        if (!fp && errno == ENOENT) {
            init = true;
        }
    }
    g_free (fname);

    if (init || all) {
        int j = 0;

        for (int i = 0; i < chunks.size(); i++) {
            if (!chunks.value(i).hide) {
                ui->tableWidget->setRowCount(ui->tableWidget->rowCount()+1);
                ui->tableWidget->setVerticalHeaderItem(j, new QTableWidgetItem(QString("%1").arg(chunks.value(i).name)));
                ui->tableWidget->setItem(j,0, new QTableWidgetItem(QString("%1").arg(selected_assoc->chunk_count[chunks.value(i).id])));
                ui->tableWidget->setItem(j,1, new QTableWidgetItem(QString("%1").arg(selected_assoc->ep1_chunk_count[chunks.value(i).id])));
                ui->tableWidget->setItem(j,2, new QTableWidgetItem(QString("%1").arg(selected_assoc->ep2_chunk_count[chunks.value(i).id])));
                j++;
            }
        }
        for (int i = 0; i < chunks.size(); i++) {
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
            /* Get rid of the quotation marks */
            QString ch = QString(token).mid(1, (int)strlen(token)-2);
            g_strlcpy(id, qPrintable(ch), sizeof id);
            temp.id = atoi(id);
            temp.hide = 0;
            temp.name[0] = '\0';
            while(token != NULL) {
                token = strtok(NULL, ",");
                if (token) {
                    if ((strstr(token, "Hide"))) {
                        temp.hide = 1;
                    } else if ((strstr(token, "Show"))) {
                        temp.hide = 0;
                    } else {
                        QString ch = QString(token).mid(1, (int)strlen(token)-2);
                        g_strlcpy(temp.name, qPrintable(ch), sizeof temp.name);
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
        for (int i = 0; i < chunks.size(); i++) {
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
        ctx_menu_.exec(event->globalPos());
    }
}



void SCTPChunkStatisticsDialog::on_pushButton_clicked()
{
    FILE* fp;

    pref_t *pref = prefs_find_preference(prefs_find_module("sctp"),"statistics_chunk_types");

    uat_t *uat = pref->varp.uat;

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
        g_snprintf(str, sizeof str, "\"%d\",\"%s\",\"%s\"\n", tempChunk.id, tempChunk.name, tempChunk.hide==0?"Show":"Hide");
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

    QTableWidgetItem *item = ui->tableWidget->itemAt(selected_point.x(), selected_point.y()-60);
    if (item) {
        row = item->row();
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
    uat_t *uat = pref->varp.uat;
    uat_clear(uat);

    if (!uat_load(pref->varp.uat, &err)) {
        /* XXX - report this through the GUI */
        printf("Error loading table '%s': %s",pref->varp.uat->name,err);
        g_free(err);
    }

    UatDialog *uatdialog = new UatDialog(this, pref->varp.uat);
    uatdialog->exec();
    // Emitting PacketDissectionChanged directly from a QDialog can cause
    // problems on OS X.
    wsApp->flushAppSignals();

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
