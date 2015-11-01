/* rpc_service_response_time_dialog.cpp
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

// warning C4267: 'argument' : conversion from 'size_t' to 'int', possible loss of data
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4267)
#endif

#include "rpc_service_response_time_dialog.h"

#include <algorithm>
#include <stdio.h>

#include <epan/dissectors/packet-dcerpc.h>
#include <epan/dissectors/packet-rpc.h>
#include <epan/guid-utils.h>
#include <epan/srt_table.h>

#include "qt_ui_utils.h"

#include <QComboBox>
#include <QHBoxLayout>
#include <QLabel>

#ifdef _MSC_VER
#pragma warning(pop)
#endif

// To do:
// - Don't assume that the user knows what programs+versions are in the
//   capture. I.e. combine this dialog with the ONC-RPC Programs dialog,
//   with two lists: programs on top, procedures on the bottom.
// - Allow the display of multiple programs and versions.
// - Expose the DCE-RPC UUIDs and ONC-RPC program numbers e.g. in an extra
//   column.
// - Make the version in the command-line args optional?

extern "C" {
static void
dce_rpc_add_program(gpointer key_ptr, gpointer value_ptr, gpointer rsrtd_ptr)
{
    RpcServiceResponseTimeDialog *rsrt_dlg = dynamic_cast<RpcServiceResponseTimeDialog *>((RpcServiceResponseTimeDialog *)rsrtd_ptr);
    if (!rsrt_dlg) return;

    guid_key *key = (guid_key *)key_ptr;
    dcerpc_uuid_value *value = (dcerpc_uuid_value *)value_ptr;

    rsrt_dlg->addDceRpcProgram(key, value);
}

static void
dce_rpc_find_versions(gpointer key_ptr, gpointer, gpointer rsrtd_ptr)
{
    RpcServiceResponseTimeDialog *rsrt_dlg = dynamic_cast<RpcServiceResponseTimeDialog *>((RpcServiceResponseTimeDialog *)rsrtd_ptr);
    if (!rsrt_dlg) return;

    guid_key *key = (guid_key *)key_ptr;
    rsrt_dlg->addDceRpcProgramVersion(key);
}

static void
onc_rpc_add_program(gpointer prog_ptr, gpointer value_ptr, gpointer rsrtd_ptr)
{
    RpcServiceResponseTimeDialog *rsrt_dlg = dynamic_cast<RpcServiceResponseTimeDialog *>((RpcServiceResponseTimeDialog *)rsrtd_ptr);
    if (!rsrt_dlg) return;

    guint32 program = GPOINTER_TO_UINT(prog_ptr);
    rpc_prog_info_value *value = (rpc_prog_info_value *) value_ptr;

    rsrt_dlg->addOncRpcProgram(program, value);
}

static void
onc_rpc_find_versions(const gchar *, ftenum_t , gpointer rpik_ptr, gpointer, gpointer rsrtd_ptr)
{
    RpcServiceResponseTimeDialog *rsrt_dlg = dynamic_cast<RpcServiceResponseTimeDialog *>((RpcServiceResponseTimeDialog *)rsrtd_ptr);
    if (!rsrt_dlg) return;

    rpc_proc_info_key *rpik = (rpc_proc_info_key *)rpik_ptr;

    rsrt_dlg->addOncRpcProgramVersion(rpik->prog, rpik->vers);
}

static void
onc_rpc_count_procedures(const gchar *, ftenum_t , gpointer rpik_ptr, gpointer, gpointer rsrtd_ptr)
{
    RpcServiceResponseTimeDialog *rsrt_dlg = dynamic_cast<RpcServiceResponseTimeDialog *>((RpcServiceResponseTimeDialog *)rsrtd_ptr);
    if (!rsrt_dlg) return;

    rpc_proc_info_key *rpik = (rpc_proc_info_key *)rpik_ptr;

    rsrt_dlg->updateOncRpcProcedureCount(rpik->prog, rpik->vers, rpik->proc);
}

} // extern "C"

RpcServiceResponseTimeDialog::RpcServiceResponseTimeDialog(QWidget &parent, CaptureFile &cf, struct register_srt *srt, RpcFamily dlg_type, const QString filter) :
    ServiceResponseTimeDialog(parent, cf, srt, filter),
    dlg_type_(dlg_type)
{
    setRetapOnShow(false);
    setHint(tr("<small><i>Select a program and version and enter a filter if desired, then press Apply.</i></small>"));

    QHBoxLayout *filter_layout = filterLayout();
    program_combo_ = new QComboBox(this);
    version_combo_ = new QComboBox(this);

    filter_layout->insertStretch(0, 1);
    filter_layout->insertWidget(0, version_combo_);
    filter_layout->insertWidget(0, new QLabel(tr("Version:")));
    filter_layout->insertWidget(0, program_combo_);
    filter_layout->insertWidget(0, new QLabel(tr("Program:")));

    if (dlg_type == DceRpc) {
        setWindowSubtitle(tr("DCE-RPC Service Response Times"));
        g_hash_table_foreach(dcerpc_uuids, dce_rpc_add_program, this);
        // This is a loooooong list. The GTK+ UI addresses this by making
        // the program combo a tree instead of a list. We might want to add a
        // full-height list to the left of the stats tree instead.
        QStringList programs = dce_name_to_uuid_key_.keys();
        std::sort(programs.begin(), programs.end(), qStringCaseLessThan);
        connect(program_combo_, SIGNAL(currentIndexChanged(QString)),
                this, SLOT(dceRpcProgramChanged(QString)));
        program_combo_->addItems(programs);
    } else {
        setWindowSubtitle(tr("ONC-RPC Service Response Times"));
        g_hash_table_foreach(rpc_progs, onc_rpc_add_program, this);
        QStringList programs = onc_name_to_program_.keys();
        std::sort(programs.begin(), programs.end(), qStringCaseLessThan);
        connect(program_combo_, SIGNAL(currentIndexChanged(QString)),
                this, SLOT(oncRpcProgramChanged(QString)));
        program_combo_->addItems(programs);
    }
}

TapParameterDialog *RpcServiceResponseTimeDialog::createDceRpcSrtDialog(QWidget &parent, const QString, const QString opt_arg, CaptureFile &cf)
{
    QString filter;
    bool have_args = false;
    QString program_name;
    e_guid_t uuid;
    int version = 0;

    // dcerpc,srt,<uuid>,<major version>.<minor version>[,<filter>]
    QStringList args_l = QString(opt_arg).split(',');
    if (args_l.length() > 1) {
        // Alas, QUuid requires Qt 4.8.
        unsigned d1, d2, d3, d4_0, d4_1, d4_2, d4_3, d4_4, d4_5, d4_6, d4_7;
        if(sscanf(args_l[0].toUtf8().constData(),
                  "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                  &d1, &d2, &d3,
                  &d4_0, &d4_1, &d4_2, &d4_3, &d4_4, &d4_5, &d4_6, &d4_7) == 11) {
                  uuid.data1 = d1;
                  uuid.data2 = d2;
                  uuid.data3 = d3;
                  uuid.data4[0] = d4_0;
                  uuid.data4[1] = d4_1;
                  uuid.data4[2] = d4_2;
                  uuid.data4[3] = d4_3;
                  uuid.data4[4] = d4_4;
                  uuid.data4[5] = d4_5;
                  uuid.data4[6] = d4_6;
                  uuid.data4[7] = d4_7;
        } else {
            program_name = args_l[0];
        }
        version = args_l[1].split('.')[0].toInt();
        if (args_l.length() > 2) {
            filter = QStringList(args_l.mid(2)).join(",");
        }
        have_args = true;
    }
    RpcServiceResponseTimeDialog *dce_rpc_dlg = new RpcServiceResponseTimeDialog(parent, cf, get_srt_table_by_name("dcerpc"), DceRpc, filter);

    if (have_args) {
        if (program_name.isEmpty()) {
            dce_rpc_dlg->setDceRpcUuidAndVersion(&uuid, version);
        } else {
            dce_rpc_dlg->setRpcNameAndVersion(program_name, version);
        }
    }
    // Else the GTK+ UI throws an error.

    return dce_rpc_dlg;
}

TapParameterDialog *RpcServiceResponseTimeDialog::createOncRpcSrtDialog(QWidget &parent, const QString, const QString opt_arg, CaptureFile &cf)
{
    QString filter;
    bool have_args = false;
    QString program_name;
    int program_num = 0;
    int version = 0;

    // rpc,srt,<program>,<version>[,<filter>
    QStringList args_l = QString(opt_arg).split(',');
    if (args_l.length() > 1) {
        bool ok = false;
        program_num = args_l[0].toInt(&ok);
        if (!ok) {
            program_name = args_l[0];
        }
        version = args_l[1].toInt();
        if (args_l.length() > 2) {
            filter = QStringList(args_l.mid(2)).join(",");
        }
        have_args = true;
    }

    RpcServiceResponseTimeDialog *onc_rpc_dlg =  new RpcServiceResponseTimeDialog(parent, cf, get_srt_table_by_name("rpc"), OncRpc, filter);

    if (have_args) {
        if (program_name.isEmpty()) {
            onc_rpc_dlg->setOncRpcProgramAndVersion(program_num, version);
        } else {
            onc_rpc_dlg->setRpcNameAndVersion(program_name, version);
        }
    }
    // Else the GTK+ UI throws an error.

    return onc_rpc_dlg;
}

void RpcServiceResponseTimeDialog::addDceRpcProgram(_guid_key *key, _dcerpc_uuid_value *value)
{
    dce_name_to_uuid_key_.insert(value->name, key);
}

void RpcServiceResponseTimeDialog::addDceRpcProgramVersion(_guid_key *key)
{
    if (guid_cmp(&(dce_name_to_uuid_key_[program_combo_->currentText()]->guid), &(key->guid))) return;

    versions_ << key->ver;
    std::sort(versions_.begin(), versions_.end());
}

void RpcServiceResponseTimeDialog::addOncRpcProgram(guint32 program, _rpc_prog_info_value *value)
{
    onc_name_to_program_.insert(value->progname, program);
}

void RpcServiceResponseTimeDialog::addOncRpcProgramVersion(guint32 program, guint32 version)
{
    if (onc_name_to_program_[program_combo_->currentText()] != program) return;

    if (versions_.isEmpty()) {
        versions_ << version;
        return;
    }
    while (version < versions_.first()) {
        versions_.prepend(versions_.first() - 1);
    }
    while (version > versions_.last()) {
        versions_.append(versions_.last() + 1);
    }
}

void RpcServiceResponseTimeDialog::updateOncRpcProcedureCount(guint32 program, guint32 version, int procedure)
{
    if (onc_name_to_program_[program_combo_->currentText()] != program) return;
    if (version_combo_->itemData(version_combo_->currentIndex()).toUInt() != version) return;

    if (procedure > onc_rpc_num_procedures_) onc_rpc_num_procedures_ = procedure;
}

void RpcServiceResponseTimeDialog::setDceRpcUuidAndVersion(_e_guid_t *uuid, int version)
{
    bool found = false;
    for (int pi = 0; pi < program_combo_->count(); pi++) {
        if (guid_cmp(uuid, &(dce_name_to_uuid_key_[program_combo_->itemText(pi)]->guid)) == 0) {
            program_combo_->setCurrentIndex(pi);

            for (int vi = 0; vi < version_combo_->count(); vi++) {
                if (version == (int) version_combo_->itemData(vi).toUInt()) {
                    version_combo_->setCurrentIndex(vi);
                    found = true;
                    break;
                }
            }
            break;
        }
    }
    if (found) fillTree();
}

void RpcServiceResponseTimeDialog::setOncRpcProgramAndVersion(int program, int version)
{
    bool found = false;
    for (int pi = 0; pi < program_combo_->count(); pi++) {
        if (program == (int) onc_name_to_program_[program_combo_->itemText(pi)]) {
            program_combo_->setCurrentIndex(pi);

            for (int vi = 0; vi < version_combo_->count(); vi++) {
                if (version == (int) version_combo_->itemData(vi).toUInt()) {
                    version_combo_->setCurrentIndex(vi);
                    found = true;
                    break;
                }
            }
            break;
        }
    }
    if (found) fillTree();
}

void RpcServiceResponseTimeDialog::setRpcNameAndVersion(const QString &program_name, int version)
{
    bool found = false;
    for (int pi = 0; pi < program_combo_->count(); pi++) {
        if (program_name.compare(program_combo_->itemText(pi), Qt::CaseInsensitive) == 0) {
            program_combo_->setCurrentIndex(pi);

            for (int vi = 0; vi < version_combo_->count(); vi++) {
                if (version == (int) version_combo_->itemData(vi).toUInt()) {
                    version_combo_->setCurrentIndex(vi);
                    found = true;
                    break;
                }
            }
            break;
        }
    }
    if (found) fillTree();
}

void RpcServiceResponseTimeDialog::dceRpcProgramChanged(const QString &program_name)
{
    clearVersionCombo();

    if (!dce_name_to_uuid_key_.contains(program_name)) return;

    g_hash_table_foreach(dcerpc_uuids, dce_rpc_find_versions, this);

    fillVersionCombo();
}

void RpcServiceResponseTimeDialog::oncRpcProgramChanged(const QString &program_name)
{
    clearVersionCombo();

    if (!onc_name_to_program_.contains(program_name)) return;

    dissector_table_foreach ("rpc.call", onc_rpc_find_versions, this);
    dissector_table_foreach ("rpc.reply", onc_rpc_find_versions, this);

    fillVersionCombo();
}

void RpcServiceResponseTimeDialog::clearVersionCombo()
{
    version_combo_->clear();
    versions_.clear();
}

void RpcServiceResponseTimeDialog::fillVersionCombo()
{
    foreach (unsigned version, versions_) {
        version_combo_->addItem(QString::number(version), version);
    }
    if (versions_.count() > 0) {
        // Select the highest-numbered version.
        version_combo_->setCurrentIndex(versions_.count() - 1);
    }
}

void RpcServiceResponseTimeDialog::fillTree()
{
    void *tap_data = NULL;
    const QString program_name = program_combo_->currentText();
    gchar *program_name_cptr = qstring_strdup(program_name);
    guint32 max_procs = 0;

    switch (dlg_type_) {
    case DceRpc:
    {
        if (!dce_name_to_uuid_key_.contains(program_name)) return;

        guid_key *dkey = dce_name_to_uuid_key_[program_name];
        dcerpcstat_tap_data_t *dtap_data = g_new0(dcerpcstat_tap_data_t, 1);
        dtap_data->uuid = dkey->guid;
        dtap_data->prog = program_name_cptr;
        dtap_data->ver = (guint16) version_combo_->itemData(version_combo_->currentIndex()).toUInt();

        dcerpc_sub_dissector *procs = dcerpc_get_proto_sub_dissector(&(dkey->guid), dtap_data->ver);
        for (int i = 0; procs[i].name; i++) {
            if (procs[i].num > max_procs) max_procs = procs[i].num;
        }
        dtap_data->num_procedures = max_procs + 1;

        tap_data = dtap_data;
        break;
    }
    case OncRpc:
    {
        if (!onc_name_to_program_.contains(program_name)) return;

        rpcstat_tap_data_t *otap_data = g_new0(rpcstat_tap_data_t, 1);
        otap_data->prog = program_name_cptr;
        otap_data->program = onc_name_to_program_[program_name];
        otap_data->version = (guint32) version_combo_->itemData(version_combo_->currentIndex()).toUInt();

        onc_rpc_num_procedures_ = -1;
        dissector_table_foreach ("rpc.call", onc_rpc_count_procedures, this);
        dissector_table_foreach ("rpc.reply", onc_rpc_count_procedures, this);
        otap_data->num_procedures = onc_rpc_num_procedures_ + 1;

        tap_data = otap_data;
        break;
    }
    }

    set_srt_table_param_data(srt_, tap_data);

    ServiceResponseTimeDialog::fillTree();
    g_free(program_name_cptr);
    g_free(tap_data);
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
