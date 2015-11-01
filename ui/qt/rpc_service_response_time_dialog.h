/* rpc_service_response_time_dialog.h
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

#ifndef __RPC_SERVICE_RESPONSE_TIME_DIALOG_H__
#define __RPC_SERVICE_RESPONSE_TIME_DIALOG_H__

#include "service_response_time_dialog.h"

class QComboBox;

struct _guid_key;
struct _dcerpc_uuid_value;
struct _e_guid_t;
struct _rpc_prog_info_value;

class RpcServiceResponseTimeDialog : public ServiceResponseTimeDialog
{
    Q_OBJECT

public:
    enum RpcFamily {
        DceRpc,
        OncRpc
    };

    RpcServiceResponseTimeDialog(QWidget &parent, CaptureFile &cf, struct register_srt *srt, RpcFamily dlg_type, const QString filter);
    static TapParameterDialog *createDceRpcSrtDialog(QWidget &parent, const QString, const QString opt_arg, CaptureFile &cf);
    static TapParameterDialog *createOncRpcSrtDialog(QWidget &parent, const QString, const QString opt_arg, CaptureFile &cf);

    void addDceRpcProgram(_guid_key *key, struct _dcerpc_uuid_value *value);
    void addDceRpcProgramVersion(_guid_key *key);
    void addOncRpcProgram(guint32 program, struct _rpc_prog_info_value *value);
    void addOncRpcProgramVersion(guint32 program, guint32 version);
    void updateOncRpcProcedureCount(guint32 program, guint32 version, int procedure);

    void setDceRpcUuidAndVersion(struct _e_guid_t *uuid, int version);
    void setOncRpcProgramAndVersion(int program, int version);
    void setRpcNameAndVersion(const QString &program_name, int version);

public slots:
    void dceRpcProgramChanged(const QString &program_name);
    void oncRpcProgramChanged(const QString &program_name);

protected slots:
    virtual void fillTree();

private:
    RpcFamily dlg_type_;
    QComboBox *program_combo_;
    QComboBox *version_combo_;
    QList<unsigned> versions_;

    // DCE-RPC
    QMap<QString, struct _guid_key *> dce_name_to_uuid_key_;

    // ONC-RPC
    QMap<QString, guint32> onc_name_to_program_;
    int onc_rpc_num_procedures_;

    void clearVersionCombo();
    void fillVersionCombo();

};

#endif // __RPC_SERVICE_RESPONSE_TIME_DIALOG_H__

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
