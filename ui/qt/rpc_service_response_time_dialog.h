/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __RPC_SERVICE_RESPONSE_TIME_DIALOG_H__
#define __RPC_SERVICE_RESPONSE_TIME_DIALOG_H__

#include "service_response_time_dialog.h"

class QUuid;
class QComboBox;

struct _guid_key;
struct _dcerpc_uuid_value;
struct _rpc_prog_info_value;

/**
 * @brief Dialog for displaying RPC service response time statistics.
 */
class RpcServiceResponseTimeDialog : public ServiceResponseTimeDialog
{
    Q_OBJECT

public:
    /**
     * @brief Defines the supported RPC families.
     */
    enum RpcFamily {
        DceRpc, /**< DCE-RPC protocol family. */
        OncRpc  /**< ONC-RPC protocol family. */
    };

    /**
     * @brief Constructs an RpcServiceResponseTimeDialog.
     * @param parent The parent widget.
     * @param cf The capture file context.
     * @param srt Pointer to the registered SRT tap structure.
     * @param dlg_type The specific RPC family type.
     * @param filter The display filter string to apply.
     */
    RpcServiceResponseTimeDialog(QWidget &parent, CaptureFile &cf, struct register_srt *srt, RpcFamily dlg_type, const QString filter);

    /**
     * @brief Factory method to create a DCE-RPC SRT dialog.
     * @param parent The parent widget.
     * @param opt_arg Optional argument string.
     * @param cf The capture file context.
     * @return Pointer to the created TapParameterDialog.
     */
    static TapParameterDialog *createDceRpcSrtDialog(QWidget &parent, const QString, const QString opt_arg, CaptureFile &cf);

    /**
     * @brief Factory method to create an ONC-RPC SRT dialog.
     * @param parent The parent widget.
     * @param opt_arg Optional argument string.
     * @param cf The capture file context.
     * @return Pointer to the created TapParameterDialog.
     */
    static TapParameterDialog *createOncRpcSrtDialog(QWidget &parent, const QString, const QString opt_arg, CaptureFile &cf);

    /**
     * @brief Adds a DCE-RPC program to the dialog.
     * @param key Pointer to the GUID key.
     * @param value Pointer to the DCE-RPC UUID value structure.
     */
    void addDceRpcProgram(_guid_key *key, struct _dcerpc_uuid_value *value);

    /**
     * @brief Adds a specific version of a DCE-RPC program.
     * @param key Pointer to the GUID key specifying the program version.
     */
    void addDceRpcProgramVersion(_guid_key *key);

    /**
     * @brief Adds an ONC-RPC program to the dialog.
     * @param program The ONC-RPC program number.
     * @param value Pointer to the RPC program info value structure.
     */
    void addOncRpcProgram(uint32_t program, struct _rpc_prog_info_value *value);

    /**
     * @brief Adds a specific version of an ONC-RPC program.
     * @param program The ONC-RPC program number.
     * @param version The program version number.
     */
    void addOncRpcProgramVersion(uint32_t program, uint32_t version);

    /**
     * @brief Sets the selected DCE-RPC UUID and version.
     * @param uuid The UUID of the DCE-RPC program.
     * @param version The version number.
     */
    void setDceRpcUuidAndVersion(const QUuid &uuid, int version);

    /**
     * @brief Sets the selected ONC-RPC program and version.
     * @param program The ONC-RPC program number.
     * @param version The version number.
     */
    void setOncRpcProgramAndVersion(int program, int version);

    /**
     * @brief Sets the RPC program by name and selects its version.
     * @param program_name The string name of the RPC program.
     * @param version The version number.
     */
    void setRpcNameAndVersion(const QString &program_name, int version);

protected:
    /**
     * @brief Provides parameter data required for the underlying SRT dialog.
     */
    virtual void provideParameterData() override;

public slots:
    /**
     * @brief Slot triggered when the DCE-RPC program selection changes.
     * @param program_name The new DCE-RPC program name.
     */
    void dceRpcProgramChanged(const QString &program_name);

    /**
     * @brief Slot triggered when the ONC-RPC program selection changes.
     * @param program_name The new ONC-RPC program name.
     */
    void oncRpcProgramChanged(const QString &program_name);

private:
    RpcFamily dlg_type_; /**< The family type (DCE-RPC or ONC-RPC) for this dialog. */
    QComboBox *program_combo_; /**< Combo box for selecting the RPC program. */
    QComboBox *version_combo_; /**< Combo box for selecting the RPC program version. */
    QList<unsigned> versions_; /**< List of available versions for the currently selected program. */

    // DCE-RPC
    QMap<QString, struct _guid_key *> dce_name_to_uuid_key_; /**< Map relating DCE-RPC program names to their GUID keys. */

    // ONC-RPC
    QMap<QString, uint32_t> onc_name_to_program_; /**< Map relating ONC-RPC program names to their program numbers. */

    /**
     * @brief Clears the current items from the version combo box.
     */
    void clearVersionCombo();

    /**
     * @brief Populates the version combo box based on the selected program.
     */
    void fillVersionCombo();

};

#endif // __RPC_SERVICE_RESPONSE_TIME_DIALOG_H__
