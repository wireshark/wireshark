/* packet-dcerpc-taskschedulerservice.c
 * Routines for DCE/RPC ITaskSchedulerService
 * Copyright 2021, Alex Sirr <alexsirruw@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-dcerpc.h"

void proto_register_dcerpc_taskschedulerservice(void);
void proto_reg_handoff_dcerpc_taskschedulerservice(void);

static int hf_taskschedulerservice_opnum;

static e_guid_t uuid_taskschedulerservice = {0x86d35949, 0x83c9, 0x4044, {0xb4, 0x24, 0xdb, 0x36, 0x32, 0x31, 0xfd, 0x0c}};
static guint16 ver_taskschedulerservice = 1;
static gint ett_taskschedulerservice;
static int proto_taskschedulerservice;

/* sub dissector table of ITaskSchedulerService interface */
static const dcerpc_sub_dissector taskschedulerservice_dissectors[] = {
    /* Just map operations for now. Payloads are encrypted due to PKT_PRIVACY */
    {0, "SchRpcHighestVersion", NULL, NULL},
    {1, "SchRpcRegisterTask", NULL, NULL},
    {2, "SchRpcRetrieveTask", NULL, NULL},
    {3, "SchRpcCreateFolder", NULL, NULL},
    {4, "SchRpcSetSecurity", NULL, NULL},
    {5, "SchRpcGetSecurity", NULL, NULL},
    {6, "SchRpcEnumFolders", NULL, NULL},
    {7, "SchRpcEnumTasks", NULL, NULL},
    {8, "SchRpcEnumInstances", NULL, NULL},
    {9, "SchRpcGetInstanceInfo", NULL, NULL},
    {10, "SchRpcStopInstance", NULL, NULL},
    {11, "SchRpcStop", NULL, NULL},
    {12, "SchRpcRun", NULL, NULL},
    {13, "SchRpcDelete", NULL, NULL},
    {14, "SchRpcRename", NULL, NULL},
    {15, "SchRpcScheduledRuntimes", NULL, NULL},
    {16, "SchRpcGetLastRunInfo", NULL, NULL},
    {17, "SchRpcGetTaskInfo", NULL, NULL},
    {18, "SchRpcGetNumberOfMissedRuns", NULL, NULL},
    {19, "SchRpcEnableTask", NULL, NULL},
    {0, NULL, NULL, NULL},
};

void proto_register_dcerpc_taskschedulerservice(void)
{
     static hf_register_info hf_taskschedulerservice_array[] = {
        {&hf_taskschedulerservice_opnum,
         {"Operation", "taskschedulerservice.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    };


    static gint *ett[] = {
        &ett_taskschedulerservice,
    };

    proto_taskschedulerservice = proto_register_protocol("Microsoft Task Scheduler Service", "TaskSchedulerService", "taskschedulerservice");
    proto_register_field_array(proto_taskschedulerservice, hf_taskschedulerservice_array, array_length (hf_taskschedulerservice_array));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_dcerpc_taskschedulerservice(void)
{
    dcerpc_init_uuid(proto_taskschedulerservice, ett_taskschedulerservice,
                     &uuid_taskschedulerservice, ver_taskschedulerservice,
                     taskschedulerservice_dissectors, hf_taskschedulerservice_opnum);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
