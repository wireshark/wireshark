/* packet-jdwp.c
 * Routines for JDWP (Java Debug Wire Protocol) dissection
 * Copyright 2020, Eugene Adell <eugene.adell@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include <epan/conversation.h>
#include <epan/wmem_scopes.h>

#include "packet-tcp.h"

void proto_register_jdwp(void);
void proto_reg_handoff_jdwp(void);

static dissector_handle_t jdwp_handle;

/* IMPORTANT IMPLEMENTATION NOTES
 *
 * You need to be looking at:
 *
 *     https://docs.oracle.com/javase/8/docs/technotes/guides/jpda/jdwp-spec.html
 *
 *
 */

#define JDWP_PORT 9009 /* Not IANA registered */
#define FRAME_HEADER_LEN 11
#define JDWP_MIN_LENGTH 11
#define JDWP_HANDSHAKE_LENGTH 14
#define JDWP_HANDSHAKE_MSG "JDWP-Handshake"

#define PACKET_TYPE_COMMAND 0
#define PACKET_TYPE_REPLY 128

#define COMMAND_SET_VIRTUALMACHINE 1
#define COMMAND_SET_REFERENCETYPE 2
#define COMMAND_SET_CLASSTYPE 3
#define COMMAND_SET_ARRAYTYPE 4
#define COMMAND_SET_INTERFACETYPE 5
#define COMMAND_SET_METHOD 6
#define COMMAND_SET_FIELD 8
#define COMMAND_SET_OBJECTREFERENCE 9
#define COMMAND_SET_STRINGREFERENCE 10
#define COMMAND_SET_THREADREFERENCE 11
#define COMMAND_SET_THREADGROUPREFERENCE 12
#define COMMAND_SET_ARRAYREFERENCE 13
#define COMMAND_SET_CLASSLOADERREFERENCE 14
#define COMMAND_SET_EVENTREQUEST 15
#define COMMAND_SET_STACKFRAME 16
#define COMMAND_SET_CLASSOBJECTREFERENCE 17
#define COMMAND_SET_EVENT 64

static int proto_jdwp = -1;

static int hf_jdwp_type = -1;
static int hf_jdwp_length = -1;
static int hf_jdwp_id = -1;
static int hf_jdwp_flags = -1;
static int hf_jdwp_commandset = -1;
static int hf_jdwp_commandset_virtualmachine = -1;
static int hf_jdwp_commandset_referencetype = -1;
static int hf_jdwp_commandset_classtype = -1;
static int hf_jdwp_commandset_arraytype = -1;
static int hf_jdwp_commandset_interfacetype = -1;
static int hf_jdwp_commandset_method = -1;
static int hf_jdwp_commandset_field = -1;
static int hf_jdwp_commandset_objectreference = -1;
static int hf_jdwp_commandset_stringreference = -1;
static int hf_jdwp_commandset_threadreference = -1;
static int hf_jdwp_commandset_threadgroupreference = -1;
static int hf_jdwp_commandset_arrayreference = -1;
static int hf_jdwp_commandset_classloaderreference = -1;
static int hf_jdwp_commandset_eventrequest = -1;
static int hf_jdwp_commandset_stackframe = -1;
static int hf_jdwp_commandset_classobjectreference = -1;
static int hf_jdwp_commandset_event = -1;
static int hf_jdwp_errorcode = -1;
static int hf_jdwp_data = -1;

static gint ett_jdwp = -1;

static expert_field ei_jdwp_hlen_invalid  = EI_INIT;
static expert_field ei_jdwp_flags_invalid  = EI_INIT;

// contains the command set names
static const value_string commandsetnames[] = {
  {1, "VirtualMachine"},
  {2, "ReferenceType"},
  {3, "ClassType"},
  {4, "ArrayType"},
  {5, "InterfaceType"},
  {6, "Method"},
  {8, "Field"},
  {9, "ObjectReference"},
  {10, "StringReference"},
  {11, "ThreadReference"},
  {12, "ThreadGroupReference"},
  {13, "ArrayReference"},
  {14, "ClassLoaderReference"},
  {15, "EventRequest"},
  {16, "StackFrame"},
  {17, "ClassObjectReference"},
  {64, "Event"},
  {0, NULL}
};

// contains the commands for the command set of type Virtual Machine
static const value_string commandset_virtualmachine[] = {
  {1, "Version"},
  {2, "ClassesBySignature"},
  {3, "AllClasses"},
  {4, "AllThreads"},
  {5, "TopLevelThreadGroups"},
  {6, "Dispose"},
  {7, "IDSizes"},
  {8, "Suspend"},
  {9, "Resume"},
  {10, "Exit"},
  {11, "CreateString"},
  {12, "Capabilities"},
  {13, "ClassPaths"},
  {14, "DisposeObjects"},
  {15, "HoldEvents"},
  {16, "ReleaseEvents"},
  {17, "CapabilitiesNew"},
  {18, "RedefineClasses"},
  {19, "SetDefaultStratum"},
  {20, "AllClassesWithGeneric"},
  {21, "InstanceCounts"},
  {0, NULL}
};

// contains the commands for the command set of type Reference
static const value_string commandset_referencetype[] = {
  {1, "Signature"},
  {2, "ClassLoader"},
  {3, "Modifiers"},
  {4, "Fields"},
  {5, "Methods"},
  {6, "GetValues"},
  {7, "SourceFile"},
  {8, "NestedTypes"},
  {9, "Status"},
  {10, "Interfaces"},
  {11, "ClassObject"},
  {12, "SourceDebugExtension"},
  {13, "SignatureWithGeneric"},
  {14, "FieldsWithGeneric"},
  {15, "MethodsWithGeneric"},
  {16, "Instances"},
  {17, "ClassFileVersion"},
  {18, "ConstantPool"},
  {0, NULL}
};

// contains the commands for the command set of type Class
static const value_string commandset_classtype[] = {
  {1, "Superclass"},
  {2, "SetValues"},
  {3, "InvokeMethod"},
  {4, "NewInstance"},
  {0, NULL}
};

// contains the commands for the command set of type Array
static const value_string commandset_arraytype[] = {
  {1, "NewInstance"},
  {0, NULL}
};

// contains the commands for the command set of type Interface
static const value_string commandset_interfacetype[] = {
  {1, "InvokeMethod"},
  {0, NULL}
};

// contains the commands for the command set of type Method
static const value_string commandset_method[] = {
  {1, "LineTable"},
  {2, "VariableTable"},
  {3, "Bytecodes"},
  {4, "IsObsolete"},
  {5, "VariableTableWithGeneric"},
  {0, NULL}
};

// contains the commands for the command set of type Field
static const value_string commandset_field[] = {
  {0, NULL}
};

// contains the commands for the command set of type Object Reference
static const value_string commandset_objectreference[] = {
  {1, "ReferenceType"},
  {2, "GetValues"},
  {3, "SetValues"},
  {5, "MonitorInfo"},
  {6, "InvokeMethod"},
  {7, "DisableCollection"},
  {8, "EnableCollection"},
  {9, "IsCollected"},
  {10, "ReferringObjects"},
  {0, NULL}
};

// contains the commands for the command set of type String Reference
static const value_string commandset_stringreference[] = {
  {1, "Value"},
  {0, NULL}
};

// contains the commands for the command set of type Thread Reference
static const value_string commandset_threadreference[] = {
  {1, "Name"},
  {2, "Suspend"},
  {3, "Resume"},
  {4, "Status"},
  {5, "ThreadGroup"},
  {6, "Frames"},
  {7, "FrameCount"},
  {8, "OwnedMonitors"},
  {9, "CurrentContentedMonitor"},
  {10, "Stop"},
  {11, "Interrupt"},
  {12, "SuspendCount"},
  {13, "OwnedMonitorsStackDepthInfo"},
  {14, "ForceEarlyReturn"},
  {0, NULL}
};

// contains the commands for the command set of type ThreadGroup Reference
static const value_string commandset_threadgroupreference[] = {
  {1, "Name"},
  {2, "Parent"},
  {3, "Children"},
  {0, NULL}
};

// contains the commands for the command set of type Array Reference
static const value_string commandset_arrayreference[] = {
  {1, "Length"},
  {2, "GetValues"},
  {3, "SetValues"},
  {0, NULL}
};

// contains the commands for the command set of type ClassLoader Reference
static const value_string commandset_classloaderreference[] = {
  {1, "VisibleClasses"},
  {0, NULL}
};

// contains the commands for the command set of type EventRequest
static const value_string commandset_eventrequest[] = {
  {1, "Set"},
  {2, "Clear"},
  {3, "ClearAllBreakpoints"},
  {0, NULL}
};

// contains the commands for the command set of type StackFrame
static const value_string commandset_stackframe[] = {
  {1, "GetValues"},
  {2, "SetValues"},
  {3, "ThisObject"},
  {4, "PopFrames"},
  {0, NULL}
};

// contains the commands for the command set of type ClassObject Reference
static const value_string commandset_classobjectreference[] = {
  {1, "ReflectedType"},
  {0, NULL}
};

// contains the commands for the command set of type Event
static const value_string commandset_event[] = {
  {100, "Composite"},
  {0, NULL}
};

/* translates the error code to human readable value
 * value 0 ("NONE") means SUCCESS, all other values mean FAILURE
 */
static const value_string error_codes[] = {
  {0, "NONE"},
  {10, "INVALID_THREAD"},
  {11, "INVALID_THREAD_GROUP"},
  {12, "INVALID_PRIORITY"},
  {13, "THREAD_NOT_SUSPENDED"},
  {14, "THREAD_SUSPENDED"},
  {20, "INVALID_OBJECT"},
  {21, "INVALID_CLASS"},
  {22, "CLASS_NOT_PREPARED"},
  {23, "INVALID_METHODID"},
  {24, "INVALID_LOCATION"},
  {25, "INVALID_FIELDID"},
  {30, "INVALID_FRAMEID"},
  {31, "NO_MORE_FRAMES"},
  {32, "OPAQUE_FRAME"},
  {33, "NOT_CURRENT_FRAME"},
  {34, "TYPE_MISMATCH"},
  {35, "INVALID_SLOT"},
  {40, "DUPLICATE"},
  {41, "NOT_FOUND"},
  {50, "INVALID_MONITOR"},
  {51, "NOT_MONITOR_OWNER"},
  {52, "INTERRUPT"},
  {60, "INVALID_CLASS_FORMAT"},
  {61, "CIRCULAR_CLASS_DEFINITION"},
  {62, "FAILS_VERIFICATION"},
  {63, "ADD_METHOD_NOT_IMPLEMENTED"},
  {64, "SCHEMA_CHANGE_NOT_IMPLEMENTED"},
  {65, "INVALID_TYPESTATE"},
  {66, "HIERARCHY_CHANGE_NOT_IMPLEMENTED"},
  {67, "DELETE_METHOD_NOT_IMPLEMENTED"},
  {68, "UNSUPPORTED_VERSION"},
  {69, "NAMES_DONT_MATCH"},
  {70, "CLASS_MODIFIERS_CHANGE_NOT_IMPLEMENTED"},
  {71, "METHOD_MODIFIERS_CHANGE_NOT_IMPLEMENTED"},
  {99, "NOT_IMPLEMENTED"},
  {100, "NULL_POINTER"},
  {101, "ABSENT_INFORMATION"},
  {102, "INVALID_EVENT_TYPE"},
  {103, "ILLEGAL_ARGUMENT"},
  {110, "OUT_OF_MEMORY"},
  {111, "ACCESS_DENIED"},
  {112, "VM_DEAD"},
  {113, "INTERNAL"},
  {115, "UNATTACHED_THREAD"},
  {500, "INVALID_TAG"},
  {502, "ALREADY_INVOKING"},
  {503, "INVALID_INDEX"},
  {504, "INVALID_LENGTH"},
  {506, "INVALID_STRING"},
  {507, "INVALID_CLASS_LOADER"},
  {508, "INVALID_ARRAY"},
  {509, "TRANSPORT_LOAD"},
  {510, "TRANSPORT_INIT"},
  {511, "NATIVE_METHOD"},
  {512, "INVALID_COUNT"},
  {0, NULL}
};

/* determine PDU length of protocol JDWP */
static guint
get_jdwp_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
  /* Handshake messages don't contain the length field and
   * they all are strictly identical in length and content
   */
  if (tvb_reported_length(tvb) == JDWP_HANDSHAKE_LENGTH) {
    if (tvb_strneql(tvb, offset, JDWP_HANDSHAKE_MSG, JDWP_HANDSHAKE_LENGTH) == 0) {
      return JDWP_HANDSHAKE_LENGTH;
    }
  }

  /* All other packets are either a Command or a Reply, of different lengths
   * and this length is indicated on the 4 first bytes
   */
  return (guint)tvb_get_ntohl(tvb, offset);
}

static int
dissect_jdwp_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  int offset = 0;

  /* packet type can take 3 values (handshake, command, reply) */
  gint packet_type;

  /* length */
  gint32 hlen = 0;

  /* flag can take 2 values (0, 128) */
  guint32 flags;

  /* fields that need to be remembered */
  guint32 mem_commandset = -1;
  guint32 mem_errorcode = -1;

  /* Check that there's enough data */
  if (tvb_reported_length(tvb) < JDWP_MIN_LENGTH)
    return 0;

  /* Set the Protocol Column */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "JDWP");
  col_clear(pinfo->cinfo, COL_INFO);

  proto_item *ti, *hlen_item, *flags_item;
  proto_tree *jdwp_tree;

  /* Clear out stuff in the info column */
  col_clear(pinfo->cinfo,COL_INFO);

  ti = proto_tree_add_item(tree, proto_jdwp, tvb, 0, -1, ENC_NA);
  jdwp_tree = proto_item_add_subtree(ti, ett_jdwp);

  /* The two first packets are Handshake packets and
   * their content is always "JDWP-Handshake"
   * All other packets are either a Command or a Reply
   */
  packet_type = 1;
  if (tvb_reported_length(tvb) == JDWP_HANDSHAKE_LENGTH) {
    if (tvb_strneql(tvb, offset, JDWP_HANDSHAKE_MSG, JDWP_HANDSHAKE_LENGTH) == 0) {
      col_append_fstr(pinfo->cinfo, COL_INFO, "JDWP Handshake");
      packet_type = 0;
    }
  }

  if (packet_type == 0) {
    proto_tree_add_item(jdwp_tree, hf_jdwp_type, tvb, offset, 14, ENC_ASCII);
    return tvb_captured_length(tvb);
  }

  /* LENGTH
   */
  hlen_item = proto_tree_add_item_ret_uint(jdwp_tree, hf_jdwp_length, tvb, offset, 4, ENC_BIG_ENDIAN, &hlen);
  offset += 4;

  /* ID
   */
  proto_tree_add_item(jdwp_tree, hf_jdwp_id, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  /* FLAGS
   */
  flags_item = proto_tree_add_item_ret_uint(jdwp_tree, hf_jdwp_flags, tvb, offset, 1, ENC_BIG_ENDIAN, &flags);
  offset += 1;

  /* COMMAND
   */
  switch (flags) {
    case PACKET_TYPE_COMMAND:
      col_append_fstr(pinfo->cinfo, COL_INFO, "Command");
      proto_tree_add_item_ret_uint(jdwp_tree, hf_jdwp_commandset, tvb, offset, 1, ENC_BIG_ENDIAN, &mem_commandset);
      offset += 1;

      switch (mem_commandset) {

        case COMMAND_SET_VIRTUALMACHINE:
          proto_tree_add_item(jdwp_tree, hf_jdwp_commandset_virtualmachine, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
          break;

        case COMMAND_SET_REFERENCETYPE:
          proto_tree_add_item(jdwp_tree, hf_jdwp_commandset_referencetype, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
          break;

        case COMMAND_SET_CLASSTYPE:
          proto_tree_add_item(jdwp_tree, hf_jdwp_commandset_classtype, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
          break;

        case COMMAND_SET_ARRAYTYPE:
          proto_tree_add_item(jdwp_tree, hf_jdwp_commandset_arraytype, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
          break;

        case COMMAND_SET_INTERFACETYPE:
          proto_tree_add_item(jdwp_tree, hf_jdwp_commandset_interfacetype, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
          break;

        case COMMAND_SET_METHOD:
          proto_tree_add_item(jdwp_tree, hf_jdwp_commandset_method, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
          break;

        case COMMAND_SET_FIELD:
          proto_tree_add_item(jdwp_tree, hf_jdwp_commandset_field, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
          break;

        case COMMAND_SET_OBJECTREFERENCE:
          proto_tree_add_item(jdwp_tree, hf_jdwp_commandset_objectreference, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
          break;

        case COMMAND_SET_STRINGREFERENCE:
          proto_tree_add_item(jdwp_tree, hf_jdwp_commandset_stringreference, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
          break;

        case COMMAND_SET_THREADREFERENCE:
          proto_tree_add_item(jdwp_tree, hf_jdwp_commandset_threadreference, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
          break;

        case COMMAND_SET_THREADGROUPREFERENCE:
          proto_tree_add_item(jdwp_tree, hf_jdwp_commandset_threadgroupreference, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
          break;

        case COMMAND_SET_ARRAYREFERENCE:
          proto_tree_add_item(jdwp_tree, hf_jdwp_commandset_arrayreference, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
          break;

        case COMMAND_SET_CLASSLOADERREFERENCE:
          proto_tree_add_item(jdwp_tree, hf_jdwp_commandset_classloaderreference, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
          break;

        case COMMAND_SET_EVENTREQUEST:
          proto_tree_add_item(jdwp_tree, hf_jdwp_commandset_eventrequest, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
          break;

        case COMMAND_SET_STACKFRAME:
          proto_tree_add_item(jdwp_tree, hf_jdwp_commandset_stackframe, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
          break;

        case COMMAND_SET_CLASSOBJECTREFERENCE:
          proto_tree_add_item(jdwp_tree, hf_jdwp_commandset_classobjectreference, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
          break;

        case COMMAND_SET_EVENT:
          proto_tree_add_item(jdwp_tree, hf_jdwp_commandset_event, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
          break;

        default:
          proto_tree_add_item(jdwp_tree, hf_jdwp_commandset_virtualmachine, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
          break;

        }

      /* command comes with data when the minimal length is 12 */
      if (hlen > 11) {
        proto_tree_add_item(jdwp_tree, hf_jdwp_data, tvb, offset, hlen - 11, ENC_NA);
      } else if (hlen < 11) {
        expert_add_info(pinfo, hlen_item, &ei_jdwp_hlen_invalid);
      }

      break;

    case PACKET_TYPE_REPLY:
      proto_tree_add_item_ret_uint(jdwp_tree, hf_jdwp_errorcode, tvb, offset, 2, ENC_BIG_ENDIAN, &mem_errorcode);
      offset += 2;

      if(mem_errorcode == 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "Reply (Success)");
      } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, "Reply (Failure)");
      }

      /* reply comes with data when the minimal length is 12 */
      if (hlen > 11) {
        proto_tree_add_item(jdwp_tree, hf_jdwp_data, tvb, offset, hlen - 11, ENC_NA);
      } else if (hlen < 11) {
        expert_add_info(pinfo, hlen_item, &ei_jdwp_hlen_invalid);
      }

      break;

    default:
      expert_add_info(pinfo, flags_item, &ei_jdwp_flags_invalid);
      break;
  }

  return tvb_captured_length(tvb);
}

static int
dissect_jdwp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN,
                   get_jdwp_message_len, dissect_jdwp_message, data);
  return tvb_captured_length(tvb);
}

void
proto_register_jdwp(void)
{

  expert_module_t* expert_jdwp;

  static hf_register_info hf[] = {
    { &hf_jdwp_type,
      { "Packet Type", "jdwp.type", FT_STRING, BASE_NONE, NULL, 0x0, "Type",
        HFILL }
    },
    { &hf_jdwp_length,
      { "Length",  "jdwp.length", FT_UINT32, BASE_DEC, NULL, 0x0, "Data Length",
        HFILL }
    },
    { &hf_jdwp_id,
      { "id",  "jdwp.id", FT_UINT32, BASE_DEC, NULL, 0x0, "unique identifier",
        HFILL }
    },
    { &hf_jdwp_flags,
      { "flags",  "jdwp.flags", FT_UINT8, BASE_HEX, NULL, 0x0, "tag packets as a command or reply",
        HFILL }
    },
    { &hf_jdwp_commandset,
      { "command set",  "jdwp.commandset", FT_UINT8, BASE_DEC, VALS(commandsetnames), 0x0, NULL,
        HFILL }
    },
    { &hf_jdwp_commandset_virtualmachine,
      { "command",  "jdwp.command", FT_UINT8, BASE_DEC, VALS(commandset_virtualmachine), 0x0, NULL,
        HFILL }
    },
    { &hf_jdwp_commandset_referencetype,
      { "command",  "jdwp.command", FT_UINT8, BASE_DEC, VALS(commandset_referencetype), 0x0, NULL,
        HFILL }
    },
    { &hf_jdwp_commandset_classtype,
      { "command",  "jdwp.command", FT_UINT8, BASE_DEC, VALS(commandset_classtype), 0x0, NULL,
        HFILL }
    },
    { &hf_jdwp_commandset_arraytype,
      { "command",  "jdwp.command", FT_UINT8, BASE_DEC, VALS(commandset_arraytype), 0x0, NULL,
        HFILL }
    },
    { &hf_jdwp_commandset_interfacetype,
      { "command",  "jdwp.command", FT_UINT8, BASE_DEC, VALS(commandset_interfacetype), 0x0, NULL,
        HFILL }
    },
    { &hf_jdwp_commandset_method,
      { "command",  "jdwp.command", FT_UINT8, BASE_DEC, VALS(commandset_method), 0x0, NULL,
        HFILL }
    },
    { &hf_jdwp_commandset_field,
      { "command",  "jdwp.command", FT_UINT8, BASE_DEC, VALS(commandset_field), 0x0, NULL,
        HFILL }
    },
    { &hf_jdwp_commandset_objectreference,
      { "command",  "jdwp.command", FT_UINT8, BASE_DEC, VALS(commandset_objectreference), 0x0, NULL,
        HFILL }
    },
    { &hf_jdwp_commandset_stringreference,
      { "command",  "jdwp.command", FT_UINT8, BASE_DEC, VALS(commandset_stringreference), 0x0, NULL,
        HFILL }
    },
    { &hf_jdwp_commandset_threadreference,
      { "command",  "jdwp.command", FT_UINT8, BASE_DEC, VALS(commandset_threadreference), 0x0, NULL,
        HFILL }
    },
    { &hf_jdwp_commandset_threadgroupreference,
      { "command",  "jdwp.command", FT_UINT8, BASE_DEC, VALS(commandset_threadgroupreference), 0x0, NULL,
        HFILL }
    },
    { &hf_jdwp_commandset_arrayreference,
      { "command",  "jdwp.command", FT_UINT8, BASE_DEC, VALS(commandset_arrayreference), 0x0, NULL,
        HFILL }
    },
    { &hf_jdwp_commandset_classloaderreference,
      { "command",  "jdwp.command", FT_UINT8, BASE_DEC, VALS(commandset_classloaderreference), 0x0, NULL,
        HFILL }
    },
    { &hf_jdwp_commandset_eventrequest,
      { "command",  "jdwp.command", FT_UINT8, BASE_DEC, VALS(commandset_eventrequest), 0x0, NULL,
        HFILL }
    },
    { &hf_jdwp_commandset_stackframe,
      { "command",  "jdwp.command", FT_UINT8, BASE_DEC, VALS(commandset_stackframe), 0x0, NULL,
        HFILL }
    },
    { &hf_jdwp_commandset_classobjectreference,
      { "command",  "jdwp.command", FT_UINT8, BASE_DEC, VALS(commandset_classobjectreference), 0x0, NULL,
        HFILL }
    },
    { &hf_jdwp_commandset_event,
      { "command",  "jdwp.command", FT_UINT8, BASE_DEC, VALS(commandset_event), 0x0, NULL,
        HFILL }
    },
    { &hf_jdwp_errorcode,
      { "error code",  "jdwp.errorcode", FT_UINT8, BASE_DEC, VALS(error_codes), 0x0, NULL,
        HFILL }
    },
    { &hf_jdwp_data,
      { "data",  "jdwp.data", FT_BYTES, BASE_NONE, NULL, 0x0, "details of the command or reply",
        HFILL }
    }
  };

  static ei_register_info ei[] = {
    { &ei_jdwp_hlen_invalid, { "jdwp.hlen.invalid", PI_MALFORMED, PI_ERROR, "Decode aborted: invalid packet length", EXPFILL }},
    { &ei_jdwp_flags_invalid, { "jdwp.flags.invalid", PI_MALFORMED, PI_ERROR, "Decode aborted: invalid flags value", EXPFILL }}
  };

  static gint *ett[] = {
    &ett_jdwp
  };

  proto_jdwp = proto_register_protocol("Java Debug Wire Protocol", "JDWP", "jdwp");
  jdwp_handle = register_dissector("jdwp", dissect_jdwp, proto_jdwp);
  proto_register_field_array(proto_jdwp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_jdwp = expert_register_protocol(proto_jdwp);
  expert_register_field_array(expert_jdwp, ei, array_length(ei));

}

void
proto_reg_handoff_jdwp(void)
{
  dissector_add_uint_with_preference("tcp.port", JDWP_PORT, jdwp_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
