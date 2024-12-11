# Test for the MySQL protocol dissector of Wireshark
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Using PDML instead of JSON as output of tshark works better
# as some field names are duplicated, which isn't accepted in JSON
#
"""MySQL tests"""

import subprocess
import xml.etree.ElementTree as ET


class TestMySQL:

    def test_mysql_84_ps_json(self, cmd_tshark, capture_file, test_env):
        """MySQL 8.4.0 with results in binary resultset from prepared statement including the JSON field type"""

        # MySQL Protocol - row packet
        #     Packet Length: 31
        #     Packet Number: 4
        #     Response Code: OK Packet (0x00)
        #     Row null buffer: 00
        #     Binary Field
        #         Length (JSON): 9
        #         JavaScript Object Notation
        #             Array
        #                 [Path with value: /[]:1]
        #                 [Member with value: []:1]
        #                 Number value: 1
        #                 [Path with value: /[]:2]
        #                 [Member with value: []:2]
        #                 Number value: 2
        #                 [Path with value: /[]:3]
        #                 [Member with value: []:3]
        #                 Number value: 3
        #     Binary Field
        #         Length (JSON): 18
        #         JavaScript Object Notation
        #             Object
        #                 Member: a
        #                     [Path with value: /a:61]
        #                     [Member with value: a:61]
        #                     Number value: 61
        #                     Key: a
        #                     [Path: /a]
        #                 Member: b
        #                     [Path with value: /b:62]
        #                     [Member with value: b:62]
        #                     Number value: 62
        #                     Key: b
        #                     [Path: /b]

        stdout = subprocess.check_output(
            (
                cmd_tshark,
                "-r",
                capture_file("mysql/mysql_84_ps_json.pcapng.gz"),
                "-T",
                "pdml",
                "-J",
                "mysql",
                "-Y",
                "mysql",
            ),
            encoding="utf-8",
            env=test_env,
        )

        tree = ET.fromstring(stdout)

        # There should not be any expert info as that indicates the dissector is incomplete
        for expertinfo in tree.findall(
            "./proto[@name='mysql']//field[@name='_ws.expert']"
        ):
            print(ET.tostring(expertinfo, "unicode"))
            assert False

        for pkt in tree:

            # Get the packet number
            num = int(
                pkt.find("./proto[@name='geninfo']/field[@name='num']").attrib["show"]
            )

            if num == 22:
                assert [
                    j.attrib["name"]
                    for j in pkt.findall(
                        "./proto/field[@show='Binary Field']/proto/field"
                    )
                ] == ["json.array", "json.object"]

    def test_mysql_84_qa_multi(self, cmd_tshark, capture_file, test_env):
        """MySQL 8.4.0 with prepared statement and query attributes"""

        stdout = subprocess.check_output(
            (
                cmd_tshark,
                "-r",
                capture_file("mysql/mysql_84_qa_multi.pcapng.gz"),
                "-T",
                "pdml",
                "-J",
                "mysql",
                "-Y",
                "mysql",
            ),
            encoding="utf-8",
            env=test_env,
        )

        # This is just a copy-paste of the `summary` variable and then formatted with the black formatter for python.
        expected = {
            4: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 73",
                        "Packet Number: 0",
                        "Server Greeting",
                    ],
                }
            },
            6: {
                1: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 264",
                        "Packet Number: 1",
                        "Login Request",
                    ],
                }
            },
            8: {
                2: {
                    "showname": "MySQL Protocol - response OK",
                    "fields": [
                        "Packet Length: 16",
                        "Packet Number: 2",
                        "Response Code: OK Packet (0x00)",
                        "Affected Rows: 0",
                        "Last INSERT ID: 0",
                        "Server Status: 0x4002",
                        "Warnings: 0",
                        "Session tracking data",
                    ],
                }
            },
            9: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 51",
                        "Packet Number: 0",
                        "Request Command Query",
                    ],
                }
            },
            10: {
                1: {
                    "showname": "MySQL Protocol - response OK",
                    "fields": [
                        "Packet Length: 107",
                        "Packet Number: 1",
                        "Response Code: OK Packet (0x00)",
                        "Affected Rows: 0",
                        "Last INSERT ID: 0",
                        "Server Status: 0x4002",
                        "Warnings: 0",
                        "Session tracking data",
                    ],
                }
            },
            11: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 20",
                        "Packet Number: 0",
                        "Request Command Query",
                    ],
                }
            },
            12: {
                1: {
                    "showname": "MySQL Protocol - response OK",
                    "fields": [
                        "Packet Length: 107",
                        "Packet Number: 1",
                        "Response Code: OK Packet (0x00)",
                        "Affected Rows: 0",
                        "Last INSERT ID: 0",
                        "Server Status: 0x4002",
                        "Warnings: 0",
                        "Session tracking data",
                    ],
                }
            },
            13: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 19",
                        "Packet Number: 0",
                        "Request Command Query",
                    ],
                }
            },
            14: {
                1: {
                    "showname": "MySQL Protocol - response OK",
                    "fields": [
                        "Packet Length: 26",
                        "Packet Number: 1",
                        "Response Code: OK Packet (0x00)",
                        "Affected Rows: 0",
                        "Last INSERT ID: 0",
                        "Server Status: 0x4000",
                        "Warnings: 0",
                        "Session tracking data",
                    ],
                }
            },
            15: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 1",
                        "Packet Number: 0",
                        "Request Command Ping",
                    ],
                }
            },
            16: {
                1: {
                    "showname": "MySQL Protocol - response OK",
                    "fields": [
                        "Packet Length: 7",
                        "Packet Number: 1",
                        "Response Code: OK Packet (0x00)",
                        "Affected Rows: 0",
                        "Last INSERT ID: 0",
                        "Server Status: 0x0000",
                        "Warnings: 0",
                    ],
                }
            },
            17: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 27",
                        "Packet Number: 0",
                        "Request Command Prepare Statement",
                    ],
                }
            },
            18: {
                1: {
                    "showname": "MySQL Protocol - response to PREPARE",
                    "fields": [
                        "Packet Length: 12",
                        "Packet Number: 1",
                        "Response Code: OK Packet (0x00)",
                        "Statement ID: 1",
                        "Number of fields: 7",
                        "Number of parameter: 1",
                        "Warnings: 0",
                    ],
                },
                2: {
                    "showname": "MySQL Protocol - parameters in response to PREPARE",
                    "fields": [
                        "Packet Length: 23",
                        "Packet Number: 2",
                        "Charset number: binary COLLATE binary (63)",
                        "Length: 21",
                        "Type: FIELD_TYPE_LONGLONG (8)",
                        "Flags: 0x0080",
                        "Decimals: 0",
                    ],
                },
                3: {
                    "showname": "MySQL Protocol - fields in response to PREPARE",
                    "fields": [
                        "Packet Length: 34",
                        "Packet Number: 3",
                        "Charset number: binary COLLATE binary (63)",
                        "Length: 11",
                        "Type: FIELD_TYPE_LONG (3)",
                        "Flags: 0x5003",
                        "Decimals: 0",
                    ],
                },
                4: {
                    "showname": "MySQL Protocol - fields in response to PREPARE",
                    "fields": [
                        "Packet Length: 34",
                        "Packet Number: 4",
                        "Charset number: binary COLLATE binary (63)",
                        "Length: 19",
                        "Type: FIELD_TYPE_DATETIME (12)",
                        "Flags: 0x0080",
                        "Decimals: 0",
                    ],
                },
                5: {
                    "showname": "MySQL Protocol - fields in response to PREPARE",
                    "fields": [
                        "Packet Length: 34",
                        "Packet Number: 5",
                        "Charset number: binary COLLATE binary (63)",
                        "Length: 26",
                        "Type: FIELD_TYPE_DATETIME (12)",
                        "Flags: 0x0080",
                        "Decimals: 6",
                    ],
                },
                6: {
                    "showname": "MySQL Protocol - fields in response to PREPARE",
                    "fields": [
                        "Packet Length: 34",
                        "Packet Number: 6",
                        "Charset number: binary COLLATE binary (63)",
                        "Length: 19",
                        "Type: FIELD_TYPE_TIMESTAMP (7)",
                        "Flags: 0x0080",
                        "Decimals: 0",
                    ],
                },
                7: {
                    "showname": "MySQL Protocol - fields in response to PREPARE",
                    "fields": [
                        "Packet Length: 34",
                        "Packet Number: 7",
                        "Charset number: binary COLLATE binary (63)",
                        "Length: 26",
                        "Type: FIELD_TYPE_TIMESTAMP (7)",
                        "Flags: 0x0080",
                        "Decimals: 6",
                    ],
                },
                8: {
                    "showname": "MySQL Protocol - fields in response to PREPARE",
                    "fields": [
                        "Packet Length: 34",
                        "Packet Number: 8",
                        "Charset number: binary COLLATE binary (63)",
                        "Length: 1",
                        "Type: FIELD_TYPE_BIT (16)",
                        "Flags: 0x0020",
                        "Decimals: 0",
                    ],
                },
                9: {
                    "showname": "MySQL Protocol - fields in response to PREPARE",
                    "fields": [
                        "Packet Length: 34",
                        "Packet Number: 9",
                        "Charset number: binary COLLATE binary (63)",
                        "Length: 16",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0080",
                        "Decimals: 0",
                    ],
                },
            },
            19: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 5",
                        "Packet Number: 0",
                        "Request Command Reset Statement",
                    ],
                }
            },
            20: {
                1: {
                    "showname": "MySQL Protocol - response OK",
                    "fields": [
                        "Packet Length: 7",
                        "Packet Number: 1",
                        "Response Code: OK Packet (0x00)",
                        "Affected Rows: 0",
                        "Last INSERT ID: 0",
                        "Server Status: 0x0000",
                        "Warnings: 0",
                    ],
                }
            },
            21: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 85",
                        "Packet Number: 0",
                        "Request Command Execute Statement",
                    ],
                }
            },
            22: {
                1: {
                    "showname": "MySQL Protocol - column count",
                    "fields": [
                        "Packet Length: 1",
                        "Packet Number: 1",
                        "Number of fields: 7",
                    ],
                },
                2: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 34",
                        "Packet Number: 2",
                        "Charset number: binary COLLATE binary (63)",
                        "Length: 11",
                        "Type: FIELD_TYPE_LONG (3)",
                        "Flags: 0x5003",
                        "Decimals: 0",
                    ],
                },
                3: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 34",
                        "Packet Number: 3",
                        "Charset number: binary COLLATE binary (63)",
                        "Length: 19",
                        "Type: FIELD_TYPE_DATETIME (12)",
                        "Flags: 0x0080",
                        "Decimals: 0",
                    ],
                },
                4: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 34",
                        "Packet Number: 4",
                        "Charset number: binary COLLATE binary (63)",
                        "Length: 26",
                        "Type: FIELD_TYPE_DATETIME (12)",
                        "Flags: 0x0080",
                        "Decimals: 6",
                    ],
                },
                5: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 34",
                        "Packet Number: 5",
                        "Charset number: binary COLLATE binary (63)",
                        "Length: 19",
                        "Type: FIELD_TYPE_TIMESTAMP (7)",
                        "Flags: 0x0080",
                        "Decimals: 0",
                    ],
                },
                6: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 34",
                        "Packet Number: 6",
                        "Charset number: binary COLLATE binary (63)",
                        "Length: 26",
                        "Type: FIELD_TYPE_TIMESTAMP (7)",
                        "Flags: 0x0080",
                        "Decimals: 6",
                    ],
                },
                7: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 34",
                        "Packet Number: 7",
                        "Charset number: binary COLLATE binary (63)",
                        "Length: 1",
                        "Type: FIELD_TYPE_BIT (16)",
                        "Flags: 0x0020",
                        "Decimals: 0",
                    ],
                },
                8: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 34",
                        "Packet Number: 8",
                        "Charset number: binary COLLATE binary (63)",
                        "Length: 16",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0080",
                        "Decimals: 0",
                    ],
                },
                9: {
                    "showname": "MySQL Protocol - row packet",
                    "fields": [
                        "Packet Length: 53",
                        "Packet Number: 9",
                        "Response Code: OK Packet (0x00)",
                        "Row null buffer: 0000",
                    ],
                },
                10: {
                    "showname": "MySQL Protocol - response OK",
                    "fields": [
                        "Packet Length: 7",
                        "Packet Number: 10",
                        "Response Code: EOF Packet (0xfe)",
                        "EOF marker: 254",
                        "Affected Rows: 0",
                        "Last INSERT ID: 0",
                        "Server Status: 0x0021",
                        "Warnings: 0",
                    ],
                },
            },
            23: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 5",
                        "Packet Number: 0",
                        "Request Command Reset Statement",
                    ],
                }
            },
            24: {
                1: {
                    "showname": "MySQL Protocol - response OK",
                    "fields": [
                        "Packet Length: 7",
                        "Packet Number: 1",
                        "Response Code: OK Packet (0x00)",
                        "Affected Rows: 0",
                        "Last INSERT ID: 0",
                        "Server Status: 0x0001",
                        "Warnings: 0",
                    ],
                }
            },
            25: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 5",
                        "Packet Number: 0",
                        "Request Command Close Statement",
                    ],
                }
            },
            26: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 1",
                        "Packet Number: 0",
                        "Request Command Quit",
                    ],
                }
            },
        }

        # Summary should look like this:
        # {
        #   <int:Packet Number>: {
        #     <int:MySQL Packet Number>: {
        #       "showname": <str>,
        #       "fields": [str, ...]
        #     }
        #   }
        # }
        summary = {}

        tree = ET.fromstring(stdout)

        # There should not be any expert info as that indicates the dissector is incomplete
        for expertinfo in tree.findall(
            "./proto[@name='mysql']//field[@name='_ws.expert']"
        ):
            print(ET.tostring(expertinfo, "unicode"))
            assert False

        for pkt in tree:

            # Get the packet number
            num = int(
                pkt.find("./proto[@name='geninfo']/field[@name='num']").attrib["show"]
            )
            summary[num] = {}

            for proto in pkt.findall("./proto[@name='mysql']"):

                mysqlnum = int(
                    proto.find("./field[@name='mysql.packet_number']").attrib["show"]
                )
                summary[num][mysqlnum] = {
                    "showname": proto.attrib["showname"],
                    "fields": [],
                }
                for field in proto.findall("./field"):
                    if "showname" in field.attrib:
                        summary[num][mysqlnum]["fields"].append(
                            field.attrib["showname"]
                        )

        print(summary)

        for pkt in summary:
            for mysqlpkt in summary[pkt]:
                assert (
                    summary[pkt][mysqlpkt]["showname"]
                    == expected[pkt][mysqlpkt]["showname"]
                )
                assert (
                    summary[pkt][mysqlpkt]["fields"]
                    == expected[pkt][mysqlpkt]["fields"]
                )

    def test_mysql_57(self, cmd_tshark, capture_file, test_env):
        """MySQL 5.7"""

        stdout = subprocess.check_output(
            (
                cmd_tshark,
                "-r",
                capture_file("mysql/mysql57.pcapng.gz"),
                "-T",
                "pdml",
                "-J",
                "mysql",
                "-Y",
                "mysql",
            ),
            encoding="utf-8",
            env=test_env,
        )

        # This is just a copy-paste of the `summary` variable and then formatted with the black formatter for python.
        expected = {
            4: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 74",
                        "Packet Number: 0",
                        "Server Greeting",
                    ],
                }
            },
            6: {
                1: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 181",
                        "Packet Number: 1",
                        "Login Request",
                    ],
                }
            },
            8: {
                2: {
                    "showname": "MySQL Protocol - response OK",
                    "fields": [
                        "Packet Length: 7",
                        "Packet Number: 2",
                        "Response Code: OK Packet (0x00)",
                        "Affected Rows: 0",
                        "Last INSERT ID: 0",
                        "Server Status: 0x0002",
                        "Warnings: 0",
                    ],
                }
            },
            9: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 33",
                        "Packet Number: 0",
                        "Request Command Query",
                    ],
                }
            },
            10: {
                1: {
                    "showname": "MySQL Protocol - column count",
                    "fields": [
                        "Packet Length: 1",
                        "Packet Number: 1",
                        "Number of fields: 1",
                    ],
                },
                2: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 39",
                        "Packet Number: 2",
                        "Charset number: latin1 COLLATE latin1_swedish_ci (8)",
                        "Length: 28",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0000",
                        "Decimals: 31",
                    ],
                },
                3: {
                    "showname": "MySQL Protocol - row packet",
                    "fields": ["Packet Length: 29", "Packet Number: 3"],
                },
                4: {
                    "showname": "MySQL Protocol - response OK",
                    "fields": [
                        "Packet Length: 7",
                        "Packet Number: 4",
                        "Response Code: EOF Packet (0xfe)",
                        "EOF marker: 254",
                        "Affected Rows: 0",
                        "Last INSERT ID: 0",
                        "Server Status: 0x0002",
                        "Warnings: 0",
                    ],
                },
            },
            11: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 10",
                        "Packet Number: 0",
                        "Request Command Query",
                    ],
                }
            },
            12: {
                1: {
                    "showname": "MySQL Protocol - response ERROR",
                    "fields": [
                        "Packet Length: 44",
                        "Packet Number: 1",
                        "Response Code: ERR Packet (0xff)",
                        "Error Code: 1054",
                        "SQL state: 42S22",
                        "Error message: Unknown column '$$' in 'field list'",
                    ],
                }
            },
            14: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 34",
                        "Packet Number: 0",
                        "Request Command Query",
                    ],
                }
            },
            15: {
                1: {
                    "showname": "MySQL Protocol - column count",
                    "fields": [
                        "Packet Length: 1",
                        "Packet Number: 1",
                        "Number of fields: 2",
                    ],
                },
                2: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 32",
                        "Packet Number: 2",
                        "Charset number: latin1 COLLATE latin1_swedish_ci (8)",
                        "Length: 34",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0000",
                        "Decimals: 31",
                    ],
                },
                3: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 28",
                        "Packet Number: 3",
                        "Charset number: latin1 COLLATE latin1_swedish_ci (8)",
                        "Length: 93",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0000",
                        "Decimals: 31",
                    ],
                },
                4: {
                    "showname": "MySQL Protocol - row packet",
                    "fields": ["Packet Length: 16", "Packet Number: 4"],
                },
                5: {
                    "showname": "MySQL Protocol - response OK",
                    "fields": [
                        "Packet Length: 7",
                        "Packet Number: 5",
                        "Response Code: EOF Packet (0xfe)",
                        "EOF marker: 254",
                        "Affected Rows: 0",
                        "Last INSERT ID: 0",
                        "Server Status: 0x0002",
                        "Warnings: 0",
                    ],
                },
            },
            17: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 116",
                        "Packet Number: 0",
                        "Request Command Query",
                    ],
                }
            },
            18: {
                1: {
                    "showname": "MySQL Protocol - column count",
                    "fields": [
                        "Packet Length: 1",
                        "Packet Number: 1",
                        "Number of fields: 4",
                    ],
                },
                2: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 44",
                        "Packet Number: 2",
                        "Charset number: latin1 COLLATE latin1_swedish_ci (8)",
                        "Length: 6",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0000",
                        "Decimals: 31",
                    ],
                },
                3: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 48",
                        "Packet Number: 3",
                        "Charset number: latin1 COLLATE latin1_swedish_ci (8)",
                        "Length: 6",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0000",
                        "Decimals: 31",
                    ],
                },
                4: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 44",
                        "Packet Number: 4",
                        "Charset number: latin1 COLLATE latin1_swedish_ci (8)",
                        "Length: 6",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0000",
                        "Decimals: 31",
                    ],
                },
                5: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 46",
                        "Packet Number: 5",
                        "Charset number: latin1 COLLATE latin1_swedish_ci (8)",
                        "Length: 6",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0000",
                        "Decimals: 31",
                    ],
                },
                6: {
                    "showname": "MySQL Protocol - row packet",
                    "fields": ["Packet Length: 28", "Packet Number: 6"],
                },
                7: {
                    "showname": "MySQL Protocol - response OK",
                    "fields": [
                        "Packet Length: 7",
                        "Packet Number: 7",
                        "Response Code: EOF Packet (0xfe)",
                        "EOF marker: 254",
                        "Affected Rows: 0",
                        "Last INSERT ID: 0",
                        "Server Status: 0x0002",
                        "Warnings: 0",
                    ],
                },
            },
            19: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 1",
                        "Packet Number: 0",
                        "Request Command Statistics",
                    ],
                }
            },
            20: {
                1: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 132",
                        "Packet Number: 1",
                        "Message: Uptime: 126  Threads: 1  Questions: 18  Slow queries: 0  Opens: 105  Flush tables: 1  Open tables: 98  Queries per second avg: 0.142",
                    ],
                }
            },
            22: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 1",
                        "Packet Number: 0",
                        "Request Command Quit",
                    ],
                }
            },
        }

        # Summary should look like this:
        # {
        #   <int:Packet Number>: {
        #     <int:MySQL Packet Number>: {
        #       "showname": <str>,
        #       "fields": [str, ...]
        #     }
        #   }
        # }
        summary = {}

        tree = ET.fromstring(stdout)

        # There should not be any expert info as that indicates the dissector is incomplete
        for expertinfo in tree.findall(
            "./proto[@name='mysql']//field[@name='_ws.expert']"
        ):
            print(ET.tostring(expertinfo, "unicode"))
            assert False

        for pkt in tree:

            # Get the packet number
            num = int(
                pkt.find("./proto[@name='geninfo']/field[@name='num']").attrib["show"]
            )
            summary[num] = {}

            for proto in pkt.findall("./proto[@name='mysql']"):

                mysqlnum = int(
                    proto.find("./field[@name='mysql.packet_number']").attrib["show"]
                )
                summary[num][mysqlnum] = {
                    "showname": proto.attrib["showname"],
                    "fields": [],
                }
                for field in proto.findall("./field"):
                    if "showname" in field.attrib:
                        summary[num][mysqlnum]["fields"].append(
                            field.attrib["showname"]
                        )

        print(summary)

        for pkt in summary:
            for mysqlpkt in summary[pkt]:
                assert (
                    summary[pkt][mysqlpkt]["showname"]
                    == expected[pkt][mysqlpkt]["showname"]
                )
                assert (
                    summary[pkt][mysqlpkt]["fields"]
                    == expected[pkt][mysqlpkt]["fields"]
                )

    def test_mysql_80(self, cmd_tshark, capture_file, test_env):
        """MySQL 8.0"""

        stdout = subprocess.check_output(
            (
                cmd_tshark,
                "-r",
                capture_file("mysql/mysql80.pcapng.gz"),
                "-T",
                "pdml",
                "-J",
                "mysql",
                "-Y",
                "mysql",
            ),
            encoding="utf-8",
            env=test_env,
        )

        # This is just a copy-paste of the `summary` variable and then formatted with the black formatter for python.
        expected = {
            4: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 74",
                        "Packet Number: 0",
                        "Server Greeting",
                    ],
                }
            },
            6: {
                1: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 182",
                        "Packet Number: 1",
                        "Login Request",
                    ],
                }
            },
            8: {
                2: {
                    "showname": "MySQL Protocol - response OK",
                    "fields": [
                        "Packet Length: 7",
                        "Packet Number: 2",
                        "Response Code: OK Packet (0x00)",
                        "Affected Rows: 0",
                        "Last INSERT ID: 0",
                        "Server Status: 0x0002",
                        "Warnings: 0",
                    ],
                }
            },
            9: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 35",
                        "Packet Number: 0",
                        "Request Command Query",
                    ],
                }
            },
            10: {
                1: {
                    "showname": "MySQL Protocol - column count",
                    "fields": [
                        "Packet Length: 1",
                        "Packet Number: 1",
                        "Number of fields: 1",
                    ],
                },
                2: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 39",
                        "Packet Number: 2",
                        "Charset number: utf8mb4 COLLATE utf8mb4_0900_ai_ci (255)",
                        "Length: 87380",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0000",
                        "Decimals: 31",
                    ],
                },
                3: {
                    "showname": "MySQL Protocol - row packet",
                    "fields": ["Packet Length: 29", "Packet Number: 3"],
                },
                4: {
                    "showname": "MySQL Protocol - response OK",
                    "fields": [
                        "Packet Length: 7",
                        "Packet Number: 4",
                        "Response Code: EOF Packet (0xfe)",
                        "EOF marker: 254",
                        "Affected Rows: 0",
                        "Last INSERT ID: 0",
                        "Server Status: 0x0002",
                        "Warnings: 0",
                    ],
                },
            },
            11: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 12",
                        "Packet Number: 0",
                        "Request Command Query",
                    ],
                }
            },
            12: {
                1: {
                    "showname": "MySQL Protocol - response ERROR",
                    "fields": [
                        "Packet Length: 44",
                        "Packet Number: 1",
                        "Response Code: ERR Packet (0xff)",
                        "Error Code: 1054",
                        "SQL state: 42S22",
                        "Error message: Unknown column '$$' in 'field list'",
                    ],
                }
            },
            14: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 36",
                        "Packet Number: 0",
                        "Request Command Query",
                    ],
                }
            },
            15: {
                1: {
                    "showname": "MySQL Protocol - column count",
                    "fields": [
                        "Packet Length: 1",
                        "Packet Number: 1",
                        "Number of fields: 2",
                    ],
                },
                2: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 32",
                        "Packet Number: 2",
                        "Charset number: utf8mb4 COLLATE utf8mb4_0900_ai_ci (255)",
                        "Length: 136",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0000",
                        "Decimals: 31",
                    ],
                },
                3: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 28",
                        "Packet Number: 3",
                        "Charset number: utf8mb4 COLLATE utf8mb4_0900_ai_ci (255)",
                        "Length: 1152",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0000",
                        "Decimals: 31",
                    ],
                },
                4: {
                    "showname": "MySQL Protocol - row packet",
                    "fields": ["Packet Length: 16", "Packet Number: 4"],
                },
                5: {
                    "showname": "MySQL Protocol - response OK",
                    "fields": [
                        "Packet Length: 7",
                        "Packet Number: 5",
                        "Response Code: EOF Packet (0xfe)",
                        "EOF marker: 254",
                        "Affected Rows: 0",
                        "Last INSERT ID: 0",
                        "Server Status: 0x0002",
                        "Warnings: 0",
                    ],
                },
            },
            17: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 118",
                        "Packet Number: 0",
                        "Request Command Query",
                    ],
                }
            },
            18: {
                1: {
                    "showname": "MySQL Protocol - column count",
                    "fields": [
                        "Packet Length: 1",
                        "Packet Number: 1",
                        "Number of fields: 4",
                    ],
                },
                2: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 44",
                        "Packet Number: 2",
                        "Charset number: utf8mb4 COLLATE utf8mb4_0900_ai_ci (255)",
                        "Length: 87380",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0000",
                        "Decimals: 31",
                    ],
                },
                3: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 48",
                        "Packet Number: 3",
                        "Charset number: utf8mb4 COLLATE utf8mb4_0900_ai_ci (255)",
                        "Length: 87380",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0000",
                        "Decimals: 31",
                    ],
                },
                4: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 44",
                        "Packet Number: 4",
                        "Charset number: utf8mb4 COLLATE utf8mb4_0900_ai_ci (255)",
                        "Length: 87380",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0000",
                        "Decimals: 31",
                    ],
                },
                5: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 46",
                        "Packet Number: 5",
                        "Charset number: utf8mb4 COLLATE utf8mb4_0900_ai_ci (255)",
                        "Length: 87380",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0000",
                        "Decimals: 31",
                    ],
                },
                6: {
                    "showname": "MySQL Protocol - row packet",
                    "fields": ["Packet Length: 32", "Packet Number: 6"],
                },
                7: {
                    "showname": "MySQL Protocol - response OK",
                    "fields": [
                        "Packet Length: 7",
                        "Packet Number: 7",
                        "Response Code: EOF Packet (0xfe)",
                        "EOF marker: 254",
                        "Affected Rows: 0",
                        "Last INSERT ID: 0",
                        "Server Status: 0x0002",
                        "Warnings: 0",
                    ],
                },
            },
            19: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 1",
                        "Packet Number: 0",
                        "Request Command Statistics",
                    ],
                }
            },
            20: {
                1: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 130",
                        "Packet Number: 1",
                        "Message: Uptime: 30  Threads: 2  Questions: 6  Slow queries: 0  Opens: 119  Flush tables: 3  Open tables: 38  Queries per second avg: 0.200",
                    ],
                }
            },
            22: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 1",
                        "Packet Number: 0",
                        "Request Command Quit",
                    ],
                }
            },
        }

        # Summary should look like this:
        # {
        #   <int:Packet Number>: {
        #     <int:MySQL Packet Number>: {
        #       "showname": <str>,
        #       "fields": [str, ...]
        #     }
        #   }
        # }
        summary = {}

        tree = ET.fromstring(stdout)

        # There should not be any expert info as that indicates the dissector is incomplete
        for expertinfo in tree.findall(
            "./proto[@name='mysql']//field[@name='_ws.expert']"
        ):
            print(ET.tostring(expertinfo, "unicode"))
            assert False

        for pkt in tree:

            # Get the packet number
            num = int(
                pkt.find("./proto[@name='geninfo']/field[@name='num']").attrib["show"]
            )
            summary[num] = {}

            for proto in pkt.findall("./proto[@name='mysql']"):

                mysqlnum = int(
                    proto.find("./field[@name='mysql.packet_number']").attrib["show"]
                )
                summary[num][mysqlnum] = {
                    "showname": proto.attrib["showname"],
                    "fields": [],
                }
                for field in proto.findall("./field"):
                    if "showname" in field.attrib:
                        summary[num][mysqlnum]["fields"].append(
                            field.attrib["showname"]
                        )

        print(summary)

        for pkt in summary:
            for mysqlpkt in summary[pkt]:
                assert (
                    summary[pkt][mysqlpkt]["showname"]
                    == expected[pkt][mysqlpkt]["showname"]
                )
                assert (
                    summary[pkt][mysqlpkt]["fields"]
                    == expected[pkt][mysqlpkt]["fields"]
                )

    def test_mariadb_114(self, cmd_tshark, capture_file, test_env):
        """MariaDB 11.4"""

        stdout = subprocess.check_output(
            (
                cmd_tshark,
                "-r",
                capture_file("mysql/mariadb114.pcapng.gz"),
                "-T",
                "pdml",
                "-J",
                "mysql",
                "-Y",
                "mysql",
            ),
            encoding="utf-8",
            env=test_env,
        )

        # This is just a copy-paste of the `summary` variable and then formatted with the black formatter for python.
        expected = {
            4: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 90",
                        "Packet Number: 0",
                        "Server Greeting",
                    ],
                }
            },
            6: {
                1: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 181",
                        "Packet Number: 1",
                        "Login Request",
                    ],
                }
            },
            8: {
                2: {
                    "showname": "MySQL Protocol - response OK",
                    "fields": [
                        "Packet Length: 7",
                        "Packet Number: 2",
                        "Response Code: OK Packet (0x00)",
                        "Affected Rows: 0",
                        "Last INSERT ID: 0",
                        "Server Status: 0x0002",
                        "Warnings: 0",
                    ],
                }
            },
            9: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 33",
                        "Packet Number: 0",
                        "Request Command Query",
                    ],
                }
            },
            10: {
                1: {
                    "showname": "MySQL Protocol - column count",
                    "fields": [
                        "Packet Length: 1",
                        "Packet Number: 1",
                        "Number of fields: 1",
                    ],
                },
                2: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 39",
                        "Packet Number: 2",
                        "Charset number: utf8mb4 COLLATE utf8mb4_unicode_ci (224)",
                        "Length: 124",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0000",
                        "Decimals: 39",
                    ],
                },
                3: {
                    "showname": "MySQL Protocol - row packet",
                    "fields": ["Packet Length: 32", "Packet Number: 3"],
                },
                4: {
                    "showname": "MySQL Protocol - response OK",
                    "fields": [
                        "Packet Length: 7",
                        "Packet Number: 4",
                        "Response Code: EOF Packet (0xfe)",
                        "EOF marker: 254",
                        "Affected Rows: 0",
                        "Last INSERT ID: 0",
                        "Server Status: 0x0002",
                        "Warnings: 0",
                    ],
                },
            },
            11: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 10",
                        "Packet Number: 0",
                        "Request Command Query",
                    ],
                }
            },
            12: {
                1: {
                    "showname": "MySQL Protocol - response ERROR",
                    "fields": [
                        "Packet Length: 44",
                        "Packet Number: 1",
                        "Response Code: ERR Packet (0xff)",
                        "Error Code: 1054",
                        "SQL state: 42S22",
                        "Error message: Unknown column '$$' in 'field list'",
                    ],
                }
            },
            14: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 34",
                        "Packet Number: 0",
                        "Request Command Query",
                    ],
                }
            },
            15: {
                1: {
                    "showname": "MySQL Protocol - column count",
                    "fields": [
                        "Packet Length: 1",
                        "Packet Number: 1",
                        "Number of fields: 2",
                    ],
                },
                2: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 32",
                        "Packet Number: 2",
                        "Charset number: utf8mb4 COLLATE utf8mb4_unicode_ci (224)",
                        "Length: 256",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0000",
                        "Decimals: 39",
                    ],
                },
                3: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 28",
                        "Packet Number: 3",
                        "Charset number: utf8mb4 COLLATE utf8mb4_unicode_ci (224)",
                        "Length: 1536",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0000",
                        "Decimals: 39",
                    ],
                },
                4: {
                    "showname": "MySQL Protocol - row packet",
                    "fields": ["Packet Length: 16", "Packet Number: 4"],
                },
                5: {
                    "showname": "MySQL Protocol - response OK",
                    "fields": [
                        "Packet Length: 7",
                        "Packet Number: 5",
                        "Response Code: EOF Packet (0xfe)",
                        "EOF marker: 254",
                        "Affected Rows: 0",
                        "Last INSERT ID: 0",
                        "Server Status: 0x0002",
                        "Warnings: 0",
                    ],
                },
            },
            17: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 116",
                        "Packet Number: 0",
                        "Request Command Query",
                    ],
                }
            },
            18: {
                1: {
                    "showname": "MySQL Protocol - column count",
                    "fields": [
                        "Packet Length: 1",
                        "Packet Number: 1",
                        "Number of fields: 4",
                    ],
                },
                2: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 44",
                        "Packet Number: 2",
                        "Charset number: utf8mb4 COLLATE utf8mb4_unicode_ci (224)",
                        "Length: 28",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0000",
                        "Decimals: 39",
                    ],
                },
                3: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 48",
                        "Packet Number: 3",
                        "Charset number: utf8mb4 COLLATE utf8mb4_unicode_ci (224)",
                        "Length: 28",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0000",
                        "Decimals: 39",
                    ],
                },
                4: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 44",
                        "Packet Number: 4",
                        "Charset number: utf8mb4 COLLATE utf8mb4_unicode_ci (224)",
                        "Length: 28",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0000",
                        "Decimals: 39",
                    ],
                },
                5: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 46",
                        "Packet Number: 5",
                        "Charset number: utf8mb4 COLLATE utf8mb4_unicode_ci (224)",
                        "Length: 28",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0000",
                        "Decimals: 39",
                    ],
                },
                6: {
                    "showname": "MySQL Protocol - row packet",
                    "fields": ["Packet Length: 32", "Packet Number: 6"],
                },
                7: {
                    "showname": "MySQL Protocol - response OK",
                    "fields": [
                        "Packet Length: 7",
                        "Packet Number: 7",
                        "Response Code: EOF Packet (0xfe)",
                        "EOF marker: 254",
                        "Affected Rows: 0",
                        "Last INSERT ID: 0",
                        "Server Status: 0x0002",
                        "Warnings: 0",
                    ],
                },
            },
            19: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 1",
                        "Packet Number: 0",
                        "Request Command Statistics",
                    ],
                }
            },
            20: {
                1: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 112",
                        "Packet Number: 1",
                        "Message: Uptime: 25  Threads: 1  Questions: 5  Slow queries: 0  Opens: 17  Open tables: 10  Queries per second avg: 0.200",
                    ],
                }
            },
            22: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 1",
                        "Packet Number: 0",
                        "Request Command Quit",
                    ],
                }
            },
        }

        # Summary should look like this:
        # {
        #   <int:Packet Number>: {
        #     <int:MySQL Packet Number>: {
        #       "showname": <str>,
        #       "fields": [str, ...]
        #     }
        #   }
        # }
        summary = {}

        tree = ET.fromstring(stdout)

        # There should not be any expert info as that indicates the dissector is incomplete
        for expertinfo in tree.findall(
            "./proto[@name='mysql']//field[@name='_ws.expert']"
        ):
            print(ET.tostring(expertinfo, "unicode"))
            assert False

        for pkt in tree:

            # Get the packet number
            num = int(
                pkt.find("./proto[@name='geninfo']/field[@name='num']").attrib["show"]
            )
            summary[num] = {}

            for proto in pkt.findall("./proto[@name='mysql']"):

                mysqlnum = int(
                    proto.find("./field[@name='mysql.packet_number']").attrib["show"]
                )
                summary[num][mysqlnum] = {
                    "showname": proto.attrib["showname"],
                    "fields": [],
                }
                for field in proto.findall("./field"):
                    if "showname" in field.attrib:
                        summary[num][mysqlnum]["fields"].append(
                            field.attrib["showname"]
                        )

        print(summary)

        for pkt in summary:
            for mysqlpkt in summary[pkt]:
                assert (
                    summary[pkt][mysqlpkt]["showname"]
                    == expected[pkt][mysqlpkt]["showname"]
                )
                assert (
                    summary[pkt][mysqlpkt]["fields"]
                    == expected[pkt][mysqlpkt]["fields"]
                )

    def test_tidb_81(self, cmd_tshark, capture_file, test_env):
        """TiDB 8.1"""

        stdout = subprocess.check_output(
            (
                cmd_tshark,
                "-r",
                capture_file("mysql/tidb81.pcapng.gz"),
                "-T",
                "pdml",
                "-J",
                "mysql",
                "-Y",
                "mysql",
            ),
            encoding="utf-8",
            env=test_env,
        )

        # This is just a copy-paste of the `summary` variable and then formatted with the black formatter for python.
        expected = {
            4: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 86",
                        "Packet Number: 0",
                        "Server Greeting",
                    ],
                }
            },
            6: {
                1: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 181",
                        "Packet Number: 1",
                        "Login Request",
                    ],
                }
            },
            8: {
                2: {
                    "showname": "MySQL Protocol - response OK",
                    "fields": [
                        "Packet Length: 7",
                        "Packet Number: 2",
                        "Response Code: OK Packet (0x00)",
                        "Affected Rows: 0",
                        "Last INSERT ID: 0",
                        "Server Status: 0x0002",
                        "Warnings: 0",
                    ],
                }
            },
            9: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 33",
                        "Packet Number: 0",
                        "Request Command Query",
                    ],
                }
            },
            10: {
                1: {
                    "showname": "MySQL Protocol - column count",
                    "fields": [
                        "Packet Length: 1",
                        "Packet Number: 1",
                        "Number of fields: 1",
                    ],
                },
                2: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 39",
                        "Packet Number: 2",
                        "Charset number: utf8mb4 COLLATE utf8mb4_bin (46)",
                        "Length: 0",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0000",
                        "Decimals: 31",
                    ],
                },
                3: {
                    "showname": "MySQL Protocol - row packet",
                    "fields": ["Packet Length: 73", "Packet Number: 3"],
                },
                4: {
                    "showname": "MySQL Protocol - response OK",
                    "fields": [
                        "Packet Length: 7",
                        "Packet Number: 4",
                        "Response Code: EOF Packet (0xfe)",
                        "EOF marker: 254",
                        "Affected Rows: 0",
                        "Last INSERT ID: 0",
                        "Server Status: 0x0002",
                        "Warnings: 0",
                    ],
                },
            },
            11: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 10",
                        "Packet Number: 0",
                        "Request Command Query",
                    ],
                }
            },
            12: {
                1: {
                    "showname": "MySQL Protocol - response ERROR",
                    "fields": [
                        "Packet Length: 44",
                        "Packet Number: 1",
                        "Response Code: ERR Packet (0xff)",
                        "Error Code: 1054",
                        "SQL state: 42S22",
                        "Error message: Unknown column '$$' in 'field list'",
                    ],
                }
            },
            14: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 34",
                        "Packet Number: 0",
                        "Request Command Query",
                    ],
                }
            },
            15: {
                1: {
                    "showname": "MySQL Protocol - column count",
                    "fields": [
                        "Packet Length: 1",
                        "Packet Number: 1",
                        "Number of fields: 2",
                    ],
                },
                2: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 32",
                        "Packet Number: 2",
                        "Charset number: utf8mb4 COLLATE utf8mb4_bin (46)",
                        "Length: 256",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0000",
                        "Decimals: 31",
                    ],
                },
                3: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 28",
                        "Packet Number: 3",
                        "Charset number: utf8mb4 COLLATE utf8mb4_bin (46)",
                        "Length: 256",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0001",
                        "Decimals: 31",
                    ],
                },
                4: {
                    "showname": "MySQL Protocol - row packet",
                    "fields": ["Packet Length: 16", "Packet Number: 4"],
                },
                5: {
                    "showname": "MySQL Protocol - response OK",
                    "fields": [
                        "Packet Length: 7",
                        "Packet Number: 5",
                        "Response Code: EOF Packet (0xfe)",
                        "EOF marker: 254",
                        "Affected Rows: 0",
                        "Last INSERT ID: 0",
                        "Server Status: 0x0002",
                        "Warnings: 0",
                    ],
                },
            },
            17: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 116",
                        "Packet Number: 0",
                        "Request Command Query",
                    ],
                }
            },
            18: {
                1: {
                    "showname": "MySQL Protocol - column count",
                    "fields": [
                        "Packet Length: 1",
                        "Packet Number: 1",
                        "Number of fields: 4",
                    ],
                },
                2: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 44",
                        "Packet Number: 2",
                        "Charset number: utf8mb4 COLLATE utf8mb4_bin (46)",
                        "Length: 0",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0000",
                        "Decimals: 31",
                    ],
                },
                3: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 48",
                        "Packet Number: 3",
                        "Charset number: utf8mb4 COLLATE utf8mb4_bin (46)",
                        "Length: 0",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0000",
                        "Decimals: 31",
                    ],
                },
                4: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 44",
                        "Packet Number: 4",
                        "Charset number: utf8mb4 COLLATE utf8mb4_bin (46)",
                        "Length: 0",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0000",
                        "Decimals: 31",
                    ],
                },
                5: {
                    "showname": "MySQL Protocol - field packet",
                    "fields": [
                        "Packet Length: 46",
                        "Packet Number: 5",
                        "Charset number: utf8mb4 COLLATE utf8mb4_bin (46)",
                        "Length: 0",
                        "Type: FIELD_TYPE_VAR_STRING (253)",
                        "Flags: 0x0000",
                        "Decimals: 31",
                    ],
                },
                6: {
                    "showname": "MySQL Protocol - row packet",
                    "fields": ["Packet Length: 32", "Packet Number: 6"],
                },
                7: {
                    "showname": "MySQL Protocol - response OK",
                    "fields": [
                        "Packet Length: 7",
                        "Packet Number: 7",
                        "Response Code: EOF Packet (0xfe)",
                        "EOF marker: 254",
                        "Affected Rows: 0",
                        "Last INSERT ID: 0",
                        "Server Status: 0x0002",
                        "Warnings: 0",
                    ],
                },
            },
            19: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 1",
                        "Packet Number: 0",
                        "Request Command Statistics",
                    ],
                }
            },
            20: {
                1: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 127",
                        "Packet Number: 1",
                        "Message: Uptime: 19  Threads: 0  Questions: 0  Slow queries: 0  Opens: 0  Flush tables: 0  Open tables: 0  Queries per second avg: 0.000",
                    ],
                }
            },
            22: {
                0: {
                    "showname": "MySQL Protocol",
                    "fields": [
                        "Packet Length: 1",
                        "Packet Number: 0",
                        "Request Command Quit",
                    ],
                }
            },
        }

        # Summary should look like this:
        # {
        #   <int:Packet Number>: {
        #     <int:MySQL Packet Number>: {
        #       "showname": <str>,
        #       "fields": [str, ...]
        #     }
        #   }
        # }
        summary = {}

        tree = ET.fromstring(stdout)

        # There should not be any expert info as that indicates the dissector is incomplete
        for expertinfo in tree.findall(
            "./proto[@name='mysql']//field[@name='_ws.expert']"
        ):
            print(ET.tostring(expertinfo, "unicode"))
            assert False

        for pkt in tree:

            # Get the packet number
            num = int(
                pkt.find("./proto[@name='geninfo']/field[@name='num']").attrib["show"]
            )
            summary[num] = {}

            for proto in pkt.findall("./proto[@name='mysql']"):

                mysqlnum = int(
                    proto.find("./field[@name='mysql.packet_number']").attrib["show"]
                )
                summary[num][mysqlnum] = {
                    "showname": proto.attrib["showname"],
                    "fields": [],
                }
                for field in proto.findall("./field"):
                    if "showname" in field.attrib:
                        summary[num][mysqlnum]["fields"].append(
                            field.attrib["showname"]
                        )

        print(summary)

        for pkt in summary:
            for mysqlpkt in summary[pkt]:
                assert (
                    summary[pkt][mysqlpkt]["showname"]
                    == expected[pkt][mysqlpkt]["showname"]
                )
                assert (
                    summary[pkt][mysqlpkt]["fields"]
                    == expected[pkt][mysqlpkt]["fields"]
                )
