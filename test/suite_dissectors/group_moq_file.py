# Wireshark tests
# SPDX-License-Identifier: GPL-2.0-or-later

"""MoQ Object File reader and dissector tests."""

import subprocess


class TestMoqFile:
    def test_metadata_and_object_data(self, cmd_tshark, capture_file, test_env):
        """Each metadata entry becomes a packet with its metadata and object bytes."""
        stdout = subprocess.check_output((
            cmd_tshark,
            '-r', capture_file('moq_file.moq'),
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', '_ws.col.Protocol',
            '-e', 'moq_file.object_id',
            '-e', 'moq_file.group_id',
            '-e', 'moq_file.subgroup_id',
            '-e', 'moq_file.data_length',
            '-e', 'moq_file.object_data',
        ), encoding='utf-8', env=test_env)

        columns = stdout.rstrip("\n").split("\t")
        assert columns[:6] == ["1", "MoQ File", "7", "3", "1", "8"]
        # FT_BYTES formatting differs across Wireshark versions (colon-separated
        # versus contiguous hexadecimal); compare the underlying bytes instead.
        assert columns[6].replace(":", "").lower() == "4d4f515445535421"
