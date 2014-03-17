#!/bin/bash
#
# Test for correct name resolution behavior
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 2005 Ulf Lamping
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

# common exit status values
EXIT_OK=0
EXIT_COMMAND_LINE=1
EXIT_ERROR=2

#TS_ARGS="-Tfields -e frame.number -e frame.time_epoch -e frame.time_delta"
TS_NR_ARGS="-r $CAPTURE_DIR/dns+icmp.pcapng.gz"

CUSTOM_PROFILE_NAME="Custom-$$"

# nameres.network_name: True
# nameres.use_external_name_resolver: False
# nameres.hosts_file_handling: False
# Profile: Default
name_resolution_net_t_ext_f_hosts_f_global() {
	env $TS_NR_ENV $TSHARK $TS_NR_ARGS \
		-o "nameres.network_name: TRUE" \
		-o "nameres.use_external_name_resolver: FALSE" \
		-o "nameres.hosts_file_handling: FALSE" \
		| grep global-8-8-8-8 > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to resolve 8.8.8.8 using global hosts file."
		return
	fi
	test_step_ok
}

# nameres.network_name: True
# nameres.use_external_name_resolver: False
# nameres.hosts_file_handling: False
# Profile: Default
name_resolution_net_t_ext_f_hosts_f_personal() {
	env $TS_NR_ENV $TSHARK $TS_NR_ARGS \
		-o "nameres.network_name: TRUE" \
		-o "nameres.use_external_name_resolver: FALSE" \
		-o "nameres.hosts_file_handling: FALSE" \
		| grep personal-8-8-4-4 > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to resolve 8.8.4.4 using personal hosts file."
		return
	fi
	test_step_ok
}

# nameres.network_name: True
# nameres_use_external_name_resolver: False
# nameres.hosts_file_handling: False
# Profile: Custom
name_resolution_net_t_ext_f_hosts_f_custom() {
	env $TS_NR_ENV $TSHARK $TS_NR_ARGS \
		-o "nameres.network_name: TRUE" \
		-o "nameres.use_external_name_resolver: FALSE" \
		-o "nameres.hosts_file_handling: FALSE" \
		-C "$CUSTOM_PROFILE_NAME" \
		| grep custom-4-2-2-2 > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to resolve 4.2.2.2 using profile $CUSTOM_PROFILE_NAME."
		return
	fi
	test_step_ok
}

# nameres.network_name: True
# nameres.use_external_name_resolver: False
# nameres.hosts_file_handling: True
# Profile: Default
name_resolution_net_t_ext_f_hosts_t_global() {
	env $TS_NR_ENV $TSHARK $TS_NR_ARGS \
		-o "nameres.network_name: TRUE" \
		-o "nameres.use_external_name_resolver: FALSE" \
		-o "nameres.hosts_file_handling: TRUE" \
		| grep global-8-8-8-8 > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -ne $EXIT_OK ]; then
		test_step_failed "Global hosts information showed up when it shouldn't."
		return
	fi
	test_step_ok
}

# nameres.network_name: True
# nameres.use_external_name_resolver: False
# nameres.hosts_file_handling: True
# Profile: Default
name_resolution_net_t_ext_f_hosts_t_personal() {
	env $TS_NR_ENV $TSHARK $TS_NR_ARGS \
		-o "nameres.network_name: TRUE" \
		-o "nameres.use_external_name_resolver: FALSE" \
		-o "nameres.hosts_file_handling: TRUE" \
		| grep personal-8-8-4-4 > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Personal hosts information showed up when it shouldn't."
		return
	fi
	test_step_ok
}

# nameres.network_name: True
# nameres_use_external_name_resolver: False
# nameres.hosts_file_handling: True
# Profile: Custom
name_resolution_net_t_ext_f_hosts_t_custom() {
	env $TS_NR_ENV $TSHARK $TS_NR_ARGS \
		-o "nameres.network_name: TRUE" \
		-o "nameres.use_external_name_resolver: FALSE" \
		-o "nameres.hosts_file_handling: TRUE" \
		-C "$CUSTOM_PROFILE_NAME" \
		| grep custom-4-2-2-2 > /dev/null 2>&1
	RETURNVALUE=$?
	if [ ! $RETURNVALUE -eq $EXIT_OK ]; then
		test_step_failed "Failed to resolve 4.2.2.2 using profile $CUSTOM_PROFILE_NAME."
		return
	fi
	test_step_ok
}

tshark_name_resolution_suite() {
	test_step_add "Name resolution, no external, no profile hosts, global profile" name_resolution_net_t_ext_f_hosts_f_global
	test_step_add "Name resolution, no external, no profile hosts, personal profile" name_resolution_net_t_ext_f_hosts_f_personal
	test_step_add "Name resolution, no external, no profile hosts, custom profile" name_resolution_net_t_ext_f_hosts_f_custom

	test_step_add "Name resolution, no external, profile hosts, global profile" name_resolution_net_t_ext_f_hosts_t_global
	test_step_add "Name resolution, no external, profile hosts, personal profile" name_resolution_net_t_ext_f_hosts_t_personal
	test_step_add "Name resolution, no external, profile hosts, custom profile" name_resolution_net_t_ext_f_hosts_t_custom
}

name_resolution_cleanup_step() {
	rm -f $WS_BIN_PATH/hosts
}

name_resolution_prep_step() {
	CUSTOM_PROFILE_PATH="$CONF_PATH/profiles/$CUSTOM_PROFILE_NAME"
	TS_NR_ENV="WIRESHARK_RUN_FROM_BUILD_DIRECTORY=1 ${HOME_ENV}=${HOME_PATH}"

	name_resolution_cleanup_step
	mkdir -p "$CUSTOM_PROFILE_PATH"
	cp "$TESTS_DIR/hosts.global" "$WS_BIN_PATH/hosts"
	cp "$TESTS_DIR/hosts.personal" "$CONF_PATH/hosts"
	cp "$TESTS_DIR/hosts.custom" "$CUSTOM_PROFILE_PATH/hosts"
}

name_resolution_suite() {
	test_step_set_pre name_resolution_prep_step
	test_step_set_post name_resolution_cleanup_step
	test_suite_add "TShark name resolution" tshark_name_resolution_suite
}

#
# Editor modelines  -  http://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#

