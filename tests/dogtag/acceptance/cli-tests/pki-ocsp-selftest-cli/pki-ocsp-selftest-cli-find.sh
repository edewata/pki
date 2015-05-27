#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-ocsp-selftest-cli
#
#   Description: PKI OCSP SELFTEST CLI
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki ocsp-selftest cli commands needs to be tested:
#  pki ocsp-selftest-find
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Niranjan Mallapadi <mrniranjan@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2013 Red Hat, Inc. All rights reserved.
#
#   This copyrighted material is made available to anyone wishing
#   to use, modify, copy, or redistribute it subject to the terms
#   and conditions of the GNU General Public License version 2.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE. See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public
#   License along with this program; if not, write to the Free
#   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
#   Boston, MA 02110-1301, USA.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Include rhts environment
. /usr/bin/rhts-environment.sh
. /usr/share/beakerlib/beakerlib.sh
. /opt/rhqa_pki/rhcs-shared.sh
. /opt/rhqa_pki/pki-key-cli-lib.sh
. /opt/rhqa_pki/env.sh

run_pki-ocsp-selftest-find_tests()
{
        local cs_Type=$1
        local cs_Role=$2

        # Creating Temporary Directory for pki ocsp-selftest-find
        rlPhaseStartSetup "pki ocsp-selftest-find Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlPhaseEnd

        # Loocspl Variables
        get_topo_stack $cs_Role $TmpDir/topo_file
        local OCSP_INST=$(cat $TmpDir/topo_file | grep MY_OCSP | cut -d= -f2)
        ocsp_instance_created="False"
        if [ "$TOPO9" = "TRUE" ] ; then
                prefix=$OCSP_INST
                ocsp_instance_created=$(eval echo \$${OCSP_INST}_INSTANCE_CREATED_STATUS)
        elif [ "$cs_Role" = "MASTER" ] ; then
                prefix=OCSP3
                ocsp_instance_created=$(eval echo \$${OCSP_INST}_INSTANCE_CREATED_STATUS)
        else
                prefix=$cs_Role
                ocsp_instance_created=$(eval echo \$${OCSP_INST}_INSTANCE_CREATED_STATUS)
        fi
if [ "$ocsp_instance_created" = "TRUE" ] ;  then
        local target_secure_port=$(eval echo \$${OCSP_INST}_SECURE_PORT)
        local tmp_ocsp_agent=$OCSP_INST\_agentV
        local tmp_ocsp_admin=$OCSP_INST\_adminV
        local tmp_ocsp_port=$(eval echo \$${OCSP_INST}_UNSECURE_PORT)
        local tmp_ocsp_host=$(eval echo \$${cs_Role})
        local valid_agent_cert=$OCSP_INST\_agentV
        local valid_audit_cert=$OCSP_INST\_auditV
        local valid_operator_cert=$OCSP_INST\_operatorV
        local valid_admin_cert=$OCSP_INST\_adminV
        local revoked_agent_cert=$OCSP_INST\_agentR
        local revoked_admin_cert=$OCSP_INST\_adminR
        local expired_admin_cert=$OCSP_INST\_adminE
        local expired_agent_cert=$OCSP_INST\_agentE
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"
        local exp="$TmpDir/expfile.out"
        local expout="$TmpDir/exp_out"
        local cert_info="$TmpDir/cert_info"
        local ocsp_selftest_find_output=$TmpDir/ocsp-selftest-find.out
        local rand=$RANDOM
        local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')


	# Config test for pki ocsp-selftest-find
	rlPhaseStartTest "pki_ocsp_selftest_find-configtest: pki ocsp-selftest-find --help configuration test"
	rlRun "pki ocsp-selftest-find --help > $ocsp_selftest_find_output" 0 "pki ocsp-selftest-find --help"
	rlAssertGrep "usage: ocsp-selftest-find \[FILTER\] \[OPTIONS...\]" "$ocsp_selftest_find_output"
	rlAssertGrep "    --help            Show help options" "$ocsp_selftest_find_output"
	rlAssertGrep "    --size <size>     Page size" "$ocsp_selftest_find_output"
	rlAssertGrep "    --start <start>   Page start" "$ocsp_selftest_find_output"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_ocsp_selftest_find_find-001: find all the existing selftests for OCSP using admin cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$valid_admin_cert\" \
		ocsp-selftest-find > $ocsp_selftest_find_output" 0 "Find all the OCSP Selftest using $valid_admin_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$valid_admin_cert\" \
		ocsp-selftest-find > $ocsp_selftest_find_output" 0 "Find all the OCSP Selftest using $valid_admin_cert"
	rlAssertGrep "3 entries matched" "$ocsp_selftest_find_output"
	rlAssertGrep "  SelfTest ID: OCSPPresence" "$ocsp_selftest_find_output"
	rlAssertGrep "  Enabled at startup: true" "$ocsp_selftest_find_output"
	rlAssertGrep "  Critical at startup: true" "$ocsp_selftest_find_output"
	rlAssertGrep "  Enabled on demand: true" "$ocsp_selftest_find_output"
	rlAssertGrep "  Critical on demand: true" "$ocsp_selftest_find_output"
	rlAssertGrep "  SelfTest ID: SystemCertsVerification" "$ocsp_selftest_find_output"
	rlAssertGrep "  Enabled at startup: true" "$ocsp_selftest_find_output"
	rlAssertGrep "  Critical at startup: true" "$ocsp_selftest_find_output"
	rlAssertGrep "  Enabled on demand: true" "$ocsp_selftest_find_output"
	rlAssertGrep "  Critical on demand: true" "$ocsp_selftest_find_output"
	rlAssertGrep "  SelfTest ID: OCSPValidity" "$ocsp_selftest_find_output"
	rlAssertGrep "  Enabled at startup: true" "$ocsp_selftest_find_output"
	rlAssertGrep "  Enabled on demand: true" "$ocsp_selftest_find_output"
	rlAssertGrep "  Critical at startup: true" "$ocsp_selftest_find_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_ocsp_selftest_find-002: verifying all ocsp selftests cannot be found by agent cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$valid_agent_cert\" \
		ocsp-selftest-find > $ocsp_selftest_find_output" 0 "Find all the OCSP Selftest using $valid_agent_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$valid_agent_cert\" \
		ocsp-selftest-find 2> $ocsp_selftest_find_output" 1,255 "Find all the OCSP Selftest using $valid_agent_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$ocsp_selftest_find_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_ocsp_selftest_find-003: verifying all ocsp selftests cannot be found by operator cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$valid_operator_cert\" \
		ocsp-selftest-find > $ocsp_selftest_find_output" 0 "Find all the OCSP Selftest using $valid_operator_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$valid_operator_cert\" \
		ocsp-selftest-find 2> $ocsp_selftest_find_output" 1,255 "Find all the OCSP Selftest using $valid_operator_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$ocsp_selftest_find_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_ocsp_selftest_find-004: verifying all ocsp selftests cannot be found by audit cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$valid_operator_cert\" \
		ocsp-selftest-find > $ocsp_selftest_find_output" 0 "Find all the OCSP Selftest using $valid_audit_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$valid_operator_cert\" \
		ocsp-selftest-find 2> $ocsp_selftest_find_output" 1,255 "Find all the OCSP Selftest using $valid_audit_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$ocsp_selftest_find_output"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_ocsp_selftest_find-005: verifying all ocsp selftests cannot be found by Revoked admin cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$revoked_admin_cert\" \
		ocsp-selftest-find > $ocsp_selftest_find_output" 0 "Find all the OCSP Selftest using $revoked_admin_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$revoked_admin_cert\" \
		ocsp-selftest-find 2> $ocsp_selftest_find_output" 1,255 "Find all the OCSP Selftest using $revoked_admin_cert"
	rlAssertGrep "PKIException: Unauthorized" "$ocsp_selftest_find_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_ocsp_selftest_find-006: verifying all ocsp selftests cannot be found by Revoked agent cert"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$revoked_agent_cert\" \
		ocsp-selftest-find > $ocsp_selftest_find_output" 0 "Find all the OCSP Selftest using $revoked_agent_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$revoked_agent_cert\" \
		ocsp-selftest-find 2> $ocsp_selftest_find_output" 1,255 "Find all the OCSP Selftest using $revoked_agent_cert"
	rlAssertGrep "ForbiddenException: Authorization Error" "$ocsp_selftest_find_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_ocsp_selftest_find-007: verifying all ocsp selftests cannot be found by Expired agent cert"
	local cur_date=$(date +%a\ %b\ %d\ %H:%M:%S)
	local end_date=$(certutil -L -d $CERTDB_DIR -n $expired_agent_cert | grep "Not After" | awk -F ": " '{print $2}')
	rlLog "Current Date/Time: $(date)"
	rlLog "Current Date/Time: before modifying using chrony $(date)"
	rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Move system to $end_date + 1 day ahead"
	rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Date after modifying using chrony: $(date)"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$expired_agent_cert\" \
		ocsp-selftest-find > $ocsp_selftest_find_output" 0 "Find all the OCSP Selftest using $expired_agent_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$expired_agent_cert\" \
		ocsp-selftest-find > $ocsp_selftest_find_output 2>&1" 1,255 "Find all the OCSP Selftest using $expired_agent_cert"
	rlAssertGrep "ProcessingException: Unable to invoke request" "$ocsp_selftest_find_output"
	rlLog "Set the date back to its original date & time"
	rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd

	rlPhaseStartTest "pki_ocsp_selftest_find-008: verifying all ocsp selftests cannot be found by Expired admin cert"
	local cur_date=$(date +%a\ %b\ %d\ %H:%M:%S)
	local end_date=$(certutil -L -d $CERTDB_DIR -n $expired_admin_cert | grep "Not After" | awk -F ": " '{print $2}')
	rlLog "Current Date/Time: $(date)"
	rlLog "Current Date/Time: before modifying using chrony $(date)"
	rlRun "chronyc -a 'manual on' 1> $TmpDir/chrony.out" 0 "Set chrony to manual mode"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Move system to $end_date + 1 day ahead"
	rlRun "chronyc -a -m 'offline' 'settime $end_date + 1 day' 'makestep' 'manual reset' 1> $TmpDir/chrony.out"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Date after modifying using chrony: $(date)"
	rlLog "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$expired_admin_cert\" \
		ocsp-selftest-find > $ocsp_selftest_find_output" 0 "Find all the OCSP Selftest using $expired_admin_cert"
	rlRun "pki -d $CERTDB_DIR \
		-c $CERTDB_DIR_PASSWORD \
		-h $tmp_ocsp_host \
		-p $tmp_ocsp_port \
		-n \"$expired_admin_cert\" \
		ocsp-selftest-find > $ocsp_selftest_find_output 2>&1" 1,255 "Find all the OCSP Selftest using $expired_admin_cert"
	rlAssertGrep "ProcessingException: Unable to invoke request" "$ocsp_selftest_find_output"
	rlLog "Set the date back to its original date & time"
	rlRun "chronyc -a -m 'settime $cur_date + 10 seconds' 'makestep' 'manual reset' 'online' 1> $TmpDir/chrony.out"
	rlAssertGrep "200 OK" "$TmpDir/chrony.out"
	rlLog "Current Date/Time after setting system date back using chrony $(date)"
	rlPhaseEnd

	rlPhaseStartTest "pki_ocsp_selftest_find-009: verify when --size 1 is specified only 1 OCSP selftest is displayed"
	rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ocsp_host \
                -p $tmp_ocsp_port \
                -n \"$valid_admin_cert\" \
                ocsp-selftest-find --size 1 > $ocsp_selftest_find_output" 0 "Run pki ocsp-selftest-find --size 1"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ocsp_host \
                -p $tmp_ocsp_port \
                -n \"$valid_admin_cert\" \
                ocsp-selftest-find --size 1 1> $ocsp_selftest_find_output" 0 "Run pki ocsp-selftest-find --size 1"
        rlAssertGrep "3 entries matched" "$ocsp_selftest_find_output"
        rlAssertGrep "  SelfTest ID: OCSPPresence" "$ocsp_selftest_find_output"
        rlAssertGrep "  Enabled at startup: true" "$ocsp_selftest_find_output"
        rlAssertGrep "  Critical at startup: true" "$ocsp_selftest_find_output"
        rlAssertGrep "  Enabled on demand: true" "$ocsp_selftest_find_output"
        rlAssertGrep "  Critical on demand: true" "$ocsp_selftest_find_output"
	rlPhaseEnd


	rlPhaseStartTest "pki_ocsp_selftest_find-0010: verify when value given in --size is more than 3 display all the selftests"
	rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ocsp_host \
                -p $tmp_ocsp_port \
                -n \"$valid_admin_cert\" \
                ocsp-selftest-find --size 100 > $ocsp_selftest_find_output" 0 "Run pki ocsp-selftest-find --size 100"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ocsp_host \
                -p $tmp_ocsp_port \
                -n \"$valid_admin_cert\" \
                ocsp-selftest-find --size 100 > $ocsp_selftest_find_output" 0 "Run pki ocsp-selftest-find --size 100"
        rlAssertGrep "3 entries matched" "$ocsp_selftest_find_output"
        rlAssertGrep "  SelfTest ID: OCSPPresence" "$ocsp_selftest_find_output"
        rlAssertGrep "  Enabled at startup: true" "$ocsp_selftest_find_output"
        rlAssertGrep "  Critical at startup: true" "$ocsp_selftest_find_output"
        rlAssertGrep "  Enabled on demand: true" "$ocsp_selftest_find_output"
        rlAssertGrep "  Critical on demand: true" "$ocsp_selftest_find_output"
        rlAssertGrep "  SelfTest ID: SystemCertsVerification" "$ocsp_selftest_find_output"
        rlAssertGrep "  Enabled at startup: true" "$ocsp_selftest_find_output"
        rlAssertGrep "  Critical at startup: true" "$ocsp_selftest_find_output"
        rlAssertGrep "  Enabled on demand: true" "$ocsp_selftest_find_output"
        rlAssertGrep "  Critical on demand: true" "$ocsp_selftest_find_output"
        rlAssertGrep "  SelfTest ID: OCSPValidity" "$ocsp_selftest_find_output"
        rlAssertGrep "  Enabled at startup: true" "$ocsp_selftest_find_output"
        rlAssertGrep "  Enabled on demand: true" "$ocsp_selftest_find_output"
        rlAssertGrep "  Critical at startup: true" "$ocsp_selftest_find_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_ocsp_selftest_find-0011: verify when value given in --size is junk no results are returned"
	rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ocsp_host \
                -p $tmp_ocsp_port \
                -n \"$valid_admin_cert\" \
                ocsp-selftest-find --size adafdafds > $ocsp_selftest_find_output" 0 "Run pki ocsp-selftest-find --size adafdafds"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ocsp_host \
                -p $tmp_ocsp_port \
                -n \"$valid_admin_cert\" \
                ocsp-selftest-find --size adafdafds > $ocsp_selftest_find_output 2>&1" 1,255 "Run pki ocsp-selftest-find --size adafdafds"
	rlAssertGrep "NumberFormatException: For input string: \"adafdafds\"" "$ocsp_selftest_find_output"
	rlAssertGroup
        PhaseEnd

	rlPhaseStartTest "pki_ocsp_selftest_find-0012: verify when no value with --size command fails with help message"
	rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ocsp_host \
                -p $tmp_ocsp_port \
                -n \"$valid_admin_cert\" \
                ocsp-selftest-find --size > $ocsp_selftest_find_output 2>&1" 1,255 "No value is passed to pki ocsp-selftest-find --size"
	rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ocsp_host \
                -p $tmp_ocsp_port \
                -n \"$valid_admin_cert\" \
                ocsp-selftest-find --size > $ocsp_selftest_find_output 2>&1" 1,255 "No value is passed to pki ocsp-selftest-find --size"
	rlAssertGrep "Error: Missing argument for option: size" "$ocsp_selftest_find_output"
	rlAssertGrep "usage: ocsp-selftest-find \[FILTER\] \[OPTIONS...\]" "$ocsp_selftest_find_output"
        rlAssertGrep "    --help            Show help options" "$ocsp_selftest_find_output"
        rlAssertGrep "    --size <size>     Page size" "$ocsp_selftest_find_output"
        rlAssertGrep "    --start <start>   Page start" "$ocsp_selftest_find_output"
	rlPhaseEnd

	rlPhaseStartTest "pki_ocsp_selftest_find-0013: verify when --size 1 and --start 1 is specified only 1 OCSP selftest is displayed"
	 rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ocsp_host \
                -p $tmp_ocsp_port \
                -n \"$valid_admin_cert\" \
                ocsp-selftest-find --size 1 --start 1 > $ocsp_selftest_find_output" 0 "Run pki ocsp-selftest-find --size 1 --start 1"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ocsp_host \
                -p $tmp_ocsp_port \
                -n \"$valid_admin_cert\" \
                ocsp-selftest-find --size 1 --start 1 > $ocsp_selftest_find_output" 0 "Run pki ocsp-selftest-find --size 1 --start 1"
        rlAssertGrep "3 entries matched" "$ocsp_selftest_find_output"
        rlAssertGrep "  SelfTest ID: SystemCertsVerification" "$ocsp_selftest_find_output"
        rlAssertGrep "  Enabled at startup: true" "$ocsp_selftest_find_output"
        rlAssertGrep "  Critical at startup: true" "$ocsp_selftest_find_output"
        rlAssertGrep "  Enabled on demand: true" "$ocsp_selftest_find_output"
        rlAssertGrep "  Critical on demand: true" "$ocsp_selftest_find_output"
	rlPhaseEnd

        rlPhaseStartTest "pki_ocsp_selftest_find-0014: verify when no value with --start command fails with help message"
        rlLog "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ocsp_host \
                -p $tmp_ocsp_port \
                -n \"$valid_admin_cert\" \
                ocsp-selftest-find --start > $ocsp_selftest_find_output 2>&1" 1,255 "No value is passed to pki ocsp-selftest-find --size"
        rlRun "pki -d $CERTDB_DIR \
                -c $CERTDB_DIR_PASSWORD \
                -h $tmp_ocsp_host \
                -p $tmp_ocsp_port \
                -n \"$valid_admin_cert\" \
                ocsp-selftest-find --start > $ocsp_selftest_find_output 2>&1" 1,255 "No value is passed to pki ocsp-selftest-find --size"
        rlAssertGrep "Error: Missing argument for option: start" "$ocsp_selftest_find_output"
        rlAssertGrep "usage: ocsp-selftest-find \[FILTER\] \[OPTIONS...\]" "$ocsp_selftest_find_output"
        rlAssertGrep "    --help            Show help options" "$ocsp_selftest_find_output"
        rlAssertGrep "    --size <size>     Page size" "$ocsp_selftest_find_output"
        rlAssertGrep "    --start <start>   Page start" "$ocsp_selftest_find_output"
        rlPhaseEnd
else
	rlPhaseStartCleanup "pki ocsp-selftest-find cleanup: Delete temp dir"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
	rlLog "OCSP subsystem is not installed"
        rlPhaseEnd
fi

}
