#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-mod CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-user-cli-user-mod    Modify existing users in the pki ca subsystem.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Roshni Pattath <rpattath@redhat.com>
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
. /opt/rhqa_pki/pki-cert-cli-lib.sh
. /opt/rhqa_pki/env.sh

######################################################################################
#pki-user-cli-role-user-create-tests should be first executed prior to pki-user-cli-user-add-ca.sh
#pki-user-cli-user-add-ca.sh should be first executed prior to pki-user-cli-user-mod-ca.sh
######################################################################################

########################################################################
# Test Suite Globals
########################################################################

########################################################################
run_pki-user-cli-user-mod-ca_tests(){
	subsystemId=$1
	SUBSYSTEM_TYPE=$2
	MYROLE=$3

	#####Create temporary dir to save the output files #####
	rlPhaseStartSetup "pki_user_cli_user_mod-ca-startup: Create temporary directory"
		rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
		rlRun "pushd $TmpDir"
	rlPhaseEnd
        get_topo_stack $MYROLE $TmpDir/topo_file
        local CA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
        ca_instance_created="False"
        if [ "$TOPO9" = "TRUE" ] ; then
                prefix=$CA_INST
                ca_instance_created=$(eval echo \$${CA_INST}_INSTANCE_CREATED_STATUS)
        elif [ "$MYROLE" = "MASTER" ] ; then
                if [[ $CA_INST == SUBCA* ]]; then
                        prefix=$CA_INST
                        ca_instance_created=$(eval echo \$${CA_INST}_INSTANCE_CREATED_STATUS)
                else
                        prefix=ROOTCA
                        ca_instance_created=$(eval echo \$${CA_INST}_INSTANCE_CREATED_STATUS)
                fi
        else
                prefix=$MYROLE
                ca_instance_created=$(eval echo \$${CA_INST}_INSTANCE_CREATED_STATUS)
        fi

if [ "$ca_instance_created" = "TRUE" ] ;  then
SUBSYSTEM_HOST=$(eval echo \$${MYROLE})
untrusted_cert_db_location=$UNTRUSTED_CERT_DB_LOCATION
untrusted_cert_db_password=$UNTRUSTED_CERT_DB_PASSWORD
user1=ca_agent2
user1fullname="Test ca agent"
user2=abcdefghijklmnopqrstuvwxyx12345678
user3=abc#
user4=abc$
user5=abc@
user6=abc?
user7=0
user1_mod_fullname="Test ca agent Modified"
user1_mod_email="testcaagent@myemail.com"
user1_mod_passwd="Secret1234"
user1_mod_state="NC"
user1_mod_phone="1234567890"
randsym=""
i18nuser=i18nuser
i18nuserfullname="Örjan Äke"
i18nuser_mod_fullname="kakskümmend"
i18nuser_mod_email="kakskümmend@example.com"
	##### pki_user_cli_user_mod-configtest ####
     rlPhaseStartTest "pki_user_cli_user_mod-configtest-001: pki user-mod configuration test"
        rlRun "pki user-mod --help > $TmpDir/pki_user_mod_cfg.out 2>&1" \
               0 \
                "User modification configuration"
        rlAssertGrep "usage: user-mod <User ID> \[OPTIONS...\]" "$TmpDir/pki_user_mod_cfg.out"
        rlAssertGrep "\--email <email>         Email" "$TmpDir/pki_user_mod_cfg.out"
        rlAssertGrep "\--fullName <fullName>   Full name" "$TmpDir/pki_user_mod_cfg.out"
        rlAssertGrep "\--phone <phone>         Phone" "$TmpDir/pki_user_mod_cfg.out"
        rlAssertGrep "\--state <state>         State" "$TmpDir/pki_user_mod_cfg.out"
	rlAssertGrep "\--help                  Show help options" "$TmpDir/pki_user_mod_cfg.out"
	rlAssertNotGrep "Error: Unrecognized option: --help" "$TmpDir/pki_user_mod_cfg.out"
    rlPhaseEnd


     ##### Tests to modify CA users ####
    rlPhaseStartTest "pki_user_cli_user_mod-CA-002: Modify a user's fullname in CA using ROOTCA_adminV"
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-add --fullName=\"$user1fullname\" $user1"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --fullName=\"$user1_mod_fullname\" $user1"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --fullName=\"$user1_mod_fullname\" $user1 > $TmpDir/pki-user-mod-ca-002.out" \
		    0 \
		    "Modified $user1 fullname"
        rlAssertGrep "Modified user \"$user1\"" "$TmpDir/pki-user-mod-ca-002.out"
        rlAssertGrep "User ID: $user1" "$TmpDir/pki-user-mod-ca-002.out"
        rlAssertGrep "Full name: $user1_mod_fullname" "$TmpDir/pki-user-mod-ca-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_mod-CA-003: Modify a user's email,phone,state,password in CA using ROOTCA_adminV"
         rlLog "Executing: pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --email $user1_mod_email --phone $user1_mod_phone --state $user1_mod_state --password $user1_mod_passwd $user1"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --email $user1_mod_email --phone $user1_mod_phone --state $user1_mod_state --password $user1_mod_passwd $user1 > $TmpDir/pki-user-mod-ca-003.out" \
                    0 \
                    "Modified $user1 information"
        rlAssertGrep "Modified user \"$user1\"" "$TmpDir/pki-user-mod-ca-003.out"
        rlAssertGrep "User ID: $user1" "$TmpDir/pki-user-mod-ca-003.out"
        rlAssertGrep "Email: $user1_mod_email" "$TmpDir/pki-user-mod-ca-003.out"

	rlAssertGrep "Phone: $user1_mod_phone" "$TmpDir/pki-user-mod-ca-003.out"

	rlAssertGrep "State: $user1_mod_state" "$TmpDir/pki-user-mod-ca-003.out"

	rlAssertGrep "Email: $user1_mod_email" "$TmpDir/pki-user-mod-ca-003.out"
rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_mod-CA-004:--email with characters and numbers"
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-add --fullName=test u1"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --email abcdefghijklmnopqrstuvwxyx12345678 u1"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --email=abcdefghijklmnopqrstuvwxyx12345678 u1 > $TmpDir/pki-user-mod-ca-004.out" \
                    0 \
                    "Modified user using ${prefix}_adminV with maximum --email length"
        rlAssertGrep "Modified user \"u1\"" "$TmpDir/pki-user-mod-ca-004.out"
        rlAssertGrep "User ID: u1" "$TmpDir/pki-user-mod-ca-004.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-004.out"
        rlAssertGrep "Email: abcdefghijklmnopqrstuvwxyx12345678" "$TmpDir/pki-user-mod-ca-004.out"
    rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_mod-CA-005:--email with maximum length and symbols "
	randsym_b64=$(openssl rand -base64 1024 |  perl -p -e 's/\n//')
        randsym=$(echo $randsym_b64 | tr -d /)
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-add --fullName=test u2"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --email=\"$randsym\" u2"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --email=\"$randsym\" u2 > $TmpDir/pki-user-mod-ca-005.out" \
                    0 \
                    "Modified user using ${prefix}_adminV with maximum --email length and character symbols in it"
        actual_email_string=`cat $TmpDir/pki-user-mod-ca-005.out | grep "Email: " | xargs echo`
        expected_email_string="Email: $randsym"
        rlAssertGrep "Modified user \"u2\"" "$TmpDir/pki-user-mod-ca-005.out"
        rlAssertGrep "User ID: u2" "$TmpDir/pki-user-mod-ca-005.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-005.out"
        if [[ $actual_email_string = $expected_email_string ]] ; then
                rlPass "$expected_email_string found"
        else
                rlFail "$expected_email_string not found"
        fi
    rlPhaseEnd


    rlPhaseStartTest "pki_user_cli_user_mod-CA-006:--email with # character "
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-add --fullName=test u3"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --email # u3"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --email=#  u3 > $TmpDir/pki-user-mod-ca-006.out" \
                    0 \
                    "Modified user using ${prefix}_adminV with --email # character"
        rlAssertGrep "Modified user \"u3\"" "$TmpDir/pki-user-mod-ca-006.out"
        rlAssertGrep "User ID: u3" "$TmpDir/pki-user-mod-ca-006.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-006.out"
        rlAssertGrep "Email: #" "$TmpDir/pki-user-mod-ca-006.out"
    rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_mod-CA-007:--email with * character "
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-add --fullName=test u4"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --email * u4"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --email=*  u4 > $TmpDir/pki-user-mod-ca-007.out" \
                    0 \
                    "Modified user using ${prefix}_adminV with --email * character"
        rlAssertGrep "Modified user \"u4\"" "$TmpDir/pki-user-mod-ca-007.out"
        rlAssertGrep "User ID: u4" "$TmpDir/pki-user-mod-ca-007.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-007.out"
        rlAssertGrep "Email: *" "$TmpDir/pki-user-mod-ca-007.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_mod-CA-008:--email with $ character "
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-add --fullName=test u5"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --email $ u5"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --email=$  u5 > $TmpDir/pki-user-mod-ca-008.out" \
                    0 \
                    "Modified user using ${prefix}_adminV with --email $ character"
        rlAssertGrep "Modified user \"u5\"" "$TmpDir/pki-user-mod-ca-008.out"
        rlAssertGrep "User ID: u5" "$TmpDir/pki-user-mod-ca-008.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-008.out"
        rlAssertGrep "Email: \\$" "$TmpDir/pki-user-mod-ca-008.out"
    rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_mod-CA-009:--email as number 0 "
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-add --fullName=test u6"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --email 0 u6"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --email=0  u6 > $TmpDir/pki-user-mod-ca-009.out " \
                    0 \
                    "Modified user using ${prefix}_adminV with --email 0"
        rlAssertGrep "Modified user \"u6\"" "$TmpDir/pki-user-mod-ca-009.out"
        rlAssertGrep "User ID: u6" "$TmpDir/pki-user-mod-ca-009.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-009.out"
        rlAssertGrep "Email: 0" "$TmpDir/pki-user-mod-ca-009.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_mod-CA-010:--state with characters and numbers "
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-add --fullName=test u7"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --state abcdefghijklmnopqrstuvwxyx12345678 u7"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --state=abcdefghijklmnopqrstuvwxyx12345678 u7 > $TmpDir/pki-user-mod-ca-010.out" \
                    0 \
                    "Modified user using ${prefix}_adminV with maximum --state length"
        rlAssertGrep "Modified user \"u7\"" "$TmpDir/pki-user-mod-ca-010.out"
        rlAssertGrep "User ID: u7" "$TmpDir/pki-user-mod-ca-010.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-010.out"
        rlAssertGrep "State: abcdefghijklmnopqrstuvwxyx12345678" "$TmpDir/pki-user-mod-ca-010.out"
    rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_mod-CA-011:--state with maximum length and symbols "
	randsym_b64=$(openssl rand -base64 1024 |  perl -p -e 's/\n//')
	randsym=$(echo $randsym_b64 | tr -d /)
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-add --fullName=test u8"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --state=\"$randsym\" u8"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --state=\"$randsym\" u8 > $TmpDir/pki-user-mod-ca-011.out" \
                    0 \
                    "Modified user using ${prefix}_adminV with maximum --state length and character symbols in it"
	actual_state_string=`cat $TmpDir/pki-user-mod-ca-011.out | grep "State: " | xargs echo`
        expected_state_string="State: $randsym"
        rlAssertGrep "Modified user \"u8\"" "$TmpDir/pki-user-mod-ca-011.out"
        rlAssertGrep "User ID: u8" "$TmpDir/pki-user-mod-ca-011.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-011.out"
	if [[ $actual_state_string = $expected_state_string ]] ; then
                rlPass "$expected_state_string found"
        else
                rlFail "$expected_state_string not found"
        fi
	rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_mod-CA-012:--state with # character "
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-add --fullName=test u9"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --state # u9"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --state=#  u9 > $TmpDir/pki-user-mod-ca-012.out" \
                    0 \
                    "Modified user using ${prefix}_adminV with --state # character"
        rlAssertGrep "Modified user \"u9\"" "$TmpDir/pki-user-mod-ca-012.out"
        rlAssertGrep "User ID: u9" "$TmpDir/pki-user-mod-ca-012.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-012.out"
        rlAssertGrep "State: #" "$TmpDir/pki-user-mod-ca-012.out"
    rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_mod-CA-013:--state with * character "
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-add --fullName=test u10"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --state * u10"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --state=*  u10 > $TmpDir/pki-user-mod-ca-013.out" \
                    0 \
                    "Modified user using ${prefix}_adminV with --state * character"
        rlAssertGrep "Modified user \"u10\"" "$TmpDir/pki-user-mod-ca-013.out"
        rlAssertGrep "User ID: u10" "$TmpDir/pki-user-mod-ca-013.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-013.out"
        rlAssertGrep "State: *" "$TmpDir/pki-user-mod-ca-013.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_mod-CA-014:--state with $ character "
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-add --fullName=test u11"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --state $ u11"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --state=$  u11 > $TmpDir/pki-user-mod-ca-014.out" \
                    0 \
                    "Modified user using ${prefix}_adminV with --state $ character"
        rlAssertGrep "Modified user \"u11\"" "$TmpDir/pki-user-mod-ca-014.out"
        rlAssertGrep "User ID: u11" "$TmpDir/pki-user-mod-ca-014.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-014.out"
        rlAssertGrep "State: \\$" "$TmpDir/pki-user-mod-ca-014.out"
    rlPhaseEnd
rlPhaseStartTest "pki_user_cli_user_mod-CA-015:--state as number 0 "
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-add --fullName=test u12"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --state 0 u12"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --state=0  u12 > $TmpDir/pki-user-mod-ca-015.out " \
                    0 \
                    "Modified user using ${prefix}_adminV with --state 0"
        rlAssertGrep "Modified user \"u12\"" "$TmpDir/pki-user-mod-ca-015.out"
        rlAssertGrep "User ID: u12" "$TmpDir/pki-user-mod-ca-015.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-015.out"
        rlAssertGrep "State: 0" "$TmpDir/pki-user-mod-ca-015.out"
    rlPhaseEnd
        
    rlPhaseStartTest "pki_user_cli_user_mod-CA-016:--phone with characters and numbers"
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-add --fullName=test u13"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --phone abcdefghijklmnopqrstuvwxyx12345678 u13"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --phone=abcdefghijklmnopqrstuvwxyx12345678 u13 > $TmpDir/pki-user-mod-ca-016.out" \
                    0 \
                    "Modified user using ${prefix}_adminV with maximum --phone length"
        rlAssertGrep "Modified user \"u13\"" "$TmpDir/pki-user-mod-ca-016.out"
        rlAssertGrep "User ID: u13" "$TmpDir/pki-user-mod-ca-016.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-016.out"
        rlAssertGrep "Phone: abcdefghijklmnopqrstuvwxyx12345678" "$TmpDir/pki-user-mod-ca-016.out"
    rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_mod-CA-017:--phone with maximum length and symbols "
	randsym_b64=$(openssl rand -base64 1024 |  perl -p -e 's/\n//')
        randsym=$(echo $randsym_b64 | tr -d /)
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-add --fullName=test usr1"
	special_symbols="*$#"
	command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-mod --phone='$randsym$special_symbols' usr1"
	rlLog "Executing: $command"
	errmsg="PKIException: LDAP error (21): error result"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify user using ${prefix}_adminV with maximum length --phone with character symbols in it"
    rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_mod-CA-018:--phone with maximum length and numbers only "
	randhex=$(openssl rand -hex 1024 |  perl -p -e 's/\n//')
        randhex_covup=${randhex^^}
        randsym=$(echo "ibase=16;$randhex_covup" | BC_LINE_LENGTH=0 bc)
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --phone=\"$randsym\" usr1"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --phone=\"$randsym\"  usr1 > $TmpDir/pki-user-mod-ca-018.out"\
                    0 \
                    "Modify user with maximum length and numbers only"
	rlAssertGrep "Modified user \"usr1\"" "$TmpDir/pki-user-mod-ca-018.out"
        rlAssertGrep "User ID: usr1" "$TmpDir/pki-user-mod-ca-018.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-018.out"
        rlAssertGrep "Phone: $randsym" "$TmpDir/pki-user-mod-ca-018.out"	
    rlPhaseEnd


    rlPhaseStartTest "pki_user_cli_user_mod-CA-019:--phone with \# character"
	 rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-add --fullName=test usr2"
	command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-mod --phone=\"#\" usr2"
	errmsg="PKIException: LDAP error (21): error result"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify user using ${prefix}_adminV --phone with character symbols in it"
    rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_mod-CA-020:--phone with * character "
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-add --fullName=test usr3"
	command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-mod --phone=\"*\" usr3"
	errmsg="PKIException: LDAP error (21): error result"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify user using ${prefix}_adminV --phone with character symbols in it"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_mod-CA-021:--phone with $ character "
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-add --fullName=test usr4"
	command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-mod --phone $ usr4"
	errmsg="PKIException: LDAP error (21): error result"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify user using ${prefix}_adminV --phone with character symbols in it"
    rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_mod-CA-022:--phone as negative number -1230 "
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-add --fullName=test u14"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --phone -1230 u14"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --phone=-1230  u14 > $TmpDir/pki-user-mod-ca-022.out " \
                    0 \
                    "Modifying User --phone negative value"
        rlAssertGrep "Modified user \"u14\"" "$TmpDir/pki-user-mod-ca-022.out"
        rlAssertGrep "User ID: u14" "$TmpDir/pki-user-mod-ca-022.out"
        rlAssertGrep "Full name: test" "$TmpDir/pki-user-mod-ca-022.out"
        rlAssertGrep "Phone: -1230" "$TmpDir/pki-user-mod-ca-022.out"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/704"
    rlPhaseEnd
#======https://fedorahosted.org/pki/ticket/704============#

 rlPhaseStartTest "pki_user_cli_user_mod-CA-023: Modify a user to CA with -t option"
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-add --fullName=test u15"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                   -t ca \
                    user-mod --fullName=\"$user1fullname\"  u15"

        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                   -t ca \
                    user-mod --fullName=\"$user1fullname\"  u15 > $TmpDir/pki-user-mod-ca-023.out" \
                    0 \
                    "Modified user u15 to CA"
        rlAssertGrep "Modified user \"u15\"" "$TmpDir/pki-user-mod-ca-023.out"
        rlAssertGrep "User ID: u15" "$TmpDir/pki-user-mod-ca-023.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-mod-ca-023.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_mod-CA-024-tier1:  Modify a user -- missing required option user id"
	command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -t ca user-mod --fullName='$user1fullname'"
	errmsg="Error: No User ID specified."
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Modify user -- missing required option user id"
    rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_mod-CA-025-tier1:  Modify a user -- all options provided"
        email="ca_agent2@myemail.com"
        user_password="agent2Password"
        phone="1234567890"
        state="NC"
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-add --fullName=test u16"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                   -t ca \
                    user-mod --fullName=\"$user1fullname\"  \
                    --email $email \
                    --password $user_password \
                    --phone $phone \
                    --state $state \
                     u16"

        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                   -t ca \
                    user-mod --fullName=\"$user1fullname\"  \
                    --email $email \
                    --password $user_password \
                    --phone $phone \
                    --state $state \
                     u16 >  $TmpDir/pki-user-mod-ca-025.out" \
                    0 \
                    "Modify user u16 to CA -- all options provided"
        rlAssertGrep "Modified user \"u16\"" "$TmpDir/pki-user-mod-ca-025.out"
        rlAssertGrep "User ID: u16" "$TmpDir/pki-user-mod-ca-025.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-mod-ca-025.out"
        rlAssertGrep "Email: $email" "$TmpDir/pki-user-mod-ca-025.out"
        rlAssertGrep "Phone: $phone" "$TmpDir/pki-user-mod-ca-025.out"
        rlAssertGrep "State: $state" "$TmpDir/pki-user-mod-ca-025.out"
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-del u16"
    rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_mod-CA-026: Modify user with --password "
        userpw="pass"
	command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -t ca user-mod $user1 --fullName='$user1fullname' --password=$userpw"
        errmsg="PKIException: The password must be at least 8 characters"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Modify a user --must be at least 8 characters --password"
    rlPhaseEnd

##### Tests to modify users using revoked cert#####
    rlPhaseStartTest "pki_user_cli_user_mod-CA-027: Should not be able to modify user using a revoked cert ROOTCA_adminR"
	command="pki -d $CERTDB_DIR -n ${prefix}_adminR -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-mod --fullName='$user1fullname' $user1"
	errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify user $user1 using a user having revoked cert"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_mod-CA-028: Should not be able to modify user using an agent or a revoked cert ROOTCA_agentR"
	command="pki -d $CERTDB_DIR -n ${prefix}_agentR -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-mod --fullName='$user1fullname' $user1"
	errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify user $user1 using a user having revoked cert"
    rlPhaseEnd

##### Tests to modify users using an agent user#####
    rlPhaseStartTest "pki_user_cli_user_mod-CA-029: Should not be able to modify user using a ROOTCA_agentV user"
	command="pki -d $CERTDB_DIR -n ${prefix}_agentV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-mod --fullName='$user1fullname' $user1"
	errmsg="ForbiddenException: Authorization Error"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify user $user1 using a agent cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_mod-CA-030: Should not be able to modify user using a ROOTCA_agentR user"
	command="pki -d $CERTDB_DIR -n ${prefix}_agentR -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-mod --fullName='$user1fullname' $user1"
	errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify user $user1 using a agent cert"
    rlPhaseEnd

##### Tests to modify users using expired cert#####
    rlPhaseStartTest "pki_user_cli_user_mod-CA-031: Should not be able to modify user using a ROOTCA_adminE cert"
        rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
	command="pki -d $CERTDB_DIR -n ${prefix}_adminE -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-mod --fullName='$user1fullname' $user1"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify user $user1 using an expired admin cert"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/934"
        rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_mod-CA-032: Should not be able to modify user using a ROOTCA_agentE cert"
        rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
	command="pki -d $CERTDB_DIR -n ${prefix}_agentE -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-mod --fullName='$user1fullname' $user1"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.users, operation: execute"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify user $user1 using an expired agent cert"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/934"
        rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
    rlPhaseEnd

 ##### Tests to modify users using audit users#####
    rlPhaseStartTest "pki_user_cli_user_mod-CA-033: Should not be able to modify user using a ROOTCA_auditV"
	command="pki -d $CERTDB_DIR -n ${prefix}_auditV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-mod --fullName='$user1fullname' $user1"
	errmsg="ForbiddenException: Authorization Error"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify user $user1 using an audit cert"
    rlPhaseEnd

        ##### Tests to modify users using operator user###
    rlPhaseStartTest "pki_user_cli_user_mod-CA-034: Should not be able to modify user using a ROOTCA_operatorV"
	command="pki -d $CERTDB_DIR -n ${prefix}_operatorV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-mod --fullName='$user1fullname' $user1"
	errmsg="ForbiddenException: Authorization Error"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify user $user1 as ${prefix}_operatorV"
    rlPhaseEnd

##### Tests to modify users using role_user_UTCA user's certificate will be issued by an untrusted CA users#####
    rlPhaseStartTest "pki_user_cli_user_mod-CA-035: Should not be able to modify user using a cert created from a untrusted CA ROOTCA_adminUTCA"
	command="pki -d $untrusted_cert_db_location -n role_user_UTCA -c $untrusted_cert_db_password -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-mod --fullName='$user1fullname' $user1"
	errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Cannot modify user $user1 as role_user_UTCA"
    rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_mod-CA-036:  Modify a user -- User ID does not exist"
        command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -t ca -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-mod --fullName='$user1fullname'  u17"
        errmsg="ResourceNotFoundException: No such object."
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Modifying a non existing user"
    rlPhaseEnd

##### Tests to modify CA users with empty parameters ####

    rlPhaseStartTest "pki_user_cli_user_mod-CA-037: Modify a user in CA using ROOTCA_adminV - fullname is empty"
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                   -t ca \
                    user-add --fullName=\"$user1fullname\"  \
                    --email $email \
                    --password $user_password \
                    --phone $phone \
                    --state $state \
                     u16"
	command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-mod --fullName=\"\" u16"
	errmsg="BadRequestException: Invalid DN syntax."
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Modifying User --fullname is empty"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/833"
    rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_mod-CA-038: Modify a user in CA using ROOTCA_adminV - email is empty"
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-show u16 > $TmpDir/pki-user-mod-ca-038_1.out" 
	rlAssertGrep "User \"u16\"" "$TmpDir/pki-user-mod-ca-038_1.out"
        rlAssertGrep "User ID: u16" "$TmpDir/pki-user-mod-ca-038_1.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-mod-ca-038_1.out"
	rlAssertGrep "Email: $email" "$TmpDir/pki-user-mod-ca-038_1.out"
        rlAssertGrep "Phone: $phone" "$TmpDir/pki-user-mod-ca-038_1.out"
        rlAssertGrep "State: $state" "$TmpDir/pki-user-mod-ca-038_1.out"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --email=\"\" u16"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --email=\"\" u16 > $TmpDir/pki-user-mod-ca-038_2.out" \
                    0 \
                    "Modifying $user1 with empty email"
	rlAssertGrep "Modified user \"u16\"" "$TmpDir/pki-user-mod-ca-038_2.out"
        rlAssertGrep "User ID: u16" "$TmpDir/pki-user-mod-ca-038_2.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-mod-ca-038_2.out"
        rlAssertGrep "Phone: $phone" "$TmpDir/pki-user-mod-ca-038_2.out"
        rlAssertGrep "State: $state" "$TmpDir/pki-user-mod-ca-038_2.out"
    rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_mod-CA-039: Modify a user in CA using ROOTCA_adminV - phone is empty"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-show u16 > $TmpDir/pki-user-mod-ca-039_1.out"
	rlAssertGrep "User \"u16\"" "$TmpDir/pki-user-mod-ca-039_1.out"
        rlAssertGrep "User ID: u16" "$TmpDir/pki-user-mod-ca-039_1.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-mod-ca-039_1.out"
        rlAssertGrep "Phone: $phone" "$TmpDir/pki-user-mod-ca-039_1.out"
        rlAssertGrep "State: $state" "$TmpDir/pki-user-mod-ca-039_1.out"
	command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-mod --phone=\"\" u16"
	rlRun "$command > $TmpDir/pki-user-mod-ca-039_2.out" 0 "Modify user with phone is empty"
	rlAssertGrep "Modified user \"u16\"" "$TmpDir/pki-user-mod-ca-039_2.out"
        rlAssertGrep "User ID: u16" "$TmpDir/pki-user-mod-ca-039_2.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-mod-ca-039_2.out"
        rlAssertGrep "State: $state" "$TmpDir/pki-user-mod-ca-039_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_user_cli_user_mod-CA-040: Modify a user in CA using ROOTCA_adminV - state is empty"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-show u16 > $TmpDir/pki-user-mod-ca-040_1.out"
	rlAssertGrep "User \"u16\"" "$TmpDir/pki-user-mod-ca-040_1.out"
        rlAssertGrep "User ID: u16" "$TmpDir/pki-user-mod-ca-040_1.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-mod-ca-040_1.out"
        rlAssertGrep "State: $state" "$TmpDir/pki-user-mod-ca-040_1.out"
	command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-mod --state=\"\" u16"
	rlRun "$command > $TmpDir/pki-user-mod-ca-040_2.out" 0 "Modify user with empty state"
	rlAssertGrep "Modified user \"u16\"" "$TmpDir/pki-user-mod-ca-040_2.out"
        rlAssertGrep "User ID: u16" "$TmpDir/pki-user-mod-ca-040_2.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-mod-ca-040_2.out"
    rlPhaseEnd

##### Tests to modify CA users with the same value ####

    rlPhaseStartTest "pki_user_cli_user_mod-CA-041: Modify a user in CA using ROOTCA_adminV - fullname same old value"
	rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-show $user1 > $TmpDir/pki-user-mod-ca-041_1.out"
	rlAssertGrep "User \"$user1\"" "$TmpDir/pki-user-mod-ca-041_1.out"
	rlAssertGrep "User ID: $user1" "$TmpDir/pki-user-mod-ca-041_1.out"
        rlAssertGrep "Full name: $user1_mod_fullname" "$TmpDir/pki-user-mod-ca-041_1.out"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --fullName=\"$user1_mod_fullname\" $user1"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --fullName=\"$user1_mod_fullname\" $user1 > $TmpDir/pki-user-mod-ca-041_2.out" \
                    0 \
                    "Modifying $user1 with same old fullname"
	rlAssertGrep "Modified user \"$user1\"" "$TmpDir/pki-user-mod-ca-041_2.out"
        rlAssertGrep "User ID: $user1" "$TmpDir/pki-user-mod-ca-041_2.out"
        rlAssertGrep "Full name: $user1_mod_fullname" "$TmpDir/pki-user-mod-ca-041_2.out"
    rlPhaseEnd

##### Tests to modify CA users adding values to params which were previously empty ####

    rlPhaseStartTest "pki_user_cli_user_mod-CA-042: Modify a user in CA using ROOTCA_adminV - adding values to params which were previously empty"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-show u16 > $TmpDir/pki-user-mod-ca-042_1.out"
        rlAssertGrep "User \"u16\"" "$TmpDir/pki-user-mod-ca-042_1.out"
        rlAssertGrep "User ID: u16" "$TmpDir/pki-user-mod-ca-042_1.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-mod-ca-042_1.out"
	rlAssertNotGrep "Email:" "$TmpDir/pki-user-mod-ca-042_1.out"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --email=\"$email\" u16"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --email=\"$email\" u16 > $TmpDir/pki-user-mod-ca-042_2.out" \
                    0 \
                    "Modifying u16 with new value for phone which was previously empty"
        rlAssertGrep "Modified user \"u16\"" "$TmpDir/pki-user-mod-ca-042_2.out"
        rlAssertGrep "User ID: u16" "$TmpDir/pki-user-mod-ca-042_2.out"
        rlAssertGrep "Full name: $user1fullname" "$TmpDir/pki-user-mod-ca-042_2.out"
	rlAssertGrep "Email: $email" "$TmpDir/pki-user-mod-ca-042_2.out"
    rlPhaseEnd

##### Tests to modify CA users having i18n chars in the fullname ####

rlPhaseStartTest "pki_user_cli_user_mod-CA-043: Modify a user's fullname having i18n chars in CA using ROOTCA_adminV"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-add --fullName=\"$i18nuserfullname\" $i18nuser"
        rlLog "Executing: pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --fullName=\"$i18nuser_mod_fullname\" $i18nuser"
        rlRun "pki -d $CERTDB_DIR \
                   -n ${prefix}_adminV \
                   -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                    user-mod --fullName=\"$i18nuser_mod_fullname\" $i18nuser > $TmpDir/pki-user-mod-ca-043.out" \
                   0 \
                    "Modified $i18nuser fullname"
        rlAssertGrep "Modified user \"$i18nuser\"" "$TmpDir/pki-user-mod-ca-043.out"
        rlAssertGrep "User ID: $i18nuser" "$TmpDir/pki-user-mod-ca-043.out"
        rlAssertGrep "Full name: $i18nuser_mod_fullname" "$TmpDir/pki-user-mod-ca-043.out"
    rlPhaseEnd

##### Tests to modify CA users having i18n chars in email ####

rlPhaseStartTest "pki_user_cli_user_mod-CA-044: Modify a user's email having i18n chars in CA using ROOTCA_adminV"
	command="pki -d $CERTDB_DIR -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) user-mod --email=$i18nuser_mod_email $i18nuser"
	errmsg="PKIException: LDAP error (21): error result"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Modified $i18nuser email should fail"
	rlLog "FAIL:https://fedorahosted.org/pki/ticket/860"
    rlPhaseEnd

#===Deleting users===#
rlPhaseStartCleanup "pki_user_cli_user_cleanup: Deleting role users"

        i=1
        while [ $i -lt 17 ] ; do
               rlRun "pki -d $CERTDB_DIR \
                          -n ${prefix}_adminV \
                          -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           user-del  u$i > $TmpDir/pki-user-del-ca-user-00$i.out" \
                           0 \
                           "Deleted user  u$i"
                rlAssertGrep "Deleted user \"u$i\"" "$TmpDir/pki-user-del-ca-user-00$i.out"
                let i=$i+1
        done
        j=1
        while [ $j -lt 5 ] ; do
               rlRun "pki -d $CERTDB_DIR \
                          -n ${prefix}_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                   -h $SUBSYSTEM_HOST \
                           -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           user-del  usr$j > $TmpDir/pki-user-del-ca-usr-00$j.out" \
                           0 \
                           "Deleted user usr$j"
                rlAssertGrep "Deleted user \"usr$j\"" "$TmpDir/pki-user-del-ca-usr-00$j.out"
                let j=$j+1
        done
        j=1
        while [ $j -lt 2 ] ; do
               eval usr=\$user$j
               rlRun "pki -d $CERTDB_DIR \
                          -n ${prefix}_adminV \
                          -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           user-del  $usr > $TmpDir/pki-user-del-ca-user-symbol-00$j.out" \
                           0 \
                           "Deleted user $usr"
                rlAssertGrep "Deleted user \"$usr\"" "$TmpDir/pki-user-del-ca-user-symbol-00$j.out"
                let j=$j+1
        done
	rlRun "pki -d $CERTDB_DIR \
                          -n ${prefix}_adminV \
                          -c $CERTDB_DIR_PASSWORD \
 		   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           user-del $i18nuser > $TmpDir/pki-user-del-ca-i18nuser-001.out" \
                           0 \
                           "Deleted user $i18nuser"
                rlAssertGrep "Deleted user \"$i18nuser\"" "$TmpDir/pki-user-del-ca-i18nuser-001.out"
$i18nuser
	#Delete temporary directory
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"

    rlPhaseEnd
 else
	rlLog "CA instance not installed"
 fi
}
