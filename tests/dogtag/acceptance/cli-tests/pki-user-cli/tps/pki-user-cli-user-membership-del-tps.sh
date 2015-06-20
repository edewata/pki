#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-membership-del TPS CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Asha Akkiangady <aakkiang@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2015 Red Hat, Inc. All rights reserved.
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
#create_role_users.sh should be first executed prior to pki-user-cli-user-membership-add-tps.sh
######################################################################################

run_pki-user-cli-user-membership-del-tps_tests(){
	subsystemId=$1
	SUBSYSTEM_TYPE=$2
	MYROLE=$3
	caId=$4
	CA_HOST=$5
	prefix=$subsystemId

	rlPhaseStartSetup "pki_user_cli_user_membership-del-TPS-001: Create temporary directory"
                rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
                rlRun "pushd $TmpDir"
        rlPhaseEnd

        get_topo_stack $MYROLE $TmpDir/topo_file
        local TPS_INST=$(cat $TmpDir/topo_file | grep MY_TPS | cut -d= -f2)
        tps_instance_created="False"
        if [ "$TOPO9" = "TRUE" ] ; then
                prefix=$TPS_INST
                tps_instance_created=$(eval echo \$${TPS_INST}_INSTANCE_CREATED_STATUS)
        elif [ "$MYROLE" = "MASTER" ] ; then
                        prefix=TPS1
                        tps_instance_created=$(eval echo \$${TPS_INST}_INSTANCE_CREATED_STATUS)
        else
                prefix=$MYROLE
                tps_instance_created=$(eval echo \$${TPS_INST}_INSTANCE_CREATED_STATUS)
        fi

  if [ "$tps_instance_created" = "TRUE" ] ;  then
	SUBSYSTEM_HOST=$(eval echo \$${MYROLE})
	untrusted_cert_nickname=role_user_UTCA

	#Available groups tps-group-find
	groupid1="TPS Agents"
        groupid2="TPS Officers"
        groupid3="Administrators"
        groupid4="TPS Operators"

        rlPhaseStartTest "pki_user_cli_user_membership-del-TPS-002: pki user-membership-del --help configuration test"
                rlRun "pki user-membership-del --help > $TmpDir/pki_user_membership_del_cfg.out 2>&1" \
                        0 \
                       "pki user-membership-del --help"
                rlAssertGrep "usage: user-membership-del <User ID> <Group ID> \[OPTIONS...\]" "$TmpDir/pki_user_membership_del_cfg.out"
                rlAssertGrep "\--help   Show help options" "$TmpDir/pki_user_membership_del_cfg.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-del-TPS-003: pki user-membership-del configuration test"
                rlRun "pki user-membership-del > $TmpDir/pki_user_membership_del_2_cfg.out 2>&1" \
                       255 \
                       "pki user-membership-del"
                rlAssertGrep "Error: Incorrect number of arguments specified." "$TmpDir/pki_user_membership_del_2_cfg.out"
                rlAssertGrep "usage: user-membership-del <User ID> <Group ID> \[OPTIONS...\]" "$TmpDir/pki_user_membership_del_2_cfg.out"
                rlAssertGrep "\--help   Show help options" "$TmpDir/pki_user_membership_del_2_cfg.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-del-TPS-004: Delete user-membership when user is added to different groups"
                i=1
                while [ $i -lt 5 ] ; do
                       rlLog "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				  -t tps \
                                   user-add --fullName=\"fullNameu$i\" u$i "
                       rlRun "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				  -t tps \
                                   user-add --fullName=\"fullNameu$i\" u$i > $TmpDir/pki-user-membership-add-user-add-tps-00$i.out" \
                                   0 \
                                   "Adding user u$i"
                        rlAssertGrep "Added user \"u$i\"" "$TmpDir/pki-user-membership-add-user-add-tps-00$i.out"
                        rlAssertGrep "User ID: u$i" "$TmpDir/pki-user-membership-add-user-add-tps-00$i.out"
                        rlAssertGrep "Full name: fullNameu$i" "$TmpDir/pki-user-membership-add-user-add-tps-00$i.out"
                        rlLog "Showing the user"
                        rlRun "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				   -t tps \
                                    user-show u$i > $TmpDir/pki-user-membership-add-user-show-tps-00$i.out" \
                                    0 \
                                    "Show pki TPS_adminV user"
                        rlAssertGrep "User \"u$i\"" "$TmpDir/pki-user-membership-add-user-show-tps-00$i.out"
                        rlAssertGrep "User ID: u$i" "$TmpDir/pki-user-membership-add-user-show-tps-00$i.out"
                        rlAssertGrep "Full name: fullNameu$i" "$TmpDir/pki-user-membership-add-user-show-tps-00$i.out"
                        rlLog "Adding the user to a group"
                        eval gid=\$groupid$i
                        rlLog "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				  -t tps \
                                   user-membership-add u$i \"$gid\""
                        rlRun "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				  -t tps \
                                   user-membership-add u$i \"$gid\" > $TmpDir/pki-user-membership-add-groupadd-tps-00$i.out" \
                                   0 \
                                   "Adding user u$i to group \"$gid\""
                        rlAssertGrep "Added membership in \"$gid\"" "$TmpDir/pki-user-membership-add-groupadd-tps-00$i.out"
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-add-groupadd-tps-00$i.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				  -t tps \
                                   user-membership-find u$i > $TmpDir/pki-user-membership-add-groupadd-find-tps-00$i.out" \
                                   0 \
                                   "Check user is in group \"$gid\""
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-add-groupadd-find-tps-00$i.out"
			rlLog "Delete the user from the group"
                        rlRun "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				   -t tps \
                                    user-membership-del u$i \"$gid\"  > $TmpDir/pki-user-membership-del-groupdel-del-tps-00$i.out" \
                                    0 \
                                    "User deleted from group \"$gid\""
                        rlAssertGrep "Deleted membership in group \"$gid\"" "$TmpDir/pki-user-membership-del-groupdel-del-tps-00$i.out"
                        let i=$i+1
                done
        rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-del-TPS-005: Delete user-membership when user is added to many groups"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            user-add --fullName=\"fullName_userall\" userall > $TmpDir/pki-user-membership-add-user-add-tps-userall-001.out" \
                            0 \
                            "Adding user userall"
                rlAssertGrep "Added user \"userall\"" "$TmpDir/pki-user-membership-add-user-add-tps-userall-001.out"
                rlAssertGrep "User ID: userall" "$TmpDir/pki-user-membership-add-user-add-tps-userall-001.out"
                rlAssertGrep "Full name: fullName_userall" "$TmpDir/pki-user-membership-add-user-add-tps-userall-001.out"
                rlLog "Adding the user to all the groups"
                i=1
                while [ $i -lt 5 ] ; do
                        eval gid=\$groupid$i
                        rlLog "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				   -t tps \
                                    user-membership-add userall \"$gid\""
                        rlRun "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				   -t tps \
                                    user-membership-add userall \"$gid\" > $TmpDir/pki-user-membership-add-groupadd-tps-userall-00$i.out" \
                                    0 \
                                    "Adding user userall to group \"$gid\""
                        rlAssertGrep "Added membership in \"$gid\"" "$TmpDir/pki-user-membership-add-groupadd-tps-userall-00$i.out"
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-add-groupadd-tps-userall-00$i.out"
                        rlLog "Check if the user is added to the group"
                        rlRun "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				   -t tps \
                                    user-membership-find userall > $TmpDir/pki-user-membership-add-groupadd-find-tps-userall-00$i.out" \
                                    0 \
                                    "Check user membership with group \"$gid\""
                        rlAssertGrep "Group: $gid" "$TmpDir/pki-user-membership-add-groupadd-find-tps-userall-00$i.out"
                        let i=$i+1
                done
		rlLog "Delete user from all the groups"
                i=1
                while [ $i -lt 5 ] ; do
                        eval gid=\$groupid$i
                        rlLog "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				   -t tps \
                                    user-membership-del userall \"$gid\""
                        rlRun "pki -d $CERTDB_DIR \
                                   -n ${prefix}_adminV \
                                   -c $CERTDB_DIR_PASSWORD \
 				   -h $SUBSYSTEM_HOST \
 				   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				   -t tps \
                                    user-membership-del userall \"$gid\" > $TmpDir/pki-user-membership-del-groupadd-tps-userall-00$i.out" \
                                    0 \
                                    "Delete userall from group \"$gid\""
                        rlAssertGrep "Deleted membership in group \"$gid\"" "$TmpDir/pki-user-membership-del-groupadd-tps-userall-00$i.out"
                        let i=$i+1
                done
        rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-del-TPS-006: Missing required option <Group id> while deleting a user from a group"
                rlRun "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				  -t tps \
                                   user-add --fullName=\"fullName_user1\" user1 > $TmpDir/pki-user-membership-add-user-add-tps-user1-001.out" \
                                   0 \
                                   "Adding user user1"
                rlAssertGrep "Added user \"user1\"" "$TmpDir/pki-user-membership-add-user-add-tps-user1-001.out"
                rlAssertGrep "User ID: user1" "$TmpDir/pki-user-membership-add-user-add-tps-user1-001.out"
                rlAssertGrep "Full name: fullName_user1" "$TmpDir/pki-user-membership-add-user-add-tps-user1-001.out"
                rlRun "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				  -t tps \
                                   user-membership-add user1 \"Administrators\" > $TmpDir/pki-user-membership-add-groupadd-tps-user1-001.out" \
                                   0 \
                                   "Adding user user1 to group \"Administrators\""
                rlAssertGrep "Added membership in \"Administrators\"" "$TmpDir/pki-user-membership-add-groupadd-tps-user1-001.out"
                rlRun "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				  -t tps \
                                   user-membership-del user1 > $TmpDir/pki-user-membership-del-groupadd-tps-user1-001.out 2>&1" \
                                   255 \
                                   "Cannot delete user from group, Missing required option <Group id>"
                rlAssertGrep "usage: user-membership-del <User ID> <Group ID>" "$TmpDir/pki-user-membership-del-groupadd-tps-user1-001.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_user_cli_user_membership-del-TPS-007: Missing required option <User ID> while deleting a user from a group"
                rlRun "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				  -t tps \
                                   user-add --fullName=\"fullName_user2\" user2 > $TmpDir/pki-user-membership-add-user-add-tps-user1-001.out" \
                                   0 \
                                   "Adding user user2"
                rlAssertGrep "Added user \"user2\"" "$TmpDir/pki-user-membership-add-user-add-tps-user1-001.out"
                rlAssertGrep "User ID: user2" "$TmpDir/pki-user-membership-add-user-add-tps-user1-001.out"
                rlAssertGrep "Full name: fullName_user2" "$TmpDir/pki-user-membership-add-user-add-tps-user1-001.out"
                rlRun "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				  -t tps \
                                   user-membership-add user2 \"Administrators\" > $TmpDir/pki-user-membership-add-groupadd-tps-user1-001.out" \
                                   0 \
                                   "Adding user user2 to group \"Administrators\""
                rlAssertGrep "Added membership in \"Administrators\"" "$TmpDir/pki-user-membership-add-groupadd-tps-user1-001.out"
                rlRun "pki -d $CERTDB_DIR \
                                  -n ${prefix}_adminV \
                                  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				  -t tps \
                                   user-membership-del \"\" \"Administrators\" > $TmpDir/pki-user-membership-del-groupadd-tps-user1-001.out 2>&1" \
                                   255 \
                                   "cannot delete user from group, Missing required option <user id>"
                rlAssertGrep "ProcessingException: Unable to invoke request" "$TmpDir/pki-user-membership-del-groupadd-tps-user1-001.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-del-TPS-008: Should not be able to user-membership-del using a revoked cert TPS_adminR"
                command="pki -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -d $CERTDB_DIR -n ${prefix}_adminR -c $CERTDB_DIR_PASSWORD -t tps user-membership-del user2 \"Administrators\""
                rlLog "Executing $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to delete user-membership using a revoked cert TPS_adminR"
		rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1202"
                rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1134"
                rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1182"
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-del-TPS-009:  Should not be able to user-membership-del using an agent with revoked cert TPS_agentR"
		command="pki -d $CERTDB_DIR -n ${prefix}_agentR -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -t tps user-membership-del user2 \"Administrators\""
		rlLog "Executing $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to delete user-membership using a revoked cert TPS_agentR"
		rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1202"
                rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1134"
                rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1182"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-del-TPS-010: Should not be able to user-membership-del using a valid agent TPS_agentV user"
		command="pki -d $CERTDB_DIR -n ${prefix}_agentV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -t tps user-membership-del user2 \"Administrators\""
		rlLog "Executing $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to delete user-membership using a valid agent cert TPS_agentV"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-del-TPS-011: Should not be able to user-membership-del using admin user with expired cert TPS_adminE"
		rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
                rlRun "date"
                command="pki -d $CERTDB_DIR -n ${prefix}_adminE -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -c $CERTDB_DIR_PASSWORD -t tps  user-membership-del user2 \"Administrators\""
		rlLog "Executing $command"
                errmsg="ProcessingException: Unable to invoke request"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to user-membership-del using admin user with expired cert TPS_adminE"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-del-TPS-012: Should not be able to user-membership-del using TPS_agentE cert"
		rlRun "date --set='+2 days'" 0 "Set System date 2 days ahead"
                rlRun "date"
                command="pki -d $CERTDB_DIR -n ${prefix}_agentE -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -t tps user-membership-del user2 \"Administrators\""
		rlLog "Executing $command"
                errmsg="ProcessingException: Unable to invoke request"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to user-membership-del using TPS_agentE cert"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-del-TPS-013: Should not be able to user-membership-del using TPS_officerV cert"
                command="pki -d $CERTDB_DIR -n ${prefix}_officerV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -t tps user-membership-del user2 \"Administrators\""
		rlLog "Executing $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to user-membership-del using TPS_officerV cert"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-del-TPS-014: Should not be able to user-membership-del using TPS_operatorV cert"
		command="pki -d $CERTDB_DIR -n ${prefix}_operatorV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -t tps user-membership-del user2 \"Administrators\""
		rlLog "Executing $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to user-membership-del using TPS_operatorV cert"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-del-TPS-015: Should not be able to user-membership-del using TPS_adminUTCA cert"
                command="pki -d $UNTRUSTED_CERT_DB_LOCATION -n $untrusted_cert_nickname -c $UNTRUSTED_CERT_DB_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -t tps user-membership-del user2 \"Administrators\""
		rlLog "Executing $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to user-membership-del using role_user_UTCA cert"
		rlLog "PKI Ticket::  https://fedorahosted.org/pki/ticket/962"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-del-TPS-016: Delete user-membership for user fullname with i18n characters"
		user6="u6"
                rlLog "user-add user fullname Éric Têko with i18n characters"
                rlLog "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            user-add --fullName='Éric Têko' $user6"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            user-add --fullName='Éric Têko' $user6" \
                            0 \
                            "Adding user fullname  ÉricTêko with i18n characters"
                rlLog "Create a group dadministʁasjɔ̃ with i18n characters"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            group-add 'dadministʁasjɔ̃' --description \"Admininstartors in French\" 2>&1 > $TmpDir/pki-user-membership-add-groupadd-tps-017_1.out" \
                            0 \
                            "Adding group dadministʁasjɔ̃ with i18n characters"
                rlAssertGrep "Added group \"dadministʁasjɔ̃\"" "$TmpDir/pki-user-membership-add-groupadd-tps-017_1.out"
                rlAssertGrep "Group ID: dadministʁasjɔ̃" "$TmpDir/pki-user-membership-add-groupadd-tps-017_1.out"
                rlAssertGrep "Description: Admininstartors in French" "$TmpDir/pki-user-membership-add-groupadd-tps-017_1.out"
                rlLog "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            user-membership-add $user6 \"dadministʁasjɔ̃\""
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            user-membership-add $user6 \"dadministʁasjɔ̃\" > $TmpDir/pki-user-membership-del-groupadd-tps-017_2.out" \
                            0 \
                            "Adding user ÉricTêko to group \"dadministʁasjɔ̃\""
                rlAssertGrep "Added membership in \"dadministʁasjɔ̃\"" "$TmpDir/pki-user-membership-del-groupadd-tps-017_2.out"
                rlAssertGrep "Group: dadministʁasjɔ̃" "$TmpDir/pki-user-membership-del-groupadd-tps-017_2.out"
		rlLog "Delete user-membership from the group"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            user-membership-del $user6  'dadministʁasjɔ̃' > $TmpDir/pki-user-membership-del-tps-017_3.out" \
                            0 \
                            "Delete user-membership from group \"dadministʁasjɔ̃\""
		rlAssertGrep "Deleted membership in group \"dadministʁasjɔ̃\"" "$TmpDir/pki-user-membership-del-tps-017_3.out"
		rlLog "Check if the user is removed from the group"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            user-membership-find $user6 > $TmpDir/pki-user-membership-find-groupadd-find-tps-017_4.out" \
                            0 \
                            "Find user-membership with group \"dadministʁasjɔ̃\""
                rlAssertGrep "0 entries matched" "$TmpDir/pki-user-membership-find-groupadd-find-tps-017_4.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-del-TPS-017: Delete user-membership for user fullname with i18n characters"
		user7="u7"
                rlLog "user-add user fullname ÖrjanÄke with i18n characters"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            user-add --fullName='ÖrjanÄke' $user7 > $TmpDir/pki-user-add-tps-018.out 2>&1" \
                            0 \
                            "Adding user full name ÖrjanÄke with i18n characters"
                rlAssertGrep "Added user \"$user7\"" "$TmpDir/pki-user-add-tps-018.out"
                rlAssertGrep "User ID: $user7" "$TmpDir/pki-user-add-tps-018.out"
                rlLog "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            user-membership-add $user7 \"dadministʁasjɔ̃\""
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            user-membership-add $user7 \"dadministʁasjɔ̃\" > $TmpDir/pki-user-membership-del-groupadd-tps-018_2.out" \
                            0 \
                            "Adding user with full name ÖrjanÄke to group \"dadministʁasjɔ̃\""
                rlAssertGrep "Added membership in \"dadministʁasjɔ̃\"" "$TmpDir/pki-user-membership-del-groupadd-tps-018_2.out"
                rlAssertGrep "Group: dadministʁasjɔ̃" "$TmpDir/pki-user-membership-del-groupadd-tps-018_2.out"
		rlLog "Delete user from the group"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            user-membership-del $user7 \"dadministʁasjɔ̃\" > $TmpDir/pki-user-membership-del-groupadd-del-tps-018_3.out" \
                            0 \
                            "Delete user-membership from the group \"dadministʁasjɔ̃\""
		rlAssertGrep "Deleted membership in group \"dadministʁasjɔ̃\"" "$TmpDir/pki-user-membership-del-groupadd-del-tps-018_3.out"
                rlLog "Check if the user is removed from the group"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            user-membership-find $user7 > $TmpDir/pki-user-membership-del-groupadd-del-tps-018_4.out" \
                            0 \
                            "Find user-membership with group \"dadministʁasjɔ̃\""
                rlAssertGrep "0 entries matched" "$TmpDir/pki-user-membership-del-groupadd-del-tps-018_4.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-del-TPS-018: Delete user-membership when uid is not associated with a group"
		rlLog "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            user-add --fullName=\"fullNameuser123\" user123 "
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            user-add --fullName=\"fullNameuser123\" user123 > $TmpDir/pki-user-membership-del-user-del-tps-019.out" \
                            0 \
                            "Adding user user123"
                rlAssertGrep "Added user \"user123\"" "$TmpDir/pki-user-membership-del-user-del-tps-019.out"
                rlAssertGrep "User ID: user123" "$TmpDir/pki-user-membership-del-user-del-tps-019.out"
                rlAssertGrep "Full name: fullNameuser123" "$TmpDir/pki-user-membership-del-user-del-tps-019.out"
                command="pki -d $CERTDB_DIR  -n ${prefix}_adminV -c $CERTDB_DIR_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -t tps user-membership-del user123 \"Administrators\""
                rlLog "Executing $command"
		errmsg="ResourceNotFoundException: No such attribute."
		errorcode=255
		rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Delete user-membership when uid is not associated with a group"
	rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_membership-del-TPS-019: Deleting a user that has membership with groups removes the user from the groups"
		rlLog "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            user-add --fullName=\"fullNameu12\" u12"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            user-add --fullName=\"fullNameu12\" u12 > $TmpDir/pki-user-membership-del-user-del-tps-020.out" \
                            0 \
                            "Adding user u12"
                rlAssertGrep "Added user \"u12\"" "$TmpDir/pki-user-membership-del-user-del-tps-020.out"
                rlAssertGrep "User ID: u12" "$TmpDir/pki-user-membership-del-user-del-tps-020.out"
                rlAssertGrep "Full name: fullNameu12" "$TmpDir/pki-user-membership-del-user-del-tps-020.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 		 	   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            user-membership-add u12 \"$groupid3\" > $TmpDir/pki-user-membership-add-groupadd-tps-20_2.out" \
                            0 \
                            "Adding user u12 to group \"Administrators\""
                rlAssertGrep "Added membership in \"$groupid3\"" "$TmpDir/pki-user-membership-add-groupadd-tps-20_2.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            user-membership-add u12 \"$groupid1\" > $TmpDir/pki-user-membership-add-groupadd-tps-20_3.out" \
                            0 \
                            "Adding user u12 to group \"$groupid1\""
                rlAssertGrep "Added membership in \"$groupid1\"" "$TmpDir/pki-user-membership-add-groupadd-tps-20_3.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            group-member-find  Administrators > $TmpDir/pki-user-del-tps-user-membership-find-user-del-tps-20_4.out" \
                            0 \
                            "List members of Administrators group"
                rlAssertGrep "User: u12" "$TmpDir/pki-user-del-tps-user-membership-find-user-del-tps-20_4.out"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            group-member-find \"$groupid1\" > $TmpDir/pki-user-del-tps-user-membership-find-user-del-tps-20_5.out" \
                            0 \
                            "List members of $groupid1 group"
                rlAssertGrep "User: u12" "$TmpDir/pki-user-del-tps-user-membership-find-user-del-tps-20_5.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            user-del  u12 > $TmpDir/pki-user-del-tps-user-membership-find-user-del-tps-20_6.out" \
                            0 \
                            "Delete user u12"
                rlAssertGrep "Deleted user \"u12\"" "$TmpDir/pki-user-del-tps-user-membership-find-user-del-tps-20_6.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 		    	   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            group-member-find $groupid3 > $TmpDir/pki-user-del-tps-user-membership-find-user-del-tps-20_7.out" \
                            0 \
                            "List members of $groupid3 group"
                rlAssertNotGrep "User: u12" "$TmpDir/pki-user-del-tps-user-membership-find-user-del-tps-20_7.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
		 	   -t tps \
                            group-member-find \"$groupid1\" > $TmpDir/pki-user-del-tps-user-membership-find-user-del-tps-20_8.out" \
                            0 \
                            "List members of $groupid1 group"
                rlAssertNotGrep "User: u12" "$TmpDir/pki-user-del-tps-user-membership-find-user-del-tps-20_8.out"
	rlPhaseEnd

	#Usability tests
	rlPhaseStartTest "pki_user_cli_user_membership-del-TPS-020: User deleted from  Administrators group cannot create a new user"
		user5="u5"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            user-add --fullName=\"fullName_user1\" testuser1 > $TmpDir/pki-user-membership-del-user-add-tps-0021.out" \
                            0 \
                            "Adding user testuser1"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            user-membership-add testuser1 \"Administrators\" > $TmpDir/pki-user-membership-add-groupadd-tps-21_2.out" \
                            0 \
                            "Adding user testuser1 to group \"Administrators\""
        	rlAssertGrep "Added membership in \"Administrators\"" "$TmpDir/pki-user-membership-add-groupadd-tps-21_2.out"

		#Create a user cert
		local TEMP_NSS_DB="$TmpDir/nssdb"
                local TEMP_NSS_DB_PASSWORD="Password"
                local ret_reqstatus
                local ret_requestid
                local valid_serialNumber
		local requestdn
                local temp_out="$TmpDir/usercert-show.out"
                rlRun "create_cert_request $TEMP_NSS_DB $TEMP_NSS_DB_PASSWORD pkcs10 rsa 2048 \"test User1\" \"testuser1\" \
                        \"testuser1@example.org\" \"Engineering\" \"Example.Inc\" "US" "--" "ret_reqstatus" "ret_requestid" $CA_HOST $(eval echo \$${caId}_UNSECURE_PORT) $requestdn $caId" 0 "Generating  pkcs10 Certificate Request"
                rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"${caId}_agentV\" -h $CA_HOST  -p $(eval echo \$${caId}_UNSECURE_PORT) ca-cert-request-review $ret_requestid \
                        --action approve 1"
                rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -h $CA_HOST  -p $(eval echo \$${caId}_UNSECURE_PORT) -n \"${caId}_agentV\" ca-cert-request-review $ret_requestid \
                        --action approve 1> $TmpDir/pki-approve-out" 0 "Approve Certificate requeset"
                rlAssertGrep "Approved certificate request $ret_requestid" "$TmpDir/pki-approve-out"
                rlLog "pki -h $CA_HOST  -p $(eval echo \$${caId}_UNSECURE_PORT) cert-request-show $ret_requestid | grep \"Certificate ID\" | sed 's/ //g' | cut -d: -f2)"
                rlRun "pki -h $CA_HOST  -p $(eval echo \$${caId}_UNSECURE_PORT) cert-request-show $ret_requestid > $TmpDir/usercert-show1.out"
                valid_serialNumber=`cat $TmpDir/usercert-show1.out | grep 'Certificate ID' | sed 's/ //g' | cut -d: -f2`
                rlLog "valid_serialNumber=$valid_serialNumber"

                #Import user certs to $TEMP_NSS_DB
                rlRun "pki -h $CA_HOST  -p $(eval echo \$${caId}_UNSECURE_PORT) cert-show $valid_serialNumber --encoded > $temp_out" 0 "command pki cert-show $valid_serialNumber --encoded"
                rlRun "certutil -d $TEMP_NSS_DB -A -n testuser1 -i $temp_out  -t \"u,u,u\""

                #Add certificate to the user
                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $temp_out > $TmpDir/validcert_021_3.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n \"${prefix}_adminV\" \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           -t tps \
                            user-cert-add testuser1 --input $TmpDir/validcert_021_3.pem  > $TmpDir/useraddcert_021_3.out" \
                            0 \
                            "Cert is added to the user testuser1"

		#Add a new user using testuser1
		local expfile="$TmpDir/expfile_testuser1.out"
                echo "spawn -noecho pki -d $TEMP_NSS_DB -n testuser1 -c $TEMP_NSS_DB_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -t tps user-add --fullName=test_user $user5" > $expfile
                echo "expect \"WARNING: UNTRUSTED ISSUER encountered on '$(eval echo \$${subsystemId}_SSL_SERVER_CERT_SUBJECT_NAME)' indicates a non-trusted CA cert '$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME)'
Import CA certificate (Y/n)? \"" >> $expfile
                echo "send -- \"Y\r\"" >> $expfile
                echo "expect \"CA server URI \[http://$HOSTNAME:8080/ca\]: \"" >> $expfile
                echo "send -- \"http://$HOSTNAME:$(eval echo \$${caId}_UNSECURE_PORT)/ca\r\"" >> $expfile
                echo "expect eof" >> $expfile
                echo "catch wait result" >> $expfile
                echo "exit [lindex \$result 3]" >> $expfile
                rlRun "/usr/bin/expect -f $expfile 2>&1 >  $TmpDir/pki-user-add-tps-021_4.out" 0 "Should be able to add users using Administrator user testuser1"
                rlAssertGrep "Added user \"$user5\"" "$TmpDir/pki-user-add-tps-021_4.out"
                rlAssertGrep "User ID: $user5" "$TmpDir/pki-user-add-tps-021_4.out"
                rlAssertGrep "Full name: test_user" "$TmpDir/pki-user-add-tps-021_4.out"

		#Delete testuser1 from the Administrators group
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            user-membership-del testuser1 \"Administrators\"  > $TmpDir/pki-user-membership-del-groupdel-del-tps-021_5.out" \
                            0 \
                            "User deleted from group \"Administrators\""
                rlAssertGrep "Deleted membership in group \"Administrators\"" "$TmpDir/pki-user-membership-del-groupdel-del-tps-021_5.out"

		#Trying to add a user using testuser1 should fail since testuser1 is not in Administrators group
		command="pki -d $TEMP_NSS_DB  -n testuser1 -c  $TEMP_NSS_DB_PASSWORD -h $SUBSYSTEM_HOST -p $(eval echo \$${subsystemId}_UNSECURE_PORT) -t tps user-add --fullName=test_user u212"
		rlLog "Executing $command"
		errmsg="ForbiddenException: Authorization Error"
		errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Should not be able to add users using non Administrator"
	rlPhaseEnd

        rlPhaseStartCleanup "pki_user_cli_user_membership-del-tps-cleanup-001: Deleting the temp directory and users"

		#===Deleting users created using TPS_adminV cert===#
		i=1
		while [ $i -lt 8 ] ; do
		       rlRun "pki -d $CERTDB_DIR \
				  -n ${prefix}_adminV \
				  -c $CERTDB_DIR_PASSWORD \
 				  -h $SUBSYSTEM_HOST \
 				  -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
				  -t tps \
				   user-del  u$i > $TmpDir/pki-user-del-tps-user-membership-del-user-del-tps-00$i.out" \
				   0 \
				   "Deleted user u$i"
			rlAssertGrep "Deleted user \"u$i\"" "$TmpDir/pki-user-del-tps-user-membership-del-user-del-tps-00$i.out"
			let i=$i+1
		done
		rlRun "pki -d $CERTDB_DIR \
		       	   -n ${prefix}_adminV \
			   -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
			    user-del  userall > $TmpDir/pki-user-del-tps-user-membership-del-user-del-tps-userall-001.out" \
			    0 \
			   "Deleted user userall"
	        rlAssertGrep "Deleted user \"userall\"" "$TmpDir/pki-user-del-tps-user-membership-del-user-del-tps-userall-001.out"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            user-del  user1 > $TmpDir/pki-user-del-tps-user-membership-del-user-del-tps-userall-001.out" \
                            0 \
                            "Deleted user user1"
                rlAssertGrep "Deleted user \"user1\"" "$TmpDir/pki-user-del-tps-user-membership-del-user-del-tps-userall-001.out"
                rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            user-del  user2 > $TmpDir/pki-user-del-tps-user-membership-del-user-del-tps-userall-001.out" \
                            0 \
                            "Deleted user user2"
                rlAssertGrep "Deleted user \"user2\"" "$TmpDir/pki-user-del-tps-user-membership-del-user-del-tps-userall-001.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            user-del  user123 > $TmpDir/pki-user-del-tps-user-membership-find-user-del-tps-user123.out" \
                            0 \
                            "Deleted user user123"
                rlAssertGrep "Deleted user \"user123\"" "$TmpDir/pki-user-del-tps-user-membership-find-user-del-tps-user123.out"
		rlRun "pki -d $CERTDB_DIR \
                           -n ${prefix}_adminV \
                           -c $CERTDB_DIR_PASSWORD \
 			   -h $SUBSYSTEM_HOST \
 			   -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			   -t tps \
                            user-del testuser1 > $TmpDir/pki-user-del-tps-user-membership-find-user-del-tps-testuser1.out" \
                            0 \
                            "Deleted user testuser1"
                rlAssertGrep "Deleted user \"testuser1\"" "$TmpDir/pki-user-del-tps-user-membership-find-user-del-tps-testuser1.out"

                #===Deleting i18n group created using TPS_adminV cert===#
                rlRun "pki -d $CERTDB_DIR \
                        -n ${prefix}_adminV \
                        -c $CERTDB_DIR_PASSWORD \
 			-h $SUBSYSTEM_HOST \
 			-p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
			-t tps \
                        group-del 'dadministʁasjɔ̃' > $TmpDir/pki-user-del-tps-group-i18n_1.out" \
                        0 \
                        "Deleting group dadministʁasjɔ̃"
                rlAssertGrep "Deleted group \"dadministʁasjɔ̃\"" "$TmpDir/pki-user-del-tps-group-i18n_1.out"
		
		#Delete temporary directory
                rlRun "popd"
                rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlPhaseEnd
 else
	rlLog "TPS instance not installed"
 fi
}
