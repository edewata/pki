#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-ca-user-cli
#   Description: PKI user-cert-delete CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-ca-user-cli-ca-user-cert-delete    Delete the certs assigned to users in the pki ca subsystem.
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
#create_role_users.sh should be first executed prior to pki-ca-user-cli-ca-user-cert-delete.sh
######################################################################################

########################################################################
# Test Suite Globals
########################################################################

########################################################################

run_pki-ca-user-cli-ca-user-cert-delete_tests(){

subsystemId=$1
SUBSYSTEM_TYPE=$2
MYROLE=$3

if [ "$TOPO9" = "TRUE" ] ; then
        prefix=$subsystemId
elif [ "$MYROLE" = "MASTER" ] ; then
        if [[ $subsystemId == SUBCA* ]]; then
                prefix=$subsystemId
        else
                prefix=ROOTCA
        fi
else
        prefix=$MYROLE
fi

CA_HOST=$(eval echo \$${MYROLE})
CA_PORT=$(eval echo \$${subsystemId}_UNSECURE_PORT)
        ##### Create temporary directory to save output files#####
    rlPhaseStartSetup "pki_user_cli_user_cert-del-ca-startup: Create temporary directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
    rlPhaseEnd

user1=testuser1
user2=testuser2
user1fullname="Test user1"
user2fullname="Test user2"
user3=testuser3
user3fullname="Test user3"
cert_info="$TmpDir/cert_info"
testname="pki_user_cert_del"
local TEMP_NSS_DB="$TmpDir/nssdb"
local TEMP_NSS_DB_PASSWD="redhat123"
eval ${subsystemId}_adminV_user=${subsystemId}_adminV
eval ${subsystemId}_adminR_user=${subsystemId}_adminR
eval ${subsystemId}_adminE_user=${subsystemId}_adminE
eval ${subsystemId}_adminUTCA_user=${subsystemId}_adminUTCA
eval ${subsystemId}_agentV_user=${subsystemId}_agentV
eval ${subsystemId}_agentR_user=${subsystemId}_agentR
eval ${subsystemId}_agentE_user=${subsystemId}_agentE
eval ${subsystemId}_auditV_user=${subsystemId}_auditV
eval ${subsystemId}_operatorV_user=${subsystemId}_operatorV
	##### pki_ca_user_cli_ca_user_cert_delete-configtest ####
     rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-del-configtest-001: pki ca-user-cert-del configuration test"
        rlRun "pki ca-user-cert-del --help > $TmpDir/pki_ca_user_cert_del_cfg.out 2>&1" \
                0 \
                "User cert delete configuration"
        rlAssertGrep "usage: ca-user-cert-del <User ID> <Cert ID>" "$TmpDir/pki_ca_user_cert_del_cfg.out"
	rlAssertNotGrep "Error: Unrecognized option: --help" "$TmpDir/pki_ca_user_cert_del_cfg.out"
	rlLog "FAIL:https://fedorahosted.org/pki/ticket/843"
    rlPhaseEnd

	##### Tests to delete certs assigned to CA users ####

	##### Delete certs asigned to a user - valid Cert ID and User ID #####

	rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-del-002-tier1: Delete cert assigned to a user - valid UserID and CertID"
		i=0
        	rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"$user1fullname\" $user1"
		 while [ $i -lt 4 ] ; do
			rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
	                algo:rsa key_size:2048 subject_cn:\"$user1fullname$(($i+1))\" subject_uid:$user1$(($i+1)) subject_email:$user1$(($i+1))@example.org \
        	        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
                	target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
	                certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        	        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                	local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
	                local STRIP_HEX_PKCS10=$(echo $valid_pkcs10_serialNumber | cut -dx -f2)
        	        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
			serialhexpkcs10user1[$i]=$valid_pkcs10_serialNumber
	                serialdecimalpkcs10user1[$i]=$valid_decimal_pkcs10_serialNumber
                	rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_ca_user_cert_del_encoded_002pkcs10$i.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
	                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_ca_user_cert_del_encoded_002pkcs10$i.out > $TmpDir/pki_ca_user_cert_del_validcert_002pkcs10$i.pem"

        	        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
                	algo:rsa key_size:2048 subject_cn:\"$user1fullname$(($i+1))\" subject_uid:$user1$(($i+1)) subject_email:$user1$(($i+1))@example.org \
	                organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        	        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                	certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
	                local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        	        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
                	local STRIP_HEX_CRMF=$(echo $valid_crmf_serialNumber | cut -dx -f2)
	                local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
			serialhexcrmfuser1[$i]=$valid_crmf_serialNumber
	                serialdecimalcrmfuser1[$i]=$valid_decimal_crmf_serialNumber
        	        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_ca_user_cert_del_encoded_002crmf$i.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
                	rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_ca_user_cert_del_encoded_002crmf$i.out > $TmpDir/pki_ca_user_cert_del_validcert_002crmf$i.pem"


			rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user1 --input $TmpDir/pki_ca_user_cert_del_validcert_002pkcs10$i.pem  > $TmpDir/pki_ca_user_cert_del_useraddcert_pkcs10_002$i.out" \
                            0 \
                            "Cert is added to the user $user1"
			
			rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user1 --input $TmpDir/pki_ca_user_cert_del_validcert_002crmf$i.pem  > $TmpDir/pki_ca_user_cert_del_useraddcert_crmf_002$i.out" \
                            0 \
                            "Cert is added to the user $user1"
                	let i=$i+1
        	done
		i=0
		rlLog "Executing pki -d $CERTDB_DIR/ \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-del $user1 \"2;${serialdecimalpkcs10user1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))$@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US\""
		rlRun "pki -d $CERTDB_DIR/ \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-del $user1 \"2;${serialdecimalpkcs10user1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US\" > $TmpDir/pki_ca_user_cert_del_002pkcs10.out" \
			0 \
			"Delete cert assigned to $user1"
		rlAssertGrep "Deleted certificate \"2;${serialdecimalpkcs10user1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_ca_user_cert_del_002pkcs10.out"

		rlLog "Executing pki -d $CERTDB_DIR/ \
			    -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-del $user1 \"2;${serialdecimalcrmfuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))$@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-del $user1 \"2;${serialdecimalcrmfuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US\" > $TmpDir/pki_ca_user_cert_del_002crmf.out" \
                        0 \
                        "Delete cert assigned to $user1"
                rlAssertGrep "Deleted certificate \"2;${serialdecimalcrmfuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_ca_user_cert_del_002crmf.out"
		
		rlRun "pki -d $CERTDB_DIR \
			   -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-del $user1"
	rlPhaseEnd

	 ##### Delete certs asigned to a user - invalid Cert ID #####

        rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-del-003: pki ca-user-cert-del should fail if an invalid Cert ID is provided"
		i=0
                rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"$user1fullname\" $user1"
                 while [ $i -lt 4 ] ; do
                        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
                        algo:rsa key_size:2048 subject_cn:\"$user1fullname$(($i+1))\" subject_uid:$user1$(($i+1)) subject_email:$user1$(($i+1))@example.org \
                        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
                        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
                        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
                        local STRIP_HEX_PKCS10=$(echo $valid_pkcs10_serialNumber | cut -dx -f2)
                        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
                        serialhexpkcs10user1[$i]=$valid_pkcs10_serialNumber
                        serialdecimalpkcs10user1[$i]=$valid_decimal_pkcs10_serialNumber
                        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_ca_user_cert_del_encoded_002pkcs10$i.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
                        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_ca_user_cert_del_encoded_002pkcs10$i.out > $TmpDir/pki_ca_user_cert_del_validcert_002pkcs10$i.pem"

                        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
                        algo:rsa key_size:2048 subject_cn:\"$user1fullname$(($i+1))\" subject_uid:$user1$(($i+1)) subject_email:$user1$(($i+1))@example.org \
                        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
                        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
                        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
                        local STRIP_HEX_CRMF=$(echo $valid_crmf_serialNumber | cut -dx -f2)
                        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
                        serialhexcrmfuser1[$i]=$valid_crmf_serialNumber
                        serialdecimalcrmfuser1[$i]=$valid_decimal_crmf_serialNumber
                        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_ca_user_cert_del_encoded_002crmf$i.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
                        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_ca_user_cert_del_encoded_002crmf$i.out > $TmpDir/pki_ca_user_cert_del_validcert_002crmf$i.pem"


                        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user1 --input $TmpDir/pki_ca_user_cert_del_validcert_002pkcs10$i.pem  > $TmpDir/pki_ca_user_cert_del_useraddcert_pkcs10_002$i.out" \
                            0 \
                            "Cert is added to the user $user1"

                        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user1 --input $TmpDir/pki_ca_user_cert_del_validcert_002crmf$i.pem  > $TmpDir/pki_ca_user_cert_del_useraddcert_crmf_002$i.out" \
                            0 \
			   "Cert is added to the user $user1"
                        let i=$i+1
                done
                i=0

		command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del $user1 '3;1000;CN=ROOTCA Signing Cert,O=redhat domain;UID=$user1,E=$user1@example.org,CN=$user1fullname,OU=Eng,O=Example,C=UK'"
		rlLog "Executing: $command"
                errmsg="PKIException: Failed to modify user."
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki ca-user-cert-del should fail if Invalid Cert ID is provided"
		
		command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del $user1 '3;1000;CN=ROOTCA Signing Cert,O=redhat domain;UID=$user1,E=$user1@example.org,CN=$user1fullname,OU=Eng,O=Example,C=UK'"
                rlLog "Executing: $command"
                errmsg="PKIException: Failed to modify user."
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki ca-user-cert-del should fail if Invalid Cert ID is provided"
	
	rlPhaseEnd

	##### Delete certs asigned to a user - User does not exist #####

        rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-del-004: pki ca-user-cert-del should fail if a non-existing User ID is provided"
		i=1
		command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del testuser4 '2;${serialdecimalpkcs10user1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ResourceNotFoundException: User not found"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki ca-user-cert-del should fail if a non-existing User ID is provided"

                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del testuser4 '2;${serialdecimalcrmfuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ResourceNotFoundException: User not found"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki ca-user-cert-del should fail if a non-existing User ID is provided"
	rlPhaseEnd

	 ##### Delete certs asigned to a user - User ID and Cert ID mismatch #####

        rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-del-005: pki ca-user-cert-del should fail is there is a mismatch of User ID and Cert ID"
		i=1
		rlRun "pki -d $CERTDB_DIR \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"$user2fullname\" $user2"
		command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del $user2 '2;${serialdecimalpkcs10user1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ResourceNotFoundException: Certificate not found"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki ca-user-cert-del should fail if there is a Cert ID and User ID mismatch"

                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del $user2 '2;${serialdecimalcrmfuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ResourceNotFoundException: Certificate not found"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki ca-user-cert-del should fail if there is a Cert ID and User ID mismatch"
	rlPhaseEnd

	##### Delete certs asigned to a user - no User ID #####

        rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-del-006-tier1: pki ca-user-cert-del should fail if User ID is not provided"
		i=1
		command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del '2;${serialdecimalpkcs10user1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="Error: Incorrect number of arguments specified."
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki ca-user-cert-del should fail if User ID is not provided"

                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del '2;${serialdecimalcrmfuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="Error: Incorrect number of arguments specified."
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki ca-user-cert-del should fail if User ID is not provided"
	rlPhaseEnd
	
	##### Delete certs asigned to a user - no Cert ID #####

        rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-del-007-tier1: pki ca-user-cert-del should fail if Cert ID is not provided"
                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del $user1"
                rlLog "Executing: $command"
                errmsg="Error: Incorrect number of arguments specified."
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki ca-user-cert-del should fail if Cert ID is not provided"
	rlPhaseEnd

	 ##### Delete certs asigned to a user - as CA_agentV ##### 

        rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-del-008: Delete certs assigned to a user - as CA_agentV should fail"
		i=1
		command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_agentV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del $user1 '2;${serialdecimalpkcs10user1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki ca-user-cert-del should fail if authenticating using a valid agent cert"

                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_agentV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del $user1 '2;${serialdecimalcrmfuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki ca-user-cert-del should fail if authenticating using a valid agent cert"
	rlPhaseEnd

	##### Delete certs asigned to a user - as CA_auditorV ##### 

        rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-del-009: Delete certs assigned to a user - as CA_auditorV should fail"
		i=1
		command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_auditV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del $user1 '2;${serialdecimalpkcs10user1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki ca-user-cert-del should fail if authenticating using a valid auditor cert"

                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_auditV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del $user1 '2;${serialdecimalcrmfuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki ca-user-cert-del should fail if authenticating using a valid auditor cert"

		rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
	rlPhaseEnd

	##### Delete certs asigned to a user - as CA_adminE ##### 

        rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-del-0010: Delete certs assigned to a user - as CA_adminE"
		i=1
		rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
		command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminE_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del $user1 '2;${serialdecimalpkcs10user1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki ca-user-cert-del should fail if authenticating using an expired admin cert"

                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminE_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del $user1 '2;${serialdecimalcrmfuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki ca-user-cert-del should fail if authenticating using an expired admin cert"
		rlRun "date --set='2 days ago'" 0 "Set System back to the present day"

                rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
	rlPhaseEnd

	 ##### Delete certs asigned to a user - as CA_agentE ##### 

        rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-del-0011: Delete certs assigned to a user - as CA_agentE"
                i=1
                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date --set='next day'" 0 "Set System date a day ahead"
                                rlRun "date"
                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_agentE_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del $user1 '2;${serialdecimalpkcs10user1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki ca-user-cert-del should fail if authenticating using an expired agent cert"

                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_agentE_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del $user1 '2;${serialdecimalcrmfuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki ca-user-cert-del should fail if authenticating using an expired agent cert"
                rlRun "date --set='2 days ago'" 0 "Set System back to the present day"

                rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
        rlPhaseEnd

	 ##### Delete certs asigned to a user - as CA_adminR ##### 

        rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-del-0012: Delete certs assigned to a user - as CA_adminR should fail"
                i=1
                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminR_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del $user1 '2;${serialdecimalpkcs10user1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki ca-user-cert-del should fail if authenticating using a revoked admin cert"

                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminR_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del $user1 '2;${serialdecimalcrmfuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki ca-user-cert-del should fail if authenticating using a revoked admin cert"

        rlPhaseEnd

	 ##### Delete certs asigned to a user - as CA_agentR ##### 

        rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-del-0013: Delete certs assigned to a user - as CA_agentR should fail"
                i=1
                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_agentR_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del $user1 '2;${serialdecimalpkcs10user1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki ca-user-cert-del should fail if authenticating using a revoked agent cert"

                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_agentR_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del $user1 '2;${serialdecimalcrmfuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki ca-user-cert-del should fail if authenticating using a revoked agent cert"
        rlPhaseEnd

	##### Delete certs asigned to a user - as role_user_UTCA ##### 

        rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-del-0014: Delete certs assigned to a user - as role_user_UTCA should fail"
                i=1
                command="pki -d $UNTRUSTED_CERT_DB_LOCATION -n role_user_UTCA -c $UNTRUSTED_CERT_DB_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del $user1 '2;${serialdecimalpkcs10user1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki ca-user-cert-del should fail if authenticating using an untrusted cert"

                command="pki -d $UNTRUSTED_CERT_DB_LOCATION -n role_user_UTCA -c $UNTRUSTED_CERT_DB_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del $user1 '2;${serialdecimalcrmfuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="PKIException: Unauthorized"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki ca-user-cert-del should fail if authenticating using an untrusted cert"

		rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
        rlPhaseEnd

	##### Delete certs asigned to a user - as CA_operatorV ##### 

        rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-del-0015: Delete certs assigned to a user - as CA_operatorV should fail"
                i=1
                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_operatorV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del $user1 '2;${serialdecimalpkcs10user1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki ca-user-cert-del should fail if authenticating using a valid operator cert"

                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_operatorV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del $user1 '2;${serialdecimalcrmfuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki ca-user-cert-del should fail if authenticating using a valid operator cert"
        rlPhaseEnd

	##### Delete certs asigned to a user - as a user not assigned to any role ##### 

        rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-del-0016: Delete certs assigned to a user - as a user not assigned to any role should fail"
		i=1
                command="pki -d $CERTDB_DIR/ -n $user2 -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del $user1 '2;${serialdecimalpkcs10user1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when authentication as a user not assigned to any role"

                command="pki -d $CERTDB_DIR/ -n $user2 -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del $user1 '2;${serialdecimalcrmfuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US'"
                rlLog "Executing: $command"
                errmsg="ForbiddenException: Authorization Error"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Error should be thrown when authentication as a user not assigned to any role"

		rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
	rlPhaseEnd

	 ##### Delete certs asigned to a user - switch positions of the required options ##### 

        rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-del-0017: Delete certs assigned to a user - switch positions of the required options"
		i=1
                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del '2;${serialdecimalpkcs10user1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US' $user1"
                rlLog "Executing: $command"
                errmsg="Error:"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki ca-user-cert-del should fail if the required options are switched positions"

                command="pki -d $CERTDB_DIR/ -n $(eval echo \$${subsystemId}_adminV_user) -c $CERTDB_DIR_PASSWORD -h $CA_HOST -p $CA_PORT ca-user-cert-del '2;${serialdecimalcrmfuser1[$i]};$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example.Inc,C=US' $user1"
                rlLog "Executing: $command"
                errmsg="Error:"
                errorcode=255
                rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki ca-user-cert-del should fail if the required options are switched positions"
		rlLog "FAIL: https://fedorahosted.org/pki/ticket/969"

	rlPhaseEnd

	### Tests to delete certs assigned to CA users - i18n characters ####

	rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-del-0019: Delete certs assigned to user - Subject name has i18n Characters"
		rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
                        algo:rsa key_size:2048 subject_cn:\"Örjan Äke\" subject_uid:\"Örjan Äke\" subject_email:test@example.org \
                        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
                        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
                        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
                        local STRIP_HEX_PKCS10=$(echo $valid_pkcs10_serialNumber | cut -dx -f2)
                        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
                        serialhexpkcs10user1[$i]=$valid_pkcs10_serialNumber
                        serialdecimalpkcs10user1[$i]=$valid_decimal_pkcs10_serialNumber
                        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_ca_user_cert_del_encoded_0019pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
                        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_ca_user_cert_del_encoded_0019pkcs10.out > $TmpDir/pki_ca_user_cert_del_validcert_0019pkcs10.pem"

                        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
                        algo:rsa key_size:2048 subject_cn:\"Örjan Äke\" subject_uid:\"Örjan Äke\" subject_email:test@example.org \
                        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
                        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
                        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
                        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
                        local STRIP_HEX_CRMF=$(echo $valid_crmf_serialNumber | cut -dx -f2)
                        local CONV_UPP_VAL_CRMF=${STRIP_HEX_CRMF^^}
                        serialhexcrmfuser1[$i]=$valid_crmf_serialNumber
                        serialdecimalcrmfuser1[$i]=$valid_decimal_crmf_serialNumber
                        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_ca_user_cert_del_encoded_0019crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
                        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_ca_user_cert_del_encoded_0019crmf.out > $TmpDir/pki_ca_user_cert_del_validcert_0019crmf.pem"


                        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user2 --input $TmpDir/pki_ca_user_cert_del_validcert_0019pkcs10.pem  > $TmpDir/pki_ca_user_cert_del_useraddcert_pkcs10_0019.out" \
                            0 \
                            "Cert is added to the user $user2"

                        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add $user2 --input $TmpDir/pki_ca_user_cert_del_validcert_0019crmf.pem  > $TmpDir/pki_ca_user_cert_del_useraddcert_crmf_0019.out" \
                            0 \
                            "Cert is added to the user $user1"
		rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-del $user2 \"2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-del $user2 \"2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US\" > $TmpDir/pki_ca_user_cert_del_0019pkcs10.out" \
                        0 \
                        "Delete cert assigned to $user2"
                rlAssertGrep "Deleted certificate \"2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_ca_user_cert_del_0019pkcs10.out"

                rlLog "Executing pki -d $CERTDB_DIR/ \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-del $user2 \"2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US\""
                rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-del $user2 \"2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US\" > $TmpDir/pki_ca_user_cert_del_0019crmf.out" \
                        0 \
                        "Delete cert assigned to $user2"
                rlAssertGrep "Deleted certificate \"2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_ca_user_cert_del_0019crmf.out"
	rlPhaseEnd

	##### Add an Admin user "admin_user", add a cert to admin_user, add a new user as admin_user, delete the cert assigned to admin_user and then adding a new user should fail #####

	rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-del-0020: Add an Admin user \"admin_user\", add a cert to admin_user, add a new user as admin_user, delete the cert assigned to admin_user and then adding a new user should fail"
		rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"Admin User\" --password=Secret123 admin_user"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-group-member-add Administrators admin_user > $TmpDir/pki-user-add-ca-group0019.out"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"Admin User1\" --password=Secret123 admin_user1"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-group-member-add Administrators admin_user1 > $TmpDir/pki-user-add-ca-group00191.out"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"Admin User\" subject_uid:\"admin_user\" subject_email:admin_user@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_ca_user_cert_del_encoded_0020pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_ca_user_cert_del_encoded_0020pkcs10.out > $TmpDir/pki_ca_user_cert_del_validcert_0020pkcs10.pem"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn:\"Admin User1\" subject_uid:\"admin_user1\" subject_email:admin_user1@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_ca_user_cert_del_encoded_0020crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_ca_user_cert_del_encoded_0020crmf.out > $TmpDir/pki_ca_user_cert_del_validcert_0020crmf.pem"

        rlRun "certutil -d $TEMP_NSS_DB -A -n \"casigningcert\" -i $CERTDB_DIR/ca_cert.pem -t \"CT,CT,CT\""

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
			    -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add admin_user --input $TmpDir/pki_user_cert_del_validcert_0020pkcs10.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add admin_user --input $TmpDir/pki_ca_user_cert_del_validcert_0020pkcs10.pem  > $TmpDir/pki_ca_user_cert_del_useraddcert_0020pkcs10.out" \
                            0 \
                            "PKCS10 Cert is added to the user admin_user"
        rlRun "certutil -d $TEMP_NSS_DB -A -n \"admin-user-pkcs10\" -i $TmpDir/pki_ca_user_cert_del_validcert_0020pkcs10.pem  -t "u,u,u""

        rlLog "pki -d $TEMP_NSS_DB/ \
                           -n admin-user-pkcs10 \
                           -c $TEMP_NSS_DB_PASSWD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"New Test User1\" new_test_user1"
        rlRun "pki -d $TEMP_NSS_DB/ \
                           -n admin-user-pkcs10 \
                           -c $TEMP_NSS_DB_PASSWD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"New Test User1\" new_test_user1 > $TmpDir/pki_ca_user_cert_del_useradd_0020.out 2>&1" \
                            0 \
                            "Adding a new user as admin_user"
        rlAssertGrep "Added user \"new_test_user1\"" "$TmpDir/pki_ca_user_cert_del_useradd_0020.out"
        rlAssertGrep "User ID: new_test_user1" "$TmpDir/pki_ca_user_cert_del_useradd_0020.out"
        rlAssertGrep "Full name: New Test User1" "$TmpDir/pki_ca_user_cert_del_useradd_0020.out"

	rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-del admin_user \"2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=admin_user,E=admin_user@example.org,CN=Admin User,OU=Engineering,O=Example.Inc,C=US\" > $TmpDir/pki_ca_user_cert_del_0020pkcs10.out" \
                        0 \
                        "Delete cert assigned to admin_user"
                rlAssertGrep "Deleted certificate \"2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=admin_user,E=admin_user@example.org,CN=Admin User,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_ca_user_cert_del_0020pkcs10.out"

        command="pki -d $TEMP_NSS_DB -n admin-user-pkcs10 -c $TEMP_NSS_DB_PASSWD -h $CA_HOST -p $CA_PORT ca-user-add --fullName='New Test User6' new_test_user6"
         rlLog "Executing: $command"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding a new user as admin_user-pkcs10 after deleting the cert from the user"

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add admin_user1 --input $TmpDir/pki_ca_user_cert_del_validcert_0020crmf.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add admin_user1 --input $TmpDir/pki_ca_user_cert_del_validcert_0020crmf.pem  > $TmpDir/pki_ca_user_cert_del_useraddcert_0020crmf.out" \
                            0 \
			   "CRMF Cert is added to the user admin_user1"
        rlRun "certutil -d $TEMP_NSS_DB -A -n \"admin-user1-crmf\" -i $TmpDir/pki_ca_user_cert_del_validcert_0020crmf.pem  -t "u,u,u""

        rlLog "pki -d $TEMP_NSS_DB/ \
                           -n admin-user1-crmf \
                           -c $TEMP_NSS_DB_PASSWD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"New Test User2\" new_test_user2"
        rlRun "pki -d $TEMP_NSS_DB/ \
                           -n admin-user1-crmf \
                           -c $TEMP_NSS_DB_PASSWD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                           ca-user-add --fullName=\"New Test User2\" new_test_user2 > $TmpDir/pki_ca_user_cert_del_useradd_0020crmf.out 2>&1" \
                            0 \
                            "Adding a new user as admin_user1"
        rlAssertGrep "Added user \"new_test_user2\"" "$TmpDir/pki_ca_user_cert_del_useradd_0020crmf.out"
        rlAssertGrep "User ID: new_test_user2" "$TmpDir/pki_ca_user_cert_del_useradd_0020crmf.out"
        rlAssertGrep "Full name: New Test User2" "$TmpDir/pki_ca_user_cert_del_useradd_0020crmf.out"

	rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-del admin_user1 \"2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=admin_user1,E=admin_user1@example.org,CN=Admin User1,OU=Engineering,O=Example.Inc,C=US\" > $TmpDir/pki_ca_user_cert_del_0020crmf.out" \
                        0 \
                        "Delete cert assigned to admin_user1"
                rlAssertGrep "Deleted certificate \"2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=admin_user1,E=admin_user1@example.org,CN=Admin User1,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_ca_user_cert_del_0020crmf.out"

	command="pki -d $TEMP_NSS_DB -n admin-user1-crmf -c $TEMP_NSS_DB_PASSWD  -h $CA_HOST -p $CA_PORT ca-user-add --fullName='New Test User6' new_test_user6"
         rlLog "Executing: $command"
        errmsg="PKIException: Unauthorized"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Adding a new user as admin_user1-crmf after deleting the cert from the user"

	rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-group-member-del Administrators admin_user"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-group-member-del Administrators admin_user1"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-del admin_user"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-del admin_user1"
        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-del new_test_user1"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-del new_test_user2"
	rlPhaseEnd

	##### Add an Agent user "agent_user", add a cert to agent_user, approve a cert request as agent_user" #####

	rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-delete-0021: Add an Agent user agent_user, add a cert to agent_user, approve a cert request as agent_user, delete the cert from agent_user and approving a new cert request should fail"
		rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"Agent User\" --type=\"Certificate Manager Agents\" agent_user"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-group-member-add \"Certificate Manager Agents\" agent_user > $TmpDir/pki-user-add-ca-group0021.out"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-add --fullName=\"Certificate Manager Agents\" agent_user1"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-group-member-add \"Certificate Manager Agents\" agent_user1 > $TmpDir/pki-user-add-ca-group00211.out"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn:\"Agent User\" subject_uid:\"agent_user\" subject_email:agent_user@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_pkcs10_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_pkcs10_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_pkcs10_serialNumber --encoded > $TmpDir/pki_ca_user_cert_del_encoded_0021pkcs10.out" 0 "Executing pki cert-show $valid_pkcs10_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_ca_user_cert_del_encoded_0021pkcs10.out > $TmpDir/pki_ca_user_cert_del_validcert_0021pkcs10.pem"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn:\"Agent User1\" subject_uid:\"agent_user1\" subject_email:agent_user1@example.org \
        organizationalunit:Engineering organization:Example.Inc country:US archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$CERTDB_DIR cert_db_pwd:$CERTDB_DIR_PASSWORD \
        certdb_nick:\"$(eval echo \$${subsystemId}_agentV_user)\" cert_info:$cert_info"
        local valid_crmf_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local valid_decimal_crmf_serialNumber=$(cat $cert_info| grep decimal_valid_serialNumber | cut -d- -f2)
        rlRun "pki -h $CA_HOST -p $CA_PORT cert-show $valid_crmf_serialNumber --encoded > $TmpDir/pki_ca_user_cert_del_encoded_0021crmf.out" 0 "Executing pki cert-show $valid_crmf_serialNumber"
        rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_ca_user_cert_del_encoded_0021crmf.out > $TmpDir/pki_ca_user_cert_del_validcert_0021crmf.pem"

        rlRun "certutil -d $TEMP_NSS_DB -A -n \"agentuserpkcs10\" -i $TmpDir/pki_ca_user_cert_del_validcert_0021pkcs10.pem  -t "u,u,u""
        rlRun "certutil -d $TEMP_NSS_DB -A -n \"agent-user1-crmf\" -i $TmpDir/pki_ca_user_cert_del_validcert_0021crmf.pem  -t "u,u,u""
	
	rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add agent_user --input $TmpDir/pki_ca_user_cert_del_validcert_0021pkcs10.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add agent_user --input $TmpDir/pki_ca_user_cert_del_validcert_0021pkcs10.pem  > $TmpDir/pki_ca_user_cert_del_useraddcert_0021pkcs10.out" \
                            0 \
                            "PKCS10 Cert is added to the user agent_user"

        rlLog "Executing pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add agent_user1 --input $TmpDir/pki_ca_user_cert_del_validcert_0021crmf.pem"
        rlRun "pki -d $CERTDB_DIR/ \
                           -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-cert-add agent_user1 --input $TmpDir/pki_ca_user_cert_del_validcert_0021crmf.pem  > $TmpDir/pki_ca_user_cert_del_useraddcert_0021crmf.out" \
                            0 \
                            "CRMF Cert is added to the user agent_user1"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$TEMP_NSS_DB cert_db_pwd:$TEMP_NSS_DB_PASSWD \
        certdb_nick:\"agentuserpkcs10\" cert_info:$cert_info" 0 "Successfully approved a cert by agent-user-pkcs10"

        rlRun "generate_new_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$TEMP_NSS_DB cert_db_pwd:$TEMP_NSS_DB_PASSWD \
        certdb_nick:\"agent-user1-crmf\" cert_info:$cert_info" 0 "Successfully approved a cert by agent-user1-crmf"

	rlRun "pki -d $CERTDB_DIR/ \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-cert-del agent_user \"2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=agent_user,E=agent_user@example.org,CN=Agent User,OU=Engineering,O=Example.Inc,C=US\" > $TmpDir/pki_ca_user_cert_del_0021pkcs10.out" \
                   0 \
                   "Delete cert assigned to agent_user"
        rlAssertGrep "Deleted certificate \"2;$valid_decimal_pkcs10_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=agent_user,E=agent_user@example.org,CN=Agent User,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_ca_user_cert_del_0021pkcs10.out"

	rlRun "pki -d $CERTDB_DIR/ \
                   -n $(eval echo \$${subsystemId}_adminV_user) \
                   -c $CERTDB_DIR_PASSWORD \
                   -h $CA_HOST \
                   -p $CA_PORT \
                   ca-user-cert-del agent_user1 \"2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=agent_user1,E=agent_user1@example.org,CN=Agent User1,OU=Engineering,O=Example.Inc,C=US\" > $TmpDir/pki_ca_user_cert_del_0021crmf.out" \
                   0 \
                   "Delete cert assigned to agent_user1"
        rlAssertGrep "Deleted certificate \"2;$valid_decimal_crmf_serialNumber;$(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME);UID=agent_user1,E=agent_user1@example.org,CN=Agent User1,OU=Engineering,O=Example.Inc,C=US\"" "$TmpDir/pki_ca_user_cert_del_0021crmf.out"

	rlRun "run_req_action_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:pkcs10 \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$TEMP_NSS_DB cert_db_pwd:$TEMP_NSS_DB_PASSWD \
        certdb_nick:\"agentuserpkcs10\" cert_info:$cert_info" 0 "Cert approval by agentuserpkcs10 should fail"

	rlAssertGrep "PKIException: Unauthorized" "$cert_info"

        rlRun "run_req_action_cert tmp_nss_db:$TEMP_NSS_DB tmp_nss_db_pwd:$TEMP_NSS_DB_PASSWD request_type:crmf \
        algo:rsa key_size:2048 subject_cn: subject_uid: subject_email: \
        organizationalunit: organization: country: archive:false req_profile:caUserCert \
        target_host:$CA_HOST protocol: port:$CA_PORT cert_db_dir:$TEMP_NSS_DB cert_db_pwd:$TEMP_NSS_DB_PASSWD \
        certdb_nick:\"agent-user1-crmf\" cert_info:$cert_info" 0 "Cert approval by agent-user1-crmf should fail"

	rlAssertGrep "PKIException: Unauthorized" "$cert_info"

	rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-group-member-del \"Certificate Manager Agents\" agent_user"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-group-member-del \"Certificate Manager Agents\" agent_user1"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-del agent_user"

        rlRun "pki -d $CERTDB_DIR \
                            -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                            ca-user-del agent_user1"
	rlPhaseEnd

#===Deleting users===#
rlPhaseStartTest "pki_user_cli_user_cleanup: Deleting role users"

        j=1
        while [ $j -lt 3 ] ; do
               eval usr=\$user$j
               rlRun "pki -d $CERTDB_DIR \
			  -n $(eval echo \$${subsystemId}_adminV_user) \
                           -c $CERTDB_DIR_PASSWORD \
                           -h $CA_HOST \
                           -p $CA_PORT \
                           ca-user-del  $usr > $TmpDir/pki-user-del-ca-user-symbol-00$j.out" \
                           0 \
                           "Deleted user $usr"
                rlAssertGrep "Deleted user \"$usr\"" "$TmpDir/pki-user-del-ca-user-symbol-00$j.out"
                let j=$j+1
        done
        #Delete temporary directory
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
}
