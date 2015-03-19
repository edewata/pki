#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/legacy-tests/ca-tests/scep_tests
#   Description: SCEP Enrollment with CA
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki commands needs to be tested:
#  /usr/bin/sscep
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Asha Akkiangady <aakkiang@redhat.com>
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
. /opt/rhqa_pki/env.sh

run_pki-legacy-ca-scep_tests()
{
        local subsystemType=$1
        local csRole=$2

	rlPhaseStartSetup "Create temporary directory"
	        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        	rlRun "pushd $TmpDir"
        rlPhaseEnd

	 # Local Variables
        get_topo_stack $csRole $TmpDir/topo_file
        local CA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
        local tomcat_name=$(eval echo \$${CA_INST}_TOMCAT_INSTANCE_NAME)
        local ca_unsecure_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local ca_secure_port=$(eval echo \$${CA_INST}_SECURE_PORT)
        local ca_host=$(eval echo \$${csRole})
        local valid_agent_user=$CA_INST\_agentV
        local valid_agent_user_password=$CA_INST\_agentV_password
        local valid_admin_user=$CA_INST\_adminV
        local valid_admin_user_password=$CA_INST\_adminV_password
        local valid_audit_user=$CA_INST\_auditV
        local valid_audit_user_password=$CA_INST\_auditV_password
        local valid_operator_user=$CA_INST\_operatorV
        local valid_operator_user_password=$CA_INST\_operatorV_password
        local valid_agent_cert=$CA_INST\_agentV
	local ca_config_file="/var/lib/pki/$tomcat_name/ca/conf/CS.cfg"
	local search_string="ca.scep.enable=false"
	local replace_string="ca.scep.enable=true"


	rlPhaseStartTest "pki_ca_scep_tests-001: Perform scep enrollment with CA using sha512 fingerprint"
		local scep_enroll_url="http://$ca_host:$ca_unsecure_port/ca/cgi-bin/pkiclient.exe"
		local scep_location="ftp://wiki.idm.lab.bos.redhat.com/dirsec/images-mp1/packages/scep_software/sscep/rhel7-x86_64_modified"
		local scep_enroll_pin="netscape"
		local scep_password="netscape"
		local scep_host_ip=$(ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1 -d'/')

		#Turn on scep
		replace_string_in_a_file $ca_config_file $search_string $replace_string
		if [ $? -eq 0 ] ; then
			chown pkiuser:pkiuser $ca_config_file
			rhcs_stop_instance $tomcat_name
			rhcs_start_instance $tomcat_name
		fi	

		rlRun "wget $scep_location/sscep -O $TmpDir/sscep"
		#delete extisting sscep from /usr/bin if any
		rlLog "Delete existing sscep from /usr/bin = rm -rf /usr/bin/sscep"
		rlRun "rm -rf /usr/bin/sscep"
		#Move sscep to /usr/bin
		rlRun "mv $TmpDir/sscep /usr/bin"
		rlRun "chmod +x /usr/bin/sscep"
		#Get mkrequest
		rlRun "wget $scep_location/mkrequest -O $TmpDir/mkrequest"
		rlRun "mv $TmpDir/mkrequest /usr/bin"
		rlRun "chmod +x /usr/bin/mkrequest"

		#Add a flatfile auth to the CA instance conf dir
		local ca_file_loc="/var/lib/pki/$tomcat_name/ca/conf/flatfile.txt"
		cat > $ca_file_loc << ca_file_loc_EOF
UID:$scep_host_ip
PWD:$scep_password
ca_file_loc_EOF
		#Restart CA
		rhcs_stop_instance $tomcat_name
		rhcs_start_instance $tomcat_name

		#Copy sscep.conf file
		rlRun "wget $scep_location/sscep.conf -O $TmpDir/sscep.conf"
		local digest="sha512"

		#do scep enrollment
		rlRun "scep_do_enroll_with_sscep $scep_enroll_pin $scep_enroll_url $scep_host_ip $TmpDir $digest"

		rlAssertGrep "pkistatus: SUCCESS" "$TmpDir/scep_enroll.out"
		rlAssertGrep "certificate written as $TmpDir/cert.crt" "$TmpDir/scep_enroll.out"
		rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/cert.crt"
		rlAssertGrep "-----END CERTIFICATE-----" "$TmpDir/cert.crt"
	rlPhaseEnd

	
	rlPhaseStartTest "pki_ca_scep_tests-002: Perform scep enrollment with CA using sha256 fingerprint"
		local scep_enroll_url="http://$ca_host:$ca_unsecure_port/ca/cgi-bin/pkiclient.exe"
		local scep_location="ftp://wiki.idm.lab.bos.redhat.com/dirsec/images-mp1/packages/scep_software/sscep/rhel7-x86_64_modified"
		local scep_enroll_pin="netscape"
		local scep_password="netscape"
		local scep_host_ip=$(ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1 -d'/')

		#Turn on scep
		replace_string_in_a_file $ca_config_file $search_string $replace_string
		if [ $? -eq 0 ] ; then
			chown pkiuser:pkiuser $ca_config_file
			rhcs_stop_instance $tomcat_name
			rhcs_start_instance $tomcat_name
		fi

		rlRun "wget $scep_location/sscep -O $TmpDir/sscep"
		#delete extisting sscep from /usr/bin if any
		rlLog "Delete existing sscep from /usr/bin = rm -rf /usr/bin/sscep"
		rlRun "rm -rf /usr/bin/sscep"
		#Move sscep to /usr/bin
		rlRun "mv $TmpDir/sscep /usr/bin"
		rlRun "chmod +x /usr/bin/sscep"
		#Get mkrequest
		rlRun "wget $scep_location/mkrequest -O $TmpDir/mkrequest"
		rlRun "mv $TmpDir/mkrequest /usr/bin"
		rlRun "chmod +x /usr/bin/mkrequest"

		#Add a flatfile auth to the CA instance conf dir
		local ca_file_loc="/var/lib/pki/$tomcat_name/ca/conf/flatfile.txt"
		cat > $ca_file_loc << ca_file_loc_EOF
UID:$scep_host_ip
PWD:$scep_password
ca_file_loc_EOF
		#Restart CA
		rhcs_stop_instance $tomcat_name
		rhcs_start_instance $tomcat_name

		local digest="sha256"

		#Copy sscep.conf file
		rlRun "wget $scep_location/sscep.conf -O $TmpDir/sscep.conf"
		local orig_fingerprint="FingerPrint     sha512"
		local replace_fingerprint="FingerPrint     $digest"
		replace_string_in_a_file $TmpDir/sscep.conf $orig_fingerprint $replace_fingerprint
		
		#do scep enrollment
		rlRun "scep_do_enroll_with_sscep $scep_enroll_pin $scep_enroll_url $scep_host_ip $TmpDir $digest"

		rlAssertGrep "pkistatus: SUCCESS" "$TmpDir/scep_enroll.out"
		rlAssertGrep "certificate written as $TmpDir/cert.crt" "$TmpDir/scep_enroll.out"
		rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/cert.crt"
		rlAssertGrep "-----END CERTIFICATE-----" "$TmpDir/cert.crt"
	rlPhaseEnd
	rlPhaseStartTest "pki_ca_scep_tests_cleanup: delete temporary directory and turn off sscep "
		#Delete temporary directory
                rlRun "popd"
                rlRun "rm -r $TmpDir" 0 "Removing tmp directory"

		#Turn off scep
		replace_string_in_a_file $ca_config_file $replace_string $search_string
		if [ $? -eq 0 ] ; then
			chown pkiuser:pkiuser $ca_config_file
			rhcs_stop_instance $tomcat_name
			rhcs_start_instance $tomcat_name
		fi
	rlPhaseEnd
}
