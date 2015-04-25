#!/usr/bin/python -t
# Authors:
#     Matthew Harmsen <mharmsen@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2012 Red Hat, Inc.
# All rights reserved.
#

# PKI Deployment Imports
from .. import pkiconfig as config
from .. import pkimessages as log
from .. import pkiscriptlet


# PKI Deployment Security Databases Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):
    rv = 0

    def spawn(self, deployer):

        if config.str2bool(deployer.mdict['pki_skip_installation']):
            config.pki_log.info(log.SKIP_SECURITY_DATABASES_SPAWN_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            return self.rv
        config.pki_log.info(log.SECURITY_DATABASES_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        if config.str2bool(deployer.mdict['pki_hsm_enable']):
            deployer.password.create_hsm_password_conf(
                deployer.mdict['pki_shared_password_conf'],
                deployer.mdict['pki_pin'],
                deployer.mdict['pki_token_password'])
        else:
            deployer.password.create_password_conf(
                deployer.mdict['pki_shared_password_conf'],
                deployer.mdict['pki_pin'])
        # Since 'certutil' does NOT strip the 'token=' portion of
        # the 'token=password' entries, create a temporary server 'pfile'
        # which ONLY contains the 'password' for the purposes of
        # allowing 'certutil' to generate the security databases
        deployer.password.create_password_conf(
            deployer.mdict['pki_shared_pfile'],
            deployer.mdict['pki_pin'], pin_sans_token=True)
        deployer.file.modify(deployer.mdict['pki_shared_password_conf'])
        deployer.certutil.create_security_databases(
            deployer.mdict['pki_database_path'],
            deployer.mdict['pki_cert_database'],
            deployer.mdict['pki_key_database'],
            deployer.mdict['pki_secmod_database'],
            password_file=deployer.mdict['pki_shared_pfile'])
        if config.str2bool(deployer.mdict['pki_hsm_enable']):
            deployer.modutil.register_security_module(
                deployer.mdict['pki_database_path'],
                deployer.mdict['pki_hsm_modulename'],
                deployer.mdict['pki_hsm_libfile'])
        deployer.file.modify(
            deployer.mdict['pki_cert_database'],
            perms=config.PKI_DEPLOYMENT_DEFAULT_SECURITY_DATABASE_PERMISSIONS)
        deployer.file.modify(
            deployer.mdict['pki_key_database'],
            perms=config.PKI_DEPLOYMENT_DEFAULT_SECURITY_DATABASE_PERMISSIONS)
        deployer.file.modify(
            deployer.mdict['pki_secmod_database'],
            perms=config.PKI_DEPLOYMENT_DEFAULT_SECURITY_DATABASE_PERMISSIONS)

        if len(deployer.instance.tomcat_instance_subsystems()) < 2:
            # only create a self signed cert for a new instance
            #
            # NOTE:  ALWAYS create the temporary sslserver certificate
            #        in the software DB regardless of whether the
            #        instance will utilize 'softokn' or an HSM
            #
            rv = deployer.certutil.verify_certificate_exists(
                deployer.mdict['pki_database_path'],
                deployer.mdict['pki_cert_database'],
                deployer.mdict['pki_key_database'],
                deployer.mdict['pki_secmod_database'],
                deployer.mdict['pki_self_signed_token'],
                deployer.mdict['pki_self_signed_nickname'],
                password_file=deployer.mdict['pki_shared_pfile'])
            if not rv:
                deployer.file.generate_noise_file(
                    deployer.mdict['pki_self_signed_noise_file'],
                    deployer.mdict['pki_self_signed_noise_bytes'])
                deployer.certutil.generate_self_signed_certificate(
                    deployer.mdict['pki_database_path'],
                    deployer.mdict['pki_cert_database'],
                    deployer.mdict['pki_key_database'],
                    deployer.mdict['pki_secmod_database'],
                    deployer.mdict['pki_self_signed_token'],
                    deployer.mdict['pki_self_signed_nickname'],
                    deployer.mdict['pki_self_signed_subject'],
                    deployer.mdict['pki_self_signed_serial_number'],
                    deployer.mdict['pki_self_signed_validity_period'],
                    deployer.mdict['pki_self_signed_issuer_name'],
                    deployer.mdict['pki_self_signed_trustargs'],
                    deployer.mdict['pki_self_signed_noise_file'],
                    password_file=deployer.mdict['pki_shared_pfile'])
                # Delete the temporary 'noise' file
                deployer.file.delete(
                    deployer.mdict['pki_self_signed_noise_file'])

            # Check to see if a secure connection is being used for the DS
            if config.str2bool(deployer.mdict['pki_ds_secure_connection']):
                # Check to see if a directory server CA certificate
                # using the same nickname already exists
                #
                # NOTE:  ALWAYS use the software DB regardless of whether
                #        the instance will utilize 'softokn' or an HSM
                #
                rv = deployer.certutil.verify_certificate_exists(
                    deployer.mdict['pki_database_path'],
                    deployer.mdict['pki_cert_database'],
                    deployer.mdict['pki_key_database'],
                    deployer.mdict['pki_secmod_database'],
                    deployer.mdict['pki_self_signed_token'],
                    deployer.mdict['pki_ds_secure_connection_ca_nickname'],
                    password_file=deployer.mdict['pki_shared_pfile'])
                if not rv:
                    # Import the directory server CA certificate
                    rv = deployer.certutil.import_cert(
                        deployer.mdict['pki_ds_secure_connection_ca_nickname'],
                        deployer.mdict['pki_ds_secure_connection_ca_trustargs'],
                        deployer.mdict['pki_ds_secure_connection_ca_pem_file'],
                        password_file=deployer.mdict['pki_shared_pfile'],
                        path=deployer.mdict['pki_database_path'],
                        token=deployer.mdict['pki_self_signed_token'])

        # Always delete the temporary 'pfile'
        deployer.file.delete(deployer.mdict['pki_shared_pfile'])
        return self.rv

    def destroy(self, deployer):

        config.pki_log.info(log.SECURITY_DATABASES_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        if deployer.mdict['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS \
                and len(deployer.instance.tomcat_instance_subsystems()) == 0:
            deployer.file.delete(deployer.mdict['pki_cert_database'])
            deployer.file.delete(deployer.mdict['pki_key_database'])
            deployer.file.delete(deployer.mdict['pki_secmod_database'])
            deployer.file.delete(deployer.mdict['pki_shared_password_conf'])
        return self.rv
