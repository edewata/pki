# Authors:
#     Endi S. Dewata <edewata@redhat.com>
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
# Copyright (C) 2015 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
from __future__ import print_function
import getopt
import inspect
import io
import logging
import os
import shutil
import sys
import tempfile
import textwrap
import time

import pki.cli
import pki.server
import pki.server.cli.audit
import pki.server.cli.config
import pki.server.cli.db
import pki.server.cli.group
import pki.server.cli.range
import pki.server.cli.subsystem
import pki.server.cli.user
import pki.server.instance

logger = logging.getLogger(__name__)


class CACLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('ca', 'CA management commands')

        self.add_module(CACreateCLI())
        self.add_module(CARemoveCLI())
        self.add_module(pki.server.cli.subsystem.SubsystemDeployCLI(self))
        self.add_module(pki.server.cli.subsystem.SubsystemUndeployCLI(self))

        self.add_module(pki.server.cli.audit.AuditCLI(self))
        self.add_module(CACertCLI())
        self.add_module(CACloneCLI())
        self.add_module(pki.server.cli.config.SubsystemConfigCLI(self))
        self.add_module(pki.server.cli.db.SubsystemDBCLI(self))
        self.add_module(pki.server.cli.group.GroupCLI(self))
        self.add_module(CAProfileCLI())
        self.add_module(pki.server.cli.range.RangeCLI(self))
        self.add_module(pki.server.cli.user.UserCLI(self))


class CACreateCLI(pki.cli.CLI):

    def __init__(self):
        super(CACreateCLI, self).__init__(
            'create', 'Create CA subsystem')

    def print_help(self):
        print('Usage: pki-server ca-create [OPTIONS] [name]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --force                        Force creation.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'database=', 'issuer=',
                'force',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        name = 'ca'
        instance_name = 'pki-tomcat'
        force = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--force':
                force = True

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) > 0:
            name = args[0]

        instance = pki.server.instance.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        server_config = instance.get_server_config()

        subsystem = pki.server.subsystem.PKISubsystemFactory.create(instance, name)

        # Creating /var/lib/pki/<instance>/<subsystem>
        logger.info('Creating %s', subsystem.base_dir)
        instance.makedirs(subsystem.base_dir, force=force)

        # Creating /etc/pki/<instance>/<subsystem>
        conf_dir = os.path.join(instance.conf_dir, subsystem.name)
        logger.info('Creating %s', conf_dir)
        instance.makedirs(conf_dir, force=force)

        # Link /var/lib/pki/<instance>/<subsystem>/conf
        # to /etc/pki/<instance>/<subsystem>
        conf_dir_link = os.path.join(subsystem.base_dir, 'conf')
        logger.info('Creating %s', conf_dir_link)
        instance.symlink(conf_dir, conf_dir_link, force=force)

        share_dir = os.path.join(pki.server.PKIServer.SHARE_DIR, subsystem.name)

        # Copy /usr/share/pki/<subsystem>/conf/CS.cfg
        # to /etc/pki/<instance>/<subsystem>/CS.cfg
        cs_conf = os.path.join(share_dir, 'conf', 'CS.cfg')
        logger.info('Creating %s', subsystem.cs_conf)

        params = {}
        params['PKI_INSTANCE_ROOT'] = pki.server.PKIServer.BASE_DIR
        params['PKI_INSTANCE_PATH'] = instance.base_dir
        params['PKI_INSTANCE_NAME'] = instance.name
        params['PKI_SUBSYSTEM_TYPE'] = subsystem.name

        params['PKI_AGENT_SECURE_PORT'] = server_config.get_secure_port()
        params['PKI_EE_SECURE_PORT'] = server_config.get_secure_port()
        params['PKI_EE_SECURE_CLIENT_AUTH_PORT'] = server_config.get_secure_port()
        params['PKI_ADMIN_SECURE_PORT'] = server_config.get_secure_port()
        params['PKI_SECURE_PORT'] = server_config.get_secure_port()
        params['PKI_UNSECURE_PORT'] = server_config.get_unsecure_port()
        params['TOMCAT_SERVER_PORT'] = server_config.get_port()
        params['PKI_PROXY_SECURE_PORT'] = ''
        params['PKI_PROXY_UNSECURE_PORT'] = ''

        params['PKI_USER'] = instance.name
        params['PKI_GROUP'] = instance.group

        params['PKI_HOSTNAME'] = 'localhost.localdomain'
        params['PKI_DS_SECURE_CONNECTION'] = 'false'
        params['PKI_SYSTEMD_SERVICENAME'] = 'pki-tomcatd@%s.service' % instance.name
        params['MASTER_CRL_ENABLE'] = 'false'
        params['PKI_ENABLE_RANDOM_SERIAL_NUMBERS'] = 'false'
        params['PKI_PROFILE_SUBSYSTEM'] = 'ProfileSubsystem'
        params['PKI_CFG_PATH_NAME'] = subsystem.cs_conf

        params['INSTALL_TIME'] = time.asctime(time.localtime(time.time()))
        params['PKI_PIDDIR'] = '/var/run/pki/tomcat'
        params['PKI_RANDOM_NUMBER'] = ''
        params['PKI_SSL_SERVER_NICKNAME'] = 'sslserver'

        instance.copyfile(
            cs_conf,
            subsystem.cs_conf,
            params=params,
            force=force)

        # Copy /usr/share/pki/<subsystem>/conf/registry.cfg
        # to /etc/pki/<instance>/<subsystem>/registry.cfg
        registry_conf = os.path.join(share_dir, 'conf', 'registry.cfg')
        logger.info('Creating %s', subsystem.registry_conf)
        instance.copy(registry_conf, subsystem.registry_conf, force=force)

        # Copy /usr/share/pki/<subsystem>/conf/database.conf
        # to /etc/pki/<instance>/<subsystem>/database.conf
        database_template = os.path.join(share_dir, 'conf', 'database.conf')
        database_conf = os.path.join(subsystem.conf_dir, 'database.conf')
        logger.info('Creating %s', database_conf)
        instance.copy(database_template, database_conf, force=force)

        # Copy /usr/share/pki/<subsystem>/conf/realm.conf
        # to /etc/pki/<instance>/<subsystem>/realm.conf
        realm_template = os.path.join(share_dir, 'conf', 'realm.conf')
        realm_conf = os.path.join(subsystem.conf_dir, 'realm.conf')
        logger.info('Creating %s', realm_conf)
        instance.copy(realm_template, realm_conf, force=force)

        # Copy /usr/share/pki/<subsystem>/conf/<type>AdminCert.profile
        # to /etc/pki/<instance>/<subsystem>/adminCert.profile
        admin_profile_template = os.path.join(share_dir, 'conf', 'rsaAdminCert.profile')
        admin_profile = os.path.join(subsystem.conf_dir, 'adminCert.profile')
        logger.info('Creating %s', admin_profile)
        instance.copy(admin_profile_template, admin_profile, force=force)

        # Copy /usr/share/pki/<subsystem>/conf/caAuditSigningCert.profile
        # to /etc/pki/<instance>/<subsystem>/caAuditSigningCert.profile
        audit_signing_profile_template = os.path.join(share_dir, 'conf', 'caAuditSigning.profile')
        audit_signing_profile = os.path.join(subsystem.conf_dir, 'caAuditSigning.profile')
        logger.info('Creating %s', audit_signing_profile)
        instance.copy(audit_signing_profile_template, audit_signing_profile, force=force)

        # Copy /usr/share/pki/<subsystem>/conf/caCert.profile
        # to /etc/pki/<instance>/<subsystem>/caCert.profile
        signing_profile_template = os.path.join(share_dir, 'conf', 'caCert.profile')
        signing_profile = os.path.join(subsystem.conf_dir, 'caCert.profile')
        logger.info('Creating %s', signing_profile)
        instance.copy(signing_profile_template, signing_profile, force=force)

        # Copy /usr/share/pki/<subsystem>/conf/caOCSPCert.profile
        # to /etc/pki/<instance>/<subsystem>/caOCSPCert.profile
        ocsp_signing_profile_template = os.path.join(share_dir, 'conf', 'caOCSPCert.profile')
        ocsp_signing_profile = os.path.join(subsystem.conf_dir, 'caOCSPCert.profile')
        logger.info('Creating %s', ocsp_signing_profile)
        instance.copy(ocsp_signing_profile_template, ocsp_signing_profile, force=force)

        # Copy /usr/share/pki/<subsystem>/conf/<type>ServerCert.profile
        # to /etc/pki/<instance>/<subsystem>/serverCert.profile
        sslserver_profile_template = os.path.join(share_dir, 'conf', 'rsaServerCert.profile')
        sslserver_profile = os.path.join(subsystem.conf_dir, 'serverCert.profile')
        logger.info('Creating %s', sslserver_profile)
        instance.copy(sslserver_profile_template, sslserver_profile, force=force)

        # Copy /usr/share/pki/<subsystem>/conf/<type>SubsystemCert.profile
        # to /etc/pki/<instance>/<subsystem>/subsystemCert.profile
        subsystem_profile_template = os.path.join(share_dir, 'conf', 'rsaSubsystemCert.profile')
        subsystem_profile = os.path.join(subsystem.conf_dir, 'subsystemCert.profile')
        logger.info('Creating %s', subsystem_profile)
        instance.copy(subsystem_profile_template, subsystem_profile, force=force)

        # Create /var/log/pki/<instance>/<subsystem>
        log_dir = os.path.join(instance.log_dir, subsystem.name)
        logger.info('Creating %s', log_dir)
        instance.makedirs(log_dir, exist_ok=True)

        # Link /var/lib/pki/<instance>/<subsystem>/logs
        # to /var/log/pki/<instance>/<subsystem>
        log_dir_link = os.path.join(subsystem.base_dir, 'logs')
        logger.info('Creating %s', log_dir_link)
        instance.symlink(log_dir, log_dir_link, force=force)

        # Create /var/log/pki/<instance>/<subsystem>/archive
        log_archive_dir = os.path.join(log_dir, 'archive')
        logger.info('Creating %s', log_archive_dir)
        instance.makedirs(log_archive_dir, exist_ok=True)

        # Create /var/log/pki/<instance>/<subsystem>/signedAudit
        log_audit_dir = os.path.join(log_dir, 'signedAudit')
        logger.info('Creating %s', log_audit_dir)
        instance.makedirs(log_audit_dir, exist_ok=True)

        # Link /var/lib/pki/<instance>/<subsystem>/registry
        # to /etc/sysconfig/pki/tomcat/<instance>
        registry_link = os.path.join(subsystem.base_dir, 'registry')
        service_conf = os.path.join(pki.server.SYSCONFIG_DIR, 'tomcat')
        logger.info('Creating %s', registry_link)
        instance.symlink(service_conf, registry_link, force=force)

        # Copy /usr/share/pki/ca/profiles/ca
        # to /var/lib/pki/<instance>/<subsystem>/profiles/ca
        profiles_dir_source = os.path.join(share_dir, 'profiles', 'ca')
        profiles_dir_target = os.path.join(subsystem.base_dir, 'profiles', 'ca')
        logger.info('Creating %s', profiles_dir_target)
        instance.copy(profiles_dir_source, profiles_dir_target, force=force)

        subsystem.load()


class CARemoveCLI(pki.cli.CLI):

    def __init__(self):
        super(CARemoveCLI, self).__init__(
            'remove', 'Remove CA subsystem')

    def print_help(self):
        print('Usage: pki-server ca-remove [OPTIONS] [name]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --force                        Force removal.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'force',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        name = 'ca'
        instance_name = 'pki-tomcat'
        force = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--force':
                force = True

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) > 0:
            name = args[0]

        instance = pki.server.instance.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        subsystem = instance.get_subsystem(name)
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        # Remove /var/log/pki/<instance>/<subsystem>
        log_dir = os.path.join(instance.log_dir, subsystem.name)
        logger.info('Removing %s', log_dir)
        pki.util.rmtree(log_dir, force=force)

        # Remove /etc/pki/<instance>/<subsystem>
        conf_dir = os.path.join(instance.conf_dir, subsystem.name)
        logger.info('Removing %s', conf_dir)
        pki.util.rmtree(conf_dir, force=force)

        # Remove /var/lib/pki/<instance>/<subsystem>
        logger.info('Removing %s', subsystem.base_dir)
        pki.util.rmtree(subsystem.base_dir, force=force)


class CACertCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('cert', 'CA certificates management commands')

        self.add_module(CACertFindCLI())
        self.add_module(CACertCreateCLI())
        self.add_module(CACertImportCLI())
        self.add_module(CACertRemoveCLI())
        self.add_module(CACertChainCLI())
        self.add_module(CACertRequestCLI())


class CACertFindCLI(pki.cli.CLI):
    '''
    Find certificates in CA
    '''

    help = '''\
        Usage: pki-server ca-cert-find [OPTIONS]

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
              --status <status>              Certificate status: VALID, INVALID, REVOKED, EXPIRED, REVOKED_EXPIRED
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''  # noqa: E501

    def __init__(self):
        super().__init__('find', inspect.cleandoc(self.__class__.__doc__))

    def print_help(self):
        print(textwrap.dedent(self.__class__.help))

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'status=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        status = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--status':
                status = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

        instance = pki.server.instance.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        subsystem.find_certs(
            status=status)


class CACertCreateCLI(pki.cli.CLI):
    '''
    Create certificate from certificate request in CA
    '''

    help = '''\
        Usage: pki-server ca-cert-create [OPTIONS]

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
              --request <ID>                 Request ID
              --profile <ID>                 Profile ID
              --type <type>                  Certificate type: selfsign (default), local
              --key-id <ID>                  Key ID
              --key-token <name>             Key token
              --key-algorithm <name>         Key algorithm (default: SHA256withRSA)
              --signing-algorithm <name>     Signing algorithm (default: SHA256withRSA)
              --serial <serial>              Certificate serial number
              --format <format>              Certificate format: PEM (default), DER
              --cert <path>                  Certificate path
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''

    def __init__(self):
        super().__init__('create', inspect.cleandoc(self.__class__.__doc__))

    def print_help(self):
        print(textwrap.dedent(self.__class__.help))

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'request=', 'profile=', 'type=',
                'key-id=', 'key-token=', 'key-algorithm=',
                'signing-algorithm=',
                'serial=', 'format=', 'cert=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        request_id = None
        profile_id = None
        cert_type = None
        key_id = None
        key_token = None
        key_algorithm = None
        signing_algorithm = None
        serial = None
        cert_format = None
        cert_path = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--request':
                request_id = a

            elif o == '--profile':
                profile_id = a

            elif o == '--type':
                cert_type = a

            elif o == '--key-id':
                key_id = a

            elif o == '--key-token':
                key_token = a

            elif o == '--key-algorithm':
                key_algorithm = a

            elif o == '--signing-algorithm':
                signing_algorithm = a

            elif o == '--serial':
                serial = a

            elif o == '--format':
                cert_format = a

            elif o == '--cert':
                cert_path = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

        instance = pki.server.instance.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        cert_data = subsystem.create_cert(
            request_id=request_id,
            profile_id=profile_id,
            cert_type=cert_type,
            key_token=key_token,
            key_id=key_id,
            key_algorithm=key_algorithm,
            signing_algorithm=signing_algorithm,
            serial=serial,
            cert_format=cert_format)

        if cert_path:
            with open(cert_path, 'wb') as f:
                f.write(cert_data)

        else:
            sys.stdout.buffer.write(cert_data)


class CACertImportCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('import', 'Import certificate into CA')

    def print_help(self):
        print('Usage: pki-server ca-cert-import [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat)')
        print('      --cert <path>                  Certificate path')
        print('      --format <format>              Certificate format: PEM (default), DER')
        print('      --profile <ID>                 Profile ID')
        print('      --request <ID>                 Request ID')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'cert=', 'format=', 'profile=', 'request=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        cert_path = None
        cert_format = None
        profile_id = None
        request_id = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--cert':
                cert_path = a

            elif o == '--format':
                cert_format = a

            elif o == '--profile':
                profile_id = a

            elif o == '--request':
                request_id = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

        instance = pki.server.instance.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        subsystem.import_cert(
            cert_path=cert_path,
            cert_format=cert_format,
            profile_id=profile_id,
            request_id=request_id)


class CACertRemoveCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('del', 'Remove certificate in CA')

    def print_help(self):
        print('Usage: pki-server ca-cert-remove [OPTIONS] <serial number>')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        if len(args) != 1:
            logger.error('Missing serial number')
            self.print_help()
            sys.exit(1)

        serial_number = args[0]
        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

        instance = pki.server.instance.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        subsystem.remove_cert(serial_number)


class CACertChainCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('chain', 'CA certificate chain management commands')

        self.add_module(CACertChainExportCLI())


class CACertChainExportCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('export', 'Export certificate chain')

    def print_help(self):
        print('Usage: pki-server ca-cert-chain-export [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --pkcs12-file <path>           PKCS #12 file to store certificates and keys.')
        print('      --pkcs12-password <password>   Password for the PKCS #12 file.')
        print('      --pkcs12-password-file <path>  File containing the PKCS #12 password.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'pkcs12-file=', 'pkcs12-password=', 'pkcs12-password-file=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        pkcs12_file = None
        pkcs12_password = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--pkcs12-file':
                pkcs12_file = a

            elif o == '--pkcs12-password':
                pkcs12_password = a.encode()

            elif o == '--pkcs12-password-file':
                with io.open(a, 'rb') as f:
                    pkcs12_password = f.read()

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

        if not pkcs12_file:
            logger.error('Missing PKCS #12 file')
            self.print_help()
            sys.exit(1)

        if not pkcs12_password:
            logger.error('Missing PKCS #12 password')
            self.print_help()
            sys.exit(1)

        instance = pki.server.instance.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        tmpdir = tempfile.mkdtemp()

        try:
            pkcs12_password_file = os.path.join(tmpdir, 'pkcs12_password.txt')
            with open(pkcs12_password_file, 'wb') as f:
                f.write(pkcs12_password)

            subsystem.export_cert_chain(pkcs12_file, pkcs12_password_file)

        finally:
            shutil.rmtree(tmpdir)


class CACertRequestCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('request', 'CA certificate requests management commands')

        self.add_module(CACertRequestFindCLI())
        self.add_module(CACertRequestShowCLI())

    @staticmethod
    def print_request(request, details=False):
        print('  Request ID: %s' % request['id'])
        print('  Type: %s' % request['type'])
        print('  Status: %s' % request['status'])

        if details:
            print('  Request: %s' % request['request'])


class CACertRequestFindCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('find', 'Find CA certificate requests')

    def print_help(self):
        print('Usage: pki-server ca-cert-request-find [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --cert                         Issued certificate.')
        print('      --cert-file                    File containing issued certificate.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'cert=', 'cert-file=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        cert = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--cert':
                cert = a

            elif o == '--cert-file':
                with io.open(a, 'rb') as f:
                    cert = f.read()

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

        instance = pki.server.instance.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        results = subsystem.find_cert_requests(cert=cert)

        self.print_message('%s entries matched' % len(results))

        first = True
        for request in results:
            if first:
                first = False
            else:
                print()

            CACertRequestCLI.print_request(request)


class CACertRequestShowCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('show', 'Show CA certificate request')

    def print_help(self):
        print('Usage: pki-server ca-cert-request-show [OPTIONS] <request ID>')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --output-file <file_name>      Save request in file.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'output-file=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        if len(args) != 1:
            logger.error('Missing request ID')
            self.print_help()
            sys.exit(1)

        request_id = args[0]
        instance_name = 'pki-tomcat'
        output_file = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--output-file':
                output_file = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

        instance = pki.server.instance.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        request = subsystem.get_cert_requests(request_id)

        if output_file:
            with io.open(output_file, 'wb') as f:
                f.write(request['request'].encode())

        else:
            CACertRequestCLI.print_request(request, details=True)


class CACloneCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('clone', 'CA clone management commands')

        self.add_module(CAClonePrepareCLI())


class CAClonePrepareCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('prepare', 'Prepare CA clone')

    def print_help(self):
        print('Usage: pki-server ca-clone-prepare [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --pkcs12-file <path>           PKCS #12 file to store certificates and keys.')
        print('      --pkcs12-password <password>   Password for the PKCS #12 file.')
        print('      --pkcs12-password-file <path>  File containing the PKCS #12 password.')
        print('      --no-key                       Do not include private key.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'pkcs12-file=', 'pkcs12-password=', 'pkcs12-password-file=',
                'no-key',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        pkcs12_file = None
        pkcs12_password = None
        no_key = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--pkcs12-file':
                pkcs12_file = a

            elif o == '--pkcs12-password':
                pkcs12_password = a.encode()

            elif o == '--pkcs12-password-file':
                with io.open(a, 'rb') as f:
                    pkcs12_password = f.read()

            elif o == '--no-key':
                no_key = True

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

        if not pkcs12_file:
            logger.error('Missing PKCS #12 file')
            self.print_help()
            sys.exit(1)

        if not pkcs12_password:
            logger.error('Missing PKCS #12 password')
            self.print_help()
            sys.exit(1)

        instance = pki.server.instance.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        tmpdir = tempfile.mkdtemp()

        try:
            pkcs12_password_file = os.path.join(tmpdir, 'pkcs12_password.txt')
            with open(pkcs12_password_file, 'wb') as f:
                f.write(pkcs12_password)

            subsystem.export_system_cert(
                'subsystem', pkcs12_file, pkcs12_password_file, no_key=no_key)
            subsystem.export_system_cert(
                'signing', pkcs12_file, pkcs12_password_file, no_key=no_key, append=True)
            subsystem.export_system_cert(
                'ocsp_signing', pkcs12_file, pkcs12_password_file, no_key=no_key, append=True)
            subsystem.export_system_cert(
                'audit_signing', pkcs12_file, pkcs12_password_file, no_key=no_key, append=True)
            instance.export_external_certs(
                pkcs12_file, pkcs12_password_file, append=True)

        finally:
            shutil.rmtree(tmpdir)


class CAProfileCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('profile', 'CA profile management commands')

        self.add_module(CAProfileImportCLI())


class CAProfileImportCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('import', 'Import CA profiles')

    def print_help(self):
        print('Usage: pki-server ca-profile-import [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --input-folder <path>          Input folder.')
        print('      --as-current-user              Run as current user.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'input-folder=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        input_folder = '/usr/share/pki/ca/profiles/ca'
        as_current_user = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--input-folder':
                input_folder = a

            elif o == '--as-current-user':
                as_current_user = True

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

        instance = pki.server.instance.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        subsystem.import_profiles(
            input_folder=input_folder,
            as_current_user=as_current_user)
