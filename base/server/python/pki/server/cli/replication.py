#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
from __future__ import absolute_import
from __future__ import print_function
import getopt
import logging
import sys

import pki.cli
import pki.server.instance

logger = logging.getLogger(__name__)


class ReplicationCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(ReplicationCLI, self).__init__(
            'replication',
            '%s replication management commands' % parent.name.upper())

        self.parent = parent
        self.add_module(ReplicationAddCLI(self))


class ReplicationAddCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(ReplicationAddCLI, self).__init__(
            'add',
            'Add %s replication agreement' % parent.parent.name.upper())

        self.parent = parent

    def print_help(self):
        print('Usage: pki-server %s-replication-add [OPTIONS]' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>           Instance ID (default: pki-tomcat).')
        print('      --master-replication-port <port>   Master replication port')
        print('      --replication-port <port>          Replication port')
        print('      --replication-security <security>  Replication security.')
        print('      --as-current-user                  Run as current user.')
        print('  -v, --verbose                          Run in verbose mode.')
        print('      --debug                            Run in debug mode.')
        print('      --help                             Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'master-replication-port=',
                'replication-port=',
                'replication-security=',
                'as-current-user',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.parent.name
        master_replication_port = None
        replication_port = None
        replication_security = None
        as_current_user = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--master-replication-port':
                master_replication_port = a

            elif o == '--replication-port':
                replication_port = a

            elif o == '--replication-security':
                replication_security = a

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

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.add_replication(
            master_replication_port=master_replication_port,
            replication_port=replication_port,
            replication_security=replication_security,
            as_current_user=as_current_user)
