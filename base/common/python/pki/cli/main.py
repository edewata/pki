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
# Copyright (C) 2014 Red Hat, Inc.
# All rights reserved.
#

import logging
import os
import shlex
import subprocess
import sys

import pki.cli
import pki.cli.password
import pki.cli.pkcs12
import pki.nssdb

logger = logging.getLogger(__name__)


PYTHON_COMMANDS = ['password-generate', 'pkcs12-import']


class PKICLI(pki.cli.CLI):

    def __init__(self):
        super(PKICLI, self).__init__(
            'pki', 'PKI command-line interface')

        self.database = None
        self.password = None
        self.password_file = None
        self.password_conf = None
        self.token = None
        self.ignore_banner = False

        self.add_module(pki.cli.password.PasswordCLI())
        self.add_module(pki.cli.pkcs12.PKCS12CLI())

    def get_full_module_name(self, module_name):
        return module_name

    def print_help(self):
        print('Usage: pki [OPTIONS]')
        print()
        print('      --client-type <type>     PKI client type (default: java)')
        print('   -d <path>                   NSS database location ' +
              '(default: ~/.dogtag/nssdb)')
        print('   -c <password>               NSS database password ' +
              '(mutually exclusive to -C and -f options)')
        print('   -C <password file>          NSS database password file ' +
              '(mutually exclusive to -c and -f options)')
        print('   -f <password config>        NSS database password configuration ' +
              '(mutually exclusive to -c and -C options)')
        print('      --token <name>           Security token name')
        print()
        print('  -v, --verbose                Run in verbose mode.')
        print('      --debug                  Show debug messages.')
        print('      --help                   Show help message.')
        print()

        super(PKICLI, self).print_help()

    def set_nss_default_db_type(self):
        """Validate NSS_DEFAULT_DB_TYPE

        Value is globally configured in /usr/share/pki/etc/pki.conf and
        sourced by shell wrapper scripts.
        """
        dbtype = os.environ.get('NSS_DEFAULT_DB_TYPE')
        if not dbtype:
            raise KeyError("NSS_DEFAULT_DB_TYPE env var is not set or empty.")
        if dbtype not in {'dbm', 'sql'}:
            raise ValueError(
                "Unsupported NSS_DEFAULT_DB_TYPE value '{}'".format(dbtype)
            )
        return dbtype

    def execute_java(self, args, properties=None, stdout=sys.stdout):

        self.set_nss_default_db_type()

        cmd = []

        java_home = os.getenv('JAVA_HOME')
        cmd.extend([java_home + '/bin/java'])

        pki_lib = os.getenv('PKI_LIB')
        cmd.extend([
            '-cp', pki_lib + '/*'
        ])

        java_fips_cmd = os.getenv('JAVA_FIPS_ENABLED')
        if java_fips_cmd:
            cmd.extend([
                java_fips_cmd
            ])

        if not properties:
            properties = {}

        for name in properties:
            option = '-D' + name + '=' + properties[name]
            cmd.append(option)

        logging_config = os.getenv('PKI_LOGGING_CONFIG')
        if logging_config and 'java.util.logging.config.file' not in properties:
            cmd.append('-Djava.util.logging.config.file=' + logging_config)

        cmd.append('com.netscape.cmstools.cli.MainCLI')

        # restore options for Java commands

        if self.database:
            cmd.extend(['-d', self.database])

        if self.password:
            cmd.extend(['-c', self.password])

        if self.password_file:
            cmd.extend(['-C', self.password_file])

        if self.password_conf:
            cmd.extend(['-f', self.password_conf])

        if not pki.nssdb.internal_token(self.token):
            cmd.extend(['--token', self.token])

        if self.ignore_banner:
            cmd.extend(['--ignore-banner'])

        if logger.isEnabledFor(logging.DEBUG):
            cmd.extend(['--debug'])

        elif logger.isEnabledFor(logging.INFO):
            cmd.extend(['-v'])

        cmd.extend(args)

        logger.debug('Command: %s', ' '.join(cmd))

        subprocess.check_call(cmd, stdout=stdout)

    def execute(self, argv, args=None):

        # append global options
        value = os.getenv('PKI_CLI_OPTIONS')
        args = shlex.split(value)
        args.extend(argv)

        client_type = 'java'

        properties = {}
        pki_options = []
        command = None
        cmd_args = []

        # read pki options before the command
        # remove options for Python module

        i = 0
        while i < len(args):
            # if arg is a command, stop
            if args[i][0] != '-':
                command = args[i]
                break

            # get properties
            if args[i] == '-D':
                try:
                    name, value = args[i + 1].split('=', 1)
                    properties[name] = value
                except IndexError:
                    break
                i = i + 2

            # get database path
            if args[i] == '-d':
                try:
                    self.database = args[i + 1]
                except IndexError:
                    break
                pki_options.append(args[i])
                pki_options.append(args[i + 1])
                i = i + 2

            # get database password
            elif args[i] == '-c':
                try:
                    self.password = args[i + 1]
                except IndexError:
                    break
                pki_options.append(args[i])
                pki_options.append(args[i + 1])
                i = i + 2

            # get database password file path
            elif args[i] == '-C':
                try:
                    self.password_file = args[i + 1]
                except IndexError:
                    break
                pki_options.append(args[i])
                pki_options.append(args[i + 1])
                i = i + 2

            # get database password config path
            elif args[i] == '-f':
                try:
                    self.password_conf = args[i + 1]
                except IndexError:
                    break
                pki_options.append(args[i])
                pki_options.append(args[i + 1])
                i = i + 2

            # get token name
            elif args[i] == '--token':
                try:
                    self.token = args[i + 1]
                except IndexError:
                    break
                pki_options.append(args[i])
                pki_options.append(args[i + 1])
                i = i + 2

            # check ignore banner option
            elif args[i] == '--ignore-banner':
                self.ignore_banner = True
                pki_options.append(args[i])
                i = i + 1

            # check verbose option
            elif args[i] == '-v' or args[i] == '--verbose':
                logging.getLogger().setLevel(logging.INFO)
                pki_options.append(args[i])
                i = i + 1

            # check debug option
            elif args[i] == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)
                pki_options.append(args[i])
                i = i + 1

            # get client type
            elif args[i] == '--client-type':
                try:
                    client_type = args[i + 1]
                except IndexError:
                    break
                pki_options.append(args[i])
                pki_options.append(args[i + 1])
                i = i + 2

            else:  # otherwise, save the arg for the next module
                cmd_args.append(args[i])
                i = i + 1

        # save the rest of the args
        while i < len(args):
            cmd_args.append(args[i])
            i = i + 1

        logger.debug('PKI options: %s', ' '.join(pki_options))
        logger.debug('PKI command: %s %s', command, ' '.join(cmd_args))

        if client_type == 'python' or command in PYTHON_COMMANDS:
            (module, module_args) = self.parse_args(cmd_args)
            module.execute(module_args)

        elif client_type == 'java':
            self.execute_java(cmd_args, properties)

        else:
            raise Exception('Unsupported client type: ' + client_type)


if __name__ == '__main__':

    logging.basicConfig(format='%(levelname)s: %(message)s')

    cli = PKICLI()

    try:
        cli.create_parser()

        # exclude script name
        cli.execute(sys.argv[1:])

    except subprocess.CalledProcessError as e:

        if logger.isEnabledFor(logging.DEBUG):
            logger.exception('Command: %s', ' '.join(e.cmd))

        elif logger.isEnabledFor(logging.INFO):
            logger.error('Command: %s', ' '.join(e.cmd))

        sys.exit(e.returncode)

    except KeyboardInterrupt:
        print()
        sys.exit(-1)
