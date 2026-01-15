# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the Lesser GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2015 Red Hat, Inc.
# All rights reserved.
#

import argparse
import collections
import grp
import logging
import os
import pwd
import shutil
from six import itervalues
import subprocess
import tempfile
import time

logger = logging.getLogger(__name__)


class CLI(object):

    def __init__(self, name, description, deprecated=False):

        self.name = name
        self.description = description
        self.parent = None
        self.deprecated = deprecated

        self.modules = collections.OrderedDict()
        self.parser = None
        self.extra_commands = None

    def get_full_name(self):
        if self.parent:
            return self.parent.get_full_module_name(self.name)
        return self.name

    def get_full_module_name(self, module_name):
        return self.get_full_name() + '-' + module_name

    def add_module(self, module):
        self.modules[module.name] = module
        module.parent = self

    def get_module(self, name):
        return self.modules.get(name)

    def get_top_module(self):
        if self.parent:
            return self.parent.get_top_module()
        return self

    def print_message(self, message):
        print('-' * len(message))
        print(message)
        print('-' * len(message))

    def print_help(self):

        print('Commands:')
        commands = {}

        if self.extra_commands:
            commands = self.extra_commands.copy()

        for module in itervalues(self.modules):

            if module.deprecated:
                continue

            commands[module.get_full_name()] = module.description

        for command, description in commands.items():
            print(' {:32}{:30}'.format(command, description))

        first = True

        for module in itervalues(self.modules):

            if not module.deprecated:
                continue

            if first:
                print()
                print('Deprecated:')
                first = False

            full_name = module.get_full_name()
            print(' {:32}{:30}'.format(full_name, module.description))

    def find_module(self, command):

        module = self

        while True:
            (module, command) = module.parse_command(command)

            if not module or not command:
                return module

    def create_parser(self, subparsers=None):

        if not self.parser:
            # create default parser
            self.parser = argparse.ArgumentParser(
                prog=self.name,
                add_help=False)

            # add basic arguments
            self.parser.add_argument(
                '-v',
                '--verbose',
                action='store_true')
            self.parser.add_argument(
                '--debug',
                action='store_true')
            self.parser.add_argument(
                '--help',
                action='store_true')

            # capture sub-command and args
            self.parser.add_argument(
                'remainder',
                nargs=argparse.REMAINDER)

        for module in self.modules.values():
            module.create_parser(subparsers=subparsers)

    def parse_command(self, command):

        # A command consists of parts joined by dashes: <part 1>-<part 2>-...-<part N>.
        # For example: cert-request-find

        # The command will be split into module name and sub command, for example:
        #  - module name: cert
        #  - sub command: request-find
        module_name = None
        sub_command = None

        # Search the module by incrementally adding parts into module name.
        # Repeat until it finds the module or until there is no more parts to
        # add.
        module = None
        position = 0

        while True:

            # Find the next dash.
            i = command.find('-', position)
            if i >= 0:
                # Dash found. Split command into module name and sub command.
                module_name = command[0:i]
                sub_command = command[i + 1:]
            else:
                # Dash not found. Use the whole command.
                module_name = command
                sub_command = None

            logger.debug('Module: %s', module_name)

            m = self.get_module(module_name)
            if m:
                # Module found. Check sub command.
                if not sub_command:
                    # No sub command. Use this module.
                    module = m
                    break

                # There is a sub command. It must be processed by module's
                # children.
                if len(m.modules) > 0:
                    # Module has children. Use this module.
                    module = m
                    break

                # Module doesn't have children. Keep looking.

            # If there's no more dashes, stop.
            if i < 0:
                break

            position = i + 1

        return (module, sub_command)

    def execute(self, argv, args=None):
        '''
        :param argv: Argument values
        :param args: Parsed arguments
        '''

        if not args:
            args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        command = None
        if len(args.remainder) > 0:
            command = args.remainder[0]
        logger.debug('CLI Command: %s', command)

        if not command:
            self.print_help()
            return

        (module, sub_command) = self.parse_command(command)

        if not module:
            raise Exception('Invalid module "%s".' % command)

        logger.debug('Module: %s', module.get_full_name())

        # Prepare module arguments.
        if sub_command:
            # If module command exists, include it as arguments:
            # <module command> <args>...
            module_args = [sub_command] + args.remainder[1:]

        else:
            # Otherwise, pass the original arguments: <args>...
            module_args = args.remainder[1:]

        module.execute(module_args)


class CLIException(Exception):

    def __init__(self, message, code=-1):
        super().__init__(message)

        self.code = code


class CLIEngine:

    def __init__(
            self,
            directory,
            password_conf,
            user=None,
            group=None):

        self.directory = directory
        self.password_conf = password_conf
        self.user = user
        self.group = group

        self.temp_dir = tempfile.mkdtemp()

        if user:
            self.uid = pwd.getpwnam(user).pw_uid
            if group:
                self.gid = grp.getgrnam(group).gr_gid
            else:
                self.gid = pwd.getpwnam(user).pw_gid
        else:
            self.uid = os.geteuid()
            self.gid = os.getegid()

        if os.geteuid() == 0 and self.user:
            os.chown(self.temp_dir, self.uid, self.gid)

        self.command_id = 0

        cmd = ['pki']

        if self.user:
            cmd.extend(['--runas-user', self.user])

        cmd.extend(['-d', self.directory])

        if self.password_conf:
            cmd.extend(['-f', self.password_conf])

        cmd.extend([
            '--tmp', self.temp_dir,
            '-'   # batch mode (no prompts)
        ])

        logger.debug('Command: %s', ' '.join(cmd))
        self.process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE)

    def execute(self, cmd):

        tokens = []
        for token in cmd:
            if ' ' in token:
                tokens.append('"' + token + '"')
            else:
                tokens.append(token)

        line = ' '.join(tokens)

        logger.debug('Command: pki> %s', line)

        self.process.stdin.write(line.encode('utf-8'))
        self.process.stdin.write('\n'.encode('utf-8'))
        self.process.stdin.flush()

        if line == 'exit':
            # don't wait for RC file
            return

        # wait for RC file
        rc_file = os.path.join(self.temp_dir, 'cmd-%d.rc' % self.command_id)
        logger.debug('Python RC file: %s', rc_file)

        self.command_id = self.command_id + 1

        counter = 0
        while not os.path.exists(rc_file) and counter <= 60:
            logger.debug('Waiting for RC file for %ds', counter)
            time.sleep(1)
            counter = counter + 1

        with open(rc_file, 'r', encoding='utf-8') as f:
            parts = f.read().split(':', 1)

        rc = int(parts[0])
        logger.debug('RC: %d', rc)

        if len(parts) > 1:
            message = parts[1]
        else:
            message = None
        logger.debug('Message: %s', message)

        if rc:
            raise CLIException(message, code=rc)

    def close(self):
        self.execute(['exit'])
        shutil.rmtree(self.temp_dir)
