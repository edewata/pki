#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import argparse
import logging
import re
import sys

import pki.cli

logger = logging.getLogger(__name__)


class SubsystemAuthCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__(
            'auth', '%s authentication management commands' % parent.name.upper())

        self.parent = parent
        self.add_module(SubsystemAuthPluginCLI(self))


class SubsystemAuthPluginCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__(
            'plugin', '%s authentication plugin management commands' % parent.parent.name.upper())

        self.parent = parent
        self.add_module(SubsystemAuthPluginFindCLI(self))
        self.add_module(SubsystemAuthPluginShowCLI(self))
        self.add_module(SubsystemAuthPluginAddCLI(self))
        self.add_module(SubsystemAuthPluginDeleteCLI(self))


class SubsystemAuthPluginFindCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__(
            'find',
            'Find %s authentication plugins' % parent.parent.parent.name.upper())

        self.parent = parent

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--as-current-user',
            action='store_true')
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

    def print_help(self):
        print('Usage: pki-server %s-auth-plugin-find [OPTIONS]' % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat)')
        print('      --as-current-user              Run as current user.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv, args=None):

        if not args:
            args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        instance_name = args.instance

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            raise pki.cli.CLIException('Invalid instance: %s' % instance_name)

        instance.load()

        subsystem_name = self.parent.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            raise pki.cli.CLIException('No such subsystem: %s' % subsystem_name.upper())

        # find auths.impl.<plugin ID>.*
        pattern = re.compile(r'^auths\.impl\.([^\.]+)\.')
        plugin_ids = set()

        for param in subsystem.config:

            m = pattern.match(param)
            if not m:
                continue

            plugin_id = m.group(1)

            if plugin_id.startswith('_'):
                continue

            plugin_ids.add(plugin_id)

        first = True
        for plugin_id in sorted(plugin_ids):

            if first:
                first = False
            else:
                print()

            print('  Plugin ID: %s' % plugin_id)

            class_param = 'auths.impl.%s.class' % plugin_id
            class_name = subsystem.config.get(class_param)
            print('  Class: %s' % class_name)


class SubsystemAuthPluginShowCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__(
            'show',
            'Display %s authentication plugin' % parent.parent.parent.name.upper())

        self.parent = parent

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--as-current-user',
            action='store_true')
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
        self.parser.add_argument(
            'plugin_id',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server %s-auth-plugin-show [OPTIONS] <plugin ID>'
              % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat)')
        print('      --as-current-user              Run as current user.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv, args=None):

        if not args:
            args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        instance_name = args.instance

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            raise pki.cli.CLIException('Invalid instance: %s' % instance_name)

        instance.load()

        subsystem_name = self.parent.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            raise pki.cli.CLIException('No such subsystem: %s' % subsystem_name.upper())

        # find auths.impl.<plugin ID>.*
        pattern = 'auths.impl.%s.' % args.plugin_id
        config = {}

        for param in subsystem.config:

            if not param.startswith(pattern):
                continue

            key = param[len(pattern):]
            config[key] = subsystem.config.get(param)

        if not config:
            raise pki.cli.CLIException(
                'No such authentication plugin: %s' % args.plugin_id)

        print('  Plugin ID: %s' % args.plugin_id)

        class_name = config.pop('class', None)
        print('  Class: %s' % class_name)

        if config:
            print('  Properties:')
            for key in config:
                print('    %s: %s' % (key, config.get(key)))


class SubsystemAuthPluginAddCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__(
            'add',
            'Add %s authentication plugin' % parent.parent.parent.name.upper())

        self.parent = parent

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--class',
            dest='class_name')
        self.parser.add_argument(
            '--as-current-user',
            action='store_true')
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
        self.parser.add_argument(
            'plugin_id',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server %s-auth-plugin-add [OPTIONS] <plugin ID>'
              % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat)')
        print('      --class <class name>           Plugin class')
        print('      --as-current-user              Run as current user.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv, args=None):

        if not args:
            args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        instance_name = args.instance

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            raise pki.cli.CLIException('Invalid instance: %s' % instance_name)

        instance.load()

        subsystem_name = self.parent.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            raise pki.cli.CLIException('No such subsystem: %s' % subsystem_name.upper())

        # find auths.impl.<plugin ID>.*
        pattern = 'auths.impl.%s.' % args.plugin_id
        params = set()

        for param in subsystem.config:

            if not param.startswith(pattern):
                continue

            params.add(param)

        if params:
            raise pki.cli.CLIException(
                'Authentication plugin already exists: %s' % args.plugin_id)

        class_param = 'auths.impl.%s.class' % args.plugin_id
        subsystem.set_config(class_param, args.class_name)

        subsystem.save()


class SubsystemAuthPluginDeleteCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__(
            'del',
            'Delete %s authentication plugin' % parent.parent.parent.name.upper())

        self.parent = parent

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--as-current-user',
            action='store_true')
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
        self.parser.add_argument(
            'plugin_id',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server %s-auth-plugin-del [OPTIONS] <plugin ID>'
              % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat)')
        print('      --as-current-user              Run as current user.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv, args=None):

        if not args:
            args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        instance_name = args.instance

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            raise pki.cli.CLIException('Invalid instance: %s' % instance_name)

        instance.load()

        subsystem_name = self.parent.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            raise pki.cli.CLIException('No such subsystem: %s' % subsystem_name.upper())

        # find auths.impl.<plugin ID>.*
        pattern = 'auths.impl.%s.' % args.plugin_id
        params = set()

        for param in subsystem.config:

            if not param.startswith(pattern):
                continue

            params.add(param)

        if not params:
            raise pki.cli.CLIException('No such authentication plugin: %s' % args.plugin_id)

        for param in params:
            subsystem.config.pop(param, None)

        subsystem.save()
