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
        self.add_module(SubsystemAuthManagerCLI(self))


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


class SubsystemAuthManagerCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__(
            'manager', '%s authentication manager management commands' % parent.parent.name.upper())

        self.parent = parent
        self.add_module(SubsystemAuthManagerFindCLI(self))
        self.add_module(SubsystemAuthManagerShowCLI(self))
        self.add_module(SubsystemAuthManagerAddCLI(self))
        self.add_module(SubsystemAuthManagerModifyCLI(self))
        self.add_module(SubsystemAuthManagerDeleteCLI(self))


class SubsystemAuthManagerFindCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__(
            'find',
            'Find %s authentication managers' % parent.parent.parent.name.upper())

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
        print('Usage: pki-server %s-auth-manager-find [OPTIONS]' % self.parent.parent.parent.name)
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

        # find auths.instance.<manager ID>.*
        pattern = re.compile(r'^auths\.instance\.([^\.]+)\.')
        manager_ids = set()

        for param in subsystem.config:

            m = pattern.match(param)
            if not m:
                continue

            manager_id = m.group(1)

            if manager_id.startswith('_'):
                continue

            manager_ids.add(manager_id)

        first = True
        for manager_id in sorted(manager_ids):

            if first:
                first = False
            else:
                print()

            print('  Manager ID: %s' % manager_id)

            plugin_param = 'auths.instance.%s.pluginName' % manager_id
            plugin_id = subsystem.config.get(plugin_param)
            print('  Plugin ID: %s' % plugin_id)


class SubsystemAuthManagerShowCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__(
            'show',
            'Display %s authentication manager' % parent.parent.parent.name.upper())

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
            '--plugin',
            dest='plugin_id')
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
            'manager_id',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server %s-auth-manager-show [OPTIONS] <manager ID>'
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

        # find auths.instance.<manager ID>.*
        pattern = 'auths.instance.%s.' % args.manager_id
        config = {}

        for param in subsystem.config:

            if not param.startswith(pattern):
                continue

            key = param[len(pattern):]
            config[key] = subsystem.config.get(param)

        if not config:
            raise pki.cli.CLIException(
                'No such authentication manager: %s' % args.manager_id)

        print('  Manager ID: %s' % args.manager_id)

        plugin_id = config.pop('pluginName', None)
        print('  Plugin ID: %s' % plugin_id)

        if config:
            print('  Properties:')
            for key in config:

                # skip properties that start with underscore
                # e.g. _001
                if key.startswith('_'):
                    continue

                # skip properties that contains underscore
                # e.g. ldapStringAttributes._001
                if '._' in key:
                    continue

                print('    %s: %s' % (key, config.get(key)))


class SubsystemAuthManagerAddCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__(
            'add',
            'Add %s authentication manager' % parent.parent.parent.name.upper())

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
            '--plugin',
            dest='plugin_id')
        self.parser.add_argument(
            '-D',
            dest='props',
            default=[],
            action='append')
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
            'manager_id',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server %s-auth-manager-add [OPTIONS] <manager ID>'
              % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat)')
        print('      --plugin                       Plugin ID')
        print('      -D<name>=<value>               Set property value.')
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

        # find auths.instance.<manager ID>.*
        pattern = 'auths.instance.%s.' % args.manager_id
        params = set()

        for param in subsystem.config:

            if not param.startswith(pattern):
                continue

            params.add(param)

        if params:
            raise pki.cli.CLIException(
                'Authentication manager already exists: %s' % args.manager_id)

        param = 'auths.instance.%s.pluginName' % args.manager_id
        subsystem.set_config(param, args.plugin_id)

        for line in args.props:
            parts = line.split('=', 1)
            name = parts[0]
            value = parts[1]

            param = 'auths.instance.%s.%s' % (args.manager_id, name)
            subsystem.set_config(param, value)

        subsystem.save()


class SubsystemAuthManagerModifyCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__(
            'mod',
            'Modify %s authentication manager' % parent.parent.parent.name.upper())

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
            '--plugin',
            dest='plugin_id')
        self.parser.add_argument(
            '-D',
            dest='props',
            default=[],
            action='append')
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
            'manager_id',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server %s-auth-manager-mod [OPTIONS] <manager ID>'
              % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat)')
        print('      --plugin                       Plugin ID')
        print('      -D<name>=<value>               Set property value.')
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

        # find auths.instance.<manager ID>.*
        pattern = 'auths.instance.%s.' % args.manager_id
        params = set()

        for param in subsystem.config:

            if not param.startswith(pattern):
                continue

            params.add(param)

        if not params:
            raise pki.cli.CLIException(
                'No such authentication manager: %s' % args.manager_id)

        param = 'auths.instance.%s.pluginName' % args.manager_id
        pki.util.set_property(subsystem.config, param, args.plugin_id)

        for line in args.props:
            parts = line.split('=', 1)
            name = parts[0]
            value = parts[1]

            param = 'auths.instance.%s.%s' % (args.manager_id, name)
            pki.util.set_property(subsystem.config, param, value)

        subsystem.save()


class SubsystemAuthManagerDeleteCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__(
            'del',
            'Delete %s authentication manager' % parent.parent.parent.name.upper())

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
            'manager_id',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server %s-auth-manager-del [OPTIONS] <manager ID>'
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

        # find auths.instance.<manager ID>.*
        pattern = 'auths.instance.%s.' % args.manager_id
        params = set()

        for param in subsystem.config:

            if not param.startswith(pattern):
                continue

            params.add(param)

        if not params:
            raise pki.cli.CLIException('No such authentication manager: %s' % args.manager_id)

        # remove auths.instance.<manager ID>.*
        for param in params:
            subsystem.config.pop(param, None)

        subsystem.save()
