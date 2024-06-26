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
# Copyright (C) 2015 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
import subprocess

import pki.server.upgrade


class RemoveInaccessableURLsFromServerXML(
        pki.server.upgrade.PKIServerUpgradeScriptlet):
    def __init__(self):
        super(RemoveInaccessableURLsFromServerXML, self).__init__()
        self.message = 'Remove inaccessable URLs from server.xml'

    # pylint: disable=W1401
    def upgrade_instance(self, instance):
        subprocess.check_call([
            'sed', '-i',
            '-e', '\\|^.*EE Client Auth URL.*ca/eeca/ca.*$|d',
            '-e', '\\|^.*Unsecure URL.*kra/ee/kra.*$|d',
            '-e', '\\|^.*Secure EE URL.*kra/ee/kra.*$|d',
            '-e', '\\|^.*Unsecure URL.*tks/ee/tks.*$|d',
            '-e', '\\|^.*Secure EE URL.*tks/ee/tks.*$|d',
            instance.server_xml
        ])
