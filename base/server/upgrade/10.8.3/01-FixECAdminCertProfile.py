# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import absolute_import
import logging
import os

import pki

logger = logging.getLogger(__name__)


class FixECAdminCertProfile(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(FixECAdminCertProfile, self).__init__()
        self.message = 'Fix EC admin certificate profile'

    def upgrade_subsystem(self, instance, subsystem):

        if subsystem.name != 'ca':
            return

        self.backup(subsystem.cs_conf)

        path = subsystem.config.get('profile.caECAdminCert.config')
        if path is None:
            # Add missing path
            logger.info('Missing profile.caECAdminCert.config')

            path = "{0}/profiles/{1}/caECAdminCert.cfg".format(
                subsystem.base_dir, subsystem.name)

        else:
            # Fix existing path
            logger.info("Fixing profile.caECAdminCert.config")
            dirname = os.path.dirname(path)
            path = os.path.join(dirname, 'caECAdminCert.cfg')

        logger.info('New path: %s', path)
        subsystem.set_config('profile.caECAdminCert.config', path)

        subsystem.set_config('profile.caECAdminCert.class_id', 'caEnrollImpl')

        # check if caECAdminCert is part of profile.list
        profile_list = subsystem.config['profile.list'].split(',')
        if 'caECAdminCert' not in profile_list:
            profile_list.append('caECAdminCert')
            subsystem.set_config('profile.list', ','.join(profile_list))

        subsystem.save()
