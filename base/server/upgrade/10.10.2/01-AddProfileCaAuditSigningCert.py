# Authors:
#     Christina Fu <cfu@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import absolute_import
import logging
import os

import pki

logger = logging.getLogger(__name__)


class AddProfileCaAuditSigningCert(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(AddProfileCaAuditSigningCert, self).__init__()
        self.message = 'Add caAuditSigningCert profile'

    def upgrade_subsystem(self, instance, subsystem):

        if subsystem.name != 'ca':
            return

        # enable old profile caSignedLogCert to properly deprecate
        opath = os.path.join(subsystem.base_dir, 'profiles', 'ca', 'caSignedLogCert.cfg')
        self.backup(opath)

        oconfig = {}

        pki.util.load_properties(opath, oconfig)

        oconfig['enable'] = 'true'
        oconfig['desc'] = '(deprecated; use caAuditSigningCert) ' + \
            'This profile is for enrolling audit log signing certificates'
        oconfig['name'] = '(deprecated; use caAuditSigningCert) ' + \
            'Manual Audit Log Signing Certificate Enrollment'

        pki.util.store_properties(opath, oconfig)

        logger.info('Creating caAuditSigningCert.cfg')
        path = os.path.join(subsystem.base_dir, 'profiles', 'ca', 'caAuditSigningCert.cfg')
        self.backup(path)

        instance.copyfile(
            '/usr/share/pki/ca/profiles/ca/caAuditSigningCert.cfg',
            path,
            exist_ok=True)

        logger.info('Adding caAuditSigningCert into profile.list')
        profile_list = subsystem.config.get('profile.list').split(',')
        if 'caAuditSigningCert' not in profile_list:
            profile_list.append('caAuditSigningCert')
            profile_list.sort()
            subsystem.set_config('profile.list', ','.join(profile_list))

        logger.info('Adding profile.caAuditSigningCert.class_id')
        subsystem.set_config('profile.caAuditSigningCert.class_id', 'caEnrollImpl')

        logger.info('Adding profile.caAuditSigningCert.config')
        subsystem.set_config('profile.caAuditSigningCert.config', path)

        self.backup(subsystem.cs_conf)
        subsystem.save()
