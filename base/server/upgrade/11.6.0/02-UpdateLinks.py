# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import os
import pki.server.upgrade

logger = logging.getLogger(__name__)


class UpdateLinks(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super().__init__()
        self.message = 'Update links'

    def update_link(self, instance, target, link):

        logger.info('Updating %s', link)

        # remove old link
        self.backup(link)
        os.remove(link)

        # create new link
        instance.symlink(target, link)

    def upgrade_instance(self, instance):

        # link /var/lib/pki/<instance>/alias
        # to conf/alias

        self.update_link(
            instance,
            os.path.join('conf', 'alias'),
            os.path.join(instance.base_dir, 'alias'))

    def upgrade_subsystem(self, instance, subsystem):

        # link /var/lib/pki/<instance>/<subsystem>/alias
        # to ../conf/alias

        self.update_link(
            instance,
            os.path.join('..', 'conf', 'alias'),
            os.path.join(instance.base_dir, subsystem.name, 'alias'))

        # link /var/lib/pki/<instance>/<subsystem>/conf
        # to ../conf/<subsystem>

        self.update_link(
            instance,
            os.path.join('..', 'conf', subsystem.name),
            os.path.join(instance.base_dir, subsystem.name, 'conf'))

        if subsystem.name == 'ca':

            # link /var/lib/pki/<instance>/ca/emails
            # to ../conf/ca/emails

            self.update_link(
                instance,
                os.path.join('..', 'conf', 'ca', 'emails'),
                os.path.join(instance.base_dir, 'ca', 'emails'))

            # link /var/lib/pki/<instance>/ca/profiles
            # to ../conf/ca/profiles

            self.update_link(
                instance,
                os.path.join('..', 'conf', 'ca', 'profiles'),
                os.path.join(instance.base_dir, 'ca', 'profiles'))
