#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
import logging

import pki.server.upgrade

logger = logging.getLogger(__name__)


class FixKRAConnector(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super().__init__()
        self.message = 'Fix KRA Connector'

    def upgrade_subsystem(self, instance, subsystem):

        if subsystem.name != 'ca':
            # not a CA -> skip
            return

        self.backup(subsystem.cs_conf)

        host_param = 'ca.connector.KRA.host'
        if host_param not in subsystem.config:
            logger.info('No KRA connector')
            return

        # get transport cert nickname
        # by default use CAEnrollProfile.DEFAULT_TRANSPORT_CERT_NICKNAME
        nickname_param = 'ca.connector.KRA.transportCertNickname'
        nickname = subsystem.config.get(nickname_param, 'KRA Transport Certificate')
        logger.info('Transport cert nickname: %s', nickname)

        # get transport cert from CS.cfg
        cert_param = 'ca.connector.KRA.transportCert'
        cert_in_config = subsystem.config.get(cert_param)
        logger.info('Transport cert in CS.cfg: %s', cert_in_config)

        nssdb = instance.open_nssdb()
        try:
            # get transport cert from NSS database
            cert_in_nssdb = nssdb.get_cert(
                nickname=nickname,
                output_format='base64')
            logger.info('Transport cert in NSS database: %s', cert_in_nssdb)

            if not cert_in_config and not cert_in_nssdb:
                logger.error('Missing transport cert')
                raise Exception('Missing transport certificate')

            if not cert_in_config:
                logger.info('Transport cert already in NSS database')
                return

            if not cert_in_nssdb:
                logger.info('Importing transport cert into NSS database')
                nssdb.add_cert(
                    nickname,
                    cert_data=cert_in_config,
                    cert_format='base64',
                    runas=False)

                logger.info('Removing transport cert from CS.cfg')
                subsystem.config.pop(cert_param)
                return

            # transport certs exist in both locations
            if cert_in_config.upper() != cert_in_nssdb.upper():
                logger.error('Transport certs mismatch')
                raise Exception(
                    'Transport certificates in %s and in %s do not match' %
                    (cert_param, nickname))

            # keep transport cert already in NSS database
            logger.info('Removing duplicate transport cert in CS.cfg')
            subsystem.config.pop(cert_param)

        finally:
            nssdb.close()

        subsystem.save()
