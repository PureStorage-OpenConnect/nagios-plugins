#!/usr/bin/env python
# Copyright (c) 2018, 2019, 2020, 2022 Pure Storage, Inc.
#
# * Overview
#
# This simple Nagios/Icinga plugin code can be used to monitor Pure Storage FlashBlade systems.
# The Pure Storage Python REST Client is used to query the FlashBlade alert messages.
# Plugin leverages the remarkably helpful nagiosplugin library by Christian Kauhaus.
#
# * Installation
#
# The script should be copied to the Nagios plugins directory on the machine hosting the Nagios server or the NRPE
# for example the /usr/lib/nagios/plugins folder.
# Change the execution rights of the program to allow the execution to 'all' (usually chmod 0755).
#

"""Pure Storage FlashBlade alert messages status

   Nagios plugin to check the general state of a Pure Storage FlashBlade from the internal alert messages.
   The plugin has two mandatory arguments:  'endpoint', which specifies the target FB, 'apitoken', which
   specifies the autentication token for the REST call session. The FlashBlade is considered unhealty if
   there is any pending message that reports a warning or critical status of one or more components
"""

import argparse
import logging
import logging.handlers
import nagiosplugin
from pypureclient import flashblade, PureError


# Disable warnings using urllib3 embedded in requests or directly
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PureFBalert(nagiosplugin.Resource):
    """Pure Storage FlashBlade active alerts

    Retrieves the general health state of a FlashBlade from the internal alerts.

    """

    def __init__(self, endpoint, apitoken):
        self.endpoint = endpoint
        self.apitoken = apitoken
        self.info = 0
        self.warn = 0
        self.crit = 0
        self.logger = logging.getLogger(self.name)
        handler = logging.handlers.SysLogHandler(address = '/dev/log')
        handler.setLevel(logging.ERROR)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    @property
    def name(self):
        return 'PURE_FB_ALERT'

    def get_alerts(self):
        """Gets active alerts from FlashBlade."""
        fbinfo = []
        try:
            client = flashblade.Client(target=self.endpoint,
                                       api_token=self.apitoken,
                                       user_agent='Pure_Nagios_plugin/0.2.0')
            res = client.get_alerts(filter='state=\'open\'')
            if isinstance(res, flashblade.ValidResponse):
                fbinfo = list(res.items)
        except Exception as e:
            raise nagiosplugin.CheckError('FB REST call returned "{}"'.format(e))
        return(fbinfo)

    def probe(self):

        fbinfo = self.get_alerts()
        self.logger.debug('FB REST call returned "%s" ', fbinfo)
        for msg in fbinfo:
            if msg.state != 'open':
                continue
            if msg.severity == 'critical':
                self.crit += 1
            elif msg.severity == 'warning':
                self.warn += 1
            elif msg.severity == 'info':
                self.info += 1

        return [nagiosplugin.Metric('critical', self.crit, min=0),
                nagiosplugin.Metric('warning', self.warn, min=0),
                nagiosplugin.Metric('info', self.info, min=0)]

def parse_args():
    argp = argparse.ArgumentParser()
    argp.add_argument('endpoint', help="FB hostname or ip address")
    argp.add_argument('apitoken', help="FB api_token")
    argp.add_argument('--warning-crit', metavar='RANGE',
                      help='warning if number of critical messages is outside RANGE')
    argp.add_argument('--critical-crit', metavar='RANGE',
                      help='critical if number of critical messages is outside RANGE')
    argp.add_argument('--warning-warn', metavar='RANGE',
                      help='warning if number of warning messages is outside RANGE')
    argp.add_argument('--critical-warn', metavar='RANGE',
                      help='critical if number of warning messages is outside RANGE')
    argp.add_argument('--warning-info', metavar='RANGE',
                      help='warning if number of info messages is outside RANGE')
    argp.add_argument('--critical-info', metavar='RANGE',
                      help='critical if number of info messages is outside RANGE')
    argp.add_argument('-v', '--verbose', action='count', default=0,
                      help='increase output verbosity (use up to 3 times)')
    argp.add_argument('-t', '--timeout', default=30,
                      help='abort execution after TIMEOUT seconds')
    return argp.parse_args()


@nagiosplugin.guarded
def main():
    args = parse_args()
    check = nagiosplugin.Check(
        PureFBalert(args.endpoint, args.apitoken),
        nagiosplugin.ScalarContext(
            'critical', args.warning_crit, args.critical_crit,
            fmt_metric='{value} critical messages'),
        nagiosplugin.ScalarContext(
            'warning', args.warning_warn, args.critical_warn,
            fmt_metric='{value} warning messages'),
        nagiosplugin.ScalarContext(
            'info', args.warning_info, args.critical_info,
            fmt_metric='{value} info messages'))
    check.main(args.verbose, args.timeout)

if __name__ == '__main__':
    main()
