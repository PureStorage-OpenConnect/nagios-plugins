#!/usr/bin/env python
# Copyright (c) 2018, 2019, 2020, 2022 Pure Storage, Inc.
#
# * Overview
#
# This simple Nagios/Icinga plugin code shows can be used to monitor Pure Storage FlashBlade systems.
# The Pure Storage Python REST Client is used to query the FlashBlade hardware compoment status.
# Plugin leverages the remarkably helpful nagiosplugin library by Christian Kauhaus.
#
# * Installation
#
# The script should be copied to the Nagios plugins directory on the machine hosting the Nagios server or the NRPE
# for example the /usr/lib/nagios/plugins folder.
# Change the execution rights of the program to allow the execution to 'all' (usually chmod 0755).
#

"""Pure Storage FlashBlade hardware components status

   Nagios plugin to retrieve the current status of hardware components from a Pure Storage FlashBlade.
   Hardware status indicators are collected from the target FA using the REST call.
   The plugin has three mandatory arguments:  'endpoint', which specifies the target FB, 'apitoken', which
   specifies the autentication token for the REST call session and 'component', that is the name of the
   hardware component to be monitored. The component must be specified using the internal naming schema of
   the Pure FlashBlade: i.e CH1 for the main chassis, CH1.FM1 for the primary flash module, CH1.FM2 for the secondary,
   CH1.FB1 for the first blade of first chassis, CH1.FB2 for the secondary blade, CH2 for the second chained FlashBlade
   and so on.
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


class PureFBhw(nagiosplugin.Resource):
    """Pure Storage FlashBlade hardware component status

    Retrieve FB hardware components status

    """

    def __init__(self, endpoint, apitoken, component):
        self.endpoint = endpoint
        self.apitoken = apitoken
        self.component = component
        self.logger = logging.getLogger(self.name)
        handler = logging.handlers.SysLogHandler(address = '/dev/log')
        handler.setLevel(logging.ERROR)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    @property
    def name(self):
        return 'PURE_FB_' + str(self.component)

    def get_status(self):
        """Get hardware component status from FlashBlade."""
        fbinfo = []
        try:
            client = flashblade.Client(target=self.endpoint,
                                       api_token=self.apitoken,
                                       user_agent='Pure_Nagios_plugin/0.2')
            if self.component is None:
                res = client.get_hardware()
            else:
                res = client.get_hardware(names=[self.component])
            if isinstance(res, flashblade.ValidResponse):
                fbinfo = list(res.items)
        except Exception as e:
            raise nagiosplugin.CheckError('FB REST call returned "{}"'.format(e))
        return(fbinfo)

    def probe(self):
        fbinfo = self.get_status()
        failedcomponents = [component for component in fbinfo if component.status not  in ['healthy', 'unused', 'not_installed']]

        if failedcomponents:
            metrics = ", ".join([component.name + ': ' + component.status for component in failedcomponents])
            metric = nagiosplugin.Metric(metrics + '. Status', 1, context='default')
        else:
            if self.component is None:
                metric = nagiosplugin.Metric('All hardware components are OK. Status', 0, context='default' )
            else:
                metric = nagiosplugin.Metric('{} hardware is OK. Status'.format(self.component), 0, context='default' )
        return metric


def parse_args():
    argp = argparse.ArgumentParser()
    argp.add_argument('endpoint', help="FB hostname or ip address")
    argp.add_argument('apitoken', help="FB api_token")
    argp.add_argument('--component', help="FB hardware component")
    argp.add_argument('-v', '--verbose', action='count', default=0,
                      help='increase output verbosity (use up to 3 times)')
    argp.add_argument('-t', '--timeout', default=30,
                      help='abort execution after TIMEOUT seconds')
    return argp.parse_args()


@nagiosplugin.guarded
def main():
    args = parse_args()
    check = nagiosplugin.Check( PureFBhw(args.endpoint, args.apitoken, args.component) )
    check.add(nagiosplugin.ScalarContext('default', '', '@1:1'))
    check.main(args.verbose, args.timeout)

if __name__ == '__main__':
    main()
