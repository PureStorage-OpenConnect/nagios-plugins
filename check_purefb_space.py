#!/usr/bin/env python
# Copyright (c) 2018, 2019, 2020, 2022 Pure Storage, Inc.
#
# * Overview
#
# This simple Nagios/Icinga plugin code shows can be used to monitor Pure Storage FlashBlade systems.
# The Pure Storage Python REST Client is used to query the FlashBlade space usage indicators.
# Plugin leverages the remarkably helpful nagiosplugin library by Christian Kauhaus.
#
# * Installation
#
# The script should be copied to the Nagios plugins directory on the machine hosting the Nagios server or the NRPE
# for example the /usr/lib/nagios/plugins folder.
# Change the execution rights of the program to allow the execution to 'all' (usually chmod 0755).
#

"""Pure Storage FlashBlade space used

   Nagios plugin to retrieve the overall used space from a Pure Storage FlashBlade, or from a single volume, or from the object store.
   Storage space indicators are collected from the target FB using the REST call.
   The plugin has two mandatory arguments:  'endpoint', which specifies the target FB and 'apitoken', which specifies the autentication
   token for the REST call session. A third optional selector flag can be used to check the occupancy of the file systems store (--fs) or
   the object store occupancy (--s3). It is also possible to retrieve the occupied space for a specific file system by specifying the 
   file system name as the additional parameter to the --fs selectot.
   The optional values for the warning and critical thresholds have different meausure units: they must be
   expressed as percentages in the case of checkig the whole FlashBlade occupancy, while they must be integer byte units if checking a
   single volume.

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


class PureFBspace(nagiosplugin.Resource):
    """Pure Storage FlashBlade space usage

    Calculate the overall FB used storage or a single volume capacity.

    """

    def __init__(self, endpoint, apitoken, type, volname):
        self.endpoint = endpoint
        self.apitoken = apitoken
        if (type == 'fs'):
            self.type = 'file-system'
            self.volname = volname
        elif (type == 'obj'):
            self.type = 'object-store'
            self.volname = volname
        else:
            self.type = 'array'
            self.volname = ''
        self.logger = logging.getLogger(self.name)
        handler = logging.handlers.SysLogHandler(address = '/dev/log')
        handler.setLevel(logging.ERROR)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    @property
    def name(self):
        if (self.type == 'file-system'):
            return 'PURE_FB_FILE_SYSTEM_SPACE'
        elif (self.type == 'object-store' ):
            return 'PURE_FB_OBJSTORE_SPACE'
        else:
            return 'PURE_FB_SPACE'


    def get_space(self):
        """Get space values from FlashBlade."""
        fbinfo = []
        try:
            client = flashblade.Client(target=self.endpoint,
                                       api_token=self.apitoken,
                                       user_agent='Pure_Nagios_plugin/0.2')
            if self.type == 'file-system' and self.volname:
                res = client.get_file_systems(names=[self.volname])
            elif self.type == 'object-store' and self.volname:
                res = client.get_buckets(names=[self.volname])
            else:
                res = client.get_arrays_space(type=self.type)
            if isinstance(res, flashblade.ValidResponse):
                fbinfo = res.items.next()
      
        except Exception as e:
            raise nagiosplugin.CheckError('FB REST call returned "{}"'.format(e))
        return(fbinfo)


    def probe(self):

        fbinfo = self.get_space()
        if not fbinfo:
            return ''
        self.logger.debug('FA REST call returned "%s" ', fbinfo)
        if (self.volname):
            space = int(fbinfo.space.virtual)
            metric = nagiosplugin.Metric(self.volname + ' space', space, 'B', min=0, context='space')
        else:
            space = int(fbinfo.space.total_physical)
            metric = nagiosplugin.Metric(self.type + ' space', space, 'B', min=0, max=100, context='space')
        return metric


def parse_args():
    argp = argparse.ArgumentParser()
    argp.add_argument('endpoint', help="FB hostname or ip address")
    argp.add_argument('apitoken', help="FB api_token")
    group = argp.add_mutually_exclusive_group()
    group.add_argument('--fs', action='store', nargs='?', const='#FS#', help='specify NFS volume name to check a specific volume')
    group.add_argument('--s3', action='store', nargs='?', const='#BKT#', help='specify bucket name to check a specific bucket')


    argp.add_argument('-w', '--warning', metavar='RANGE', default='',
                      help='return warning if space is outside RANGE. Value has to be expressed in percentage for the FB, while in bytes for the single volume')
    argp.add_argument('-c', '--critical', metavar='RANGE', default='',
                      help='return critical if space is outside RANGE. Value has to be expressed in percentage for the FB, while in bytes for the single volume')
    argp.add_argument('-v', '--verbose', action='count', default=0,
                      help='increase output verbosity (use up to 3 times)')
    argp.add_argument('-t', '--timeout', default=30,
                      help='abort execution after TIMEOUT seconds')
    return argp.parse_args()


@nagiosplugin.guarded
def main():
    args = parse_args()
    vol = ''
    type = ''
    if (args.fs is not None):
        type = 'fs'
        if (args.fs != '#FS#'):
            vol = args.fs
    elif (args.s3 is not None):
        type = 'obj'
        if (args.s3 != '#BKT#'):
            vol = args.s3

    check = nagiosplugin.Check( PureFBspace(args.endpoint, args.apitoken, type, vol) )
    check.add(nagiosplugin.ScalarContext('space', args.warning, args.critical))
    check.main(args.verbose, args.timeout)

if __name__ == '__main__':
    main()
