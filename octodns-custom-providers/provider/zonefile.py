#from octodns.zone import Zone
from octodns.provider.base import BaseProvider
from octodns.provider.plan import Plan
#from octodns.source.axfr import ZoneFileSource

import logging

import dns.zone
import dns.rdataclass
import dns.rdatatype

class ZoneFileProvider(BaseProvider):
    SUPPORTS_GEO=False
    SUPPORTS = set(('A', 'AAAA', 'CAA', 'CNAME', 'MX', 'NS', 'PTR', 'SPF',
        'SRV', 'TXT'))


    def __init__(self, id, directory, check_origin=True):
        '''
        Arguments
        =========
        id: str
        directory: str
        check_origin: bool
        '''
        self.log = logging.getLogger('ZoneFileProvider[{}]'.format(id))
        self.log.debug('__init__: directory={}'.format(directory))

        self.directory = directory

        super(ZoneFileProvider, self).__init__(id)

    def populate(self, zone, target=False, lenient=False):
        self.log.warn("ZoneFileProvider only implements target, for source octodns.source.axfr.ZoneFileSource should be used.")

    def _apply(self,plan):
        '''
        Arguments
        =========
        plan: octodns.provider.plan.Plan
        '''
        # self.desired to dns.zone -> to file
        records = plan.desired.records
        zone = dns.zone.Zone(plan.desired.name)

        for record in plan.desired.records:
            data = record.data
            name = record.name

            rdset = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.from_text(record._type))

            if 'value' in data:
                rdset.add(dns.rdata.from_text(dns.rdataclass.IN,
                    dns.rdatatype.from_text(record._type), data['value']), ttl=int(data['ttl'] ))
            elif 'values' in data:
                for value in data['values']:
                    rdset.add(dns.rdata.from_text(dns.rdataclass.IN,
                        dns.rdatatype.from_text(record._type), value), ttl=int(data['ttl'] ))
            else:
                self.log.warning("neither value nor values found in {}".format(name))
                continue

            zone.replace_rdataset(name, rdset)

        zone.to_file( self.directory + '/' + plan.desired.name)
