from octodns.provider.base import BaseProvider

import logging

import dns.zone
import dns.rdataclass
import dns.rdatatype

import os

class RdataParameterException(Exception):
    def __init__(self, msg):
        super().__init__(msg)

def _create_rdata( rdclass, rdtype, data ):
    if isinstance(data,str):
        if rdtype == 16: # TXT-Record
            return dns.rdata.from_text(rdclass, rdtype, '"'+data+'"')
        return dns.rdata.from_text(rdclass, rdtype, data)

    cls = dns.rdata.get_rdata_class(rdclass, rdtype)

    if rdtype == 257: # CAA-Record
        data['tag'] = bytes(data['tag'], 'utf-8')
        data['value'] = bytes(data['value'], 'utf-8')

    if rdtype == 44: # SSHFP-Record
        data['algorithm'] = data.pop('algorithm')
        data['fp_type'] = data.pop('fingerprint_type')
        data['fingerprint'] = bytes.fromhex(data['fingerprint'])

    if rdtype == 52: # TLSA-Record
        data['usage'] = data.pop('certificate_usage')
        data['mtype'] = data.pop('matching_type')
        data['cert'] = bytes.fromhex(data.pop('certificate_association_data'))

    if rdtype == 35: # NAPTR-Record
        data['order'] = data.pop('order')
        data['preference'] = data.pop('preference')
        data['flags'] = data.pop('flags')
        data['regexp'] = data.pop('regexp')
        data['replacement'] = data.pop('replacement')

    for slot in cls.__slots__:
        if not slot in data:
            raise RdataParameterException('{} is missing'.format(slot))

    return cls(rdclass, rdtype, **data)

class ZoneFileProvider(BaseProvider):
    SUPPORTS_MULTIVALUE_PTR = True
    SUPPORTS_GEO = False
    SUPPORTS = set(('A', 'AAAA', 'CAA', 'CNAME', 'MX', 'NAPTR', 'NS', 'PTR',
                    'SPF', 'SRV', 'SSHFP', 'TLSA', 'TXT'))

    '''
    SOA dict
    {
        mname
        rname
        serial
        refresh
        retry
        expire
        ttl
    }
    '''

    def __init__(self, id, directory, soa, soa_ttl=3600, file_extension = '', support_root_ns = True):
        '''
        Arguments
        =========
        id: str
        directory: str
        soa: dict
        extension: str
        '''
        self.log = logging.getLogger('ZoneFileProvider[{}]'.format(id))
        self.log.debug('__init__: directory={}'.format(directory))

        self.directory = directory
        self.file_extension = file_extension
        self.soa = soa
        self.soa_ttl = soa_ttl
        self.support_root_ns = support_root_ns

        # OctoDNS does not recursively check dicts for 'env/' keyword
        # TODO Error handling
        serial = self.soa['serial']
        if type(serial) == str and serial.startswith('env/'):
            self.soa['serial'] = int(os.environ[ serial.split('/',1)[1] ])

        super(ZoneFileProvider, self).__init__(id)

    @property
    def SUPPORTS_ROOT_NS(self):
        return self.support_root_ns

    def populate(self, zone, target=False, lenient=False):
        if target:
            return False

        raise NotImplementedError(
            "ZoneFileProvider only implements the target part." +
            " Use OctoDns' own ZoneFileSource to read from ZoneFiles.")


    def _apply(self, plan):
        '''
        Arguments
        =========
        plan: octodns.provider.plan.Plan
        '''

        zone = dns.zone.Zone(plan.desired.name)

        soaset = dns.rdataset.Rdataset(
            dns.rdataclass.IN, dns.rdatatype.SOA)
        soaset.add(_create_rdata(
            dns.rdataclass.IN,
            dns.rdatatype.SOA,
            self.soa), self.soa_ttl)
        zone.replace_rdataset('@',soaset)

        for record in plan.desired.records:
            data = record.data
            name = record.name

            rdset = dns.rdataset.Rdataset(
                dns.rdataclass.IN, dns.rdatatype.from_text(record._type))

            if 'value' in data:
                rdset.add(
                    _create_rdata(
                        dns.rdataclass.IN,
                        dns.rdatatype.from_text(record._type),
                        data['value']),
                    ttl=int(data['ttl']))
            elif 'values' in data:
                for value in data['values']:
                    rdset.add(
                        _create_rdata(
                            dns.rdataclass.IN,
                            dns.rdatatype.from_text(record._type),
                            value),
                        ttl=int(data['ttl']))
            else:
                self.log.warning(
                    "neither value nor values found in {}".format(name))
                continue

            zone.replace_rdataset(name, rdset)

        zone.to_file(self.directory + '/' + plan.desired.name + self.file_extension)
