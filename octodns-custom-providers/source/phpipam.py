#import octodns.zone.Zone
import octodns.record
import octodns.source.base
import phpipam_api
import logging
import re

class PhpipamSource(octodns.source.base.BaseSource):
    SUPPORTS_GEO=False
    SUPPORTS=set(('A', 'AAAA'))

    def __init__(self, id, url, user, token, appid, cidrs, tag = 'Used', default_ttl='3600', reverse = False):
        '''
        Arguments
        =========
        id: str
        url: str
        user: str
        token: str
        appid: str
        cidrs: str[]
            list of cidrs to search
        tag: str
            Address tag name
        '''
        self.log = logging.getLogger('PhpipamSource[{}]'.format(id))
        self.log.debug('__init__: id=%s url=%s appid=%s', id, url, appid)

        super(PhpipamSource, self).__init__(id)

        self._default_ttl = default_ttl
        self._tag = tag
        self._cidrs = cidrs
        self._ipam = phpipam_api.PhpipamAPI( url, appid, user, token )
        self._reverse = reverse

    @staticmethod
    def _ip_in_arpa_zone(zone_name, reverse_parts):
        zone_parts = zone_name.strip('.').split('.')[0:-2][::-1]
        for i in range(len(zone_parts)):
            if not zone_parts[i] == reverse_parts[3-i]:
                return []

        return reverse_parts[0:4-len(zone_parts)]

    def _populate_reverse(self, zone, selected_addresses):
        for hostname in selected_addresses:
            if type(hostname) is not str:
                # If an IP has no hostname set
                continue

            data={
                'type':'PTR',
                'ttl':self._default_ttl,
                'value':f'{hostname.strip(".")}.'
            }

            ips=[]
            if type(selected_addresses[hostname]) == list:
                ips = selected_addresses[hostname]
            else:
                ips.append(selected_addresses[hostname])

            for ip in ips:
                # TODO de-uglify
                parts = ip.split('.')[::-1]
                relative_parts = PhpipamSource._ip_in_arpa_zone(zone.name, parts)
                if len(relative_parts) == 0:
                    continue

                arpa_name = '.'.join(relative_parts).strip('.')

                new_record = octodns.record.Record.new( zone, arpa_name, data)
                zone.add_record( new_record )

    def _populate_forward(self, zone, selected_addresses):
        print(selected_addresses)
        for _selected_address in selected_addresses:
            if type(_selected_address) is not str:
                # If an IP has no hostname set
                continue

            if not _selected_address.endswith(zone.name.strip('.')):
                continue

            hostname = re.sub( '\.' + zone.name.strip('.').replace('.', '\.') + '$', '', _selected_address)

            data={
                'type':'A',
                'ttl':self._default_ttl,
                'values':selected_addresses[_selected_address]
            }

            new_record = octodns.record.Record.new( zone, hostname, data)
            zone.add_record( new_record )


    def populate(self, zone, target=False, lenient=False):
        ipam = self._ipam
        tag = self._tag
        cidrs = self._cidrs
        domain = zone.name
        reverse = self._reverse

        if domain.endswith('in-addr.arpa.'):
            reverse = True

        tags = ipam.addresses.getTags()
        tag_id = ''
        for _tag in tags:
            if _tag['type'] == tag:
                tag_id=_tag['id']
        if len(tag_id) == 0:
            self.log.error(f'populate(): tag {tag} was not found.')
            return False

        self.log.debug(f'populate(): tag {tag} has id {tag_id}')

        selected_addresses = {}

        for _cidr in cidrs:
            subnets = ipam.subnets.search(search=_cidr)

            if not len(subnets) == 1:
                self.log.warning(f'populate(): CIDR {_cidr} has no or no exact match. Ignoring.')
                continue
            subnet = subnets[0]

            addresses = ipam.subnets.getAddresses(subnet_id=subnet['id'])
            for _address in addresses:
                hostname = _address['hostname']
                ip = _address['ip']

                if not _address['tag'] == tag_id:
                    continue

                if hostname in selected_addresses:
                    selected_addresses[hostname].append(ip)
                else:
                    selected_addresses[hostname]=[ip]

        if reverse:
            self._populate_reverse(zone, selected_addresses)
        else:
            self._populate_forward(zone, selected_addresses)

        return True
