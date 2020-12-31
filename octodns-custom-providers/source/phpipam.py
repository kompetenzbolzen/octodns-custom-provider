import octodns.zone.Zone
import octodns.source.base.BaseSource
import phpipam
import logging

class PhpipamSource(BaseSource):
    SUPPORTS_GEO=False
    SUPPORTS=set(('A', 'AAAA'))

    def __init__(self, id, url, user="", token, appid, section):
        '''
        Arguments
        =========
        id: str
        url: str
        user: str
        token: str
        appid: str
        section: str
            phpipam section id to search for addresses
        '''
        self.log = logging.getLogger('PhpipamSource[{}]'.format(id))
        self.log.debug('__init__: id=%s url=%s appid=%s', id, url, appid)

        super(PhpipamSource).__init__(id)

        self._ipam = PhpipamAPI( url, appid, user, token )

    def populate(self, zone, target=False, lenient=False):
        domain = zone.name

        # Do the *MAGIC* Here
        return False
