# octodns-custom-providers

Custom [OctoDNS](https://github.com/octodns/octodns) Providers/Sources I wrote for myself

## octodns-custom-providers.provider.zonefile.ZoneFileProvider

OctoDNS only provides a ZoneFile source. This Provider can create a BIND compatible ZoneFile.
It can NOT be used as a source. Use the builtin OctoDNS ZoneFile source instead.

soa.serial can be used with `env/` keyword to use environment variable as Serialnumber

Example

```
providers:
  zonefile:
    class: octodns-custom-providers.provider.zonefile.ZoneFileProvider
    directory: zonefiles
    soa:
      mname: ns.example.com
      rname: dns.example.com
      serial: 123456
      refresh: 7200
      retry: 3600
      expire: 1209600
      minimum: 3600
```

## octodns-custom-providers.source.phpipam.PhpipamSource

This source allows to use [PHPipam](https://github.com/phpipam/phpipam) as a source for IP address mappings.
Reverse-Mappings are created, when used to create a `in-addr.arpa` zone or forced with `reverse: True`

Requires: [python-phpipam](https://github.com/kompetenzbolzen/python-phpipam)

```
roviders:
  phpipam:
    class: octodns-custom-providers.source.phpipam.PhpipamSource
    url: 'https://phpipam.example.com/'
    user: env/PHPIPAM_USER
    token: env/PHPIPAM_TOKEN
    appid: 'myapp'
    cidrs:
      - 10.1.0.0/16
```

