# octodns-custom-providers

Custom [OctoDNS](https://github.com/octodns/octodns) Providers/Sources I wrote for myself

## octodns-custom-providers.provider.zonefile.ZoneFileProvider

OctoDNS only provides a ZoneFile source. This Provider can create a BIND compatible ZoneFile.
It can NOT be used as a source. Use the builtin OctoDNS ZoneFile source instead.

Example

```
providers:
  zonefile:
    class: octodns-custom-providers.provider.zonefile.ZoneFileProvider
    directory: zonefiles
```

## octodns-custom-providers.source.phpipam.PhpipamSource

This source allows to use [PHPipam](https://github.com/phpipam/phpipam) as a source for IP address mappings.

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

