snmp client module for python

requirements:
- pysnmp
- netaddr

support on python 2/3

Example:

    import simple_snmp
    device = simple_snmp.DEVICE(<host>, <community-string>)
    
    err, out = device.snmpget_hostname()
    print('Host Name: %s' % out)
    
    err, out = device.snmpget_mac()
    print('Mac Address: %s' % out)
    
    