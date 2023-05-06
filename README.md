# Python snmp client module. It is only support snmp version (1/2c) and is also compatible with python2/3.

## Requirements
- pysnmp
- netaddr

## Usage example
```python
import simple_snmp
device = simple_snmp.DEVICE(<host>, <community-string>)

err, out = device.snmpget_hostname()
print('Host Name: %s' % out)

err, out = device.snmpget_mac()
print('Mac Address: %s' % out)
``` 
