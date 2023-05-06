# vim: set fileencoding=utf-8 :
import re
import netaddr
import pysnmp as pp
from subprocess import Popen, PIPE
from pysnmp import hlapi


# Convert timeticks to datetime
# -----------------------------
# timeticks / 100 = seconds
# timeticks / 6000 = minutes
# timeticks / 360000 = hours
# timeticks / 8640000 = days
#
# SNMP ERROR INFO
# ---------------
# Yields:
#     errorIndication (str) – True value indicates SNMP engine error.
#     errorStatus (str) – True value indicates SNMP PDU error.
#     errorIndex (int) – Non-zero value refers to varBinds[errorIndex-1]
#     varBinds (tuple) – A sequence of ObjectType class instances representing MIB variables returned in SNMP response.
#
# Raises:
#     PySnmpError – Or its derivative indicating that an error occurred while performing SNMP operation.
#
# Ref :
#     http://snmplabs.com/pysnmp/docs/hlapi/asyncore/sync/manager/cmdgen/getcmd.html
#
# To Do:
#     Need to handle more ObjectType of ASN1
#
# Note:
#     Only support for snmp v1 and v2c
#     Support both python2 and python3

def decode_pyobject(value):
    """Convert ASN1 ObjectType to python object and human readable form
    """

    if isinstance(value, hlapi.TimeTicks):
        datetime_str = "{days} days, {hours}:{minutes}:{seconds}"
        days, m = divmod(int(value), 8640000)
        hours, m = divmod(m, 360000)
        minutes, m = divmod(m, 6000)
        seconds, m = divmod(m, 100)

        return datetime_str.format(
            days=days,
            hours=hours,
            minutes=minutes if len(str(minutes)) is 2 else "0%s" % minutes,
            seconds=seconds if len(str(seconds)) is 2 else "0%s" % seconds
        )

    elif isinstance(value, hlapi.Integer32) or isinstance(value, hlapi.Gauge32):
        return int(value)

    elif isinstance(value, hlapi.IpAddress):
        return value.prettyPrint()

    elif isinstance(value, hlapi.OctetString):
        return value.prettyPrint()

    return str(value)


# Custom Exceptions Classes
class UnsuppportedOid(Exception):
    pass


class PySnmpError(Exception):
    pass


class DEVICE():

    def __init__(self, ipaddress, community, version=1, timeout=3, retries=1):

        self.__engine = hlapi.SnmpEngine()
        self.__community_data = None
        self.__community = community
        self.__version = version
        self.__set_community_data()
        self.__ipaddress = ipaddress
        self.__context_data = hlapi.ContextData()
        self.__timeout = timeout
        self.__retries = retries
        self.__uptime = 0
        self.__sysinfo = None
        self.__hostname = None
        self.__mac = None

    def isalive(self, pingcount=1, interval=1):
        status = False
        process = Popen(['ping', '-c', str(pingcount), '-i', str(interval),
                         self.get_ipaddress()], stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        if stdout.find(b"100% packet loss") == -1:
            status = True

        return status

    def __set_community_data(self):

        if self.__version == 1:
            index = 0
        elif self.__version == 2:
            index = 1
        else:
            raise ValueError('Invalid snmp\'s version number')

        self.__community_data = hlapi.CommunityData(
            self.__community, mpModel=index)

    def set_timeout(self, timeout=3):

        self.__timeout = timeout

    def set_retries(self, retries=1):

        self.__retries = retries

    def set_community(self, community):

        self.__community = community
        self.__set_community_data()

    def set_version(self, version):

        self.__version = version
        self.__set_community_data()

    def get_timeout(self):

        return self.__timeout

    def get_retries(self):

        return self.__retries

    def get_ipaddress(self):

        return self.__ipaddress

    def get_version(self):

        return self.__version

    def get_community(self):

        return self.__community

    def snmpget_uptime(self, force=False):

        oid = '.1.3.6.1.2.1.1.3.0'
        error = None

        if (not self.__uptime) or force:
            error, data = self.snmpget(oid)
            if not error:
                self.__uptime = data[0][1]

        return error, self.__uptime

    def snmpget_sysinfo(self, force=False):

        oid = '.1.3.6.1.2.1.1.1.0'
        error = None

        if (not self.__sysinfo) or force:
            error, data = self.snmpget(oid)
            if not error:
                self.__sysinfo = data[0][1]

        return error, self.__sysinfo

    def snmpget_hostname(self, force=False):

        oid = '.1.3.6.1.2.1.1.5.0'
        error = None

        if (not self.__hostname) or force:
            error, data = self.snmpget(oid)
            if not error:
                self.__hostname = data[0][1]

        return error, self.__hostname

    def snmpget_mac(self, force=False):

        oid = '.1.3.6.1.2.1.2.2.1.6.2'
        error = None

        if (not self.__mac) or force:
            error, data = self.snmpget(oid)
            if not error:
                tmp = data[0][1][2:]
                self.__mac = str(netaddr.EUI(tmp))

        return error, self.__mac

    def load_basicinfo(self, force=False, check_ping=True):

        if check_ping:
            if not self.isalive():
                return None

        self.snmpget_hostname(force)
        self.snmpget_mac(force)
        self.snmpget_sysinfo(force)
        self.snmpget_uptime(force)

        return 'loaded'

    def _oid_object(self, oid):

        return [hlapi.ObjectType(hlapi.ObjectIdentity(each)) for each in oid]

    def snmpget(self, *oid):
        error = None
        results = list()
        oidobj = self._oid_object(oid)

        try:

            errorIndication, errorStatus, errorIndex, varBinds = next(
                hlapi.getCmd(self.__engine,
                             self.__community_data,
                             hlapi.UdpTransportTarget(
                                 (self.__ipaddress, 161),
                                 timeout=self.__timeout,
                                 retries=self.__retries
                             ),
                             self.__context_data,
                             *oidobj
                             )
            )

            if errorIndication:
                """ Wrong community string or unreachable ip address
                """
                # raise TimeoutError(errorIndication)
                msg = str(errorIndication)
                error = TimeoutError(msg)

            elif errorStatus:
                """ unsupported oid 
                """
                # raise ValueError('%s at %s' % (errorStatus.prettyPrint(),
                #                     errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
                msg = errorStatus.prettyPrint()
                error = UnsuppportedOid(msg)

            else:

                for varBind in varBinds:
                    results.append([str(varBind[0].getOid()),
                                    decode_pyobject(varBind[1])])

        except pp.error.PySnmpError as e:
            msg = str(e)
            error = PySnmpError(msg)

        return error, results

    def snmpwalk(self, oid):

        if re.findall(r'\.[0]$', oid):
            error, results = self.snmpget(oid)
            return error, results

        error = None
        results = list()
        g = hlapi.nextCmd(self.__engine,
                          self.__community_data,
                          hlapi.UdpTransportTarget(
                              (self.__ipaddress, 161),
                              timeout=self.__timeout,
                              retries=self.__retries
                          ),
                          self.__context_data,
                          hlapi.ObjectType(hlapi.ObjectIdentity(oid)),
                          lexicographicMode=False
                          )

        while 1:
            try:
                errorIndication, errorStatus, errorIndex, varBinds = next(g)
                if errorIndication:
                    """ Wrong community string or unreachable ip address
                    """
                    # raise TimeoutError(errorIndication)
                    msg = str(errorIndication)
                    error = TimeoutError(msg)

                elif errorStatus:
                    """ unsupported oid 
                    """
                    # raise ValueError('%s at %s' % (errorStatus.prettyPrint(),
                    #                     errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
                    msg = errorStatus.prettyPrint()
                    error = UnsuppportedOid(msg)

                else:

                    for varBind in varBinds:
                        results.append(
                            [str(varBind[0].getOid()), decode_pyobject(varBind[1])])

            except pp.error.PySnmpError as e:
                msg = str(e)
                error = PySnmpError(msg)
            except StopIteration:
                break
        return error, results
