"""NAPALM HPE Comware Handler."""
# Copyright 2017 Vincent Misson. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

"""
Napalm driver for HPE Comware
"""

import re
import socket
import telnetlib

from netmiko import ConnectHandler, FileTransfer, InLineTransfer
from napalm.base.base import NetworkDriver
from napalm.base.exceptions import ReplaceConfigException, MergeConfigException, \
            ConnectionClosedException, CommandErrorException

from napalm.base.utils import py23_compat

class ComwareDriver(NetworkDriver):
    """NAPALM HPE Comware Handler."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """NAPALM HPE Comware Handler."""
        if optional_args is None:
            optional_args = {}
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        self.transport = optional_args.get('transport', 'ssh')

        # Retrieve file names
        self.candidate_cfg = optional_args.get('candidate_cfg', 'candidate_config.txt')
        self.merge_cfg = optional_args.get('merge_cfg', 'merge_config.txt')
        self.rollback_cfg = optional_args.get('rollback_cfg', 'rollback_config.txt')
        self.inline_transfer = optional_args.get('inline_transfer', False)
        if self.transport == 'telnet':
            # Telnet only supports inline_transfer
            self.inline_transfer = True

        # None will cause autodetection of dest_file_system
        self._dest_file_system = optional_args.get('dest_file_system', None)
        self.auto_rollback_on_error = optional_args.get('auto_rollback_on_error', True)

        # Netmiko possible arguments
        netmiko_argument_map = {
            'port': None,
            'secret': '',
            'verbose': False,
            'keepalive': 30,
            'global_delay_factor': 1,
            'use_keys': False,
            'key_file': None,
            'ssh_strict': False,
            'system_host_keys': False,
            'alt_host_keys': False,
            'alt_key_file': '',
            'ssh_config_file': None,
            'allow_agent': False,
        }

        # Build dict of any optional Netmiko args
        self.netmiko_optional_args = {}
        for k, v in netmiko_argument_map.items():
            try:
                self.netmiko_optional_args[k] = optional_args[k]
            except KeyError:
                pass

        default_port = {
            'ssh': 22,
            'telnet': 23
        }
        self.port = optional_args.get('port', default_port[self.transport])

        self.device = None
        self.config_replace = False
        self.interface_map = {}

        self.profile = ["comware"]

    def open(self):
        """Open a connection to the device."""
        device_type = 'hp_comware'
        if self.transport == 'telnet':
            device_type = 'comware_telnet'
        self.device = ConnectHandler(device_type=device_type,
                                     host=self.hostname,
                                     username=self.username,
                                     password=self.password,
                                     **self.netmiko_optional_args)
        # ensure in enable mode
        self.device.enable()

    def close(self):
        """Close the connection to the device."""
        self.device.disconnect()

    def _send_command(self, command):
        """Wrapper for self.device.send.command().

        If command is a list will iterate through commands until valid command.
        """
        try:
            if isinstance(command, list):
                for cmd in command:
                    output = self.device.send_command(cmd)
                    if "% Invalid" not in output:
                        break
            else:
                output = self.device.send_command(command)
            return output
        except (socket.error, EOFError) as e:
            raise ConnectionClosedException(str(e))

    def is_alive(self):
        """Returns a flag with the state of the connection."""
        null = chr(0)
        if self.device is None:
            return {'is_alive': False}
        if self.transport == 'telnet':
            try:
                # Try sending IAC + NOP (IAC is telnet way of sending command
                # IAC = Interpret as Command (it comes before the NOP)
                self.device.write_channel(telnetlib.IAC + telnetlib.NOP)
                return {'is_alive': True}
            except UnicodeDecodeError:
                # Netmiko logging bug (remove after Netmiko >= 1.4.3)
                return {'is_alive': True}
            except AttributeError:
                return {'is_alive': False}
        else:
            # SSH
            try:
                # Try sending ASCII null byte to maintain the connection alive
                self.device.write_channel(null)
                return {'is_alive': self.device.remote_conn.transport.is_active()}
            except (socket.error, EOFError):
                # If unable to send, we can tell for sure that the connection is unusable
                return {'is_alive': False}
        return {'is_alive': False}

    def get_lldp_neighbors(self):
        lldp = {}
        command = 'display lldp neighbor-information verbose'
        output = self._send_command(command)

        # Check if router supports the command
        if '% Invalid input' in output:
            return {}

        for lldp_interfaces in re.split("\n\n", output):
            local_port = ""
            port = ""
            sysname = ""
            management = ""
            for lldp_entry in lldp_interfaces.splitlines():
                if 'LLDP neighbor-information of port' in lldp_entry:
                    local_port = re.findall(r'([^\[\]]*)', lldp_entry)[2]
                    #lldp_detail = 'display lldp neighbor-information interface ' + local_port + ' verbose'
                    #output_detail = self._send_command(lldp_detail)

                elif 'Port ID             :' in lldp_entry:
                    port = lldp_entry.split(' : ')[1]
                elif 'System name         :' in lldp_entry:
                    sysname = lldp_entry.split(' : ')[1]
                elif 'Management address                : ' in lldp_entry:
                    ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', lldp_entry)
                    if ip != []:
                        management = ip[0]
                    if sysname == "":
                        sysname = management
            port = port.replace('Ten-GigabitEthernet', 'XGE')
            port = port.replace('FortyGigE', 'FGE')
            local_port = local_port.replace('Ten-GigabitEthernet', 'XGE')
            local_port = local_port.replace('FortyGigE', 'FGE')
            entry = {'hostname': sysname, 'port': port}
            lldp.setdefault(local_port, [])
            lldp[local_port].append(entry)

        return lldp

    @staticmethod
    def parse_uptime(uptime_str):
        """
        Extract the uptime string from the given HPE Comware Device.

        Return the uptime in seconds as an integer
        """
        HOUR_SECONDS = 3600
        DAY_SECONDS = 24 * HOUR_SECONDS
        WEEK_SECONDS = 7 * DAY_SECONDS
        YEAR_SECONDS = 365 * DAY_SECONDS
        # Initialize to zero
        (years, weeks, days, hours, minutes) = (0, 0, 0, 0, 0)

        uptime_str = uptime_str.strip()
        time_list = uptime_str.split(',')
        for element in time_list:
            if re.search("year", element):
                years = int(element.split()[0])
            elif re.search("week", element):
                weeks = int(element.split()[0])
            elif re.search("day", element):
                days = int(element.split()[0])
            elif re.search("hour", element):
                hours = int(element.split()[0])
            elif re.search("minute", element):
                minutes = int(element.split()[0])

        uptime_sec = (years * YEAR_SECONDS) + (weeks * WEEK_SECONDS) + (days * DAY_SECONDS) + \
                     (hours * 3600) + (minutes * 60)
        return uptime_sec

    def get_facts(self):
        """Return a set of facts from the devices."""
        # default values.
        vendor = u'Hewlett Packard Enterprise'
        uptime = -1
        serial_number, fqdn, os_version, hostname, domain_name = ('Unknown',) * 5

        # obtain output from device
        show_ver = self._send_command('display version')
        show_dev = self._send_command('display device manuinfo')
        show_current = self._send_command('display cur')
        show_ip_int_br = self._send_command('display ip interface brief')

        # uptime/serial_number/IOS version
        for line in show_ver.splitlines():
            if ' uptime is ' in line:
                model, uptime_str = line.split(' uptime is ')
                uptime = self.parse_uptime(uptime_str)
                model = model.strip()

            if 'Boot image version' in line:
                _, os_version = line.split("Boot image version: ")
                os_version = os_version.strip()

        # Determine domain_name and fqdn
        for line in show_current.splitlines():
            if ' sysname ' in line:
                _, hostname = line.split(" sysname ")
                hostname = hostname.strip()

            if ' domain default enable ' in line:
                _, domain_name = line.split(" domain default enable ")
                domain_name = domain_name.strip()
                break
        if domain_name != 'Unknown' and hostname != 'Unknown':
            fqdn = u'{}.{}'.format(hostname, domain_name)

        for line in show_dev.splitlines():
            if 'DEVICE_SERIAL_NUMBER' in line:
                _, serial = line.split("DEVICE_SERIAL_NUMBER : ")
                if serial_number != 'Unknown':
                    serial_number += " / " + serial.strip()
                else:
                    serial_number = serial.strip()

        # interface_list filter
        interface_list = []
        show_ip_int_br = show_ip_int_br.strip()
        for line in show_ip_int_br.splitlines():
            if 'Interface ' in line:
                continue
            interface = line.split()[0]
            interface_list.append(interface)

        return {
            'uptime': uptime,
            'vendor': vendor,
            'os_version': py23_compat.text_type(os_version),
            'serial_number': py23_compat.text_type(serial_number),
            'model': py23_compat.text_type(model),
            'hostname': py23_compat.text_type(hostname),
            'fqdn': fqdn,
            'interface_list': interface_list
        }

    def get_environment(self):
        """
        Get environment facts.

        power and fan are currently not implemented
        cpu is using 1-minute average
        cpu hard-coded to cpu0 (i.e. only a single CPU)
        """
        environment = {}
        cpu_cmd = 'display cpu-usage'
        mem_cmd = 'display memory'
        temp_cmd = 'display environment'

        output = self._send_command(cpu_cmd)
        environment.setdefault('cpu', {})
        cpu_id = 0
        for line in output.splitlines():
            if 'in last 1 minute' in line:
                # CPU utilization for five seconds: 2%/0%; one minute: 2%; five minutes: 1%
                cpu_regex = r'^.*(\d+)%.*$'
                environment['cpu'][cpu_id] = {}
                environment['cpu'][cpu_id]['%usage'] = 0.0
                match = re.search(cpu_regex, line)
                environment['cpu'][cpu_id]['%usage'] = float(match.group(1))
                cpu_id += 1


        output = self._send_command(mem_cmd)
        proc_used_mem = 0
        proc_free_mem = 0
        for line in output.splitlines():
            if 'Mem' in line:
                proc_used_mem += int(line.split()[2])
                proc_free_mem += int(line.split()[3])
        environment.setdefault('memory', {})
        environment['memory']['used_ram'] = proc_used_mem
        environment['memory']['available_ram'] = proc_free_mem



        environment.setdefault('temperature', {})
        output = self._send_command(temp_cmd)

        for line in output.splitlines():
            if 'hotspot 1' in line:
                system_temp = float(line.split()[3])
                system_temp_alert = float(line.split()[5])
                system_temp_crit = float(line.split()[6])
                env_value = {'is_alert': system_temp >= system_temp_alert,
                             'is_critical': system_temp >= system_temp_crit, 'temperature': system_temp}
                environment['temperature']['system'] = env_value

        # Initialize 'power' and 'fan' to default values (not implemented)
        environment.setdefault('power', {})
        environment['power']['invalid'] = {'status': True, 'output': -1.0, 'capacity': -1.0}
        environment.setdefault('fans', {})
        environment['fans']['invalid'] = {'status': True}

        return environment

    def get_config(self, retrieve='all'):
        """Implementation of get_config for IOS.

        Returns the startup or/and running configuration as dictionary.
        The keys of the dictionary represent the type of configuration
        (startup or running). The candidate is always empty string,
        since IOS does not support candidate configuration.
        """

        configs = {
            'startup': '',
            'running': '',
            'candidate': '',
        }

        if retrieve in ('startup', 'all'):
            command = 'display saved-configuration'
            output = self._send_command(command)
            configs['startup'] = output

        if retrieve in ('running', 'all'):
            command = 'display current-configuration'
            output = self._send_command(command)
            configs['running'] = output

        return configs
