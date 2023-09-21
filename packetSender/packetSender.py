from scapy.arch.windows import get_windows_if_list
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, fragment
from typing import List
import configparser
import logging
import time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


config = configparser.ConfigParser()


class PacketSender():
    protocol: str
    src: str
    iface: str
    payload = str
    packetCount: int
    packet: UDP
    frags: List[str]
    patternData = {
        "protocol": ['UDP', 'TCP'],
        "payload": [b'\x00' * 1472, b'\xff' * 1472]
    }

    def __init__(self) -> None:
        self.readConfig()

    def readConfig(self) -> None:
        config.read('config.ini')
        defaultConfig = config['default']

        self.src = defaultConfig['source']
        self.dest = defaultConfig['destination']
        self.iface = defaultConfig['iface']
        # self.payload = defaultConfig['payload']
        # self.protocol = defaultConfig['protocol']
        # self.packetCount = int(defaultConfig['packetCount'])

        print("Src: ", self.src, "\nDest: ",
              self.dest, "\nInterface:", self.iface)

    # def definePacket(self, protocol, payload):
    #     self.packet = IP(dst = "192.168.8.1", proto=17)/UDP()/payload
    #     # NDD : define packet based on passed parameters
    #     # if protocol == 'UDP':
    #     #     ip_layer = IP(dst=self.dest, proto=17)
    #     #     udp_layer = UDP()
    #     #     self.packet = ip_layer/udp_layer/payload
    #     # elif protocol == 'TCP':
    #     #     self.packet = IP(dst=self.dest, proto=6)/TCP()/payload
    #     # else:
    #     #     raise ValueError("Invalid protocol. Supported protocols are 'UDP' and 'TCP'.")

    def sendPackets(self):
        # NDD : send packets for specific duration and log it properly as well

        # packet = self.definePacket()
        # send(self.packet, count = self.packetCount, verbose = False, iface = self.iface)
        self.payload = b'U' * 1472
        self.packet = IP(dst=self.dest, proto=17)/UDP()/self.payload
        self.frags = fragment(self.packet)

        print("Packet", self.packet)
        print("Fragment", self.frags)

        send(self.packet, count=5, verbose=False, iface=self.iface)

    # def simulatePatterns(self):
    #     # for payload in self.patternData['payload']:
    #     #     for protocol in self.patternData['protocol']:
    #     #         self.definePacket(protocol, payload)
    #     #         self.sendPackets()
    #     #         print(self.packet)
    #     payload = b'U' * 1472
    #     self.definePacket('UDP', payload)
    #     self.sendPackets()


# print(packetCount)
if __name__ == "__main__":
    sender = PacketSender()
    sender.sendPackets()
    # sender.simulatePatterns()
    # print()
