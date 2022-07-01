from scapy.all import *

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, Raw
from scapy.layers.inet import _IPOption_HDR

TYPE_IPV4 = 0x800
TYPE_BP = 0x9999
TYPE_FD = 0x9998

class IPv4Data(Packet):
   name = 'IPv4Data'
   fields_desc = [ BitField("version", 0, 4),
                   BitField("ihl", 0, 4),
                   BitField("tos", 0, 8),
                   BitField("totalLen", 0, 16),
                   BitField("identification", 0, 16),
                   BitField("flags", 0, 3),
                   BitField("flagOffset", 0, 13),
                   BitField("ttl", 0, 8),
                   BitField("protocol", 0, 8),
                   BitField("hdrChecksum", 0, 16),
                   SourceIPField("srcAddr", 0),
                   SourceIPField("dstAddr", 0),
                   BitField("options", 0, 32)]

class Detect(Packet):
   name = "DetectData"
   fields_desc = [BitField("in_time", 0, 32),
                  BitField("type", 0, 6),
                  BitField("port", 0, 8),
                  BitField("flg", 0, 1),
                  BitField("recirculate_flg", 0, 1)]
   
class BackupPath(Packet):
   name = "BackUpPath"
   fields_desc = [BitField("config", 1, 8),
                  XShortField("type", TYPE_IPV4)]
   def mysummary(self):
      return self.sprintf("config=%config%, type=%type%")
   
class UdpData(Packet):
   name = "UdpData"
   fields_desc = [BitField("sport", 0, 16),
                  BitField("dport", 0, 16),
                  BitField("len", 0, 16),
                  BitField("chksum", 0, 16)]

bind_layers(Ether, IP, type=TYPE_IPV4)
bind_layers(Ether, Detect, type=TYPE_BP)
bind_layers(Ether, BackupPath, type=TYPE_FD)
bind_layers(BackupPath, IP, type=TYPE_IPV4)
