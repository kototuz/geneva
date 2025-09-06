import os
import time
import socket
from threading import Thread
from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP
from scapy.config import conf

import actions
from layers.packet import Packet

socket.setdefaulttimeout(1)

class PacketModifier(Thread):
    def __init__(self, logger, iptables_rule, queue_num):
        super().__init__()
        self.iptables_rule = iptables_rule
        self.logger = logger
        self.strategy = actions.strategy.Strategy([], [])
        self.stop = False
        self.nfqueue = NetfilterQueue()
        self.nfqueue.bind(queue_num, self.handle_packet)
        self.socket = conf.L3socket(iface=actions.utils.get_interface())
        self.nfqueue_socket = socket.fromfd(
                self.nfqueue.get_fd(),
                socket.AF_UNIX,
                socket.SOCK_STREAM)

    def start(self):
        os.system(self.iptables_rule.create_cmd)
        super().start()

    def shutdown(self):
        self.stop = True
        self.join()
        self.nfqueue.unbind()
        self.nfqueue_socket.close()
        self.socket.close()
        os.system(self.iptables_rule.delete_cmd)
        self.logger.info("Packet modifier stopped")

    def handle_packet(self, nfpacket):
        packet = Packet(IP(nfpacket.get_payload()))
        self.logger.debug("Outbound packet %s", str(packet))
        nfpacket.drop()

        try:
            new_packets = self.strategy.act_on_packet(packet, self.logger, direction="out")
            for p in new_packets:
                if p.sleep:
                    Thread(target=self.delayed_send, args=(p.packet, p.sleep)).start()
                else:
                    self.socket.send(p.packet)
        except Exception as e:
            self.logger.error("Applying strategy failed: %s", str(e))

    def delayed_send(self, packet, delay):
        self.logger.info("Sleeping for %fs", delay)
        time.sleep(delay)
        self.socket.send(packet)

    def run(self):
        try:
            while not self.stop:
                try:
                    self.nfqueue.run_socket(self.nfqueue_socket)
                # run_socket can raise an OSError on shutdown for some builds of netfilterqueue
                except (socket.timeout, OSError):
                    pass
        except Exception as e:
            raise e

class IptablesRule:
    def __init__(self, create_cmd, delete_cmd):
        self.create_cmd = create_cmd
        self.delete_cmd = delete_cmd
