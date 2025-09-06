#!.venv/bin/python3

import os
import sys
import time
import socket
import logging
import argparse
from threading import Thread
from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP
from scapy.config import conf

import actions
import actions.strategy
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



if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="Packet Modifier", description="Modifies packets applying specified strategy")
    parser.add_argument("strategy")
    parser.add_argument("--log", default="info", help="log level")
    args = parser.parse_args(sys.argv[1:])

    log_lvls = {"INFO": logging.INFO, "DEBUG": logging.DEBUG, "ERROR": logging.ERROR}
    logging.basicConfig(format="[%(levelname)s] %(message)s", level=log_lvls[args.log.upper()])
    logger = logging.getLogger();

    queue_num = 200
    rule = IptablesRule(f"iptables -t mangle -I POSTROUTING 1 -o enp3s0 -p tcp -m multiport --dports 80,443 -m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:6 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num {queue_num} --queue-bypass", "iptables -t mangle -D POSTROUTING 1")
    pm = PacketModifier(logger, rule, queue_num)

    strategy = actions.utils.parse(args.strategy, logger)
    pm.strategy = strategy

    try:
        pm.start()
        while True:
            pass
    except Exception as e:
        logger.error("Packet modifier: %s", e)
    except KeyboardInterrupt:
        print()
    finally:
        pm.shutdown()
