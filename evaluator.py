import os
import time
import socket
import urllib
import requests
from threading import Thread
from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP
from scapy.config import conf

import actions
from layers.packet import Packet

socket.setdefaulttimeout(1)

class Evaluator:
    def __init__(self, logger, test_request):
        self.test_request = test_request
        self.logger = logger
        self.logger.info("Evaluator test request: %s", test_request)
        self.packet_handler = PacketHandler(logger)

    def __enter__(self):
        self.packet_handler.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.packet_handler.shutdown()

    def evaluate(self, population):
        for ind in population:
            self.packet_handler.strategy = ind
            self.logger.info("Evaluating %s...", str(ind))
            try:
                fitness = 0
                res = requests.get(self.test_request, timeout=3)
                self.logger.info("    Response code: %d", res.status_code)
                if res.status_code == 200:
                    fitness += 100
            except requests.exceptions.ConnectTimeout:
                self.logger.info("    Timeout")
                fitness -= 100
            except (requests.exceptions.ConnectionError, ConnectionResetError):
                self.logger.info("    Connection RST")
                fitness -= 90
            except urllib.error.URLError as exc:
                self.logger.info(exc)
                fitness -= 101
            except (requests.exceptions.Timeout, requests.exceptions.HTTPError) as exc:
                self.logger.info("    Failed: %s", exc)
                fitness -= 120
            except Exception as e:
                self.logger.info("    Request failed: %s", str(e))
                fitness -= 100
            finally:
                ind.fitness = fitness * 4

        return population

    def canary_phase(self, canary):
        assert 0, "Not implemented"

class PacketHandler(Thread):
    QUEUE_NUM = 200

    def __init__(self, logger):
        super().__init__()
        self.logger = logger
        self.strategy = actions.strategy.Strategy([], [])
        self.stop = False
        self.nfqueue = NetfilterQueue()
        self.nfqueue.bind(200, self.handle_packet)
        self.socket = conf.L3socket(iface=actions.utils.get_interface())
        self.nfqueue_socket = socket.fromfd(
                self.nfqueue.get_fd(),
                socket.AF_UNIX,
                socket.SOCK_STREAM)

    def start(self):
        os.system(f"iptables -A OUTPUT -p tcp -j NFQUEUE --queue-num {self.QUEUE_NUM}")
        super().start()

    def shutdown(self):
        self.stop = True
        self.join()
        self.nfqueue.unbind()
        self.nfqueue_socket.close()
        self.socket.close()
        os.system("iptables -D OUTPUT 1")
        self.logger.info("Packet handler stopped")

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
