import urllib
import requests

import pkt_modifier

class Evaluator:
    QUEUE_NUM = 200

    def __init__(self, logger, test_requests):
        self.test_requests = test_requests
        self.logger = logger
        rule = pkt_modifier.IptablesRule(f"iptables -A OUTPUT -p tcp -j NFQUEUE --queue-num {self.QUEUE_NUM}", "iptables -D OUTPUT 1")
        self.packet_modifier = pkt_modifier.PacketModifier(logger, rule, self.QUEUE_NUM)

    def __enter__(self):
        self.packet_modifier.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.packet_modifier.shutdown()

    def evaluate(self, population):
        for ind in population:
            self.packet_modifier.strategy = ind
            self.logger.info("Evaluating %s...", str(ind))

            fitness = 0
            for req in self.test_requests:
                try:
                    self.logger.info("    %s", req)
                    res = requests.get(req, timeout=3)
                    self.logger.info("        Response code: %d", res.status_code)
                    if res.status_code == 200:
                        fitness += 100
                except requests.exceptions.ConnectTimeout:
                    self.logger.info("        Timeout")
                    fitness -= 100
                except (requests.exceptions.ConnectionError, ConnectionResetError):
                    self.logger.info("        Connection RST")
                    fitness -= 90
                except urllib.error.URLError as exc:
                    self.logger.info(exc)
                    fitness -= 101
                except (requests.exceptions.Timeout, requests.exceptions.HTTPError) as exc:
                    self.logger.info("        Failed: %s", exc)
                    fitness -= 120
                except Exception as e:
                    self.logger.info("        Request failed: %s", str(e))
                    fitness -= 100
            ind.fitness = fitness * 4

        return population

    def canary_phase(self, canary):
        assert 0, "Not implemented"
