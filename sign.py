import decimal
import logging

from io import BytesIO
from binascii import unhexlify

from ecc import PrivateKey
from script import Script, p2sh_script, p2wpkh_script
from helper import hash160, SIGHASH_ALL
from tx import Tx, TxIn, TxOut
from rpc import testnet, mainnet


logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)


key = PrivateKey(58800187338825965989061197411175755305019286370732616970021105328088303800804)

def spend_p2sh():
    # FIXME: this should become a test but it's so damn ugly!
    prev = Tx.parse(BytesIO(bytes.fromhex('0100000001830208d3882c8a3a3fbcb504dc2cb3da131668c0dc36aa08d946965424a6e5c6000000006d4830450221008419726010715866b6a8da03308f1b91f5d322b3db58c0f5d0f2ceff3816cd5d02200122c799ac58a603556c7af02232521889241cc68e667bcbaca1a7b281b2920001232103a219347581e196b7e48bd19e6b4d616afa3f4111ea1f31213e9722693033ff52acffffffff01a47e1e000000000017a914dc4eb0dda425606a7a0dd0f8ae1bfb08fca2f0658700000000')))
    # inputs
    tx_in = TxIn(
        prev.hash(),
        0,
    )
    # ouputs
    unspent_amount = prev.tx_outs[0].amount
    fees = 500
    sec = key.point.sec(compressed=True)
    redeem_script  = Script(cmds=[sec, 172])
    raw_redeem = redeem_script.raw_serialize()
    h160 = hash160(raw_redeem)
    locking_script = p2sh_script(h160)
    tx_out = TxOut(
        int(unspent_amount - fees),
        locking_script,
    )
    # construct transaction
    tx = Tx(1, [tx_in], [tx_out], 0, testnet=True)
    print(tx)
    # sign transaction
    verifies = tx.sign_input(0, key, redeem_script=redeem_script)
    print("verifies?", verifies)
    # broadcast 
    print(testnet.sendrawtransaction(tx.serialize().hex()))


def p2sh_to_p2wpkh():
    # FIXME: this should become a test but it's so damn ugly!
    raw = testnet.getrawtransaction('9cc0af2298a312e641963ae60407bac000bd6c05cb402809f6b8dd786996333c', 0)
    prev = Tx.parse(BytesIO(bytes.fromhex(raw)))
    # inputs
    tx_in = TxIn(
        prev.hash(),
        0,
    )
    # ouputs
    unspent_amount = prev.tx_outs[0].amount
    fees = 500
    sec = key.point.sec(compressed=True)
    redeem_script  = Script(cmds=[sec, 172])
    raw_redeem = redeem_script.raw_serialize()
    h160 = hash160(sec)
    locking_script = p2wpkh_script(h160)
    tx_out = TxOut(
        int(unspent_amount - fees),
        locking_script,
    )
    # construct transaction
    tx = Tx(1, [tx_in], [tx_out], 0, testnet=True)
    print(tx)
    # sign transaction
    verifies = tx.sign_input(0, key, redeem_script=redeem_script)
    print("verifies?", verifies)
    # broadcast 
    print(testnet.sendrawtransaction(tx.serialize().hex()))


def p2wpkh_to_p2wpkh():
    raw = testnet.getrawtransaction('0585ca62c2b0c95993a52913c2ea2407f0ae6cb46260ef20a6189b8fd3759b04', 0)
    prev = Tx.parse(BytesIO(bytes.fromhex(raw)))
    # inputs
    tx_in = TxIn(
        prev.hash(),
        0,
    )
    # ouputs
    unspent_amount = prev.tx_outs[0].amount
    fees = 500
    sec = key.point.sec(compressed=True)
    h160 = hash160(sec)
    locking_script = p2wpkh_script(h160)
    tx_out = TxOut(
        int(unspent_amount - fees),
        locking_script,
    )
    # construct transaction
    tx = Tx(1, [tx_in], [tx_out], 0, testnet=True, segwit=True)
    print(tx)
    # sign transaction
    verifies = tx.sign_input(0, key)
    print("verifies?", verifies)
    # broadcast 
    print(testnet.sendrawtransaction(tx.serialize().hex()))

p2wpkh_to_p2wpkh()
