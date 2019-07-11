import decimal
import logging
import argparse

from io import BytesIO
from os.path import isfile
from binascii import unhexlify
from random import randint

from ecc import PrivateKey
from script import Script, p2sh_script, p2wpkh_script, address_to_script_pubkey
from helper import hash160, SIGHASH_ALL
from tx import Tx, TxIn, TxOut
from rpc import testnet, mainnet


logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)


key = PrivateKey(58800187338825965989061197411175755305019286370732616970021105328088303800804)

def spend_p2sh():
    # FIXME: this should become a test but it's so damn ugly!
    prev = Tx.parse(BytesIO(bytes.fromhex('01000000016886a6969d2008a5052723bcf9326075efdb5f3d83b518ed2671b206a4a80e59000000006a4730440220632e2dd5b76f9878691c1787705bd5f0822f9b711b16406e80f7e280451b545902202713e18bb30c4ec65c691fb04e917deb99bee572969687f9e1f201fdff4e11c3012103a219347581e196b7e48bd19e6b4d616afa3f4111ea1f31213e9722693033ff52ffffffff02881300000000000017a914dc4eb0dda425606a7a0dd0f8ae1bfb08fca2f06587c42c0f0000000000160014f32a49dfea14463042f30974e8eeb351a6df006500000000')))
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
    raw = testnet.getrawtransaction('93470e8622d2e1074c6dea2431beb7d9d96d1036a11fe1cb49c842d02748feae', 0)
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
    raw = testnet.getrawtransaction('c375525ec91184887daa8111b66016e2997a84ff810c4f52fbd7856d25335269', 0)
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


class Wallet:
    filename = 'testnet.wallet'

    def __init__(self, secret):
        self.private_key = PrivateKey(secret)

    @classmethod
    def create(cls):
        if isfile(cls.filename):
            raise RuntimeError('file exists: {}'.format(filename))
        secret = randint(0, 2**256)
        wallet = cls(secret)
        wallet.save()
        return wallet

    @classmethod
    def open(cls):
        with open(cls.filename) as f:
            secret = int(f.read())
        return cls(secret)

    def save(self):
        with open(self.filename, 'w') as f:
            f.write(str(self.secret))

    def sign(self):
        pass


def handle_address(args):
    wallet = Wallet.open()
    public_key = wallet.private_key.point
    if args.type == 'p2pkh':
        return public_key.address(compressed=True, testnet=True)
    elif args.type == 'p2sh':
        # FIXME: hacky
        from helper import encode_base58_checksum
        sec = key.point.sec(compressed=True)
        redeem_script  = Script(cmds=[sec, 172])
        raw_redeem = redeem_script.raw_serialize()
        h160 = hash160(raw_redeem)
        p2sh_script(h160)
        prefix = b'\xc4'  # testnet
        return encode_base58_checksum(prefix + h160)
    elif args.type == 'p2wpkh':
        return public_key.bech32_address(testnet=True)
    else:
        raise ValueError('unknown address type')


def handle_send(args):
    wallet = Wallet.open()

    # construct inputs
    utxos = [(u['txid'], u['vout']) for u in testnet.listunspent(0)]
    tx_ins = []
    input_sum = 0
    for tx_id, tx_index in utxos:
        raw = testnet.getrawtransaction(tx_id, 0)
        tx = Tx.parse(BytesIO(bytes.fromhex(raw)))
        tx_ins.append(TxIn(tx.hash(), tx_index))
        input_sum += tx.tx_outs[tx_index].amount
        if input_sum > args.amount:
            break
    assert input_sum >= args.amount, "insufficient utxos to pay {}".format(args.amount)

    # construct outputs
    sec = wallet.private_key.point.sec(compressed=True)
    script_pubkey = address_to_script_pubkey(args.address)
    send_output = TxOut(args.amount, script_pubkey)
    fees = 500  # FIXME
    change = input_sum - args.amount - fees
    change_script_pubkey = p2wpkh_script(hash160(sec))
    change_output = TxOut(change, change_script_pubkey)
    tx_outs = [send_output, change_output]

    # construct transaction and sign inputs
    tx = Tx(1, tx_ins, tx_outs, 0, testnet=True, segwit=True)
    for index, tx_in in enumerate(tx.tx_ins):
        # get the redeem script if we're spending P2SH output
        if tx_in.script_pubkey(testnet=True).is_p2sh_script_pubkey():
            redeem_script = Script(cmds=[sec, 172])
        else:
            redeem_script = None
        verifies = tx.sign_input(index, wallet.private_key, redeem_script=redeem_script)
        if not verifies:
            raise RuntimeError("input doesn't verify")
    broadcasted = testnet.sendrawtransaction(tx.serialize().hex())
    print(broadcasted)


def main():
    parser = argparse.ArgumentParser(description='bedrock bitcoin tools')
    subparsers = parser.add_subparsers()

    # "bedrock address"
    address = subparsers.add_parser('address', help='get your addresses')
    address.add_argument('type', help='output type (p2pkh|p2sh|p2wpkh)')
    address.set_defaults(func=handle_address)

    # "bedrock send"
    send = subparsers.add_parser('send', help='send coins')
    send.add_argument('address', help='recipient bitcoin address')
    send.add_argument('amount', type=int, help='how many satoshis to send')
    send.set_defaults(func=handle_send)

    args = parser.parse_args()
    print(args.func(args))



if __name__ == '__main__':
    main()
    # p2wpkh_to_p2wpkh()
