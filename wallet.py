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
        sec = public_key.sec(compressed=True)
        redeem_script = Script(cmds=[sec, 172])
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
        print(f"inputs: {tx_id}:{tx_index}")
        raw = testnet.getrawtransaction(tx_id, 0)
        tx = Tx.parse(BytesIO(bytes.fromhex(raw)))
        if tx.segwit:  # FIXME
            continue
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
    tx = Tx(1, tx_ins, tx_outs, 0, testnet=True, segwit=True)  # FIXME segwit param
    # tx = Tx(1, tx_ins, tx_outs, 0, testnet=True)
    for index, tx_in in enumerate(tx.tx_ins):
        # get the redeem script if we're spending P2SH output
        if tx_in.script_pubkey(testnet=True).is_p2sh_script_pubkey():
            redeem_script = Script(cmds=[sec, 172])
        else:
            redeem_script = None
        verifies = tx.sign_input(index, wallet.private_key, redeem_script=redeem_script)
        if not verifies:
            raise RuntimeError("input doesn't verify")
    print(tx.tx_ins[0].script_pubkey(testnet=True))
    print(tx.tx_ins[1].script_pubkey(testnet=True))
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
