import decimal
from binascii import unhexlify

from ecc import PrivateKey
from script import Script, p2sh_script
from helper import hash160, SIGHASH_ALL
from tx import Tx, TxIn, TxOut
from rpc import testnet, mainnet



decimal.getcontext().prec = 8


key = PrivateKey(58800187338825965989061197411175755305019286370732616970021105328088303800804)

def send_to_p2sh():
    unspent = testnet.listunspent(1)[0]
    assert unspent['label'] == 'BITBOY'
    tx_in = TxIn(
        unhexlify(unspent['txid']),
        int(unspent['vout']),
    )
    unspent_amount = int(float(unspent['amount']) * 100_000_000)
    fees = 1000
    sec = key.point.sec(compressed=True)
    redeem_script = Script(cmds=[sec, 172])
    raw_redeem_script = redeem_script.serialize()[1:]  # chop off varint
    h160 = hash160(raw_redeem_script)
    locking_script = p2sh_script(h160)
    tx_out = TxOut(
        int(unspent_amount - fees),
        locking_script,
    )
    print(tx_in.value(testnet=True))
    print(tx_out.amount)

    tx = Tx(1, [tx_in], [tx_out], 0, testnet=True)

    # sign
    tx.sign_input(0, key)

    print(tx.serialize())

    print(testnet.sendrawtransaction(tx.serialize().hex()))


def send_from_p2sh():
    pass


def test_p2sh():
    sec = key.point.sec(compressed=True)
    print(sec)
    redeem_script = Script(cmds=[sec, 172])
    # the "redeem script" that is hashed by h16 doesn't include the varint prefix
    h160 = hash160(redeem_script.serialize()[1:])
    locking_script = p2sh_script(h160)
    z = 0
    der = key.sign(z).der() + b'\x01'
    solution = Script([0, der])
    solution.cmds.append(redeem_script.serialize()[1:])
    combined = solution + locking_script
    print("combined:", combined)
    print(combined.evaluate(z, None))


send_to_p2sh()
