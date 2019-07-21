import logging

from tx import Tx
from io import BytesIO

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

# signed with bitboy
raw = '02000000000102670bd7163f2b166af516f4cbbd2ac2d34f29065fce4d5f0d789b10f6ef99aeb30000000000ffffffff670bd7163f2b166af516f4cbbd2ac2d34f29065fce4d5f0d789b10f6ef99aeb30100000000ffffffff02e8030000000000001600149f6d67cbe1813e6878e282b01a8ec7e80a4556870000000000000000160014f32a49dfea14463042f30974e8eeb351a6df006502483045022100eee6afd9e97068ef63205999cbd9c1e64b42f8cadfb8108a2df2521250d2ef3c02206bbbf838589f67fc9013dd854275469ae53cbf15f03d6c8e4aa705d9f918e620012103a219347581e196b7e48bd19e6b4d616afa3f4111ea1f31213e9722693033ff5202483045022100f0097f1046761061bce1ff27ac0ecc9e390acd7c726a691a184f2d9a44a59e8d02206ce2af0afbc83a6fba0dd6b80cffc58b15eea8cb223de4d6813442cdd944280e012103a219347581e196b7e48bd19e6b4d616afa3f4111ea1f31213e9722693033ff5200000000'
tx = Tx.parse(BytesIO(bytes.fromhex(raw)), testnet=True)
# print("bitboy tx")
# print(tx)
print(tx.verify())
# print("segwit", tx.segwit)
# print("witness", tx.tx_ins[0].witness)
# print("script_pubkey", tx.tx_ins[0].script_pubkey(testnet=True))
print("is p2wpkh", tx.tx_ins[0].script_pubkey(testnet=True).is_p2wpkh_script_pubkey())
print(tx.tx_ins[0].prev_tx.hex())
# print("script_sig", tx.tx_ins[0].script_sig)

# signed with bedrock
raw = "01000000000102e7b6b08dc592368fc81cb10e28bd509f095c72887f0ac88de303c1ec2a57031c000000006b483045022100b233e5ba8efcd586387cfaa698bd035eeec57dd5b90c4d02de97a85e7ec46a48022075d510b8255939bda7d8ffd4438596b80b00cd89f1e1bb90bb443457636d2fe5012103a219347581e196b7e48bd19e6b4d616afa3f4111ea1f31213e9722693033ff52ffffffffe7b6b08dc592368fc81cb10e28bd509f095c72887f0ac88de303c1ec2a57031c0100000000ffffffff02a086010000000000160014f32a49dfea14463042f30974e8eeb351a6df0065c4b50d0000000000160014f32a49dfea14463042f30974e8eeb351a6df00650002483045022100d3c2abea36a4bea2e0b61f61002f5a243ab5453a507b6e1667e9aa777b3369f202204c8a3d440baa9dc9b83110e64c6167434fe3ee5bb947c6339482ec63aa4bcaf3012103a219347581e196b7e48bd19e6b4d616afa3f4111ea1f31213e9722693033ff5200000000"
tx = Tx.parse(BytesIO(bytes.fromhex(raw)), testnet=True)
# print("bedrock tx")
# print(tx)
# print(tx.verify())
