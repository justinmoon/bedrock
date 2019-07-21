from logging import getLogger

from io import BytesIO
from unittest import TestCase

from .helper import (
    decode_bech32,
    decode_base58,
    encode_bech32_checksum,
    encode_varint,
    encode_varstr,
    h160_to_p2pkh_address,
    h160_to_p2sh_address,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
    sha256,
)
from .op import (
    op_equal,
    op_hash160,
    op_verify,
    OP_CODE_FUNCTIONS,
    OP_CODE_NAMES,
)


def p2pkh_script(h160):
    '''Takes a hash160 and returns the p2pkh ScriptPubKey'''
    return Script([0x76, 0xa9, h160, 0x88, 0xac])


def p2sh_script(h160):
    '''Takes a hash160 and returns the p2sh ScriptPubKey'''
    return Script([0xa9, h160, 0x87])


def p2wpkh_script(h160):
    '''Takes a hash160 and returns the p2wpkh ScriptPubKey'''
    return Script([0x00, h160])


def p2wsh_script(h160):
    '''Takes a hash160 and returns the p2wsh ScriptPubKey'''
    return Script([0x00, h160])


def address_to_script_pubkey(s):
    '''Convert address into ScriptPubKey'''
    # p2pkh
    if s[:1] in ('1', 'm', 'n'):
        h160 = decode_base58(s)
        return p2pkh_script(h160)
    # p2sh
    elif s[:1] in ('2', '3'):
        h160 = decode_base58(s)
        return p2sh_script(h160)
    # p2wpkh
    elif s[:3] in ('bc1', 'tb1'):
        raw_script = decode_bech32(s)
        return Script.parse(BytesIO(encode_varstr(raw_script)))
    else:
        raise RuntimeError('unknown type of address: {}'.format(s))


LOGGER = getLogger(__name__)


def print_state(instructions, instruction, stack, altstack):
    LOGGER.info('-' * 78)
    print_altstack = len(altstack) > 0
    if print_altstack:
        column_width = 18
        in_between = 2
    else:
        column_width = 24
        in_between = 3
    format_str = '{0: <' + str(column_width) + '}'
    total_height = max(len(instructions), 1, len(stack))
    for i in range(total_height):
        to_print = ''
        if len(instructions) >= total_height - i:
            current = instructions[len(instructions) - (total_height - i)]
            if type(current) == int:
                current = OP_CODE_NAMES.get(current) or '<unknown>'
            else:
                current = current.hex()[:column_width]
            to_print += format_str.format(current)
        else:
            to_print += ' ' * column_width
        to_print += ' ' * in_between
        if i == total_height - 1:
            current = instruction
            if type(current) == int:
                current = OP_CODE_NAMES.get(current) or '<unknown>'
            else:
                current = current.hex()[:column_width]
            to_print += format_str.format(current)
        else:
            to_print += ' ' * column_width
        to_print += ' ' * in_between
        if len(stack) >= total_height - i:
            current = stack[total_height - i - 1]
            if len(current) == 0:
                current = '0'
            else:
                current = current.hex()[:column_width]
            to_print += format_str.format(current)
        if print_altstack:
            to_print += ' ' * in_between
            if len(stack) >= total_height - i:
                current = stack[total_height - i - 1]
                if len(current) == 0:
                    current = '0'
                else:
                    current = current.hex()[:column_width]
                to_print += format_str.format(current)
        LOGGER.info(to_print)


class Script:

    def __init__(self, cmds=None):
        if cmds is None:
            self.cmds = []
        else:
            self.cmds = cmds

    def __repr__(self):
        result = []
        for cmd in self.cmds:
            if type(cmd) == int:
                if OP_CODE_NAMES.get(cmd):
                    name = OP_CODE_NAMES.get(cmd)
                else:
                    name = 'OP_[{}]'.format(cmd)
                result.append(name)
            else:
                result.append(cmd.hex())
        return ' '.join(result)

    def __add__(self, other):
        return Script(self.cmds + other.cmds)

    @classmethod
    def parse(cls, s):
        # get the length of the entire field
        length = read_varint(s)
        # initialize the cmds array
        cmds = []
        # initialize the number of bytes we've read to 0
        count = 0
        # loop until we've read length bytes
        while count < length:
            # get the current byte
            current = s.read(1)
            # increment the bytes we've read
            count += 1
            # convert the current byte to an integer
            current_byte = current[0]
            # if the current byte is between 1 and 75 inclusive
            if current_byte >= 1 and current_byte <= 75:
                # we have an cmd set n to be the current byte
                n = current_byte
                # add the next n bytes as an cmd
                cmds.append(s.read(n))
                # increase the count by n
                count += n
            elif current_byte == 76:
                # op_pushdata1
                data_length = little_endian_to_int(s.read(1))
                cmds.append(s.read(data_length))
                count += data_length + 1
            elif current_byte == 77:
                # op_pushdata2
                data_length = little_endian_to_int(s.read(2))
                cmds.append(s.read(data_length))
                count += data_length + 2
            else:
                # we have an opcode. set the current byte to op_code
                op_code = current_byte
                # add the op_code to the list of cmds
                cmds.append(op_code)
        if count != length:
            raise SyntaxError('parsing script failed')
        return cls(cmds)

    def raw_serialize(self):
        # initialize what we'll send back
        result = b''
        # go through each cmd
        for cmd in self.cmds:
            # if the cmd is an integer, it's an opcode
            if type(cmd) == int:
                # turn the cmd into a single byte integer using int_to_little_endian
                result += int_to_little_endian(cmd, 1)
            else:
                # otherwise, this is an element
                # get the length in bytes
                length = len(cmd)
                # for large lengths, we have to use a pushdata opcode
                if length < 75:
                    # turn the length into a single byte integer
                    result += int_to_little_endian(length, 1)
                elif length > 75 and length < 0x100:
                    # 76 is pushdata1
                    result += int_to_little_endian(76, 1)
                    result += int_to_little_endian(length, 1)
                elif length >= 0x100 and length <= 520:
                    # 77 is pushdata2
                    result += int_to_little_endian(77, 1)
                    result += int_to_little_endian(length, 2)
                else:
                    raise ValueError('too long an cmd')
                result += cmd
        return result

    def serialize(self):
        # get the raw serialization (no prepended length)
        result = self.raw_serialize()
        # get the length of the whole thing
        total = len(result)
        # encode_varint the total length of the result and prepend
        return encode_varint(total) + result

    def evaluate(self, z, witness):
        # create a copy as we may need to add to this list if we have a
        # RedeemScript
        print(self.cmds)
        cmds = self.cmds[:]
        stack = []
        altstack = []
        print_state(cmds, b'', stack, altstack)
        while len(cmds) > 0:
            cmd = cmds.pop(0)
            print_state(cmds, cmd, stack, altstack)
            if type(cmd) == int:
                # do what the opcode says
                operation = OP_CODE_FUNCTIONS[cmd]
                if cmd in (99, 100):
                    # op_if/op_notif require the cmds array
                    if not operation(stack, cmds):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                elif cmd in (107, 108):
                    # op_toaltstack/op_fromaltstack require the altstack
                    if not operation(stack, altstack):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                elif cmd in (172, 173, 174, 175):
                    # these are signing operations, they need a sig_hash
                    # to check against
                    if not operation(stack, z):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                else:
                    if not operation(stack):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
            else:
                # add the cmd to the stack
                stack.append(cmd)
                # p2sh rule. if the next three cmds are:
                # OP_HASH160 <20 byte hash> OP_EQUAL this is the RedeemScript
                # OP_HASH160 == 0xa9 and OP_EQUAL == 0x87
                if len(cmds) == 3 and cmds[0] == 0xa9 \
                    and type(cmds[1]) == bytes and len(cmds[1]) == 20 \
                    and cmds[2] == 0x87:
                    redeem_script = encode_varint(len(cmd)) + cmd
                    # we execute the next three opcodes
                    cmds.pop()
                    h160 = cmds.pop()
                    cmds.pop()
                    if not op_hash160(stack):
                        return False
                    stack.append(h160)
                    if not op_equal(stack):
                        return False
                    # final result should be a 1
                    if not op_verify(stack):
                        LOGGER.info('bad p2sh h160')
                        return False
                    # hashes match! now add the RedeemScript
                    redeem_script = encode_varint(len(cmd)) + cmd
                    stream = BytesIO(redeem_script)
                    cmds.extend(Script.parse(stream).cmds)
                # witness program version 0 rule. if stack cmds are:
                # 0 <20 byte hash> this is p2wpkh
                if len(stack) == 2 and stack[0] == b'' and len(stack[1]) == 20:  # <1>
                    h160 = stack.pop()
                    stack.pop()
                    cmds.extend(witness)
                    cmds.extend(p2pkh_script(h160).cmds)
                # witness program version 0 rule. if stack cmds are:
                # 0 <32 byte hash> this is p2wsh
                if len(stack) == 2 and stack[0] == b'' and len(stack[1]) == 32:
                    s256 = stack.pop()  # <1>
                    stack.pop()  # <2>
                    cmds.extend(witness[:-1])  # <3>
                    witness_script = witness[-1]  # <4>
                    if s256 != sha256(witness_script):  # <5>
                        LOGGER.debug('bad sha256 {} vs {}'.format
                            (s256.hex(), sha256(witness_script).hex()))
                        return False
                    stream = BytesIO(encode_varint(len(witness_script)) 
                        + witness_script)
                    witness_script_cmds = Script.parse(stream).cmds  # <6>
                    cmds.extend(witness_script_cmds)
        LOGGER.debug('stack after execution: {}'.format(stack))
        if len(stack) == 0:
            return False
        if stack.pop() == b'':
            return False
        return True

    def is_p2pkh_script_pubkey(self):
        '''Returns whether this follows the
        OP_DUP OP_HASH160 <20 byte hash> OP_EQUALVERIFY OP_CHECKSIG pattern.'''
        # there should be exactly 5 cmds
        # OP_DUP (0x76), OP_HASH160 (0xa9), 20-byte hash, OP_EQUALVERIFY (0x88),
        # OP_CHECKSIG (0xac)
        return len(self.cmds) == 5 and self.cmds[0] == 0x76 \
            and self.cmds[1] == 0xa9 \
            and type(self.cmds[2]) == bytes and len(self.cmds[2]) == 20 \
            and self.cmds[3] == 0x88 and self.cmds[4] == 0xac

    def is_p2sh_script_pubkey(self):
        '''Returns whether this follows the
        OP_HASH160 <20 byte hash> OP_EQUAL pattern.'''
        # there should be exactly 3 cmds
        # OP_HASH160 (0xa9), 20-byte hash, OP_EQUAL (0x87)
        return len(self.cmds) == 3 and self.cmds[0] == 0xa9 \
            and type(self.cmds[1]) == bytes and len(self.cmds[1]) == 20 \
            and self.cmds[2] == 0x87

    def is_p2wpkh_script_pubkey(self):
        '''Returns whether this follows the
        OP_0 <20 byte hash> pattern.'''
        return len(self.cmds) == 2 and self.cmds[0] == 0x00 \
            and type(self.cmds[1]) == bytes and len(self.cmds[1]) == 20

    def is_p2wsh_script_pubkey(self):
        return len(self.cmds) == 2 and self.cmds[0] == 0x00 \
            and type(self.cmds[1]) == bytes and len(self.cmds[1]) == 32

    def address(self, testnet=False):
        '''Returns the address corresponding to the script'''
        if self.is_p2pkh_script_pubkey():  # p2pkh
            # hash160 is the 3rd cmd
            h160 = self.cmds[2]
            # convert to p2pkh address using h160_to_p2pkh_address (remember testnet)
            return h160_to_p2pkh_address(h160, testnet)
        elif self.is_p2sh_script_pubkey():  # p2sh
            # hash160 is the 2nd cmd
            h160 = self.cmds[1]
            # convert to p2sh address using h160_to_p2sh_address (remember testnet)
            return h160_to_p2sh_address(h160, testnet)
        elif self.is_p2wpkh_script_pubkey():  # p2sh
            # hash160 is the 2nd element
            witness_program = self.raw_serialize()
            # convert to bech32 address using encode_bech32_checksum
            return encode_bech32_checksum(witness_program, testnet)
        else:
            # only produce addresses for scripts we recognize
            raise ValueError('Unknown ScriptPubKey')


class ScriptTest(TestCase):

    def test_parse(self):
        script_pubkey = BytesIO(bytes.fromhex('6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937'))
        script = Script.parse(script_pubkey)
        want = bytes.fromhex('304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a71601')
        self.assertEqual(script.cmds[0].hex(), want.hex())
        want = bytes.fromhex('035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937')
        self.assertEqual(script.cmds[1], want)

    def test_serialize(self):
        want = '6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937'
        script_pubkey = BytesIO(bytes.fromhex(want))
        script = Script.parse(script_pubkey)
        self.assertEqual(script.serialize().hex(), want)

    def test_address(self):
        address_1 = '1BenRpVUFK65JFWcQSuHnJKzc4M8ZP8Eqa'
        h160 = decode_base58(address_1)
        p2pkh_script_pubkey = p2pkh_script(h160)
        self.assertEqual(p2pkh_script_pubkey.address(), address_1)
        address_2 = 'mrAjisaT4LXL5MzE81sfcDYKU3wqWSvf9q'
        self.assertEqual(p2pkh_script_pubkey.address(testnet=True), address_2)
        address_3 = '3CLoMMyuoDQTPRD3XYZtCvgvkadrAdvdXh'
        h160 = decode_base58(address_3)
        p2sh_script_pubkey = p2sh_script(h160)
        self.assertEqual(p2sh_script_pubkey.address(), address_3)
        address_4 = '2N3u1R6uwQfuobCqbCgBkpsgBxvr1tZpe7B'
        self.assertEqual(p2sh_script_pubkey.address(testnet=True), address_4)
