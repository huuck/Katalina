import logging
from utils import LogHandler
from helpers import *


handler = LogHandler()
log = logging.getLogger(__name__)
log.addHandler(handler)
# log.setLevel(logging.INFO)
log.setLevel(logging.ERROR)



class InstructionReturn:
    def __init__(self, ret, is_external_call, parameters):
        self.ret = ret
        self.is_external_call = is_external_call
        self.parameters = parameters

class Instruction:

    def __init__(self, opcode):
        self.fmt: int = 0x0
        self.prefix: str = "NOP"
        self.suffix: str = ""

        self.opcode = opcode

        self.address = 0

        # used by some instructions
        self.operator_type = 0
        self.operand_type = 0

    def decode_args_by_format(self, fmt: int, fd) -> tuple:
        decoded_args: list = []
        returned_args: list = []

        t: int = fmt & 0xF
        fmt >>= 4

        # argument_length in nibbles
        arg_length: int = 1
        while fmt:
            if t != fmt & 0xF:
                decoded_args.append({'len': arg_length, 'signed': t >= 0xA})
                arg_length = 1

                t = fmt & 0xF
            else:
                arg_length += 1

            fmt >>= 4

        decoded_args.append({'len': arg_length, 'signed': t >= 0xA})

        while len(decoded_args) > 0:
            decoded_arg = decoded_args.pop()

            if decoded_arg['len'] == 1:
                byte = b2i(fd.read(1))
                nibble0: int = nibble_at(byte, 0)
                nibble1: int = nibble_at(byte, 1)

                if decoded_arg['signed']:
                    nibble0 = twos_complement(nibble0, 0.5)

                decoded_arg = decoded_args.pop()

                if decoded_arg['signed']:
                    nibble1 = twos_complement(nibble1, 0.5)

                returned_args += [nibble0, nibble1]
            else:
                bytez = b2i(fd.read(decoded_arg['len'] // 2))
                if decoded_arg['signed']:
                    bytez = twos_complement(bytez, decoded_arg['len'] // 2)

                returned_args.append(bytez)
        return tuple(returned_args) if len(returned_args) > 1 else returned_args[0]

    def decode_args(self, fd) -> tuple:
        return self.decode_args_by_format(self.fmt, fd)

    def print_instruction(self) -> None:
        raise NotImplementedError()

    def fetch(self) -> None:
        raise NotImplementedError()

    def decode(self, fd) -> None:
        self.address = fd.tell() - 1

    def execute(self, memory, v):
        new_pc = self.address + 1 + (self.fmt.bit_length() + 7) // 8
        # align PC to 2 bytes
        new_pc += new_pc % 2

        log.debug(new_pc)
        return InstructionReturn(new_pc, False, [])


class OpCodeNotFoundError(Exception):
    def __init__(self, opcode):
        super().__init__("%s not defined, try another decoder!" % hex(opcode))


class Move(Instruction):

    def fetch(self) -> None:
        self.prefix = "MOVE(OBJ)"

        match self.opcode:
            case 0x01 | 0x07 | 0x04:
                self.fmt = 0x12
            case 0x02 | 0x08 | 0x05:
                self.suffix = "/FROM16"
                self.fmt = 0x112222
            case 0x03 | 0x09 | 0x06:
                self.suffix = "/16"
                self.fmt = 0x11112222
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd) -> None:
        super().decode(fd)
        # align bytes
        if self.opcode in [0x03, 0x09, 0x06]:
            fd.read(1)
        (self.vA, self.vB) = self.decode_args(fd)

    def print_instruction(self):
        log.debug("%s%s v%s v%s" % (self.prefix, self.suffix, self.vA, self.vB))

    def execute(self, memory, v):
        if self.opcode not in [0x04, 0x05, 0x06]:
            v[self.vA] = v[self.vB]
        else:
            # DO WIDE MOVE
            v[self.vA] = v[self.vB]
            v[self.vA + 1] = v[self.vB + 1]
        return super().execute(memory, v)


class MoveResult(Instruction):

    def fetch(self) -> None:
        self.prefix = "MOVE-RESULT(EX)"
        match self.opcode:
            case 0x0a | 0x0b | 0x0c | 0x0d:
                self.fmt = 0x11
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd) -> None:
        super().decode(fd)
        self.vA = self.decode_args(fd)

    def print_instruction(self):
        log.debug("%s v%s" % (self.prefix, self.vA))

    def execute(self, memory, v):
        if self.opcode != 0x0b:
            v[self.vA] = memory.last_return
        else:
            # handle wide
            try:
                v[self.vA] = memory.last_return[0]
                v[self.vA + 1] = memory.last_return[1]
            except TypeError as te:
                # handle null returns from the API translator
                v[self.vA] = 0
                v[self.vA + 1] = 0

        return super().execute(memory, v)


class Return(Instruction):

    def fetch(self) -> None:
        self.prefix = "RETURN"
        match self.opcode:
            case 0x0e | 0x0f | 0x10 | 0x11:
                self.fmt = 0x11
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd) -> None:
        super().decode(fd)
        self.vA = self.decode_args(fd)

    def print_instruction(self):
        if self.opcode != 0x0e:
            log.debug("%s v%s" % (self.prefix, self.vA))
        else:
            log.debug("%s-VOID" % self.prefix)

    def execute(self, memory, v):
        if self.opcode == 0x0e:
            pass
        elif self.opcode == 0x10:
            memory.last_return = (v[self.vA], v[self.vA + 1])
        else:
            memory.last_return = v[self.vA]
        return super().execute(memory, v)


class Nop(Instruction):

    def fetch(self) -> None:
        pass

    def decode(self, fd) -> None:
        super().decode(fd)
        pass

    def print_instruction(self):
        log.debug("NOP")

    def execute(self, memory, v):
        return super().execute(memory, v)


class Const(Instruction):

    def fetch(self) -> None:
        self.prefix = "CONST"
        match self.opcode:
            case 0x12:
                self.suffix = "/4"
                self.fmt = 0x1A
            case 0x13:
                self.suffix = "/16"
                self.fmt = 0x11AAAA
            case 0x14:
                self.suffix = ""
                self.fmt = 0x11AAAAAAAA
            case 0x15:
                self.suffix = "/HIGH16"  # 420#BLAZEIT
                self.fmt = 0x11AAAA
            case 0x16:
                self.suffix = "-WIDE/16"
                self.fmt = 0x11AAAA
            case 0x17:
                self.suffix = "-WIDE/32"
                self.fmt = 0x11AAAAAAAA
            case 0x18:
                self.suffix = "-WIDE"
                self.fmt = 0x11AAAAAAAAAAAAAAAA
            case 0x19:
                self.suffix = "WIDE/HIGH16"
                self.fmt = 0x11AAAA
            case 0x1a:
                self.suffix = "-STRING"
                self.fmt = 0x112222
            case 0x1b:
                self.suffix = "-STRING/JUMBO"
                self.fmt = 0x1122222222
            case 0x1c:
                self.suffix = "-CLASS"
                self.fmt = 0x112222
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd) -> None:
        super().decode(fd)
        (self.vA, self.vB) = self.decode_args(fd)

    def print_instruction(self):
        log.debug("%s%s v%s %s" % (self.prefix, self.suffix, self.vA, self.vB))

    def execute(self, memory, v):
        if self.opcode in [0x1a, 0x1b]:
            pass

        match self.opcode:
            case 0x12 | 0x13 | 0x14 | 0x18:
                v[self.vA] = self.vB
            case 0x15:
                v[self.vA] = self.vB << 16
            case 0x16:
                v[self.vA] = self.vB  # << 48
            case 0x17:
                v[self.vA] = self.vB  # << 32
            case 0x19:
                v[self.vA] = self.vB << 48
            case 0x1a | 0x1b:
                # do string lookup here
                v[self.vA] = memory.dex.string_ids[self.vB].value.raw_data
            case 0x1c:
                # do class lookup here
                v[self.vA] = self.vB
            case _:
                raise OpCodeNotFoundError(self.opcode)

        # redistribute across 2 registers for wide movement
        if self.opcode in [0x16, 0x17, 0x18, 0x19]:
            v[self.vA + 1] = v[self.vA] & 0xFFFFFFFF
            v[self.vA] >>= 32
        return super().execute(memory, v)


class Monitor(Instruction):

    def print_instruction(self):
        log.debug("MONITOR-ENTER/EXIT %s" % self.vA)

    def fetch(self) -> None:
        self.fmt = 0x11

    def decode(self, fd) -> None:
        super().decode(fd)
        self.vA = self.decode_args(fd)


class CheckCast(Instruction):

    def print_instruction(self):
        log.debug("CHECK-CAST %s v%s" % (self.vA, self.vB))

    def fetch(self) -> None:
        self.fmt = 0x112222

    def decode(self, fd) -> None:
        super().decode(fd)
        (self.vA, self.vB) = self.decode_args(fd)


class InstanceOf(Instruction):

    def print_instruction(self):
        log.debug("INSTANCE-OF v%s v%s @%s" % (self.vA, self.vB, self.vC))

    def fetch(self) -> None:
        self.fmt = 0x123333

    def decode(self, fd) -> None:
        super().decode(fd)
        (self.vA, self.vB, self.vC) = self.decode_args(fd)


class ArrLength(Instruction):

    def fetch(self) -> None:
        self.prefix = "ARRAY-LENGTH"
        match self.opcode:
            case 0x21:
                self.fmt = 0x12
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd) -> None:
        super().decode(fd)
        (self.vA, self.vB) = self.decode_args(fd)

    def print_instruction(self):
        log.debug("%s v%s v%s" % (self.prefix, self.vA, self.vB))

    def execute(self, memory, v):
        # account for junk left inside the registers
        try:
            v[self.vA] = len(v[self.vB])
        except TypeError:
            v[self.vA] = 0

        return super().execute(memory, v)


class NewInstance(Instruction):

    def fetch(self) -> None:
        self.prefix = "NEW-INSTANCE"
        match self.opcode:
            case 0x22:
                self.fmt = 0x112222
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd) -> None:
        super().decode(fd)
        (self.vA, self.vB) = self.decode_args(fd)

    def print_instruction(self):
        log.debug("%s v%s" % (self.prefix, self.vA))

    def execute(self, memory, v):
        # TODO: parse TypeID vB
        if "String" in memory.dex.type_ids[self.vB].type_name:
            v[self.vA] = ""
        else:
            v[self.vA] = None
        return super().execute(memory, v)


class Array(Instruction):

    def fetch(self) -> None:
        self.prefix = ""
        match self.opcode:
            case 0x23:
                self.suffix = "NEW-ARRAY"
                self.fmt = 0x123333
            case 0x24:
                self.suffix = "FILLED-NEW-ARRAY"
                self.fmt = 0x1233334567
            case 0x25:
                self.suffix = "FILLED-NEW-ARRAY/RANGE"
                self.fmt = 0x1122223333
            case 0x26:
                self.suffix = "FILL-ARRAY-DATA"
                self.fmt = 0x11AAAAAAAA
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd) -> None:
        super().decode(fd)
        match self.opcode:
            case 0x23:
                (self.vA, self.vB, self.vC) = self.decode_args(fd)
            case 0x24:
                (self.vA, self.vB, self.vC, self.vD, self.vE, self.vF, self.vG) = self.decode_args(fd)
            case 0x25:
                (self.vA, self.vB, self.vC) = self.decode_args(fd)
            case 0x26:
                (self.vA, self.vB) = self.decode_args(fd)

    def print_instruction(self):
        try:
            log.debug("%s v%s v%s @%s" % (self.suffix, self.vA, self.vB, hex(self.vC)))
        except AttributeError:
            log.debug("%s v%s @%s" % (self.suffix, self.vA, self.vB))

    def execute(self, memory, v):
        match self.opcode:
            case 0x23:
                new_arr: list = []
                # account for junk in the size register
                try:
                    for i in range(v[self.vB]):
                        new_arr.append(0)
                except:
                    new_arr = []
                v[self.vA] = new_arr
            case 0x24:
                # TODO: implement
                pass
            case 0x25:
                # TODO: implement
                pass
            case 0x26:
                # skip array pseudo-instruction header (03 00), we don't need it

                memory.fd.seek(self.address + self.vB * 2 + 2)

                (element_width, element_num) = self.decode_args_by_format(0x111122222222, memory.fd)

                for i in range(element_num):
                    v[self.vA][i] = b2i(memory.fd.read(element_width))
                # restore PC, skipping over the read instruction data
                memory.fd.seek(self.address + 6)
        return super().execute(memory, v)


class Throw(Instruction):

    def print_instruction(self):
        log.debug("THROW v%s" % self.vA)

    def fetch(self) -> None:
        self.fmt = 0x11

    def decode(self, fd) -> None:
        super().decode(fd)
        self.vA = self.decode_args(fd)

    def execute(self, memory, v):
        return super().execute(memory, v)


class Goto(Instruction):

    def fetch(self) -> None:
        self.prefix = "GOTO"
        match self.opcode:
            case 0x28:
                self.fmt = 0xAA
            case 0x29:
                self.suffix = "/16"
                self.fmt = 0xAAAA
            case 0x2a:
                self.suffix = "/32"
                self.fmt = 0xAAAAAAAA
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd) -> None:
        super().decode(fd)
        # hack for aligning /16 and /32 constants
        if self.opcode in [0x29, 0x2a]:
            fd.read(1)
        self.vA = self.decode_args(fd)

    def print_instruction(self):
        log.debug("%s%s @%s" % (self.prefix, self.suffix, hex(self.vA)))

    def execute(self, memory, v):
        return InstructionReturn(self.address + self.vA * 2, False, [])


class Switch(Instruction):

    def print_instruction(self) -> None:
        log.debug("SWITCH v%s @%s" % (self.vA, self.vB))

    def fetch(self) -> None:
        self.fmt = 0x11AAAAAAAA

    def decode(self, fd) -> None:
        super().decode(fd)
        (self.vA, self.vB) = self.decode_args(fd)
        self.switch_table = {}

        # read packed switch data
        old_fd_index = fd.tell()

        fd.seek(old_fd_index + self.vB * 2 - 6)
        fake_opcode = fd.read(2)
        nr_elements = b2i(fd.read(2))
        if self.opcode == 0x2b:
            element_base = twos_complement(b2i(fd.read(4)), 4)
            for i in range(0, nr_elements):
                self.switch_table[element_base + i] = twos_complement(b2i(fd.read(4)), 4)
        if self.opcode == 0x2c:
            for i in range(0, nr_elements):
                self.switch_table[twos_complement(b2i(fd.read(4)), 4)] = 0
            for key in self.switch_table.keys():
                self.switch_table[key] = twos_complement(b2i(fd.read(4)), 4)

        fd.seek(old_fd_index)

    def execute(self, memory, v):
        found_switch_branch = False
        for value, offset in self.switch_table.items():
            if v[self.vA] == value:
                ret = self.address + offset * 2
                found_switch_branch = True

        if not found_switch_branch:
            return super().execute(memory, v)
        else:
            return InstructionReturn(ret, False, [])


class Cmp(Instruction):

    def print_instruction(self):
        log.debug("CMP v%s v%s v%s" % (self.vA, self.vB, self.vC))

    def fetch(self) -> None:
        self.fmt = 0x112233

    def decode(self, fd) -> None:
        super().decode(fd)
        (self.vA, self.vB, self.vC) = self.decode_args(fd)

    def execute(self, memory, v):
        a: int = 0
        b: int = 0
        c: int = 0
        if self.opcode >= 0x2f:
            a = (v[self.vB] << 32) + v[self.vB + 1]
            b = (v[self.vC] << 32) + v[self.vC + 1]
        else:
            a = v[self.vB]
            b = v[self.vC]

        if not a or not b:
            match self.opcode:
                case 0x2d:
                    c = -1
                case 0x2e:
                    c = 1
                case 0x2f:
                    c = -1
                case 0x30:
                    c = 1
        else:
            if a > b:
                c = 1
            elif a < b:
                c = -1
            else:
                c = 0

        v[self.vA] = c
        return super().execute(memory, v)


IF_LOOKUP = {0x32: "EQ", 0x33: "NE", 0x34: "LT", 0x35: "GE", 0x36: "GT", 0x37: "LE"}
IFZ_LOOKUP = {0x38: "EQZ", 0x39: "NEZ", 0x3a: "LTZ", 0x3b: "GEZ", 0x3c: "GTZ", 0x3d: "LEZ"}


class If(Instruction):

    def fetch(self) -> None:
        self.prefix = "IF"
        match self.opcode:
            case 0x32 | 0x33 | 0x34 | 0x35 | 0x36 | 0x37:
                self.suffix = IF_LOOKUP[self.opcode]
                self.fmt = 0x12AAAA
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd) -> None:
        super().decode(fd)
        (self.vA, self.vB, self.vC) = self.decode_args(fd)

    def print_instruction(self):
        log.debug("%s-%s v%s v%s @%s" % (self.prefix, self.suffix, self.vA, self.vB, hex(self.vC)))

    def execute(self, memory, v):
        if v[self.vA] is None or v[self.vB] is None:
            return super().execute(memory, v)

        match self.opcode:
            case 0x32:
                if v[self.vA] == v[self.vB]:
                    ret = self.address + self.vC * 2
                else:
                    return super().execute(memory, v)
            case 0x33:
                if v[self.vA] != v[self.vB]:
                    ret = self.address + self.vC * 2
                else:
                    return super().execute(memory, v)
            case 0x34:
                if v[self.vA] < v[self.vB]:
                    ret = self.address + self.vC * 2
                else:
                    return super().execute(memory, v)
            case 0x35:
                if v[self.vA] >= v[self.vB]:
                    ret = self.address + self.vC * 2
                else:
                    return super().execute(memory, v)
            case 0x36:
                if v[self.vA] > v[self.vB]:
                    ret = self.address + self.vC * 2
                else:
                    return super().execute(memory, v)
            case 0x37:
                if v[self.vA] <= v[self.vB]:
                    ret = self.address + self.vC * 2
                else:
                    return super().execute(memory, v)

        return InstructionReturn(ret, False, [])


class IfZ(Instruction):

    def fetch(self) -> None:
        self.prefix = "IF"
        match self.opcode:
            case 0x38 | 0x39 | 0x3a | 0x3b | 0x3c | 0x3d:
                self.suffix = IFZ_LOOKUP[self.opcode]
                self.fmt = 0x11AAAA
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd) -> None:
        super().decode(fd)
        (self.vA, self.vB) = self.decode_args(fd)

    def print_instruction(self):
        log.debug("%s-%s v%s @%s" % (self.prefix, self.suffix, self.vA, hex(self.vB)))

    def execute(self, memory, v):
        # always skip execution for None; is it wise? time will tell :/
        if v[self.vA] is None:
            return super().execute(memory, v)
            return

        match self.opcode:
            case 0x38:
                if v[self.vA] == 0:
                    ret = self.address + self.vB * 2
                else:
                    return super().execute(memory, v)
            case 0x39:
                if v[self.vA] != 0:
                    ret = self.address + self.vB * 2
                else:
                    return super().execute(memory, v)
            case 0x3a:
                if v[self.vA] < 0:
                    ret = self.address + self.vB * 2
                else:
                    return super().execute(memory, v)
            case 0x3b:
                if v[self.vA] >= 0:
                    ret = self.address + self.vB * 2
                else:
                    return super().execute(memory, v)
            case 0x3c:
                if v[self.vA] > 0:
                    ret = self.address + self.vB * 2
                else:
                    return super().execute(memory, v)
            case 0x3d:
                if v[self.vA] <= 0:
                    ret = self.address + self.vB * 2
                else:
                    return super().execute(memory, v)

        return InstructionReturn(ret, False, [])


AOP_LOOKUP = {0x44: "INT", 0x45: "WIDE", 0x46: "OBJECT", 0x47: "BOOLEAN", 0x48: "BYTE", 0x49: "CHAR", 0x4a: "SHORT",
              0x4b: "INT", 0x4c: "WIDE", 0x4d: "OBJECT", 0x4e: "BOOLEAN", 0x4f: "BYTE", 0x50: "CHAR", 0x51: "SHORT"}


class ArrayOp(Instruction):
    def fetch(self) -> None:
        self.fmt = 0x112233

        if 0x44 <= self.opcode <= 0x4a:
            self.prefix = "AGET"
        elif 0x4b <= self.opcode <= 0x51:
            self.prefix = "APUT"
        else:
            raise OpCodeNotFoundError(self.opcode)

        self.suffix = AOP_LOOKUP[self.opcode]

    def decode(self, fd) -> None:
        super().decode(fd)
        (self.vA, self.vB, self.vC) = self.decode_args(fd)

    def print_instruction(self):
        log.debug("%s-%s v%s v%s @v%s" % (self.prefix, self.suffix, self.vA, self.vB, self.vC))

    def execute(self, memory, v):
        if 0x44 <= self.opcode <= 0x4a:
            try:
                v[self.vA] = v[self.vB][v[self.vC]]
            except TypeError as te:
                v[self.vA] = None

        elif 0x4b <= self.opcode <= 0x51:
            v[self.vB][v[self.vC]] = v[self.vA]
        return super().execute(memory, v)


class IOp(Instruction):
    def print_instruction(self):
        log.debug("%s-%s v%s v%s @%s" % (self.prefix, self.suffix, self.vA, self.vB, self.vC))

    def fetch(self) -> None:
        self.fmt = 0x123333

    def decode(self, fd) -> None:
        super().decode(fd)
        self.suffix = "???"
        if 0x52 <= self.opcode <= 0x58:
            self.prefix = "IGET"
        elif 0x59 <= self.opcode <= 0x5f:
            self.prefix = "IPUT"
        else:
            raise OpCodeNotFoundError(self.opcode)

        (self.vA, self.vB, self.vC) = self.decode_args(fd)

    def execute(self, memory, v):
        if self.vC == 4418:
            pass

        # TODO: handle wide cornercase
        if 0x52 <= self.opcode <= 0x58:
            v[self.vA] = memory.instance_fields.get(self.vC, 0)

            # wide cornercase
            if self.opcode == 0x53:
                v[self.vA + 1] = v[self.vA] & 0xFFFFFFFF
                v[self.vA] = v[self.vA] >> 32
        elif 0x59 <= self.opcode <= 0x5f:
            memory.instance_fields[self.vC] = v[self.vA]
            # wide cornercase
            if self.opcode == 0x5a:
                memory.instance_fields[self.vC] <<= 32
                memory.instance_fields[self.vC] += v[self.vA + 1]

        return super().execute(memory, v)


class SGet(Instruction):

    def print_instruction(self):
        log.debug("%s-%s v%s @v%s" % (self.prefix, self.suffix, self.vA, self.vB))

    def fetch(self) -> None:
        self.fmt = 0x112222

    def decode(self, fd) -> None:
        super().decode(fd)
        self.prefix = "SGET"
        self.suffix = "???"
        (self.vA, self.vB) = self.decode_args(fd)

    def execute(self, memory, v):
        v[self.vA] = memory.static_fields.get(self.vB, None)
        if self.opcode == 0x61:
            # wide cornercase
            try:
                v[self.vA + 1] = v[self.vA] & 0xFFFFFFFF
                v[self.vA] = v[self.vA] >> 32
            except TypeError:
                # reset the registers in case of junk
                v[self.vA + 1] = 0
                v[self.vA] = 0

        return super().execute(memory, v)


class SPut(Instruction):

    def print_instruction(self):
        log.debug("%s-%s v%s @v%s" % (self.prefix, self.suffix, self.vA, self.vB))

    def fetch(self) -> None:
        self.fmt = 0x112222

    def decode(self, fd) -> None:
        super().decode(fd)
        self.prefix = "SPUT"
        self.suffix = "???"
        (self.vA, self.vB) = self.decode_args(fd)

    def execute(self, memory, v):
        memory.static_fields[self.vB] = v[self.vA]

        # wide cornercase
        if self.opcode == 0x68:
            try:
                memory.static_fields[self.vB] <<= 32
                memory.static_fields[self.vB] += v[self.vA + 1]
            except TypeError:
                # reset the static field in case of junk left inside the register
                memory.static_fields[self.vB] = 0

        return super().execute(memory, v)


INVOKE_LOOKUP = {0x6e: "VIRTUAL", 0x6f: "SUPER", 0x70: "DIRECT", 0x71: "STATIC", 0x72: "INTERFACE"}


class InvokeKind(Instruction):

    def fetch(self) -> None:
        self.prefix = "INVOKE"
        self.fmt = 0x1233334567
        self.suffix = INVOKE_LOOKUP[self.opcode]

        if not (0x6e <= self.opcode <= 0x72):
            raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd) -> None:
        super().decode(fd)
        (self.vE, self.vX, self.vZ, self.vA, self.vB, self.vC, self.vD) = self.decode_args(fd)

    def print_instruction(self):
        args = [self.vA, self.vB, self.vC, self.vD, self.vE]
        log.debug(("%s-%s args_nr:%s method@%s " + ("v%s") * self.vX) %
                  ((self.prefix, self.suffix, self.vX, self.vZ) + tuple(args[0: self.vX])))

    def execute(self, memory, v):
        args_arr = [self.vA, self.vB, self.vC, self.vD, self.vE]
        # don't send more arguments than we've got
        # TODO: do another bugfixing round

        # TODO: FIX NEEDS_MORE_WORK
        needs_more_work = True

        # try:
        #     needs_more_work = frame.translate_api(self.vZ, args_arr[:self.vX])
        # except Exception as ex:
        #     needs_more_work = False
        #     log.error("Translation API error when calling: %s\n" % traceback.format_exc())
        #     log.error("Registers content: ")
        #     frame.print_registers()

        params = [self.vA, self.vB, self.vC, self.vD, self.vE]
        params = params[0:self.vX]
        if needs_more_work:
            return InstructionReturn(self.vZ, True, params)
        else:
            return super().execute(memory, v)


class InvokeKindRange(Instruction):

    def fetch(self) -> None:
        self.prefix = "INVOKE-RANGE"
        self.fmt = 0x1122223333
        self.suffix = INVOKE_LOOKUP[self.opcode - 0x6]

    def decode(self, fd) -> None:
        super().decode(fd)
        (self.vA, self.vB, self.vC) = self.decode_args(fd)

    def print_instruction(self):
        log.debug("%s-%s args_nr:%s method@%s v%s" % (self.prefix, self.suffix, self.vA, self.vB, self.vC))

    def execute(self, memory, v):
        params = [x for x in range(self.vC, self.vC + self.vA)]

        # TODO: FIX NEEDS_MORE_WORK
        # needs_more_work = translate_api(self.vB, params)
        needs_more_work = True
        if needs_more_work:
            return InstructionReturn(self.vB, True, params)
        else:
            return super().execute(memory, v)


class UnOp(Instruction):
    def fetch(self) -> None:
        self.fmt = 0x12

    def decode(self, fd) -> None:
        super().decode(fd)
        (self.vA, self.vB) = self.decode_args(fd)

        match self.opcode:
            case 0x7b:
                self.prefix = "NEG-INT"
            case 0x7c:
                self.prefix = "NOT-INT"
            case 0x7d:
                self.prefix = "NEG-LONG"
            case 0x7e:
                self.prefix = "NOT-LONG"
            case 0x7f:
                self.prefix = "NEG-FLOAT"
            case 0x80:
                self.prefix = "NEG-DOUBLE"
            case 0x81:
                self.prefix = "INT-TO-LONG"
            case 0x82:
                self.prefix = "INT-TO-FLOAT"
            case 0x83:
                self.prefix = "INT-TO-DOUBLE"
            case 0x84:
                self.prefix = "LONG-TO-INT"
            case 0x85:
                self.prefix = "LONG-TO-FLOAT"
            case 0x86:
                self.prefix = "LONG-TO-DOUBLE"
            case 0x87:
                self.prefix = "FLOAT-TO-INT"
            case 0x88:
                self.prefix = "FLOAT-TO-LONG"
            case 0x89:
                self.prefix = "FLOAT-TO-DOUBLE"
            case 0x8a:
                self.prefix = "DOUBLE-TO-INT"
            case 0x8b:
                self.prefix = "DOUBLE-TO-LONG"
            case 0x8c:
                self.prefix = "DOUBLE-TO-FLOAT"
            case 0x8d:
                self.prefix = "INT-TO-BYTE"
            case 0x8e:
                self.prefix = "INT-TO-CHAR"
            case 0x8f:
                self.prefix = "INT-TO-SHORT"

    def print_instruction(self):
        log.debug("%s v%s v%s" % (self.prefix, self.vA, self.vB))

    def execute(self, memory, v):
        match self.opcode:
            case 0x7b | 0x7f:
                try:
                    v[self.vA] = -v[self.vB]
                except TypeError:
                    # account for junk inside registers
                    v[self.vA] = 0
            case 0x7c | 0x7e:
                # TODO: check Android source code
                v[self.vA] = ~v[self.vB]
            case 0x7d | 0x80:
                tmp1 = -v[self.vB]
                tmp2 = -v[self.vB + 1]
                v[self.vA] = tmp1
                v[self.vA + 1] = tmp2
            case 0x82 | 0x86 | 0x87 | 0x8b:
                pass  # no need to trim/exted datatype
            case 0x81 | 0x83 | 0x88 | 0x89:
                tmp1 = 0x00000000
                tmp2 = v[self.vB]

                v[self.vA] = 0x00000000
                v[self.vA + 1] = tmp2
            case 0x84 | 0x85 | 0x8a | 0x8c:
                # get the least significat 32 bits and put them into the destination
                # this is dumb, why did I do this?
                v[self.vA] = (v[self.vB] << 32) + v[self.vB + 1] & 0xFFFFFFFF
                # pass
            case 0x8d:
                # assume bytes are identical to chars
                v[self.vA] = (v[self.vB] & 0xFF)  # - 0xFF - 1
                if v[self.vA] > 0x7F:
                    v[self.vA] = v[self.vA] - 0xFF - 1
            case 0x8e:
                v[self.vA] = (v[self.vB] & 0xFFFF)
            case 0x8f:
                v[self.vA] = (v[self.vB] & 0xFFFF)  # - 0xFFFF - 1
                if v[self.vA] > 0x7FFF:
                    v[self.vA] = v[self.vA] - 0xFFFF - 1

        return super().execute(memory, v)


class BinOp(Instruction):
    def fetch(self) -> None:
        self.fmt = 0x112233

        if not (0x90 <= self.opcode <= 0xaf):
            raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd) -> None:
        super().decode(fd)
        (self.vA, self.vB, self.vC) = self.decode_args(fd)

        # find out the operator type and the operand type
        # ------------OPERANDS-------------
        # 0 - int
        # 1 - long
        # 2 - float
        # 3 - double
        # ------------OPERATORS------------
        # 0 - add
        # 1 - sub
        # 2 - mul
        # 3 - div
        # 4 - rem
        # 5 - and
        # 6 - or
        # 7 - xor
        # 8 - shl
        # 9 - shr
        # a - ushr
        self.operand_type = (self.opcode - 0x90) // 11
        self.operator_type = (self.opcode - 0x90) % 11
        if self.operand_type == 2:  # float or double
            self.operand_type = (self.opcode - 0xa6) // 5 + 2
            self.operator_type = (self.opcode - 0xa6) % 5

        match self.operator_type:
            case 0x0:
                self.prefix = "ADD"
            case 0x1:
                self.prefix = "SUB"
            case 0x2:
                self.prefix = "MUL"
            case 0x3:
                self.prefix = "DIV"
            case 0x4:
                self.prefix = "REM"
            case 0x5:
                self.prefix = "AND"
            case 0x6:
                self.prefix = "OR"
            case 0x7:
                self.prefix = "XOR"
            case 0x8:
                self.prefix = "SHL"
            case 0x9:
                self.prefix = "SHR"
            case 0xa:
                self.prefix = "USHR"

        match self.operand_type:
            case 0x0:
                self.suffix = "INT"
            case 0x1:
                self.suffix = "LONG"
            case 0x2:
                self.suffix = "FLOAT"
            case 0x3:
                self.suffix = "DOUBLE"

    def print_instruction(self):
        log.debug("%s-%s v%s v%s v%s" % (self.prefix, self.suffix, self.vA, self.vB, self.vC))


    def execute(self, memory, v):
        # gonna do a hack for now and not process the operand type (and only do some caps on the output register)
        if self.operand_type != 0x1:
            b = v[self.vB]
            c = v[self.vC]
        elif self.operator_type not in [0x8, 0x9, 0xa]:
            b = (v[self.vB] << 32) + v[self.vB + 1]
            c = (v[self.vC] << 32) + v[self.vC + 1]
        else:  # CONSITENCY, BRUH!
            b = (v[self.vB] << 32) + v[self.vB + 1]
            c = v[self.vC]

        try:
            a = alu_op(self.operator_type, self.operand_type, b, c)
        except ZeroDivisionError:
            # account for junk left in registers
            a = 0

        if self.operand_type != 0x1:
            v[self.vA] = a
        else:
            v[self.vA] = a >> 32
            v[self.vA + 1] = a & 0xFFFFFFFF

        return super().execute(memory, v)


class BinOp2Addr(Instruction):
    def fetch(self) -> None:
        if not (0xb0 <= self.opcode <= 0xcf):
            raise OpCodeNotFoundError(self.opcode)

        self.fmt = 0x12

    def decode(self, fd) -> None:
        super().decode(fd)
        (self.vA, self.vB) = self.decode_args(fd)

        self.operand_type = (self.opcode - 0xb0) // 11
        self.operator_type = (self.opcode - 0xb0) % 11
        if self.operand_type == 2:  # float or double
            self.operand_type = (self.opcode - 0xc6) // 5 + 2
            self.operator_type = (self.opcode - 0xc6) % 5

        match self.operator_type:
            case 0x0:
                self.prefix = "ADD"
            case 0x1:
                self.prefix = "SUB"
            case 0x2:
                self.prefix = "MUL"
            case 0x3:
                self.prefix = "DIV"
            case 0x4:
                self.prefix = "REM"
            case 0x5:
                self.prefix = "AND"
            case 0x6:
                self.prefix = "OR"
            case 0x7:
                self.prefix = "XOR"
            case 0x8:
                self.prefix = "SHL"
            case 0x9:
                self.prefix = "SHR"
            case 0xa:
                self.prefix = "USHR"

        match self.operand_type:
            case 0x0:
                self.suffix = "INT"
            case 0x1:
                self.suffix = "LONG"
            case 0x2:
                self.suffix = "FLOAT"
            case 0x3:
                self.suffix = "DOUBLE"

    def print_instruction(self):
        log.debug("%s-%s/2ADDR v%s v%s" % (self.prefix, self.suffix, self.vA, self.vB))

    def execute(self, memory, v):
        # gonna do a hack for now and not process the operand type (and only do some caps on the output register)
        a: int = 0
        b: int = 0

        if self.operand_type != 0x1:
            a = v[self.vA]
            b = v[self.vB]
        elif self.operator_type not in [0x8, 0x9, 0xa]:
            a = (v[self.vA] << 32) + v[self.vA + 1]
            b = (v[self.vB] << 32) + v[self.vB + 1]
        else:  # CONSITENCY, BRUH!
            a = (v[self.vA] << 32) + v[self.vA + 1]
            b = v[self.vB]

        a = alu_op(self.operator_type, self.operand_type, a, b)

        if self.operand_type != 0x1:
            v[self.vA] = a
        else:
            v[self.vA] = a >> 32
            v[self.vA + 1] = a & 0xFFFFFFFF

        return super().execute(memory, v)


class BinOpLit(Instruction):

    def fetch(self) -> None:
        if 0xd0 <= self.opcode <= 0xd7:
            self.fmt = 0x12AAAA
        elif 0xd8 <= self.opcode <= 0xe2:
            self.fmt = 0x1122AA
        else:
            raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd) -> None:
        super().decode(fd)
        (self.vA, self.vB, self.vC) = self.decode_args(fd)

        if 0xd0 <= self.opcode <= 0xd7:
            self.suffix = "INT/LIT16"
            self.operator_type = self.opcode - 0xd0
        elif 0xd8 <= self.opcode <= 0xe2:
            self.suffix = "INT/LIT8"
            self.operator_type = self.opcode - 0xd8

        match self.operator_type:
            case 0x0:
                self.prefix = "ADD"
            case 0x1:
                self.prefix = "RSUB"
            case 0x2:
                self.prefix = "MUL"
            case 0x3:
                self.prefix = "DIV"
            case 0x4:
                self.prefix = "REM"
            case 0x5:
                self.prefix = "AND"
            case 0x6:
                self.prefix = "OR"
            case 0x7:
                self.prefix = "XOR"
            case 0x8:
                self.prefix = "SHL"
            case 0x9:
                self.prefix = "SHR"
            case 0xa:
                self.prefix = "USHR"

    def print_instruction(self):
        log.debug("%s-%s v%s v%s %s" % (self.prefix, self.suffix, self.vA, self.vB, self.vC))

    def execute(self, memory, v):
        # gonna do a hack for now and not process the operand type (and only do some caps on the output register)
        # handle reverse substraction cornercase 8-|
        if self.operator_type != 0x1:
            b = v[self.vB]
            c = self.vC
        else:
            b = self.vC
            c = v[self.vB]

        a = alu_op(self.operator_type, self.operand_type, b, c)

        v[self.vA] = a
        return super().execute(memory, v)
