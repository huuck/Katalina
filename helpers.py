def b2i(raw_bytes):
    return int.from_bytes(raw_bytes, "little")


def lsb(raw_bytes):
    return raw_bytes & 0x0F


def msb(raw_bytes):
    return raw_bytes >> 4


def nibble_at(raw_bytes, idx):
    return raw_bytes >> (4 * idx) & 0x0F


def twos_complement(number, num_bytes):
    if number >> (int(num_bytes * 8) - 1):
        return number - (1 << int(num_bytes * 8))
    else:
        return number


def i2b(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')


def logical_rshift(signed_integer, places, num_bits=32):
    unsigned_integer = signed_integer % (1 << num_bits)
    return unsigned_integer >> places

def logical_lshift(signed_integer, places, num_bits=32):
    unsigned_integer = signed_integer % (1 << num_bits)
    return unsigned_integer << places



def alu_op(op: int, operand: int, b: int, c: int):
    # TODO: disable this pokemon and start fixing bugs
    if b is None:
        b = 0
    if c is None:
        c = 0

    a: int

    if op == 0x6 and operand == 0x0:
        pass

    match op:
        case 0x0:
            a = b + c
        case 0x1:
            a = b - c
        case 0x2:
            a = b * c
        case 0x3:
            try:
                a = b // c
            except ZeroDivisionError:
                a = 0
        case 0x4:
            a = b % c
        case 0x5:
            a = b & c
        case 0x6:
            a = b | c
        case 0x7:
            a = b ^ c
        case 0x8: # <<
            c = c % 64
            BITBACK = 0xffffffffffffffff
            if operand != 0x1:
                c = c % 32
                BITBACK = 0xffffffff
            a = b << c # should keep sign
            a &= BITBACK
        case 0x9: # >>
            c = c % 64
            BITBACK = 0xffffffffffffffff
            if operand != 0x1:
                c = c % 32
                BITBACK = 0xffffffff
            a = b >> c  # should keep sign
            a &= BITBACK
        case 0xa: # >>>
            c = c % 64
            BITBACK = 0xffffffffffffffff
            if operand != 0x1:
                c = c % 32
                BITBACK = 0xffffffff
            if operand == 0x0:
                a = logical_rshift(b, c)
            else:
                a = logical_rshift(b, c, 64)
            a &= BITBACK
    match operand:
        case 0x0:
            a = int(a)
            a = (a & 0xFFFFFFFF)
            if a > 0x7FFFFFFF:
                a = a - 0xFFFFFFFF - 1
        case 0x1:
            a = int(a)
            a = a & 0xFFFFFFFFFFFFFFFF
            if a > 0x7FFFFFFFFFFFFFFF:
                a = a - 0xFFFFFFFFFFFFFFFF - 1
        case _:
            pass  # TODO: ¯\_(ツ)_/¯

    return a


# taken from https://www.w3schools.com/java/ref_string_hashcode.asp
def string_hash_code(string: str):
    h = 0
    for c in string:
        h = int((((31 * h + ord(c)) ^ 0x80000000) & 0xFFFFFFFF) - 0x80000000)
    return h