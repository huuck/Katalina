import logging

from utils import LogHandler
from base64 import b64decode, urlsafe_b64decode
from helpers import string_hash_code

handler = LogHandler()
log = logging.getLogger(__name__)
log.addHandler(handler)
log.setLevel(logging.INFO)

def translate_api(method_idx: int, params: list, vm, v) -> bool:
    class_name: str = vm.dex.method_ids[method_idx].class_name
    method_name: str = vm.dex.method_ids[method_idx].method_name
    log.debug("Translating method: %s->%s with %s" % (
        class_name, method_name, [str(v[param])[0:8] for param in params]))

    if class_name == "Landroid/util/Base64;":
        if method_name == "decode":
            # add missing padding because python has very strong opinions about this
            v[params[0]] += [61] * (-len(v[params[0]]) % 4)
            # also sanitize the input by turning everything to bytes
            try:
                if len(params) == 1:
                    vm.memory.last_return = list(b64decode(bytes(v[params[0]])))
                else:
                    # check for URL safe base64 decode (that's how people usually use the flag)
                    vm.memory.last_return = list(urlsafe_b64decode(bytes(v[params[0]])))
            except:
                # pokemoning the exception for the fallback for weird string formats
                vm.memory.last_return = list(b64decode("".join([chr(x) for x in v[params[0]]])))
            return False
    elif class_name == "Landroid/view/Display;":
        vm.memory.last_return = 0
        return False
    elif class_name == "Landroid/text/TextUtils;":
        if method_name == "isEmpty":
            try:
                vm.memory.last_return = v[params[0]] is None or len(v[params[0]]) > 0
            except Exception:
                vm.memory.last_return = 0

            return False
    elif class_name == "Ljava/io/ByteArrayOutputStream;":
        if method_name == "<init>":
            v[params[0]] = []

            return False
        if method_name == "write":
            v[params[0]].append(v[params[1]])

            return False
        if method_name == "toByteArray":
            vm.memory.last_return = v[params[0]]

            return False
    elif class_name == "Ljava/lang/Object;":
        if method_name == "hashCode":
            vm.memory.last_return = string_hash_code(v[params[0]].decode("utf-8"))
            return False
    elif class_name == "Ljava/lang/String;":
        if method_name == "<init>":
            # TODO: fix hack
            try:
                v[params[0]] = bytearray(v[params[1]]).decode("utf-8")
            except ValueError as ve:
                # got negative bytes (which somehow work in java land), need to strip the sign
                ret = []
                for b in v[params[1]]:
                    if b < 0:
                        b += 0xFF + 1
                    ret.append(b)
                v[params[0]] = bytearray(ret).decode("utf-8", "ignore")

            log.info(f"String created: {v[params[0]]}")
            return False
        if method_name == "charAt":
            try:
                vm.memory.last_return = ord(v[params[0]].decode("utf-8", "surrogatepass")[v[params[1]]])
            except AttributeError as ae:
                try:
                    vm.memory.last_return = ord(v[params[0]][v[params[1]]])
                except TypeError as te:
                    vm.memory.last_return = v[params[0]][v[params[1]]]
            return False
        if method_name == "split":
            vm.memory.last_return = str(v[params[0]]).split(str(v[params[1]]))
            return False
        if method_name == "equals":
            vm.memory.last_return = v[params[0]] == v[params[1]]
            return False
        if method_name == "length":
            # TODO: remove catch all
            try:
                vm.memory.last_return = len(v[params[0]].decode("utf-8"))
            except AttributeError as ex:
                # TODO: remove catch all
                try:
                    vm.memory.last_return = len(v[params[0]])
                except:
                    vm.memory.last_return = 0
            except Exception as ex:
                vm.memory.last_return = 0
            return False
        if method_name == "substring":
            pass
            return False
        if method_name == "indexOf":
            # TODO: account for char substring
            try:
                vm.memory.last_return = v[params[0]].find(chr(v[params[1]]))
            except TypeError as te:
                # sometimes we get substrings, sometimes we get char codes
                vm.memory.last_return = str(v[params[0]]).find(str(v[params[1]]))
            except Exception as ex:
                # TODO: remove catch all
                vm.memory.last_return = 0
            return False
        if method_name == "valueOf":
            vm.memory.last_return = chr(v[params[0]])
            return False
        if method_name == "toLowerCase":
            vm.memory.last_return = v[params[0]].lower()
            return False
        if method_name == "getBytes":
            # TODO: standardize string passing across methods
            try:
                vm.memory.last_return = list(v[params[0]].encode("utf-8"))
            except:
                vm.memory.last_return = list(v[params[0]])
            return False

    elif class_name == "Ljava/lang/StringBuilder;":
        if method_name == "<init>":
            if len(params) > 1:
                if isinstance(v[params[1]], list):
                    v[params[0]] = ''.join(chr(i) for i in v[params[1]])
                if isinstance(v[params[1]], str):
                    v[params[0]] = v[params[1]]
            else:
                v[params[0]] = ''
            log.info(f"String created: {v[params[0]]}")
            return False
        if method_name == "append":
            # TODO: maybe find a more elegant solution
            try:
                v[params[0]] = str(v[params[0]]) + chr(v[params[1]])
            except TypeError as te:
                try:
                    v[params[0]] = str(v[params[0]]) + v[params[1]].decode("utf-8")
                except AttributeError as ae:
                    v[params[0]] = str(v[params[0]]) + str(v[params[1]])
            return False
        if method_name == "length":
            try:
                vm.memory.last_return = len(v[params[0]])
            except Exception:
                # TODO: remove catch all
                vm.memory.last_return = 0
            return False
        if method_name == "toString":
            vm.memory.last_return = v[params[0]]
            log.info(f"String created: {v[params[0]]}")
            return False
    elif class_name == "Ljava/lang/StringBuffer;":
        if method_name == "<init>":
            if isinstance(v[params[1]], list):
                v[params[0]] = ''.join(chr(i) for i in v[params[1]])
            if isinstance(v[params[1]], str):
                v[params[0]] = v[params[1]]
            log.info(f"String created: {v[params[0]]}")
            return False
        if method_name == "toString":
            vm.memory.last_return = v[params[0]]
            return False

    # disable interators for now, they are more trouble than it's worth
    elif class_name == "Ljava/util/Iterator;":
        if method_name == "hasNext":
            vm.memory.last_return = False
            return False
    elif class_name == "Ljava/util/ArrayList;":
        if method_name == "<init>":
            v[params[0]] = []
            return False

        if method_name == "size":
            vm.memory.last_return = len(v[params[0]])
            return False

        if method_name == "add":
            # hack to quickly whip up a list
            if not v[params[0]]:
                v[params[0]] = []
            v[params[0]].append(v[params[1]])
            return False

        if method_name == "get":
            vm.memory.last_return = v[params[0]][v[params[1]]]
            return False
    elif class_name == "Ljava/util/List;":
        if method_name == "size":
            if isinstance(v[params[0]], list):
                vm.memory.last_return = len(v[params[0]])
            else:
                vm.memory.last_return = 0
            return False
    elif class_name == "Ljavax/crypto/spec/SecretKeySpec;":
        if method_name == "<init>":
            return False
    else:
        if any([x in method_name for x in ["Int", "Long", "Float"]]) and "get" in method_name:
            vm.memory.last_return = 0
            return False
        if "String" in method_name and "get" in method_name and len(method_name) > 9:
            vm.memory.last_return = "None"
            return False
    return True