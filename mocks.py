import logging

from utils import *
from base64 import b64decode, urlsafe_b64decode
from helpers import string_hash_code

handler = LogHandler()
log = logging.getLogger(__name__)
log.addHandler(handler)
log.setLevel(logging.INFO)

# stores state data for in between calls
state_data = {}

def dump_string(string: str, vm):
    log.info(string, extra={"type": LOG_TYPE_STRING, "fqfn": vm.get_fqfn(vm.call_stack[0])})


def Landroid_util_Base64_decode(params: list, vm, v: list):
    # add missing padding because python has very strong opinions about this
    if type(v[params[0]]) is list:
        v[params[0]] += [61] * (-len(v[params[0]]) % 4)
    else:
        v[params[0]] += '=' * (-len(v[params[0]]) % 4)
    # also sanitize the input by turning everything to bytes
    try:
        if len(params) == 1 or v[params[1]] == 0:
            try:
                vm.memory.last_return = list(b64decode(bytes(v[params[0]])))
            except:
                # maybe switch this around?
                vm.memory.last_return = list(b64decode(v[params[0]]))
        else:
            # check for URL safe base64 decode (that's how people usually use the flag)
            vm.memory.last_return = list(urlsafe_b64decode(bytes(v[params[0]])))
    except:
        # pokemoning the exception for the fallback for weird string formats
        vm.memory.last_return = list(b64decode("".join([chr(x) for x in v[params[0]]])))


def Landroid_view_TextUtils_isEmpty(params: list, vm, v: list):
    try:
        vm.memory.last_return = v[params[0]] is None or len(v[params[0]]) == 0
    except Exception:
        vm.memory.last_return = 0

def Landroid_text_TextUtils_isEmpty(params: list, vm, v: list):
    try:
        vm.memory.last_return = v[params[0]] is None or len(v[params[0]]) == 0
    except Exception:
        vm.memory.last_return = 0

def Ljava_io_ByteArrayOutputStream_0init0(params: list, vm, v: list):
    v[params[0]] = []


def Ljava_io_ByteArrayOutputStream_write(params: list, vm, v: list):
    v[params[0]].append(v[params[1]])


def Ljava_io_ByteArrayOutputStream_toByteArray(params: list, vm, v: list):
    vm.memory.last_return = v[params[0]]


def Ljava_lang_Object_hashCode(params: list, vm, v: list):
    vm.memory.last_return = string_hash_code(v[params[0]].decode("utf-8"))

def Ljava_lang_String_hashCode(params: list, vm, v: list):
    
    h = 0
    for c in v[params[0]]:
        h = int((((31 * h + ord(c)) ^ 0x80000000) & 0xFFFFFFFF) - 0x80000000)
    vm.memory.last_return = h


def Ljava_lang_String_0init0(params: list, vm, v: list):        
        # print(v[params[0]])
        # print(v[params[1]])
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
        # print(v[params[0]])
        dump_string(f"{v[params[0]]}", vm);


def Ljava_lang_String_charAt(params: list, vm, v: list):
    try:
        vm.memory.last_return = ord(v[params[0]].decode("utf-8", "surrogatepass")[v[params[1]]])
    except AttributeError as ae:
        try:
            vm.memory.last_return = ord(v[params[0]][v[params[1]]])
        except TypeError as te:
            vm.memory.last_return = v[params[0]][v[params[1]]]


def Ljava_lang_String_split(params: list, vm, v: list):
    vm.memory.last_return = str(v[params[0]]).split(str(v[params[1]]))


def Ljava_lang_String_equals(params: list, vm, v: list):
    vm.memory.last_return = v[params[0]] == v[params[1]]


def Ljava_lang_String_length(params: list, vm, v: list):
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


def Ljava_lang_String_indexOf(params: list, vm, v: list):
    # TODO: account for char substring
    try:
        vm.memory.last_return = v[params[0]].find(chr(v[params[1]]))
    except TypeError as te:
        # sometimes we get substrings, sometimes we get char codes
        vm.memory.last_return = str(v[params[0]]).find(str(v[params[1]]))
    except Exception as ex:
        # TODO: remove catch all
        vm.memory.last_return = 0


def Ljava_lang_String_valueOf(params: list, vm, v: list):
    try:
        vm.memory.last_return = chr(v[params[0]])
    except:
        vm.memory.last_return = bytes(bytearray(v[params[0]][v[params[1]]:v[params[1]]+v[params[2]]])).decode('ascii')
        dump_string(vm.memory.last_return, vm)

def Ljava_lang_Integer_valueOf(params: list, vm, v: list):
    vm.memory.last_return = int(v[params[0]])

def Ljava_lang_Integer_intValue(params: list, vm, v: list):
    vm.memory.last_return = int(v[params[0]])



def Ljava_lang_String_toLowerCase(params: list, vm, v: list):
    vm.memory.last_return = v[params[0]].lower()


def Ljava_lang_String_getBytes(params: list, vm, v: list):
    # TODO: standardize string passing across methods
    try:
        vm.memory.last_return = list(v[params[0]].encode("utf-8"))
    except:
        vm.memory.last_return = list(v[params[0]])

def Ljava_lang_String_toCharArray(params: list, vm, v:list):
    temp = []
    for c in v[params[0]]:
        if type(c) is str:
            temp.append(ord(c))
        else:
            temp.append(c)
    
    # print(temp)
    # TMP = []
    # for i in range(0, len(old), 2):
    #     TMP.append(old[i] | (old[i+1] << 8))
    # print(TMP)
    vm.memory.last_return = temp

def Ljava_lang_StringBuilder_0init0(params: list, vm, v: list):
    if len(params) > 1:
        if isinstance(v[params[1]], list):
            v[params[0]] = ''.join(chr(i) for i in v[params[1]])
        if isinstance(v[params[1]], str):
            v[params[0]] = v[params[1]]
    else:
        v[params[0]] = ''

    dump_string(f"{v[params[0]]}", vm)


def Ljava_lang_StringBuilder_append(params: list, vm, v: list):
    # TODO: maybe find a more elegant solution
    try:
        v[params[0]] = str(v[params[0]]) + chr(v[params[1]])
    except TypeError as te:
        try:
            v[params[0]] = str(v[params[0]]) + v[params[1]].decode("utf-8")
        except AttributeError as ae:
            v[params[0]] = str(v[params[0]]) + str(v[params[1]])
    vm.memory.last_return = v[params[0]]


def Ljava_lang_StringBuilder_length(params: list, vm, v: list):
    try:
        vm.memory.last_return = len(v[params[0]])
    except Exception:
        # TODO: remove catch all
        vm.memory.last_return = 0

def Ljava_lang_StringBuilder_toString(params: list, vm, v: list):
    # print(v[params[0]])
    vm.memory.last_return = v[params[0]]
    dump_string(f"{v[params[0]]}", vm)
    log.info(f"String created: {v[params[0]]}")


def Ljava_lang_StringBuffer_0init0(params: list, vm, v: list):
    if isinstance(v[params[1]], list):
        v[params[0]] = ''.join(chr(i) for i in v[params[1]])
    if isinstance(v[params[1]], str):
        v[params[0]] = v[params[1]]

    dump_string(f"{v[params[0]]}", vm);

def Ljava_lang_StringBuffer_toString(params: list, vm, v: list):
    vm.memory.last_return = v[params[0]]


def Ljava_util_Iterator_hasNext(params: list, vm, v: list):
    vm.memory.last_return = False


def Ljava_util_ArrayList_0init0(params: list, vm, v: list):
    v[params[0]] = []


def Ljava_util_ArrayList_size(params: list, vm, v: list):
    vm.memory.last_return = len(v[params[0]])


def Ljava_util_ArrayList_add(params: list, vm, v: list):
    # hack to quickly whip up a list
    if not v[params[0]]:
        v[params[0]] = []
    v[params[0]].append(v[params[1]])


def Ljava_util_ArrayList_get(params: list, vm, v: list):
    vm.memory.last_return = v[params[0]][v[params[1]]]


def Ljava_util_List_0init0(params: list, vm, v: list):
    v[params[0]] = []


def Ljava_util_List_size(params: list, vm, v: list):
    if isinstance(v[params[0]], list):
        vm.memory.last_return = len(v[params[0]])
    else:
        vm.memory.last_return = 0


def Ljavax_crypto_spec_SecretKeySpec_0init0(params: list, vm, v: list):
    state_data['aes_key'] = v[params[1]]

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
def Ljavax_crypto_Cipher_doFinal(params: list, vm, v:list):
    # TODO: CLEANUP + CBC
    key = bytearray(state_data['aes_key'])
    cipher_text = bytearray(v[params[1]])
    iv = b'\00'*16
    # most common two modes are CBC and ECB try one and then the other
    # won't bother with IVs for now
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        original_data = unpad(cipher.decrypt(cipher_text), AES.block_size)
    # TODO: POKEMON!
    except:
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        original_data = unpad(cipher.decrypt(cipher_text), AES.block_size)

    dump_string(f"String decrypted: {original_data.decode('utf-8')} with key {key.decode('utf-8')}", vm)
    vm.memory.last_return = original_data


def Ljava_lang_System_arraycopy(params: list, vm, v:list):
    v[params[2]][v[params[3]]:v[params[1]]+v[params[4]]] = v[params[0]][v[params[1]]:v[params[1]]+v[params[4]]]


def try_to_mock_method(method_idx: int, params: list, vm, v) -> bool:
    class_name: str = vm.dex.method_ids[method_idx].class_name
    method_name: str = vm.dex.method_ids[method_idx].method_name
    log.debug("Translating method: %s->%s with %s" % (
        class_name, method_name, [str(v[param])[0:8] for param in params]))

    fqcn = class_name.replace('/', '_').replace(';', '') + '_' + method_name.replace('<', '0').replace('>', '0')
    

    fp = globals().get(fqcn, None)

    if fp:
        try:
            # print(fp)
            # print("mock before", params, v, params[1], len(v))
            fp(params, vm, v)
        except Exception as ex:
            log.error("Could not execute mock for %s->%s(%s): %s" % (class_name, method_name, [str(v[param])[0:8] for param in params], ex))
        return False
    elif class_name == "Landroid/view/Display;":
        vm.memory.last_return = 0
        return False
    else:
        if any([x in method_name for x in ["Int", "Long", "Float"]]) and "get" in method_name:
            vm.memory.last_return = 0
            return False
        if "String" in method_name and "get" in method_name and len(method_name) > 9:
            vm.memory.last_return = "None"
            return False
        if "Array" in method_name and "get" in method_name:
            vm.memory.last_return = []
    # print("????????????????????")
    return True

def Ljava_lang_Class_forName(params: list, vm, v:list):
    vm.memory.last_return = v[params[0]]
    
def Ljava_lang_Class_getMethod(params: list, vm, v:list):
    vm.memory.last_return = [v[params[0]], v[params[1]]]

def Ljava_lang_StackTraceElement_getClassName(params: list, vm, v:list):
    vm.memory.last_return = v[params[0]]["class_name"]

def Ljava_lang_Thread_currentThread(params: list, vm, v:list):
    vm.memory.last_return = "CURRENT_THREAD"

def Ljava_lang_Thread_getStackTrace(params: list, vm, v:list):
    if v[params[0]] == "CURRENT_THREAD":
        st = [{"class_name": "java.lang.Thread", "method_name": "getStackTrace"}]
        for m_id in vm.call_stack[::-1]:
            st.append({"class_name": vm.dex.method_ids[m_id].class_name[1:-1].replace("/","."), "method_name": vm.dex.method_ids[m_id].method_name})
    vm.memory.last_return = st

def Ljava_lang_reflect_Method_invoke(params: list, vm, v:list):
    try:
        t_class_name = v[params[0]][0].replace('.', '/')
    except:
        t_class_name = "None"
        log.error("Error solving reflection! Register state: " + str(v))
    t_method_name = v[params[0]][1]
    full_name = f"L{t_class_name};->{t_method_name}"
    for index, method in enumerate(vm.dex.method_ids):
        if f"{method.class_name}->{method.method_name}" not in full_name:
            continue

        class_name: str = vm.dex.method_ids[index].class_name
        method_name: str = vm.dex.method_ids[index].method_name

        log.debug("Invoke Translating method: %s->%s with %s" % (
            class_name, method_name, [str(v[param]) for param in params]))

        fqcn = class_name.replace('/', '_').replace(';', '') + '_' + method_name.replace('<', '0').replace('>', '0')

        fp = globals().get(fqcn, None)

        if fp:
            try:
                fp(params[1:], vm, v)
            except Exception as ex:
                log.error("Could not execute mock for %s->%s(%s): %s" % (class_name, method_name, [str(v[param])[0:8] for param in params], ex))
            return False
        elif class_name == "Landroid/view/Display;":
            vm.memory.last_return = 0
            return False
        else:
            if any([x in method_name for x in ["Int", "Long", "Float"]]) and "get" in method_name:
                vm.memory.last_return = 0
                return False
            if "String" in method_name and "get" in method_name and len(method_name) > 9:
                vm.memory.last_return = "None"
                return False
            if "Array" in method_name and "get" in method_name:
                vm.memory.last_return = []

    class_name = v[params[0]][0]
    method_name = v[params[0]][1]
    try:
        fqcn = "L"+class_name.replace('.', '_').replace(';', '') + '_' + method_name.replace('<', '0').replace('>', '0')
    except:
        fqcn = "None"
        log.error("Error solving reflection! Register state:" + str(v))
    fp = globals().get(fqcn, None)
    if fp:
        fp(params[1:], vm, v)
    else:
        log.debug(f"Reflected method not found in mocks {full_name}")

def Ljava_lang_StackTraceElement_getMethodName(params: list, vm, v:list):
    vm.memory.last_return = v[params[0]]["method_name"]