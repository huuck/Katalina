#!/usr/bin/env python
import argparse
import logging
from types import FrameType

from vm import VM
from utils import LogHandler, JsonFormatter

from typing import Optional, List

import signal
from contextlib import contextmanager

import itertools
import pathlib

import re

handler = LogHandler()
log = logging.getLogger("main")
# log.setLevel(logging.INFO)
log.setLevel(logging.ERROR)
# logging.

log.addHandler(handler)


class TimeoutException(Exception):
    pass

@contextmanager
def time_limit(seconds: int):
    def signal_handler(_signalnum: int, _frame: Optional[FrameType]):
        raise TimeoutException("Timed out!")

    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)


def call_methods_by_name(vm: VM, name: str, method_args: Optional[List],
                         execution_flags: Optional[dict]) -> None:
    for index, method in enumerate(vm.dex.method_ids):
        if name in (method.class_name + method.method_name) and vm.method_data.get(index, None):
            try:
                with time_limit(5):
                    log.info(f"Calling {method.class_name}->{method.method_name}")
                    vm.call_stack = []
                    vm.call_method_by_id(index, method_args, execution_flags)
            except TimeoutException:
                vm.print_call_stack()
                log.warning(f"Method {method.class_name}->{method.method_name} timed out...")
            except Exception as ex:
                log.error(f"Error running {method.class_name}->{method.method_name}: {ex}")
                vm.print_call_stack()


def call_method_by_fqcn(vm: VM, full_name: str, method_args: Optional[list]) -> None:
    for index, method in enumerate(vm.dex.method_ids):
        if f"{method.class_name}->{method.method_name}" not in full_name:
            continue  # Fast fail

        if not vm.method_data.get(index, None):
            log.warning(f"Did not generate metadata for {full_name}")

        try:
            args_type = "".join([p.value for p in method.proto_id.params_types.list])
        except AttributeError:
            log.warning(f"Failed to parse arg types of \
                {method.class_name}->{method.method_name}")
            args_type = ""

        try:
            vm.call_method_by_id(index, method_args)
        except Exception as ex:
           log.error(str(ex))

def get_methods_by_signature(vm: VM, signature: str, params: Optional[list]) -> None:
    method_offsets = []
    method_names = []

    for index, method in enumerate(vm.dex.method_ids):
        ret_type = method.proto_id.return_type
        params_types = ";".join([item.value for item in method.proto_id.params_types.list]) \
            if method.proto_id.params_types else ""

        m_signature = str(params_types) + "->" + ret_type
        if m_signature == signature:
            try:
                method_offsets.append(vm.method_data[index].code_off.value)
                method_names.append(method.class_name + "->" + method.method_name)
            except KeyError:
                pass

    for index, method_offset in enumerate(method_offsets):
        log.debug(method_names[method_offsets.index(method_offset)])
        try:
            func = vm.get_method_at_offset(method_offset)
            func.execute(None, method.v)
        except Exception as ex:
            log.error(method_names[index] + ": ERROR " + str(ex))


def call_functions_in_package(vm: VM, package: str):
    for index, method in enumerate(vm.dex.method_ids):
        if package not in method.class_name:
            continue
        if not vm.method_data.get(index, None):
            log.warning(
                f"Method {method.class_name}.{method.method_name}.{method.proto_id} had no metadata generated")

        try:
            with time_limit(20):
                vm.call_method_by_id(index, [])
        except Exception as ex:
            log.debug(str(ex))


def call_entrypoints(vm: VM) -> None:
    activities = ["onCreate", "onStart", "onRestart", "onResume", "onPause", "onStop", "onDestroy", "onRestoreInstanceState"]
    services = ["onServiceConnected", "onStartCommand", "onBind", "onAccessibilityEvent", "onCreateInputMethod", "onGesture", "onInterrupt", "onSystemActionsChanged"]
    receivers = ["onReceive"]
    threads = ["returnResult", "onStartJob", "onStopJob"]
    loading = ["attachBaseContext"]
    ui = ["onActionItemClicked", "onCheckboxClicked", "onCheckedChanged", "onClick", "onCreateActionMode", "onCreateContextMenu", "onCreateDialog", "onCreateOptionsMenu", "onContextItemSelected", "onDestroyActionMode", "onItemCheckedStateChanged", "onLongClick", "onMenuItemClick", "onOptionsItemSelected", "onPrepareActionMode", "onRadioButtonClicked", "onTimeSet"]
    network = ["loadUrl"]

    entrypoints_to_call = itertools.chain(*[activities, services, receivers, threads, loading, ui, network])

    for entrypoint in entrypoints_to_call:
        call_methods_by_name(vm, entrypoint, [None], {"do_branching": False})


def find_method(vm_instance, class_name, method_name):
    for index, method in enumerate(vm_instance.dex.method_ids):
        # print(class_name, method.class_name)
        if method_name in method.method_name and class_name in method.class_name:
            return index
    return -1

def decrypt_string(vm_instance, enc_string, called_function_name, base_class_name="com/aug0825/fri0954/ProtectedAppStart1"):
    clinit_method_name = "Lcom/aug0825/fri0954/ProtectedAppStart1;-><clinit>"
    dec_method_name = "Lcom/aug0825/fri0954/ProtectedAppStart1;->returns"

    check = find_method(vm_instance, base_class_name, called_function_name)
    call_method_by_fqcn(vm_instance, clinit_method_name, [])

    vm_instance.call_stack = [check]
    call_method_by_fqcn(vm_instance, dec_method_name, [enc_string])
    return vm_instance.memory.last_return

def decrypt_test():
    deny_list = []
    dex_file_path = "./classes.dex"
    vm_instance = VM(dex_file_path, deny_list)

    base_class_name = "com/aug0825/fri0954/ProtectedAppStart1"
    called_function = "attachBaseContext"
    enc_string = b'\xef\xb7\x93\xea\x91\x8d\xe8\x96\xa6\xe4\xa5\xa3\xe5\xae\xab\xe3\xac\xb3\xe4\xa7\x91\xe4\x9a\xa6\xe8\xb0\xa3\xe1\xb0\xbc\xe0\xae\xa2\xe8\x81\x99'.decode()
    
    # called_function에는 return 을 호출한 함수의 이름을 넣어줘야함.
    dec = decrypt_string(vm_instance, enc_string, called_function, base_class_name=base_class_name)
    print("Decrypt result:", dec)
    
def unpack(target = "classes.dex", baksmali = "baksmali-2.5.2.jar"):
    import subprocess
    unpack_command = f"java -jar {baksmali} d {target}"
    output = subprocess.check_output(unpack_command.split())

def pack(target = "out", smali = "smali-2.5.2.jar"):
    import subprocess
    pack_command = f"java -jar {smali} a {target}"
    output = subprocess.check_output(pack_command.split())

def main():
    log.info("[+] Deobfuscator start!")
    unpack()
    log.info("[+] Unpack classes.dex -> convert smali")
    log.info("\tresult: ./out/")

    malware_base_class_name = "com/aug0825/fri0954/ProtectedAppStart1"
    patch_target = pathlib.Path("out/"+malware_base_class_name+'.smali')
    
    if not patch_target.exists():
        log.error("Class not found.")
        return
    
    raw_source_code = patch_target.read_text()

    def find_methods_in_code(code):
        pattern = r"\.method.*?\.end method"
        matches = re.findall(pattern, code, re.DOTALL)
        return matches
    
    def find_const_string_in_code(code):
        pattern = r'const-string.*?invoke-static.*?com/aug0825/fri0954/ProtectedAppStart1;->returns.*?move-result-object.*?\n'
        matches = re.findall(pattern, code, re.DOTALL)
        return matches
    
    def unicode_escape(s):
        return "".join(map(lambda c: rf"\u{ord(c):04x}", s))
    
    methods = find_methods_in_code(raw_source_code)
    functions = {}

    dex_file_path = "./classes.dex"
    vm_instance = VM(dex_file_path, [])
    base_class_name = "com/aug0825/fri0954/ProtectedAppStart1"

    
    for method in methods:
        function_name = method.split("\n")[0].split(" ")[-1].split("(")[0]
        method_number = find_method(vm_instance, base_class_name, function_name)
        functions[function_name] = {"number":method_number, "raw":method}


    count = 1

    for method_name, item in functions.items():
        obfuscate_string_targets = find_const_string_in_code(item["raw"])
        if not obfuscate_string_targets:
            continue


        for obstring in obfuscate_string_targets:
            codes = [x.replace("    ", "") for x in obstring.split("\n") if x]
            encrypt_string_raw = codes[0].split(",")[-1][1:]
            encrypt_string = eval(encrypt_string_raw)
            dec = decrypt_string(vm_instance, encrypt_string, method_name, base_class_name=base_class_name)
            raw_source_code = raw_source_code.replace(obstring, f"{codes[0].split(",")[0]}, \"{unicode_escape(dec)}\"\n")
            count += 1

    patch_target.write_text(raw_source_code)
    pack()

            
if __name__ == '__main__':
    main()
