#!/usr/bin/env python
import argparse
import logging
from types import FrameType

from vm import VM
from typing import Optional, List
from utils import LogHandler

import signal
from contextlib import contextmanager

import itertools


handler = LogHandler()
log = logging.getLogger("main")
log.setLevel(logging.INFO)
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


def call_methods_by_name(vm: VM, method_name: str, method_args: Optional[List],
                         execution_flags: Optional[dict]) -> None:
    for index, method in enumerate(vm.dex.method_ids):
        if method.method_name == method_name and vm.method_data.get(index, None):
            log.debug(method.class_name + "->" + method_name)
            try:
                with time_limit(5):
                    log.debug(f"Calling {method_name}")
                    vm.call_stack = []
                    vm.call_method_by_id(index, method_args, execution_flags)
            except TimeoutException:
                vm.print_call_stack()
                log.warning(f"Method {method_name} timed out...")
            except Exception as ex:
                log.error(f"Error running {method_name}: {ex}")
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

def main():
    # vm_instance = VM("assets/draw.dex")
    # call_entrypoints(vm_instance)
    # call_method_by_fqcn(vm_instance, "Ln/a/n/a;->a", [[74, -54, 109, -126, 90, -64, 118, -60, 112, -54], [25, -81]])
    # call_methods_by_name(vm_instance, "name", [None], {"do_branching": False})
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-v", "--verbose", help="Enable verbose logging", action="store_true"
    )
    parser.add_argument(
        "-xe", "--entrypoints", help="Execute Android entry points", action="store_true"
    )

    parser.add_argument(
        "-xm", "--match", help="Execute function that matches specified name",
        nargs=1
    )

    parser.add_argument(
        "-x", "--execute",
        help="Execute the given function with parameters specified as a fully qualified function name. Example:\
        python3 main.py classes.dex -x 'Lcom/njzbfugl/lzzhmzl/App;->$(III)' '67,84,1391'",
        nargs=2,
    )

    parser.add_argument(
        "-dl", "--denylist", help="Skips the execution of methods whose fully qualified name contains words from the specified list. Example: \
         python3 main.py --execute --denylist androidx,unity",
        nargs=1,
        required=False
    )

    parser.add_argument(
        "-j", "--json", help="Output generated Strings as JSON object", action="store_true"
    )

    parser.add_argument("DEX_FILE", nargs='?')
    args = parser.parse_args()
    if not args.DEX_FILE:
        parser.print_help()
        return 0

    deny_list = []
    if args.denylist:
        deny_list = args.denylist[0].split(',')

    dex_file_path = args.DEX_FILE
    vm_instance = VM(dex_file_path, deny_list)

    if args.execute:
        method_name = args.execute[0]
        parameter_string = args.execute[1]
        parameters = parameter_string.split(",")
        parameters = list(map(lambda p: int(p) if p.isdecimal() else p, parameters))  # Cast to int type if applicable
        call_method_by_fqcn(vm_instance, method_name, parameters)
    if args.entrypoints:
        call_entrypoints(vm_instance)
    if args.match:
        match_string = args.match[0]
        call_methods_by_name(vm_instance, match_string, [None], {"do_branching": False})


if __name__ == '__main__':
    main()
