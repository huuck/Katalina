#!/usr/bin/env python
import argparse
import logging
from types import FrameType

from vm import VM
from typing import Optional, List
from utils import LogHandler

import signal
from contextlib import contextmanager


class TimeoutException(Exception):
    pass


# logging.root.setLevel(logging.DEBUG)

handler = LogHandler()
log = logging.getLogger("Recaff")
log.setLevel(logging.INFO)
log.addHandler(handler)


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
        if method.method_name == method_name and vm.method_metadata.get(index, None):
            log.debug(method.class_name + "->" + method_name)
            try:
                with time_limit(20):
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
    """
    Call a method of a class based on its fully-qualified class name (FQCN). i.E.'Lcom/njzbfugl/lzzhmzl/App;->$(III)'
    """
    for index, method in enumerate(vm.dex.method_ids):
        if f"{method.class_name}->{method.method_name}" not in full_name:
            continue  # Fast fail

        if not vm.method_metadata.get(index, None):
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
    """
    Returns the method object
    """
    method_offsets = []
    method_names = []

    for index, method in enumerate(vm.dex.method_ids):
        ret_type = method.proto_id.return_type
        params_types = ";".join([item.value for item in method.proto_id.params_types.list]) \
            if method.proto_id.params_types else ""

        m_signature = str(params_types) + "->" + ret_type
        if m_signature == signature:
            try:
                method_offsets.append(vm.method_metadata[index].code_off.value)
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
    """
    Execute all functions in a specific Java Namespace. i.E. 'com.MyApp.Strings.*'
    """
    for index, method in enumerate(vm.dex.method_ids):
        if package not in method.class_name:
            continue
        if not vm.method_metadata.get(index, None):
            log.warning(
                f"Method {method.class_name}.{method.method_name}.{method.proto_id} had no metadata generated")

        # try:
        #    args_type = "".join([p.value for p in method.proto_id.params_types.list])
        # except AttributeError as ex:
        #    log.error(f"failed to parse argument types from {method.proto_id.params_types.list}")
        #     args_type = ""

        try:
            with time_limit(20):
                vm.call_method_by_id(index, [])
        except Exception as ex:
            log.debug(str(ex))


def call_entrypoints(vm: VM) -> None:
    """
    Executes all Entrypoints into an android application.  !!!  List is most likely incomplete.
    TODO: At this point it might even make sense to call every function named `on[A-Z].*`
    """
    # Entrypoints for Activities
    call_methods_by_name(vm, "onCreate", [None], {"do_branching": False})
    call_methods_by_name(vm, "onStart", [None], {"do_branching": False})
    call_methods_by_name(vm, "onRestart", [None], {"do_branching": False})
    call_methods_by_name(vm, "onResume", [None], {"do_branching": False})
    call_methods_by_name(vm, "onPause", [None], {"do_branching": False})
    call_methods_by_name(vm, "onStop", [None], {"do_branching": False})
    call_methods_by_name(vm, "onDestroy", [None], {"do_branching": False})
    call_methods_by_name(vm, "onRestoreInstanceState", [None], {"do_branching": False})

    # Entrypoints for Services
    call_methods_by_name(vm, "onServiceConnected", [None], {"do_branching": False})
    call_methods_by_name(vm, "onStartCommand", [None], {"do_branching": False})
    call_methods_by_name(vm, "onBind", [None], {"do_branching": False})
    call_methods_by_name(vm, "onAccessibilityEvent", [None], {"do_branching": False})
    call_methods_by_name(vm, "onCreateInputMethod", [None], {"do_branching": False})
    call_methods_by_name(vm, "onGesture", [None], {"do_branching": False})
    call_methods_by_name(vm, "onInterrupt", [None], {"do_branching": False})
    call_methods_by_name(vm, "onSystemActionsChanged", [None], {"do_branching": False})

    # Entrypoints for Broadcast Receivers
    call_methods_by_name(vm, "onReceive", [None], {"do_branching": False})

    # Entrypoints for threads and abstractions
    call_methods_by_name(vm, "returnResult", [None], {"do_branching": False})
    call_methods_by_name(vm, "onStartJob", [None], {"do_branching": False})  # JobService
    call_methods_by_name(vm, "onStopJob", [None], {"do_branching": False})  # JobService

    # Entrypoints for dynamic dex loading
    call_methods_by_name(vm, "attachBaseContext", [None], {"do_branching": False})

    # Entrypoints for UI events
    call_methods_by_name(vm, "onActionItemClicked", [None], {"do_branching": False})
    call_methods_by_name(vm, "onCheckboxClicked", [None], {"do_branching": False})
    call_methods_by_name(vm, "onCheckedChanged", [None], {"do_branching": False})
    call_methods_by_name(vm, "onClick", [None], {"do_branching": False})
    call_methods_by_name(vm, "onCreateActionMode", [None], {"do_branching": False})
    call_methods_by_name(vm, "onCreateContextMenu", [None], {"do_branching": False})
    call_methods_by_name(vm, "onCreateDialog", [None], {"do_branching": False})
    call_methods_by_name(vm, "onCreateOptionsMenu", [None], {"do_branching": False})
    call_methods_by_name(vm, "onContextItemSelected", [None], {"do_branching": False})
    call_methods_by_name(vm, "onDestroyActionMode", [None], {"do_branching": False})
    call_methods_by_name(vm, "onItemCheckedStateChanged", [None], {"do_branching": False})
    call_methods_by_name(vm, "onLongClick", [None], {"do_branching": False})
    call_methods_by_name(vm, "onMenuItemClick", [None], {"do_branching": False})
    call_methods_by_name(vm, "onOptionsItemSelected", [None], {"do_branching": False})
    call_methods_by_name(vm, "onPrepareActionMode", [None], {"do_branching": False})
    call_methods_by_name(vm, "onRadioButtonClicked", [None], {"do_branching": False})
    call_methods_by_name(vm, "onTimeSet", [None], {"do_branching": False})
    
    # Entrypoints for network related stuff
    call_methods_by_name(vm, "loadUrl", [None], {"do_branching": False})


def main():
    vm_instance = VM("assets/stringfog.dex")
    call_entrypoints(vm_instance)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-v", "--verbose", help="Enable verbose logging", action="store_true"
    )
    parser.add_argument(
        "-e", "--entrypoints", help="Execute Android entry points", action="store_true"
    )
    parser.add_argument(
        "-x", "--execute",
        help="Execute the given function with parameters. Example:\
        python3 main.py classes.dex -x 'Lcom/njzbfugl/lzzhmzl/App;->$(III)' '67,84,1391'",
        nargs=2,
    )
    parser.add_argument(
        "-j", "--json", help="Output generated Strings as JSON object", action="store_true"
    )

    parser.add_argument("DEX_FILE", nargs='?')
    args = parser.parse_args()
    if not args.DEX_FILE:
        parser.print_help()
        return 0

    dex_file_path = args.DEX_FILE
    vm_instance = VM(dex_file_path)
    if args.execute:
        method_name = args.execute[0]
        parameter_string = args.execute[1]
        parameters = parameter_string.split(",")
        parameters = list(map(lambda p: int(p) if p.isdecimal() else p, parameters))  # Cast to int type if applicable
        call_method_by_fqcn(vm_instance, method_name, parameters)
    if args.entrypoints:
        call_entrypoints(vm_instance)


if __name__ == '__main__':
    main()