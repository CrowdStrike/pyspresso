#!/usr/bin/python
## @file        javajournal.py
#  @brief       Traces Java method calls.
#  @author      Jason Geffner
#  @copyright   CrowdStrike, Inc. 2016

import socket
import argparse
import thread
import re
import os
import subprocess

from pyspresso.debug_interface import DebugInterface
import pyspresso.event_modifiers as Modifier
import pyspresso.events as Event
from pyspresso.constants import *


class JavaJournal:
    """ Our Java method call tracer. """

    di = None
    """ A :any:`DebugInterface` object. """

    jar = ""

    classpath = ""

    class_ = ""

    # File path of the directory in which to store log files.
    _log_dir = ""

    # Don't begin logging until a method from this class is called. 
    _begin = ""

    # List of Java classes to include in logging.
    _include = []

    # List of Java classes to exclude from logging.
    _exclude = []

    # Mapping of thread numbers to log files.
    _log_files = {}


    def __init__(self, jar="", classpath="", class_="", log_dir="", begin="",
                 include=[], exclude=[]):
        if jar == "" and classpath == "":
            raise Exception("You must specify a jar or a classpath")

        if jar != "" and classpath != "":
            raise Exception("You must specify a jar OR a classpath, not both")

        if classpath != "" and class_ == "":
            raise Exception("If specifying a classpath, you must also " +
                            "specify a class")

        self.jar = jar
        self.classpath = classpath
        self.class_ = class_
        
        if not os.path.isdir(log_dir):
            raise Exception("Invalid log directory")
        self._log_dir = log_dir
        
        self._begin = begin

        if len(include) != 0 and len(exclude) != 0:
            raise Exception("Arguments exclude and include are mutually " +
                            "exclusive; you may use one or the other but not" +
                            "both")
        self._include = include
        self._exclude = exclude


    def set_break_on_method_entry_and_method_exit(self):
        """ Set "breakpoints" on Java method entries and exits. """

        for event_kind in (
            EventKind.METHOD_ENTRY, EventKind.METHOD_EXIT_WITH_RETURN_VALUE):
            if len(self._exclude) != 0:
                modifiers = []
                for pattern in self._exclude:
                    modifiers.append(Modifier.ClassExclude(pattern))
                self.di.event_request.set(event_kind, SuspendPolicy.ALL,
                                          modifiers)
            elif len(self._include) != 0:
                for pattern in self._include:
                    self.di.event_request.set(event_kind, SuspendPolicy.ALL,
                                              [Modifier.ClassMatch(pattern)])
            else:
                self.di.event_request.set(event_kind)


    #
    # Print and log to file the method entry/exit event.
    #
    def _log_method(self, entry, thread_id, frame_count, s):
        # Remove BEL and new-line characters for logging.
        s = s.replace("\x07", "").replace("\r", "").replace("\n", "")

        line = " "*(frame_count - 1) + ("" if entry else "^ ") + s
        print line
        if thread_id not in self._log_files:
            self._log_files[thread_id] = open(os.path.join(
                self._log_dir, "thread_" + str(thread_id) + ".txt"), "w")
        self._log_files[thread_id].write(line + "\n")

    #
    # Print and log to file the method entry event.
    #
    def log_method_entry(self, thread_id, frame_count, s):
        self._log_method(True, thread_id, frame_count, s)

    #
    # Print and log to file the method exit event.
    #
    def log_method_exit(self, thread_id, frame_count, s):
        self._log_method(False, thread_id, frame_count, s)

    #
    # Run the tracer.
    #
    def run(self):

        # Create a DebugInterface object.
        self.di = DebugInterface()

        #
        # Run the target in a new console. Usage of the "-Xdebug" argument will
        # cause the JVM to start in a suspended state.
        #

        args = ["java.exe", "-Xdebug", self.di.xdebug_arg]
        
        if self.jar != "":
            args += ["-jar", self.jar]
        else:
            args += ["-classpath", self.classpath, self.class_]
        
        subprocess.Popen(args, creationflags=subprocess.CREATE_NEW_CONSOLE)


        #
        # Attach our debugger to the process created with our DebugInterface's
        # xdebug_arg parameter above.
        #
        self.di.utils.attach()


        #
        # Set initial breakpoint(s).
        #

        if self._begin != "":
            # Set a breakpoint on the first method called in the _begin class.
            begin_request_id = self.di.event_request.set(
                EventKind.METHOD_ENTRY,
                SuspendPolicy.ALL,
                [Modifier.ClassMatch(self._begin)])
        else:
            # Set breakpoints on general method calls.
            self.set_break_on_method_entry_and_method_exit()


        #
        # Wait for and handle incoming debug events.
        #

        while True:
            # Get the next event packet from the event queue.
            event_packet = self.di.utils.wait_for_event()

            # Extract the suspend policy and all events from the packet.
            (events, suspend_policy) = self.di.utils.parse_events(
                event_packet.data)

            # Iterate over each event.
            for event in events:
                if isinstance(event, Event.MethodEntry):
                    if self._begin != "":
                        #
                        # Remove our initial "breakpoint" and start logging
                        # general method calls.
                        #
                        self.di.event_request.clear(
                            EventKind.METHOD_ENTRY,
                            begin_request_id)
                        self._begin = ""
                        self.set_break_on_method_entry_and_method_exit()

                    # Get the method's class's name.
                    class_name = re.search(
                        "L([^;]*)",
                        self.di.reference_type.get_signature(
                            event.location.class_id)).groups()[0]
                    class_name = class_name.replace("/", ".")

                    # Get the method's details.
                    method = self.di.utils.get_method(event.location.class_id,
                                                      event.location.method_id)

                    # Get the method's arguments.
                    arguments = self.di.utils.get_method_arguments(
                        event.thread,
                        self.di.utils.parse_jni(method.signature)[0],
                        method.mod_bits)

                    # Get the thread's frame count (call-stack depth).
                    frame_count = self.di.thread_reference.get_frame_count(
                        event.thread)

                    # Log the event.
                    self.log_method_entry(
                        event.thread,
                        frame_count,
                        class_name + "." + method.name +
                        "(" + ", ".join(arguments) + ")")
                
                elif isinstance(event, Event.MethodExitWithReturnValue):
                    # Get the thread's frame count (call-stack depth).
                    frame_count = self.di.thread_reference.get_frame_count(
                        event.thread)

                    # Log the event.
                    self.log_method_exit(
                        event.thread,
                        frame_count,
                        self.di.utils.get_string_representation_of_value(
                            event.value))

                elif isinstance(event, Event.VMDeath):
                    return

            # Resume the VM as necessary.
            if suspend_policy == SuspendPolicy.EVENT_THREAD:
                self.di.thread_reference.resume(event.thread)
            elif suspend_policy == SuspendPolicy.ALL:
                self.di.virtual_machine.resume()


if __name__ == "__main__":
    #
    # Parse command line arguments.
    #

    class ArgParser(argparse.ArgumentParser):
        def error(self, message):
            print "Error: " + message
            print
            print self.format_help().replace("usage:", "Usage:")
            self.exit(0)
    parser = ArgParser(
        add_help=False,
        description="Traces Java method calls using Java Debug Wire Protocol.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=r"""
You must specify either -jar or both -classpath and -class.

Examples:
    %(prog)s -jar C:\malware.jar
    %(prog)s -classpath C:\malware.jar -class evil.Destruction -begin evil.Destruction -include evil.*
    %(prog)s -exclude java.lang.String;java.lang.System;java.util.concurrent.*
""")

    args = parser.add_argument_group("Arguments")
    args.add_argument("-jar",       metavar="<path>",                   required=False, default="",          help="File path of the target JAR file")
    args.add_argument("-classpath", metavar="<path>",                   required=False, default="",          help="Class search path of directories and ZIP/JAR files")
    args.add_argument("-class",     metavar="<class>",                  required=False, default="",          help="Full name of class to execute")
    args.add_argument("-log",       metavar="<path>",                   required=False, default=os.getcwd(), help="Directory in which to store method trace log files (default is current directory)")
    args.add_argument("-begin",     metavar="<class>",                  required=False, default="",          help="Don't begin logging until a method from this class is called (default is to begin logging at JVM initialization)")
    args.add_argument("-exclude",   metavar="<path|class1;class2;...>", required=False, default="",          help="Java classes to exclude from logging (each entry can begin or end with \"*\"); can be the file path of a text file containing list of classes (one per line), or a semicolon-separated list of classes specified in the command line")
    args.add_argument("-include",   metavar="<path|class1;class2;...>", required=False, default="",          help="Java classes to include in logging (methods from all other classes will be excluded) (each entry can begin or end with \"*\"); can be the file path of a text file containing list of classes (one per line), or a semicolon-separated list of classes specified in the command line")    
    for arg in [action.dest for action in parser._actions]:
        globals()["arg_" + arg] = getattr(parser.parse_args(), arg)

    #
    # Validate command line arguments.
    #

    if arg_jar != "":
        if arg_classpath != "":
            parser.error("You must choose -jar OR -classpath, not both.")
    elif arg_classpath != "":
        if arg_class == "":
            parser.error("If specifying a -classpath, you must also specify" +
                         " the -class.")
    else:
        parser.error("You must specify a jar or a classpath.")

    if not os.path.isdir(arg_log):
        parser.error("You must specify a valid -log directory.")

    if arg_exclude != "" and arg_include != "":
        parser.error(
            "Arguments -exclude and -include are mutually exclusive; you may" +
            " use one or the other but not both.")
    
    for v in ("include", "exclude"):
        if globals()["arg_" + v] == "":
            globals()[v + "_classes"] = []
            continue
        if os.path.isfile(globals()["arg_" + v]):
            with open(globals()["arg_" + v]) as f:
                globals()[v + "_classes"] = f.read().splitlines()
            continue
        globals()[v + "_classes"] = globals()["arg_" + v].split(";")


    # Initialize and run the tracer.
    JavaJournal(arg_jar, arg_classpath, arg_class, arg_log, arg_begin,
                include_classes, exclude_classes).run()