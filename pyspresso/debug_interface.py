#!/usr/bin/python
## @file        debug_interface.py
#  @brief       Debug interface on top of debug transport.
#  @author      Jason Geffner
#  @copyright   CrowdStrike, Inc. 2016

import os
import re
import socket
import uuid
import binascii
import hashlib
import thread
import threading
import struct
import inspect

import pyspresso.transport
import pyspresso.events as Event
import pyspresso.event_modifiers as Modifier
from pyspresso.constants import *


class _StructUnpacker:
    """ This class is used to unpack consecutive values (or sets of values)
    from a buffer.
    """

    def __init__(self, buffer):
        self.buffer = buffer
        self.i = 0
    def unpack_next(self, fmt):
        values = struct.unpack_from(fmt, self.buffer, self.i)
        self.i += struct.calcsize(fmt)
        return values


class DebugInterface:
    """ The :any:`DebugInterface` class provides a debug interface on top of
    :any:`DebugTransport`.
    """

    connected = False
    """ Boolean that specifies whether or not this :any:`DebugInterface` is
    connected to the target JVM.
    """

    transport = None
    """ A :any:`DebugTransport` object, initialized by the
    :any:`DebugInterface` constructor.
    """

    xdebug_arg = ""
    """ Command line switch to be used when running the Java target with the
    ``"-Xdebug"`` command line argument.
    """

    jni_tags = {}
    """ Mapping of JNI tags to names and sizes. """

    event_classes = {}
    """ Mapping of :any:`EventKind` to :py:class:`pyspresso.events.Event`
    class. """

    #
    # Variables for handling received packets.
    #
    _replies = {}
    _events = []
    _events_semaphore = threading.Semaphore(0)
    _waiting = {}


    class StructSizes:
        """ JDWP object sizes.
        
        See details at
        http://docs.oracle.com/javase/8/docs/technotes/guides/jpda/jdwp-spec.html
        """

        field_id = ""
        """ Size of a JDWP ``fieldID`` value in the form of a ``struct`` format
        character (``"B"``, ``"I"``, ``"Q"``, etc.).
        """

        method_id = ""
        """ Size of a JDWP ``methodID`` value in the form of a ``struct``
        format character (``"B"``, ``"I"``, ``"Q"``, etc.).
        """

        object_id = ""
        """ Size of a JDWP ``objectID`` value in the form of a ``struct``
        format character (``"B"``, ``"I"``, ``"Q"``, etc.).
        """

        reference_type_id = ""
        """ Size of a JDWP ``referenceTypeID`` value in the form of a
        ``struct`` format character (``"B"``, ``"I"``, ``"Q"``, etc.).
        """

        frame_id = ""
        """ Size of a JDWP ``frameID`` value in the form of a ``struct`` format
        character (``"B"``, ``"I"``, ``"Q"``, etc.).
        """

    _struct_sizes = StructSizes()
    """ JDWP object sizes as ``struct`` format characters. """
    
    _methods = {}
    """ Cache of method names, indexed by reference type ID and method ID. """


    class Utilities:
        """ Utility functions. """

        def __init__(self, di):
            self.di = di

        def attach(self):
            """ Attach to the Java process launced with this
            :any:`DebugInterface` object's :any:`xdebug_arg` command line
            switch.
            """

            def recv_packets(di):
                """ Continuously read packets from the debugee and insert them
                into the _replies dictionary or _events queue, as appropriate.
                """

                while True:
                    packet = di.transport.recv_packet()
                    if packet == None:
                        # Emit a synthetic VM_DEATH event.
                        di.connected = False
                        di._events += [pyspresso.transport.CommandPacket(
                            -1, Command.Event.Composite, struct.pack(
                                ">BIBi",
                                SuspendPolicy.ALL, 1, EventKind.VM_DEATH, -1),
                            0)]
                        return

                    #
                    # Handle the packet as a Reply Packet or a Command (Event)
                    # Packet.
                    #
                    if isinstance(packet, pyspresso.transport.ReplyPacket):
                        di._replies[packet.id] = packet
                        di._waiting[packet.id].set()
                    elif isinstance(packet, pyspresso.transport.CommandPacket):
                        di._events += [packet]
                        di._events_semaphore.release()
                    else:
                        raise Exception("Unexpected packet type received")


            def initialize_id_sizes(di):
                """ Query sizes of JDWP objects and cache them as struct format
                characters.
                """

                for attr in ("field_id", "method_id", "object_id",
                             "reference_type_id", "frame_id"):
                    id_size = {1:"B", 2:"H", 4:"I", 8:"Q"}[getattr(
                        di.virtual_machine.id_sizes, attr)]
                    setattr(di._struct_sizes, attr, id_size)


            def initialize_jni_tags(di):
                """ Initialize the JNI tags dictionary (di.jni_tags). """

                #     Tag   name             size as struct format character
                t = (("[", "array",          di._struct_sizes.object_id),
                     ("B", "byte",           "B"),
                     ("C", "char",           "h"),
                     ("L", "object",         di._struct_sizes.object_id),
                     ("F", "float",          "f"),
                     ("D", "double",         "d"),
                     ("I", "int",            "i"),
                     ("J", "long",           "q"),
                     ("S", "short",          "h"),
                     ("V", "void",           "0s"),
                     ("Z", "boolean",        "B"),
                     ("s", "string",         di._struct_sizes.object_id),
                     ("t", "thread",         di._struct_sizes.object_id),
                     ("g", "thread_group",   di._struct_sizes.object_id),
                     ("l", "class_loader",   di._struct_sizes.object_id),
                     ("c", "class",          di._struct_sizes.object_id))

                for tag, name, size in t:
                    self.di.jni_tags[tag] = JniTag(tag, name, size)


            self.di.transport.attach()
            self.di.connected = True
            self.di.transport.handshake()
            thread.start_new_thread(recv_packets, (self.di,))
            initialize_id_sizes(self.di)
            initialize_jni_tags(self.di)

        def _send_and_recv(self, packet):
            """ Send packet to debuggee and return Reply :any:`Packet` object.
            """

            self.di._waiting[packet.id] = threading.Event()
            self.di.transport.send_packet(packet)
            self.di._waiting[packet.id].wait()
            del self.di._waiting[packet.id]
            return self.di._replies.pop(packet.id)

        def wait_for_event(self):
            """ Wait for the next debug event from the debuggee and return the
            event's :any:`CommandPacket`.
            """

            self.di._events_semaphore.acquire()
            event_packet = self.di._events.pop(0)
            if not (event_packet.command_set == Command.Event.Composite[0] and
                    event_packet.command == Command.Event.Composite[1]):
                raise Exception(
                    "Unexpected event packet command_set or command: ("
                    + str(event_packet.command_set) + ", " +
                    str(event_packet.command) + ")")
            return event_packet

        def parse_events(self, data):
            """ Extract all events from an event :any:`CommandPacket` object's
            *data* buffer.

            Returns a tuple. The first value in the tuple is a list of
            :py:class:`pyspresso.events.Event` objects; the second value in the
            tuple is the composite event's :any:`SuspendPolicy`.
            """

            unpacker = _StructUnpacker(data)
            suspend_policy, event_count = unpacker.unpack_next(">BI")
            events = []
            for e in xrange(event_count):
                event_kind = unpacker.unpack_next(">B")[0]
                event = self.di.event_classes[event_kind]()
                for field in event._unpack_order:
                    if field in ("request_id", "status"):
                        value = unpacker.unpack_next(">i")[0]
                    elif field in ("thread", "type_id"):
                        value = unpacker.unpack_next(">" + self.di._struct_sizes.object_id)[0]
                    elif field in ("location", "catch_location"):
                        (type, class_id, method_id, index) = unpacker.unpack_next(
                            ">B" + self.di._struct_sizes.object_id + self.di._struct_sizes.method_id + "Q")
                        value = Location(self.di, type, class_id, method_id, index)
                    elif field in ("value", "value_to_be"):
                        value = Value()
                        value.tag = unpacker.unpack_next(">c")[0]
                        value.value = unpacker.unpack_next(">" + self.di.jni_tags[value.tag].size)[0]
                    elif field in ("object", "exception"):
                        value = TaggedObjectId()
                        (value.tag, value.object_id) = unpacker.unpack_next(
                            ">c" + self.di._struct_sizes.object_id)
                    elif field == "timeout":
                        value = unpacker.unpack_next(">q")[0]
                    elif field == "timed_out":
                        value = (unpacker.unpack_next(">B")[0] != 0)
                    elif field == "ref_type_tag":
                        value = unpacker.unpack_next(">B")[0]
                    elif field == "signature":
                        length = unpacker.unpack_next(">I")[0]
                        value = unpacker.unpack_next(">" + str(length) + "s")[0]
                    elif field == "field_id":
                        value = unpacket.unpack_next(">" + self.di._struct_sizes.field_id)[0]
                    else:
                        raise ValueError("Unknown field name")
                    setattr(event, field, value)

                events += [event]
        
            return events, suspend_policy

        def parse_jni(self, jni):
            """ Parse a JNI type signature string, such as
            ``"(ILjava/lang/String;[I)J"``. For details, see
            https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/types.html#type_signatures

            Returns a two-value tuple. The first value is a list of method
            :any:`Parameter` objects; the second value is a single
            :any:`Parameter` representing the method's return type.
            """

            args = []
            if jni[0] != "(":
                raise ValueError("JNI string does not begin with \"(\": " + jni)
            i = 1

            in_args = True

            while True:
                c = jni[i]
                i = i + 1
                if c == ")":
                    if in_args:
                        in_args = False
                        continue
                    else:
                        raise ValueError("\")\" found in JNI string's return type: " + jni)
                if c in "BCFDIJSVZstglc":
                    tag = c
                    name = None
                elif c == "L":
                    tag = c
                    semicolon = jni.find(";", i + 1)
                    if semicolon == -1:
                        raise ValueError("No \";\" found after \"L\" in JNI string: " + jni)
                    name = jni[i:semicolon].replace("/", ".")
                    if name == "java.lang.ThreadGroup":
                        name = "ThreadGroup"
                        tag = "g"
                    elif name == "java.lang.String":
                        name = "String"
                        tag = "s"
                    elif name == "java.lang.ClassLoader":
                        name = "ClassLoader"
                        tag = "l"
                    elif name == "java.lang.Thread":
                        name = "Thread"
                        tag = "t"
                    elif name == "java.lang.Object":
                        name = "Object"
                    i = semicolon + 1
                elif c == "[":
                    array_dimensions = 1
                    while True:
                        c = jni[i]
                        i = i + 1
                        if c == "[":
                            array_dimensions += 1
                        else:
                            break
                    tag = "["
                    if c in "BCFDIJSVZstglc":
                        name = self.di.jni_tags[c].name + "[]"*array_dimensions
                    elif c == "L":
                        semicolon = jni.find(";", i + 1)
                        if semicolon == -1:
                            raise ValueError("No \";\" found after \"L\" in JNI string: " + jni)
                        name = jni[i:semicolon].replace("/", ".") + "[]"*array_dimensions
                        if name[:name.find("[")] in (
                            "java.lang.ThreadGroup",
                            "java.lang.String",
                            "java.lang.ClassLoader",
                            "java.lang.Thread",
                            "java.lang.Object"):
                            name = name[len("java.lang."):]
                        i = semicolon + 1
                    else:
                        raise ValueError("Unexpected character encountered in JNI string: " + jni)
                else:
                    raise ValueError("Unexpected character encountered in JNI string: " + jni)

                parameter = Parameter(tag, name)
            
                if in_args:
                    args += [parameter]
                else:
                    return_type = parameter
                    break

            return args, return_type

        def get_method_arguments(self, thread_id, parameters, mod_bits):
            """ Get the list of method arguments in a given thread's stack
            frame.
            """

            class Slot:
                slot = 0
                """ The local variable's index in the frame. """

                sig_byte = 0
                """ A :any:`Tag` identifying the type of the variable. """

            # Get thread's frame ID.
            frames = self.di.thread_reference.get_frames(thread_id, 0, 1)
            frame_id = frames[0].frame_id

            arguments = []
            slots = []

            # If the method is not static then it has a hidden "this" argument.
            if mod_bits & AccessFlags.STATIC == 0:
                try:
                    tagged_object_id = self.di.stack_frame.get_this_object(thread_id,
                                                                        frame_id)
                    tag = tagged_object_id.tag
                except JdwpCommandError:
                    tag = "L"
                parameters = [Parameter(tag, "this")] + parameters

            if len(parameters) == 0 and len(slots) == 0:
                return arguments

            for arg in parameters:
                slot = Slot()
                slot.slot = len(slots)
                slot.sig_byte = arg.tag
                slots += [slot]

            try:
                values = self.di.stack_frame.get_values(thread_id, frame_id, slots)
            except JdwpCommandError as e:
                if e.error_code == Error.OPAQUE_FRAME:
                    for arg in parameters:
                        if arg.name != None:
                            arguments += ["<" + arg.name + ">"]
                        else:
                            arguments += ["<" + self.di.jni_tags[arg.tag].name + ">"]
                else:
                    arguments += ["<unknown>..."]
                return arguments

            if len(values) != len(slots):
                raise RuntimeError("Unexpected value count")

            for value in values:
                tag_name = self.di.jni_tags[value.tag].name
                tag_size = self.di.jni_tags[value.tag].size

                if tag_size == None:
                    arguments += [tag_name]
                    continue

                argument = ""
                if mod_bits & AccessFlags.STATIC == 0 and len(arguments) == 0:
                    argument = "this: "

                argument += self.get_string_representation_of_value(value)

                arguments += [argument]

            return arguments

        def get_string_representation_of_value(self, value=None):
            """ Get a string representation of *value*, a :any:`Value` value. """

            tag_name = self.di.jni_tags[value.tag].name

            # If value is a primitive, return it as a string.
            if value.tag in "BCFDIJSZ":
                return str(value.value)

            if tag_name == "void":
                return "void"
            elif tag_name == "array":
                if value.value == 0:
                    return "<null array>"
                length = self.di.array_reference.get_length(value.value)
                if length == 0:
                    s = "<empty array>"
                else:
                    first_value = self.di.array_reference.get_values(value.value, 0, 1)[0]
                    s = "<" + self.di.jni_tags[first_value.tag].name + " array> [length " + str(length) + "]"
                s += " [ID " + str(value.value) + "]"
                return s
            elif tag_name == "object":
                if value.value == 0:
                    return "null"
                reference_type = self.di.object_reference.get_reference_type(value.value)
                s = "<" + self.di.reference_type.get_signature(reference_type.type_id)[1:-1].replace("/", ".") + ">"
                s += " [ID " + str(value.value) + "]"
                return s
            elif tag_name == "string":
                return "\"" + self.di.string_reference.get_value(value.value) + "\""
            elif tag_name == "thread":
                return "<Thread> [name \"" + self.di.thread_reference.get_name(value.value) + "\"] [ID " + str(value.value) + "]"
            elif tag_name == "thread_group":
                return "<ThreadGroup> [name \"" + self.di.thread_group_reference.get_name(value.value) + "\"] [ID " + str(value.value) + "]"
            elif tag_name == "class_loader":
                reference_type = self.di.object_reference.get_reference_type(value.value)
                s = "<" + self.di.reference_type.get_signature(reference_type.type_id)[1:-1].replace("/", ".") + ">"
                s += " [ID " + str(value.value) + "]"
                return s
            elif tag_name == "class":
                reference_type = self.di.class_object_reference.get_reflected_type(value.value)
                s = "<" + self.di.reference_type.get_signature(reference_type.type_id)[1:-1].replace("/", ".") + ">"
                s += " [ID " + str(value.value) + "]"
                return s
            else:
                raise ValueError("Unexpected tag name")

        def get_method(self, reference_type_id=0, method_id=0):
            """ Returns a :any:`Method` object from a given numeric
            *reference_type_id* and a given numeric *method_id*.
            """

            # Try to return the method from the cache.
            try:
                return self.di._methods[reference_type_id][method_id]
            except KeyError:
                self.di._methods[reference_type_id] = {}
                for method in self.di.reference_type.get_methods(
                    reference_type_id):
                    self.di._methods[reference_type_id][method_id] = method
                return self.di._methods[reference_type_id][method_id]


    utils = Utilities(None)
    """ Utility functions. Updated by the :any:`DebugInterface` constructor
    with the actual :any:`DebugInterface` object.
    """


    def __init__(self, transport=None, server=False, address=None):
        """ The :any:`DebugInterface` constructor initializes member variables
        and creates a :any:`DebugTransport` object accessible as the
        ``transport`` member variable. It also creates the ``xdebug_arg``
        member variable to be used when running the Java target with the
        ``"-Xdebug"`` command line argument.

        The *transport* value should be ``"memory"`` for a shared-memory-based
        transport or ``"socket"`` for a socket-based transport.

        If the *server* value is ``True`` then  the debugger acts as the server
        and the debuggee acts as the client. Otherwise, the debuggee acts as
        the server and the debugger acts as the client.

        The *address* value should be in the format ``"hostname:port"`` for
        socket-based transport, or should be the shared file mapping name for
        shared-memory-based transport.
        """

        #
        # Initialize the event_classes dictionary.
        #

        for class_ in [
            getattr(Event, class_[0])
            for class_ in inspect.getmembers(Event, inspect.isclass)
            if class_[1].__module__ == "pyspresso.events"]:
            self.event_classes[class_.event_kind] = class_


        #
        # Initialize debug transport.
        #

        if server:
            raise Exception("Debug server not yet implemented")

        if transport is None:
            if os.name == "nt" and (address is None or (type(address) is str
                and re.match(r"[A-Za-z0-9.-]+:\d+", address) is None)):
                #
                # Default to "memory" on Windows if address not specified or if
                # address doesn't look like a "hostname:port" string.
                #
                transport = "memory"
            else:
                transport = "socket"

        # Validate transport type.
        if transport not in ("memory", "socket"):
            raise Exception("Invalid transport")

        # Set a default address if none was specified.
        if address is None:
            if transport == "socket":
                # Pick a local port.
                s = socket.socket()
                s.bind(("", 0))
                address = "localhost:" + str(s.getsockname()[1])
                s.close()
            else:
                # Pick a unique shared file mapping name.
                address = "pyspresso_" + binascii.b2a_base64(
                    hashlib.sha256(uuid.uuid4().bytes).digest())[:8]

        # Map high-level transport name to low-level transport name.
        internal_transport = {"memory": "dt_shmem", "socket": "dt_socket"}[transport]

        self.transport = pyspresso.transport.DebugTransport(
            transport=internal_transport, address=address)

        self.xdebug_arg = "-Xrunjdwp:transport=" + internal_transport + ",server=y,address=" + address

        self.utils = self.Utilities(self)

        # Initialize all JdwpCommand objects.
        self.virtual_machine = JdwpCommand.VirtualMachine(self)
        self.reference_type = JdwpCommand.ReferenceType(self)
        self.class_type = JdwpCommand.ClassType(self)
        self.array_type = JdwpCommand.ArrayType(self)
        self.interface_type = JdwpCommand.InterfaceType(self)
        self.method = JdwpCommand.Method(self)
        self.object_reference = JdwpCommand.ObjectReference(self)
        self.string_reference = JdwpCommand.StringReference(self)
        self.thread_reference = JdwpCommand.ThreadReference(self)
        self.thread_group_reference = JdwpCommand.ThreadGroupReference(self)
        self.array_reference = JdwpCommand.ArrayReference(self)
        self.class_loader_reference = JdwpCommand.ClassLoaderReference(self)
        self.event_request = JdwpCommand.EventRequest(self)
        self.stack_frame = JdwpCommand.StackFrame(self)
        self.class_object_reference = JdwpCommand.ClassObjectReference(self)


class JdwpCommand:
    """ This class contains Python-wrappers for JDWP commands.

    Most of the docstrings in the subclasses are copied from
    http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html
    """

    class _Command(object):
        def __init__(self, di):
            self._di = di

        def send_command(self, command, data, error):
            reply = self._di.utils._send_and_recv(
                self._di.transport.make_packet(command, data))
            if error is not None and reply.error_code != Error.NONE:
                raise JdwpCommandError(
                    error + " (error " + str(reply.error_code) + ")",
                    reply.error_code)

            return _StructUnpacker(reply.data)

    class VirtualMachine(_Command):

        _version = None
        @property
        def version(self):
            """ The JDWP version implemented by the target VM. The version
            string format is implementation dependent.
            """

            if self._version is not None:
                return self._version

            class Version:
                description	= ""
                """ Text information on the VM version. """

                jdwp_major = 0
                """ Major JDWP Version number. """

                jdwp_minor = 0
                """ Minor JDWP Version number. """

                vm_version = ""
                """ Target VM JRE version, as in the java.version property. """

                vm_name = ""
                """ Target VM name, as in the java.vm.name property. """

            unpacker = self.send_command(
                Command.VirtualMachine.Version,
                "",
                "Could not get version information")
                
            self._version = Version()
            length = unpacker.unpack_next(">I")[0]
            self._version.description = unpacker.unpack_next(">" + str(length) + "s")[0]
            self._version.jdwp_major = unpacker.unpack_next(">i")[0]
            self._version.jdwp_minor = unpacker.unpack_next(">i")[0]
            length = unpacker.unpack_next(">I")[0]
            self._version.vm_version = unpacker.unpack_next(">" + str(length) + "s")[0]
            length = unpacker.unpack_next(">I")[0]
            self._version.vm_name = unpacker.unpack_next(">" + str(length) + "s")[0]

            return self._version

        def get_classes_by_signature(self, signature=""):
            """ Returns reference types for all the classes loaded by the
            target VM which match the given *signature*. Multple reference
            types will be returned if two or more class loaders have loaded a
            class of the same name. The search is confined to loaded classes
            only; no attempt is made to load a class of the given signature.

            The *signature* value is the JNI signature of the class to find
            (for example, ``"Ljava/lang/String;"``).
            """

            unpacker = self.send_command(
                Command.VirtualMachine.ClassesBySignature,
                struct.pack(">i" + str(len(signature)) + "s", len(signature),
                            signature),
                "Could not get classes by signature")

            count = unpacker.unpack_next(">I")[0]

            classes = []

            for i in xrange(count):
                c = Class()
                (c.ref_type_tag, c.type_id, c.status) = unpacker.unpack_next(
                    ">B" + self._di._struct_sizes.object_id + "i")
                c.signature = signature
                classes += [c]

            return classes

        @property
        def all_classes(self):
            """ Returns reference types for all classes currently loaded by the
            target VM.
            """

            unpacker = self.send_command(
                Command.VirtualMachine.AllClasses,
                "",
                "Could not get all classes")

            count = unpacker.unpack_next(">I")[0]

            classes = []

            for i in xrange(count):
                c = Class()
                (c.ref_type_tag, c.type_id) = unpacker.unpack_next(
                    ">B" + self._di._struct_sizes.object_id)
                length = unpacker.unpack_next(">I")[0]
                c.signature = unpacker.unpack_next(">" + str(length) + "s")[0]
                c.status = unpacker.unpack_next(">i")[0]
                classes += [c]

            return classes

        @property
        def all_threads(self):
            """ Returns all threads currently running in the target VM. The
            returned list contains threads created through java.lang.Thread,
            all native threads attached to the target VM through JNI, and
            system threads created by the target VM. Threads that have not yet
            been started and threads that have completed their execution are
            not included in the returned list.
            """

            unpacker = self.send_command(
                Command.VirtualMachine.AllThreads,
                "",
                "Could not get all threads")

            count = unpacker.unpack_next(">I")[0]

            threads = []

            for i in xrange(count):
                threads += [unpacker.unpack_next(
                    ">" + self._di._struct_sizes.object_id)[0]]

            return threads

        @property
        def top_level_thread_groups(self):
            """ Returns all thread groups that do not have a parent. This
            command may be used as the first step in building a tree (or trees)
            of the existing thread groups.
            """

            unpacker = self.send_command(
                Command.VirtualMachine.TopLevelThreadGroups,
                "",
                "Could not get all top level thread groups")

            count = unpacker.unpack_next(">I")[0]

            groups = []

            for i in xrange(count):
                groups += [unpacker.unpack_next(
                    ">" + self._di._struct_sizes.object_id)[0]]

            return groups

        def dispose(self):
            """ Invalidates this virtual machine mirror. The communication
            channel to the target VM is closed, and the target VM prepares to
            accept another subsequent connection from this debugger or another
            debugger.
            """

            self.send_command(
                Command.VirtualMachine.Dispose,
                "",
                None)

        _id_sizes = None
        @property
        def id_sizes(self):
            """ Returns the sizes of variably-sized data types in the target
            VM.The returned values indicate the number of bytes used by the
            identifiers in command and reply packets.
            """

            if self._id_sizes is not None:
                return self._id_sizes

            class IDSizes:
                field_id = 0
                """ fieldID size in bytes. """

                method_id = 0
                """ methodID size in bytes. """

                object_id = 0
                """ objectID size in bytes. """

                reference_type_id = 0
                """ referenceTypeID size in bytes. """

                frame_id = 0
                """ frameID size in bytes. """

            
            unpacker = self.send_command(
                Command.VirtualMachine.IDSizes,
                "",
                "Could not get ID sizes")

            self._id_sizes = IDSizes()

            (self._id_sizes.field_id,
            self._id_sizes.method_id,
            self._id_sizes.object_id,
            self._id_sizes.reference_type_id,
            self._id_sizes.frame_id) = unpacker.unpack_next(">5i")

            return self._id_sizes

        def suspend(self):
            """ Suspends the execution of the application running in the target
            VM. All Java threads currently running will be suspended.

            Unlike java.lang.Thread.suspend, suspends of both the virtual
            machine and individual threads are counted. Before a thread will
            run again, it must be resumed through the VM-level resume
            (http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_VirtualMachine_Resume)
            command or the thread-level resume
            (http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_ThreadReference_Resume)
            command the same number of times it has been suspended.
            """

            self.send_command(
                Command.VirtualMachine.Suspend,
                ""
                "Could not suspend VM")

        def resume(self):
            """ Resumes execution of the application after the suspend command
            or an event has stopped it. Suspensions of the Virtual Machine and
            individual threads are counted. If a particular thread is suspended
            n times, it must resumed n times before it will continue.
            """

            self.send_command(
                Command.VirtualMachine.Resume,
                "",
                None)

        def exit(self, exit_code=0):
            """ Terminates the target VM with the given *exit_code*. On some
            platforms, the exit code might be truncated, for example, to the
            low order 8 bits. All ids previously returned from the target VM
            become invalid. Threads running in the VM are abruptly terminated.
            A thread death exception is not thrown and finally blocks are not
            run.
            """

            self.send_command(
                Command.VirtualMachine.Exit,
                struct.pack(">i", exit_code),
                None)

        def create_string(self, string=""):
            """ Creates a new UTF-8 *string* object in the target VM and
            returns its id.
            """

            unpacker = self.send_command(
                Command.VirtualMachine.CreateString,
                struct.pack(">i" + str(len(string)) + "s", len(string),
                            string),
                "Could not create string")

            return unpacker.unpack_next(
                ">" + self._di._struct_sizes.object_id)[0]

        _capabilities = None
        @property
        def capabilities(self):
            """ Retrieve this VM's capabilities. The capabilities are returned
            as booleans, each indicating the presence or absence of a
            capability. The commands associated with each capability will
            return the NOT_IMPLEMENTED error if the cabability is not
            available.
            """

            if self._capabilities is not None:
                return self._capabilities

            class Capabilities:
                can_watch_field_modification = False
                """ Can the VM watch field modification, and therefore can it
                send the Modification Watchpoint Event?
                """

                can_watch_field_access = False
                """ Can the VM watch field access, and therefore can it send
                the Access Watchpoint Event?
                """

                can_get_bytecodes = False
                """ Can the VM get the bytecodes of a given method? """

                can_get_synthetic_attribute = False
                """ Can the VM determine whether a field or method is
                synthetic? (that is, can the VM determine if the method or the
                field was invented by the compiler?)
                """

                can_get_owned_monitor_info = False
                """ Can the VM get the owned monitors infornation for a thread?
                """

                can_get_current_contended_monitor = False
                """ Can the VM get the current contended monitor of a thread?
                """

                can_get_monitor_info = False
                """ Can the VM get the monitor information for a given object?
                """

            unpacker = self.send_command(
                Command.VirtualMachine.Capabilities,
                "",
                "Could not get capabilities")

            self._capabilities = Capabilities()
            
            (self._capabilities.can_watch_field_modification,
            self._capabilities.can_watch_field_access,
            self._capabilities.can_get_bytecodes,
            self._capabilities.can_get_synthetic_attribute,
            self._capabilities.can_get_owned_monitor_info,
            self._capabilities.can_get_current_contended_monitor,
            self._capabilities.can_get_monitor_info) = unpacker.unpack_next(
                ">7?")

            return self._capabilities

        @property
        def class_paths(self):
            """ Retrieve the classpath and bootclasspath of the target VM. If
            the classpath is not defined, returns an empty list. If the
            bootclasspath is not defined returns an empty list.

            Returns a 3-tuple of (base_directory, class_paths,
            boot_class_paths).
            """

            unpacker = self.send_command(
                Command.VirtualMachine.ClassPaths,
                "",
                "Could not get class paths")

            length = unpacker.unpack_next(">I")[0]
            base_directory = unpacker.unpack_next(">" + str(length) + "s")[0]

            class_paths = []
            count = unpacker.unpack_next(">I")[0]
            for i in xrange(count):
                length = unpacker.unpack_next(">I")[0]
                class_paths += [unpacker.unpack_next(">" + str(length) + "s")[0]]

            boot_class_paths = []
            count = unpacker.unpack_next(">I")[0]
            for i in xrange(count):
                length = unpacker.unpack_next(">I")[0]
                boot_class_paths += [unpacker.unpack_next(
                    ">" + str(length) + "s")[0]]

            return base_directory, class_paths, boot_class_paths

        def dispose_objects(self, objects=[]):
            """ Releases a list of object IDs. For each object in the list,
            the following applies. The count of references held by the back-end
            (the reference count) will be decremented by refCnt. If thereafter
            the reference count is less than or equal to zero, the ID is freed.
            Any back-end resources associated with the freed ID may be freed,
            and if garbage collection was disabled for the object, it will be
            re-enabled. The sender of this command promises that no further
            commands will be sent referencing a freed ID.

            Use of this command is not required. If it is not sent, resources
            associated with each ID will be freed by the back-end at some time
            after the corresponding object is garbage collected. It is most
            useful to use this command to reduce the load on the back-end if a
            very large number of objects has been retrieved from the back-end
            (a large array, for example) but may not be garbage collected any
            time soon.
            
            IDs may be re-used by the back-end after they have been freed with
            this command.This description assumes reference counting, a
            back-end may use any implementation which operates equivalently.
            """

            data = struct.pack(">i", len(objects))

            for o in objects:
                data += struct.pack(
                    ">" + self._di._struct_sizes.object_id + "i",
                    o.object, o.ref_cnt)

            self.send_command(
                Command.VirtualMachine.DisposeObjects,
                data,
                None)

        def hold_events(self):
            """ Tells the target VM to stop sending events. Events are not
            discarded; they are held until a subsequent ReleaseEvents command
            is sent. This command is useful to control the number of events
            sent to the debugger VM in situations where very large numbers of
            events are generated. While events are held by the debugger
            back-end, application execution may be frozen by the debugger
            back-end to prevent buffer overflows on the back end. Responses to
            commands are never held and are not affected by this command. If
            events are already being held, this command is ignored.
            """

            self.send_command(
                Command.VirtualMachine.HoldEvents,
                "",
                None)

        def release_events(self):
            """ Tells the target VM to continue sending events. This command
            is used to restore normal activity after a HoldEvents command.
            If there is no current HoldEvents command in effect, this command
            is ignored.
            """

            self.send_command(
                Command.VirtualMachine.ReleaseEvents,
                "",
                None)

        _capabilities_new = None
        @property
        def capabilities_new(self):
            """ Retrieve all of this VM's capabilities. The capabilities are
            returned as booleans, each indicating the presence or absence of a
            capability. The commands associated with each capability will
            return the NOT_IMPLEMENTED error if the cabability is not
            available. Since JDWP version 1.4.
            """

            if self._capabilities_new is not None:
                return self._capabilities_new

            class CapabilitiesNew:
                can_watch_field_modification = False
                """ Can the VM watch field modification, and therefore can it
                send the Modification Watchpoint Event?
                """

                can_watch_field_access	= False
                """ Can the VM watch field access, and therefore can it send
                the Access Watchpoint Event?
                """

                can_get_bytecodes	= False
                """ Can the VM get the bytecodes of a given method? """

                can_get_synthetic_attribute = False
                """ Can the VM determine whether a field or method is
                synthetic? (that is, can the VM determine if the method or the
                field was invented by the compiler?)
                """

                can_get_owned_monitor_info = False
                """ Can the VM get the owned monitors infornation for a thread?
                """

                can_get_current_contended_monitor = False
                """ Can the VM get the current contended monitor of a thread?
                """

                can_get_monitor_info = False
                """ Can the VM get the monitor information for a given object?
                """

                can_redefine_classes = False
                """ Can the VM redefine classes? """

                can_add_method = False
                """ Can the VM add methods when redefining classes? """
                
                can_unrestrictedly_redefine_classes = False
                """ Can the VM redefine classes in arbitrary ways? """

                can_pop_frames = False
                """ Can the VM pop stack frames? """

                can_use_instance_filters = False
                """ Can the VM filter events by specific object? """

                can_get_source_debug_extension = False
                """ Can the VM get the source debug extension? """

                can_request_vm_death_event = False
                """ Can the VM request VM death events? """

                can_set_default_stratum = False
                """ Can the VM set a default stratum? """

                can_get_instance_info = False
                """ Can the VM return instances, counts of instances of classes
                and referring objects? 
                """

                can_request_monitor_events	= False
                """ Can the VM request monitor events? """

                can_get_monitor_frame_info = False
                """ Can the VM get monitors with frame depth info? """

                can_use_source_name_filters	= False
                """ Can the VM filter class prepare events by source name? """

                can_get_constant_pool = False
                """ Can the VM return the constant pool information? """
                
                can_force_early_return = False
                """ Can the VM force early return from a method? """

            unpacker = self.send_command(
                Command.VirtualMachine.CapabilitiesNew,
                "",
                "Could not get new capabilities")

            self._capabilities_new = CapabilitiesNew()
            
            (self._capabilities_new.can_watch_field_modification,
            self._capabilities_new.can_watch_field_access,
            self._capabilities_new.can_get_bytecodes,
            self._capabilities_new.can_get_synthetic_attribute,
            self._capabilities_new.can_get_owned_monitor_info,
            self._capabilities_new.can_get_current_contended_monitor,
            self._capabilities_new.can_get_monitor_info,
            self._capabilities_new.can_redefine_classes,
            self._capabilities_new.can_add_method,
            self._capabilities_new.can_unrestrictedly_redefine_classes,
            self._capabilities_new.can_pop_frames,
            self._capabilities_new.can_use_instance_filters,
            self._capabilities_new.can_get_source_debug_extension,
            self._capabilities_new.can_request_vm_death_event,
            self._capabilities_new.can_set_default_stratum,
            self._capabilities_new.can_get_instance_info,
            self._capabilities_new.can_request_monitor_events,
            self._capabilities_new.can_get_monitor_frame_info,
            self._capabilities_new.can_use_source_name_filters,
            self._capabilities_new.can_get_constant_pool,
            self._capabilities_new.can_force_early_return) = unpacker.unpack_next(
                ">21?")

            return self._capabilities_new

        def redefine_classes(self, classes=[]):
            """ Installs new class definitions. If there are active stack
            frames in methods of the redefined classes in the target VM then
            those active frames continue to run the bytecodes of the original
            method. These methods are considered obsolete - see
            :any:`is_obsolete`. The methods in the redefined classes will be
            used for new invokes in the target VM. The original method ID
            refers to the redefined method. All breakpoints in the redefined
            classes are cleared. If resetting of stack frames is desired, the
            :any:`pop_frames` command can be used to pop frames with obsolete
            methods.

            Requires ``can_redefine_classes`` capability - see
            :any:`capabilities_new`. In addition to the canRedefineClasses
            capability, the target VM must have the canAddMethod capability to
            add methods when redefining classes, or the
            canUnrestrictedlyRedefineClasses to redefine classes in arbitrary
            ways.
            """

            data = struct.pack(">I", len(classes))
            for class_ in classes:
                data += struct.pack(
                    ">" + self._di._struct_sizes.object_id + "I",
                    class_.ref_type, len(class_.class_file))
                data += class_.class_file

            self.send_command(
                Command.VirtualMachine.RedefineClasses,
                data,
                "Could not redefine classes")

        def _default_stratum(self, stratum_id=""):
            self.send_command(
                Command.VirtualMachine.SetDefaultStratum,
                struct.pack(">i" + str(len(stratum_id)) + "s", len(stratum_id),
                            stratum_id),
                "Could not set default stratum")
        default_stratum = property(None, _default_stratum)
        """ Set the default stratum. Requires ``can_set_default_stratum``
        capability - see :any:`capabilities_new`.

        Note that this is a write-only attribute.
        """

        @property
        def all_classes_with_generic(self):
            """ Returns reference types for all classes currently loaded by the
            target VM. Both the JNI signature and the generic signature are
            returned for each class. Generic signatures are described in the
            signature attribute section in The Java Virtual Machine
            Specification. Since JDWP version 1.5.
            """

            unpacker = self.send_command(
                Command.VirtualMachine.AllClassesWithGeneric,
                "",
                "Could not get all classes")

            classes = []
            count = unpacker.unpack_next(">I")[0]
            for i in xrange(count):
                c = Class()
                (c.ref_type_tag, c.type_id) = unpacker.unpack_next(
                    ">B" + self._di._struct_sizes.object_id)
                length = unpacker.unpack_next(">I")[0]
                c.signature = unpacker.unpack_next(">" + str(length) + "s")[0]
                length = unpacker.unpack_next(">I")[0]
                c.generic_signature = unpacker.unpack_next(
                    ">" + str(length) + "s")[0]
                c.status = unpacker.unpack_next(">i")[0]
                classes += [c]

            return classes

        def get_instance_counts(self, reference_types=[]):
            """ Returns the number of instances of each reference type in the
            input list. Only instances that are reachable for the purposes of
            garbage collection are counted. If a reference type is invalid, eg.
            it has been unloaded, zero is returned for its instance count.
            
            Since JDWP version 1.6. Requires ``can_get_instance_info``
            capability - see :any:`capabilities_new`.
            """

            data = struct.pack(">I", len(reference_types))
            for reference_type in reference_types:
                data += struct.pack(">" + self._di._struct_sizes.object_id,
                                    reference_type)

            unpacker = self.send_command(
                Command.VirtualMachine.InstanceCounts,
                data,
                "Could not get instance counts")

            instance_counts = []
            count = unpacker.unpack_next(">I")[0]
            for i in xrange(count):
                instance_counts += [unpacker.unpack_next(">Q")[0]]

            return instance_counts

    class ReferenceType(_Command):
        def get_signature(self, ref_type=0):
            """ Returns the JNI signature of a reference type. JNI signature
            formats are described in the Java Native Inteface Specification
            (http://java.sun.com/products/jdk/1.2/docs/guide/jni/index.html).

            For primitive classes the returned signature is the signature of
            the corresponding primitive type; for example, "I" is returned as
            the signature of the class represented by java.lang.Integer.TYPE.
            """

            unpacker = self.send_command(
                Command.ReferenceType.Signature,
                struct.pack(">" + self._di._struct_sizes.object_id, ref_type),
                "Could not get signature")

            length = unpacker.unpack_next(">I")[0]
            return unpacker.unpack_next(">" + str(length) + "s")[0]

        def get_class_loader(self, ref_type=0):
            """ Returns the instance of java.lang.ClassLoader which loaded a
            given reference type. If the reference type was loaded by the
            system class loader, the returned object ID is null.
            """

            unpacker = self.send_command(
                Command.ReferenceType.ClassLoader,
                struct.pack(">" + self._di._struct_sizes.object_id, ref_type),
                "Could not get ClassLoader")

            return unpacker.unpack_next(
                ">" + self._di._struct_sizes.object_id)[0]

        def get_modifiers(self, ref_type):
            """ Returns the modifiers (also known as access flags) for a
            reference type. The returned bit mask contains information on the
            declaration of the reference type. If the reference type is an
            array or a primitive class (for example, java.lang.Integer.TYPE),
            the value of the returned bit mask is undefined.
            """

            unpacker = self.send_command(
                Command.ReferenceType.Modifiers,
                struct.pack(">" + self._di._struct_sizes.object_id, ref_type),
                "Could not get modifiers")

            return unpacker.unpack_next(">i")[0]

        def get_fields(self, ref_type=0):
            """ Returns information for each field in a reference type.
            Inherited fields are not included. The field list will include any
            synthetic fields created by the compiler. Fields are returned in
            the order they occur in the class file.
            """

            unpacker = self.send_command(
                Command.ReferenceType.Fields,
                struct.pack(">" + self._di._struct_sizes.object_id, ref_type),
                "Could not get fields")

            fields = []
            count = unpacker.unpack_next(">I")[0]
            for i in xrange(count):
                field = Field()
                field.field_id = unpacker.unpack_next(
                    ">" + self._di._struct_sizes.field_id)[0]
                length = unpacker.unpack_next(">I")[0]
                field.name = unpacker.unpack_next(">" + str(length) + "s")[0]
                length = unpacker.unpack_next(">I")[0]
                field.signature = unpacker.unpack_next(
                    ">" + str(length) + "s")[0]
                field.mod_bits = unpacker.unpack_next(">I")[0]
                fields += [field]

            return fields

        def get_methods(self, ref_type=0):
            """ Returns information for each method in a reference type.
            Inherited methods are not included. The list of methods will
            include constructors (identified with the name "<init>"), the
            initialization method (identified with the name "<clinit>") if
            present, and any synthetic methods created by the compiler.
            Methods are returned in the order they occur in the class file.
            """

            unpacker = self.send_command(
                Command.ReferenceType.Methods,
                struct.pack(">" + self._di._struct_sizes.object_id, ref_type),
                "Could not get methods")
            
            declared = unpacker.unpack_next(">I")[0]
            methods = []
            for i in xrange(declared):
                method = Method()
                (method.method_id, name_len) = unpacker.unpack_next(
                    ">" + self._di._struct_sizes.method_id + "I")
                (method.name, jni_len) = unpacker.unpack_next(
                    ">" + str(name_len) + "sI")
                (method.signature, method.mod_bits) = unpacker.unpack_next(
                    ">" + str(jni_len) + "sI")
                methods += [method]

            return methods

        def get_values(self, ref_type=0, fields=[]):
            """ Returns the value of one or more static fields of the reference
            type. Each field must be member of the reference type or one of its
            superclasses, superinterfaces, or implemented interfaces. Access
            control is not enforced; for example, the values of private fields
            can be obtained.
            """

            data = struct.pack(">" + self._di._struct_sizes.object_id + "I",
                               ref_type, len(fields))
            for field in fields:
                data += struct.pack(
                    ">" + self._di._struct_sizes.field_id, field)

            unpacker = self.send_command(
                Command.ReferenceType.GetValues,
                data,
                "Could not get fields")

            count = unpacker.unpack_next(">I")[0]
            values = []
            for i in xrange(count):
                value = Value()
                value.tag = unpacker.unpack_next(">c")[0]
                value.value = unpacker.unpack_next(
                    ">" + self._di.jni_tags[value.tag].size)[0]
                values += [value]

            return values

        def get_source_file(self, ref_type=0):
            """ Returns the name of source file in which a reference type was
            declared.
            """

            unpacker = self.send_command(
                Command.ReferenceType.SourceFile,
                struct.pack(">" + self._di._struct_sizes.object_id, ref_type),
                "Could not get source file name")

            length = unpacker.unpack_next(">I")[0]
            return unpacker.unpack_next(">" + str(length) + "s")[0]

        def get_nested_types(self, ref_type=0):
            """ Returns the classes and interfaces directly nested within this
            type. Types further nested within those types are not included.
            """

            unpacker = self.send_command(
                Command.ReferenceType.NestedTypes,
                struct.pack(">" + self._di._struct_sizes.object_id, ref_type),
                "Could not get nested types")

            count = unpacker.unpack_next(">I")[0]

            classes = []

            for i in xrange(count):
                class_ = ReferenceType()
                class_.ref_type_tag = unpacker.unpack_next(">B")[0]
                class_.type_id = unpacker.unpack_next(
                    ">" + self._di._struct_sizes.object_id)[0]
                classes += [class_]

            return classes

        def get_status(self, ref_type=0):
            """ Returns the current status of the reference type. The status
            indicates the extent to which the reference type has been
            initialized, as described in section 2.1.6 of The Java Virtual
            Machine Specification. If the class is linked the PREPARED and
            VERIFIED bits in the returned status bits will be set. If the class
            is initialized the INITIALIZED bit in the returned status bits will
            be set. If an error occured during initialization then the ERROR
            bit in the returned status bits will be set. The returned status
            bits are undefined for array types and for primitive classes (such
            as java.lang.Integer.TYPE).
            """

            unpacker = self.send_command(
                Command.ReferenceType.Status,
                struct.pack(">" + self._di._struct_sizes.object_id, ref_type),
                "Could not get status")

            return unpacker.unpack_next(">i")[0]

        def get_interfaces(self, ref_type=0):
            """ Returns the interfaces declared as implemented by this class.
            Interfaces indirectly implemented (extended by the implemented
            interface or implemented by a superclass) are not included.
            """

            unpacker = self.send_command(
                Command.ReferenceType.Interfaces,
                struct.pack(">" + self._di._struct_sizes.object_id, ref_type),
                "Could not get interfaces")

            count = unpacker.unpack_next(">I")[0]
            interfaces = []
            for i in xrange(count):
                interfaces += [unpacker.unpack_next(
                    ">" + self._di._struct_sizes.object_id)[0]]

            return interfaces

        def get_class_object(self, ref_type=0):
            """ Returns the class object corresponding to this type. """

            unpacker = self.send_command(
                Command.ReferenceType.ClassObject,
                struct.pack(">" + self._di._struct_sizes.object_id, ref_type),
                "Could not get class object")

            return unpacker.unpack_next(
                ">" + self._di._struct_sizes.object_id)[0]

        def get_source_debug_extension(self, ref_type=0):
            """ Returns the value of the SourceDebugExtension attribute. Since
            JDWP version 1.4. Requires ``can_get_source_debug_extension``
            capability - see :any:`capabilities_new`.
            """

            unpacker = self.send_command(
                Command.ReferenceType.SourceDebugExtension,
                struct.pack(">" + self._di._struct_sizes.object_id, ref_type),
                "Could not get SourceDebugExtension attribute")

            length = unpacker.unpack_next(">I")[0]
            return unpacker.unpack_next(">" + str(length) + "s")[0]

        def get_signature_with_generic(self, ref_type=0):
            """ Returns the JNI signature of a reference type along with the
            generic signature if there is one. Generic signatures are described
            in the signature attribute section in The Java Virtual Machine
            Specification. Since JDWP version 1.5.

            Returns a 2-tuple: (signature, generic_signature)
            """

            unpacker = self.send_command(
                Command.ReferenceType.SourceDebugExtension,
                struct.pack(">" + self._di._struct_sizes.object_id, ref_type),
                "Could not get signatures")

            length = unpacker.unpack_next(">I")[0]
            signature = unpacker.unpack_next(">" + str(length) + "s")[0]
            length = unpacker.unpack_next(">I")[0]
            generic_signature = unpacker.unpack_next(
                ">" + str(length) + "s")[0]

            return (signature, generic_signature)

        def get_fields_with_generic(self, ref_type=0):
            """ Returns information, including the generic signature if any,
            for each field in a reference type. Inherited fields are not
            included. The field list will include any synthetic fields created
            by the compiler. Fields are returned in the order they occur in the
            class file. Generic signatures are described in the signature
            attribute section in The Java Virtual Machine Specification. Since
            JDWP version 1.5.
            """

            unpacker = self.send_command(
                Command.ReferenceType.FieldsWithGeneric,
                struct.pack(">" + self._di._struct_sizes.object_id, ref_type),
                "Could not get fields")

            fields = []
            count = unpacker.unpack_next(">I")[0]
            for i in xrange(count):
                field = Field()
                field.field_id = unpacker.unpack_next(
                    ">" + self._di._struct_sizes.field_id)[0]
                length = unpacker.unpack_next(">I")[0]
                field.name = unpacker.unpack_next(">" + str(length) + "s")[0]
                length = unpacker.unpack_next(">I")[0]
                field.signature = unpacker.unpack_next(
                    ">" + str(length) + "s")[0]
                length = unpacker.unpack_next(">I")[0]
                field.generic_signature = unpacker.unpack_next(
                    ">" + str(length) + "s")[0]
                field.mod_bits = unpacker.unpack_next(">I")[0]
                fields += [field]

            return fields

        def get_methods_with_generic(self, ref_type=0):
            """ Returns information, including the generic signature if any,
            for each method in a reference type. Inherited methodss are not 
            included. The list of methods will include constructors (identified
            with the name "<init>"), the initialization method (identified with
            the name "<clinit>") if present, and any synthetic methods created
            by the compiler. Methods are returned in the order they occur in
            the class file. Generic signatures are described in the signature
            attribute section in The Java Virtual Machine Specification. Since
            JDWP version 1.5.
            """

            unpacker = self.send_command(
                Command.ReferenceType.MethodsWithGeneric,
                struct.pack(">" + self._di._struct_sizes.object_id, ref_type),
                "Could not get methods")
            
            declared = unpacker.unpack_next(">I")[0]
            methods = []
            for i in xrange(declared):
                method = Method()
                method.method_id = unpacker.unpack_next(
                    ">" + self._di._struct_sizes.method_id)[0]
                for attr in ("name", "signature", "generic_signature"):
                    length = unpacker.unpack_next(">I")[0]
                    setattr(method, attr, unpacker.unpack_next(
                        ">" + str(length) + "s")[0])
                method.mod_bits = unpacker.unpack_next(">I")[0]
                methods += [method]

            return methods

        def get_instances(self, ref_type=0, max_instances=0):
            """ Returns instances of this reference type. Only instances that
            are reachable for the purposes of garbage collection are returned.

            Since JDWP version 1.6. Requires ``can_get_instance_info``
            capability - see :any:`capabilities_new`.
            """

            unpacker = self.send_command(
                Command.ReferenceType.Instances,
                struct.pack(
                    ">" + self._di._struct_sizes.object_id + "i",
                    ref_type, max_instances),
                "Could not get instances")
            
            count = unpacker.unpack_next(">I")[0]
            instances = []
            for i in xrange(count):
                instance = TaggedObjectId()
                (instance.tag, instance.object_id) = unpacker.unpack_next(
                    ">c" + self._di._struct_sizes.object_id)
                instances += [instance]

            return instances

        def get_class_file_version(self, ref_type=0):
            """ Returns the class file major and minor version numbers, as
            defined in the class file format of the Java Virtual Machine
            specification.
            
            Since JDWP version 1.6.

            Returns a 2-tuple: (major_version, minor_version)
            """

            unpacker = self.send_command(
                Command.ReferenceType.ClassFileVersion, 
                struct.pack(">" + self._di._struct_sizes.object_id, ref_type),
                "Could not get class file version")

            return unpacker.unpack_next(">ii")

        def get_constant_pool(self, ref_type=0):
            """ Return the raw bytes of the constant pool in the format of the
            constant_pool item of the Class File Format in The Java Virtual
            Machine Specification.

            Since JDWP version 1.6. Requires ``can_get_constant_pool``
            capability - see :any:`capabilities_new`.

            Returns the 2-tuple ``(count, cpbytes)``, where ``count`` is the
            total number of constant pool entries plus one (this corresponds to
            the constant_pool_count item of the Class File Format in The Java
            Virtual Machine Specification) and ``cpbytes`` contains the raw
            bytes of the constant pool.
            """

            unpacker = self.send_command(
                Command.ReferenceType.ConstantPool, 
                struct.pack(">" + self._di._struct_sizes.object_id, ref_type),
                "Could not get constant pool")

            count = unpacker.unpack_next(">I")[0]
            bytes = unpacker.unpack_next(">I")[0]
            cpbytes = unpacker.unpack_next(">" + str(bytes) + "s")[0]

            return (count, cpbytes)

    class ClassType(_Command):
        def get_superclass(self, class_=0):
            """ Returns the immediate superclass of a class. """

            unpacker = self.send_command(
                Command.ClassType.Superclass,
                struct.pack(">" + self._di._struct_sizes.object_id, class_),
                "Could not get superclass")

            return unpacker.unpack_next(
                ">" + self._di._struct_sizes.object_id)[0]

        def set_values(self, class_=0, values=[]):
            """ Sets the value of one or more static fields. Each field must be
            a member of the class type or one of its superclasses,
            superinterfaces, or implemented interfaces. Access control is not
            enforced; for example, the values of private fields can be set.
            Final fields cannot be set. For primitive values, the value's type
            must match the field's type exactly. For object values, there must
            exist a widening reference conversion from the value's type to
            the field's type and the field's type must be loaded.

            The *values* list should be a list of objects, where each object
            has attributes ``field_id`` (the field to set) and ``value`` (the
            value to put in the field).
            """

            original_values = self._di.reference_type.get_values(
                class_, [value.field_id for value in values])

            data = struct.pack(">" + self._di._struct_sizes.object_id + "I",
                               class_, len(values))

            for i in xrange(len(values)):
                data += struct.pack(">" + self._di._struct_sizes.field_id,
                                    values[i].field_id)
                data += struct.pack(
                    ">" + self._di.jni_tags[original_values[i].tag].size,
                    values[i].value)

            self.send_command(
                Command.ClassType.SetValues,
                data,
                "Could not set values")

        def invoke_method(self, class_=0, thread=0, method_id=0, arguments=[],
                          options=0):
            """ Invokes a static method.

            For more information, see
            http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_ClassType_InvokeMethod
            
            Returns a 2-tuple: ``(return_value, exception)``, where ``value``
            is a :any:`Value` and ``exception`` is a :any:`TaggedObjectId`.            
            """

            data = struct.pack(">2" + self._di._struct_sizes.object_id +
                               self._di._struct_sizes.method_id + "I",
                               class_, thread, method_id, len(arguments))

            for argument in arguments:
                data += struct.pack(">c", argument.tag)
                data += struct.pack(">" + self._di.jni_tags[argument.tag].size,
                                    argument.value)

            data += struct.pack(">i", options)

            unpacker = self.send_command(
                Command.ClassType.InvokeMethod,
                data,
                "Could not invoke method")

            return_value = Value()
            return_value.tag = unpacker.unpack_next(">c")[0]
            return_value.value = unpacker.unpack_next(
                ">" + self._di.jni_tags[return_value.tag].size)[0]

            exception = TaggedObjectId()
            (exception.tag, exception.object_id) = unpacker.unpack_next(
                    ">c" + self._di._struct_sizes.object_id)

            return (return_value, exception)

        def create_new_instance(self, class_=0, thread=0, method_id=0,
                                arguments=[], options=0):
            """ Creates a new object of this type, invoking the specified
            constructor.

            For more information, see
            http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_ClassType_NewInstance

            Returns a 2-tuple: ``(new_object, exception)``, where
            ``new_object`` is a :any:`TaggedObjectId` and ``exception`` is a
            :any:`TaggedObjectId`.            
            """

            data = struct.pack(">2" + self._di._struct_sizes.object_id +
                               self._di._struct_sizes.method_id + "I",
                               class_, thread, method_id, len(arguments))

            for argument in arguments:
                data += struct.pack(">c", argument.tag)
                data += struct.pack(">" + self._di.jni_tags[argument.tag].size,
                                    argument.value)

            data += struct.pack(">i", options)

            unpacker = self.send_command(
                Command.ClassType.NewInstance,
                data,
                "Could not create new instance")

            new_object = TaggedObjectId()
            (new_object.tag, new_object.object_id) = unpacker.unpack_next(
                    ">c" + self._di._struct_sizes.object_id)

            exception = TaggedObjectId()
            (exception.tag, exception.object_id) = unpacker.unpack_next(
                    ">c" + self._di._struct_sizes.object_id)

            return (new_object, exception)

    class ArrayType(_Command):
        def create_new_instance(self, array_type=0, length=0):
            """ Creates a new array object of this type with a given length.
            """

            unpacker = self.send_command(
                Command.ArrayType.NewInstance,
                struct.pack(">" + self._di._struct_sizes.object_id + "I",
                            array_type, length),
                "Could not create array")

            new_array = TaggedObjectId()
            new_array.tag = unpacker.unpack_next(">c")[0]
            new_array.value = unpacker.unpack_next(
                ">" + self._di._struct_sizes.object_id)[0]
            
            return new_array

    class InterfaceType(_Command):
        def invoke_method(self, class_=0, thread=0, method_id=0, arguments=[],
                          options=0):
            """ Invokes a static method.

            For more information, see
            http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_InterfaceType_InvokeMethod
            
            Returns a 2-tuple: ``(return_value, exception)``, where ``value``
            is a :any:`Value` and ``exception`` is a :any:`TaggedObjectId`.            
            """

            data = struct.pack(">2" + self._di._struct_sizes.object_id +
                               self._di._struct_sizes.method_id + "I",
                               class_, thread, method_id, len(arguments))

            for argument in arguments:
                data += struct.pack(">c", argument.tag)
                data += struct.pack(">" + self._di.jni_tags[argument.tag].size,
                                    argument.value)

            data += struct.pack(">i", options)

            unpacker = self.send_command(
                Command.InterfaceType.InvokeMethod,
                data,
                "Could not invoke method")

            return_value = Value()
            return_value.tag = unpacker.unpack_next(">c")[0]
            return_value.value = unpacker.unpack_next(
                ">" + self._di.jni_tags[return_value.tag].size)[0]

            exception = TaggedObjectId()
            (exception.tag, exception.object_id) = unpacker.unpack_next(
                    ">c" + self._di._struct_sizes.object_id)

            return (return_value, exception)

    class Method(_Command):
        class VariableTable:
            arg_cnt = 0
            """ The number of words in the frame used by arguments. Eight-byte
            arguments use two words; all others use one.
            """

            class Slot:
                code_index = 0
                """ First code index at which the variable is visible
                (unsigned). Used in conjunction with length. The variable can
                be get or set only when the current codeIndex <= current frame
                code index < codeIndex + length.
                """

                name = ""
                """ The variable's name. """

                signature = ""
                """ The variable type's JNI signature. """

                generic_signature = ""
                """ The variable type's generic signature or an empty string if
                there is none.
                """
                    
                length = 0
                """ Unsigned value used in conjunction with codeIndex. The
                variable can be get or set only when the current codeIndex <=
                current frame code index < code index + length.
                """

                slot = 0
                """ The local variable's index in its frame. """

            slots = []
            """ List of :any:`Slot` values. """

        def get_line_table(self, ref_type=0, method_id=0):
            """ Returns line number information for the method, if present. The
            line table maps source line numbers to the initial code index of
            the line. The line table is ordered by code index (from lowest to
            highest). The line number information is constant unless a new
            class definition is installed using :any:`redefine_classes`.
            """

            class LineTable:
                start = 0
                """ Lowest valid code index for the method, >=0, or -1 if the
                method is native.
                """

                end = 0
                """ Highest valid code index for the method, >=0, or -1 if the
                method is native.
                """

                class Line:
                    line_code_index = 0
                    """ Initial code index of the line, start <= lineCodeIndex
                    < end.
                    """

                    line_number = 0
                    """ Line number. """

                lines = []
                """ A list of :any:`Line` objects. """


            unpacker = self.send_command(
                Command.Method.LineTable,
                struct.pack(">" + self._di._struct_sizes.object_id +
                            self._di._struct_sizes.method_id,
                            ref_type, method_id),
                "Could not get line table")

            line_table = LineTable()
            (line_table.start, line_table.end, count) = unpacker.unpack_next(
                ">2qI")
            for i in xrange(count):
                line = LineTable.Line()
                (line.line_code_index, line.line_number) = unpacker.unpack_next(
                    ">qi")
                line_table.lines += [line]

            return line_table

        def get_variable_table(self, ref_type=0, method_id=0):
            """ Returns variable information for the method. The variable
            table includes arguments and locals declared within the method. For
            instance methods, the "this" reference is included in the table.
            Also, synthetic variables may be present.
            """

            unpacker = self.send_command(
                Command.Method.VariableTable,
                struct.pack(">" + self._di._struct_sizes.object_id +
                            self._di._struct_sizes.method_id,
                            ref_type, method_id),
                "Could not get variable table")

            variable_table = VariableTable()

            (variable_table.arg_cnt, count) = unpacker.unpack_next(">2I")
            for i in xrange(count):
                slot = VariableTable.Slot()
                slot.code_index = unpacker.unpack_next(">Q")[0]
                length = unpacker.unpack_next(">I")[0]
                slot.name = unpacker.unpack_next(">" + str(length) + "s")[0]
                length = unpacker.unpack_next(">I")[0]
                slot.signature = unpacker.unpack_next(
                    ">" + str(length) + "s")[0]
                (slot.length, slot.slot) = unpacker.unpack_next(">Ii")
                variable_table.slots += [slot]

            return variable_table

        def get_bytecodes(self, ref_type=0, method_id=0):
            """ Retrieve the method's bytecodes as defined in The Java Virtual
            Machine Specification. Requires ``can_get_bytecodes`` capability
            - see :any:`capabilities_new`.
            """

            unpacker = self.send_command(
                Command.Method.Bytecodes,
                struct.pack(">" + self._di._struct_sizes.object_id +
                            self._di._struct_sizes.method_id,
                            ref_type, method_id),
                "Could not get bytecodes")

            count = unpacker.unpack_next(">I")[0]
            return unpacker.unpack_next(">" + str(count) + "s")[0]

        def is_obsolete(self, ref_type=0, method_id=0):
            """ Determine if this method is obsolete. A method is obsolete if
            it has been replaced by a non-equivalent method using the
            :any:`redefine_classes` command. The original and redefined methods
            are considered equivalent if their bytecodes are the same except
            for indices into the constant pool and the referenced constants are
            equal.
            """

            unpacker = self.send_command(
                Command.Method.IsObsolete,
                struct.pack(">" + self._di._struct_sizes.object_id +
                            self._di._struct_sizes.method_id,
                            ref_type, method_id),
                "Could not get obsolete status")

            return unpacker.unpack_next(">?")[0]

        def get_variable_table_with_generic(self, ref_type=0, method_id=0):
            """ Returns variable information for the method, including generic
            signatures for the variables. The variable table includes arguments
            and locals declared within the method. For instance methods, the
            "this" reference is included in the table. Also, synthetic
            variables may be present. Generic signatures are described in the
            signature attribute section in The Java Virtual Machine
            Specification. Since JDWP version 1.5.
            """

            unpacker = self.send_command(
                Command.Method.VariableTableWithGeneric,
                struct.pack(">" + self._di._struct_sizes.object_id +
                            self._di._struct_sizes.method_id,
                            ref_type, method_id),
                "Could not get variable table")

            variable_table = VariableTable()

            (variable_table.arg_cnt, count) = unpacker.unpack_next(">2I")
            for i in xrange(count):
                slot = VariableTable.Slot()
                slot.code_index = unpacker.unpack_next(">Q")[0]
                length = unpacker.unpack_next(">I")[0]
                slot.name = unpacker.unpack_next(">" + str(length) + "s")[0]
                length = unpacker.unpack_next(">I")[0]
                slot.signature = unpacker.unpack_next(
                    ">" + str(length) + "s")[0]
                length = unpacker.unpack_next(">I")[0]
                slot.generic_signature = unpacker.unpack_next(
                    ">" + str(length) + "s")[0]
                (slot.length, slot.slot) = unpacker.unpack_next(">Ii")
                variable_table.slots += [slot]

            return variable_table

    class ObjectReference(_Command):
        def get_reference_type(self, object_id=0):
            """ Returns the runtime type of the object. The runtime type will
            be a class or an array.
            """

            unpacker = self.send_command(
                Command.ObjectReference.ReferenceType,
                struct.pack(">" + self._di._struct_sizes.object_id, object_id),
                "Could not get runtime type")

            runtime_reference = ReferenceType()
            (runtime_reference.ref_type_tag,
            runtime_reference.type_id) = unpacker.unpack_next(
                ">B" + self._di._struct_sizes.object_id)

            return runtime_reference

        def get_values(self, object_id=0, fields=[]):
            """ Returns the value of one or more instance fields. Each field
            must be member of the object's type or one of its superclasses,
            superinterfaces, or implemented interfaces. Access control is not
            enforced; for example, the values of private fields can be
            obtained.
            """

            data = struct.pack(">" + self._di._struct_sizes.object_id + "I",
                               object_id, len(fields))
            for field in fields:
                data += struct.pack(">" + self._di._struct_sizes.field_id,
                                    field)

            unpacker = self.send_command(
                Command.ObjectReference.GetValues,
                data,
                "Could not get instance field values")

            count = unpacker.unpack_next(">I")[0]
            values = []
            for i in xrange(count):
                value = Value()
                value.tag = unpacker.unpack_next(">c")[0]
                value.value = unpacker.unpack_next(
                    ">" + self._di.jni_tags[value.tag].size)[0]
                values += [value]

            return values

        def set_values(self, object_id=0, values=[]):
            """ Sets the value of one or more instance fields. Each field must
            be member of the object's type or one of its superclasses,
            superinterfaces, or implemented interfaces. Access control is not
            enforced; for example, the values of private fields can be set. For
            primitive values, the value's type must match the field's type
            exactly. For object values, there must be a widening reference
            conversion from the value's type to thefield's type and the field's
            type must be loaded.

            The *values* list should be a list of objects, where each object
            has attributes ``field_id`` (the field to set) and ``value`` (the
            value to put in the field).
            """

            original_values = self.get_values(
                object_id, [value.field_id for value in values])

            data = struct.pack(">" + self._di._struct_sizes.object_id + "I",
                               object_id, len(values))

            for i in xrange(len(values)):
                data += struct.pack(">" + self._di._struct_sizes.field_id,
                                    values[i].field_id)
                data += struct.pack(
                    ">" + self._di.jni_tags[original_values[i].tag].size,
                    values[i].value)

            self.send_command(
                Command.ObjectReference.SetValues,
                data,
                "Could not set values")

        def get_monitor_info(self, object_id=0):
            """ Returns monitor information for an object. All threads in the
            VM must be suspended. Requires ``can_get_monitor_info``
            capability - see :any:`capabilities_new`.
            """

            unpacker = self.send_command(
                Command.ObjectReference.MonitorInfo,
                struct.pack(">" + self._di._struct_sizes.object_id, object_id),
                "Could not get monitor information")

            class MonitorInformation:
                owner = 0
                """ The monitor owner, or null if it is not currently owned.
                """

                entry_count = 0
                """ The number of times the monitor has been entered. """

                waiters = []
                """ Threads that are waiting for this monitor. """

            monitor_information = MonitorInformation()
            
            (monitor_information.owner,
             monitor_information.entry_count,
             count) = unpacker.unpack_next(
                ">" + self._di._struct_sizes.object_id + "2I")

            for i in xrange(count):
                monitor_information.waiters += [unpacker.unpack_next(
                    ">" + self._di._struct_sizes.object_id)[0]]

            return monitor_information

        def invoke_method(self, object_id=0, thread=0, class_=0, method_id=0,
                          arguments=[], options=0):
            """ Invokes a static method.

            For more information, see
            http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_ObjectReference_InvokeMethod
            
            Returns a 2-tuple: ``(return_value, exception)``, where ``value``
            is a :any:`Value` and ``exception`` is a :any:`TaggedObjectId`.            
            """

            data = struct.pack(">3" + self._di._struct_sizes.object_id +
                               self._di._struct_sizes.method_id + "I",
                               object_id, thread, class_, method_id,
                               len(arguments))

            for argument in arguments:
                data += struct.pack(">c", argument.tag)
                data += struct.pack(">" + self._di.jni_tags[argument.tag].size,
                                    argument.value)

            data += struct.pack(">i", options)

            unpacker = self.send_command(
                Command.ObjectReference.InvokeMethod,
                data,
                "Could not invoke method")

            return_value = Value()
            return_value.tag = unpacker.unpack_next(">c")[0]
            return_value.value = unpacker.unpack_next(
                ">" + self._di.jni_tags[return_value.tag].size)[0]

            exception = TaggedObjectId()
            (exception.tag, exception.object_id) = unpacker.unpack_next(
                    ">c" + self._di._struct_sizes.object_id)

            return (return_value, exception)

        def disable_collection(self, object_id=0):
            """ Prevents garbage collection for the given object. By default
            all objects in back-end replies may be collected at any time the
            target VM is running. A call to this command guarantees that the
            object will not be collected. The :any:`enable_collection` command
            can be used to allow collection once again.

            Note that while the target VM is suspended, no garbage collection
            will occur because all threads are suspended. The typical
            examination of variables, fields, and arrays during the suspension
            is safe without explicitly disabling garbage collection.

            This method should be used sparingly, as it alters the pattern of
            garbage collection in the target VM and, consequently, may result
            in application behavior under the debugger that differs from its
            non-debugged behavior.
            """

            self.send_command(
                Command.ObjectReference.DisableCollection,
                struct.pack(">" + self._di._struct_sizes.object_id, object_id),
                "Could not disable garbage collection")

        def enable_collection(self, object_id=0):
            """ Permits garbage collection for this object. By default all
            objects returned by JDWP may become unreachable in the target VM,
            and hence may be garbage collected. A call to this command is
            necessary only if garbage collection was previously disabled with
            the :any:`disable_collection` command.
            """

            self.send_command(
                Command.ObjectReference.EnableCollection,
                struct.pack(">" + self._di._struct_sizes.object_id, object_id),
                "Could not enable garbage collection")

        def is_collected(self, object_id=0):
            """ Determines whether an object has been garbage collected in the
            target VM.
            """

            unpacker = self.send_command(
                Command.ObjectReference.IsCollected,
                struct.pack(">" + self._di._struct_sizes.object_id, object_id),
                "Could not determine garbage collection status")

            return unpacker.unpack_next(">?")[0]

        def get_referring_objects(self, object_id=0, max_referrers=0):
            """ Returns objects that directly reference this object. Only
            objects that are reachable for the purposes of garbage collection
            are returned. Note that an object can also be referenced in other
            ways, such as from a local variable in a stack frame, or from a JNI
            global reference. Such non-object referrers are not returned by
            this command.

            Since JDWP version 1.6. Requires ``can_get_instance_info``
            capability - see :any:`capabilities_new`.
            """

            unpacker = self.send_command(
                Command.ObjectReference.ReferringObjects,
                struct.pack(">" + self._di._struct_sizes.object_id + "I",
                            object_id, max_referrers),
                "Could not get referring objects")

            referring_objects = []

            count = unpacker.unpack_next(">I")[0]
            for i in xrange(count):
                instance = TaggedObjectId()
                (instance.tag, instance.object_id) = unpacker.unpack_next(
                    ">c" + self._di._struct_sizes.object_id)
                referring_objects += [instance]

            return referring_objects

    class StringReference(_Command):
        def get_value(self, string_object_id=0):
            """ Returns the characters contained in the string. """

            unpacker = self.send_command(
                Command.StringReference.Value,
                struct.pack(">" + self._di._struct_sizes.object_id,
                            string_object_id),
                "Could not get string value")

            length = unpacker.unpack_next(">I")[0]
            return unpacker.unpack_next(">" + str(length) + "s")[0]

    class ThreadReference(_Command):
        def get_name(self, thread_id=0):
            """ Returns the thread name. """

            unpacker = self.send_command(
                Command.ThreadReference.Name,
                struct.pack(">" + self._di._struct_sizes.object_id, thread_id),
                "Could not get thread name")

            length = unpacker.unpack_next(">I")[0]
            return unpacker.unpack_next(">" + str(length) + "s")[0]

        def suspend(self, thread_id=0):
            """ Suspends the thread.

            Unlike java.lang.Thread.suspend(), suspends of both the virtual
            machine and individual threads are counted. Before a thread will
            run again, it must be resumed the same number of times it has been
            suspended.

            Suspending single threads with command has the same dangers
            java.lang.Thread.suspend(). If the suspended thread holds a monitor
            needed by another running thread, deadlock is possible in the
            target VM (at least until the suspended thread is resumed again).

            The suspended thread is guaranteed to remain suspended until
            resumed through one of the JDI resume methods mentioned above; the
            application in the target VM cannot resume the suspended thread
            through {@link java.lang.Thread#resume}.

            Note that this doesn't change the status of the thread (see the
            :any:`get_status` command.) For example, if it was Running, it will
            still appear running to other threads.
            """

            self.send_command(
                Command.ThreadReference.Suspend,
                struct.pack(">" + self._di._struct_sizes.object_id, thread_id),
                "Could not suspend thread")

        def resume(self, thread_id=0):
            """ Resumes the execution of a given thread. If this thread was not
            previously suspended by the front-end, calling this command has no
            effect. Otherwise, the count of pending suspends on this thread is
            decremented. If it is decremented to 0, the thread will continue to
            execute.
            """

            self.send_command(
                Command.ThreadReference.Resume,
                struct.pack(">" + self._di._struct_sizes.object_id, thread_id),
                "Could not resume thread")

        def get_status(self, thread_id=0):
            """ Returns the current status of a thread. The thread status reply
            indicates the thread status the last time it was running. The
            suspend status provides information on the thread's suspension, if
            any.

            Returns a 2-tuple: ``(thread_status, suspend_status)``, where
            ``thread_status`` is of type :any:`ThreadStatus` and
            ``suspend_status`` is of type :any:`SuspendStatus`.
            """

            unpacker = self.send_command(
                Command.ThreadReference.Status,
                struct.pack(">" + self._di._struct_sizes.object_id, thread_id),
                "Could not get thread status")

            return unpacker.unpack_next(">2i")

        def get_thread_group(self, thread_id=0):
            """ Returns the thread group that contains a given thread. """

            unpacker = self.send_command(
                Command.ThreadReference.ThreadGroup,
                struct.pack(">" + self._di._struct_sizes.object_id, thread_id),
                "Could not get thread group")

            return unpacker.unpack_next(
                ">" + self._di._struct_sizes.object_id)[0]

        def get_frames(self, thread_id=0, start_frame=0, length=0):
            """ Returns the current call stack of a suspended thread. The
            sequence of frames starts with the currently executing frame,
            followed by its caller, and so on. The thread must be suspended,
            and the returned frameID is valid only while the thread is
            suspended.
            """

            class Frame:
                frame_id = 0
                """ The ID of this frame. """

                location = None
                """ The current location of this frame. """

            unpacker = self.send_command(
                Command.ThreadReference.Frames,
                struct.pack(">" + self._di._struct_sizes.object_id + "2i",
                            thread_id, start_frame, length),
                "Could not get call stack")

            frames = []

            count = unpacker.unpack_next(">I")[0]
            for i in xrange(count):
                frame = Frame()
                frame.frame_id = unpacker.unpack_next(
                    ">" + self._di._struct_sizes.frame_id)[0]
                (type, class_id, method_id, index) = unpacker.unpack_next(
                    ">B" + self._di._struct_sizes.object_id +
                    self._di._struct_sizes.method_id + "Q")
                frame.location = Location(self._di, type, class_id, method_id,
                                          index)
                frames += [frame]

            return frames

        def get_frame_count(self, thread_id=0):
            """ Returns the count of frames on this thread's stack. The thread
            must be suspended, and the returned count is valid only while the
            thread is suspended. Returns JDWP.Error.errorThreadNotSuspended if
            not suspended.
            """

            unpacker = self.send_command(
                Command.ThreadReference.FrameCount,
                struct.pack(">" + self._di._struct_sizes.object_id, thread_id),
                "Could not get frame count")

            return unpacker.unpack_next(">I")[0]

        def get_owned_monitors(self, thread_id=0):
            """ Returns the objects whose monitors have been entered by this
            thread. The thread must be suspended, and the returned information
            is relevant only while the thread is suspended. Requires
            ``can_get_owned_monitor_info`` capability - see
            :any:`capabilities_new`.
            """

            unpacker = self.send_command(
                Command.ThreadReference.OwnedMonitors,
                struct.pack(">" + self._di._struct_sizes.object_id, thread_id),
                "Could not get monitors")

            monitors = []

            count = unpacker.unpack_next(">I")[0]
            for i in xrange(count):
                monitor = TaggedObjectId()
                (monitor.tag, monitor.object_id) = unpacker.unpack_next(
                    ">c" + self._di._struct_sizes.object_id)
                monitors += [monitor]

            return monitors

        def get_current_contended_monitor(self, thread_id=0):
            """ Returns the object, if any, for which this thread is waiting.
            The thread may be waiting to enter a monitor, or it may be waiting,
            via the java.lang.Object.wait method, for another thread to invoke
            the notify method. The thread must be suspended, and the returned
            information is relevant only while the thread is suspended.
            Requires ``can_get_current_contended_monitor`` capability - see
            :any:`capabilities_new`.
            """

            unpacker = self.send_command(
                Command.ThreadReference.CurrentContendedMonitor,
                struct.pack(">" + self._di._struct_sizes.object_id, thread_id),
                "Could not get contended monitor")

            monitor = TaggedObjectId()
            (monitor.tag, monitor.object_id) = unpacker.unpack_next(
                ">c" + self._di._struct_sizes.object_id)

            return monitor

        def stop(self, thread_id=0, throwable=0):
            """ Stops the thread with an asynchronous exception, as if done by
            java.lang.Thread.stop.
            """

            self.send_command(
                Command.ThreadReference.Stop,
                struct.pack(">2" + self._di._struct_sizes.object_id, thread_id,
                            throwable),
                "Could not stop thread")

        def interrupt(self, thread_id=0):
            """ Interrupt the thread, as if done by java.lang.Thread.interrupt.
            """

            self.send_command(
                Command.ThreadReference.Interrupt,
                struct.pack(">" + self._di._struct_sizes.object_id, thread_id),
                "Could not interrupt thread")

        def get_suspend_count(self, thread_id=0):
            """ Get the suspend count for this thread. The suspend count is the
            number of times the thread has been suspended through the
            thread-level or VM-level suspend commands without a corresponding
            resume.
            """

            unpacker = self.send_command(
                Command.ThreadReference.SuspendCount,
                struct.pack(">" + self._di._struct_sizes.object_id, thread_id),
                "Could not get suspend count")

            return unpacker.unpack_next(">i")[0]

        def get_owned_monitors_stack_depth_info(self, thread_id=0):
            """ Returns monitor objects owned by the thread, along with stack
            depth at which the monitor was acquired. Returns stack depth of -1
            if the implementation cannot determine the stack depth (e.g., for
            monitors acquired by JNI MonitorEnter).The thread must be
            suspended, and the returned information is relevant only while the
            thread is suspended. Requires ``can_get_monitor_frame_info``
            capability - see :any:`capabilities_new`.

            Since JDWP version 1.6.
            """

            class OwnedMonitor:
                monitor = 0
                """ An owned monitor. """

                stack_depth = 0
                """ Stack depth location where monitor was acquired. """

            unpacker = self.send_command(
                Command.ThreadReference.OwnedMonitorsStackDepthInfo,
                struct.pack(">" + self._di._struct_sizes.object_id, thread_id),
                "Could not get monitor objects")

            owned_monitors = []
            
            count = unpacker.unpack_next(">I")[0]
            for i in xrange(count):
                owned_monitor = OwnedMonitor()
                owned_monitor.monitor = TaggedObjectId()
                (owned_monitor.monitor.tag,
                owned_monitor.monitor.object_id) = unpacker.unpack_next(
                    ">c" + self._di._struct_sizes.object_id)
                owned_monitor.stack_depth = unpacker.unpack_next(">i")[0]
                owned_monitors += [owned_monitor]

            return owned_monitors

        def force_early_return(self, thread_id=0, value=None):
            """ Force a method to return before it reaches a return statement.

            For more information, see
            http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_ThreadReference_ForceEarlyReturn
            """

            self.send_command(
                Command.ThreadReference.ForceEarlyReturn,
                struct.pack(">" + self._di._struct_sizes.object_id + "c" +
                            self._di.jni_tags[value.tag].size, thread_id,
                            value.tag, value.value),
                "Could not force method to return early")

    class ThreadGroupReference(_Command):
        def get_name(self, thread_group_id=0):
            """ Returns the thread group name. """

            unpacker = self.send_command(
                Command.ThreadGroupReference.Name,
                struct.pack(">" + self._di._struct_sizes.object_id,
                            thread_group_id),
                "Could not get thread group name")

            length = unpacker.unpack_next(">I")[0]
            return unpacker.unpack_next(">" + str(length) + "s")[0]

        def get_parent(self, thread_group_id=0):
            """ Returns the thread group, if any, which contains a given thread
            group.
            """

            unpacker = self.send_command(
                Command.ThreadGroupReference.Parent,
                struct.pack(">" + self._di._struct_sizes.object_id,
                            thread_group_id),
                "Could not get thread group parent")

            return unpacker.unpack_next(
                ">" + self._di._struct_sizes.object_id)[0]

        def get_children(self, thread_group_id=0):
            """ Returns the live threads and active thread groups directly
            contained in this thread group. Threads and thread groups in child
            thread groups are not included. A thread is alive if it has been
            started and has not yet been stopped. See java.lang.ThreadGroup
            (http://docs.oracle.com/javase/8/docs/api/java/lang/ThreadGroup.html)
            for information about active ThreadGroups.

            Returns a 2-tuple: ``(child_threads, child_groups)``, where
            ``child_threads`` is a list of direct child thread IDs, and
            ``child_groups`` is a list of direct child thread group IDs.
            """

            unpacker = self.send_command(
                Command.ThreadGroupReference.Children,
                struct.pack(">" + self._di._struct_sizes.object_id,
                            thread_group_id),
                "Could not get thread group children")

            child_threads = []
            count = unpacker.unpack_next(">I")[0]
            for i in xrange(count):
                child_threads += [unpacker.unpack_next(
                    ">" + self._di._struct_sizes.object_id)[0]]

            child_groups = []
            count = unpacker.unpack_next(">I")[0]
            for i in xrange(count):
                child_groups += [unpacker.unpack_next(
                    ">" + self._di._struct_sizes.object_id)[0]]

            return (child_threads, child_groups)

    class ArrayReference(_Command):
        def get_length(self, array_object_id=0):
            """ Returns the number of components in a given array. """

            unpacker = self.send_command(
                Command.ArrayReference.Length,
                struct.pack(">" + self._di._struct_sizes.object_id,
                            array_object_id),
                "Could not get array length")

            return unpacker.unpack_next(">I")[0]

        def get_values(self, array_object_id=0, first_index=0, length=0):
            """ Returns a range of array components. The specified range must
            be within the bounds of the array.
            """

            unpacker = self.send_command(
                Command.ArrayReference.GetValues,
                struct.pack(">" + self._di._struct_sizes.object_id + "2I",
                            array_object_id, first_index, length),
                "Could not get array values")

            (tag, count) = unpacker.unpack_next(">cI")
            values = []
            for i in xrange(count):
                value = Value()
                if tag in "BCFDIJSVZ":
                    value.tag = tag
                    value.value = unpacker.unpack_next(
                        ">" + self._di.jni_tags[tag].size)[0]
                else:
                    value.tag = unpacker.unpack_next(">c")[0]
                    value.value = unpacker.unpack_next(
                        ">" + self._di.jni_tags[value.tag].size)[0]
                values += [value]

            return values

        def set_values(self, array_object_id=0, first_index=0, values=[]):
            """ Sets a range of array components. The specified range must be
            within the bounds of the array. For primitive values, each value's
            type must match the array component type exactly. For object
            values, there must be a widening reference conversion from the
            value's type to the array component type and the array component
            type must be loaded.
            """

            signature = self._di.reference_type.get_signature(array_object_id)
            if signature[0] != "[":
                raise Exception("Unexpected JNI string for array object")

            data = struct.pack(">" + self._di._struct_sizes.object_id + "2I",
                            array_object_id, first_index, len(values))
            for value in values:
                data += struct.pack(">" + self._di.jni_tags[signature[1]].size,
                                    value)

            self.send_command(
                Command.ArrayReference.SetValues,
                data,
                "Could not set array values")

    class ClassLoaderReference(_Command):
        def get_visible_classes(self, class_loader_id=0):
            """ Returns a list of all classes which this class loader has been
            requested to load. This class loader is considered to be an
            initiating class loader for each class in the returned list. The
            list contains each reference type defined by this loader and any
            types for which loading was delegated by this class loader to
            another class loader.

            The visible class list has useful properties with respect to the
            type namespace. A particular type name will occur at most once in
            the list. Each field or variable declared with that type name in a
            class defined by this class loader must be resolved to that single
            type.

            No ordering of the returned list is guaranteed.
            """

            unpacker = self.send_command(
                Command.ClassLoaderReference.VisibleClasses,
                struct.pack(">" + self._di._struct_sizes.object_id,
                            class_loader_id),
                "Could not get visible classes")

            visible_classes = []

            count = unpacker.unpack_next(">I")[0]
            for i in xrange(count):
                visible_class = ReferenceType()
                (visible_class.ref_type_tag,
                visible_class.type_id) = unpacker.unpack_next(
                    ">B" + self._di._struct_sizes.object_id)
                visible_classes += [visible_class]

            return visible_classes

    class EventRequest(_Command):
        def set(self, event_kind=0, suspend_policy=SuspendPolicy.ALL,
                modifiers=[]):
            """ Set an event request. When the event described by this request
            occurs, an event
            (http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_Event)
            is sent from the target VM. If an event occurs that has not been
            requested then it is not sent from the target VM. The two
            exceptions to this are the VM Start Event and the VM Death Event
            which are automatically generated events - see Composite Command
            (http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_Event_Composite)
            for further details.

            The *event_kind* value should be a defined :any:`EventKind` value.

            The *suspend_policy* value should be a defined :any:`SuspendPolicy`
            value.

            The *modifiers* value should be a list of event modifier objects,
            whose classes are in ``event_modifiers.py``.

            The return value is a 32-bit signed request ID.
            """
            data = struct.pack(">BBi", event_kind, suspend_policy, len(modifiers))
            for modifier in modifiers:
                data += struct.pack(">B", modifier.mod_kind)
                if isinstance(modifier, Modifier.Count):
                    data += struct.pack(">i", modifier.count)
                elif isinstance(modifier, Modifier.Conditional):
                    data += struct.pack(">i", modifier.expr_id)
                elif isinstance(modifier, Modifier.ThreadOnly):
                    data += struct.pack(
                        ">" + self._di._struct_sizes.object_id,
                        modifier.thread)
                elif isinstance(modifier, Modifier.ClassOnly):
                    data += struct.pack(
                        ">" + self._di._struct_sizes.reference_type_id,
                        modifier.class_)
                elif isinstance(modifier, Modifier.ClassMatch) or isinstance(
                                modifier, Modifier.ClassExclude):
                    data += struct.pack(
                        ">i" + str(len(modifier.class_pattern)) + "s",
                        len(modifier.class_pattern), modifier.class_pattern)
                elif isinstance(modifier, Modifier.LocationOnly):
                    data += modifier.loc.location
                elif isinstance(modifier, Modifier.ExceptionOnly):
                    data += struct.pack(
                        ">" + self._di._struct_sizes.reference_type_id + "BB",
                        modifier.exception_or_null,
                        modifier.caught,
                        modifier.uncaught)
                elif isinstance(modifier, Modifier.FieldOnly):
                    data += struct.pack(
                        ">" + self._di._struct_sizes.reference_type_id +
                        self._di._struct_sizes.field_id,
                        modifier.declaring,
                        modifier.field_id)
                elif isinstance(modifier, Modifier.Step):
                    data += struct.pack(
                        ">" + self._di._struct_sizes.object_id + "ii",
                        modifier.thread,
                        modifier.size,
                        modifier.depth)
                elif isinstance(modifier, Modifier.InstanceOnly):
                    data += struct.pack(">" + self._di._struct_sizes.object_id,
                                        modifier.instance)
                elif isinstance(modifier, Modifier.SourceNameMatch):
                    data += struct.pack(
                        ">i" + str(len(modifier.source_name_pattern)) + "s",
                        len(modifier.source_name_pattern),
                        modifier.source_name_pattern)
                else:
                    raise Exception("Unknown modifier type")

            unpacker = self.send_command(
                Command.EventRequest.Set,
                data,
                "Couldn't set event request")
        
            return unpacker.unpack_next(">i")[0]

        def clear(self, event_kind=0, request_id=0):
            """ Clear an event request. See JDWP.EventKind 
            (http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_EventKind)
            for a complete list of events that can be cleared. Only the event
            request matching the specified event kind and requestID is cleared.
            If there isn't a matching event request the command is a no-op and
            does not result in an error. Automatically generated events do not
            have a corresponding event request and may not be cleared using
            this command.
            """

            self.send_command(
                Command.EventRequest.Clear,
                struct.pack(">Bi", event_kind, request_id),
                "Could not clear event request")

        def clear_all_breakpoints(self):
            """ Removes all set breakpoints, a no-op if there are no
            breakpoints set.
            """

            self.send_command(
                Command.EventRequest.ClearAllBreakpoints,
                "",
                "Could not clear all breakpoints")

    class StackFrame(_Command):
        def get_values(self, thread_id=0, frame_id=0, slots=[]):
            """ Returns the value of one or more local variables in a given
            frame. Each variable must be visible at the frame's code index.
            Even if local variable information is not available, values can be
            retrieved if the front-end is able to determine the correct local
            variable index. (Typically, this index can be determined for method
            arguments from the method signature without access to the local
            variable table information.)
            """

            data = struct.pack(
                    ">" + self._di._struct_sizes.object_id +
                    self._di._struct_sizes.frame_id + "I",
                    thread_id, frame_id, len(slots))

            for slot in slots:
                data += struct.pack(">ic", slot.slot, slot.sig_byte)

            unpacker = self.send_command(
                Command.StackFrame.GetValues,
                data,
                "Could not get values from stack frame")

            values = []
            for i in xrange(unpacker.unpack_next(">I")[0]):
                value = Value()
                value.tag = unpacker.unpack_next(">c")[0]
                value.value = unpacker.unpack_next(
                    ">" + self._di.jni_tags[value.tag].size)[0]
                values += [value]

            return values

        def set_values(self, thread_id=0, frame_id=0, slot_values=[]):
            """ Sets the value of one or more local variables. Each variable
            must be visible at the current frame code index. For primitive
            values, the value's type must match the variable's type exactly.
            For object values, there must be a widening reference conversion
            from the value's type to thevariable's type and the variable's type
            must be loaded.

            Even if local variable information is not available, values can be
            set, if the front-end is able to determine the correct local
            variable index. (Typically, thisindex can be determined for method
            arguments from the method signature without access to the local
            variable table information.)
            """

            data = struct.pack(
                    ">" + self._di._struct_sizes.object_id +
                    self._di._struct_sizes.frame_id + "I",
                    thread_id, frame_id, len(slot_values))

            for slot_value in slot_values:
                data += struct.pack(">i", slot_value.slot)
                data += struct.pack(">c", slot_value.value.tag)
                data += struct.pack(
                    ">" + self._di.jni_tags[slot_value.value.tag].size,
                    slot_value.value.value)

            self.send_command(
                Command.StackFrame.SetValues,
                data,
                "Could not set values in stack frame")

        def get_this_object(self, thread_id=0, frame_id=0):
            """ Returns the value of the 'this' reference for this frame. If
            the frame's method is static or native, the reply will contain the
            null object reference.

            The returned value is a :any:`TaggedObjectId`.
            """

            unpacker = self.send_command(
                Command.StackFrame.ThisObject,
                struct.pack(
                    ">" + self._di._struct_sizes.object_id +
                    self._di._struct_sizes.frame_id, thread_id, frame_id),
                "Could not get the value of 'this'")

            tagged_object_id = TaggedObjectId()
            (tagged_object_id.tag,
            tagged_object_id.object_id) = unpacker.unpack_next(
                    ">c" + self._di._struct_sizes.object_id)
            return tagged_object_id

        def pop_frames(self, thread_id=0, frame_id=0):
            """ Pop the top-most stack frames of the thread stack, up to, and
            including 'frame'. The thread must be suspended to perform this
            command. The top-most stack frames are discarded and the stack
            frame previous to 'frame' becomes the current frame. The operand
            stack is restored -- the argument values are added back and if the
            invoke was not invokestatic, objectref is added back as well. The
            Java virtual machine program counter is restored to the opcode of
            the invoke instruction.

            Since JDWP version 1.4. Requires ``can_pop_frames`` capability -
            see :any:`capabilities_new`.
            """

            self.send_command(
                Command.StackFrame.PopFrames,
                struct.pack(
                    ">" + self._di._struct_sizes.object_id +
                    self._di._struct_sizes.frame_id, thread_id, frame_id),
                "Could not pop frames")

    class ClassObjectReference(_Command):
        def get_reflected_type(self, class_object_id=0):
            """ Returns the reference type reflected by this class object. """

            unpacker = self.send_command(
                Command.ClassObjectReference.ReflectedType,
                struct.pack(
                    ">" + self._di._struct_sizes.object_id, class_object_id),
                "Could not get reflected type")

            reference_type = ReferenceType()
            (reference_type.ref_type_tag,
            reference_type.type_id) = unpacker.unpack_next(
                ">B" + self._di._struct_sizes.object_id)

            return reference_type


class Class:
    ref_type_tag = ""
    """ Kind of reference type; one of any :any:`TypeTag` values. """

    type_id = 0
    """ Matching loaded reference type. """

    signature = ""
    """ The JNI signature of the loaded reference type. """

    generic_signature = ""
    """ The generic signature of the loaded reference type or an empty string
    if there is none.
    """

    status = 0
    """ The current class status; one of any :any:`ClassStatus`
    values.
    """


class ReferenceType:
    ref_type_tag = 0
    """ :any:`TypeTag` of following reference type. """

    type_id = 0
    """ Reference type ID. """


class Location:
    """ An executable location as defined by JDWP. For details, see
    http://docs.oracle.com/javase/8/docs/technotes/guides/jpda/jdwp-spec.html
    """

    type = 0
    """ A :any:`TypeTag` value. """

    class_id = 0
    """ A JDWP ``classID`` value. """

    method_id = 0
    """ A JDWP ``methodID`` value. """

    index = 0
    """ An index that identifies a location within the method. """

    location = ""
    """ The raw interpretation of this location as a JDWP byte string. """

    def __init__(self, di, type=0, class_id=0, method_id=0, index=0, location=""):
        """ The :any:`Location` constructor constructs a :any:`Location` object
        from either a *location* byte string **or** from a *type*, *class_id*,
        *method_id*, and *index*.

        The *di* value must be a reference to a :any:`DebugInterface` object.
        """

        fmt = ">B" + di._struct_sizes.reference_type_id + di._struct_sizes.method_id + "Q"

        if location != "":
            self.type, self.class_id, self.method_id, self.index = struct.unpack(
                fmt, location)
            self.location = location
        else:
            self.location = struct.pack(fmt, type, class_id, method_id, index)
            self.type = type
            self.class_id = class_id
            self.method_id = method_id
            self.index = index


class TaggedObjectId:
    tag = ""
    """ Single-character type signature representation. """

    object_id = 0
    """ Object ID. """


class Value:
    """ A value retrieved from the target VM. """

    tag = ""
    """ Single-character type signature representation. """

    value = 0
    """ An object ID or a primitive value. """

    def __init__(self, tag="", value=0):
        self.tag = tag
        self.value = value


class Method:
    """ The :any:`Method` class defines a Java method. """

    method_id = 0
    """ Method ID. """

    name = ""
    """ Name of method. """

    signature = ""
    """ JNI signature of method. """

    generic_signature = ""
    """ The generic signature of the method, or an empty string if there is
    none.
    """

    mod_bits = 0
    """ The modifier bit flags (also known as access flags) which
    provide additional information on the field declaration.
    Individual flag values are defined in Chapter 4 of The Java
    Virtual Machine Specification. In addition, The 0xf0000000 bit
    identifies the field as synthetic, if the synthetic attribute
    capability (:any:`capabilities`) is available.
    """


class JniTag:
    """ https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/types.html """

    tag = ""
    """ Single-character type signature representation. """

    name = ""
    """ Human-readable Java type string. """

    size = ""
    """ The size of the type as a ``struct`` format character. """

    def __init__(self, tag, name, size):
        self.tag = tag
        self.name = name
        self.size = size


class Parameter:
    """ A method parameter. """

    tag = None
    """ The parameter's :any:`JniTag`. """

    name = None
    """ A string that represents the name of the parameter, or ``None`` if no
    name can be determined.
    """

    def __init__(self, tag=None, name=None):
        self.tag = tag
        self.name = name


class Field:
    field_id = 0
    """ Field ID. """

    name = ""
    """ Name of field. """

    signature = ""
    """ JNI Signature of field. """

    generic_signature = ""
    """ The generic signature of the field, or an empty string if there is
    none.
    """

    mod_bits = 0
    """ The modifier bit flags (also known as access flags) which
    provide additional information on the field declaration.
    Individual flag values are defined in Chapter 4 of The Java
    Virtual Machine Specification. In addition, The 0xf0000000 bit
    identifies the field as synthetic, if the synthetic attribute
    capability (:any:`capabilities`) is available.
    """


class JdwpCommandError(Exception):
    def __init__(self,*args,**kwargs):
        super(JdwpCommandError, self).__init__(args[0])
        self.error_code = args[1]
