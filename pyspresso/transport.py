#!/usr/bin/python
## @file        transport.py
#  @brief       Debug transports for the Java Debug Wire Protocol
#               (http://docs.oracle.com/javase/8/docs/technotes/guides/jpda/jdwp-spec.html)
#  @author      Jason Geffner
#  @copyright   CrowdStrike, Inc. 2016

import socket
import time
import struct
import os
import mmap
import ctypes
import threading
import itertools
import array


class DebugTransport:
    """ The :any:`DebugTransport` class defines JDWP transports for both
    shared-memory-based transport and socket-based transport.
    """

    class AtomicCounter:
        """ Atomic "fetch and increment" class for packet IDs. """
        def __init__(self):
            self._counter = itertools.count()
            self._lock = threading.Lock()
        def next(self):
            """ Return the next 32-bit packet ID. """
            with self._lock:
                return self._counter.next() & 0xFFFFFFFF


    def __init__(self, transport="dt_shmem", server=False, address=None):
        """ The :any:`DebugTransport` constructor initializes member variables
        and binds transport-specific functions.

        The *transport* value should be ``"dt_shmem"`` for shared-memory-based
        transport or ``"dt_socket"`` for socket-based transport.

        If the *server* value is ``True`` then the debugger acts as the server
        and the debuggee acts as the client. Otherwise, the debuggee acts as
        the server and the debugger acts as the client.
        
        The *address* value should be in the format ``"hostname:port"`` for
        socket-based transport, or should be the shared file mapping name for
        shared-memory-based transport.
        """

        self._address = address
        self._id = self.AtomicCounter()

        if server:
            raise Exception("Debug server not yet implemented")

        if transport == "dt_shmem":
            if os.name != "nt":
                raise Exception("Shared memory transport is only available on Windows")
        elif transport != "dt_socket":
            raise Exception("Invalid transport type")

        if address is None:
            if transport == "dt_shmem":
                self._address = "javadebug"
            else:
                raise Exception("address required for dt_socket")

        # Bind transport-specific functions.
        for method in ("attach", "send", "send_packet", "recv", "recv_packet"):
            setattr(self, method, getattr(self, "_" + method + "_" + transport[3:]))

    def attach(self):
        """ Attach to the debuggee. """
        raise Exception("Abstract method called")

    def send(self, bytes):
        """ Send bytes to the debuggee. """
        raise Exception("Abstract method called")
    
    def send_packet(self, packet):
        """ Decode and send a JDWP :any:`CommandPacket` to the debuggee. """
        raise Exception("Abstract method called")
    
    def recv(self, count):
        """ Receive bytes from the debuggee. """
        raise Exception("Abstract method called")
    
    def recv_packet(self):
        """ Receive the next :any:`CommandPacket` or :any:`ReplyPacket` from
        the debuggee.
        """
        raise Exception("Abstract method called")
    
    def handshake(self):
        """ Perform the initial handshake with the debuggee. """
        h = "JDWP-Handshake"
        self.send(h)
        if self.recv(len(h)) != h:
            raise Exception("Unexpected handshake response")

    def make_packet(self, command, data=""):
        """ Create a JDWP :any:`CommandPacket`. """
        return CommandPacket(self._id.next(), command, data)


    #
    # Shared-memory-based transport. Currently only implemented for Windows.
    #
    # Based on:
    # http://hg.openjdk.java.net/jdk8/jdk8/jdk/file/tip/src/share/transport/shmem/shmemBase.c
    # http://hg.openjdk.java.net/jdk8/jdk8/jdk/file/tip/src/windows/transport/shmem/shmem_md.c
    #

    class Mutex():
        """ Mutex class to support Python's ``with`` statement. """

        def __init__(self, handle):
            if handle == 0:
                raise WindowsError("Invalid mutex handle")
            self.handle = handle
        def __enter__(self):
            # Wait on mutex.
            return ctypes.windll.kernel32.WaitForSingleObject(self.handle, -1)
        def __exit__(self, type, value, traceback):
            # Release the mutex.
            ctypes.windll.kernel32.ReleaseMutex(self.handle)


    def _wait_for_object(self, object_handle):
        wait_value = ctypes.windll.kernel32.WaitForMultipleObjects(
            2,
            (ctypes.wintypes.HANDLE * 2)(self.debuggee_handle, object_handle),
            False,
            -1)
        if wait_value == 0:
            raise WindowsError("Remote process terminated")
        elif wait_value == 1:
            return
        else:
            raise WindowsError("Error while waiting for a synchronization object")

    def _attach_shmem(self):
        #
        # Initialize ctypes values.
        #

        import ctypes.wintypes

        FILE_MAP_READ = 4
        SYNCHRONIZE = 0x00100000
        EVENT_MODIFY_STATE = 2
        ctypes.windll.kernel32.OpenFileMappingW.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.LPCWSTR]
        ctypes.windll.kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
        ctypes.windll.kernel32.OpenProcess.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
        ctypes.windll.kernel32.WaitForSingleObject.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD]
        ctypes.windll.kernel32.WaitForMultipleObjects.argtypes = [ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.HANDLE), ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
        ctypes.windll.kernel32.ReleaseMutex.argtypes = [ctypes.wintypes.HANDLE]
        ctypes.windll.kernel32.OpenMutexW.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.LPCWSTR]
        ctypes.windll.kernel32.OpenEventW.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.LPCWSTR]
        ctypes.windll.kernel32.SetEvent.argtypes = [ctypes.wintypes.HANDLE]

        #
        # Notify the client that we're attaching.
        #

        class SharedListener(ctypes.Structure):
            _fields_ = [("mutexName", ctypes.c_char * 75),
                        ("acceptEventName", ctypes.c_char * 75),
                        ("attachEventName", ctypes.c_char * 75),
                        ("isListening", ctypes.c_bool),
                        ("isAccepted", ctypes.c_bool),
                        ("acceptingPID", ctypes.c_longlong),
                        ("attachingPID", ctypes.c_longlong)]

        # Wait until the mapping exists.
        handle = 0
        while handle == 0:
            handle = ctypes.windll.kernel32.OpenFileMappingW(FILE_MAP_READ, False, self._address)
            time.sleep(.01)
        ctypes.windll.kernel32.CloseHandle(handle)

        # Open SharedListener memory map.
        shared_listener = SharedListener.from_buffer(mmap.mmap(
            0,
            ctypes.sizeof(SharedListener),
            self._address))

        self.debuggee_handle = ctypes.windll.kernel32.OpenProcess(
            SYNCHRONIZE, False, shared_listener.acceptingPID)
        if self.debuggee_handle == 0:
            raise WindowsError("Could not open handle to process ID " +
                               str(shared_listener.acceptingPID))

        # Get SharedListener mutex and event handles.
        with self.Mutex(ctypes.windll.kernel32.OpenMutexW(SYNCHRONIZE, False, shared_listener.mutexName)):
            accept_event = ctypes.windll.kernel32.OpenEventW(
                SYNCHRONIZE | EVENT_MODIFY_STATE,
                False,
                shared_listener.acceptEventName)
            if accept_event == 0:
                raise WindowsError("Could not open event " +
                                   shared_listener.acceptEventName)

            attach_event = ctypes.windll.kernel32.OpenEventW(
                SYNCHRONIZE | EVENT_MODIFY_STATE,
                False,
                shared_listener.attachEventName)
            if attach_event == 0:
                raise WindowsError("Could not open event " +
                                   shared_listener.attachEventName)

            shared_listener.attachingPID = os.getpid()

            # Signal the attach event.
            if ctypes.windll.kernel32.SetEvent(attach_event) == 0:
                raise WindowsError("Could not set event " +
                                   shared_listener.attachEventName)

            # Wait for the accept event.
            self._wait_for_object(accept_event)


            #
            # Initialize incoming and outgoing data streams.
            #

            class SharedStream(ctypes.Structure):
                _fields_ = [("mutexName", ctypes.c_char * 75),
                            ("hasDataEventName", ctypes.c_char * 75),
                            ("hasSpaceEventName", ctypes.c_char * 75),
                            ("readOffset", ctypes.c_int),
                            ("writeOffset", ctypes.c_int),
                            ("isFull", ctypes.c_bool),
                            ("buffer", ctypes.c_byte * 5000)]

            class SharedMemory(ctypes.Structure):
                _fields_ = [("incoming", SharedStream),
                            ("outgoing", SharedStream)]

            self._streams = type("", (), {})

            # Open SharedMemory memory map.
            self._shared_memory = SharedMemory.from_buffer(mmap.mmap(
                0,
                ctypes.sizeof(SharedMemory),
                self._address + "." + str(os.getpid())))

            for stream_name in ("incoming", "outgoing"):
                # Get a reference to the mapped stream's data.
                shared_stream = getattr(self._shared_memory, stream_name)


                #
                # Get a handle to the stream's mutex and events.
                #

                stream = type("", (), {})

                stream.mutex = ctypes.windll.kernel32.OpenMutexW(
                    SYNCHRONIZE,
                    False,
                    shared_stream.mutexName)
                if stream.mutex == 0:
                    raise WindowsError("Could not open mutex " + shared_stream.mutexName)

                stream.hasData = ctypes.windll.kernel32.OpenEventW(
                    SYNCHRONIZE | EVENT_MODIFY_STATE,
                    False,
                    shared_stream.hasDataEventName)
                if stream.hasData == 0:
                    raise WindowsError("Could not open event " + shared_stream.hasDataEventName)
                
                stream.hasSpace = ctypes.windll.kernel32.OpenEventW(
                    SYNCHRONIZE | EVENT_MODIFY_STATE,
                    False,
                    shared_stream.hasSpaceEventName)
                if stream.hasSpace == 0:
                    raise WindowsError("Could not open event " + shared_stream.hasSpaceEventName)

                # Save the stream's handles.
                setattr(self._streams, stream_name, stream)

    def _send_shmem(self, bytes):
        # Use the outgoing stream and the outgoing shared memory.
        stream = self._streams.outgoing
        shared_memory = self._shared_memory.outgoing

        index = 0

        # Send bytes via circular buffer.
        with self.Mutex(stream.mutex) as mutex:
            while index < len(bytes):
                while shared_memory.isFull:
                    if ctypes.windll.kernel32.ReleaseMutex(stream.mutex) == 0:
                        raise WindowsError("Could not release mutex")
                    self._wait_for_object(stream.hasSpace)
                    self._wait_for_object(stream.mutex)
            
                fragment_start = shared_memory.writeOffset
                max_length = (shared_memory.readOffset if fragment_start < shared_memory.readOffset else 5000)- fragment_start
                fragment_length = min(max_length, len(bytes) - index)
                ctypes.memmove(ctypes.addressof(shared_memory.buffer) + fragment_start, bytes[index:index+fragment_length], fragment_length)
                shared_memory.writeOffset = (fragment_start + fragment_length) % 5000
                index += fragment_length
                shared_memory.isFull = (shared_memory.readOffset == shared_memory.writeOffset)
                if ctypes.windll.kernel32.SetEvent(stream.hasData) == 0:
                    raise WindowsError("Could not set event")

    def _send_packet_shmem(self, packet):
        # Send a packet using native-system byte ordering.
        self.send(struct.pack("=IBBBI", packet.id, packet.flags,
                              packet.command_set, packet.command,
                              len(packet.data)) + packet.data)

    def _recv_shmem(self, count):
        # Use the incoming stream and the incoming shared memory.
        stream = self._streams.incoming
        shared_memory = self._shared_memory.incoming

        bytes = [None] * count
        index = 0

        # Receive bytes via circular buffer.
        with self.Mutex(stream.mutex) as mutex:
            while index < count:
                while shared_memory.writeOffset == shared_memory.readOffset and not shared_memory.isFull:
                    if ctypes.windll.kernel32.ReleaseMutex(stream.mutex) == 0:
                        raise WindowsError("Could not release mutex")
                    self._wait_for_object(stream.hasData)
                    self._wait_for_object(stream.mutex)

                fragment_start = shared_memory.readOffset
                max_length = (shared_memory.writeOffset if fragment_start < shared_memory.writeOffset else 5000)- fragment_start
                fragment_length = min(max_length, count - index)
                bytes[index:index+fragment_length] = shared_memory.buffer[fragment_start:fragment_start+fragment_length]
                shared_memory.readOffset = (fragment_start + fragment_length) % 5000
                index += fragment_length
                shared_memory.isFull = False
                if ctypes.windll.kernel32.SetEvent(stream.hasSpace) == 0:
                    raise WindowsError("Could not set event")

        # Convert the byte array into a Python string.
        return array.array("b", bytes).tostring()

    def _recv_packet_shmem(self):
        #
        # Command Packet:
        #     - Header:
        #         - id (4 bytes)
        #         - flags (1 byte)
        #         - command set (1 byte)
        #         - command (1 byte)
        #         - data length (4 bytes)
        #     - data (variable)
        #
        # Reply Packet:
        #     - Header
        #         - id (4 bytes)
        #         - flags (1 byte)
        #         - error code (2 bytes)
        #         - data length (4 bytes)
        #     - data (variable)
        #
        #
        # Note that the structures above are different from what's formally
        # documented in the JDWP spec.
        #
        
        try:
            # Read header.
            header = self.recv(11)
            if len(header) == 0:
                return None

            # Unpack common header.
            packet = Packet()
            packet.id, packet.flags = struct.unpack_from("=IB", header)

            # Parse the packet as a Reply Packet or a Command (Event) Packet.
            if packet.flags & 0x80 != 0:
                error_code, data_length = struct.unpack_from("=HI", header, 5)
            else:
                command_set, command, data_length = struct.unpack_from("=BBI", header, 5)

            # Read variable-length data.
            if data_length > 0:
                data = self.recv(data_length)
                if len(data) == 0:
                    return None
            else:
                data = ""

            # Parse the packet as a Reply Packet or a Command (Event) Packet.
            if packet.flags & 0x80 != 0:
                return ReplyPacket(packet.id, error_code, data, packet.flags)
            else:
                return CommandPacket(packet.id, (command_set, command), data, packet.flags)
        except WindowsError:
            return None


    #
    # Socket-based transport.
    #

    def _attach_socket(self):
        if ":" in self._address:
            host, port = self._address.split(":")
            port = int(port)
        else:
            host = "localhost"
            port = self._address

        self._socket = socket.socket()
        self._socket.connect((host, port))

    def _send_socket(self, bytes):
        self._socket.sendall(bytes)

    def _send_packet_socket(self, packet):
        # Send a Command Packet using big-endian byte ordering.
        self.send(struct.pack(">IIBBB", packet.length, packet.id, packet.flags,
                              packet.command_set, packet.command) + packet.data)

    def _recv_socket(self, count):
        data = ""
        remaining = count
        while remaining > 0:
            try:
                bytes = self._socket.recv(remaining)
            except socket.error:
                bytes = ""
            if len(bytes) == 0:
                break
            data += bytes
            remaining -= len(bytes)
        if len(data) < count:
            return ""
        return data

    def _recv_packet_socket(self):
        #
        # Command Packet:
        #     - Header:
        #         - length (4 bytes)
        #         - id (4 bytes)
        #         - flags (1 byte)
        #         - command set (1 byte)
        #         - command (1 byte)
        #     - data (variable)
        #
        # Reply Packet:
        #     - Header
        #         - length (4 bytes)
        #         - id (4 bytes)
        #         - flags (1 byte)
        #         - error code (2 bytes)
        #     - data (variable)
        #
        
        # Read header.
        header = self.recv(11)
        if len(header) == 0:
            return None

        # Unpack common header.
        packet = Packet()
        packet.length, packet.id, packet.flags = struct.unpack_from(">IIB", header)

        # Read variable-length data.
        if packet.length > 11:
            packet.data = self.recv(packet.length - 11)
            if len(packet.data) == 0:
                return None

        # Parse the packet as a Reply Packet or a Command (Event) Packet.
        if packet.flags & 0x80 != 0:
            return ReplyPacket(packet.id, struct.unpack_from(">H", header, 9)[0], packet.data, packet.flags)
        else:
            return CommandPacket(packet.id, struct.unpack_from(">BB", header, 9), packet.data, packet.flags)


class Packet:
    """ Abstract class for a JDWP packet, as defined at
    http://docs.oracle.com/javase/8/docs/technotes/guides/jpda/jdwp-spec.html
    """

    length = 0
    """ Length of the packet. """

    id = 0
    """ Command/reply packet ID. """

    flags = 0
    """ Packet flags. """
    
    data = ""
    """ Command data or reply data. """


class CommandPacket(Packet):
    """ A JDWP Command :any:`Packet`, as defined at
    http://docs.oracle.com/javase/8/docs/technotes/guides/jpda/jdwp-spec.html
    """

    command_set = 0
    """ Packet's command set. """

    command = 0
    """ Packet's command. """

    def __init__(self, id, command, data="", flags=0):
        self.length = len(data) + 11
        self.id = id
        self.flags = flags
        self.command_set = command[0]
        self.command = command[1]
        self.data = data


class ReplyPacket(Packet):
    """ A JDWP Reply :any:`Packet`, as defined at
    http://docs.oracle.com/javase/8/docs/technotes/guides/jpda/jdwp-spec.html
    """

    error_code = 0
    """ Packet's error response code. """

    def __init__(self, id, error_code, data="", flags=0x80):
        self.length = len(data) + 11
        self.id = id
        self.flags = flags
        self.error_code = error_code
        self.data = data
