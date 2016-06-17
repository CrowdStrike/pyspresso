#!/usr/bin/python
## @file        constants.py
#  @brief       JDWP debug constants.
#  @author      Jason Geffner
#  @copyright   CrowdStrike, Inc. 2016


class Command:
    """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html """
    class VirtualMachine:
        """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_VirtualMachine """
        Version = (1, 1)
        ClassesBySignature = (1, 2)
        AllClasses = (1, 3)
        AllThreads = (1, 4)
        TopLevelThreadGroups = (1, 5)
        Dispose = (1, 6)
        IDSizes = (1, 7)
        Suspend = (1, 8)
        Resume = (1, 9)
        Exit = (1, 10)
        CreateString = (1, 11)
        Capabilities = (1, 12)
        ClassPaths = (1, 13)
        DisposeObjects = (1, 14)
        HoldEvents = (1, 15)
        ReleaseEvents = (1, 16)
        CapabilitiesNew = (1, 17)
        RedefineClasses = (1, 18)
        SetDefaultStratum = (1, 19)
        AllClassesWithGeneric = (1, 20)
        InstanceCounts = (1, 21)
    class ReferenceType:
        """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_ReferenceType """
        Signature = (2, 1)
        ClassLoader = (2, 2)
        Modifiers = (2, 3)
        Fields = (2, 4)
        Methods = (2, 5)
        GetValues = (2, 6)
        SourceFile = (2, 7)
        NestedTypes = (2, 8)
        Status = (2, 9)
        Interfaces = (2, 10)
        ClassObject = (2, 11)
        SourceDebugExtension = (2, 12)
        SignatureWithGeneric = (2, 13)
        FieldsWithGeneric = (2, 14)
        MethodsWithGeneric = (2, 15)
        Instances = (2, 16)
        ClassFileVersion = (2, 17)
        ConstantPool = (2, 18)
    class ClassType:
        """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_ClassType """
        Superclass = (3, 1)
        SetValues = (3, 2)
        InvokeMethod = (3, 3)
        NewInstance = (3, 4)
    class ArrayType:
        """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_ArrayType """
        NewInstance = (4, 1)
    class InterfaceType:
        """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_InterfaceType """
        InvokeMethod = (5, 1)
    class Method:
        """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_Method """
        LineTable = (6, 1)
        VariableTable = (6, 2)
        Bytecodes = (6, 3)
        IsObsolete = (6, 4)
        VariableTableWithGeneric = (6, 5)
    class Field:
        """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_Field """
        pass
    class ObjectReference:
        """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_ObjectReference """
        ReferenceType = (9, 1)
        GetValues = (9, 2)
        SetValues = (9, 3)
        MonitorInfo = (9, 5)
        InvokeMethod = (9, 6)
        DisableCollection = (9, 7)
        EnableCollection = (9, 8)
        IsCollected = (9, 9)
        ReferringObjects = (9, 10)
    class StringReference:
        """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_StringReference """
        Value = (10, 1)
    class ThreadReference:
        """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_ThreadReference """
        Name = (11, 1)
        Suspend = (11, 2)
        Resume = (11, 3)
        Status = (11, 4)
        ThreadGroup = (11, 5)
        Frames = (11, 6)
        FrameCount = (11, 7)
        OwnedMonitors = (11, 8)
        CurrentContendedMonitor = (11, 9)
        Stop = (11, 10)
        Interrupt = (11, 11)
        SuspendCount = (11, 12)
        OwnedMonitorsStackDepthInfo = (11, 13)
        ForceEarlyReturn = (11, 14)
    class ThreadGroupReference:
        """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_ThreadGroupReference """
        Name = (12, 1)
        Parent = (12, 2)
        Children = (12, 3)
    class ArrayReference:
        """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_ArrayReference """
        Length = (13, 1)
        GetValues = (13, 2)
        SetValues = (13, 3)
    class ClassLoaderReference:
        """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_ClassLoaderReference """
        VisibleClasses = (14, 1)
    class EventRequest:
        """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_EventRequest """
        Set = (15, 1)
        Clear = (15, 2)
        ClearAllBreakpoints = (15, 3)
    class StackFrame:
        """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_StackFrame """
        GetValues = (16, 1)
        SetValues = (16, 2)
        ThisObject = (16, 3)
        PopFrames = (16, 4)
    class ClassObjectReference:
        """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_ClassObjectReference """
        ReflectedType = (17, 1)
    class Event:
        """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_Event """
        Composite = (64, 100)

class Error:
    """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_Error """
    NONE = 0
    INVALID_THREAD = 10
    INVALID_THREAD_GROUP = 11
    INVALID_PRIORITY = 12
    THREAD_NOT_SUSPENDED = 13
    THREAD_SUSPENDED = 14
    THREAD_NOT_ALIVE = 15
    INVALID_OBJECT = 20
    INVALID_CLASS = 21
    CLASS_NOT_PREPARED = 22
    INVALID_METHODID = 23
    INVALID_LOCATION = 24
    INVALID_FIELDID = 25
    INVALID_FRAMEID = 30
    NO_MORE_FRAMES = 31
    OPAQUE_FRAME = 32
    NOT_CURRENT_FRAME = 33
    TYPE_MISMATCH = 34
    INVALID_SLOT = 35
    DUPLICATE = 40
    NOT_FOUND = 41
    INVALID_MONITOR = 50
    NOT_MONITOR_OWNER = 51
    INTERRUPT = 52
    INVALID_CLASS_FORMAT = 60
    CIRCULAR_CLASS_DEFINITION = 61
    FAILS_VERIFICATION = 62
    ADD_METHOD_NOT_IMPLEMENTED = 63
    SCHEMA_CHANGE_NOT_IMPLEMENTED = 64
    INVALID_TYPESTATE = 65
    HIERARCHY_CHANGE_NOT_IMPLEMENTED = 66
    DELETE_METHOD_NOT_IMPLEMENTED = 67
    UNSUPPORTED_VERSION = 68
    NAMES_DONT_MATCH = 69
    CLASS_MODIFIERS_CHANGE_NOT_IMPLEMENTED = 70
    METHOD_MODIFIERS_CHANGE_NOT_IMPLEMENTED = 71
    NOT_IMPLEMENTED = 99
    NULL_POINTER = 100
    ABSENT_INFORMATION = 101
    INVALID_EVENT_TYPE = 102
    ILLEGAL_ARGUMENT = 103
    OUT_OF_MEMORY = 110
    ACCESS_DENIED = 111
    VM_DEAD = 112
    INTERNAL = 113
    UNATTACHED_THREAD = 115
    INVALID_TAG = 500
    ALREADY_INVOKING = 502
    INVALID_INDEX = 503
    INVALID_LENGTH = 504
    INVALID_STRING = 506
    INVALID_CLASS_LOADER = 507
    INVALID_ARRAY = 508
    TRANSPORT_LOAD = 509
    TRANSPORT_INIT = 510
    NATIVE_METHOD = 511
    INVALID_COUNT = 512

class EventKind:
    """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_EventKind """
    SINGLE_STEP = 1
    BREAKPOINT = 2
    FRAME_POP = 3
    EXCEPTION = 4
    USER_DEFINED = 5
    THREAD_START = 6
    THREAD_DEATH = 7
    THREAD_END = 7
    CLASS_PREPARE = 8
    CLASS_UNLOAD = 9
    CLASS_LOAD = 10
    FIELD_ACCESS = 20
    FIELD_MODIFICATION = 21
    EXCEPTION_CATCH = 30
    METHOD_ENTRY = 40
    METHOD_EXIT = 41
    METHOD_EXIT_WITH_RETURN_VALUE = 42
    MONITOR_CONTENDED_ENTER = 43
    MONITOR_CONTENDED_ENTERED = 44
    MONITOR_WAIT = 45
    MONITOR_WAITED = 46
    VM_START = 90
    VM_INIT = 90
    VM_DEATH = 99
    VM_DISCONNECTED = 100

class ThreadStatus:
    """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_ThreadStatus """
    ZOMBIE = 0
    RUNNING = 1
    SLEEPING = 2
    MONITOR = 3
    WAIT = 4

class SuspendStatus:
    """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_SuspendStatus """
    SUSPEND_STATUS_SUSPENDED = 1

class ClassStatus:
    """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_ClassStatus """
    VERIFIED = 1
    PREPARED = 2
    INITIALIZED = 4
    ERROR = 8

class TypeTag:
    """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_TypeTag """
    CLASS = 1
    INTERFACE = 2
    ARRAY = 3

class Tag:
    """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_Tag """
    ARRAY = 91
    BYTE = 66
    CHAR = 67
    OBJECT = 76
    FLOAT = 70
    DOUBLE = 68
    INT = 73
    LONG = 74
    SHORT = 83
    VOID = 86
    BOOLEAN = 90
    STRING = 115
    THREAD = 116
    THREAD_GROUP = 103
    CLASS_LOADER = 108
    CLASS_OBJECT = 99

class StepDepth:
    """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_StepDepth """
    INTO = 0
    OVER = 1
    OUT = 2

class StepSize:
    """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_StepSize """
    MIN = 0
    LINE = 1

class SuspendPolicy:
    """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_SuspendPolicy """
    NONE = 0
    EVENT_THREAD = 1
    ALL = 2

class InvokeOptions:
    """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_InvokeOptions """
    INVOKE_SINGLE_THREADED = 1
    INVOKE_NONVIRTUAL = 2

class AccessFlags:
    """ https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.6 """
    PUBLIC = 0x0001
    PRIVATE = 0x0002
    PROTECTED = 0x0004
    STATIC = 0x0008
    FINAL = 0x0010
    SYNCHRONIZED = 0x0020
    BRIDGE = 0x0040
    VARARGS = 0x0080
    NATIVE = 0x0100
    ABSTRACT = 0x0400
    STRICT = 0x0800
    SYNTHETIC = 0x1000

class EventModifier:
    """ http://docs.oracle.com/javase/8/docs/platform/jpda/jdwp/jdwp-protocol.html#JDWP_EventRequest_Set """
    COUNT = 1
    CONDITIONAL = 2
    THREAD_ONLY = 3
    CLASS_ONLY = 4
    CLASS_MATCH = 5
    CLASS_EXCLUDE = 6
    LOCATION_ONLY = 7
    EXCEPTION_ONLY = 8
    FIELD_ONLY = 9
    STEP = 10
    INSTANCE_ONLY = 11
    SOURCE_NAME_MATCH = 12
