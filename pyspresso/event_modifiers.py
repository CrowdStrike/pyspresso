#!/usr/bin/python
## @file        event_modifiers.py
#  @brief       JDWP event modifiers.
#  @author      Jason Geffner
#  @copyright   CrowdStrike, Inc. 2016

from pyspresso.constants import EventModifier


class Count:
    def __init__(self, count=0):
        self.mod_kind = EventModifier.COUNT
        self.count = count

class Conditional:
    def __init__(self, expr_id=0):
        self.mod_kind = EventModifier.CONDITIONAL
        self.expr_id = expr_id

class ThreadOnly:
    def __init__(self, thread=0):
        self.mod_kind = EventModifier.THREAD_ONLY
        self.thread = thread

class ClassOnly:
    def __init__(self, class_=0):
        self.mod_kind = EventModifier.CONDITIONAL
        self.class_ = class_

class ClassMatch:
    def __init__(self, class_pattern=""):
        self.mod_kind = EventModifier.CLASS_MATCH
        self.class_pattern = class_pattern

class ClassExclude:
    def __init__(self, class_pattern=""):
        self.mod_kind = EventModifier.CLASS_EXCLUDE
        self.class_pattern = class_pattern

class LocationOnly:
    def __init__(self, loc=None):
        self.mod_kind = EventModifier.LOCATION_ONLY
        self.loc = loc

class ExceptionOnly:
    def __init__(self, exception_or_null=0, caught=False, uncaught=False):
        self.mod_kind = EventModifier.EXCEPTION_ONLY
        self.exception_or_null = exception_or_null
        self.caught = caught
        self.uncaught = uncaught

class FieldOnly:
    def __init__(self, declaring=0, field_id=0):
        self.mod_kind = EventModifier.FIELD_ONLY
        self.declaring = declaring
        self.field_id = field_id

class Step:
    def __init__(self, thread=0, size=0, depth=0):
        self.mod_kind = EventModifier.STEP
        self.thread = thread
        self.size = size
        self.depth = depth

class InstanceOnly:
    def __init__(self, instance=0):
        self.mod_kind = EventModifier.INSTANCE_ONLY
        self.instance = instance

class SourceNameMatch:
    def __init__(self, source_name_pattern=""):
        self.mod_kind = EventModifier.SOURCE_NAME_MATCH
        self.source_name_pattern = source_name_pattern
