# This is a generated file based on https://formats.kaitai.io/dex/ but with minor tweaks for string processing.
# Unfortunately the original cannot parse KSY cannot parse the UTF16 strings in the "fake" UTF8 format we need which makes string processing way easier
# See line 460
from typing import List

from pkg_resources import parse_version
import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream
from enum import Enum

if parse_version(kaitaistruct.__version__) < parse_version('0.9'):
    raise Exception(
        "Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

import vlq_base128_le

def custom_decode_utf8(byte_str):
    result = []
    i = 0

    while i < len(byte_str):
        byte = byte_str[i]

        if byte & 0b10000000 == 0:  # 1-byte character
            result.append(chr(byte))
            i += 1
        elif byte & 0b11100000 == 0b11000000:  # 2-byte character
            char_code = ((byte & 0b00011111) << 6) | (byte_str[i + 1] & 0b00111111)
            result.append(chr(char_code))
            i += 2
        elif byte & 0b11110000 == 0b11100000:  # 3-byte character
            char_code = ((byte & 0b00001111) << 12) | ((byte_str[i + 1] & 0b00111111) << 6) | (byte_str[i + 2] & 0b00111111)
            result.append(chr(char_code))
            i += 3
        else:
            # For simplicity, assume 4-byte characters are not used in this example
            raise ValueError("Invalid UTF-8 encoding")

    return ''.join(result)

class Dex(KaitaiStruct):
    """Android OS applications executables are typically stored in its own
    format, optimized for more efficient execution in Dalvik virtual
    machine.
    
    This format is loosely similar to Java .class file format and
    generally holds the similar set of data: i.e. classes, methods,
    fields, annotations, etc.
    
    .. seealso::
       Source - https://source.android.com/devices/tech/dalvik/dex-format
    """

    class ClassAccessFlags(Enum):
        public = 1
        private = 2
        protected = 4
        static = 8
        final = 16
        interface = 512
        abstract = 1024
        synthetic = 4096
        annotation = 8192
        enum = 16384

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.header = Dex.HeaderItem(self._io, self, self._root)

    class HeaderItem(KaitaiStruct):

        class EndianConstant(Enum):
            endian_constant = 305419896
            reverse_endian_constant = 2018915346

        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.magic = self._io.read_bytes(4)
            if not self.magic == b"\x64\x65\x78\x0A":
                raise kaitaistruct.ValidationNotEqualError(b"\x64\x65\x78\x0A", self.magic, self._io,
                                                           u"/types/header_item/seq/0")
            self.version_str = (KaitaiStream.bytes_terminate(self._io.read_bytes(4), 0, False)).decode(u"utf-8",
                                                                                                       "ignore")
            self.checksum = self._io.read_u4le()
            self.signature = self._io.read_bytes(20)
            self.file_size = self._io.read_u4le()
            self.header_size = self._io.read_u4le()
            self.endian_tag = KaitaiStream.resolve_enum(Dex.HeaderItem.EndianConstant, self._io.read_u4le())
            self.link_size = self._io.read_u4le()
            self.link_off = self._io.read_u4le()
            self.map_off = self._io.read_u4le()
            self.string_ids_size = self._io.read_u4le()
            self.string_ids_off = self._io.read_u4le()
            self.type_ids_size = self._io.read_u4le()
            self.type_ids_off = self._io.read_u4le()
            self.proto_ids_size = self._io.read_u4le()
            self.proto_ids_off = self._io.read_u4le()
            self.field_ids_size = self._io.read_u4le()
            self.field_ids_off = self._io.read_u4le()
            self.method_ids_size = self._io.read_u4le()
            self.method_ids_off = self._io.read_u4le()
            self.class_defs_size = self._io.read_u4le()
            self.class_defs_off = self._io.read_u4le()
            self.data_size = self._io.read_u4le()
            self.data_off = self._io.read_u4le()

    class MapList(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.size = self._io.read_u4le()
            self.list = [None] * (self.size)
            for i in range(self.size):
                self.list[i] = Dex.MapItem(self._io, self, self._root)

    class EncodedValue(KaitaiStruct):

        class ValueTypeEnum(Enum):
            byte = 0
            short = 2
            char = 3
            int = 4
            long = 6
            float = 16
            double = 17
            method_type = 21
            method_handle = 22
            string = 23
            type = 24
            field = 25
            method = 26
            enum = 27
            array = 28
            annotation = 29
            null = 30
            boolean = 31

        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.value_arg = self._io.read_bits_int_be(3)
            self.value_type = KaitaiStream.resolve_enum(Dex.EncodedValue.ValueTypeEnum, self._io.read_bits_int_be(5))
            self._io.align_to_byte()
            _on = self.value_type
            if _on == Dex.EncodedValue.ValueTypeEnum.int:
                self.value = self._io.read_s4le()
            elif _on == Dex.EncodedValue.ValueTypeEnum.annotation:
                self.value = Dex.EncodedAnnotation(self._io, self, self._root)
            elif _on == Dex.EncodedValue.ValueTypeEnum.long:
                self.value = self._io.read_s8le()
            elif _on == Dex.EncodedValue.ValueTypeEnum.method_handle:
                self.value = self._io.read_u4le()
            elif _on == Dex.EncodedValue.ValueTypeEnum.byte:
                self.value = self._io.read_s1()
            elif _on == Dex.EncodedValue.ValueTypeEnum.array:
                self.value = Dex.EncodedArray(self._io, self, self._root)
            elif _on == Dex.EncodedValue.ValueTypeEnum.method_type:
                self.value = self._io.read_u4le()
            elif _on == Dex.EncodedValue.ValueTypeEnum.short:
                self.value = self._io.read_s2le()
            elif _on == Dex.EncodedValue.ValueTypeEnum.method:
                self.value = self._io.read_u4le()
            elif _on == Dex.EncodedValue.ValueTypeEnum.double:
                self.value = self._io.read_f8le()
            elif _on == Dex.EncodedValue.ValueTypeEnum.float:
                self.value = self._io.read_f4le()
            elif _on == Dex.EncodedValue.ValueTypeEnum.type:
                self.value = self._io.read_u4le()
            elif _on == Dex.EncodedValue.ValueTypeEnum.enum:
                self.value = self._io.read_u4le()
            elif _on == Dex.EncodedValue.ValueTypeEnum.field:
                self.value = self._io.read_u4le()
            elif _on == Dex.EncodedValue.ValueTypeEnum.string:
                self.value = self._io.read_u4le()
            elif _on == Dex.EncodedValue.ValueTypeEnum.char:
                self.value = self._io.read_u2le()

    class CallSiteIdItem(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.call_site_off = self._io.read_u4le()

    class MethodIdItem(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.class_idx = self._io.read_u2le()
            self.proto_idx = self._io.read_u2le()
            self.name_idx = self._io.read_u4le()

        @property
        def class_name(self):
            """the definer of this method."""
            if hasattr(self, '_m_class_name'):
                return self._m_class_name if hasattr(self, '_m_class_name') else None

            self._m_class_name = self._root.type_ids[self.class_idx].type_name
            return self._m_class_name if hasattr(self, '_m_class_name') else None

        @property
        def proto_desc(self):
            """the short-form descriptor of the prototype of this method."""
            if hasattr(self, '_m_proto_desc'):
                return self._m_proto_desc if hasattr(self, '_m_proto_desc') else None

            self._m_proto_desc = self._root.proto_ids[self.proto_idx].shorty_desc
            return self._m_proto_desc if hasattr(self, '_m_proto_desc') else None

        @property
        def proto_id(self):
            return self._root.proto_ids[self.proto_idx]

        @property
        def method_name(self):
            """the name of this method."""
            if hasattr(self, '_m_method_name'):
                return self._m_method_name if hasattr(self, '_m_method_name') else None

            self._m_method_name = self._root.string_ids[self.name_idx].value.data
            return self._m_method_name if hasattr(self, '_m_method_name') else None

    class TypeItem(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.type_idx = self._io.read_u2le()

        @property
        def value(self):
            if hasattr(self, '_m_value'):
                return self._m_value if hasattr(self, '_m_value') else None

            self._m_value = self._root.type_ids[self.type_idx].type_name
            return self._m_value if hasattr(self, '_m_value') else None

    class TypeIdItem(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.descriptor_idx = self._io.read_u4le()

        @property
        def type_name(self):
            if hasattr(self, '_m_type_name'):
                return self._m_type_name if hasattr(self, '_m_type_name') else None

            self._m_type_name = self._root.string_ids[self.descriptor_idx].value.data
            return self._m_type_name if hasattr(self, '_m_type_name') else None

    class AnnotationElement(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.name_idx = vlq_base128_le.VlqBase128Le(self._io)
            self.value = Dex.EncodedValue(self._io, self, self._root)

    class EncodedField(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.field_idx_diff = vlq_base128_le.VlqBase128Le(self._io)
            self.access_flags = vlq_base128_le.VlqBase128Le(self._io)

    class EncodedArrayItem(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.value = Dex.EncodedArray(self._io, self, self._root)

    class ClassDataItem(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.static_fields_size = vlq_base128_le.VlqBase128Le(self._io)
            self.instance_fields_size = vlq_base128_le.VlqBase128Le(self._io)
            self.direct_methods_size = vlq_base128_le.VlqBase128Le(self._io)
            self.virtual_methods_size = vlq_base128_le.VlqBase128Le(self._io)
            self.static_fields = [None] * (self.static_fields_size.value)
            for i in range(self.static_fields_size.value):
                self.static_fields[i] = Dex.EncodedField(self._io, self, self._root)

            self.instance_fields = [None] * (self.instance_fields_size.value)
            for i in range(self.instance_fields_size.value):
                self.instance_fields[i] = Dex.EncodedField(self._io, self, self._root)

            self.direct_methods = [None] * (self.direct_methods_size.value)
            for i in range(self.direct_methods_size.value):
                self.direct_methods[i] = Dex.EncodedMethod(self._io, self, self._root)

            self.virtual_methods = [None] * (self.virtual_methods_size.value)
            for i in range(self.virtual_methods_size.value):
                self.virtual_methods[i] = Dex.EncodedMethod(self._io, self, self._root)

    class FieldIdItem(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.class_idx = self._io.read_u2le()
            self.type_idx = self._io.read_u2le()
            self.name_idx = self._io.read_u4le()

        @property
        def class_name(self):
            """the definer of this field."""
            if hasattr(self, '_m_class_name'):
                return self._m_class_name if hasattr(self, '_m_class_name') else None

            self._m_class_name = self._root.type_ids[self.class_idx].type_name
            return self._m_class_name if hasattr(self, '_m_class_name') else None

        @property
        def type_name(self):
            """the type of this field."""
            if hasattr(self, '_m_type_name'):
                return self._m_type_name if hasattr(self, '_m_type_name') else None

            self._m_type_name = self._root.type_ids[self.type_idx].type_name
            return self._m_type_name if hasattr(self, '_m_type_name') else None

        @property
        def field_name(self):
            """the name of this field."""
            if hasattr(self, '_m_field_name'):
                return self._m_field_name if hasattr(self, '_m_field_name') else None

            self._m_field_name = self._root.string_ids[self.name_idx].value.data
            return self._m_field_name if hasattr(self, '_m_field_name') else None

    class EncodedAnnotation(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.type_idx = vlq_base128_le.VlqBase128Le(self._io)
            self.size = vlq_base128_le.VlqBase128Le(self._io)
            self.elements = [None] * (self.size.value)
            for i in range(self.size.value):
                self.elements[i] = Dex.AnnotationElement(self._io, self, self._root)

    class ClassDefItem(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.class_idx = self._io.read_u4le()
            self.access_flags = KaitaiStream.resolve_enum(Dex.ClassAccessFlags, self._io.read_u4le())
            self.superclass_idx = self._io.read_u4le()
            self.interfaces_off = self._io.read_u4le()
            self.source_file_idx = self._io.read_u4le()
            self.annotations_off = self._io.read_u4le()
            self.class_data_off = self._io.read_u4le()
            self.static_values_off = self._io.read_u4le()

        @property
        def type_name(self):
            if hasattr(self, '_m_type_name'):
                return self._m_type_name if hasattr(self, '_m_type_name') else None

            self._m_type_name = self._root.type_ids[self.class_idx].type_name
            return self._m_type_name if hasattr(self, '_m_type_name') else None

        @property
        def class_data(self):
            if hasattr(self, '_m_class_data'):
                return self._m_class_data if hasattr(self, '_m_class_data') else None

            if self.class_data_off != 0:
                _pos = self._io.pos()
                self._io.seek(self.class_data_off)
                self._m_class_data = Dex.ClassDataItem(self._io, self, self._root)
                self._io.seek(_pos)

            return self._m_class_data if hasattr(self, '_m_class_data') else None

        @property
        def static_values(self):
            if hasattr(self, '_m_static_values'):
                return self._m_static_values if hasattr(self, '_m_static_values') else None

            if self.static_values_off != 0:
                _pos = self._io.pos()
                self._io.seek(self.static_values_off)
                self._m_static_values = Dex.EncodedArrayItem(self._io, self, self._root)
                self._io.seek(_pos)

            return self._m_static_values if hasattr(self, '_m_static_values') else None

    class TypeList(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.size = self._io.read_u4le()
            self.list = [None] * (self.size)
            for i in range(self.size):
                self.list[i] = Dex.TypeItem(self._io, self, self._root)

    class StringIdItem(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.string_data_off = self._io.read_u4le()

        class StringDataItem(KaitaiStruct):
            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._read()

            def _read(self):
                self.utf16_size = vlq_base128_le.VlqBase128Le(self._io)
                
                byte = self._io.read_bytes(1)
                self.raw_data = b''
                
                while byte != b'\x00':
                    self.raw_data += byte
                    byte = self._io.read_bytes(1)
                
                
                try:
                    self.data = self.raw_data.decode("utf-8")
                except ValueError as ve:

                    result = custom_decode_utf8(self.raw_data)
                    ret = []
                    for c in result:
                        ret.append(ord(c))
                    self.data = ret
                self.raw_data = self.data

            def custom_decode_utf8(this, byte_str):
                result = []
                i = 0

                while i < len(byte_str):
                    byte = byte_str[i]

                    if byte & 0b10000000 == 0:  # 1-byte character
                        result.append(chr(byte))
                        i += 1
                    elif byte & 0b11100000 == 0b11000000:  # 2-byte character
                        char_code = ((byte & 0b00011111) << 6) | (byte_str[i + 1] & 0b00111111)
                        result.append(chr(char_code))
                        i += 2
                    elif byte & 0b11110000 == 0b11100000:  # 3-byte character
                        char_code = ((byte & 0b00001111) << 12) | ((byte_str[i + 1] & 0b00111111) << 6) | (byte_str[i + 2] & 0b00111111)
                        result.append(chr(char_code))
                        i += 3
                    else:
                        # For simplicity, assume 4-byte characters are not used in this example
                        raise ValueError("Invalid UTF-8 encoding")

                return ''.join(result)

        @property
        def value(self):
            if hasattr(self, '_m_value'):
                return self._m_value if hasattr(self, '_m_value') else None

            _pos = self._io.pos()
            self._io.seek(self.string_data_off)
            self._m_value = Dex.StringIdItem.StringDataItem(self._io, self, self._root)
            self._io.seek(_pos)
            return self._m_value if hasattr(self, '_m_value') else None

    class ProtoIdItem(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.shorty_idx = self._io.read_u4le()
            self.return_type_idx = self._io.read_u4le()
            self.parameters_off = self._io.read_u4le()

        @property
        def shorty_desc(self):
            """short-form descriptor string of this prototype, as pointed to by shorty_idx."""
            if hasattr(self, '_m_shorty_desc'):
                return self._m_shorty_desc if hasattr(self, '_m_shorty_desc') else None

            self._m_shorty_desc = self._root.string_ids[self.shorty_idx].value.data
            return self._m_shorty_desc if hasattr(self, '_m_shorty_desc') else None

        @property
        def params_types(self):
            """list of parameter types for this prototype."""
            if hasattr(self, '_m_params_types'):
                return self._m_params_types if hasattr(self, '_m_params_types') else None

            if self.parameters_off != 0:
                io = self._root._io
                _pos = io.pos()
                io.seek(self.parameters_off)
                self._m_params_types = Dex.TypeList(io, self, self._root)
                io.seek(_pos)

            return self._m_params_types if hasattr(self, '_m_params_types') else None

        @property
        def return_type(self):
            """return type of this prototype."""
            if hasattr(self, '_m_return_type'):
                return self._m_return_type if hasattr(self, '_m_return_type') else None

            self._m_return_type = self._root.type_ids[self.return_type_idx].type_name
            return self._m_return_type if hasattr(self, '_m_return_type') else None

    class EncodedMethod(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.method_idx_diff = vlq_base128_le.VlqBase128Le(self._io)
            self.access_flags = vlq_base128_le.VlqBase128Le(self._io)
            self.code_off = vlq_base128_le.VlqBase128Le(self._io)

    class MapItem(KaitaiStruct):

        class MapItemType(Enum):
            header_item = 0
            string_id_item = 1
            type_id_item = 2
            proto_id_item = 3
            field_id_item = 4
            method_id_item = 5
            class_def_item = 6
            call_site_id_item = 7
            method_handle_item = 8
            map_list = 4096
            type_list = 4097
            annotation_set_ref_list = 4098
            annotation_set_item = 4099
            class_data_item = 8192
            code_item = 8193
            string_data_item = 8194
            debug_info_item = 8195
            annotation_item = 8196
            encoded_array_item = 8197
            annotations_directory_item = 8198

        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.type = KaitaiStream.resolve_enum(Dex.MapItem.MapItemType, self._io.read_u2le())
            self.unused = self._io.read_u2le()
            self.size = self._io.read_u4le()
            self.offset = self._io.read_u4le()

    class EncodedArray(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.size = vlq_base128_le.VlqBase128Le(self._io)
            self.values = [None] * (self.size.value)
            for i in range(self.size.value):
                self.values[i] = Dex.EncodedValue(self._io, self, self._root)

    @property
    def string_ids(self):
        """string identifiers list.
        
        These are identifiers for all the strings used by this file, either for
        internal naming (e.g., type descriptors) or as constant objects referred to by code.
        
        This list must be sorted by string contents, using UTF-16 code point values
        (not in a locale-sensitive manner), and it must not contain any duplicate entries.
        """
        if hasattr(self, '_m_string_ids'):
            return self._m_string_ids if hasattr(self, '_m_string_ids') else None

        _pos = self._io.pos()
        self._io.seek(self.header.string_ids_off)
        self._m_string_ids = [None] * (self.header.string_ids_size)
        for i in range(self.header.string_ids_size):
            self._m_string_ids[i] = Dex.StringIdItem(self._io, self, self._root)

        self._io.seek(_pos)
        return self._m_string_ids if hasattr(self, '_m_string_ids') else None

    @property
    def method_ids(self) -> List[MethodIdItem]:
        """method identifiers list.
        
        These are identifiers for all methods referred to by this file,
        whether defined in the file or not.
        
        This list must be sorted, where the defining type (by type_id index
        is the major order, method name (by string_id index) is the intermediate
        order, and method prototype (by proto_id index) is the minor order.
        
        The list must not contain any duplicate entries.
        """
        if hasattr(self, '_m_method_ids'):
            return self._m_method_ids if hasattr(self, '_m_method_ids') else None

        _pos = self._io.pos()
        self._io.seek(self.header.method_ids_off)
        self._m_method_ids = [None] * (self.header.method_ids_size)
        for i in range(self.header.method_ids_size):
            self._m_method_ids[i] = Dex.MethodIdItem(self._io, self, self._root)

        self._io.seek(_pos)
        return self._m_method_ids if hasattr(self, '_m_method_ids') else None

    @property
    def link_data(self) -> bytes:
        """data used in statically linked files.
        
        The format of the data in this section is left unspecified by this document.
        
        This section is empty in unlinked files, and runtime implementations may
        use it as they see fit.
        """
        if hasattr(self, '_m_link_data'):
            return self._m_link_data if hasattr(self, '_m_link_data') else None

        _pos = self._io.pos()
        self._io.seek(self.header.link_off)
        self._m_link_data = self._io.read_bytes(self.header.link_size)
        self._io.seek(_pos)
        return self._m_link_data if hasattr(self, '_m_link_data') else None

    @property
    def map(self):
        if hasattr(self, '_m_map'):
            return self._m_map if hasattr(self, '_m_map') else None

        _pos = self._io.pos()
        self._io.seek(self.header.map_off)
        self._m_map = Dex.MapList(self._io, self, self._root)
        self._io.seek(_pos)
        return self._m_map if hasattr(self, '_m_map') else None

    @property
    def class_defs(self) -> List[ClassDefItem]:
        """class definitions list.
        
        The classes must be ordered such that a given class's superclass and
        implemented interfaces appear in the list earlier than the referring class.
        
        Furthermore, it is invalid for a definition for the same-named class to
        appear more than once in the list.
        """
        if hasattr(self, '_m_class_defs'):
            return self._m_class_defs if hasattr(self, '_m_class_defs') else None

        _pos = self._io.pos()
        self._io.seek(self.header.class_defs_off)
        self._m_class_defs = [None] * (self.header.class_defs_size)
        for i in range(self.header.class_defs_size):
            self._m_class_defs[i] = Dex.ClassDefItem(self._io, self, self._root)

        self._io.seek(_pos)
        return self._m_class_defs if hasattr(self, '_m_class_defs') else None

    @property
    def data(self) -> bytes:
        """data area, containing all the support data for the tables listed above.
        
        Different items have different alignment requirements, and padding bytes
        are inserted before each item if necessary to achieve proper alignment.
        """
        if hasattr(self, '_m_data'):
            return self._m_data if hasattr(self, '_m_data') else None

        _pos = self._io.pos()
        self._io.seek(self.header.data_off)
        self._m_data = self._io.read_bytes(self.header.data_size)
        self._io.seek(_pos)
        return self._m_data if hasattr(self, '_m_data') else None

    @property
    def type_ids(self) -> List[TypeIdItem]:
        """type identifiers list.
        
        These are identifiers for all types (classes, arrays, or primitive types)
        referred to by this file, whether defined in the file or not.
        
        This list must be sorted by string_id index, and it must not contain any duplicate entries.
        """
        if hasattr(self, '_m_type_ids'):
            return self._m_type_ids if hasattr(self, '_m_type_ids') else None

        _pos = self._io.pos()
        self._io.seek(self.header.type_ids_off)
        self._m_type_ids = [None] * (self.header.type_ids_size)
        for i in range(self.header.type_ids_size):
            self._m_type_ids[i] = Dex.TypeIdItem(self._io, self, self._root)

        self._io.seek(_pos)
        return self._m_type_ids if hasattr(self, '_m_type_ids') else None

    @property
    def proto_ids(self) -> List[ProtoIdItem]:
        """method prototype identifiers list.
        
        These are identifiers for all prototypes referred to by this file.
        
        This list must be sorted in return-type (by type_id index) major order,
        and then by argument list (lexicographic ordering, individual arguments
        ordered by type_id index). The list must not contain any duplicate entries.
        """
        if hasattr(self, '_m_proto_ids'):
            return self._m_proto_ids if hasattr(self, '_m_proto_ids') else None

        _pos = self._io.pos()
        self._io.seek(self.header.proto_ids_off)
        self._m_proto_ids = [None] * (self.header.proto_ids_size)
        for i in range(self.header.proto_ids_size):
            self._m_proto_ids[i] = Dex.ProtoIdItem(self._io, self, self._root)

        self._io.seek(_pos)
        return self._m_proto_ids if hasattr(self, '_m_proto_ids') else None

    @property
    def field_ids(self) -> List[FieldIdItem]:
        """field identifiers list.
        
        These are identifiers for all fields referred to by this file, whether defined in the file or not.
        
        This list must be sorted, where the defining type (by type_id index)
        is the major order, field name (by string_id index) is the intermediate
        order, and type (by type_id index) is the minor order.
        
        The list must not contain any duplicate entries.
        """
        if hasattr(self, '_m_field_ids'):
            return self._m_field_ids if hasattr(self, '_m_field_ids') else None

        _pos = self._io.pos()
        self._io.seek(self.header.field_ids_off)
        self._m_field_ids = [None] * (self.header.field_ids_size)
        for i in range(self.header.field_ids_size):
            self._m_field_ids[i] = Dex.FieldIdItem(self._io, self, self._root)

        self._io.seek(_pos)
        return self._m_field_ids if hasattr(self, '_m_field_ids') else None
