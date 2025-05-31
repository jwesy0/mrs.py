"""
    mrs.py
    Wrapper of libmrs, for Python
    by Wes, 2025
"""

from glob import glob
import io
import os
from os import path
import re
import struct
import tempfile
import time
import zlib

class NotAMrsFileError(IOError):
    super

class InvalidMrsEncryptionError(IOError):
    super

class NotAssigned:
    pass

def _dec_str(s: bytes):
    try:
        ss = s.decode('mbcs')
        return (ss, 'mbcs')
    except:
        try:
            ss = s.decode('1252')
            return (ss, '1252')
        except:
            try:
                ss = s.decode('utf-8')
                return (ss, 'utf-8')
            except:
                raise UnicodeError(f'Unknown encoding.')

def _enc_str(s: str):
    try:
        ss = s.encode('mbcs')
        return (ss, 'mbcs')
    except:
        try:
            ss = s.encode('1252')
            return (ss, '1252')
        except:
            try:
                ss = s.encode('utf-8')
                return (ss, 'utf-8')
            except:
                raise UnicodeError('Unknown encoding.')

def _is_valid_filename(f: str):
    invalid_names = [
        '.',    '..',
        'CON',  'PRN',  'AUX',  'NUL',  'COM0', 'COM1', 'COM2', 'COM3',
        'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'COM¹', 'COM²',
        'COM³', 'LPT0', 'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6',
        'LPT7', 'LPT8', 'LPT9', 'LPT¹', 'LPT²', 'LPT³'
    ]
    invalid_chars = ['<', '>', ':', '"', '|', '?', '*']
    invalid_chars.extend(range(1, 32))

    for i in invalid_chars:
        if type(i) == int:
            i = chr(i)
        if i in f:
            raise UnicodeError

    dirs = f.split('\\')
    for i in dirs:
        fname = path.splitext(i)[0]
        if fname.upper() in invalid_names:
            raise UnicodeError

######## _dostime ##############################################
class _dostime:
    class _time:
        def __init__(self):
            self.hour   = 0
            self.minute = 0
            self.second = 0
            self.value  = 0
        
        def set_time(self, tm: time.struct_time|int):
            if isinstance(tm, time.struct_time):
                self.hour   = int(tm.tm_hour)
                self.minute = int(tm.tm_min)
                self.second = int(tm.tm_sec / 2)
                self.value = (self.second & 0b11111) | ((self.minute & 0b111111) << 5) | ((self.hour & 0b11111) << 11)
            elif isinstance(tm, int):
                self.hour   = int((tm & 0b11111) >> 11)
                self.minute = int((tm & 0b111111) >> 5)
                self.second = int(tm & 0b11111)
                self.value  = tm
        
    class _date:
        def __init__(self):
            self.year  = 0
            self.month = 0
            self.day   = 0
            self.value = 0
        
        def set_date(self, tm: time.struct_time|int):
            if isinstance(tm, time.struct_time):
                self.year  = int(tm.tm_year - 1980)
                self.month = int(tm.tm_mon)
                self.day   = int(tm.tm_mday)
                self.value = (self.day & 0b11111) | ((self.month & 0b1111) << 5) | ((self.year & 0b1111111) << 9)
            elif isinstance(tm, int):
                self.year  = int((tm & 0b1111111) >> 9)
                self.month = int((tm & 0b1111) >> 5)
                self.day   = int(tm & 0b11111)
                self.value = tm
        
    def __init__(self):
        self.time = self._time()
        self.date = self._date()
    
    def dostime(self, t: float|None = None):
        tm = None

        if t != None:
            try:
                tm = time.localtime(t)
            except:
                tm = time.localtime(time.time())
        else:
            tm = time.localtime(time.time())

        self.time.set_time(tm)
        self.date.set_date(tm)
    
    def mktimedos(self) -> time.time:
        tm = time.struct_time([
            int(self.date.year + 1980),
            int(self.date.month),
            int(self.date.day),
            int(self.time.hour),
            int(self.time.minute),
            int(self.time.second * 2),
            0, 0, 0
        ])
        return time.mktime(tm)

######## _mrs_hdr ##############################################
class _mrs_hdr:
    MAGIC1 = 0x5030207
    MAGIC2 = 0x5030208
    MAGIC3 = 0x6054b50
    
    size = 22

    __fmt = "<IHHHHIIH"

    def __init__(self):
        self.signature       = 0
        self.disk_num        = 0
        self.disk_start      = 0
        self.dir_count       = 0
        self.total_dir_count = 0
        self.dir_size        = 0
        self.dir_offset      = 0
        self.comment_length  = 0

    def __bytes__(self) -> bytes:
        b = struct.pack(self.__fmt, self.signature,
                                    self.disk_num,
                                    self.disk_start,
                                    self.dir_count,
                                    self.total_dir_count,
                                    self.dir_size,
                                    self.dir_offset,
                                    self.comment_length)
        return b
    
    def dump(self):
        print('_mrs_hdr dump (%u):' % self.size)
        print('  signature       %08x' % self.signature)
        print('  disk_num        %u' % self.disk_num)
        print('  disk_start      %u' % self.disk_start)
        print('  dir_count       %u' % self.dir_count)
        print('  total_dir_count %u' % self.total_dir_count)
        print('  dir_size        %u' % self.dir_size)
        print('  dir_offset      %08x' % self.dir_offset)
        print('  comment_length  %u' % self.comment_length)
    
    def read(self, f: io.BufferedIOBase|bytes|bytearray):
        b = NotAssigned
        if isinstance(f, io.BufferedIOBase):
            b = f.read(self.size)
        elif isinstance(f, bytes):
            b = f
        elif isinstance(f, bytearray):
            b = bytes(f)
        else:
            raise TypeError(f'"f" MUST be a io.BufferedIOBase, bytes or bytearray.')
        
        ( self.signature,
          self.disk_num,
          self.disk_start,
          self.dir_count,
          self.total_dir_count,
          self.dir_size,
          self.dir_offset,
          self.comment_length ) = struct.unpack_from(self.__fmt, b)

    def write(self, f):
        pass

######## _mrs_local_hdr ########################################
class _mrs_local_hdr:
    MAGIC1  = 0x4034b50
    MAGIC2  = 0x85840000
    VER     = 0x14

    size = 30

    __fmt = "<IHHHHHIIIHH"

    def __init__(self):
        self.signature         = 0
        self.version           = 0
        self.flags             = 0
        self.compression       = 0
        self.filetime          = _dostime()
        self.crc32             = 0
        self.compressed_size   = 0
        self.uncompressed_size = 0
        self.filename_length   = 0
        self.extra_length      = 0
        self.filename          = None
        self.extra             = None
    
    def dump(self):
        print('_mrs_local_hdr dump (%u):' % self.size)
        print('  signature         %08x' % self.signature)
        print('  version           %04x' % self.version)
        print('  flags             %04x' % self.flags)
        print('  compression       %04x' % self.compression)
        print('  filetime          %04x %04x' % (self.filetime.time.value, self.filetime.date.value))
        print('  crc32             %08x' % self.crc32)
        print('  compressed_size   %u' % self.compressed_size)
        print('  uncompressed_size %u' % self.uncompressed_size)
        print('  filename_length   %u' % self.filename_length)
        print('  extra_length      %u' % self.extra_length)
        if self.filename:
            print('  filename          %s' % self.filename)
        if self.extra:
            print('  extra             %s' % self.extra)
    
    def read(self, f: io.BufferedIOBase|bytes|bytearray):
        b = NotAssigned
        if isinstance(f, io.BufferedIOBase):
            b = f.read(self.size)
        elif isinstance(f, bytes):
            b = f
        elif isinstance(f, bytearray):
            b = bytes(f)
        else:
            raise TypeError(f'"f" MUST be a io.BufferedIOBase, bytes or bytearray.')
        
        ( self.signature,
          self.version,
          self.flags,
          self.compression,
          _ftime,
          _fdate,
          self.crc32,
          self.compressed_size,
          self.uncompressed_size,
          self.filename_length,
          self.extra_length ) = struct.unpack_from(self.__fmt, b)
        
        offset = self.size

        self.filetime.time.set_time(_ftime)
        self.filetime.date.set_date(_fdate)

######## _mrs_central_dir_hdr ##################################
class _mrs_central_dir_hdr:
    MAGIC1     = 0x2014b50
    MAGIC2     = 0x5024b80
    VER_MADE   = 0x19
    VER_NEEDED = 0x14

    size = 46

    __fmt = "<IHHHHHHIIIHHHHHII"

    def __init__(self):
        self.signature         = 0
        self.version_made      = 0
        self.version_needed    = 0
        self.flags             = 0
        self.compression       = 0
        self.filetime          = _dostime()
        self.crc32             = 0
        self.compressed_size   = 0
        self.uncompressed_size = 0
        self.filename_length   = 0
        self.extra_length      = 0
        self.comment_length    = 0
        self.disk_start        = 0
        self.int_attr          = 0
        self.ext_attr          = 0
        self.offset            = 0
        self.filename          = None
        self.extra             = None
        self.comment           = None
    
    def read(self, f: io.BufferedIOBase|bytes|bytearray):
        b = NotAssigned
        if isinstance(f, io.BufferedIOBase):
            b = f.read(self.size)
        elif isinstance(f, bytes):
            b = f
        elif isinstance(f, bytearray):
            b = bytes(f)
        else:
            raise TypeError(f'"f" MUST be a io.BufferedIOBase, bytes or bytearray.')
        
        ( self.signature,
          self.version_made,
          self.version_needed,
          self.flags,
          self.compression,
          _ftime,
          _fdate,
          self.crc32,
          self.compressed_size,
          self.uncompressed_size,
          self.filename_length,
          self.extra_length,
          self.comment_length,
          self.disk_start,
          self.int_attr,
          self.ext_attr,
          self.offset ) = struct.unpack_from(self.__fmt, b)
        
        offset = self.size
        
        self.filetime.time.set_time(_ftime)
        self.filetime.date.set_date(_fdate)

        if self.filename_length:
            self.filename = b[offset:(offset + self.filename_length)]
            offset += self.filename_length
        
        if self.extra_length:
            self.extra = b[offset:(offset + self.extra_length)]
            offset += self.extra_length
        
        if self.comment_length:
            self.comment = b[offset:(offset + self.comment_length)]
    
    def dump(self):
        print('_mrs_central_dir_hdr dump (%u):' % self.size)
        print('  signature         %08x' % self.signature)
        print('  version_made      %04x' % self.version_made)
        print('  version_needed    %04x' % self.version_needed)
        print('  flags             %04x' % self.flags)
        print('  compression       %04x' % self.compression)
        print('  mod. time         %04x' % self.filetime.time.value)
        print('  mod. date         %04x' % self.filetime.date.value)
        print('  crc32             %08x' % self.crc32)
        print('  compressed_size   %u' % self.compressed_size)
        print('  uncompressed_size %u' % self.uncompressed_size)
        print('  filename_length   %u' % self.filename_length)
        print('  extra_length      %u' % self.extra_length)
        print('  comment_length    %u' % self.comment_length)
        print('  disk_start        %04x' % self.disk_start)
        print('  int_attr          %04x' % self.int_attr)
        print('  ext_attr          %08x' % self.ext_attr)
        print('  offset            %08x' % self.offset)
        if self.filename:
            print('  filename          %s' % self.filename)
        if self.extra:
            print('  extra             %s' % self.extra)
        if self.comment:
            print('  comment           %s' % self.comment)

######## _mrs_file #############################################
class _mrs_file:
    def __init__(self):
        self.lh = _mrs_local_hdr()
        self.dh = _mrs_central_dir_hdr()
        self.filenameuc = None  # File name in Unicode
        self.filenameenc = None # File name encoding
    
    def dump(self):
        self.lh.dump()
        self.dh.dump()
        print('Filename: %s' % self.filenameuc)
        print('Encoding: %s' % self.filenameenc)

class mrs_signature_where:
    BASE_HDR        = 1
    LOCAL_HDR       = 2
    CENTRAL_DIR_HDR = 3

class mrs_file:
    def __init__(self, *, index, name, crc32, size, compressed_size, ftime, lhextra, dhextra, dhcomment):
        self.__index           = index
        self.__name            = name
        self.__crc32           = crc32
        self.__size            = size
        self.__compressed_size = compressed_size
        self.__ftime           = ftime
        self.__lhextra         = lhextra
        self.__dhextra         = dhextra
        self.__dhcomment       = dhcomment
    
    @property
    def index(self):
        return self.__index

    @property
    def name(self):
        return self.__name

    @name.setter
    def name(self, v: str):
        if not isinstance(v, str):
            raise TypeError('name MUST be a string')
        try:
            _is_valid_filename(v)
        except:
            raise UnicodeError(f'v contains an invalid file name: "{v}".') from None
        self.__name = v
    
    @property
    def crc32(self):
        return self.__crc32
    
    @property
    def size(self):
        return self.__size
    
    @property
    def compressed_size(self):
        return self.__compressed_size

    @property
    def ftime(self):
        return self.__ftime

    @ftime.setter
    def ftime(self, v: time.time):
        if not isinstance(v, time.time):
            raise TypeError('ftime MUST be a float')
        self.__ftime = v
    
    @property
    def lh_extra(self):
        return self.__lhextra

    @lh_extra.setter
    def lh_extra(self, v: bytearray|bytes|str|None):
        if isinstance(v, bytearray):
            print('<bytearray>')
            self.__lhextra = bytes(v)
        elif isinstance(v, bytes):
            print('<bytes>')
            self.__lhextra = bytes(v)
        elif isinstance(v, str):
            print('<str>')
            self.__lhextra = v.encode('utf-8', 'ignore')
        elif v == None:
            self.__lhextra = None
            print('<none>')
        else:
            raise TypeError('lh_extra MUST be a bytearray, bytes, str or None')
    
    @property
    def dh_extra(self):
        return self.__dhextra

    @dh_extra.setter
    def dh_extra(self, v: bytearray|bytes|str|None):
        if isinstance(v, bytearray):
            print('<bytearray>')
            self.__dhextra = bytes(v)
        elif isinstance(v, bytes):
            print('<bytes>')
            self.__dhextra = bytes(v)
        elif isinstance(v, str):
            print('<str>')
            self.__dhextra = v.encode('utf-8', 'ignore')
        elif v == None:
            self.__dhextra = None
            print('<none>')
        else:
            raise TypeError('dh_extra MUST be a bytearray, bytes, str or None')
    
    @property
    def dh_comment(self):
        return self.__dhcomment

    @dh_comment.setter
    def dh_comment(self, v: bytearray|bytes|str|None):
        if isinstance(v, bytearray):
            print('<bytearray>')
            self.__dhcomment = bytes(v)
        elif isinstance(v, bytes):
            print('<bytes>')
            self.__dhcomment = bytes(v)
        elif isinstance(v, str):
            print('<str>')
            self.__dhcomment = v.encode('utf-8', 'ignore')
        elif v == None:
            self.__dhcomment = None
            print('<none>')
        else:
            raise TypeError('dh_comment MUST be a bytearray, bytes, str or None')

class mrs_dupe_behavior:
    KEEP_NEW  = 0
    KEEP_OLD  = 1
    KEEP_BOTH = 2

######## mrs_encryption ########################################
class mrs_encryption:
    BASE_HDR        = 1
    LOCAL_HDR       = 2
    CENTRAL_DIR_HDR = 4
    HEADERS         = BASE_HDR | LOCAL_HDR | CENTRAL_DIR_HDR
    BUFFER          = 8
    ALL             = HEADERS | BUFFER

    def __init__(self):
        self.base_hdr        = None
        self.local_hdr       = None
        self.central_dir_hdr = None
        self.buffer          = None

######## mrs ###################################################
class mrs:
    COMPRESSION_STORE   = 0
    COMPRESSION_DEFLATE = 8

    def __init__(self):
        self.__files: list[_mrs_file] = []
        self.__hdr      = _mrs_hdr()
        self.__mem      = tempfile.TemporaryFile('w+b')
        self.__decrypt  = mrs_encryption()
        self.__encrypt  = mrs_encryption()
        self.__sigcheck = None
    
    def __del__(self):
        if not self.__mem.closed:
            self.__mem.close()
    
    def __mrs_default_decrypt(self, buffer: bytes, size: int):
        buf = bytearray(buffer)
        for i in range(size):
            c = buf[i]
            c = ((c >> 3) | (c << 5)) & 0xFF
            buf[i] = (~c) & 0xFF
        return bytes(buf)
    
    def __mrs_default_encrypt(self, buffer: bytes, size: int):
        buf = bytearray(buffer)
        for i in range(size):
            c = (~buf[i]) & 0xFF
            c = ((c << 3) | (c >> 5)) & 0xFF
            buf[i] = c
        return bytes(buf)
    
    def __mrs_default_signatures(self, where: int, signature: int) -> bool:
        if not isinstance(signature, int):
            return False

        if where == mrs_signature_where.BASE_HDR:
            if signature in (_mrs_hdr.MAGIC1, _mrs_hdr.MAGIC2, _mrs_hdr.MAGIC3):
                return True
        elif where == mrs_signature_where.LOCAL_HDR:
            if signature in (_mrs_local_hdr.MAGIC1, _mrs_local_hdr.MAGIC2):
                return True
        elif where == mrs_signature_where.CENTRAL_DIR_HDR:
            if signature in (_mrs_central_dir_hdr.MAGIC1, _mrs_central_dir_hdr.MAGIC2):
                return True
        return False
    
    def __mem_read(self, offset: int, bufsize: int) -> bytes:
        self.__mem.seek(0, io.SEEK_END)
        sz = self.__mem.tell()
        if offset >= sz:
            raise BufferError('Offset %08x(%u) is invalid.')
        self.__mem.seek(offset, io.SEEK_SET)
        buf = self.__mem.read(bufsize)
        self.__mem.seek(0, io.SEEK_END)
        return buf
    
    def __is_duplicate(self, name):
        # print(name)
        fname = ''
        fext = ''
        fnum = 0
        exact_match = (False, 0)
        n = []

        p = re.compile('(?P<fname>.+?)(?:\s\((?P<fnum>\d+)\)|)(?P<fext>\.[^.]+?|)$', re.IGNORECASE)
        r = re.match(p, name)
        if r:
            rd = r.groupdict()
            fnum = int(rd.get('fnum')) if rd.get('fnum') else 0
            fname = rd.get('fname')
            fext = rd.get('fext')

        # print(f'Name: {fname}')
        # print(f'Ext:  {fext}')
        # print(f'Num:  {fnum}')

        for i in self.__files:
            # print(i.filenameuc)
            r = re.match(p, i.filenameuc)
            rd = r.groupdict()
            f2num = int(rd.get('fnum')) if rd.get('fnum') else 0
            f2name = rd.get('fname', '')
            f2ext = rd.get('fext', '')
            # print(f"{f2num} {f2name} {f2ext}")
            if (f2name.lower() == fname.lower()) and (f2ext.lower() == fext.lower()):
                if f2num == fnum:
                    # print('Exact match!')
                    exact_match = (True, self.__files.index(i))
                    continue
                n.append(f2num)
                continue
        
        if exact_match[0]:
            fnum = 2
            n.sort()
            for i in n:
                if i == fnum:
                    fnum += 1
                elif i != fnum:
                    # print(f"Found num available: {i}")
                    break
            # print('Got n\'s:', n)
            # print(f'fnum is {fnum}')
            return (exact_match[1], f'{fname} ({fnum}){fext}')
        
        return None
    
    def add_file(self, name: str, /, final_name: str = None, on_dupe: mrs_dupe_behavior = mrs_dupe_behavior.KEEP_NEW):
        print('mrs.add_file():')
        print(f'Adding file "{name}"')

        real_name = path.realpath(name)
        print(f'which real path is "{real_name}"')

        if not final_name:
            final_name = path.split(real_name)[1]
        
        final_name = final_name.replace('/', '\\')
        try:
            _is_valid_filename(final_name)
        except:
            raise UnicodeError(f'final_name contains an invalid file name: "{final_name}".')# from None
        
        ###TODO: Verificar se há arquivos duplicados
        dup = self.__is_duplicate(final_name)
        if dup:
            if on_dupe == mrs_dupe_behavior.KEEP_OLD:
                raise ValueError(f'Duplicate file for "{final_name}".')
            elif on_dupe == mrs_dupe_behavior.KEEP_BOTH:
                final_name = dup[1]

        f = _mrs_file()
        f.filenameuc = final_name

        try:
            (final_name, f.filenameenc) = _enc_str(final_name)
        except:
            raise UnicodeError('Unknown encoding for final_name.')
        
        # try:
        #     final_name = final_name.encode('mbcs')
        #     f.filenameenc = 'mbcs'
        # except:
        #     try:
        #         final_name = final_name.encode('1252')
        #         f.filenameenc = '1252'
        #     except:
        #         try:
        #             final_name = final_name.encode('utf-8')
        #             f.filenameenc = 'utf-8'
        #         except:
        #             raise UnicodeError('Unknown encoding for final_name.')
        
        print(f'Final name will be "{final_name}"')

        if not path.exists(real_name):
            raise FileNotFoundError(f'"{name}" was not found.')

        if path.isdir(real_name):
            raise IsADirectoryError(f'"{name}" is a directory.')

        fp = None
        try:
            fp = open(real_name, 'rb')
        except:
            raise IOError(f'Cannot open "{name}".')
        
        ftime = path.getmtime(fp.fileno())
        fsize = path.getsize(fp.fileno())

        f.dh.signature         = _mrs_central_dir_hdr.MAGIC1
        f.dh.version_made      = _mrs_central_dir_hdr.VER_MADE
        f.dh.version_needed    = _mrs_central_dir_hdr.VER_NEEDED
        f.dh.compression       = mrs.COMPRESSION_DEFLATE
        f.dh.uncompressed_size = fsize
        f.dh.filename_length   = len(final_name)
        f.dh.filetime.dostime(ftime)

        f.lh.signature         = _mrs_local_hdr.MAGIC1
        f.lh.version           = _mrs_local_hdr.VER
        f.lh.compression       = f.dh.compression
        f.lh.uncompressed_size = f.dh.uncompressed_size
        f.lh.filename_length   = f.dh.filename_length
        f.lh.filetime          = f.dh.filetime

        buf = fp.read()

        fp.close()
        
        cbuf = None
        if fsize > 0:
            f.dh.crc32 = zlib.crc32(buf)
            f.lh.crc32 = f.dh.crc32
            try:
                cobj = zlib.compressobj(9, 8, -15)
                cbuf = cobj.compress(buf)
            except:
                cbuf = buf
                f.dh.compression = mrs.COMPRESSION_STORE
        else:
            cbuf = buf
            f.dh.compression = mrs.COMPRESSION_STORE
        
        buf = None
        
        f.dh.compressed_size = len(cbuf)
        f.lh.compressed_size = f.dh.compressed_size
        print('Compressed size: %u' % f.dh.compressed_size)

        f.lh.compression = f.dh.compression

        f.dh.filename = final_name
        f.lh.filename = f.dh.filename

        f.dh.offset = self.__mem.tell()
        self.__mem.write(cbuf)
        print('Offset is now: %u' % self.__mem.tell())
        
        f.dump()

        if on_dupe == mrs_dupe_behavior.KEEP_NEW and dup:
            self.__files[dup[0]] = f
            self.__files[dup[0]].lh.dump()
        else:
            self.__files.append(f)
            self.__hdr.dir_count += 1
            self.__hdr.total_dir_count = self.__hdr.dir_count
    
    def add_folder(self, name: str, /, base_name: str = None, on_dupe: mrs_dupe_behavior = mrs_dupe_behavior.KEEP_NEW):
        print(f'Adding folder "{name}"')
        real_path = path.realpath(name)
        print(f'Which real path is "{real_path}"')

        if not path.exists(real_path):
            raise FileNotFoundError(f'"{name}" was not found.')
        if not path.isdir(real_path):
            raise NotADirectoryError(f'"{name}" is not a directory.')
        
        fl = glob(f'**', root_dir=real_path, recursive=True)
        for i in fl:
            fname = f'{real_path}/{i}'
            ffname = f'{base_name}/{i}' if base_name else i
            print(fname)
            if path.isdir(fname):
                print(' <skipping dir>')
                continue
            self.add_file(fname, final_name=ffname, on_dupe=on_dupe)
    
    # TODO: add_mrs
    def add_mrs(self, name: str, /, base_name: str = None, on_dupe: mrs_dupe_behavior = mrs_dupe_behavior.KEEP_NEW):
        # print('Let\'s add files from a MRS archive')
        realpath = path.realpath(name)
        # print(f'"{name}", which real path is "{realpath}"')

        if not path.exists(realpath):
            raise FileNotFoundError(f'"{name}" was not found.')
        
        if path.isdir(realpath):
            raise IsADirectoryError(f'"{name}" is a directory.')
        
        fp = None
        try:
            fp = open(realpath, 'rb')
        except:
            raise IOError(f'Cannot open "{name}".')
        
        fp.seek(-22, io.SEEK_END)
        
        _decrypt = mrs_encryption()
        _decrypt.base_hdr        = self.__decrypt.base_hdr if self.__decrypt.base_hdr else self.__mrs_default_decrypt
        _decrypt.local_hdr       = self.__decrypt.local_hdr if self.__decrypt.local_hdr else _decrypt.base_hdr
        _decrypt.central_dir_hdr = self.__decrypt.central_dir_hdr if self.__decrypt.central_dir_hdr else _decrypt.base_hdr
        _decrypt.buffer          = self.__decrypt.buffer
        
        hdr = _mrs_hdr()

        hdr_b = fp.read(_mrs_hdr.size)
        hdr_b = _decrypt.base_hdr(hdr_b, _mrs_hdr.size)

        hdr.read(hdr_b)

        if (not self.__mrs_default_signatures(mrs_signature_where.BASE_HDR, hdr.signature)) and (not self.__sigcheck or not self.__sigcheck(mrs_signature_where.BASE_HDR, hdr.signature)):
            raise NotAMrsFileError(f'"{name}" is not a MRS file or the decryption is incorrect.')

        # print('  Dir size: %u' % hdr.dir_size)
        # print('Dir offset: %08x' % hdr.dir_offset)

        fp.seek(hdr.dir_offset)
        cdir_b = fp.read(hdr.dir_size)

        if len(cdir_b) != hdr.dir_size:
            raise NotAMrsFileError(f'"{name}" is not a MRS file or is corrupted.')
        
        _files = []
        cdir_b = _decrypt.central_dir_hdr(cdir_b, hdr.dir_size)
        offset = 0
        for i in range(hdr.dir_count):
            f = _mrs_file()
            # print(f'Reading file {i} header')
            cdir = _mrs_central_dir_hdr()
            f.dh.read(cdir_b)

            if (not self.__mrs_default_signatures(mrs_signature_where.CENTRAL_DIR_HDR, f.dh.signature)) and (not self.__sigcheck or not self.__sigcheck(mrs_signature_where.CENTRAL_DIR_HDR, f.dh.signature)):
                raise InvalidMrsEncryptionError(f'Invalid decryption for "{name}".')
            
            try:
                (f.filenameuc, f.filenameenc) = _dec_str(f.dh.filename)
            except:
                raise UnicodeError(f'"{name}": Unknown encoding for {f.dh.filename} filename.') from None
            # try:
            #     f.filenameuc = f.dh.filename.decode('mbcs')
            #     f.filenameenc = 'mbcs'
            # except:
            #     try:
            #         f.filenameuc = f.dh.filename.decode('1252')
            #         f.filenameenc = '1252'
            #     except:
            #         try:
            #             f.filenameuc = f.dh.filename.decode('utf-8')
            #             f.filenameenc = 'utf-8'
            #         except:
            #             raise UnicodeError(f'"{name}": Unknown encoding for {f.dh.filename} filename.')
            
            if base_name:
                f.filenameuc = f'{base_name}/{f.filenameuc}'
                f.dh.filename = f.filenameuc.encode(f.filenameenc)

            try:
                _is_valid_filename(f.filenameuc)
            except:
                raise UnicodeError(f'"{name}": "{f.filenameuc}" contains a invalid file name.') from None
            
            fp.seek(f.dh.offset)
            lhdr_b = fp.read(_mrs_local_hdr.size) # Local header bytes
            lhdr_b = _decrypt.local_hdr(lhdr_b, _mrs_local_hdr.size)

            f.lh.read(lhdr_b)
            # lhdr = _mrs_local_hdr()
            # lhdr.read(lhdr_b)
            
            if (not self.__mrs_default_signatures(mrs_signature_where.LOCAL_HDR, f.lh.signature)) and (not self.__sigcheck or not self.__sigcheck(mrs_signature_where.LOCAL_HDR, f.lh.signature)):
                raise InvalidMrsEncryptionError(f'Invalid decryption for "{name}".')
            
            # Let's skip file name for local header
            fp.seek(f.lh.filename_length, io.SEEK_CUR)
            if f.lh.extra_length:
                _extra = fp.read(f.lh.extra_length)
                f.lh.extra = self.__mrs_default_decrypt(_extra, f.lh.extra_length)
            
            # Now let's read the file content
            # NOTE: Should it give an error for 'compression' field value different from 0 and 8 ?
            # We skip zero-byte files for decompression and/or reading
            f.dh.offset = 0
            if f.dh.compressed_size != 0:
                f.dh.offset = self.__mem.tell()
                # print(f.dh.offset)
                # print(f.dh.compressed_size)
                fbuf = fp.read(f.dh.compressed_size)
                # TODO: Decrypt the file buffer if there's a decryption routine for it
                if f.dh.compression == self.COMPRESSION_DEFLATE:
                    # print('Compression method: DEFLATE')
                    # fbuf = fp.read(f.dh.compressed_size)
                    # print(fbuf)
                    try:
                        ffbuf = zlib.decompress(fbuf, -15)
                    except:
                        raise zlib.error(f'Invalid DEFLATE stream at "{name}" for the archived file named "{f.dh.filename}".')
                    self.__mem.seek(0, io.SEEK_END)
                    self.__mem.write(fbuf)
                else:
                    # print('Compression method: STORE')
                    # fbuf = fp.read(f.dh.compressed_size)
                    self.__mem.seek(0, io.SEEK_END)
                    self.__mem.write(fbuf)
                    # print(fbuf)

            dup = self.__is_duplicate(f.filenameuc)
            if dup:
                if on_dupe == mrs_dupe_behavior.KEEP_OLD:
                    raise ValueError(f'Duplicate file for "{f.filenameuc}" in "{name}".')
                elif on_dupe == mrs_dupe_behavior.KEEP_BOTH:
                    f.filenameuc = dup[1]

            # print(offset, f'({f.dh.size}, {f.dh.filename_length}, {f.dh.extra_length}, {f.dh.comment_length})')
            offset_next = (f.dh.size + f.dh.filename_length + f.dh.extra_length + f.dh.comment_length)

            # Update file name
            f.dh.filename = f.filenameuc.encode(f.filenameenc)
            f.dh.filename_length = len(f.dh.filename)
            f.lh.filename = f.dh.filename
            f.lh.filename_length = len(f.lh.filename)
            
            _files.append((f, dup))

            cdir_b = cdir_b[offset_next:]
        
        # print('ALL FILES OK!')

        for (i,j) in _files:
            if j and on_dupe==mrs_dupe_behavior.KEEP_NEW:
                # print('Found duplicate')
                self.__files[j[0]] = i
            else:
                # print(i.filenameuc, i.filenameenc)
                # print(i.dh.dump())
                # print(i.lh.dump())
                self.__files.append(i)
                self.__hdr.dir_count += 1
                self.__hdr.total_dir_count = self.__hdr.dir_count
        
        fp.close()

    def read(self, index: int) -> bytes:
        if not isinstance(index, int):
            raise TypeError('index MUST be an unsigned integer.')
        
        if index >= self.__hdr.dir_count:
            raise IndexError(f'Out of bound index, there\'s no file at index {index}.')
        
        # print(f'Trying to read file at index {index}')
        b = self.__mem_read(self.__files[index].dh.offset, self.__files[index].dh.compressed_size)
        # print(self.__files[index].dh.offset, self.__files[index].dh.compressed_size, b)
        if self.__files[index].dh.compression == mrs.COMPRESSION_DEFLATE:
            b = zlib.decompress(b, -15)
        return b
    
    def set_decryption(self, *, base_hdr=NotAssigned, local_hdr=NotAssigned, central_dir_hdr=NotAssigned, buffer=NotAssigned):
        if base_hdr != NotAssigned:
            if not callable(base_hdr):
                raise TypeError('"base_hdr" MUST be a function.')
            self.__decrypt.base_hdr = base_hdr
        
        if local_hdr != NotAssigned:
            if not callable(local_hdr):
                raise TypeError('"local_hdr" MUST be a function.')
            self.__decrypt.local_hdr = local_hdr
        
        if central_dir_hdr != NotAssigned:
            if not callable(central_dir_hdr):
                raise TypeError('"central_dir_hdr" MUST be a function.')
            self.__decrypt.central_dir_hdr = central_dir_hdr
        
        if buffer != NotAssigned:
            if not callable(buffer):
                raise TypeError('"buffer" MUST be a function.')
            self.__decrypt.buffer = buffer
    
    def set_encryption(self, *, base_hdr=NotAssigned, local_hdr=NotAssigned, central_dir_hdr=NotAssigned, buffer=NotAssigned):
        if base_hdr != NotAssigned:
            if not callable(base_hdr):
                raise TypeError('"base_hdr" MUST be a function.')
            self.__encrypt.base_hdr = base_hdr
        
        if local_hdr != NotAssigned:
            if not callable(local_hdr):
                raise TypeError('"local_hdr" MUST be a function.')
            self.__encrypt.local_hdr = local_hdr
        
        if central_dir_hdr != NotAssigned:
            if not callable(central_dir_hdr):
                raise TypeError('"central_dir_hdr" MUST be a function.')
            self.__encrypt.central_dir_hdr = central_dir_hdr
        
        if buffer != NotAssigned:
            if not callable(buffer):
                raise TypeError('"buffer" MUST be a function.')
            self.__encrypt.buffer = buffer
    
    def set_signature_check(self, f):
        if f != None and not callable(f):
            raise TypeError(f'"f" MUST be a function.')
        self.__sigcheck = f
    
    def get_file_count(self) -> int:
        return self.__hdr.dir_count

    def get_file(self, index: int) -> mrs_file:
        if not isinstance(index, int):
            raise TypeError('index MUST be an unsigned integer')

        if index >= self.__hdr.dir_count:
            raise IndexError(f'Out of bound index, there\'s no file at index {index}')
        f = self.__files[index]
        return mrs_file(index=index, name=f.filenameuc, crc32=f.dh.crc32, size=f.dh.uncompressed_size, compressed_size=f.dh.compressed_size, ftime=f.dh.filetime.mktimedos(), lhextra=f.lh.extra, dhextra=f.dh.extra, dhcomment=f.dh.comment)

    def set_file(self, index: int, file: mrs_file):
        if not isinstance(index, int):
            raise TypeError('index MUST be an unsigned integer.')
        
        if not isinstance(file, mrs_file):
            raise TypeError('file MUST be a mrs_file object.')
        
        if index >= self.__hdr.dir_count:
            raise IndexError(f'Out of bound index, there\'s no file at index {index}.')
        
        # name
        self.__files[index].filenameuc = file.name
        (self.__files[index].dh.filename, self.__files[index].filenameenc) = _enc_str(file.name)
        self.__files[index].lh.filename = self.__files[index].dh.filename
        # ftime
        tim = _dostime()
        tim.dostime(file.ftime)
        self.__files[index].dh.filetime = tim
        # lhextra
        self.__files[index].lh.extra = file.lh_extra
        # dhextra
        self.__files[index].dh.extra = file.dh_extra
        # dhcomment
        self.__files[index].dh.comment = file.dh_comment
    
    def get_files(self):
        for i in self.__files:
            yield mrs_file(index=self.__files.index(i), name=i.filenameuc, crc32=i.dh.crc32, compressed_size=i.dh.compressed_size, size=i.dh.uncompressed_size, ftime=i.dh.filetime.mktimedos(), lhextra=i.lh.extra, dhextra=i.dh.extra, dhcomment=i.dh.comment)