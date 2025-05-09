"""
    mrs.py
    Wrapper of libmrs, for Python
    by Wes, 2025
"""

import io
import os
from os import path
import re
import tempfile
import time
import zlib

######## _dostime ##############################################
class _dostime:
    class _time:
        def __init__(self):
            self.hour   = 0
            self.minute = 0
            self.second = 0
            self.value  = 0
        
        def set_time(self, tm: time.struct_time):
            self.hour   = int(tm.tm_hour)
            self.minute = int(tm.tm_min)
            self.second = int(tm.tm_sec / 2)
            self.value = (self.second & 0b11111) | ((self.minute & 0b111111) << 5) | ((self.hour & 0b11111) << 11)
        
    class _date:
        def __init__(self):
            self.year  = 0
            self.month = 0
            self.day   = 0
            self.value = 0
        
        def set_date(self, tm: time.struct_time):
            self.year  = int(tm.tm_year - 1980)
            self.month = int(tm.tm_mon)
            self.day   = int(tm.tm_mday)
            self.value = (self.day & 0b11111) | ((self.month & 0b1111) << 5) | ((self.year & 0b1111111) << 9)
        
    def __init__(self):
        self.time = self._time()
        self.date = self._date()
    
    def dostime(self, t: float = None):
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
    
    def mktimedos(self) -> time.struct_time:
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

    def __init__(self):
        self.signature       = 0
        self.disk_num        = 0
        self.disk_start      = 0
        self.dir_count       = 0
        self.total_dir_count = 0
        self.dir_size        = 0
        self.dir_offset      = 0
        self.comment_length  = 0
    
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
    
    def read(self, f):
        pass

    def write(self, f):
        pass

######## _mrs_local_hdr ########################################
class _mrs_local_hdr:
    MAGIC1  = 0x4034b50
    MAGIC2  = 0x85840000
    VER     = 0x14

    size = 30

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
        print('  filetime          %02x %02x' % (self.filetime.time, self.filetime.date))
        print('  crc32             %08x' % self.crc32)
        print('  compressed_size   %u' % self.compressed_size)
        print('  uncompressed_size %u' % self.uncompressed_size)
        print('  filename_length   %u' % self.filename_length)
        print('  extra_length      %u' % self.extra_length)
        print('  filename          %s' % self.filename if self.filename else '<empty>')
        print('  extra             %.*s' % (self.extra_length if self.extra else 7, self.extra if self.extra else '<empty>'))

######## _mrs_central_dir_hdr ##################################
class _mrs_central_dir_hdr:
    MAGIC1     = 0x2014b50
    MAGIC2     = 0x5024b80
    VER_MADE   = 0x19
    VER_NEEDED = 0x14

    size = 46

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

######## _mrs_file #############################################
class _mrs_file:
    def __init__(self):
        self.lh = _mrs_local_hdr()
        self.dh = _mrs_central_dir_hdr()
        self.filenameuc = None

class mrs_dupe_behavior:
    KEEP_NEW  = 0
    KEEP_OLD  = 1
    KEEL_BOTH = 2

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
        self.__hdr     = _mrs_hdr()
        self.__files: list[_mrs_file] = []
        self.__mem     = tempfile.TemporaryFile('w+b')
        self.__decrypt = mrs_encryption()
        self.__encrypt = mrs_encryption()
    
    def __del__(self):
        if not self.__mem.closed:
            self.__mem.close()
        
    def __is_valid_filename(self, f: str):
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
    
    def __mem_read(self, offset: int, bufsize: int) -> bytes:
        self.__mem.seek(0, io.SEEK_END)
        sz = self.__mem.tell()
        if offset >= sz:
            raise BufferError('Offset %08x(%u) is invalid.')
        self.__mem.seek(offset, io.SEEK_SET)
        buf = self.__mem.read(bufsize - offset)
        self.__mem.seek(0, io.SEEK_END)
        return buf
    
    def __is_duplicate(self, name):
        print(name)
        fname = ''
        fext = ''
        fnum = 0
        n = []

        p = re.compile('(?P<fname>.+?)(?:\s\((?P<fnum>\d+)\)|)(?P<fext>\.[^.]+?|)$', re.IGNORECASE)
        r = re.match(p, name)
        if r:
            rd = r.groupdict()
            fnum = int(rd.get('fnum')) if rd.get('fnum') else 0
            fname = rd.get('fname')
            fext = rd.get('fext')

        print(f'Name: {fname}')
        print(f'Ext:  {fext}')
        print(f'Num:  {fnum}')

        for i in self.__files:
            print(i.filenameuc)
            r = re.match(p, i.filenameuc)
            rd = r.groupdict()
            f2num = int(rd.get('fnum')) if rd.get('fnum') else 0
            f2name = rd.get('fname')
            f2ext = rd.get('fext')
            print('')
    
    def add_file(self, name: str, /, final_name: str = None, on_dupe: mrs_dupe_behavior = mrs_dupe_behavior.KEEP_NEW):
        print('mrs.add_file():')
        print(f'Adding file "{name}"')

        real_name = path.realpath(name)
        print(f'which real path is "{real_name}"')

        if not final_name:
            final_name = path.split(real_name)[1]
        
        final_name = final_name.replace('/', '\\')
        try:
            self.__is_valid_filename(final_name)
        except:
            raise UnicodeError(f'final_name contains a invalid file name: "{final_name}".') from None
        
        ###TODO: Verificar se há arquivos duplicados
        self.__is_duplicate(final_name)

        f = _mrs_file()
        f.filenameuc = final_name
        
        try: final_name = final_name.encode('mbcs')
        except:
            try: final_name = final_name.encode('1252')
            except:
                try: final_name = final_name.encode('utf-8')
                except:
                    raise UnicodeError('final_name contains invalid characters.')
        
        print(f'Final name will be "{final_name}"')

        if not path.exists(real_name):
            raise FileNotFoundError(f'"{name}" was not found.')

        if path.isdir(real_name):
            raise IsADirectoryError(f'"{name}" is a directory.')

        fp = open(real_name, 'rb')
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
                cbuf = zlib.compress(buf, 9)
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
        ###TODO: Ação ao encontrar um arquivo duplicado

        self.__files.append(f)
        self.__hdr.dir_count += 1
        self.__hdr.total_dir_count = self.__hdr.dir_count

    def dump(self):
        pass