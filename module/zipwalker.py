"""
Zip Walker: Zip File Analyzer

Reference:
https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
"""

import os
import struct
import logging


Logger = None


def init_logging(logname, logfile, debug):
    """init logging"""

    global Logger

    Logger = logging.getLogger(logname)
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
            
    if debug:
        Logger.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)
        fh = logging.FileHandler(logfile)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        Logger.addHandler(fh)
    else:
        Logger.setLevel(logging.WARN)
        ch.setLevel(logging.WARN)         
    
    ch.setFormatter(formatter)
    Logger.addHandler(ch)

    if debug:
        log_debug('[******** Debug Mode ********]')


def log_debug(message):
    """log debug message"""

    global Logger

    if Logger is not None:
        Logger.debug(message)


def log_warn(message):
    """log warning message"""

    global Logger

    if Logger is not None:
        Logger.debug(message)


def log_error(message):
    """log error message"""

    global Logger

    if Logger is not None:
        Logger.debug(message)



class ZipLocalHeader:

    def __init__(self, data):
        """init ZipLocalHeader class"""

        self.signature = None
        self.version = None
        self.flag = None
        self.compression_method = None
        self.last_modify_time = None
        self.last_modify_date = None
        self.crc32 = None
        self.compressed_size = None
        self.uncompressed_size = None
        self.filename_length = None
        self.extra_field_length = None
        self.filename = None
        self.extra_field = None
        self.encrypted = False
        self.length = 0

        pointer = 0

        self.signature = data[0x00:0x04]
        log_debug('LocalHeader::Signature: ' + self.signature.encode('hex'))
        if self.signature != '\x50\x4b\x03\x04':
            raise Exception('LocalHeader::Signature Invalid')

        self.version = struct.unpack('<H', data[0x04:0x06])[0]
        log_debug('LocalHeader::Version: ' + hex(self.version))

        self.flag = struct.unpack('<H', data[0x06:0x08])[0]
        log_debug('LocalHeader::Flag: ' + hex(self.flag))

        self.compression_method = struct.unpack('<H', data[0x08:0x0A])[0]
        log_debug('LocalHeader::CompressionMethod: ' + hex(self.compression_method))

        if self.compression_method == 6:
            log_debug('Compression Method: Imploded')
        elif self.compression_method == 8:
            log_debug('Compression Method: Deflated')
        elif self.compression_method == 9:
            log_debug('Compression Method: Enhanced Deflating using Deflate64')
        elif self.compression_method == 12:
            log_debug('Compression Method: BZIP2')
        elif self.compression_method == 14:
            log_debug('Compression Method: LZMA')
        else:
            log_debug('Compression Method: Other')

        if self.flag & 0x01:
            log_debug('Flag: File Encrypted')
            self.encrypted = True

        if self.compression_method == 8 or self.compression_method == 9:
            compression_option = (self.flag >> 1) & 0x03
            if compression_option == 0:
                log_debug('Compression Option: Normal')
            elif compression_option == 1:
                log_debug('Compression Option: Maximum')
            elif compression_option == 2:
                log_debug('Compression Option: Fast')
            elif compression_option == 3:
                log_debug('Compression Option: Super Fast')
            
        self.last_modify_time = struct.unpack('<H', data[0x0A:0x0C])[0]
        log_debug('LocalHeader::LastModifyTime: ' + hex(self.last_modify_time))

        self.last_modify_date = struct.unpack('<H', data[0x0C:0x0E])[0]
        log_debug('LocalHeader::LastModifyDate: ' + hex(self.last_modify_date))

        self.crc32 = struct.unpack('<I', data[0x0E:0x12])[0]
        log_debug('LocalHeader::CRC32: ' + hex(self.crc32))

        self.compressed_size = struct.unpack('<I', data[0x12:0x16])[0]
        log_debug('LocalHeader::CompressedSize: ' + hex(self.compressed_size))

        self.uncompressed_size = struct.unpack('<I', data[0x16:0x1A])[0]
        log_debug('LocalHeader::UncompressedSize: ' + hex(self.uncompressed_size))

        self.filename_length = struct.unpack('<H', data[0x1A:0x1C])[0]
        log_debug('LocalHeader::FilenameLength: ' + hex(self.filename_length))
        
        self.extra_field_length = struct.unpack('<H', data[0x1C:0x1E])[0]
        log_debug('LocalHeader::ExtraFieldLength: ' + hex(self.extra_field_length))

        if self.filename_length > 0:
            self.filename = data[0x1E:0x1E+self.filename_length]
            log_debug('LocalHeader::Filename: ' + self.filename)

        pointer = 0x1E + self.filename_length
        if self.extra_field_length > 0:
            self.extra_field = data[pointer:pointer+self.extra_field_length]
            log_debug('LocalHeader::Extra: ' + self.extra_field.encode('hex'))

        self.length = pointer + self.extra_field_length


class CentralDirectoryHeader:

    def __init__(self, data):
        """init CentralDirectoryHeader class"""

        self.signature = None
        self.version_made_by = None
        self.version_needed_to_extract = None
        self.flag = None
        self.compression_method = None
        self.last_modify_time = None
        self.last_modify_date = None
        self.crc32 = None
        self.compressed_size = None
        self.uncompressed_size = None
        self.filename_length = None
        self.extra_field_length = None
        self.comment_length = None
        self.disk_number_start = None
        self.internal_file_attributes = None
        self.external_file_attributes = None
        self.local_header_offset = None
        self.filename = None
        self.extra_field = None
        self.comment = None
        self.length = 0

        pointer = 0

        self.signature = data[0x00:0x04]
        log_debug('LocalHeader::Signature: ' + self.signature.encode('hex'))
        if self.signature != '\x50\x4b\x01\x02':
            raise Exception('CentralDirectoryHeader::Signature Invalid')

        self.version_made_by = struct.unpack('<H', data[0x04:0x06])[0]
        log_debug('CentralDirectoryHeader::VersionMadeBy: ' + hex(self.version_made_by))

        self.version_needed_to_extract = struct.unpack('<H', data[0x06:0x08])[0]
        log_debug('CentralDirectoryHeader::VersionNeededToExtract: ' + hex(self.version_needed_to_extract))

        self.flag = struct.unpack('<H', data[0x08:0x0A])[0]
        log_debug('CentralDirectoryHeader::Flag: ' + hex(self.flag))

        self.compression_method = struct.unpack('<H', data[0x0A:0x0C])[0]
        log_debug('CentralDirectoryHeader::CompressionMethod: ' + hex(self.compression_method))

        self.last_modify_time = struct.unpack('<H', data[0x0C:0x0E])[0]
        log_debug('CentralDirectoryHeader::LastModifyTime: ' + hex(self.last_modify_time))

        self.last_modify_date = struct.unpack('<H', data[0x0E:0x10])[0]
        log_debug('CentralDirectoryHeader::LastModifyDate: ' + hex(self.last_modify_date))

        self.crc32 = struct.unpack('<I', data[0x10:0x14])[0]
        log_debug('CentralDirectoryHeader::CRC32: ' + hex(self.crc32))
            
        self.compressed_size = struct.unpack('<I', data[0x14:0x18])[0]
        log_debug('CentralDirectoryHeader::CompressedSize: ' + hex(self.compressed_size))

        self.uncompressed_size = struct.unpack('<I', data[0x18:0x1C])[0]
        log_debug('CentralDirectoryHeader::UncompressedSize: ' + hex(self.uncompressed_size))

        self.filename_length = struct.unpack('<H', data[0x1C:0x1E])[0]
        log_debug('CentralDirectoryHeader::FilenameLength: ' + hex(self.filename_length))
        
        self.extra_field_length = struct.unpack('<H', data[0x1E:0x20])[0]
        log_debug('CentralDirectoryHeader::ExtraFieldLength: ' + hex(self.extra_field_length))

        self.comment_length = struct.unpack('<H', data[0x20:0x22])[0]
        log_debug('CentralDirectoryHeader::CommentLength: ' + hex(self.comment_length))

        self.disk_number_start = struct.unpack('<H', data[0x22:0x24])[0]
        log_debug('CentralDirectoryHeader::DiskNumberStart: ' + hex(self.disk_number_start))

        self.internal_file_attributes = struct.unpack('<H', data[0x24:0x26])[0]
        log_debug('CentralDirectoryHeader::InternalFileAttributes: ' + hex(self.internal_file_attributes))

        self.external_file_attributes = struct.unpack('<I', data[0x26:0x2A])[0]
        log_debug('CentralDirectoryHeader::ExternalFileAttributes: ' + hex(self.external_file_attributes))

        self.local_header_offset = struct.unpack('<I', data[0x2A:0x2E])[0]
        log_debug('CentralDirectoryHeader::LocalHeaderOffset: ' + hex(self.local_header_offset))

        if self.filename_length > 0:
            self.filename = data[0x2E:0x2E+self.filename_length]
            log_debug('CentralDirectoryHeader::Filename: ' + self.filename)

        pointer = 0x2E + self.filename_length
        if self.extra_field_length > 0:
            self.extra_field = data[pointer:pointer+self.extra_field_length]
            log_debug('CentralDirectoryHeader::Extra: ' + self.extra_field.encode('hex'))

        pointer += self.extra_field_length
        if self.comment_length > 0:
            self.comment = data[pointer:pointer+self.comment_length]
            log_debug('CentralDirectoryHeader::Comment: ' + self.comment)

        self.length = pointer + self.comment_length


class CentralDirectoryEnd:

    def __init__(self, data):
        """init CentralDirectoryEnd class"""

        self.signature = None
        self.number_this_disk = None
        self.central_directory_start_disk = None
        self.number_central_directory_entries = None
        self.number_file_entries = None
        self.central_directory_size = None
        self.central_directory_offset = None
        self.zip_comment_length = None
        self.zip_comment = None
        self.length = 0

        self.signature = data[0x00:0x04]
        log_debug('LocalHeader::Signature: ' + self.signature.encode('hex'))
        if self.signature != '\x50\x4b\x05\x06':
            raise Exception('CentralDirectoryEnd::Signature Invalid')
        
        self.number_this_disk = struct.unpack('<H', data[0x04:0x06])[0]
        log_debug('CentralDirectoryEnd::NumberThisDisk: ' + hex(self.number_this_disk))

        self.central_directory_start_disk = struct.unpack('<H', data[0x06:0x08])[0]
        log_debug('CentralDirectoryEnd::CentralDirectoryStartDisk: ' + hex(self.central_directory_start_disk))

        self.number_central_directory_entries = struct.unpack('<H', data[0x08:0x0A])[0]
        log_debug('CentralDirectoryEnd::CentralDirectoryEntries: ' + hex(self.number_central_directory_entries))

        self.number_file_entries = struct.unpack('<H', data[0x0A:0x0C])[0]
        log_debug('CentralDirectoryEnd::FileEntries: ' + hex(self.number_file_entries))

        self.central_directory_size = struct.unpack('<I', data[0x0C:0x10])[0]
        log_debug('CentralDirectoryEnd::CentralDirectorySize: ' + hex(self.central_directory_size))

        self.central_directory_offset = struct.unpack('<I', data[0x10:0x14])[0]
        log_debug('CentralDirectoryEnd::CentralDirectoryOffset: ' + hex(self.central_directory_offset))

        self.zip_comment_length = struct.unpack('<H', data[0x14:0x16])[0]
        log_debug('CentralDirectoryEnd::ZipCommentLength: ' + hex(self.zip_comment_length))

        if self.zip_comment_length > 0:
            self.zip_comment = data[0x16:0x16+zip_comment_length]
            log_debug('CentralDirectoryEnd::ZipComment: ' + self.zip_comment)

        self.length = 0x16 + self.zip_comment_length


class Zip:

    def __init__(self, filename, debug=False):
        """init Zip class"""
        
        logname = os.path.basename(filename)
        logfile = 'zipwalker_debug.txt'
        init_logging(logname, logfile, debug)

        log_debug('File: ' + filename)

        self.filename = filename
        self.data = open(filename, 'rb').read()
        self.zipped_files = list()
        self.central_directory_headers = list()

        i = 0
        pointer = 0
        signature = ''
        while True:
            log_debug('######## File ' + hex(i+1) + ' ########')
            
            zipped_file = dict()
            
            zipped_file['localheader'] = ZipLocalHeader(self.data[pointer:])
            pointer += zipped_file['localheader'].length
            
            zipped_file['filedata'] = self.data[pointer:pointer+zipped_file['localheader'].compressed_size]
            log_debug('FileDataSize: ' + hex(len(zipped_file['filedata'])))
            pointer += zipped_file['localheader'].compressed_size
            
            signature = self.data[pointer:pointer+0x04]
            log_debug('NextSignature: ' + signature.encode('hex'))
            
            if signature == '\x50\x4b\x07\x08':
                zipped_file['crc32'] = struct.unpack('<I', self.data[pointer+0x04:pointer+0x08])[0]
                log_debug('CRC32: ' + hex(zipped_file['crc32']))

                zipped_file['compressedsize'] = struct.unpack('<I', self.data[pointer+0x08:pointer+0x0C])[0]
                log_debug('CompressedSize: ' + hex(zipped_file['compressedsize']))
                
                zipped_file['uncompressedsize'] = struct.unpack('<I', self.data[pointer+0x0C:pointer+0x10])[0]
                log_debug('UncompressedSize: ' + hex(zipped_file['uncompressedsize']))
                
                pointer += 16
                signature = self.data[pointer:pointer+0x04]
                log_debug('NextSignature: ' + signature.encode('hex'))
            
            self.zipped_files.append(zipped_file)
            if signature != '\x50\x4b\x03\x04':
                break
            
            i += 1

        i = 0
        while True:
            
            if signature != '\x50\x4b\x01\x02':
                break

            log_debug('######## Central Directory ' + hex(i+1) + ' ########')

            central_directory_header = CentralDirectoryHeader(self.data[pointer:])
            self.central_directory_headers.append(central_directory_header)
            
            pointer += central_directory_header.length
            signature = self.data[pointer:pointer+0x04]
            log_debug('NextSignature: ' + signature.encode('hex'))

            i += 1

        if signature == '\x50\x4b\x05\x06':

            log_debug('######## End of Central Directory ########')
            
            self.central_directory_end = CentralDirectoryEnd(self.data[pointer:])
            pointer += self.central_directory_end.length

        if pointer == len(self.data):
            log_debug('File End: ' + hex(pointer))
        elif pointer < len(data):
            log_debug('Overlay Data: ' + hex(len(data) - pointer))


    