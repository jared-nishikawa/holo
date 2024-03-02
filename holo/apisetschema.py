import pefile
import struct


class ApisetNotFoundError(Exception):
    pass


class ApisetSchema(dict):
    def __init__(self, path):
        pef = pefile.PE(path)
        apiset = None
        for sec in pef.sections:
            if sec.Name == b'.apiset\x00':
                apiset = sec
        if not apiset:
            raise ApisetNotFoundError()
        data = apiset.get_data()
        version = struct.unpack("<i", data[:4])[0]
        if version == 2:
            A = ApisetMap(data)
        elif version == 6:
            A = ApisetMap6(data)
        sch = A.gen_schema()
        for k in sch:
            self[k] = sch[k]
        #self.schema = A.gen_schema()

    def resolve(self, name):
        name = name.lower()
        if "-" in name:
            name = name.split('.')[0][:-2]
            if name in self:
                name = self[name][-1]
        return name


class ApisetMap6:
    def __init__(self, data, index=0):
        self.data = data
        self.version = struct.unpack("<i", self.data[:4])[0]
        self.size = struct.unpack("<i", self.data[4:8])[0]
        self.zero1 = struct.unpack("<i", self.data[8:12])[0]
        self.num_hosts = struct.unpack("<i", self.data[12:16])[0]
        self.unk1 = struct.unpack("<i", self.data[16:20])[0]
        self.size2 = struct.unpack("<i", self.data[20:24])[0]
        self.unk2 = struct.unpack("<i", self.data[24:28])[0]
        desc_ptrs = [index + 28 + 24*i for i in range(self.num_hosts)]
        self.descriptors = [DLLHostDescriptor6(self.data[p:p+24]) for p in desc_ptrs]

    def gen_schema(self):
        schema = {}
        for D in self.descriptors:
            o = D.offset_dll_str
            l = D.str_len2
            v_dll = self.data[o:o+l].replace(b"\x00", b"").decode()
    
            for i in range(D.num_reds):
                r = D.offset_dll_red + 20*i
                red = DLLRedirector6(self.data[r:r+20])
                h_name = self.data[red.offset_hostname:red.offset_hostname+red.hostname_size]
                r_dll = h_name.replace(b"\x00", b"").decode()
                schema[v_dll] = schema.get(v_dll, []) + [r_dll]
        return schema

class DLLHostDescriptor6:
    def __init__(self, data):
        assert len(data) == 24
        self.zero1 = struct.unpack("<i", data[:4])[0]
        self.offset_dll_str = struct.unpack("<i", data[4:8])[0]
        self.str_len = struct.unpack("<i", data[8:12])[0]
        self.str_len2 = struct.unpack("<i", data[12:16])[0]
        self.offset_dll_red = struct.unpack("<i", data[16:20])[0]
        self.num_reds = struct.unpack("<i", data[20:24])[0]

class DLLRedirector6:
    def __init__(self, data):
        assert len(data) == 20
        self.zero0 = struct.unpack("<i", data[:4])[0]
        self.offset_importname = struct.unpack("<i", data[4:8])[0]
        self.importname_size = struct.unpack("<i", data[8:12])[0]
        self.offset_hostname = struct.unpack("<i", data[12:16])[0]
        self.hostname_size = struct.unpack("<i", data[16:20])[0]


class ApisetMap:
    def __init__(self, data, index=0):
        self.data = data
        self.version = struct.unpack("<i", self.data[:4])[0]
        self.num_hosts = struct.unpack("<i", self.data[4:8])[0]
        self.desc_ptrs = [index + 8 + 12*i for i in range(self.num_hosts)]

    def gen_schema(self):
        schema = {}
        for p in self.desc_ptrs:
            D = DLLHostDescriptor(self.data[p:p+12])
            o = D.offset_dll_str
            l = D.str_len
            v_dll = self.data[o:o+l].replace(b"\x00", b"").decode()[:-2]
    
            r = D.offset_dll_red
            R = DLLRedirector(self.data[r:r+4], r)

            q = R.red_ptrs[R.num_reds-1]
            for i in range(R.num_reds):
                q = R.red_ptrs[i]
                RD = Redirection(self.data[q:q+16])
                x,y = RD.offset2, RD.len2

                r_dll = self.data[x:x+y].replace(b"\x00", b"").decode()

                schema[v_dll] = schema.get(v_dll, []) + [r_dll]
        return schema

class DLLHostDescriptor:
    def __init__(self, data):
        assert len(data) == 12
        self.offset_dll_str = struct.unpack("<i", data[:4])[0]
        self.str_len = struct.unpack("<i", data[4:8])[0]
        self.offset_dll_red = struct.unpack("<i", data[8:12])[0]

class DLLRedirector:
    def __init__(self, data, index):
        self.num_reds = struct.unpack("<i", data[:4])[0]
        self.red_ptrs = [index + 4 + 16*i for i in range(self.num_reds)]

class Redirection:
    def __init__(self, data):
        assert len(data) == 16
        self.offset1 = struct.unpack("<i", data[:4])[0]
        self.len1 = struct.unpack("<h", data[4:6])[0]
        self.pad1 = struct.unpack("<h", data[6:8])[0]
        self.offset2 = struct.unpack("<i", data[8:12])[0]
        self.len2 = struct.unpack("<h", data[12:14])[0]
        self.pad2 = struct.unpack("<h", data[14:16])[0]

