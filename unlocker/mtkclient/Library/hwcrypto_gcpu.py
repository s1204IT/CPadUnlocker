#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2022 GPLv3 License

import hmac
import hashlib
import logging
from struct import pack, unpack
from binascii import hexlify
from mtkclient.Library.utils import LogBase, logsetup

CSS_DEC_DK = 0x00
CSS_DEC_TK = 0x01
CSS_DSC_AV = 0x02
CSS_AUTH_DRV = 0x03
CSS_AUTH_DEC = 0x04
CSS_AUTH_BK = 0x05

C2_D = 0x08
C2_E = 0x09
C2_G = 0x0A
C2_H = 0x0B
CPPM_DPAK = 0x0C
CPRM_DPAK = 0x0D
CPRM_EPAK = 0x0E
CPRM_DCI_VFY = 0x0F

AES_CTR = 0x1E
AES_OFB = 0x1F
AES_D = 0x20
AES_E = 0x21
AES_G = 0x22
AES_DPAK = 0x23
AES_EPAK = 0x24
AES_CMAC = 0x25
AES_DCBC = 0x26
AES_ECBC = 0x27
AES_H = 0x28

AES_D_CMP = 0x36
AESEK_D = 0x74
AESEK_E = 0x75
AESPK_EK_D = 0x76
AESPK_EK_E = 0x77
AESPK_D = 0x78
AESPK_E = 0x79
AESPK_DPAK = 0x7A
AESPK_EPAK = 0x7B
AESPK_DCBC = 0x7C
AESPK_ECBC = 0x7D
AESPK_EK_DCBC = 0x7E

VCPS_H = 0x28
VCPS_DPAK = 0x29
VCPS_EPAK = 0x2A
VCPS_DKBH = 0x2B
VCPS_DHDK = 0x2C
VCPS_DCBC = 0x2D
VCPS_ECBC = 0x2E

AACS_DBD = 0x30
AACS_EBD = 0x31
AACS_DTN = 0x32
AACS_ETN = 0x33
AACS_DHD = 0x34
AACS_EHD = 0x35
AACS_DV_CALC = 0x37

TDES_D = 0x50
TDES_E = 0x51
TDES_DMA_D = 0x52
TDES_DMA_E = 0x53
TDES_CBC_D = 0x54
TDES_CBC_E = 0x55

BDRE_DBD = 0x58
BDRE_EBD = 0x59
BDRE_DTN = 0x5A
BDRE_ETN = 0x5B
BDRE_BE = 0x5C

GCPU_WRITE = 0x6e
GCPU_READ = 0x6f

MEMCPY = 0x10
DMA = 0x11
SHA_1 = 0x40
SHA_256 = 0x41
MD5 = 0x42
SHA_224 = 0x43
ROM_BIST = 0x5E
RNG = 0x6B
MEM_XOR = 0x71
TS_DESC = 0x81
PTX = 0x8c
RC4DPAK = 0x87
RC4KSA = 0x88

regval = {
    "GCPU_REG_CTL": 0,
    "GCPU_REG_MSC": 4,

    "GCPU_AXI": 0x20,
    "GCPU_UNK2": 0x24,

    "GCPU_REG_PC_CTL": 0x400,
    "GCPU_REG_MEM_ADDR": 0x404,
    "GCPU_REG_MEM_DATA": 0x408,
    "GCPU_REG_READ_REG": 0x410,
    "GCPU_REG_MONCTL": 0x414,
    "GCPU_REG_DRAM_MON": 0x418,
    "GCPU_REG_CYC": 0x41c,
    "GCPU_REG_DRAM_INST_BASE": 0x420,

    "GCPU_REG_TRAP_START": 0x440,
    "GCPU_REG_TRAP_END": 0x478,

    "GCPU_REG_INT_SET": 0x800,
    "GCPU_REG_INT_CLR": 0x804,
    "GCPU_REG_INT_EN": 0x808,
    "GCPU_UNK3": 0x80C,

    "GCPU_REG_MEM_CMD": 0xC00,
    "GCPU_REG_MEM_P0": 0xC04,
    "GCPU_REG_MEM_P1": 0xC08,
    "GCPU_REG_MEM_P2": 0xC0C,
    "GCPU_REG_MEM_P3": 0xC10,
    "GCPU_REG_MEM_P4": 0xC14,
    "GCPU_REG_MEM_P5": 0xC18,
    "GCPU_REG_MEM_P6": 0xC1C,
    "GCPU_REG_MEM_P7": 0xC20,
    "GCPU_REG_MEM_P8": 0xC24,
    "GCPU_REG_MEM_P9": 0xC28,
    "GCPU_REG_MEM_P10": 0xC2C,
    "GCPU_REG_MEM_P11": 0xC30,
    "GCPU_REG_MEM_P12": 0xC34,
    "GCPU_REG_MEM_P13": 0xC38,
    "GCPU_REG_MEM_P14": 0xC3C,
    "GCPU_REG_MEM_Slot": 0xC40
}
CKSYS_BASE = 0x10000000
CLR_CLK_GATING_CTRL2 = (CKSYS_BASE + 0x09C)


class GCpuReg:
    def __init__(self, setup):
        self.gcpu_base = setup.gcpu_base
        self.read32 = setup.read32
        self.write32 = setup.write32

    def __setattr__(self, key, value):
        if key in ("mtk", "gcpu_base", "read32", "write32", "regval"):
            return super(GCpuReg, self).__setattr__(key, value)
        if key in regval:
            addr = regval[key] + self.gcpu_base
            return self.write32(addr, value)
        else:
            return super(GCpuReg, self).__setattr__(key, value)

    def __getattribute__(self, item):
        if item in ("mtk", "gcpu_base", "read32", "write32", "regval"):
            return super(GCpuReg, self).__getattribute__(item)
        if item in regval:
            addr = regval[item] + self.gcpu_base
            return self.read32(addr)
        else:
            return super(GCpuReg, self).__getattribute__(item)


def from_dwords(data) -> bytearray:
    res = bytearray()
    for i in range(0, data):
        res.extend(pack("<I", data[i]))
    return res


def to_dwords(data) -> list:
    res = []
    if len(data) % 4 != 0:
        data += b"\x00" * (4 - len(data) % 4)
    for i in range(0, len(data), 4):
        res.append(unpack("<I", data[i:i + 4])[0])
    return res


def xor_data(a: bytearray, b: bytearray, length=None):
    res = bytearray()
    if length is None:
        length = len(a)
    for i in range(0, length):
        res.append(a[i] ^ b[i])
    return res


class GCpu(metaclass=LogBase):
    def __init__(self, setup, loglevel=logging.INFO, gui: bool = False):
        self.__logger = logsetup(self, self.__logger, loglevel, gui)
        self.info = self.__logger.info
        self.error = self.__logger.error
        self.warning = self.__logger.warning
        self.read32 = setup.read32
        self.write32 = setup.write32
        self.reg = GCpuReg(setup)
        self.gcpu_base = setup.gcpu_base
        self.hwcode = setup.hwcode

    def reset(self):
        ctl = self.reg.GCPU_REG_CTL & 0xfffffff0
        self.reg.GCPU_REG_CTL = ctl
        self.reg.GCPU_REG_CTL = ctl | 0xf

        ctl = self.reg.GCPU_REG_CTL & 0xffffffe0
        msc = self.reg.GCPU_REG_MSC | (1 << 16)
        self.reg.GCPU_REG_CTL = ctl
        self.reg.GCPU_REG_MSC = msc
        self.reg.GCPU_REG_CTL = ctl | 0x1f

    def init(self):
        keyslot = 0x12
        ivslot = 0x1A
        self.reg.GCPU_REG_MEM_P2 = 0x0
        self.reg.GCPU_REG_MEM_P3 = 0x0
        self.reg.GCPU_REG_MEM_P4 = 0x0
        self.reg.GCPU_REG_MEM_P5 = 0x0
        self.reg.GCPU_REG_MEM_P6 = 0x0
        self.reg.GCPU_REG_MEM_P7 = 0x0
        self.reg.GCPU_REG_MEM_P8 = 0x0
        self.reg.GCPU_REG_MEM_P9 = 0x0
        self.reg.GCPU_REG_MEM_P10 = 0x0
        self.write32(self.gcpu_base + regval["GCPU_REG_MEM_CMD"] + keyslot * 4, [0, 0, 0, 0])
        self.write32(self.gcpu_base + regval["GCPU_REG_MEM_CMD"] + 22 * 4, [0, 0, 0, 0])
        self.write32(self.gcpu_base + regval["GCPU_REG_MEM_CMD"] + ivslot * 4, [0, 0, 0, 0, 0, 0, 0, 0])

    def uninit(self):
        self.reg.GCPU_REG_CTL = (self.reg.GCPU_REG_CTL & 0xfffffff0) | 0xf

    def mem_read(self, addr: int, length: int):
        self.reg.GCPU_REG_MEM_ADDR = addr
        return b"".join([pack("<I", self.reg.GCPU_REG_MEM_DATA + i * 4) for i in range(length // 4)])

    def mem_write(self, addr: int, data):
        if isinstance(data, bytes) or isinstance(data, bytearray):
            data = to_dwords(data)
        assert addr & (1 << 13)
        self.reg.GCPU_REG_MEM_ADDR = (1 << 31) | addr
        self.reg.GCPU_REG_MEM_DATA = data

    def acquire(self):
        if self.hwcode==0x8167:
            self.write32(CLR_CLK_GATING_CTRL2, self.read32(CLR_CLK_GATING_CTRL2) | 0x8000000)
            self.reg.GCPU_REG_CTL |= 0xF
            self.reg.GCPU_REG_MSC = self.reg.GCPU_REG_MSC & 0x7FF0BF7F | 0x34080
            self.reg.GCPU_REG_CTL |= 0x1F
            self.reg.GCPU_REG_MSC |= 0x2000
            self.reg.GCPU_AXI = 0x885B
            self.reg.GCPU_UNK2 &= 0xFFFDFFFD
            self.reg.GCPU_REG_MEM_ADDR = 0x80002000
            self.reg.GCPU_REG_INT_CLR = 1
            self.reg.GCPU_REG_INT_EN = 0
        else:
            self.reg.GCPU_REG_CTL &= 0xFFFFFFF0
            self.reg.GCPU_REG_CTL |= 0xF
            self.reg.GCPU_REG_MSC |= 0x10000
            self.reg.GCPU_REG_CTL &= 0xFFFFFFE0
            self.reg.GCPU_REG_MSC |= 0x10000
            self.reg.GCPU_REG_CTL |= 0x1F
            self.reg.GCPU_REG_MSC |= 0x2000

    def release(self):
        if self.hwcode in [0x8172, 0x8127, None]:
            self.reg.GCPU_REG_CTL = self.reg.GCPU_REG_CTL & 0xFFFFFFF0
            self.reg.GCPU_REG_CTL = self.reg.GCPU_REG_CTL | 0xF

    def set_pc(self, addr: int):
        self.reg.GCPU_REG_PC_CTL = addr

    def read_reg(self, register: int):
        self.reg.GCPU_REG_MONCTL = register
        return self.reg.GCPU_REG_READ_REG

    def read_regs(self):
        for register in range(32):
            yield register, self.read_reg(register)

    def memptr_set(self, offset, data):
        if self.gcpu_base is not None:
            if isinstance(data, bytes) or isinstance(data, bytearray):
                data = to_dwords(data)
            pos = 0
            for dw in data:
                self.write32(self.gcpu_base + regval["GCPU_REG_MEM_CMD"] + pos + (offset * 4), dw)
                pos += 4

    def memptr_get(self, offset, length):
        data = bytearray()
        for i in range(0, length, 4):
            data.extend(pack("<I", self.read32(self.gcpu_base + regval["GCPU_REG_MEM_CMD"] + i + (offset * 4))))
        return data

    def print_regs(self):
        regs = [(f"R{register}: %08X" % value) for register, value in self.read_regs()]
        for i in range(0, 32, 4):
            self.__logger.info(", ".join(regs[i * 4:(i * 4) + 4]))

    def cmd(self, cmd, addr=0, args=None):
        GCPU_INT_MASK = 3
        CLR_EN = 3
        if args is not None:
            for i in range(1, 48):
                self.write32(self.gcpu_base + regval["GCPU_REG_MEM_CMD"] + (i * 4), args[i])
        if self.hwcode == 0x8167:
            self.reg.GCPU_REG_INT_CLR = 1
            self.reg.GCPU_REG_INT_EN = 0
        else:
            self.reg.GCPU_REG_INT_CLR = CLR_EN
            self.reg.GCPU_REG_INT_EN = GCPU_INT_MASK
        self.reg.GCPU_REG_MEM_CMD = cmd
        self.reg.GCPU_REG_PC_CTL = addr

        while not self.reg.GCPU_REG_INT_SET:
            pass
        if self.reg.GCPU_REG_INT_SET & 2:
            if not self.reg.GCPU_REG_INT_SET & 1:
                while not self.reg.GCPU_REG_INT_SET:
                    pass
            result = -1
            self.reg.GCPU_REG_INT_CLR = CLR_EN
        else:
            while not self.reg.GCPU_REG_DRAM_MON & 1:
                pass
            result = 0
            self.reg.GCPU_REG_INT_CLR = CLR_EN
        return result

    def set_mode_cmd(self, encrypt=False, mode="cbc", encryptedkey=True):
        cmd = AESPK_EK_DCBC
        if encrypt:
            if mode == "ecb":
                if encryptedkey:
                    cmd = AESPK_EK_E
                else:
                    cmd = AESPK_E
            elif mode == "cbc":
                if encryptedkey:
                    cmd = AESPK_ECBC
                else:
                    cmd = AESPK_ECBC
        else:
            if mode == "ecb":
                if encryptedkey:
                    cmd = AESPK_EK_D
                else:
                    cmd = AESPK_D
            elif mode == "cbc":
                if encryptedkey:
                    cmd = AESPK_EK_DCBC
                else:
                    cmd = AESPK_DCBC
        return self.cmd(cmd)

    def aes_read_cbc(self, addr, encrypt=False, keyslot=18, ivslot=26):
        self.aes_cbc(encrypt=encrypt, src=addr, dst=0, length=16, keyslot=keyslot, ivslot=ivslot)
        res = self.read32(self.gcpu_base + regval["GCPU_REG_MEM_CMD"] + 26 * 4, 4)
        data = b""
        for word in res:
            data += pack("<I", word)
        return data

    def aes_setup_cbc(self, addr, data, iv=None, encrypt=False):
        keyslot = 0x12
        seedslot = 0x16
        ivslot = 0x1A
        if iv is None:
            iv = "4dd12bdf0ec7d26c482490b3482a1b1f"
        if len(data) != 16:
            raise RuntimeError("data must be 16 bytes")
        if isinstance(iv, str):
            iv_bytes = bytes.fromhex(iv)
        else:
            iv_bytes = iv
        words = []
        for x in range(4):
            word = unpack("<I", data[x * 4:(x + 1) * 4])[0]
            pat = unpack("<I", iv_bytes[x * 4:(x + 1) * 4])[0]
            words.append(word ^ pat)
        self.write32(self.gcpu_base + regval["GCPU_REG_MEM_CMD"] + keyslot * 4, [0, 0, 0, 0])
        self.write32(self.gcpu_base + regval["GCPU_REG_MEM_CMD"] + seedslot * 4, [0, 0, 0, 0])
        self.write32(self.gcpu_base + regval["GCPU_REG_MEM_CMD"] + ivslot * 4, [0, 0, 0, 0, 0, 0, 0, 0])
        self.write32(self.gcpu_base + regval["GCPU_REG_MEM_CMD"] + ivslot * 4, words)

        src = 0
        if self.hwcode == 0x8172:
            src = 0xD848
        return self.aes_cbc(encrypt=encrypt, src=src, dst=addr, length=16, keyslot=keyslot, ivslot=ivslot)

    def readmem(self, addr, length):
        if length // 4 == 1:
            return pack("<I", self.read32(addr, length // 4))
        return b"".join([pack("<I", val) for val in self.read32(addr, length // 4)])

    def mtk_gcpu_decrypt_mtee_img(self, data, keyseed, ivseed, aeskey1, aeskey2):
        src = 0x43001240
        dst = 0x43001000
        self.write32(src, to_dwords(data))
        self.memptr_set(0x12, aeskey1)
        self.memptr_set(0x16, keyseed)

        self.reg.GCPU_REG_MEM_P0 = 1
        self.reg.GCPU_REG_MEM_P1 = 0x12
        self.reg.GCPU_REG_MEM_P2 = 0x16
        self.reg.GCPU_REG_MEM_P3 = 0x1A
        self.cmd(AESPK_D)
        seed = bytearray(ivseed)
        aeskey2 = bytearray(aeskey2)
        for i in range(0x10):
            aeskey2[i] = seed[i] ^ aeskey2[i]

        self.memptr_set(0x12, aeskey2)
        length = len(data)
        self.reg.GCPU_REG_MEM_P0 = src
        self.reg.GCPU_REG_MEM_P1 = dst
        self.reg.GCPU_REG_MEM_P2 = length >> 4
        self.reg.GCPU_REG_MEM_P4 = 0x12
        self.reg.GCPU_REG_MEM_P5 = 0x1A
        self.reg.GCPU_REG_MEM_P6 = 0x1A
        self.cmd(AESPK_EK_DCBC)
        rdata = self.readmem(dst, length)
        return rdata

    def aes_read_ecb(self, data, encrypt=False, src=0x12, dst=0x1a, keyslot=0x30):
        if self.load_hw_key(0x30):
            self.memptr_set(src, data)
            if encrypt:
                if not self.aes_encrypt_ecb(keyslot, src, dst):
                    return self.memptr_get(dst, 16)
            else:
                if not self.aes_decrypt_ecb(keyslot, src, dst):
                    return self.memptr_get(dst, 16)

    def aes_cbc(self, encrypt, src, dst, length=16, keyslot=18, ivslot=26):
        dlength = length // 16
        if length % 16 != 0:
            dlength += 1
        self.reg.GCPU_REG_MEM_P0 = src
        self.reg.GCPU_REG_MEM_P1 = dst
        self.reg.GCPU_REG_MEM_P2 = dlength
        self.reg.GCPU_REG_MEM_P4 = keyslot
        self.reg.GCPU_REG_MEM_P5 = ivslot
        self.reg.GCPU_REG_MEM_P6 = ivslot
        if self.set_mode_cmd(encrypt=encrypt, mode="cbc", encryptedkey=True) != 0:
            raise RuntimeError("failed to call the function!")

    def aes_pk_init(self):
        self.reg.GCPU_REG_CTL &= 0xFFFFFFF8
        self.reg.GCPU_REG_CTL |= 7
        self.reg.GCPU_REG_MSC = 0x80FF1800
        self.reg.GCPU_UNK1 = 0x887f
        self.reg.GCPU_UNK2 = 0
        self.reg.GCPU_UNK3 = 0xffffffff
        self.reg.GCPU_UNK3 = 0xffffffff
        self.reg.GCPU_UNK3 = 0xffffffff
        self.reg.GCPU_UNK3 = 0x2

    def aes_pk_ecb(self, encrypt, src, dst, length=32):
        self.reg.GCPU_REG_CTL = self.reg.GCPU_REG_CTL & 0xFFFFFFF8
        self.reg.GCPU_REG_CTL |= 7
        self.reg.GCPU_REG_MSC = 0x80FF1800
        self.reg.GCPU_UNK1 = 0x887f
        self.reg.GCPU_UNK2 = 0
        self.reg.GCPU_UNK3 = 0xFFFFFFFF
        self.reg.GCPU_UNK3 = 0xFFFFFFFF
        self.reg.GCPU_UNK3 = 0xFFFFFFFF
        self.reg.GCPU_UNK3 = 2

        self.reg.GCPU_REG_MSC |= 0x2000
        if encrypt:
            self.reg.GCPU_REG_MEM_CMD = 0x7B
        else:
            self.reg.GCPU_REG_MEM_CMD = 0x7A
        self.reg.GCPU_REG_MEM_P0 = src
        self.reg.GCPU_REG_MEM_P1 = dst
        self.reg.GCPU_REG_MEM_P2 = length // 16
        self.reg.GCPU_REG_MEM_P3 = 0
        self.reg.GCPU_REG_MEM_P4 = 0
        self.write32(self.gcpu_base + regval["GCPU_REG_MEM_P5"], 0x9 * [0])
        self.reg.GCPU_REG_PC_CTL = 0

        while True:
            res = self.reg.GCPU_REG_INT_CLR
            if res != 0:
                break
        self.reg.GCPU_REG_INT_CLR = res

        self.write32(self.gcpu_base + regval["GCPU_REG_MEM_CMD"], 0xE0 * [0])

        self.reg.GCPU_REG_INT_EN = 0x0
        self.reg.GCPU_REG_MSC = 0x80fe1800

    def mtk_gcpu_mtee_6735(self):
        self.acquire()
        src = 0x5019A180
        dst = 0x5019A200
        label = b"www.mediatek.com0123456789ABCDEF"
        self.write32(src, to_dwords(label))
        self.aes_pk_ecb(encrypt=True, src=src, dst=dst, length=32)
        res = self.read32(dst, 8)
        data = b""
        for word in res:
            data += pack("<I", word)
        return data

    def mtk_gcpu_mtee_8167(self, data=None, encrypt=True, src=0x13, dst=0x13, keyslot=0x30):
        self.init()
        self.acquire()
        if self.load_hw_key(keyslot):
            self.memptr_set(src, bytearray(bytes.fromhex("4B65796D61737465724D617374657200")))
            if encrypt:
                if not self.aes_encrypt_ecb(keyslot, src, dst):
                    return self.memptr_get(dst, 16)
            else:
                if not self.aes_decrypt_ecb(keyslot, src, dst):
                    return self.memptr_get(dst, 16)

    def aes_decrypt_ecb(self, key_offset, data_offset, out_offset):
        self.reg.GCPU_REG_MEM_P0 = 1
        self.reg.GCPU_REG_MEM_P1 = key_offset
        self.reg.GCPU_REG_MEM_P2 = data_offset
        self.reg.GCPU_REG_MEM_P3 = out_offset
        if self.set_mode_cmd(encrypt=False, mode="ecb", encryptedkey=False) != 0:
            raise Exception("failed to call the function!")

    def aes_encrypt_ecb(self, key_offset, data_offset, out_offset):
        self.reg.GCPU_REG_MEM_P0 = 1
        self.reg.GCPU_REG_MEM_P1 = key_offset
        self.reg.GCPU_REG_MEM_P2 = data_offset
        self.reg.GCPU_REG_MEM_P3 = out_offset
        if self.set_mode_cmd(encrypt=True, mode="ecb", encryptedkey=False) != 0:
            raise Exception("failed to call the function!")

    def load_hw_key(self, offset):
        self.reg.GCPU_REG_MEM_P0 = 0x58
        self.reg.GCPU_REG_MEM_P1 = offset
        self.reg.GCPU_REG_MEM_P2 = 4
        if self.cmd(0x70) != 0:
            raise Exception("failed to call the function!")
        res = self.read32(self.gcpu_base + regval["GCPU_REG_MEM_CMD"] + 26 * 4, 4)
        data = b""
        for word in res:
            data += pack("<I", word)
        return data

    def disable_range_blacklist(self):
        self.info("Disabling bootrom range checks..")
        for field in self.setup.blacklist:
            addr = field[0]
            values = field[1]
            if isinstance(values, int):
                values = [values, 0x00000000, 0x00000000, 0x80]
            data = b""
            for value in values:
                data += pack("<I", value)
            self.aes_setup_cbc(addr, data)

    def mtk_crypto_hmac_sha256_by_devkey_using_seed(self, seed, data):
        dev_key = bytearray("\x00" * 16)
        self.init()
        if not self.load_hw_key(0x30):
            self.memptr_set(0x12, seed)
            if not self.aes_decrypt_ecb(0x30, 0x12, 0x1a):
                dev_key = self.memptr_get(0x1a, 16)
                self.info("scrambled key: " + hexlify(dev_key[:0x10]).decode('utf-8'))
            else:
                self.error("gcpu_aes_decrypt failed")
        else:
            self.error("gcpu_load_hw_key failed")
        self.uninit()
        return hmac.new(key=dev_key, digestmod=hashlib.sha256, msg=data).digest()[:16]

    def get_devinfo_with_index(self, index: int):
        if self.mtk.config.hwcode == 0x8173:
            if index == 12:
                return from_dwords(self.read32(0x10206140))
            elif index == 14:
                return from_dwords(self.read32(0x10206144))
        return bytearray()

    def mtk_crypto_hmac_sha256_by_devkey(self, data: bytearray, seed: bytearray):
        if seed is None:
            seed = bytearray("\x00" * 16)
        dev_val = self.get_devinfo_with_index(12)
        seed = xor_data(seed, dev_val, 4)
        dev_val = self.get_devinfo_with_index(13)
        seed[4:4 + 4] = xor_data(seed[4:4 + 4], dev_val, 4)
        self.info("seed: " + hexlify(seed[:16]).decode('utf-8'))
        return self.mtk_crypto_hmac_sha256_by_devkey_using_seed(seed, data)

    def byteswap(self, data):
        data = bytearray(data)
        for i in range(0, len(data) // 2):
            j = len(data) - i - 1
            o = data[i]
            data[j] = data[i]
            data[i] = o
        return data

    def derive_rpmb(self, cid):
        expand = bytearray([cid[i % 16] for i in range(64)])
        init_seed = bytearray(bytes.fromhex("735f23c962e7a10ab201d9a6426064b1"))
        result = self.mtk_crypto_hmac_sha256_by_devkey(data=expand, seed=init_seed)
        rpmb_key = hmac.new(key=result[:0x20], digestmod=hashlib.sha256, msg="RPMB\x00").digest()
        rpmb_key = self.byteswap(rpmb_key)
        return rpmb_key
