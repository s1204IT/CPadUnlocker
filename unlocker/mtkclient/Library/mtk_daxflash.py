#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2021 GPLv3 License
import logging
import time
import os
import hashlib
from binascii import hexlify
from struct import pack, unpack
from mtkclient.Library.utils import LogBase, progress, logsetup
from mtkclient.Library.error import ErrorHandler
from mtkclient.Library.daconfig import EMMC_PartitionType, UFS_PartitionType, DaStorage
from mtkclient.Library.partition import Partition
from mtkclient.config.payloads import pathconfig
from mtkclient.Library.xflash_ext import xflashext, XCmd
from mtkclient.Library.settings import hwparam


class NandExtension:
    cellusage = 0
    addr_type = 0
    bin_type = 0
    operation_type = 0
    sys_slc_percent = 0
    usr_slc_percent = 0
    phy_max_size = 0


def addr_to_block(addr, blocksize):
    return addr // blocksize


class DAXFlash(metaclass=LogBase):
    class Cmd:
        MAGIC = 0xFEEEEEEF
        SYNC_SIGNAL = 0x434E5953

        UNKNOWN = 0x010000
        DOWNLOAD = 0x010001
        UPLOAD = 0x010002
        FORMAT = 0x010003
        WRITE_DATA = 0x010004
        READ_DATA = 0x010005
        FORMAT_PARTITION = 0x010006
        SHUTDOWN = 0x010007
        BOOT_TO = 0x010008
        DEVICE_CTRL = 0x010009
        INIT_EXT_RAM = 0x01000A
        SWITCH_USB_SPEED = 0x01000B
        READ_OTP_ZONE = 0x01000C
        WRITE_OTP_ZONE = 0x01000D
        WRITE_EFUSE = 0x01000E
        READ_EFUSE = 0x01000F
        NAND_BMT_REMARK = 0x010010
        SETUP_ENVIRONMENT = 0x010100
        SETUP_HW_INIT_PARAMS = 0x010101

        SET_BMT_PERCENTAGE = 0x020001
        SET_BATTERY_OPT = 0x020002
        SET_CHECKSUM_LEVEL = 0x020003
        SET_RESET_KEY = 0x020004
        SET_HOST_INFO = 0x020005
        SET_META_BOOT_MODE = 0x020006
        SET_EMMC_HWRESET_PIN = 0x020007
        SET_GENERATE_GPX = 0x020008
        SET_REGISTER_VALUE = 0x020009
        SET_EXTERNAL_SIG = 0x02000A
        SET_REMOTE_SEC_POLICY = 0x02000B
        SET_ALL_IN_ONE_SIG = 0x02000C
        SET_RSC_INFO = 0x02000D
        SET_UPDATE_FW = 0x020010
        SET_UFS_CONFIG = 0x020011

        GET_EMMC_INFO = 0x040001
        GET_NAND_INFO = 0x040002
        GET_NOR_INFO = 0x040003
        GET_UFS_INFO = 0x040004
        GET_DA_VERSION = 0x040005
        GET_EXPIRE_DATA = 0x040006
        GET_PACKET_LENGTH = 0x040007
        GET_RANDOM_ID = 0x040008
        GET_PARTITION_TBL_CATA = 0x040009
        GET_CONNECTION_AGENT = 0x04000A
        GET_USB_SPEED = 0x04000B
        GET_RAM_INFO = 0x04000C
        GET_CHIP_ID = 0x04000D
        GET_OTP_LOCK_STATUS = 0x04000E
        GET_BATTERY_VOLTAGE = 0x04000F
        GET_RPMB_STATUS = 0x040010
        GET_EXPIRE_DATE = 0x040011
        GET_DRAM_TYPE = 0x040012
        GET_DEV_FW_INFO = 0x040013
        GET_HRID = 0x040014
        GET_ERROR_DETAIL = 0x040015

        START_DL_INFO = 0x080001
        END_DL_INFO = 0x080002
        ACT_LOCK_OTP_ZONE = 0x080003
        DISABLE_EMMC_HWRESET_PIN = 0x080004
        CC_OPTIONAL_DOWNLOAD_ACT = 0x800005
        DA_STOR_LIFE_CYCLE_CHECK = 0x080007

        UNKNOWN_CTRL_CODE = 0x0E0000
        CTRL_STORAGE_TEST = 0x0E0001
        CTRL_RAM_TEST = 0x0E0002
        DEVICE_CTRL_READ_REGISTER = 0x0E0003

    class ChecksumAlgorithm:
        PLAIN = 0
        CRC32 = 1
        MD5 = 2

    class FtSystemOSE:
        OS_WIN = 0
        OS_LINUX = 1

    class DataType:
        DT_PROTOCOL_FLOW = 1
        DT_MESSAGE = 2

    def __init__(self, mtk, daconfig, loglevel=logging.INFO):
        self.__logger = logsetup(self, self.__logger, loglevel, mtk.config.gui)
        self.info = self.__logger.info
        self.debug = self.__logger.debug
        self.error = self.__logger.error
        self.warning = self.__logger.warning
        self.mtk = mtk
        self.loglevel = loglevel
        self.daext = False
        self.sram = None
        self.dram = None
        self.emmc = None
        self.nand = None
        self.nor = None
        self.ufs = None
        self.chipid = None
        self.randomid = None
        self.__logger = self.__logger
        self.eh = ErrorHandler()
        self.config = self.mtk.config
        self.usbwrite = self.mtk.port.usbwrite
        self.usbread = self.mtk.port.usbread
        self.echo = self.mtk.port.echo
        self.rbyte = self.mtk.port.rbyte
        self.rdword = self.mtk.port.rdword
        self.rword = self.mtk.port.rword
        self.daconfig = daconfig
        self.partition = Partition(self.mtk, self.readflash, self.read_pmt, loglevel)
        self.pathconfig = pathconfig()
        self.patch = False
        self.generatekeys = self.mtk.config.generatekeys
        if self.generatekeys:
            self.patch = True
        self.xft = xflashext(self.mtk, self, loglevel)

    def usleep(self, usec):
        time.sleep(usec / 100000)

    def ack(self, rstatus=True):
        try:
            tmp = pack("<III", self.Cmd.MAGIC, self.DataType.DT_PROTOCOL_FLOW, 4)
            data = pack("<I", 0)
            self.usbwrite(tmp)
            self.usbwrite(data)
            if rstatus:
                status = self.status()
                return status
            return True
        except:
            return -1

    def xsend(self, data, datatype=DataType.DT_PROTOCOL_FLOW, is64bit: bool = False):
        if isinstance(data, int):
            if is64bit:
                data = pack("<Q", data)
                length = 8
            else:
                data = pack("<I", data)
                length = 4
        else:
            length = len(data)
        tmp = pack("<III", self.Cmd.MAGIC, datatype, length)
        if self.usbwrite(tmp):
            return self.usbwrite(data)
        return False

    def xread(self):
        try:
            hdr = self.usbread(4 + 4 + 4)
            magic, datatype, length = unpack("<III", hdr)
        except Exception as err:
            self.error("xread error: " + str(err))
            return -1
        if magic != 0xFEEEEEEF:
            self.error("xread error: Wrong magic")
            return -1
        resp = self.usbread(length)
        return resp

    def rdword(self, count=1):
        data = []
        for i in range(count):
            data.append(unpack("<I", self.xread())[0])
        if count == 1:
            return data[0]
        return data

    def status(self):
        hdr = self.usbread(4 + 4 + 4)
        magic, datatype, length = unpack("<III", hdr)
        if magic != 0xFEEEEEEF:
            self.error("Status error: Wrong magic")
            return -1
        tmp = self.usbread(length)
        if len(tmp) < length:
            self.error(f"Status length error: Too few data {hex(len(hdr))}")
            return -1
        if length == 2:
            status = unpack("<H", tmp)[0]
            if status == 0x0:
                return 0
        elif length == 4:
            status = unpack("<I", tmp)[0]
            if status == 0xFEEEEEEF:
                return 0
        else:
            status = unpack("<" + str(length // 4) + "I", tmp)[0]
        return status

    def read_pmt(self):
        return b"", []

    def send_param(self, params):
        if isinstance(params, bytes):
            params = [params]
        for param in params:
            pkt = pack("<III", self.Cmd.MAGIC, self.DataType.DT_PROTOCOL_FLOW, len(param))
            if self.usbwrite(pkt):
                length = len(param)
                pos = 0
                while length > 0:
                    dsize = min(length, 0x200)
                    if not self.usbwrite(param[pos:pos + dsize]):
                        break
                    pos += dsize
                    length -= dsize
        status = self.status()
        if status == 0:
            return True
        else:
            if status != 0xc0040050:
                self.error(f"Error on sending parameter: {self.eh.status(status)}")
        return False

    def send_devctrl(self, cmd, param=None, status=None):
        if status is None:
            status = [0]
        if self.xsend(self.Cmd.DEVICE_CTRL):
            status[0] = self.status()
            if status[0] == 0x0:
                if self.xsend(cmd):
                    status[0] = self.status()
                    if status[0] == 0x0:
                        if param is None:
                            return self.xread()
                        else:
                            return self.send_param(param)
        if status[0] != 0xC0010004:
            self.error(f"Error on sending dev ctrl {cmd}:" + self.eh.status(status[0]))
        return b""

    def set_reset_key(self, reset_key=0x68):
        param = pack("<I", reset_key)
        return self.send_devctrl(self.Cmd.SET_RESET_KEY, param)

    def set_meta(self, porttype="off"):
        class mtk_boot_mode_flag:
            boot_mode = b"\x00"
            com_type = b"\x00"
            com_id = b"\x00"

            def __init__(self, mode="off"):
                if mode == "off":
                    self.boot_mode = b"\x00"
                    self.com_type = b"\x00"
                    self.com_id = b"\x00"
                elif mode == "uart":
                    self.boot_mode = b"\x01"
                    self.com_type = b"\x01"
                    self.com_id = b"\x00"
                elif mode == "usb":
                    self.boot_mode = b"\x01"
                    self.com_type = b"\x02"
                    self.com_id = b"\x00"

            def get(self):
                return self.boot_mode + self.com_type + self.com_id

        metamode = mtk_boot_mode_flag(porttype).get()
        return self.send_devctrl(self.Cmd.SET_META_BOOT_MODE, metamode)

    def set_checksum_level(self, checksum_level=0x0):
        param = pack("<I", checksum_level)
        return self.send_devctrl(self.Cmd.SET_CHECKSUM_LEVEL, param)

    def set_battery_opt(self, option=0x2):
        param = pack("<I", option)
        return self.send_devctrl(self.Cmd.SET_BATTERY_OPT, param)

    def send_emi(self, emi):
        if self.xsend(self.Cmd.INIT_EXT_RAM):
            status = self.status()
            if status == 0:
                try:
                    time.sleep(0.01)
                    if self.xsend(pack("<I", len(emi))):
                        if self.send_param([emi]):
                            self.info(f"DRAM setup passed.")
                            return True
                except Exception as err:
                    self.error(f"Error on sending emi: {str(err)}")
                    return False
            else:
                self.error(f"Error on sending emi: {self.eh.status(status)}")
        return False

    def send_data(self, data):
        pkt2 = pack("<III", self.Cmd.MAGIC, self.DataType.DT_PROTOCOL_FLOW, len(data))
        if self.usbwrite(pkt2):
            bytestowrite = len(data)
            pos = 0
            while bytestowrite > 0:
                if self.usbwrite(data[pos:pos + 64]):
                    pos += 64
                    bytestowrite -= 64
            status = self.status()
            if status == 0x0:
                return True
            else:
                self.error(f"Error on sending data: {self.eh.status(status)}")
                return False

    def boot_to(self, at_address, da, display=True, timeout=0.5):
        if self.xsend(self.Cmd.BOOT_TO):
            if self.status() == 0:
                param = pack("<QQ", at_address, len(da))
                pkt1 = pack("<III", self.Cmd.MAGIC, self.DataType.DT_PROTOCOL_FLOW, len(param))
                if self.usbwrite(pkt1):
                    if self.usbwrite(param):
                        if self.send_data(da):
                            self.info(f"Upload data was accepted. Jumping to stage 2...")
                            if timeout:
                                time.sleep(timeout)
                            status = -1
                            try:
                                status = self.status()
                            except:
                                if status == -1:
                                    self.error(f"Stage was't executed. Maybe dram issue ?.")
                                    return False
                                self.error(f"Error on boot to: {self.eh.status(status)}")
                                return False

                            if status == 0x434E5953 or status == 0x0:
                                return True
                            else:
                                self.error(f"Error on boot to: {self.eh.status(status)}")
        return False

    def get_connection_agent(self):
        res = self.send_devctrl(self.Cmd.GET_CONNECTION_AGENT)
        if res != b"":
            status = self.status()
            if status == 0x0:
                return res
            else:
                self.error(f"Error on getting connection agent: {self.eh.status(status)}")
        return None

    def partitiontype_and_size(self, storage=None, parttype=None, length=0):
        if storage == DaStorage.MTK_DA_STORAGE_EMMC or storage == DaStorage.MTK_DA_STORAGE_SDMMC:
            storage = 1
            if parttype is None or parttype == "user":
                parttype = EMMC_PartitionType.MTK_DA_EMMC_PART_USER
            elif parttype == "boot1":
                parttype = EMMC_PartitionType.MTK_DA_EMMC_PART_BOOT1
                if self.daconfig.flashtype == "emmc":
                    length = min(length, self.emmc.boot1_size)
            elif parttype == "boot2":
                parttype = EMMC_PartitionType.MTK_DA_EMMC_PART_BOOT2
                if self.daconfig.flashtype == "emmc":
                    length = min(length, self.emmc.boot2_size)
            elif parttype == "gp1":
                parttype = EMMC_PartitionType.MTK_DA_EMMC_PART_GP1
                if self.daconfig.flashtype == "emmc":
                    length = min(length, self.emmc.gp1_size)
            elif parttype == "gp2":
                parttype = EMMC_PartitionType.MTK_DA_EMMC_PART_GP2
                if self.daconfig.flashtype == "emmc":
                    length = min(length, self.emmc.gp2_size)
            elif parttype == "gp3":
                parttype = EMMC_PartitionType.MTK_DA_EMMC_PART_GP3
                if self.daconfig.flashtype == "emmc":
                    length = min(length, self.emmc.gp3_size)
            elif parttype == "gp4":
                parttype = EMMC_PartitionType.MTK_DA_EMMC_PART_GP4
                if self.daconfig.flashtype == "emmc":
                    length = min(length, self.emmc.gp4_size)
            elif parttype == "rpmb":
                parttype = EMMC_PartitionType.MTK_DA_EMMC_PART_RPMB
                if self.daconfig.flashtype == "emmc":
                    length = min(length, self.emmc.rpmb_size)
            else:
                self.error("Unknown parttype. Known parttypes are \"boot1\",\"boot2\",\"gp1\"," +
                           "\"gp2\",\"gp3\",\"gp4\",\"rpmb\"")
                return []
        elif storage == DaStorage.MTK_DA_STORAGE_UFS:
            if parttype is None or parttype == "lu3" or parttype == "user":
                parttype = UFS_PartitionType.UFS_LU3
                length = min(length, self.ufs.lu0_size)
            elif parttype in ["lu1", "boot1"]:
                parttype = UFS_PartitionType.UFS_LU1
                length = min(length, self.ufs.lu1_size)
            elif parttype in ["lu2", "boot2"]:
                parttype = UFS_PartitionType.UFS_LU2
                length = min(length, self.ufs.lu2_size)
            elif parttype in ["lu4", "rpmb"]:
                parttype = UFS_PartitionType.UFS_LU4
                length = min(length, self.ufs.lu2_size)
            else:
                self.error("Unknown parttype. Known parttypes are \"lu1\",\"lu2\",\"lu3\",\"lu4\"")
                return []
        elif storage in [DaStorage.MTK_DA_STORAGE_NAND, DaStorage.MTK_DA_STORAGE_NAND_MLC,
                         DaStorage.MTK_DA_STORAGE_NAND_SLC, DaStorage.MTK_DA_STORAGE_NAND_TLC,
                         DaStorage.MTK_DA_STORAGE_NAND_SPI, DaStorage.MTK_DA_STORAGE_NAND_AMLC]:
            parttype = EMMC_PartitionType.MTK_DA_EMMC_PART_USER
            length = min(length, self.nand.total_size)
        elif storage in [DaStorage.MTK_DA_STORAGE_NOR, DaStorage.MTK_DA_STORAGE_NOR_PARALLEL,
                         DaStorage.MTK_DA_STORAGE_NOR_SERIAL]:
            parttype = EMMC_PartitionType.MTK_DA_EMMC_PART_USER
            length = min(length, self.nor.available_size)
        return [storage, parttype, length]

    def formatflash(self, addr, length, storage=None,
                    parttype=None, display=False):
        self.mtk.daloader.progress.clear()
        part_info = self.getstorage(parttype, length)
        if not part_info:
            return False
        storage, parttype, length = part_info
        self.info(f"Formatting addr {hex(addr)} with length {hex(length)}, please standby....")
        self.mtk.daloader.progress.show_progress("Erasing", 0, length, True)
        if self.xsend(self.Cmd.FORMAT):
            status = self.status()
            if status == 0:

                ne = NandExtension()
                param = pack("<IIQQ", storage, parttype, addr, length)
                param += pack("<IIIIIIII", ne.cellusage, ne.addr_type, ne.bin_type, ne.operation_type,
                              ne.sys_slc_percent, ne.usr_slc_percent, ne.phy_max_size, 0x0)
                if self.send_param(param):
                    status = self.status()
                    while status == 0x40040004:
                        time.sleep(self.status() / 1000.0)
                        status = self.ack()
                    if status == 0x40040005:
                        self.mtk.daloader.progress.show_progress("Erasing", length, length, True)
                        self.info(f"Successsfully formatted addr {hex(addr)} with length {length}.")
                        return True

            if status != 0x0:
                self.error(f"Error on format: {self.eh.status(status)}")
        return False

    def get_da_version(self):
        data = self.send_devctrl(self.Cmd.GET_DA_VERSION)
        status = self.status()
        if status == 0:
            self.info(f"DA-VERSION      : {data.decode('utf-8')}")
            return data
        else:
            self.error(f"Error on getting chip id: {self.eh.status(status)}")
            return None

    def get_chip_id(self):
        class Chipid:
            hw_code = 0
            hw_sub_code = 0
            hw_version = 0
            sw_version = 0
            chip_evolution = 0

        chipid = Chipid
        data = self.send_devctrl(self.Cmd.GET_CHIP_ID)
        chipid.hw_code, chipid.hw_sub_code, chipid.hw_version, chipid.sw_version, chipid.chip_evolution = unpack(
            "<HHHHH",
            data[:(5 * 2)])
        status = self.status()
        if status == 0:
            self.info("HW-CODE         : 0x%X", chipid.hw_code)
            self.info("HWSUB-CODE      : 0x%X", chipid.hw_sub_code)
            self.info("HW-VERSION      : 0x%X", chipid.hw_version)
            self.info("SW-VERSION      : 0x%X", chipid.sw_version)
            self.info("CHIP-EVOLUTION  : 0x%X", chipid.chip_evolution)
            return chipid
        else:
            self.error(f"Error on getting chip id: {self.eh.status(status)}")
        return None

    def get_ram_info(self):
        resp = self.send_devctrl(self.Cmd.GET_RAM_INFO)
        if resp != b"":
            status = self.status()
            if status == 0x0:
                class RamInfo:
                    type = 0
                    base_address = 0
                    size = 0

                sram = RamInfo()
                dram = RamInfo()
                if len(resp) == 24:
                    sram.type, sram.base_address, sram.size, dram.type, dram.base_address, dram.size = unpack("<IIIIII",
                                                                                                              resp)
                elif len(resp) == 48:
                    sram.type, sram.base_address, sram.size, dram.type, dram.base_address, dram.size = unpack("<QQQQQQ",
                                                                                                              resp)

                return sram, dram
            else:
                self.error(f"Error on getting ram info: {self.eh.status(status)}")
        return None, None

    def get_emmc_info(self, display=True):
        resp = self.send_devctrl(self.Cmd.GET_EMMC_INFO)
        if resp == b'':
            return None
        status = self.status()
        if status == 0:
            class EmmcInfo:
                type = 1
                block_size = 0x200
                boot1_size = 0
                boot2_size = 0
                rpmb_size = 0
                gp1_size = 0
                gp2_size = 0
                gp3_size = 0
                gp4_size = 0
                user_size = 0
                cid = b""
                fwver = 0
                unknown = b""

            emmc = EmmcInfo()
            pos = 0
            emmc.type, emmc.block_size = unpack("<II", resp[pos:pos + 8])
            pos += 8
            emmc.boot1_size, emmc.boot2_size, emmc.rpmb_size, emmc.gp1_size, emmc.gp2_size, emmc.gp3_size, \
            emmc.gp4_size, emmc.user_size = unpack("<QQQQQQQQ", resp[pos:pos + (8 * 8)])
            pos += 8 * 8
            emmc.cid = resp[pos:pos + (4 * 4)]
            pos += (4 * 4)
            emmc.fwver = unpack("<Q", resp[pos:pos + 8])[0]
            pos += 8
            emmc.unknown = resp[pos:]
            if emmc.type != 0 and display:
                self.info(f"EMMC FWVer:      {hex(emmc.fwver)}")
                try:
                    self.info(f"EMMC ID:         {emmc.cid[3:9].decode('utf-8')}")
                except:
                    pass
                self.info(f"EMMC CID:        {hexlify(emmc.cid).decode('utf-8')}")
                if self.config.hwparam is not None:
                    self.config.set_cid(emmc.cid)
                self.info(f"EMMC Boot1 Size: {hex(emmc.boot1_size)}")
                self.info(f"EMMC Boot2 Size: {hex(emmc.boot2_size)}")
                self.info(f"EMMC GP1 Size:   {hex(emmc.gp1_size)}")
                self.info(f"EMMC GP2 Size:   {hex(emmc.gp2_size)}")
                self.info(f"EMMC GP3 Size:   {hex(emmc.gp3_size)}")
                self.info(f"EMMC GP4 Size:   {hex(emmc.gp4_size)}")
                self.info(f"EMMC RPMB Size:  {hex(emmc.rpmb_size)}")
                self.info(f"EMMC USER Size:  {hex(emmc.user_size)}")
            return emmc
        else:
            self.error(f"Error on getting emmc info: {self.eh.status(status)}")
        return None

    def get_nand_info(self, display=True):
        resp = self.send_devctrl(self.Cmd.GET_NAND_INFO)
        if resp == b'':
            return None
        status = self.status()
        if status == 0:
            class NandInfo:
                type = 1
                page_size = 0
                block_size = 0x200
                spare_size = 0
                total_size = 0
                available_size = 0
                nand_bmt_exist = 0
                nand_id = 0

            nand = NandInfo()
            pos = 0
            nand.type, nand.page_size, nand.block_size, nand.spare_size = unpack("<IIII", resp[pos:pos + 16])
            pos += 16
            nand.total_size, nand.available_size = unpack("<QQ", resp[pos:pos + (2 * 8)])
            pos += 2 * 8
            nand.nand_bmt_exist = resp[pos:pos + 1]
            pos += 1
            nand.nand_id = unpack("<12B", resp[pos:pos + 12])
            if nand.type != 0:
                if display:
                    self.info(f"NAND Pagesize:   {hex(nand.page_size)}")
                    self.info(f"NAND Blocksize:  {hex(nand.block_size)}")
                    self.info(f"NAND Sparesize:  {hex(nand.spare_size)}")
                    self.info(f"NAND Total size: {hex(nand.total_size)}")
                    self.info(f"NAND Avail:      {hex(nand.available_size)}")
                    self.info(f"NAND ID:         {hexlify(nand.nand_id).decode('utf-8')}")
            return nand
        else:
            self.error(f"Error on getting nand info: {self.eh.status(status)}")
        return None

    def get_rpmb_status(self):
        resp = self.send_devctrl(self.Cmd.GET_RPMB_STATUS)
        if resp == b'':
            return None
        status = self.status()
        if status == 0:
            return resp

    def get_nor_info(self, display=True):
        resp = self.send_devctrl(self.Cmd.GET_NOR_INFO)
        if resp == b'':
            return None
        status = self.status()
        if status == 0:
            class NorInfo:
                type = 1
                page_size = 0
                available_size = 0

            nor = NorInfo()
            nor.type, nor.page_size, nor.available_size = unpack("<IIQ", resp[:16])
            if nor.type != 0:
                if display:
                    self.info(f"NOR Pagesize: {hex(nor.page_size)}")
                    self.info(f"NOR Size:     {hex(nor.available_size)}")
            return nor
        else:
            self.error(f"Error on getting nor info: {self.eh.status(status)}")
        return None

    def get_ufs_info(self, display=True):
        resp = self.send_devctrl(self.Cmd.GET_UFS_INFO)
        if resp == b'':
            return None
        status = self.status()
        if status == 0:
            class UfsInfo:
                type = 1
                block_size = 0
                lu0_size = 0
                lu1_size = 0
                lu2_size = 0
                cid = b""
                fwver = b""
                serial = b""
            ufs = UfsInfo()
            ufs.type, ufs.block_size, ufs.lu2_size, ufs.lu1_size, ufs.lu0_size = unpack("<IIQQQ",
                                                                                        resp[:(2 * 4) + (3 * 8)])
            pos = (2 * 4) + (3 * 8)
            buf = resp[pos:]
            ufs.cid = buf[:16]
            ufs.fwver = buf[22:22+4]
            ufs.serial = buf[30:30+0xC]
            if ufs.type != 0:
                if display:
                    self.info(f"UFS Blocksize:{hex(ufs.block_size)}")
                    try:
                        self.info(f"UFS ID:       {ufs.cid[2:].decode('utf-8')}")
                    except:
                        pass
                    self.info(f"UFS MID:      {hex(ufs.cid[0])}")
                    self.info(f"UFS CID:      {hexlify(ufs.cid).decode('utf-8')}")
                    self.info(f"UFS FWVer:    {hexlify(ufs.fwver).decode('utf-8')}")
                    self.info(f"UFS Serial:   {hexlify(ufs.serial).decode('utf-8')}")
                    self.info(f"UFS LU0 Size: {hex(ufs.lu0_size)}")
                    self.info(f"UFS LU1 Size: {hex(ufs.lu1_size)}")
                    self.info(f"UFS LU2 Size: {hex(ufs.lu2_size)}")
                if self.config.hwparam is not None:
                    self.config.set_cid(buf[:0x11+2]+buf[0x16:0x16+4+1]+buf[0x1E:0x1E+0xC])
                self.mtk.config.pagesize = ufs.block_size
                self.mtk.daloader.daconfig.pagesize = ufs.block_size
            return ufs
        else:
            self.error(f"Error on getting ufs info: {self.eh.status(status)}")
        return None

    def get_expire_date(self):
        res = self.send_devctrl(self.Cmd.GET_EXPIRE_DATE)
        if res != b"":
            status = self.status()
            if status == 0x0:
                return res
            else:
                self.error(f"Error on getting expire date: {self.eh.status(status)}")
        return None

    def get_random_id(self):
        res = self.send_devctrl(self.Cmd.GET_RANDOM_ID)
        if res != b"":
            status = self.status()
            if status == 0:
                return res
            else:
                self.error(f"Error on getting random id: {self.eh.status(status)}")
        return None

    def get_hrid(self):
        res = self.send_devctrl(self.Cmd.GET_HRID)
        if res != b"":
            status = self.status()
            if status == 0:
                return res
            else:
                self.error(f"Error on getting hrid info: {self.eh.status(status)}")
        return None

    def get_dev_fw_info(self):
        res = self.send_devctrl(self.Cmd.GET_DEV_FW_INFO)
        if res != b"":
            status = self.status()
            if status == 0:
                return res
            else:
                self.error(f"Error on getting dev fw info: {self.eh.status(status)}")
        return None

    def get_da_stor_life_check(self):
        res = self.send_devctrl(self.Cmd.DA_STOR_LIFE_CYCLE_CHECK)
        if res != b"":
            return unpack("<I", res)[0]
        else:
            return 0

    def get_packet_length(self):
        resp = self.send_devctrl(self.Cmd.GET_PACKET_LENGTH)
        if resp != b"":
            status = self.status()
            if status == 0:
                class Packetlen:
                    write_packet_length = 0
                    read_packet_length = 0

                plen = Packetlen()
                plen.write_packet_length, plen.read_packet_length = unpack("<II", resp)
                return plen
            else:
                self.error(f"Error on getting packet length: {self.eh.status(status)}")
        return None

    def get_usb_speed(self):
        resp = self.send_devctrl(self.Cmd.GET_USB_SPEED)
        if resp != b"":
            status = self.status()
            if status == 0:
                return resp
            else:
                self.error(f"Error on getting usb speed: {self.eh.status(status)}")
        return None

    def set_usb_speed(self):
        resp = self.xsend(self.Cmd.SWITCH_USB_SPEED)
        if resp != b"":
            status = self.status()
            if status == 0:
                if self.xsend(pack("<I", 0x0E8D2001)):
                    status = self.status()
                    if status == 0:
                        return True
            else:
                self.error(f"Error on getting usb speed: {self.eh.status(status)}")
        return False

    def cmd_write_data(self, addr, size, storage=DaStorage.MTK_DA_STORAGE_EMMC,
                       parttype=EMMC_PartitionType.MTK_DA_EMMC_PART_USER):
        if self.xsend(self.Cmd.WRITE_DATA):
            status = self.status()
            if status == 0:
                ne = NandExtension()
                param = pack("<IIQQ", storage, parttype, addr, size)
                param += pack("<IIIIIIII", ne.cellusage, ne.addr_type, ne.bin_type, ne.operation_type,
                              ne.sys_slc_percent, ne.usr_slc_percent, ne.phy_max_size, 0x0)
                if self.send_param(param):
                    return True
            else:
                self.error(f"Error on writing data: {self.eh.status(status)}")
        return False

    def cmd_read_data(self, addr, size, storage=DaStorage.MTK_DA_STORAGE_EMMC,
                      parttype=EMMC_PartitionType.MTK_DA_EMMC_PART_USER):
        if self.xsend(self.Cmd.READ_DATA):
            status = self.status()
            if status == 0:
                ne = NandExtension()
                param = pack("<IIQQ", storage, parttype, addr, size)
                param += pack("<IIIIIIII", ne.cellusage, ne.addr_type, ne.bin_type, ne.operation_type,
                              ne.sys_slc_percent, ne.usr_slc_percent, ne.phy_max_size, 0x0)
                self.send_param(param)
                status = self.status()
                if status == 0x0:
                    return True
            if status != 0x0:
                self.error(f"Error on reading data: {self.eh.status(status)}")
        return False

    def readflash(self, addr, length, filename, parttype=None, display=True):
        partinfo = self.getstorage(parttype, length)
        if not partinfo:
            return None
        self.mtk.daloader.progress.clear()
        storage, parttype, length = partinfo
        plen = self.get_packet_length()
        bytesread = 0
        if self.cmd_read_data(addr=addr, size=length, storage=storage, parttype=parttype):
            bytestoread = length
            total = length
            if filename != "":
                with open(filename, "wb") as wf:
                    while bytestoread > 0:
                        status = self.usbread(4 + 4 + 4)
                        magic, datatype, slength = unpack("<III", status)
                        if magic == 0xFEEEEEEF:
                            resdata = self.usbread(slength)
                        if slength > 4:
                            wf.write(resdata)
                            stmp = pack("<III", self.Cmd.MAGIC, self.DataType.DT_PROTOCOL_FLOW, 4)
                            data = pack("<I", 0)
                            self.usbwrite(stmp)
                            self.usbwrite(data)
                            bytestoread -= len(resdata)
                            bytesread += len(resdata)
                            if display:
                                self.mtk.daloader.progress.show_progress("Read", bytesread, total, display)
                        elif slength == 4:
                            if unpack("<I", resdata)[0] != 0:
                                break
                    status = self.usbread(4 + 4 + 4)
                    magic, datatype, slength = unpack("<III", status)
                    if magic == 0xFEEEEEEF:
                        resdata = self.usbread(slength)
                        if slength == 4:
                            if unpack("<I", resdata)[0] == 0:
                                if display:
                                    self.mtk.daloader.progress.show_progress("Read", total, total, display)
                                return True
                return False
            else:
                buffer = bytearray()
                while length > 0:
                    tmp = self.xread()
                    buffer.extend(tmp)
                    if self.ack() != 0:
                        break
                    if display:
                        self.mtk.daloader.progress.show_progress("Read", bytesread, total, display)
                    length -= len(tmp)
                    bytesread += len(tmp)
                if display:
                    self.mtk.daloader.progress.show_progress("Read", total, total, display)
                return buffer
        return False

    class ShutDownModes:
        NORMAL = 0
        HOME_SCREEN = 1
        FASTBOOT = 2

    def shutdown(self, async_mode: int = 0, dl_bit: int = 0, bootmode: ShutDownModes = ShutDownModes.NORMAL):
        if self.xsend(self.Cmd.SHUTDOWN):
            status = self.status()
            if status == 0:
                hasflags = 0
                if async_mode or dl_bit or bootmode > 0:
                    hasflags = 1
                enablewdt = 0
                dont_resetrtc = 0
                leaveusb = 0
                if self.xsend(pack("<IIIIIIII", hasflags, enablewdt, async_mode, bootmode, dl_bit,
                                   dont_resetrtc, leaveusb, 0)):
                    status = self.status()
                    if status == 0:
                        self.mtk.port.close(reset=True)
                        return True
            else:
                self.error(f"Error on sending shutdown: {self.eh.status(status)}")
        self.mtk.port.close(reset=True)
        return False

    def getstorage(self, parttype, length):
        if self.daconfig.flashtype == "nor":
            storage = DaStorage.MTK_DA_STORAGE_NOR
        elif self.daconfig.flashtype == "nand":
            storage = DaStorage.MTK_DA_STORAGE_NAND
        elif self.daconfig.flashtype == "ufs":
            storage = DaStorage.MTK_DA_STORAGE_UFS
            if parttype == EMMC_PartitionType.MTK_DA_EMMC_PART_USER:
                parttype = UFS_PartitionType.UFS_LU3
        elif self.daconfig.flashtype == "sdc":
            storage = DaStorage.MTK_DA_STORAGE_SDMMC
        else:
            storage = DaStorage.MTK_DA_STORAGE_EMMC

        part_info = self.partitiontype_and_size(storage, parttype, length)
        return part_info

    def writeflash(self, addr, length, filename, offset=0, parttype=None, wdata=None, display=True):
        self.mtk.daloader.progress.clear()
        fh = None
        fill = 0
        if filename is not None:
            if os.path.exists(filename):
                fsize = os.stat(filename).st_size
                length = min(fsize, length)
                if length % 512 != 0:
                    fill = 512 - (length % 512)
                    length += fill
                fh = open(filename, "rb")
                fh.seek(offset)
            else:
                self.error(f"Filename doesn't exists: {filename}, aborting flash write.")
                return False

        partinfo = self.getstorage(parttype, length)
        if not partinfo:
            return False
        storage, parttype, rlength = partinfo
        plen = self.get_packet_length()
        write_packet_size = plen.write_packet_length

        bytestowrite = rlength
        if self.cmd_write_data(addr, length, storage, parttype):
            try:
                pos = 0
                while bytestowrite > 0:
                    if display:
                        if length > bytestowrite:
                            rpos = length - bytestowrite
                        else:
                            rpos = 0
                        self.mtk.daloader.progress.show_progress("Write", rpos, length, display)
                    dsize = min(write_packet_size, bytestowrite)
                    if fh:
                        data = bytearray(fh.read(dsize))
                        if len(data) < dsize:
                            data.extend(b"\x00" * fill)
                    else:
                        data = wdata[pos:pos + dsize]
                    checksum = sum(data) & 0xFFFF
                    dparams = [pack("<I", 0x0), pack("<I", checksum), data]
                    if not self.send_param(dparams):
                        self.error("Error on writing pos 0x%08X" % pos)
                        return False
                    bytestowrite -= dsize
                    pos += dsize
                status = self.status()
                if status == 0x0:
                    self.send_devctrl(self.Cmd.CC_OPTIONAL_DOWNLOAD_ACT)
                    self.mtk.daloader.progress.show_progress("Write", length, length, display)
                    if fh:
                        fh.close()
                    return True
                else:
                    self.error(f"Error on writeflash: {self.eh.status(status)}")
            except Exception as e:
                self.error(str(e))
                if fh:
                    fh.close()
                return False
        if fh:
            fh.close()
        return False

    def sync(self):
        if self.xsend(self.Cmd.SYNC_SIGNAL):
            return True
        return False

    def setup_env(self):
        if self.xsend(self.Cmd.SETUP_ENVIRONMENT):
            da_log_level = 2
            log_channel = 1
            system_os = self.FtSystemOSE.OS_LINUX
            ufs_provision = 0x0
            param = pack("<IIIII", da_log_level, log_channel, system_os, ufs_provision, 0x1)
            if self.send_param(param):
                return True
        return False

    def setup_hw_init(self):
        if self.xsend(self.Cmd.SETUP_HW_INIT_PARAMS):
            param = pack("<I", 0x0)
            if self.send_param(param):
                return True
        return False

    def upload(self):
        if self.daconfig.da_loader is None:
            self.error("No valid da loader found... aborting.")
            return False
        loader = self.daconfig.loader
        self.info(f"Uploading xflash stage 1 from {os.path.basename(loader)}")
        if not os.path.exists(loader):
            self.info(f"Couldn't find {loader}, aborting.")
            return False
        with open(loader, 'rb') as bootldr:
            da1offset = self.daconfig.da_loader.region[1].m_buf
            da1size = self.daconfig.da_loader.region[1].m_len
            da1address = self.daconfig.da_loader.region[1].m_start_addr
            da2address = self.daconfig.da_loader.region[1].m_start_addr
            da1sig_len = self.daconfig.da_loader.region[1].m_sig_len
            bootldr.seek(da1offset)
            da1 = bootldr.read(da1size)
            da2offset = self.daconfig.da_loader.region[2].m_buf
            da2sig_len = self.daconfig.da_loader.region[2].m_sig_len
            bootldr.seek(da2offset)
            da2 = bootldr.read(self.daconfig.da_loader.region[2].m_len)

            hashaddr, hashmode, hashlen = self.mtk.daloader.compute_hash_pos(da1, da2, da2sig_len)
            if hashaddr is not None:
                da1 = self.xft.patch_da1(da1)
                da2 = self.xft.patch_da2(da2)
                da1 = self.mtk.daloader.fix_hash(da1, da2, hashaddr, hashmode, hashlen)
                self.patch = True
                self.daconfig.da2 = da2[:hashlen]
            else:
                self.daconfig.da2 = da2[:-da2sig_len]

            if self.mtk.preloader.send_da(da1address, da1size, da1sig_len, da1):
                self.info("Successfully uploaded stage 1, jumping ..")
                if self.mtk.preloader.jump_da(da1address):
                    sync = self.usbread(1)
                    if sync != b"\xC0":
                        self.error("Error on DA sync")
                        return False
                    else:
                        self.sync()
                        self.setup_env()
                        self.setup_hw_init()
                        res = self.xread()
                        if res == pack("<I", self.Cmd.SYNC_SIGNAL):
                            self.info("Successfully received DA sync")
                            return True
                        else:
                            self.error(f"Error jumping to DA: {res}")
                else:
                    self.error("Error on jumping to DA.")
            else:
                self.error("Error on sending DA.")
        return False

    def reinit(self, display=False):
        self.config.hwparam = hwparam(self.config.meid, self.config.hwparam_path)
        self.config.sram, self.config.dram = self.get_ram_info()
        self.emmc = self.get_emmc_info(display)
        self.nand = self.get_nand_info(display)
        self.nor = self.get_nor_info(display)
        self.ufs = self.get_ufs_info(display)
        if self.emmc is not None and self.emmc.type != 0:
            self.daconfig.flashtype = "emmc"
            self.daconfig.flashsize = self.emmc.user_size
            self.daconfig.rpmbsize = self.emmc.rpmb_size
            self.daconfig.boot1size = self.emmc.boot1_size
            self.daconfig.boot2size = self.emmc.boot2_size
        elif self.nand is not None and self.nand.type != 0:
            self.daconfig.flashtype = "nand"
            self.daconfig.flashsize = self.nand.total_size
            self.daconfig.rpmbsize = 0
            self.daconfig.boot1size = 0x400000
            self.daconfig.boot2size = 0x400000
        elif self.nor is not None and self.nor.type != 0:
            self.daconfig.flashtype = "nor"
            self.daconfig.flashsize = self.nor.available_size
            self.daconfig.rpmbsize = 0
            self.daconfig.boot1size = 0x400000
            self.daconfig.boot2size = 0x400000
        elif self.ufs is not None and self.ufs.type != 0:
            self.daconfig.flashtype = "ufs"
            self.daconfig.flashsize = self.ufs.lu0_size
            self.daconfig.rpmbsize = self.ufs.lu1_size
            self.daconfig.boot1size = self.ufs.lu1_size
            self.daconfig.boot2size = self.ufs.lu2_size
        self.chipid = self.get_chip_id()
        self.daversion = self.get_da_version()
        self.randomid = self.get_random_id()
        speed = self.get_usb_speed()
        if speed == b"full-speed":
            self.info("Reconnecting to preloader")
            self.config.set_gui_status(self.config.tr("Reconnecting to preloader"))
            self.set_usb_speed()
            self.mtk.port.close(reset=False)
            time.sleep(2)
            while not self.mtk.port.cdc.connect():
                time.sleep(0.5)
            self.info("Connected to preloader")
            self.mtk.port.cdc.set_fast_mode(True)
            self.config.set_gui_status(self.config.tr("Connected to preloader"))

    def upload_da(self):
        if self.upload():
            self.get_expire_date()
            self.set_reset_key(0x68)
            self.set_checksum_level(0x0)
            connagent = self.get_connection_agent()
            emmc_info = self.get_emmc_info(False)
            if emmc_info is not None and emmc_info.user_size != 0:
                self.info("DRAM config needed for : " + hexlify(emmc_info.cid[:8]).decode('utf-8'))
            else:
                ufs_info = self.get_ufs_info()
                if ufs_info is not None and ufs_info.block_size != 0:
                    self.info("DRAM config needed for : " + hexlify(ufs_info.cid).decode('utf-8'))

            stage = None
            if connagent == b"brom":
                stage = 1
                if self.daconfig.emi is None:
                    self.info("No preloader given. Searching for preloader")
                    found = False
                    self.info("Sending emi data ...")
                    for root, dirs, files in os.walk(os.path.join(self.pathconfig.get_loader_path(), 'Preloader')):
                        for file in files:
                            with open(os.path.join(root, file), "rb") as rf:
                                data = rf.read()
                                if emmc_info is not None:
                                    if emmc_info.cid[:8] in data:
                                        preloader = os.path.join(root, file)
                                        self.daconfig.extract_emi(preloader)
                                        if not self.send_emi(self.daconfig.emi):
                                            continue
                                        else:
                                            found = True
                                            self.info("Detected working preloader: " + preloader)
                                            break
                                else:
                                    self.warning("No emmc info, can't parse existing preloaders.")
                                if found:
                                    break
                    if not found:
                        self.warning("No preloader given. Operation may fail due to missing dram setup.")
                else:
                    self.info("Sending emi data ...")
                    if not self.send_emi(self.daconfig.emi):
                        return False
                    else:
                        self.info("Sending emi data succeeded.")
            elif connagent == b"preloader":
                stage = 1
            if stage == 1:
                self.info("Uploading stage 2...")
                with open(self.daconfig.loader, 'rb') as bootldr:
                    stage = stage + 1
                    loaded = self.boot_to(self.daconfig.da_loader.region[stage].m_start_addr, self.daconfig.da2)
                    if loaded:
                        self.info("Successfully uploaded stage 2")
                        self.reinit(True)
                        self.config.hwparam.writesetting("hwcode", hex(self.config.hwcode))

                        daextdata = self.xft.patch()
                        if daextdata is not None:
                            self.daext = False
                            if self.boot_to(at_address=0x68000000, da=daextdata):
                                ret = self.send_devctrl(XCmd.CUSTOM_ACK)
                                status = self.status()
                                if status == 0x0 and unpack("<I", ret)[0] == 0xA1A2A3A4:
                                    self.info("DA Extensions successfully added")
                                    self.daext = True
                            if not self.daext:
                                self.warning("DA Extensions failed to enable")

                            if self.generatekeys:
                                self.xft.generate_keys()
                        return True
                    else:
                        self.error("Error on booting to da (xflash)")
                        return False
            else:
                self.error("Didn't get brom connection, got instead: " + hexlify(connagent).decode('utf-8'))
        return False
