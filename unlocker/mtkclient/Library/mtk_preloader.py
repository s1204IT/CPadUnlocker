#!/usr/bin/python3
# -*- coding: utf-8 -*-
# (c) B.Kerler 2018-2021 GPLv3 License
import os
import logging
import shutil
from enum import Enum
from struct import unpack, pack
from binascii import hexlify
from mtkclient.Library.utils import LogBase, logsetup
from mtkclient.Library.error import ErrorHandler
import time

USBDL_BIT_EN = 0x00000001  # 1: download bit enabled
USBDL_BROM = 0x00000002  # 0: usbdl by brom; 1: usbdl by bootloader
USBDL_TIMEOUT_MASK = 0x0000FFFC  # 14-bit timeout: 0x0000~0x3FFE: second; 0x3FFFF: no timeout
USBDL_TIMEOUT_MAX = (USBDL_TIMEOUT_MASK >> 2)  # maximum timeout indicates no timeout
USBDL_MAGIC = 0x444C0000  # Brom will check this magic number
MISC_LOCK_KEY_MAGIC = 0xAD98


def calc_xflash_checksum(data):
    checksum = 0
    pos = 0
    for i in range(0, len(data) // 4):
        checksum += unpack("<I", data[i * 4:(i * 4) + 4])[0]
        pos += 4
    if len(data) % 4 != 0:
        for i in range(4 - (len(data) % 4)):
            checksum += data[pos]
            pos += 1
    return checksum & 0xFFFFFFFF


class Preloader(metaclass=LogBase):
    class Rsp(Enum):
        NONE = b''
        CONF = b'\x69'
        STOP = b'\x96'
        ACK = b'\x5A'
        NACK = b'\xA5'

    class Cap(Enum):
        PL_CAP0_XFLASH_SUPPORT = (0x1 << 0)
        PL_CAP0_MEID_SUPPORT = (0x1 << 1)
        PL_CAP0_SOCID_SUPPORT = (0x1 << 2)

    class Cmd(Enum):
        # if CFG_PRELOADER_AS_DA
        SEND_PARTITION_DATA = b"\x70"
        JUMP_TO_PARTITION = b"\x71"

        CHECK_USB_CMD = b"\x72"
        STAY_STILL = b"\x80"
        CMD_88 = b"\x88"
        CMD_READ16_A2 = b"\xA2"

        I2C_INIT = b"\xB0"
        I2C_DEINIT = b"\xB1"
        I2C_WRITE8 = b"\xB2"
        I2C_READ8 = b"\xB3"
        I2C_SET_SPEED = b"\xB4"
        I2C_INIT_EX = b"\xB6"
        I2C_DEINIT_EX = b"\xB7"  # JUMP_MAUI
        I2C_WRITE8_EX = b"\xB8"  # READY
        """
        / Boot-loader resposne from BLDR_CMD_READY (0xB8)
        STATUS_READY                0x00        // secure RO is found and ready to serve
        STATUS_SECURE_RO_NOT_FOUND  0x01        // secure RO is not found: first download? => dead end...
        STATUS_SUSBDL_NOT_SUPPORTED 0x02        // BL didn't enable Secure USB DL
        """
        I2C_READ8_EX = b"\xB9"
        I2C_SET_SPEED_EX = b"\xBA"
        GET_MAUI_FW_VER = b"\xBF"

        OLD_SLA_SEND_AUTH = b"\xC1"
        OLD_SLA_GET_RN = b"\xC2"
        OLD_SLA_VERIFY_RN = b"\xC3"
        PWR_INIT = b"\xC4"
        PWR_DEINIT = b"\xC5"
        PWR_READ16 = b"\xC6"
        PWR_WRITE16 = b"\xC7"
        CMD_C8 = b"\xC8"  # RE

        READ16 = b"\xD0"
        READ32 = b"\xD1"
        WRITE16 = b"\xD2"
        WRITE16_NO_ECHO = b"\xD3"
        WRITE32 = b"\xD4"
        JUMP_DA = b"\xD5"
        JUMP_BL = b"\xD6"
        SEND_DA = b"\xD7"
        GET_TARGET_CONFIG = b"\xD8"
        SEND_ENV_PREPARE = b"\xD9"
        brom_register_access = b"\xDA"
        UART1_LOG_EN = b"\xDB"
        UART1_SET_BAUDRATE = b"\xDC",  # RE
        BROM_DEBUGLOG = b"\xDD",  # RE
        JUMP_DA64 = b"\xDE",  # RE
        GET_BROM_LOG_NEW = b"\xDF",  # RE

        SEND_CERT = b"\xE0",
        GET_ME_ID = b"\xE1"
        SEND_AUTH = b"\xE2"
        SLA = b"\xE3"
        CMD_E4 = b"\xE4"
        CMD_E5 = b"\xE5"
        CMD_E6 = b"\xE6"
        GET_SOC_ID = b"\xE7"

        ZEROIZATION = b"\xF0"
        GET_PL_CAP = b"\xFB"
        GET_HW_SW_VER = b"\xFC"
        GET_HW_CODE = b"\xFD"
        GET_BL_VER = b"\xFE"
        GET_VERSION = b"\xFF"

    def __init__(self, mtk, loglevel=logging.INFO):
        self.mtk = mtk
        self.__logger = logsetup(self, self.__logger, loglevel, mtk.config.gui)
        self.info = self.__logger.info
        self.debug = self.__logger.debug
        self.error = self.__logger.error
        self.eh = ErrorHandler()
        self.gcpu = None
        self.config = mtk.config
        self.display = True
        self.rbyte = self.mtk.port.rbyte
        self.rword = self.mtk.port.rword
        self.rdword = self.mtk.port.rdword
        self.usbread = self.mtk.port.usbread
        self.usbwrite = self.mtk.port.usbwrite
        self.echo = self.mtk.port.echo
        self.sendcmd = self.mtk.port.mtk_cmd

    def init(self, maxtries=None, display=True):
        if os.path.exists(".state"):
            try:
                os.remove(".state")
                os.remove(os.path.join("logs", "hwparam.json"))
            except OSError:
                pass
        readsocid = self.config.readsocid
        skipwdt = self.config.skipwdt

        if not display:
            self.info("Status: Waiting for PreLoader VCOM, please reconnect mobile to brom mode")
            self.config.set_gui_status(self.config.tr("Status: Waiting for connection"))
        else:
            self.info("Status: Waiting for PreLoader VCOM, please connect mobile")
            self.config.set_gui_status(self.config.tr("Status: Waiting for connection"))
        res = False
        tries = 0
        while not res and tries < 10:
            res = self.mtk.port.handshake(maxtries=maxtries)
            if not res:
                if display:
                    self.error("Status: Handshake failed, retrying...")
                    self.config.set_gui_status(self.config.tr("Status: Handshake failed, retrying..."))
                self.mtk.port.close()
                tries += 1
        if tries == 10:
            return False

        if not self.echo(self.Cmd.GET_HW_CODE.value):  # 0xFD
            if not self.echo(self.Cmd.GET_HW_CODE.value):
                self.error("Sync error. Please power off the device and retry.")
                self.config.set_gui_status(self.config.tr("Sync error. Please power off the device and retry."))
            return False
        else:
            val = self.rdword()
            self.config.hwcode = (val >> 16) & 0xFFFF
            self.config.hwver = val & 0xFFFF
            self.config.init_hwcode(self.config.hwcode)

        cpu = self.config.chipconfig.name
        if self.display:
            self.info("\tCPU:\t\t\t" + cpu + "(" + self.config.chipconfig.description + ")")
            self.config.cpu = cpu.replace("/", "_")
            self.info("\tHW version:\t\t" + hex(self.config.hwver))
            self.info("\tWDT:\t\t\t" + hex(self.config.chipconfig.watchdog))
            self.info("\tUart:\t\t\t" + hex(self.config.chipconfig.uart))
            self.info("\tBrom payload addr:\t" + hex(self.config.chipconfig.brom_payload_addr))
            self.info("\tDA payload addr:\t" + hex(self.config.chipconfig.da_payload_addr))
            if self.config.chipconfig.cqdma_base is not None:
                self.info("\tCQ_DMA addr:\t\t" + hex(self.config.chipconfig.cqdma_base))
            self.info("\tVar1:\t\t\t" + hex(self.config.chipconfig.var1))

        if not skipwdt:
            if self.display:
                self.info("Disabling Watchdog...")
            self.setreg_disablewatchdogtimer(self.config.hwcode)  # D4
        if self.display:
            self.info("HW code:\t\t\t" + hex(self.config.hwcode))
        self.config.target_config = self.get_target_config(self.display)
        self.info("Get Target info")
        self.get_blver()
        self.get_bromver()
        res = self.get_hw_sw_ver()
        self.config.hwsubcode = 0
        self.config.hwver = 0
        self.config.swver = 0
        if res != -1:
            self.config.hwsubcode = res[0]
            self.config.hwver = res[1]
            self.config.swver = res[2]
        if self.display:
            self.info("\tHW subcode:\t\t" + hex(self.config.hwsubcode))
            self.info("\tHW Ver:\t\t\t" + hex(self.config.hwver))
            self.info("\tSW Ver:\t\t\t" + hex(self.config.swver))
        meid = self.get_meid()
        if meid is not None:
            self.config.set_meid(meid)
            if self.display:
                self.info("ME_ID:\t\t\t" + hexlify(meid).decode('utf-8').upper())
            if readsocid or self.config.chipconfig.socid_addr:
                socid = self.get_socid()
                if len(socid) >= 16:
                    self.config.set_socid(socid)
                if self.display:
                    if socid != b"":
                        self.info("SOC_ID:\t\t\t" + hexlify(socid).decode('utf-8').upper())
        return True

    def read(self, addr, dwords=1, length=32) -> list:
        result = []
        cmd = self.Cmd.READ16 if length == 16 else self.Cmd.READ32
        if self.echo(cmd.value):
            if self.echo(pack(">I", addr)):
                ack = self.echo(pack(">I", dwords))
                status = self.rword()
                if ack and status <= 0xFF:
                    if length == 32:
                        result = self.rdword(dwords)
                    else:
                        result = self.rword(dwords)
                    status2 = unpack(">H", self.usbread(2))[0]
                    if status2 <= 0xFF:
                        return result
                else:
                    self.error(self.eh.status(status))
        return result

    def read32(self, addr, dwords=1) -> list:
        return self.read(addr, dwords, 32)

    def read16(self, addr, dwords=1) -> list:
        return self.read(addr, dwords, 16)

    def write(self, addr, values, length=32) -> bool:
        cmd = self.Cmd.WRITE16 if length == 16 else self.Cmd.WRITE32
        packfmt = ">H" if length == 16 else ">I"

        if isinstance(values, int):
            values = [values]
        if self.echo(cmd.value):
            if self.echo(pack(">I", addr)):
                ack = self.echo(pack(">I", len(values)))
                status = self.rword()
                if status > 0xFF:
                    self.error(f"Error on da_write{length}, addr {hex(addr)}, {self.eh.status(status)}")
                    return False
                if ack and status <= 3:
                    for val in values:
                        if not self.echo(pack(packfmt, val)):
                            break
                    status2 = self.rword()
                    if status2 <= 0xFF:
                        return True
                    else:
                        self.error(f"Error on da_write{length}, addr {hex(addr)}, {self.eh.status(status2)}")
            else:
                self.error(f"Error on da_write{length}, addr {hex(addr)}, write address")
        else:
            self.error(f"Error on da_write{length}, addr {hex(addr)}, send cmd")
        return False

    def write16(self, addr, words) -> bool:
        return self.write(addr, words, 16)

    def write32(self, addr, dwords) -> bool:
        return self.write(addr, dwords, 32)

    def writemem(self, addr, data):
        for i in range(0, len(data), 4):
            value = data[i:i + 4]
            while len(value) < 4:
                value += b"\x00"
            self.write32(addr + i, unpack("<I", value))

    def reset_to_brom(self, en=True, timeout=0):
        usbdlreg = 0

        # if anything is wrong and caused wdt reset, enter bootrom download mode #
        timeout = USBDL_TIMEOUT_MAX if timeout == 0 else timeout // 1000
        timeout <<= 2
        timeout &= USBDL_TIMEOUT_MASK  # usbdl timeout cannot exceed max value

        usbdlreg |= timeout
        if en:
            usbdlreg |= USBDL_BIT_EN
        else:
            usbdlreg &= ~USBDL_BIT_EN

        usbdlreg &= ~USBDL_BROM
        # Add magic number for MT6582
        usbdlreg |= USBDL_MAGIC  # | 0x444C0000

        # set BOOT_MISC0 as watchdog resettable
        RST_CON = self.config.chipconfig.misc_lock + 8
        USBDL_FLAG = self.config.chipconfig.misc_lock - 0x20
        self.write32(self.config.chipconfig.misc_lock, MISC_LOCK_KEY_MAGIC)
        self.write32(RST_CON, 1)
        self.write32(self.config.chipconfig.misc_lock, 0)
        self.write32(USBDL_FLAG, usbdlreg)
        return

    def run_ext_cmd(self, cmd: bytes = b"\xB1"):
        self.usbwrite(self.Cmd.CMD_C8.value)
        assert self.usbread(1) == self.Cmd.CMD_C8.value
        self.usbwrite(cmd)
        assert self.usbread(1) == cmd
        self.usbread(1)
        self.usbread(2)

    def jump_bl(self):
        if self.echo(self.Cmd.JUMP_BL.value):
            status = self.rword()
            if status <= 0xFF:
                status2 = self.rword()
                if status2 <= 0xFF:
                    return True
        return False

    def jump_to_partition(self, partitionname):
        if isinstance(partitionname, str):
            partitionname = bytes(partitionname, 'utf-8')[:64]
        partitionname = partitionname + (64 - len(partitionname)) * b'\x00'
        if self.echo(self.Cmd.JUMP_TO_PARTITION.value):
            self.usbwrite(partitionname)
            status2 = self.rword()
            if status2 <= 0xFF:
                return True

    def send_partition_data(self, partitionname, data):
        checksum = calc_xflash_checksum(data)
        if isinstance(partitionname, str):
            partitionname = bytes(partitionname, 'utf-8')[:64]
        partitionname = partitionname + (64 - len(partitionname)) * b'\x00'
        if self.echo(self.Cmd.SEND_PARTITION_DATA.value):
            self.usbwrite(partitionname)
            self.usbwrite(pack(">I", len(data)))
            status = self.rword()
            if status <= 0xFF:
                length = len(data)
                pos = 0
                while length > 0:
                    dsize = min(length, 0x200)
                    if not self.usbwrite(data[pos:pos + dsize]):
                        break
                    pos += dsize
                    length -= dsize
                # self.usbwrite(data)
                self.usbwrite(pack(">I", checksum))

    def setreg_disablewatchdogtimer(self, hwcode):
        """
        SetReg_DisableWatchDogTimer; BRom_WriteCmd32(): Reg 0x10007000[1]={ Value 0x22000000 }.
        """
        addr, value = self.config.get_watchdog_addr()

        if hwcode in [0x6575, 0x6577]:
            """
            SoCs which share the same watchdog IP as mt6577 must use 16-bit I/O.
            For example: mt6575, mt8317 and mt8377 (their hwcodes are 0x6575).
            """
            res = self.write16(addr, value)
        else:
            res = self.write32(addr, value)
            if res and hwcode == 0x6592:
                """
                mt6592 has an additional watchdog register at 0x10000500.
                TODO: verify if writing to this register is actually needed.
                """
                res = self.write32(0x10000500, 0x22000000)
        if not res:
            self.error("Received wrong SetReg_DisableWatchDogTimer response")
            return False
        else:
            return True

    def get_bromver(self):
        if self.usbwrite(self.Cmd.GET_VERSION.value):
            res = self.usbread(1)
            self.mtk.config.bromver = unpack("B", res)[0]
            return self.mtk.config.bromver
        return -1

    def get_blver(self):
        if self.usbwrite(self.Cmd.GET_BL_VER.value):
            res = self.usbread(1)
            if res == self.Cmd.GET_BL_VER.value:
                # We are in boot rom ...
                self.info("BROM mode detected.")
            self.mtk.config.blver = unpack("B", res)[0]
            return self.mtk.config.blver
        return -1

    def get_target_config(self, display=True):
        if self.echo(self.Cmd.GET_TARGET_CONFIG.value):
            target_config, status = unpack(">IH", self.rbyte(6))
            sbc = True if (target_config & 0x1) else False
            sla = True if (target_config & 0x2) else False
            daa = True if (target_config & 0x4) else False
            swjtag = True if (target_config & 0x6) else False
            epp = True if (target_config & 0x8) else False
            cert = True if (target_config & 0x10) else False
            memread = True if (target_config & 0x20) else False
            memwrite = True if (target_config & 0x40) else False
            cmd_c8 = True if (target_config & 0x80) else False
            if display:
                self.info(f"Target config:\t\t{hex(target_config)}")
                self.info(f"\tSBC enabled:\t\t{sbc}")
                self.info(f"\tSLA enabled:\t\t{sla}")
                self.info(f"\tDAA enabled:\t\t{daa}")
                self.info(f"\tSWJTAG enabled:\t\t{swjtag}")
                self.info(f"\tEPP_PARAM at 0x600 after EMMC_BOOT/SDMMC_BOOT:\t{epp}")
                self.info(f"\tRoot cert required:\t{cert}")
                self.info(f"\tMem read auth:\t\t{memread}")
                self.info(f"\tMem write auth:\t\t{memwrite}")
                self.info(f"\tCmd 0xC8 blocked:\t{cmd_c8}")

            if status > 0xff:
                raise Exception("Get Target Config Error")
            return {"sbc": sbc, "sla": sla, "daa": daa, "epp": epp, "cert": cert,
                    "memread": memread, "memwrite": memwrite, "cmdC8": cmd_c8}
        else:
            self.warning("CMD Get_Target_Config not supported.")
            return {"sbc": False, "sla": False, "daa": False, "epp": False, "cert": False,
                    "memread": False, "memwrite": False, "cmdC8": False}

    def jump_da(self, addr):
        self.info(f"Jumping to {hex(addr)}")
        self.config.set_gui_status(self.config.tr(f"Jumping to {hex(addr)}"))
        if self.echo(self.Cmd.JUMP_DA.value):
            self.usbwrite(pack(">I", addr))
            data = b""
            try:
                resaddr = self.rdword()
            except Exception as e:
                self.error(f"Jump_DA Resp2 {str(e)} ," + hexlify(data).decode('utf-8'))
                self.config.set_gui_status(self.config.tr("DA Error"))
                return False
            if resaddr == addr:
                try:
                    status = self.rword()
                except Exception as e:
                    self.error(f"Jump_DA Resp2 {str(e)} ," + hexlify(data).decode('utf-8'))
                    self.config.set_gui_status(self.config.tr("DA Error"))
                    return False
                if status == 0:
                    self.info(f"Jumping to {hex(addr)}: ok.")
                    self.config.set_gui_status(self.config.tr(f"Jumping to {hex(addr)}: ok."))
                    return True
                else:
                    self.error(f"Jump_DA status error:{self.eh.status(status)}")
                    self.config.set_gui_status(self.config.tr("DA Error"))

        return False

    def jump_da64(self, addr: int):
        if self.echo(self.Cmd.JUMP_DA64.value):
            self.usbwrite(pack(">I", addr))
            try:
                resaddr = self.rdword()
            except Exception as e:
                self.error(f"Jump_DA Resp2 {str(e)} , addr {hex(addr)}")
                return False
            if resaddr == addr:
                self.echo(b"\x01")  # for 64Bit, 0 for 32Bit
                try:
                    status = self.rword()
                except Exception as e:
                    self.error(f"Jump_DA Resp2 {str(e)} , addr {hex(addr)}")
                    return False
                if status == 0:
                    return True
                else:
                    self.error(f"Jump_DA64 status error:{self.eh.status(status)}")
        return False

    def uart1_log_enable(self):
        if self.echo(self.Cmd.UART1_LOG_EN):
            status = self.rword()
            if status == 0:
                return True
            else:
                self.error(f"Uart1 log enable error:{self.eh.status(status)}")
        return False

    def uart1_set_baud(self, baudrate):
        if self.echo(self.Cmd.UART1_SET_BAUDRATE.value):
            self.usbwrite(pack(">I", baudrate))
            status = self.rword()
            if status == 0:
                return True
            else:
                self.error(f"Uart1 set baudrate error:{self.eh.status(status)}")
        return False

    def send_root_cert(self, cert):
        gen_chksum, data = self.prepare_data(b"", cert)
        if self.echo(self.Cmd.SEND_CERT.value):
            if self.echo(pack(">I", len(data))):
                status = self.rword()
                if 0x0 <= status <= 0xFF:
                    if not self.upload_data(cert, gen_chksum):
                        self.error("Error on uploading certificate.")
                        return False
                    return True
                self.error(f"Send cert error:{self.eh.status(status)}")
        return False

    def send_auth(self, auth):
        gen_chksum, data = self.prepare_data(auth)
        if self.echo(self.Cmd.SEND_AUTH):
            self.usbwrite(len(data))
            status = self.rword()
            if 0x0 <= status <= 0xFF:
                if not self.upload_data(data, gen_chksum):
                    self.error("Error on uploading auth.")
                    return False
                return True
            self.error(f"Send auth error:{self.eh.status(status)}")
        return False

    def get_brom_log(self):
        if self.echo(self.Cmd.BROM_DEBUGLOG.value):  # 0xDD
            length = self.rdword()
            logdata = self.rbyte(length)
            return logdata
        else:
            self.error(f"Brom log cmd not supported.")
        return b""

    def get_brom_log_new(self):
        if self.echo(self.Cmd.GET_BROM_LOG_NEW.value):  # 0xDF
            length = self.rdword()
            logdata = self.rbyte(length)
            status = self.rword()
            if status == 0:
                return logdata
            else:
                self.error(f"Brom log status error:{self.eh.status(status)}")
        return b""

    def get_hwcode(self):
        res = self.sendcmd(self.Cmd.GET_HW_CODE.value, 4)  # 0xFD
        return unpack(">HH", res)

    def brom_register_access(self, address, length, data=None, check_status=True):
        if data is None:
            mode = 0
        else:
            mode = 1
        if self.mtk.port.echo(self.Cmd.brom_register_access.value):
            self.mtk.port.echo(pack(">I", mode))
            self.mtk.port.echo(pack(">I", address))
            self.mtk.port.echo(pack(">I", length))
            status = self.mtk.port.usbread(2)
            try:
                status = unpack("<H", status)[0]
            except:
                pass

            if status != 0:
                if status == 0x1A1D:
                    raise RuntimeError("Kamakiri2 failed, cache issue :(")
                if isinstance(status, int):
                    raise RuntimeError(self.eh.status(status))
                else:
                    raise RuntimeError("Kamakiri2 failed :(")

            if mode == 0:
                data = self.mtk.port.usbread(length)
            else:
                self.mtk.port.usbwrite(data[:length])

            if check_status:
                status = self.mtk.port.usbread(2)
                try:
                    status = unpack("<H", status)[0]
                except:
                    pass
                if status != 0:
                    raise RuntimeError(self.eh.status(status))
            return data

    def get_plcap(self):
        res = self.sendcmd(self.Cmd.GET_PL_CAP.value, 8)  # 0xFB
        self.mtk.config.plcap = unpack(">II", res)
        return self.mtk.config.plcap

    def get_hw_sw_ver(self):
        res = self.sendcmd(self.Cmd.GET_HW_SW_VER.value, 8)  # 0xFC
        return unpack(">HHHH", res)

    def get_meid(self):
        if self.usbwrite(self.Cmd.GET_BL_VER.value):
            res = self.usbread(1)
            if res == self.Cmd.GET_BL_VER.value:
                self.usbwrite(self.Cmd.GET_ME_ID.value)  # 0xE1
                if self.usbread(1) == self.Cmd.GET_ME_ID.value:
                    length = unpack(">I", self.usbread(4))[0]
                    self.mtk.config.meid = self.usbread(length)
                    status = unpack("<H", self.usbread(2))[0]
                    if status == 0:
                        self.config.is_brom = True
                        return self.mtk.config.meid
                    else:
                        self.error("Error on get_meid: " + self.eh.status(status))
            else:
                self.config.is_brom = False
        return None

    def get_socid(self):
        if self.usbwrite(self.Cmd.GET_BL_VER.value):
            res = self.usbread(1)
            if res == self.Cmd.GET_BL_VER.value:
                self.usbwrite(self.Cmd.GET_SOC_ID.value)  # 0xE7
                if self.usbread(1) == self.Cmd.GET_SOC_ID.value:
                    length = unpack(">I", self.usbread(4))[0]
                    self.mtk.config.socid = self.usbread(length)
                    status = unpack("<H", self.usbread(2))[0]
                    if status == 0:
                        return self.mtk.config.socid
                    else:
                        self.error("Error on get_socid: " + self.eh.status(status))
        return b""

    def prepare_data(self, data, sigdata=b"", maxsize=0):
        gen_chksum = 0
        data = (data[:maxsize] + sigdata)
        if len(data + sigdata) % 2 != 0:
            data += b"\x00"
        for x in range(0, len(data), 2):
            gen_chksum ^= unpack("<H", data[x:x + 2])[0]  # 3CDC
        if len(data) & 1 != 0:
            gen_chksum ^= data[-1:]
        return gen_chksum, data

    def upload_data(self, data, gen_chksum):
        self.config.set_gui_status(self.config.tr(f"Uploading data."))
        bytestowrite = len(data)
        pos = 0
        while bytestowrite > 0:
            size = min(bytestowrite, 64)
            self.usbwrite(data[pos:pos + size])
            bytestowrite -= size
            pos += size
        # self.usbwrite(b"")
        try:
            res = self.rword(2)
            if isinstance(res, list):
                checksum, status = res
                if gen_chksum != checksum and checksum != 0:
                    self.warning("Checksum of upload doesn't match !")
                if 0 <= status <= 0xFF:
                    return True
                else:
                    self.error(f"upload_data failed with error: " + self.eh.status(status))
                    return False
            else:
                self.error("Error on getting checksum while uploading data.")
                return False
        except Exception as e:
            self.error(f"upload_data resp error : " + str(e))
            return False
        return True

    def send_da(self, address, size, sig_len, dadata):
        self.config.set_gui_status(self.config.tr("Sending DA."))
        gen_chksum, data = self.prepare_data(dadata[:-sig_len], dadata[-sig_len:], size)
        if not self.echo(self.Cmd.SEND_DA.value):  # 0xD7
            self.error(f"Error on DA_Send cmd")
            self.config.set_gui_status(self.config.tr("Error on DA_Send cmd"))
            return False
        if not self.echo(address):
            self.error(f"Error on DA_Send address")
            self.config.set_gui_status(self.config.tr("Error on DA_Send address"))
            return False
        if not self.echo(len(data)):
            self.error(f"Error on DA_Send size")
            self.config.set_gui_status(self.config.tr("Error on DA_Send size"))
            return False
        if not self.echo(sig_len):
            self.error(f"Error on DA_Send sig_len")
            self.config.set_gui_status(self.config.tr("Error on DA_Send sig_len"))
            return False

        status = self.rword()
        if 0 <= status <= 0xFF:
            if not self.upload_data(data, gen_chksum):
                self.error("Error on uploading da data")
                return False
            else:
                return True
        self.error(f"DA_Send status error:{self.eh.status(status)}")
        self.config.set_gui_status(self.config.tr("Error on DA_Send"))
        return False
