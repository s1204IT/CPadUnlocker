class damodes:
    DEFAULT = 0
    XFLASH = 1

class efuse:
    def __init__(self, base, hwcode):
        if hwcode in [0x8167]:
            self.efuses = [base+0x20, base+0x30, base+0x38, base+0x40, base+0x44,
                        0x8000000, base+0x60, base+0x260, base+0x264, base+0x268,
                        base+0x120, base+0x130, base+0x140, base+0x144, base+0x26C,
                        base+0x270, base+0x274, base+0x278, base+0x27C, base+0x280,
                        0x8000000, base+0x284, base+0x850, base+0x854, base+0x858,
                        base+0x85C, base+0x860, base+0x864, base+0x868, base+0x86C,
                        base+0x320, 0x8000008, base+0x560, base+0x90, base+0x94,
                        base+0x98, base+0x9C, base+0xA0, base+0xA4, base+0xA8,
                        base+0xAC, base+0x250, base+0x254, base+0x258, base+0x25C,
                        base+0x300, base+0x304, base+0x308, base+0x30C, 0x8000000,
                        base+0x310, base+0x540, base+0x544, base+0x548, base+0x54C,
                        base+0x550, base+0x558, base+0x55C, base+0x050, 0x8000000,
                        base+0x180, base+0x184, base+0x188, base+0x18C, base+0x190,
                        base+0x194, base+0x198, base+0x580, base+0x584, base+0x588,
                        base+0x58C, base+0x590, base+0x594, base+0x598, base+0x068,
                        base+0x028, base+0x070, base+0x074, base+0x078, base+0x07C
                        ]

class chipconfig:
    def __init__(self, var1=None, watchdog=None, uart=None, brom_payload_addr=None,
                 da_payload_addr=None, pl_payload_addr=None, cqdma_base=None, sej_base=None, dxcc_base=None,
                 gcpu_base=None, ap_dma_mem=None, name="", description="", dacode=None,
                 meid_addr=None, socid_addr=None, blacklist=(), blacklist_count=None,
                 send_ptr=None, ctrl_buffer=(), cmd_handler=None, brom_register_access=None,
                 damode=damodes.DEFAULT, loader=None, prov_addr=None, misc_lock=None,
                 efuse_addr=None):
        self.var1 = var1
        self.watchdog = watchdog
        self.uart = uart
        self.brom_payload_addr = brom_payload_addr
        self.da_payload_addr = da_payload_addr
        self.pl_payload_addr = pl_payload_addr
        self.cqdma_base = cqdma_base
        self.ap_dma_mem = ap_dma_mem
        self.sej_base = sej_base
        self.dxcc_base = dxcc_base
        self.name = name
        self.description = description
        self.dacode = dacode
        self.blacklist = blacklist
        self.blacklist_count = blacklist_count,
        self.send_ptr = send_ptr,
        self.ctrl_buffer = ctrl_buffer,
        self.cmd_handler = cmd_handler,
        self.brom_register_access = brom_register_access,
        self.meid_addr = meid_addr
        self.socid_addr = socid_addr
        self.prov_addr = prov_addr
        self.gcpu_base = gcpu_base
        self.dacode = dacode
        self.damode = damode
        self.loader = loader
        self.misc_lock = misc_lock
        self.efuse_addr = efuse_addr

hwconfig = {
    0x8167: chipconfig(
        var1=0xCC,
        watchdog=0x10007000,
        uart=0x11005000,
        brom_payload_addr=0x100A00,
        da_payload_addr=0x201000,
        pl_payload_addr=0x40001000,
        gcpu_base=0x1020D000,
        sej_base=0x1000A000,
        cqdma_base=0x10212C00,
        ap_dma_mem=0x11000000 + 0x1A0,
        blacklist=[(0x102968, 0x0), (0x00107954, 0x0)],
        blacklist_count=0x0000000A,
        send_ptr=(0x1029ac, 0xd2e4),
        ctrl_buffer=0x0010339C,
        cmd_handler=0x0000DFF7,
        brom_register_access=(0xd6f2, 0xd7ac),
        meid_addr=0x103478,
        socid_addr=0x103488,
        efuse_addr=0x10009000,
        damode=damodes.XFLASH,
        dacode=0x8167,
        name="CT3",
        loader="mt8167_payload.bin")
}
