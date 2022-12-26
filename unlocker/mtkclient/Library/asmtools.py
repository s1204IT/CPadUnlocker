#!/usr/bin/python3
# -*- coding: utf-8 -*-
#(c) B.Kerler 2018-2021 GPLv3 License
from capstone import *
from keystone import *
import argparse


def asm(code, cpu, mode, bigendian):
    if bigendian:
        little = KS_MODE_BIG_ENDIAN
    else:
        little = KS_MODE_LITTLE_ENDIA
    print("CPU: %s, MODE: %s" % (cpu, mode))
    ks = None
    if cpu == "arm":
        if mode == "arm":
            ks = Ks(KS_ARCH_ARM, KS_MODE_ARM + little)
        elif mode == "thumb":
            ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB + little)
        elif mode == "v8":
            ks = Ks(KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_V8 + little)
    elif cpu == "arm64":
        ks = Ks(KS_ARCH_ARM64, little)
    elif cpu == "mips":
        if mode == "micro":
            ks = Ks(KS_ARCH_MIPS, KS_MODE_MICRO + little)
        elif mode == "3":
            ks = Ks(KS_ARCH_MIPS, KS_MODE_MIPS3 + little)
        elif mode == "32R6":
            ks = Ks(KS_ARCH_MIPS, KS_MODE_MIPS32R6 + little)
        elif mode == "32":
            ks = Ks(KS_ARCH_MIPS, KS_MODE_MIPS32 + little)
        elif mode == "64":
            ks = Ks(KS_ARCH_MIPS, KS_MODE_MIPS64 + little)
    elif cpu == "x86":
        if mode == "16":
            ks = Ks(KS_ARCH_X86, KS_MODE_16 + little)
        elif mode == "32":
            ks = Ks(KS_ARCH_X86, KS_MODE_32 + little)
        elif mode == "64":
            ks = Ks(KS_ARCH_X86, KS_MODE_64 + little)
    elif cpu == "ppc":
        if mode == "32":
            ks = Ks(KS_ARCH_PPC, KS_MODE_PPC32 + little)
        elif mode == "64":
            ks = Ks(KS_ARCH_PPC, KS_MODE_PPC64 + little)
        elif mode == "qpx":
            ks = Ks(KS_ARCH_PPC, KS_MODE_QPX + little)
    elif cpu == "sparc":
        if mode == "32":
            ks = Ks(KS_ARCH_SPARC, KS_MODE_SPARC32 + little)
        elif mode == "64":
            ks = Ks(KS_ARCH_SPARC, KS_MODE_SPARC64 + little)
        elif mode == "v9":
            ks = Ks(KS_ARCH_SPARC, KS_MODE_V9 + little)
    elif cpu == "systemz":
        ks = Ks(KS_ARCH_SYSTEMZ, KS_MODE_BIG_ENDIAN)
    elif cpu == "hexagon":
        ks = Ks(KS_ARCH_HEXAGON, KS_MODE_LITTLE_ENDIAN)

    if (ks == None):
        print("CPU and/or Mode not supported!")
        exit(0)

    encoding, count = ks.asm(code)
    return encoding


def disasm(code, cpu, mode, bigendian, size):
    cs = None
    if bigendian:
        little = CS_MODE_BIG_ENDIAN
    else:
        little = CS_MODE_LITTLE_ENDIAN

    if cpu == "arm":
        if mode == "arm":
            cs = Cs(CS_ARCH_ARM, CS_MODE_ARM + little)
        elif mode == "thumb":
            cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB + little)
        elif mode == "mclass":
            cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_MCLASS + little)
        elif mode == "v8":
            cs = Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_V8 + little)
    elif cpu == "arm64":
        cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM + little)
    elif cpu == "mips":
        if mode == "micro":
            cs = Cs(CS_ARCH_MIPS, CS_MODE_MICRO + little)
        elif mode == "32":
            cs = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + little)
        elif mode == "64":
            cs = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 + little)
        elif mode == "32R6-Micro":
            cs = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32R6 + CS_MODE_MICRO + little)
        elif mode == "32R6":
            cs = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32R6 + little)
    elif cpu == "x86":
        if mode == "16":
            cs = Cs(CS_ARCH_X86, CS_MODE_16 + little)
        elif mode == "32":
            cs = Cs(CS_ARCH_X86, CS_MODE_32 + little)
        elif mode == "64":
            cs = Cs(CS_ARCH_X86, CS_MODE_64 + little)
    elif cpu == "ppc":
        cs = None
    elif cpu == "sparc":
        if mode == "None":
            cs = Cs(CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN)
        elif mode == "v9":
            cs = Cs(CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN + CS_MODE_V9)
    elif cpu == "systemz":
        cs = Cs(CS_ARCH_SYSZ, 0)
    elif cpu == "xcore":
        cs = Cs(CS_ARCH_XCORE, 0)

    if (cs == None):
        print("CPU and/or mode not supported!")
        exit(0)

    instr = []
    for i in cs.disasm(code, size):
        instr.append("%s\t%s" % (i.mnemonic, i.op_str))
    return instr


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description='Disasm/Asm Tool (c) B. Kerler 2018')

    parser.add_argument(
        '--infile', '-in',
        help='Input File',
        default='')
    parser.add_argument(
        '--outfile', '-out',
        help='Output File',
        default='')

    parser.add_argument(
        '--cstyle', '-cstyle',
        help='Print in c style',
        action="store_true")

    parser.add_argument(
        '--bigendian', '-bigendian',
        help='Big endian',
        action="store_true")

    parser.add_argument(
        '--disasm', '-disasm',
        help='Disasm: arm[arm,thumb,mclass,v8],arm64[arm],mips[micro,3,32R6,GP64],x86[16,32,64],ppc[64],sparc[32,64,v9],systemz,xcore',
        default='')

    parser.add_argument(
        '--asm', '-asm',
        help='Asm: arm[arm,thumb,mclass,v8],arm64[arm],mips[micro,32,64,32R6,32R6-Micro],x86[16,32,64],ppc[32,64,qpx],sparc[None,v9],systemz,hexagon',
        default='')

    parser.add_argument(
        '--inp', '-input',
        help='Disasm: hexstring, Asm: instruction string input ',
        default='')

    args = parser.parse_args()

    if args.asm == '' and args.disasm == '':
        print("[asmtools] Usage: -asm cpu,mode or -disasm cpu,mode")
        exit(0)

    if (args.infile == '' and args.inp == ''):
        print("[asmtools] I must have an infile to work on (-in) or a string input (--inp")
        exit(0)

    if args.asm != "":
        cpu, mode = args.asm.split(",")
    else:
        cpu, mode = args.disasm.split(",")

    if args.inp != "":
        args.inp = args.inp.replace("\\n", "\n")
        if args.asm != "":
            aa = asm(args.inp, cpu, mode, args.bigendian)
        else:
            aa = disasm(bytes.fromhex(args.inp), cpu, mode, args.bigendian, len(args.inp))
    else:
        with open(args.infile, "rb") as rf:
            code = rf.read()
            if args.asm != "":
                aa = asm(code, cpu, mode, args.bigendian)
            else:
                aa = disasm(code, cpu, mode, args.bigendian, len(code))

    if args.outfile != "":
        with open(args.outfile, "wb") as wf:
            if args.asm != "":
                ba = bytearray()
                for i in aa:
                    ba.append(i)
                wf.write(ba)
            else:
                wf.write(aa)
    else:
        if args.asm != "":
            sc = ""
            count = 0
            out = ""
            for i in aa:
                if args.cstyle:
                    out += ("\\x%02x" % i)
                else:
                    out += ("%02x" % i)
                sc += "%02x" % i
                count += 1
            print(out)
        else:
            print(aa)
        '''
        segment=bytearray(code[0x01C97C:0x01C990])
        segment[7]=0xE1
        segment[11]=0xE1
        segment[15]=0xE5
        segment[19]=0xEA
        print(hex(segment[7]))
        print(disasm(bytes(segment),len(segment)))
        '''


main()
