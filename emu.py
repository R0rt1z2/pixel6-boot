import sys
import struct
import capstone
import keystone

from unicorn import *
from unicorn.arm64_const import *
import unicorn.arm_const

ABL_LOAD_ADDRESS    = 0xFFFF0000F8800000
DOWNLOAD_BUFFER     = 0xFFFF000090700000
MEMORY_START        = 0xFFFF0000F8000000
MEMORY_SIZE         = 200 * 1024 * 1024
STACK_START         = MEMORY_START + MEMORY_SIZE - 0x1000
PAGE_SIZE           = 10 * 1024 * 1024

FASTBOOT_RUN        = 0xFFFF0000F8882434
FASTBOOT_WRITE      = 0xFFFF0000F888461C
DEBUG_STDIO_WRITE   = 0xFFFF0000F8952354
FASTBOOT_LOOP_CHECK = 0xFFFF0000F8810198
ENTRY_RUN           = 0xFFFF0000F881B58C
MUTEX_ACQUIRE       = 0xFFFF0000F8853BFC
STACK_CHK_FAIL      = 0xFFFF0000F889F678
STACK_CANARY_ADDR   = 0xFFFF0000F8A654F8

bootloader = 'abl.bin'

if len(sys.argv) > 1:
    bootloader = sys.argv[1]

with open(bootloader, 'rb') as f:
    BINARY = f.read()

disassembler = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
_stack_chk_count = 0

def disas(code, addr):
    for insn in disassembler.disasm(code, addr):
        print('0x%x:\t%s\t%s' % (insn.address, insn.mnemonic, insn.op_str))

def gen_shellcode(data, address):
    ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
    ret = ks.asm(data, address)
    return bytes(ret[0])

def print_regs(uc):
    for reg in ['X0','X1','X2','X3','X8','X19','X20','X21',
                'X22','X23','X24','X28','X29','X30','SP','PC']:
        val = uc.reg_read(getattr(unicorn.arm64_const, 'UC_ARM64_REG_%s' % reg))
        print('%s=%016x' % (reg, val), end='  ')
    print()

def print_stack(uc, num=10):
    sp = uc.reg_read(UC_ARM64_REG_SP)
    print('SP=%x' % sp)
    for i in range(num):
        addr = sp + i * 8
        try:
            v = struct.unpack('Q', uc.mem_read(addr, 8))[0]
            print('  [%x] %016x  (sp+%x)' % (addr, v, i * 8))
        except:
            break

def is_sane_address(addr):
    if addr < 0x1000:
        return False
    top = addr >> 48
    if top not in (0x0000, 0xFFFF):
        return False
    return True

def hook_mem_invalid_auto(uc, uc_mem_type, addr, size, value, user_data):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    start = addr & ~(PAGE_SIZE - 1)
    if not is_sane_address(addr):
        try:
            uc.mem_map(start, PAGE_SIZE)
        except:
            pass
        return True
    print('  [mem] unmapped access @PC=%x addr=%x -> mapping %x' % (pc, addr, start))
    try:
        uc.mem_map(start, PAGE_SIZE)
    except:
        pass
    return True

def hook_mem_invalid_verbose(uc, uc_mem_type, addr, size, value, user_data):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    print('[!] INVALID MEMORY  PC=%x  addr=%x  size=%d  value=%x' % (pc, addr, size, value))
    print_regs(uc)
    print_stack(uc)
    return False

def hook_intr(uc, intno, user_data):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    uc.reg_write(UC_ARM64_REG_PC, pc + 4)

def hook_nop_ret(uc, address, size, user_data):
    lr = uc.reg_read(UC_ARM64_REG_LR)
    uc.reg_write(UC_ARM64_REG_PC, lr)

def hook_stack_chk_fail(uc, address, size, user_data):
    global _stack_chk_count
    _stack_chk_count += 1
    if _stack_chk_count > 5:
        uc.emu_stop()
        return
    lr = uc.reg_read(UC_ARM64_REG_LR)
    uc.reg_write(UC_ARM64_REG_X0, 0)
    uc.reg_write(UC_ARM64_REG_PC, lr)

def hook_fastboot_run(uc, address, size, user_data):
    global commands
    while commands:
        command = commands.pop(0)
        if command == b'outofloop':
            break
        print('  [usb->bl] %s' % command.decode(errors='replace'))
    lr = uc.reg_read(UC_ARM64_REG_LR)
    uc.reg_write(UC_ARM64_REG_PC, lr)

def hook_fastboot_loop_check(uc, address, size, user_data):
    global commands
    if not commands:
        uc.reg_write(UC_ARM64_REG_X0, 0)
        uc.reg_write(UC_ARM64_REG_PC, address + 4)

def hook_fastboot_write(uc, address, size, user_data):
    ptr = uc.reg_read(UC_ARM64_REG_X0)
    sz  = uc.reg_read(UC_ARM64_REG_X1)
    try:
        s = uc.mem_read(ptr, sz).decode('utf-8', errors='replace')
    except:
        s = ''
    print('  [bl->usb] %s' % s)

def hook_stdio_write(uc, address, size, user_data):
    ptr = uc.reg_read(UC_ARM64_REG_X1)
    sz  = uc.reg_read(UC_ARM64_REG_X2)
    try:
        s = uc.mem_read(ptr, sz).decode('utf-8', errors='replace')
    except:
        s = ''
    print(s, end='')

def setup_emulator(verbose_mem=False):
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

    mu.mem_map(MEMORY_START,        MEMORY_SIZE)
    mu.mem_map(0xFFFF000080000000,  PAGE_SIZE)
    mu.mem_map(0xFFFF000002000000,  PAGE_SIZE)
    mu.mem_map(0xD8000000,          PAGE_SIZE)
    mu.mem_map(0xF8200000,          PAGE_SIZE)
    mu.mem_map(0xFFFFFFFF19200000,  PAGE_SIZE)
    mu.mem_map(0xFFFFFFFFF8200000,  PAGE_SIZE)
    mu.mem_map(0xFFFFFFFF10000000,  PAGE_SIZE)
    mu.mem_map(0xFFFFFFFF20000000,  PAGE_SIZE)
    mu.mem_map(DOWNLOAD_BUFFER,     1024 * 1024 * 5)

    mu.reg_write(UC_ARM64_REG_SP, STACK_START)

    simd_init = gen_shellcode(
        'mov x1, #(0x3 << 20);msr cpacr_el1, x1;isb;STP Q1, Q2, [SP,#0x10]',
        DOWNLOAD_BUFFER
    )
    mu.mem_write(DOWNLOAD_BUFFER, simd_init)
    mu.emu_start(DOWNLOAD_BUFFER, 0, count=3)

    mu.mem_write(ABL_LOAD_ADDRESS, BINARY)
    mu.mem_write(STACK_CANARY_ADDR, struct.pack('Q', 0xA5A5A5A5A5A5A5A5))

    if verbose_mem:
        mu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid_verbose)
    else:
        mu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid_auto)

    mu.hook_add(UC_HOOK_INTR,  hook_intr)
    mu.hook_add(UC_HOOK_CODE,  hook_fastboot_run,        begin=FASTBOOT_RUN,         end=FASTBOOT_RUN)
    mu.hook_add(UC_HOOK_CODE,  hook_fastboot_write,      begin=FASTBOOT_WRITE,       end=FASTBOOT_WRITE)
    mu.hook_add(UC_HOOK_CODE,  hook_stdio_write,         begin=DEBUG_STDIO_WRITE,    end=DEBUG_STDIO_WRITE)
    mu.hook_add(UC_HOOK_CODE,  hook_fastboot_loop_check, begin=FASTBOOT_LOOP_CHECK,  end=FASTBOOT_LOOP_CHECK)
    mu.hook_add(UC_HOOK_CODE,  hook_nop_ret,             begin=MUTEX_ACQUIRE,        end=MUTEX_ACQUIRE)
    mu.hook_add(UC_HOOK_CODE,  hook_stack_chk_fail,      begin=STACK_CHK_FAIL,       end=STACK_CHK_FAIL)

    return mu

def run(verbose_mem=False):
    global commands, _stack_chk_count
    _stack_chk_count = 0
    commands = [
        b'flashing unlock',
        b'oem dmesg',
        b'outofloop',
    ]

    try:
        mu = setup_emulator(verbose_mem=verbose_mem)
        mu.emu_start(ENTRY_RUN, 0)
        pc = mu.reg_read(UC_ARM64_REG_PC)
        print('>>> PC = 0x%x' % pc)
    except UcError as e:
        print('ERROR: %s' % e)

if __name__ == '__main__':
    import fire
    fire.Fire(run)