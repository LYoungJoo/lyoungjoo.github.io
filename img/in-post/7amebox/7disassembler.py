#!/usr/bin/python
TYPE_R = 0
TYPE_I = 1

BOLD = ''#'\033[1m'
RED = ''#BOLD + '\033[31m'
CYAN = ''#BOLD + '\033[36m'
YELLOW = ''#BOLD + '\033[33m'
END = ''#'\033[0m'


def terminate(msg):
    print msg
    exit(-1)


def print_disasm(op,op_type,opers,pc,func_list):

    register_list = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7','r8', 'r9', 'r10', 'bp', 'sp', 'pc', 'eflags', 'zero']

    op_string = ''
    opers_string = ''

    dst = register_list[opers[0]]

    if op_type == TYPE_R:
        src = register_list[opers[1]]
    elif op_type == TYPE_I:
        src = hex(opers[1])
    else :
        terminate("OP ERROR")

    if op == 0:
        op_string = 'mov' + "   "
        opers_string += dst + ", "
        opers_string += "[" + src + "]"

    elif op == 1:
        op_string = 'movb' + "   "
        opers_string += dst + ", "
        opers_string += "[" + src + "]"

    elif op == 2:
        op_string = 'mov' + "   "
        opers_string += "[" + src + "]" + ", "
        opers_string += dst 

    elif op == 3:
        op_string = 'movb' + "   "
        opers_string += "[" + src + "]" + ", "          
        opers_string += dst  

    elif op == 4:
        op_string = 'mov' + "   "
        opers_string += dst + ", "
        opers_string += src

    elif op == 5:
        op_string = 'xchg' + "   "
        opers_string += dst + ", "
        opers_string += src

    elif op == 6:
        op_string = 'push' + "   "
        if op_type == TYPE_R:     
            opers_string += dst
        elif op_type == TYPE_I:
            opers_string += src

    elif op == 7:
        if dst == 'pc':
            op_string = 'ret'
            opers_string += ''
            func_list.append(pc+2)
        else :
            op_string = 'pop' + "   "
            opers_string += dst

    elif op == 8:
        op_string = RED + 'syscall' + END

    elif op == 9:
        op_string = 'add' + "   "
        opers_string += dst + ", "
        opers_string += src

    elif op == 10:
        op_string = 'addl' + "   "
        opers_string += dst + ", "
        opers_string += src

    elif op == 11:
        op_string = 'sub' + "   "
        opers_string += dst + ", "
        opers_string += src

    elif op == 12:
        op_string = 'subb' + "   "
        opers_string += dst + ", "
        opers_string += src

    elif op == 13:
        op_string = 'shr' + "   "
        opers_string += dst + ", "
        opers_string += src

    elif op == 14:
        op_string = 'shl' + "  "
        opers_string += dst + ", "
        opers_string += src

    elif op == 15:
        op_string = 'mul' + "   "
        opers_string += dst + ", "
        opers_string += src

    elif op == 16:
        op_string = 'div' + "   "
        opers_string += dst + ", "
        opers_string += src

    elif op == 17:
        op_string = 'inc' + "   "
        opers_string += dst

    elif op == 18:
        op_string = 'dec' + "   "
        opers_string += dst

    elif op == 19:
        op_string = 'and' + "   "
        opers_string += dst + ", "
        opers_string += src

    elif op == 20:
        op_string = 'or' + "   "
        opers_string += dst + ", "
        opers_string += src

    elif op == 21:
        op_string = 'xor' + "   "
        opers_string += dst + ", "
        opers_string += src

    elif op == 22:
        op_string = 'mod' + "   "
        opers_string += dst + ", "
        opers_string += src

    elif op == 23:
        op_string = 'cmp' + "   "
        opers_string += dst + ", "
        opers_string += src

    elif op == 24:
        op_string = 'cmpb' + "   "
        opers_string += dst + ", "
        opers_string += src

    elif op == 25:
        if op_type == TYPE_I and dst == 'pc':
            if int(src[2:],16) > 0x100000:
                target = (pc + 0x5) - (0x200000 - int(src[2:],16))
            else :
                target = (pc + 0x5) + int(src[2:],16)
            op_string = YELLOW + 'jmpif(!NF!ZF)'
            opers_string = ' ' + hex(target) + END
        else:   
            op_string = 'jmpif(!NF!ZF)' + "   "
            opers_string += dst + ", "
            opers_string += src

    elif op == 26:
        if op_type == TYPE_I and dst == 'pc':
            if int(src[2:],16) > 0x100000:
                target = (pc + 0x5) - (0x200000 - int(src[2:],16))
            else :
                target = (pc + 0x5) + int(src[2:],16)
            op_string = YELLOW + 'jmpif(NF!ZF)'
            opers_string = ' ' + hex(target) + END
        else:   
            op_string = 'jmpif(NF!ZF)' + "   "
            opers_string += dst + ", "
            opers_string += src

    elif op == 27:
        if op_type == TYPE_I and dst == 'pc':
            if int(src[2:],16) > 0x100000:
                target = (pc + 0x5) - (0x200000 - int(src[2:],16))
            else :
                target = (pc + 0x5) + int(src[2:],16)
            op_string = YELLOW + 'jmpif(ZF)'
            opers_string = ' ' + hex(target) + END
        else:   
            op_string = 'jmpif(ZF)' + "   "
            opers_string += dst + ", "
            opers_string += src

    elif op == 28:
        if op_type == TYPE_I and dst == 'pc':
            if int(src[2:],16) > 0x100000:
                target = (pc + 0x5) - (0x200000 - int(src[2:],16))
            else :
                target = (pc + 0x5) + int(src[2:],16)
            op_string = YELLOW + 'jmpif(!ZF)'
            opers_string = ' ' + hex(target) + END
        else:        
            op_string = 'jmpif(!ZF)' + "   "
            opers_string += dst + ", "
            opers_string += src

    elif op == 29:
        if op_type == TYPE_I and dst == 'pc':
            if int(src[2:],16) > 0x100000:
                target = (pc + 0x5) - (0x200000 - int(src[2:],16))
            else :
                target = (pc + 0x5) + int(src[2:],16)
            op_string = YELLOW + 'jmp'
            opers_string = ' ' + hex(target) + END
        else:
            op_string = 'jmp' + "   "
            opers_string += dst + ", "
            opers_string += src

    elif op == 30:
        if op_type == TYPE_I and dst == 'pc':
            if int(src[2:],16) > 0x100000:
                target = (pc + 0x5) - (0x200000 - int(src[2:],16))
            else :
                target = (pc + 0x5) + int(src[2:],16)
            op_string = YELLOW + 'call'
            opers_string = ' ' + hex(target) + END
            func_list.append(target)
        else:
            op_string = 'call' + "   "
            opers_string += dst + ", "
            opers_string += src
    
    # function
    if pc == 0:
        print CYAN + '_start:' + END
    
    for func in func_list:
        if func == pc:
            print CYAN + 'sub_' + hex(func)[2:] + ' : ' + END
            break
        
    # print
    print '   ' + hex(pc) + " : " + op_string + opers_string


def read_file(file, addr, length):
    return file[addr : addr + length]

def read_file_tri(file, addr, count):
    res = []
    for i in range(count):
        tri = 0
        tri |= file[addr + i*3]
        tri |= file[addr + i*3 + 1]  << 14
        tri |= file[addr + i*3 + 2]  << 7
        res.append(tri)
    return res

def dispatch(file, addr):
        opcode = bit_concat(read_file(file, addr, 2))
        op      = (opcode & 0b11111000000000) >> 9
        op_type = (opcode & 0b00000100000000) >> 8
        opers   = []
        if op_type == TYPE_R:
            opers.append((opcode & 0b00000011110000) >> 4)
            opers.append((opcode & 0b00000000001111))
            op_size = 2

        elif op_type == TYPE_I:
            opers.append((opcode & 0b00000011110000) >> 4)
            opers.append(read_file_tri(file, addr+2, 1)[0])
            op_size = 5

        return op, op_type, opers, op_size

def bit_concat(bit_list):
        res = 0
        for bit in bit_list:
            res <<= 7
            res += bit & 0b1111111
        return res

def main():
    pc = 0
    func_list = []
    while True:
        file = [ord(i) for i in (open('mic_check.firm').read())]
        op, op_type, opers, op_size = dispatch(file,pc)
        print_disasm(op, op_type, opers, pc, func_list)
        pc += op_size

        if len(file) <= pc+2:
            break

if __name__ == "__main__":
    main()
