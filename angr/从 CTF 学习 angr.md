本文通过 angr_CTF 学习 angr 的操作

首先，对所有文件执行 ``checksec``
![](截屏2021-04-18%20上午11.31.58.png)
确定所有的可执行文件 ``pie`` 都已经关闭
### 解题
**00_angr_find**  
直接获取字符进行复杂计算后，判断是否相同
查找满足达到 ``Good Job`` 地址的输入
```py
import angr

def main():
    proj = angr.Project("/home/darenfy/angr_CTF/Angr_Tutorial_For_CTF/problems/00_angr_find")

    init_state = proj.factory.entry_state()
    simulation = proj.factory.simgr(init_state)

    print_good = 0x0804867D

    simulation.explore(find=print_good)

    if simulation.found:
        solution = simulation.found[0]
        print('flag: ', solution.posix.dumps(0))
    else:
        print('no solution')

if __name__ == '__main__':
    main()
```

**01_angr_avoid**  
拖入 IDA
执行反编译，弹窗函数太大
![](截屏2021-04-18%20下午12.24.23.png)
![](截屏2021-04-18%20下午12.53.37.png)
当二进制函数太大时，使用 avoid 反向查找也能达到很好的效果
```py
import angr

def main():
    proj = angr.Project("/home/darenfy/angr_CTF/Angr_Tutorial_For_CTF/problems/01_angr_avoid")

    init_state = proj.factory.entry_state()

    simulation = proj.factory.simgr(init_state)

    print_good = 0x080485E5

    avoid_address = 0x080485A8

    simulation.explore(find=print_good, avoid=avoid_address)

    if simulation.found:
        solution = simulation.found[0]
        print('flag: ', solution.posix.dumps(0))
    else:
        print('no solution')

if __name__ == '__main__':
    main()

```

**02_angr_find_condition**  
拖入 IDA 就离谱
![](截屏2021-04-18%20下午12.34.16.png)
内部的 ``Good Job`` 和 ``Try again`` 也太多了  
此时可以探索满足条件的状态，而非地址值
```py
import angr
import sys

def main():
    proj = angr.Project("/home/darenfy/angr_CTF/Angr_Tutorial_For_CTF/problems/02_angr_find_condition")
    init_state = proj.factory.entry_state()
    simulation = proj.factory.simgr(init_state)

    def is_successful(state):
        return b'Good Job' in state.posix.dumps(sys.stdout.fileno())

    def should_abort(state):
        return b'Try again' in state.posix.dumps(sys.stdout.fileno())

    simulation.explore(find=is_successful, avoid=should_abort)

    if simulation.found:
        solution = simulation.found[0]
        print('flag: ', solution.posix.dumps(sys.stdin.fileno()))
    else:
        print('no flag')

if __name__ == '__main__':
    main()
```
**03_angr_symbolic_registers**  
拖入 IDA
![](截屏2021-04-18%20上午11.40.37.png)
输入函数是要求输入三个数字，分别存入 ``eax`` ``ebx`` ``edx``
判断对这三个数字进行复杂计算后是否为零，而得到 ``Good job`` 

所以我们的目的是获得满足需求的寄存器值，可以考虑设置寄存器符号值进行求解

将 ``get_user_input`` 下一行设置为起始地址，此时无需初始化，可以用 ``blank_state()``

构建三个符号值，传入该状态相应寄存器，随后进行求解
```py
import angr
import claripy
import sys

def main():
    def is_successful(state):
        return b'Good Job' in state.posix.dumps(sys.stdout.fileno())

    def should_abort(state):
        return b'Try again' in state.posix.dumps(sys.stdout.fileno())
    proj = angr.Project("/home/darenfy/angr_CTF/Angr_Tutorial_For_CTF/problems/03_angr_symbolic_registers")

    start_address = 0x08048980

    init_state = proj.factory.blank_state(addr=start_address)
    simulation = proj.factory.simgr(init_state)

    password0 = claripy.BVS('p0', 32)
    password1 = claripy.BVS('p1', 32)
    password2 = claripy.BVS('p2', 32)

    init_state.regs.eax = password0
    init_state.regs.ebx = password1
    init_state.regs.edx = password2

    simulation.explore(find=is_successful, avoid=should_abort)

    if simulation.found:
        solution = simulation.found[0]
        solution0 = solution.solver.eval(password0)
        solution1 = solution.solver.eval(password1)
        solution2 = solution.solver.eval(password2)

        print('flag: ', hex(solution0), hex(solution1), hex(solution2))
    else:
        print('no flag')

if __name__ == '__main__':
    main()
```

**04_angr_symbolic_stack**  
拖入 IDA
![](截屏2021-04-18%20下午12.56.34.png)
输入函数要求输入两个参数，进行复杂计算后同样进行判断，解决办法可以同上题一致  
与上题不同的是，由于栈的存在，起始地址的选择需要注意
```bash
push    ebp
mov     ebp, esp
sub     esp, 18h
# 以上为正常加载时，栈帧处理

sub     esp, 4
lea     eax, [ebp+var_10]
push    eax
lea     eax, [ebp+var_C]
push    eax
push    offset aUU      ; "%u %u"
call    ___isoc99_scanf
add     esp, 10h
# 以上为执行 scanf 时的完整栈帧处理 

mov     eax, [ebp+var_C]
sub     esp, 0Ch
...
```
在 ``scanf`` 之后启动，我们跳过对应栈，手动构造所需栈  
```text
1. esp -> ebp

由于两个参数是从 [ebp - 10h] [ebp - 0ch] 处取得
2. padding [ebp, ebp-8h]

3. push symbols to [ebp - 10h] [ebp - 0ch]
```
完整解答  
```py
import angr
import claripy
import sys

def is_successful(state):
    return b'Good Job' in state.posix.dumps(sys.stdout.fileno())

def should_abort(state):
    return b'Try again' in state.posix.dumps(sys.stdout.fileno())

def main():

    proj = angr.Project("/home/darenfy/angr_CTF/Angr_Tutorial_For_CTF/problems/04_angr_symbolic_stack")

    start_address = 0x8048697

    init_state = proj.factory.blank_state(addr=start_address)

    init_state.regs.ebp = init_state.regs.esp

    password0 = claripy.BVS('password0', 32)
    password1 = claripy.BVS('password1', 32)

    padding_len = 0x8
    init_state.regs.esp -= padding_len

    init_state.stack_push(password0)
    init_state.stack_push(password1)

    simulation = proj.factory.simgr(init_state)
    simulation.explore(find=is_successful, avoid=should_abort)

    if simulation.found:
        solution = simulation.found[0]
        solution0 = solution.solver.eval(password0)
        solution1 = solution.solver.eval(password1)

        print('flag: ', solution0, solution1)
    else:
        print('no flag')

if __name__ == '__main__':
    main()
```

**05_angr_symbolic_memory**  
本题调用 ``scanf("%8s %8s %8s %8s")``  
直接对内存操作即可，注意最终输出结果需要转换为 ``bytes``
```py
import angr
import claripy
import sys

def success(state):
    return b'Good Job' in state.posix.dumps(sys.stdout.fileno())

def fail(state):
    return b'Try again' in state.posix.dumps(sys.stdout.fileno())

def main():

    proj = angr.Project("/home/darenfy/angr_CTF/Angr_Tutorial_For_CTF/problems/05_angr_symbolic_memory")

    start_address = 0x08048601
    init_state = proj.factory.blank_state(addr=start_address)

    user_input = claripy.BVS("user_input", 64)
    password0 = claripy.BVS("password0", 64)
    password1 = claripy.BVS("password1", 64)
    password2 = claripy.BVS("password2", 64)

    init_state.memory.store(0x0A1BA1C0, user_input)
    init_state.memory.store(0x0A1BA1C8, password0)
    init_state.memory.store(0x0A1BA1D0, password1)
    init_state.memory.store(0x0A1BA1D8, password2)

    simulation = proj.factory.simgr(init_state)
    simulation.explore(find=success, avoid=fail)

    if simulation.found:
        solution = simulation.found[0]
        solution0 = solution.solver.eval(user_input, cast_to=bytes)
        solution1 = solution.solver.eval(password0, cast_to=bytes)
        solution2 = solution.solver.eval(password1, cast_to=bytes)
        solution3 = solution.solver.eval(password2, cast_to=bytes)

        print('flag: ', solution0, solution1, solution2, solution3)
    else:
        print('no flag')

if __name__ == '__main__':
    main()
```

**06_angr_symbolic_dynamic_memory**  
上题是静态内存加载，如果是动态内存该如何解决呢
可以伪造一个未被使用的内存地址，并修改数据指针指向该地址  
注： Angr 在内存中存储整数使用大端序，你可以使用参数 ``endness=proj.arch.memory_endness``，在 x86 平台上，是小端序
```py
import angr
import claripy
import sys

def success(state):
    return b'Good Job' in state.posix.dumps(sys.stdout.fileno())

def fail(state):
    return b'Try again' in state.posix.dumps(sys.stdout.fileno())

def main():

    proj = angr.Project("/home/darenfy/angr_CTF/Angr_Tutorial_For_CTF/problems/06_angr_symbolic_dynamic_memory")

    start_address = 0x08048699
    init_state = proj.factory.blank_state(addr=start_address)

    fake_heap_addr = 0x602000
    buffer0 = 0x0ABCC8A4
    buffer1 = 0x0ABCC8AC
    password0 = claripy.BVS("password0", 64)
    password1 = claripy.BVS("password1", 64)

    init_state.mem[buffer0].uint32_t = fake_heap_addr
    init_state.mem[buffer1].uint32_t = fake_heap_addr + 9

    init_state.memory.store(0x602000, password0)
    init_state.memory.store(0x602000 + 9, password1)

    simulation = proj.factory.simgr(init_state)
    simulation.explore(find=success, avoid=fail)

    if simulation.found:
        solution = simulation.found[0]
        solution0 = solution.solver.eval(password0, cast_to=bytes)
        solution1 = solution.solver.eval(password1, cast_to=bytes)

        print('flag: ', solution0 + solution1)
    else:
        print('no flag')

if __name__ == '__main__':
    main()
```

**07_angr_symbolic_file**  
本题大致流程是使用 ``fread`` 函数从文件中读取 ``password``，命令行输入将被写入 ``ignore_me`` 函数的文件中

需要确定读取文件的 ``fread`` 函数并将其文件参数替换成我们手动模拟出的文件，最后解出符号输入

`` txt -> fopen() -> fread() -> fclose() -> unlink()``

```py
import angr
import claripy
import sys

def success(state):
    return b'Good Job' in state.posix.dumps(sys.stdout.fileno())

def fail(state):
    return b'Try again' in state.posix.dumps(sys.stdout.fileno())

def main():

    proj = angr.Project("/home/darenfy/angr_CTF/Angr_Tutorial_For_CTF/problems/07_angr_symbolic_file")

    start_address = 0x080488E7
    init_state = proj.factory.blank_state(addr=start_address)

    filename = 'OJKSQYDP.txt'
    symbolic_file_size_bytes = 64

    password = claripy.BVS('password', symbolic_file_size_bytes * 8)
    password_file = angr.storage.SimFile(filename, content=password, size=symbolic_file_size_bytes)
    init_state.fs.insert(filename, password_file)

    simulation = proj.factory.simgr(init_state)
    simulation.explore(find=success, avoid=fail)

    if simulation.found:
        solution = simulation.found[0]
        solution0 = solution.solver.eval(password, cast_to=bytes)

        print('flag: ', solution0)
    else:
        print('no flag')

if __name__ == '__main__':
    main()
```
**08_angr_constraints**  
本题主要流程是构造了一个判断函数 ``check_equals_xxxxxxx``，它会将经过复杂计算的输入与其引用的的字符串做比较

思路为在这个函数之前手动约束输入字符串与引用字符串相等

```py
import angr
import claripy
import sys

def success(state):
    return b'Good Job' in state.posix.dumps(sys.stdout.fileno())

def fail(state):
    return b'Try again' in state.posix.dumps(sys.stdout.fileno())

def main():

    proj = angr.Project("/home/darenfy/angr_CTF/Angr_Tutorial_For_CTF/problems/08_angr_constraints")

    start_address = 0x08048625
    init_state = proj.factory.blank_state(addr=start_address)

    password = claripy.BVS('passwd', 16*8)
    init_state.memory.store(0x804A050, password)

    checkpoints_addr = 0x0804866C
    simulation = proj.factory.simgr(init_state)
    simulation.explore(find=checkpoints_addr)

    if simulation.found:
        solution = simulation.found[0]
        load_symbol = solution.memory.load(0x804A050, 16)
        solution.add_constraints(load_symbol == 'AUPDNNPROEZRJWKB')
        flag = solution.solver.eval(password, cast_to=bytes)

        print('flag: ', flag)
    else:
        print('no flag')

if __name__ == '__main__':
    main()
```

**09_angr_hooks**  
与上题相比，在 ``check_equals_xxxxx`` 之后再输入字符串与经复杂计算的内置密码进行比较，采用 ``Hook`` 处理掉 ``check_equals_xxxx``

```py
import angr
import claripy
import sys

def success(state):
    return b'Good Job' in state.posix.dumps(sys.stdout.fileno())

def fail(state):
    return b'Try again' in state.posix.dumps(sys.stdout.fileno())

def main():

    proj = angr.Project("/home/darenfy/angr_CTF/Angr_Tutorial_For_CTF/problems/09_angr_hooks")

    init_state = proj.factory.entry_state()

    checkpoints_addr = 0x080486B3
    skip_len = 5

    @proj.hook(checkpoints_addr, length=skip_len)
    def skip_check(state):
        buffer_addr = 0x0804A054
        load_buffer_symbol = state.memory.load(buffer_addr, 16)
        check_str = 'XYMKBKUHNIQYNQXE'
        state.regs.eax = claripy.If(
            load_buffer_symbol == check_str,
            claripy.BVV(1, 32),
            claripy.BVV(0, 32)
        )

    simulation = proj.factory.simgr(init_state)
    simulation.explore(find=success, avoid=fail)

    if simulation.found:
        solution = simulation.found[0]
        flag = solution.posix.dumps(sys.stdin.fileno())

        print('flag: ', flag)
    else:
        print('no flag')

if __name__ == '__main__':
    main()
```
**10_angr_simprocedures**  
拖入 IDA，这种图又来了
![](截屏2021-04-18%20下午3.30.08.png)
类似与上题，但是调用次数太多，采用 hook 的方法就没有任何意义了，所以可以使用 ``SimProcedure`` 自己实现 ``check_equals_xxxx`` 并 ``Hook`` ``check_equals_xxxx``符号

```py
import angr
import claripy
import sys

def success(state):
    return b'Good Job' in state.posix.dumps(sys.stdout.fileno())

def fail(state):
    return b'Try again' in state.posix.dumps(sys.stdout.fileno())

def main():

    proj = angr.Project("/home/darenfy/angr_CTF/Angr_Tutorial_For_CTF/problems/10_angr_simprocedures")

    init_state = proj.factory.entry_state()

    class ReplaceCheck(angr.SimProcedure):
        def run(self, to_check, length):
            input_addr = to_check
            input_len = length

            user_input = self.state.memory.load(
                input_addr,
                input_len
            )

            check_str = 'ORSDDWXHZURJRBDH'
            return self.state.solver.If(
                user_input == check_str,
                self.state.solver.BVV(1, 32),
                self.state.solver.BVV(0, 32)
            )
    
    check_symbols = 'check_equals_ORSDDWXHZURJRBDH'
    proj.hook_symbol(check_symbols, ReplaceCheck())

    simulation = proj.factory.simgr(init_state)
    simulation.explore(find=success, avoid=fail)

    if simulation.found:
        solution = simulation.found[0]
        flag = solution.posix.dumps(sys.stdin.fileno())

        print('flag: ', flag)
    else:
        print('no flag')

if __name__ == '__main__':
    main()
```
**11_angr_sim_scanf**  
拖入 IDA，为何总是它  
![](截屏2021-04-18%20下午3.46.39.png)
这次不再是 ``check_equals_xxxx`` 了，而是换成了 ``scanf``，构造自己的版本进行替换,因为 ``Angr`` 不支持用 ``scanf`` 请求多个参数

```py
import angr
import claripy
import sys

def success(state):
    return b'Good Job' in state.posix.dumps(sys.stdout.fileno())

def fail(state):
    return b'Try again' in state.posix.dumps(sys.stdout.fileno())

def main():

    proj = angr.Project("/home/darenfy/angr_CTF/Angr_Tutorial_For_CTF/problems/11_angr_sim_scanf")

    init_state = proj.factory.entry_state()

    class ReplaceScanf(angr.SimProcedure):
        def run(self, formatstring, addr1, addr2):
            scanf0 = claripy.BVS("scanf0", 8*4)
            scanf1 = claripy.BVS("scanf1", 8*4)

            self.state.mem[addr1].uint32_t = scanf0
            self.state.mem[addr2].uint32_t = scanf1

            self.state.globals['solutions'] = (scanf0, scanf1)
    
    scanf_symbol = '__isoc99_scanf'
    proj.hook_symbol(scanf_symbol, ReplaceScanf())

    simulation = proj.factory.simgr(init_state)
    simulation.explore(find=success, avoid=fail)

    if simulation.found:
        solution = simulation.found[0]
        flag = solution.globals['solutions']

        print('flag: ', solution.solver.eval(flag[0]), solution.solver.eval(flag[1]))
    else:
        print('no flag')

if __name__ == '__main__':
    main()
```

**12_angr_veritesting**  
本题是对 ``veritesting`` 参数的尝试验证  
```py
import angr
import claripy
import sys

def success(state):
    return b'Good Job.' in state.posix.dumps(sys.stdout.fileno())

def fail(state):
    return b'Try again.' in state.posix.dumps(sys.stdout.fileno())

def main():

    proj = angr.Project("/home/darenfy/angr_CTF/Angr_Tutorial_For_CTF/problems/12_angr_veritesting")
    init_state = proj.factory.entry_state()
    simulation = proj.factory.simgr(init_state, veritesting=True)

    simulation.explore(find=success, avoid=fail)

    if simulation.found:
        solution = simulation.found[0]
        flag = solution.posix.dumps(sys.stdin.fileno())

        print('flag: ', flag)
    else:
        print('no flag')

if __name__ == '__main__':
    main()
```

**13_angr_static_binary**  
本题与第一题相似，只不过是使用静态库编译，Angr 可以使用使用 ``SimProcedures`` 将标准库进行替换以加快运行速度  

```py
import angr
import claripy
import sys

def main():

    proj = angr.Project("/home/darenfy/angr_CTF/Angr_Tutorial_For_CTF/problems/13_angr_static_binary")
    init_state = proj.factory.entry_state()

    proj.hook(0x0804ED40, angr.SIM_PROCEDURES['libc']['printf']())
    proj.hook(0x0804ED80, angr.SIM_PROCEDURES['libc']['scanf']())
    proj.hook(0x0804F350, angr.SIM_PROCEDURES['libc']['puts']())
    proj.hook(0x08048D10, angr.SIM_PROCEDURES['glibc']['__libc_start_main']())

    simulation = proj.factory.simgr(init_state, veritesting=True)

    good = 0x080489E6
    TryAgain = 0x080489D4

    simulation.explore(find=good, avoid=TryAgain)

    if simulation.found:
        solution = simulation.found[0]
        flag = solution.posix.dumps(sys.stdin.fileno())

        print('flag: ', flag)
    else:
        print('no flag')

if __name__ == '__main__':
    main()
```

加上 ``veritesting`` 后依旧可以解出来

本来还想测试一下速度比，在看到未替换文件执行过程的艰难后，我只能说 ``Angr`` 真强

**14_angr_shared_library**  
本题中检查函数由外部 ``so`` 文件加载，如何加载 ``so`` 文件呢？  
共享库文件使用 ``PIC`` 即位置无关代码，在加载时，需要指定基址  
```py
import angr
import claripy
import sys

def main():

    base = 0x4000000
    proj = angr.Project(
        "/home/darenfy/angr_CTF/Angr_Tutorial_For_CTF/problems/lib14_angr_shared_library.so", 
        load_options={
            'main_opts': {
                'custom_base_addr' : base
            }
    })

    buffer_pointer = claripy.BVV(0x3000000, 32)
    validate = base + 0x6d7
    init_state = proj.factory.call_state(validate, buffer_pointer, claripy.BVV(8, 32))

    password = claripy.BVS('password', 8*8)
    init_state.memory.store(buffer_pointer, password)

    simulation = proj.factory.simgr(init_state)
    success_addr = base + 0x783

    simulation.explore(find=success_addr)

    if simulation.found:
        solution = simulation.found[0]
        solution.add_constraints(solution.regs.eax != 0)
        flag = solution.solver.eval(password, cast_to=bytes)

        print('flag: ', flag)
    else:
        print('no flag')

if __name__ == '__main__':
    main()
```
**15_angr_arbitrary_read**  
![](截屏2021-04-19%20上午10.51.51.png)  
本题需要通过输入数字和字符串将程序溢出达到任意读的目的  
所以考虑的步骤为：  
- 输出使用的函数是 ``puts``，可以利用它输出 ``Good Job``  
- 判断 ``puts`` 的第一个参数，即指向被打印字符串的指针是否可以被用户修改为 ``Good Job`` 的地址  
- 解出能够打印 ``Good Job`` 的输入  

```py
import angr
import claripy
import sys

def main():
    proj = angr.Project('/home/darenfy/angr_CTF/Angr_Tutorial_For_CTF/problems/15_angr_arbitrary_read')
    init_state = proj.factory.entry_state()

    class ReplacementScanf(angr.SimProcedure):

        def run(self, formatstring, check_key_address, input_buffer_address):
            scanf0 = claripy.BVS('scanf0', 4*8)
            scanf1 = claripy.BVS('scanf1', 20 * 8)

            for char in scanf1.chop(bits=8):
                self.state.add_constraints(char >= '0', char <='z')

            self.state.memory.store(check_key_address, scanf0, endness=proj.arch.memory_endness)
            self.state.memory.store(input_buffer_address, scanf1)
            
            self.state.globals['solution0'] = scanf0
            self.state.globals['solution1'] = scanf1

    scanf_symbol = '__isoc99_scanf'
    proj.hook_symbol(scanf_symbol, ReplacementScanf())

    def check_puts(state):
        puts_parameter = state.memory.load(state.regs.esp+4, 4, endness=proj.arch.memory_endness)

        if state.solver.symbolic(puts_parameter):
            good_job_string_address = 0x484F4A47

            copied_state = state.copy()

            copied_state.add_constraints(puts_parameter == good_job_string_address)
            if copied_state.satisfiable():
                state.add_constraints(puts_parameter == good_job_string_address)
                return True
            else:
                return False
        else:
            return False
    
    simulation = proj.factory.simgr(init_state)

    def success(state):
        puts_address = 0x8048370

        if state.addr == puts_address:
            return check_puts(state)
        else:
            return False

    simulation.explore(find=success)

    if simulation.found:
        solution_state = simulation.found[0]

        scanf0 = solution_state.globals['solution0']
        scanf1 = solution_state.globals['solution1']
        solution0 = solution_state.solver.eval(scanf0)
        solution1 = solution_state.solver.eval(scanf1, cast_to=bytes)
        print('overflow:', solution0, solution1)

if __name__ == '__main__':
    main()
```
**16_angr_arbitrary_write**  
拖入 IDA  
![](截屏2021-04-19%20上午11.17.55.png)  
本题目的是通过控制 ``strncpy`` 的源数据和目的地址来实现向任意地址写入任意数据  
约束为源数据为引用字符串，目的指针指向安全缓存  

```py
import angr
import claripy
import sys

def main():
    proj = angr.Project('/home/darenfy/angr_CTF/Angr_Tutorial_For_CTF/problems/16_angr_arbitrary_write')
    init_state = proj.factory.entry_state()

    class ReplacementScanf(angr.SimProcedure):

        def run(self, formatstring, check_key_address, input_buffer_address):
            scanf0 = claripy.BVS('scanf0', 4*8)
            scanf1 = claripy.BVS('scanf1', 20 * 8)

            for char in scanf1.chop(bits=8):
                self.state.add_constraints(char >= '0', char <='z')

            self.state.memory.store(check_key_address, scanf0, endness=proj.arch.memory_endness)
            self.state.memory.store(input_buffer_address, scanf1)
            
            self.state.globals['solution0'] = scanf0
            self.state.globals['solution1'] = scanf1

    scanf_symbol = '__isoc99_scanf'
    proj.hook_symbol(scanf_symbol, ReplacementScanf())

    def check_strncpy(state):
        strncpy_dest = state.memory.load(state.regs.esp+4, 4, endness=proj.arch.memory_endness)
        strncpy_src = state.memory.load(state.regs.esp+8, 4, endness=proj.arch.memory_endness)
        strncpy_len = state.memory.load(state.regs.esp+12, 4, endness=proj.arch.memory_endness)
        
        src_contents = state.memory.load(strncpy_src, strncpy_len)

        if state.solver.symbolic(strncpy_dest) and state.solver.symbolic(src_contents):

            password_string = "NDYNWEUJ"
            buffer_address = 0x57584344

            does_src_hold_password = src_contents[-1:-64] == password_string
            does_dest_equal_buffer_address = strncpy_dest == buffer_address
            
            if state.satisfiable(extra_constraints=(does_src_hold_password, does_dest_equal_buffer_address)):
                state.add_constraints(does_src_hold_password, does_dest_equal_buffer_address)
                return True
            else:
                return False
        else:
            return False
    
    simulation = proj.factory.simgr(init_state)

    def success(state):
        strncpy_addr = 0x08048410

        if state.addr == strncpy_addr:
            return check_strncpy(state)
        else:
            return False

    simulation.explore(find=success)

    if simulation.found:
        solution_state = simulation.found[0]

        scanf0 = solution_state.globals['solution0']
        scanf1 = solution_state.globals['solution1']
        solution0 = solution_state.solver.eval(scanf0)
        solution1 = solution_state.solver.eval(scanf1, cast_to=bytes)
        print('overflow:', solution0, solution1)

if __name__ == '__main__':
    main()
```

**17_angr_arbitrary_jump**  
当一个指令有很多分支的可能性时，称之为不受约束的状态， 比如说当用户的输入决定下一条指令的位置

``Angr`` 在遭遇不受约束状态时会将其抛出，本题将要关闭默认行为，转而利用此状态去进行任意跳转  
处理步骤：
- 初始化模拟器，利用 ``angr`` 记录不受约束的状态
- 开始步进直到发现 ``eip`` 为符号的状态  
- 限制 ``eip`` 与 ``print_good`` 函数地址相同

```py
import angr
import claripy
import sys

def main():
    proj = angr.Project('/home/darenfy/angr_CTF/Angr_Tutorial_For_CTF/problems/17_angr_arbitrary_jump')
    init_state = proj.factory.entry_state()

    class ReplacementScanf(angr.SimProcedure):
        def run(self, format_string, input_buffer_address):
            input_buffer = claripy.BVS(
                'input_buffer', 64 * 8)  
            for char in input_buffer.chop(bits=8):
                self.state.add_constraints(char >= '0', char <= 'z')

            self.state.memory.store(
                input_buffer_address, input_buffer, endness=proj.arch.memory_endness)
            self.state.globals['solution'] = input_buffer

    scanf_symbol = '__isoc99_scanf'
    proj.hook_symbol(scanf_symbol, ReplacementScanf())

    simulation = proj.factory.simgr(
        init_state, 
        save_unconstrained=True,
        stashes={
            'active':[init_state],
            'unconstrained': [],
            'found': [],
        })

    def has_found_solution():
        return simulation.found

    def has_unconstrained():
        return simulation.unconstrained

    def has_active():
        return simulation.active

    while (has_active() or has_unconstrained()) and (not has_found_solution()):
        for unconstrained_state in simulation.unconstrained:
            eip = unconstrained_state.regs.eip
            if unconstrained_state.satisfiable(extra_constraints=(eip == 0x42585249,)):
                simulation.move('unconstrained', 'found')

        simulation.step()
    
    if simulation.found:
        solution_state = simulation.found[0]
        solution_state.add_constraints(solution_state.regs.eip == 0x42585249)
        
        flag = solution_state.solver.eval(solution_state.globals['solution'], cast_to=bytes)
        print(flag[::-1])
    else:
        raise Exception('Could not find the solution')

if __name__ == '__main__':
  main()
```
---
**参考资料**
angr_ctf 题目
https://github.com/jakespringer/angr_ctf

write_ups 参考
https://github.com/Hustcw/Angr_Tutorial_For_CTF
https://github.com/ZERO-A-ONE/AngrCTF_FITM
https://blog.csdn.net/u013648063/category_10403710.html?spm=1001.2014.3001.5482
