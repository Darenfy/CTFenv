angr 是多架构二进制分析工具，能够执行动态符号执行和多种静态分析

## angr API 文档
主要查看常见信息
### angr
#### Project  
angr 模块的主类，用来容纳二进制集及他们之间的关系并提供分析
常见变量
- ``analysis`` — 可用分析类型
- ``factory`` — 提供对重要分析节点的访问，比如路径组、符号执行结果
- ``loader`` — 程序加载器
- ``storage`` — 应该被加载或存储的字典

常用函数
- ``hook(addr, hook=None, length=0)``  
    使用一个函数去 Hook 一节代码
- ``factory.blank_state(**kargs)``
    返回一个几乎未初始化的状态对象
- ``factory.entry_state(**kargs)``
    返回一个代表程序入口点的状态对象  
- ``call_state(addr, *args, **kwargs)``
    返回初始化到给定函数起点的状态对象，就像是被传入给定参数调用
- ``simulation_manager()``

#### Program State  
SimState 表示程序的状态，包括内存、寄存器等  

常见变量与属性
- ``regs`` — 寄存器  
- ``mem`` — 内存
- ``memory`` — 作为 flat memory region  
- ``solver`` — 符号求解和变量管理器
- ``addr`` — 指令指针的具体地址

常用函数
- ``add_constraints`` — 添加约束  
- ``satisfiable`` — 当约束满足时  
- ``step`` — 使用当前状态执行符号执行
- ``copy`` — 复制状态
- ``stack_push`` — 入栈
- ``stack_pop`` — 出栈

#### Storage  
**SimMemView**  
访问内存便捷接口
- state.mem.deref 解索引  
- state.mem.types 为数据指定数据类型  
- state.mem.resolved/.concrete 抽取结构化数据  

**SimFile**  
在硬盘中构建文件  
参数：name, content, size

**Memory Mixins**
- find(addr, data, max_search, **kwargs)
- load(addr, **kwargs)
- store(addr, data, **kwargs)

#### Simulation Manager
主要功能是处理 State，并根据需要进行 step forward, filter, merge, move around

例如，可以以不同的速率步进两个不同的状态 stashes，然后将其进行 merge

Stashes 可以被作为属性获取到（比如 ``.active``）

多路复用 可以加上 ``mp_`` ，单个状态可以加上 ``one_``

注意：不应直接构造 SimulationManager，有便携的方式创建 factory

最重要的方法是 ``step`` ``explore`` ``use_technique``

**explore**
explore(stash='active', n=None, find=None, avoid=None, find_stash='found',avoid_stash='avoid', cfg=None, num_find=1, **kwargs)

explore 主要用来探索路径的可能性

查找 find 条件 存入 find_stash
避免 avoid 条件 存入 avoid_stash

find 和 avoid 参数可能是：
- 地址
- 地址集合或列表
- 拥有状态的函数，并返回是否匹配

#### Procedure  
**SimProcedure**  
这是一个非常棒的对象，可以用来描述状态运行的流程
通常可以构建子类并重写 ``run()`` 函数

#### Analysis  
程序上的各种分析  
主要类
- ``angr.analysis.analysis.Analysis``
    描述程序分析  
- ``angr.analysis.forward_analysis.forward_analysis.ForwardAnalysis``  
    前端分析框架，可以为多种分析提供基础，包括 CFG 分析， VFG 分析，DDG 分析等  
    前端分析通过遍历图、计算抽象值、将结果存储在抽象状态中，提供前端数据流分析。用户可以指定遍历图的位置、遍历方式、抽象值与抽象状态的定义方式  
- ``angr.analysis.backward_slice.BackwardSlice``  
    程序后端切片。  
    基于 CFG，CDG，DDG 从特定语句创建后端切片  

- ``angr.analysis.bindiff.BinDiff``  
    计算 angr Project 表示的两个二进制之间的 diff  

- ``angr.analysis.cfg.cfg_fast.CFGFast``  
    在给定的二进制文件中查找函数，并以非常快速的方式构建控制流程图：避免模拟程序执行、跟踪状态、展示花费巨大的数据流分析，CFGFast 将展现轻量级分析，部分启发式，部分强假设  

### cle - Binary Loader  
CLE 是一个可拓展的二进制加载器，主要目标是加载可执行文件及所依赖的各种库，生成程序加载和执行的地址空间
#### Loading Interface  
``Loder`` 加载所有对象和输出进程的内存抽象  
常见可选参数：
- ``auto_load_libs`` — 是否自动加载共享库
- ``force_load_libs`` — 强制加载的库列表
- ``main_opts`` — 加载 ``main binary`` 的选项字典  
- ``lib_opts`` — 加载对应库名时的选项字典  
- ``preload_libs`` — 与 ``force_load_libs`` 类似，会提供符号解析，比任意依赖都高

可选项字典需要从以下键值中选取：
- ``backend``:“elf”， “pe“， ”mach-o“， ”blob“
- ``arch``: 用在此二进制上的 ``archinfo.Arch`` 对象
- ``base_addr``: 将对象重载到指定基址
- ``entry_point``: 对象的入口点
其余键值定义在各个后端中

### claripy — Solver Engine  
除非进行核心分析，否则不必要用到深层 API，大部分时间均当作 z3 的简易前端  

### pyvex — Binary Translator  
PyVEX 提供接口，能够将二进制代码转换成 VEX 中间语言  

### archinfo — Arch Information Repository  
archinfo 是一个类集合，包含了制定架构信息，用于辅助跨架构工具，比如 pyvex  

---
**参考资料**
官网文档
https://docs.angr.io/
http://angr.io/api-doc/index.html
https://github.com/angr/angr/tree/master/angr/procedures/libc

https://www.jianshu.com/p/f660800bb70f
https://xz.aliyun.com/t/7117#toc-14