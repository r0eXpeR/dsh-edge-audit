<!-- 改编自 Cloudflare security-audit-skill MEMORY-SAFETY-AND-BINARY.md，MIT，Copyright (c) 2025-2026 Cloudflare, Inc.。完整英文清单：references/full/native-memory.md -->

# 原生内存、二进制与内核

## 核心方法

适用：在内存不安全或特权上下文处理不可信字节，包括 C/C++/Objective-C、Rust `unsafe`、FFI、内核模块与驱动、parser/decoder、网络 daemon、固件、binary loader、语言 runtime、JIT。协议授权与状态机逻辑见 api-messaging。大型目标按 parser、allocator/lifetime、FFI、并发、loader、runtime、特权接口拆分。

- 从攻击者可控输入和所有调用者重新推导每个 bound 与 lifetime，按最坏的被接受情况验证，不看典型测试向量。
- Panic、sanitizer 报告、crash 只有在现实不可信输入能到达时才证明缺陷。不要从标签推断内存破坏、代码执行或共享可用性影响。
- 只用强隔离的本地 harness、sanitizer、确定性并发测试、已有 fuzz target、调试器辅助故障分类。证明不变量被破坏和可观察影响后即停；不研发后续内存利用技术。
- 汇编、JIT 代码、自定义 allocator、对象内访问、外部库可能逃出 sanitizer 覆盖，要确认相关指令是否被插桩。
- 审计修复与重复路径：一个调用者、架构、协议角色、feature flag、兼容路径上的检查保护不了 sibling。
- 为每个 parser/FFI 边界建表：接受的长度/类型、已检查表示、分配 owner、consumer、线程、teardown。多数 native 发现就是这张表里的一处分歧。
- 用已有语料和本地生成的小边界 fixture，保存确切的 sanitizer/运行输出及触发它的输入属性；避免大资源消耗和任何线上目标。

## 类目检查点

### 边界、整数与表示
- **越界读写**：长度、offset、index、terminator 到达固定或已分配 buffer 而无正确 bound。减去 prefix、对齐、padding、terminator 后重算余量；同时查源与目标容量；短输入是否在声明长度被信任前就被读取。
- **整数溢出、下溢、截断、符号**：审查分配、复制、循环、索引、指针运算前的攻击者算术。高命中模式：`a - b` 且 `b > a`、`count * element_size`、接近类型上限的加法、负值转无符号、64 位长度收窄到 32 位、`-1` 哨兵变大尺寸。确认后续使用的是哪个已检查表示。
- **单位与指针深度混淆**：混用字节、元素、code unit、page、word、wire unit、嵌套指针元素大小。比较解析、校验、分配、API 边界、复制时的单位。边界检查与分配用了同一错误单位仍是错的。
- **未初始化/部分初始化数据**：buffer、padding、struct 字段、vector capacity 在初始化前被返回、比较、哈希、序列化或跨信任边界。需要可观察消费者和现实输出长度；栈分配本身不是泄露。

### 生命周期、类型与并发
- **UAF、陈旧视图、double free**：owner 被释放时 callback、wait queue、timer、iterator、borrowed slice、缓存 raw pointer 仍可使用。查每条 error、cancellation、close、realloc 路径；嵌入式通知锚点的每条 free 路径都须 drain 或 detach 所有 observer。
- **类型混淆/非法 downcast**：tag、vtable、union discriminator、object kind、foreign handle 的检查与后续读取的表示不一致。找未检查 dynamic cast、重用后陈旧 tag、校验元素与消费元素不同的序列化类型。
- **引用计数与 ownership 竞态**：非原子 retain/release、check 后无锁 use、跨线程 ownership 不一致。比较 fast、error、shutdown、兼容路径的锁和 ownership 规则。
- **共享状态竞态/TOCTOU**：并发 parser stream、全局 cache、lazy init、signal handler、资源 teardown 使先前建立的 bound、策略、指针失效。用可重复调度、barrier 或 thread sanitizer 验证；没有安全相关状态迁移的假设交错仍是 Needs Validation。
- **锁序、死锁、饥饿**：外部可达操作以不一致顺序取锁，或持锁跨 callback 与阻塞 I/O。仅在有界输入可停止共享进度时按可用性报告，否则记为并发缺陷。

### FFI 与 ABI
- **指针-长度/ownership 契约不匹配**：调用方与被调方在谁分配、释放、pin、修改 buffer，指针有效多久，长度是字节还是元素上有分歧。追每个 `extern`、CGo/JNI/Python/native binding、生成 wrapper 两侧；查 null、零长度、别名、callback 保留。
- **布局、对齐、enum 分歧**：struct、bitfield、packed record、callback 签名、整数宽度、enum、调用约定因架构或 build flag 不同。核实 `repr`、packing、对齐、endianness、ABI 类型。不透明外部实现需 Needs Validation。
- **Unwind、异常、线程亲和违规**：异常或 panic 跨越禁止 unwind 的 ABI，callback 在 teardown 后运行，要求单一 runtime 线程的 API 在别处调用。定影响前确认进程 abort 还是状态损坏。

### Binary 加载与 runtime
- **库/插件/可执行搜索顺序信任**：特权进程从低信任可写路径加载，或经攻击者可影响的工作目录或环境解析裸名。比较安装归属与每个 fallback、兼容搜索路径。
- **制品身份/签名绑定缺失**：loader 验证一个文件或元数据记录，却映射另一镜像（路径解析、文件替换、架构 slice、内嵌资源未绑定）。
- **畸形 binary 元数据与重定位**：offset、count、section、relocation、symbol、bytecode、debug 元数据在范围、重叠、表示检查前被信任。区分内存破坏与安全拒绝。
- **JIT/生成代码一致性**：validator、解释器、优化器、生成代码对类型、bound、副作用、lifetime 看法不一。用同一本地输入 diff 优化与未优化路径；语言语义内的输出差异不算。
- **卸载、重载、teardown**：函数指针、callback、worker 线程、数据视图在模块卸载或 runtime reset 后存活；failed-load 清理与启动同等审查。

### 内核与特权接口
- **User-copy 边界与重复读**：syscall、ioctl、驱动从用户内存得出可信事实后再读同一可变地址（double fetch）；审计每个 user-copy 的大小、方向、访问检查。
- **特权对象生命周期/dispatch**：retain/release 不平衡、teardown 无 observer drain、selector/table 索引未检查、兼容路径漏 guard；并排 diff 每条 dispatch 与 free 路径。
- **权限不足的强力接口**：device node、admin socket、helper、管理 API 校验形状但不校验调用方对资源的权限。外部权限或沙箱策略决定时记 Needs Validation。

## 验证与反证

1. 确立现实的不可信入口，以及破坏 bounds、type、lifetime、ABI、并发、loader 或权限不变量的确切操作。
2. 分类可观察效果：invalid read、invalid write、stale alias、wrong object、未初始化输出、未授权镜像加载、deadlock、安全进程终止。不声称超出观察的效果。
3. 用最窄的隔离本地 harness、已有测试、sanitizer、fuzzer 复现，核实 sanitizer 覆盖故障操作，记录架构/构建条件。无沙箱时保持静态结论并标明证据级别。
4. 并发用确定性调度或 sanitizer trace；binary 加载要证明已检查身份不同于映射身份，并指出低信任写入者。
5. **常见误报**：仅限 C/C++/`unsafe`/FFI，安全 Rust、Go、托管语言的内存破坏主张须先证明存在 unsafe 或 native 边界；panic 或安全退出不等于内存破坏；用户把自己的插件加载进自己的进程；被安全拒绝的畸形文件；无消费者的未初始化栈变量。
6. 确认需确切输入、源码路径、观察结果；可达性、ABI、构建、部署、运行事实未决时记 Needs Validation，写明所需有界检查。
