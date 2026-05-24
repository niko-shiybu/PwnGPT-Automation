# ROP Benchmark 失败根因详细分析报告

> 分析时间: 2026-05-04
> 数据来源: 20260503-155325 ROP benchmark (max-iters=6, 无 logic_gate)
> 总体结果: 1/10 PASS (rop-1), 9/10 FAIL

---

## 一、核心问题的三层分类

将 9 个失败案例按失败根因分为三个层次：

### 第一层：测量正确 → 但策略/地址/调用约定错误（3 个 32-bit 案例）

| 案例 | 偏移测量 | 偏移使用 | 真正失败原因 |
|------|---------|---------|------------|
| rop-2 | ✅ 140 (准确) | ✅ 140 | `not_called()` 调 `system("/bin/date")` 而非 `/bin/sh`，LLM 反复尝试找不存在的 `int 0x80` gadget |
| rop-3 | ✅ 140 (准确) | ✅ 140 | 无 win 函数无 `/bin/sh` 字符串，需 ret2libc，但 6 轮反复调用 `disassemble main` 从未做真正的 libc 泄漏 |
| rop-4 | ✅ 140 (准确) | ✅ 140 | 函数地址错误 (`0x08048f5c` vs 正确 `0x08048F0E`)，调用约定参数布局错误 |

**结论：偏移测量不是问题。这 3 个案例中测量完全正确。失败在于 LLM 的 exploit 策略和地址使用。**

### 第二层：测量完全失败 → LLM 幻觉偏移值（4 个 64-bit 案例）

| 案例 | 正确偏移 | 测量结果 | exploit 使用 | 偏差 |
|------|---------|---------|-------------|------|
| rop-5 | 136 | **-1 (失败)** | 512 | 用 pattern_len 当偏移 |
| rop-6 | 136 | **-1 (失败)** | 128 | 缺 RBP 8 字节 |
| rop-7 | 24 | **-1 (失败)** | 512 | 用 pattern_len 当偏移 |
| rop-8 | 24 | **-1 (失败)** | 512 | 用 pattern_len 当偏移 |

**结论：64-bit 的 `stack_measure_ret_offset_gdb` 工具 100% 失败。LLM 在测量失败后将 pattern_len (512) 幻觉为偏移值。这是当前 pipeline 最大的系统性缺陷。**

### 第三层：边界/环境问题（2 个案例）

| 案例 | 问题 |
|------|------|
| rop-9 | 偏移测量到 EBP (56) 而非返回地址 (60)，差 4 字节；且 `get_flag()` 需要特定参数 |
| rop-10 | 二进制无执行权限，测量完全无法进行 |

---

## 二、Decider 是否发现了偏移测量准确度问题？

### 答案：Decider 发现了测量失败，但诊断和建议全是模糊的样板话术。

以下是 rop-5 的全部 decider 诊断（6 轮迭代）：

```
Iter 1: "偏移量测量失败（ret_offset_bytes=-1）...建议使用pattern_create和pattern_offset来手动计算偏移量"
Iter 2: "测量过程中出现了异常...尝试使用其他工具或方法来获取callsystem函数的地址"
Iter 3: "偏移量应为136字节。请重新测量并确认这个偏移量"  ← 提到了136但没坚持
Iter 4: "重新检查并确认callsystem函数的地址"
Iter 5: (SIGILL) "重新检查并确认callsystem函数的地址和pop_rdi_ret gadget"
Iter 6: (SIGSEGV) "确保这些地址与二进制文件中的实际地址匹配"
```

**Decider 从未做到以下几点：**

1. ❌ **从未指出** `stack_measure_ret_offset_gdb` 工具对 64-bit 二进制系统性失效
2. ❌ **从未指出** 偏移 512 来自 pattern_len 而非实际测量
3. ❌ **从未指出** "你写的 32-bit 代码用了 p32，但这是 64-bit 程序"（实际上打包是对的，但架构意识欠缺）
4. ❌ **从未给出** 具体的替代测量方法（如 "用 gdb 手动 run，看 rsp 指向的 pattern 偏移"）
5. ❌ **从未追踪** "同一工具连续失败 N 次" 的事实

Decider 的 `value_score` 在 6 轮中始终为 -50（除了 Iter 6 为 -80），说明它的评估完全退化——没有随着失败次数增加而提高严重性评估。

### Decider 建议的具体性分析

对比 rop-2 (32-bit，测量正确) 和 rop-5 (64-bit，测量失败) 的 decider 建议：

| 维度 | rop-2 (32-bit) | rop-5 (64-bit) |
|------|---------------|----------------|
| 偏移准确性 | 从未检查 (因为测量返回了 140) | "重新测量" 但没说怎么测 |
| 架构意识 | 从未提及 32-bit vs 64-bit | "缓冲区128+保存rbp8=136" 提了一次但后续又忘了 |
| gadget 地址 | "确认关键 gadget" | "确认关键 gadget" (完全相同的话术) |
| 替代方案 | 无 | "使用 pattern_create 手动计算" 但 executor 没做 |

---

## 三、LLM 将测量结果转化为 exploit 的能力分析

### 场景 A：测量结果正确时 (32-bit 案例)

**LLM 能正确使用测量值**（如 offset=140），但会在其他方面犯错：

1. **rop-2 exploit** (`candidate_exploit.py`):
   ```python
   ret_offset = 140  # ✅ 正确使用
   # ❌ 但试图找 int 0x80 gadget — 这是 32-bit syscall 方式，二进制中不存在
   rop_chain += p32(pop_eax_ret) + p32(0xb)  # 想用 sys_execve
   ```
   → **思路错误**：绕了一大圈去找不存在的 gadget，而非直接用已有 system@plt

2. **rop-3 exploit**:
   ```python
   # ✅ 偏移 140 正确
   # ❌ 尝试 elf.search(b'/bin/sh\x00') — 二进制根本没这个字符串
   # ❌ 6 轮循环调用 disassemble main 不做 libc 泄漏
   ```
   → **策略错误**：不了解 ret2libc 需要先泄漏 libc 地址

3. **rop-4 exploit**:
   ```python
   offset = 140  # ✅ 正确
   # ❌ win_addr = 0x08048f5c  — 错误地址
   # ❌ p32(win) + p32(deadbeef) + p32(cafebabe) — 参数布局错误
   ```
   → **地址错误 + 调用约定错误**

### 场景 B：测量结果失败时 (64-bit 案例)

**LLM 会将 pattern_len 幻觉为偏移值**：

```python
# rop-5 最终 exploit:
offset = 512  # ❌ 来自 pattern_len，正确值应为 136

# rop-6 最终 exploit:
payload = b"A" * 128  # ❌ 缺 RBP 8 字节，正确值应为 136

# rop-7 最终 exploit:
offset = 512  # ❌ 来自 pattern_len，正确值应为 24

# rop-8 最终 exploit:
offset = 512  # ❌ 来自 pattern_len，正确值应为 24
```

**偏移幻觉的成因链**：
```
1. stack_measure_ret_offset_gdb 对 64-bit 返回 -1
2. 但 fact_store 中仍记录了 pattern_len=512
3. LLM exploit writer 看到 "crash offset proof" 中提及 512
4. 将 512 当作偏移直接写入 exploit
5. 验证：SIGSEGV
6. Decider： "重新测量偏移" 
7. Executor：再次调用同一个工具 → 再次 -1
8. 循环...
```

### 场景 C：架构意识

好消息：LLM **在所有案例中都正确使用了 p32/p64**：
- 32-bit 案例全部使用 `p32()`
- 64-bit 案例全部使用 `p64()`

这说明 exploit writer 的 prompt 中的架构意识是有效的。

---

## 四、Pipeline 系统性缺陷总结

### 缺陷 1：64-bit 测量工具全线崩溃（最严重）

`stack_measure_ret_offset_gdb` 是一个为 32-bit 设计的工具：
- 32-bit: 3/3 成功 (100%)
- 64-bit: 0/5 成功 (0%)

GDB 在 64-bit 二进制上崩溃在函数体内（RIP 指向 `vulnerable_function+31`），而非在覆盖的返回地址处，所以 cyclic_find 永远找不到正确的 offset。

### 缺陷 2：无可用的测量降级路径

当 `stack_measure_ret_offset_gdb` 失败时，没有自动降级到：
- 手动 `cyclic` 模式生成 + 发送 + core dump 分析
- `disassemble vulnerable_function` + 手动计算 `buf_size + 8(64-bit RBP)`
- 直接写 probe script 发送递增长度的 overflow 探测

### 缺陷 3：Decider 只有样板话术，没有领域知识

Decider 的 prompt 中缺少：
- 对 `ret_offset_bytes=-1` 含义的领域知识
- 对 "pattern_len 不等于 offset" 的认识
- 对 32-bit vs 64-bit 调用约定差异的知识
- 对 "同一工具连续失败应尝试完全不同的方法" 的规则

### 缺陷 4：无 "测量失败断路器" (Circuit Breaker)

Pipeline 允许同一工具在同一测量请求上无限次失败：
- rop-3: `disassemble main` 被调用 6 次，结果相同
- rop-5/6/7/8: `stack_measure_ret_offset_gdb` 被连续调用，结果都是 -1

### 缺陷 5：Exploit 生成不了解测量可信度

Exploit writer 不区分：
- "这是准确测量的值" (如 32-bit offset=140)
- "这是测量失败后的占位值" (如 pattern_len=512)

它把所有 fact_store 中的值都当作等可信度的事实。

---

## 五、优先级修复建议

### P0 — 修复 64-bit 偏移测量（解除所有 64-bit 案例的阻塞）

1. 重写 `stack_measure_ret_offset_gdb`，为 64-bit 使用不同的 GDB 检测逻辑
2. 或者添加纯 pwntools 的 cyclic 测量方法（不依赖 GDB）：
   ```python
   io = process(binary)
   io.send(cyclic(512))
   io.wait()
   core = io.corefile
   offset = cyclic_find(core.fault_addr)
   ```

### P1 — 添加测量断路器 + 降级链

在 executor_agent 中：
```
stack_measure_ret_offset_gdb 失败 ×2 
  → disassemble vulnerable_function + 手动计算
  → 若仍失败，写 probe script 发送递增 overflow
```

### P2 — Decider prompt 注入领域知识

```
当 ret_offset_bytes == -1 时：
  - 这意味着 GDB 工具对当前二进制失效（常见于 64-bit）
  - 不要建议 "重新测量"，建议 "用 disassemble 手动计算偏移"
  - buffer_size + 8 (64-bit RBP) = 返回地址偏移
```

### P3 — Exploit writer 须知测量可信度

在 fact_store 中标注每个值的来源和可信度，让 exploit writer 区分 "已验证的测量" vs "占位默认值"。

---

## 六、数据总表

| 案例 | 架构 | 偏移测量 | 偏移使用 | 打包 | 函数地址 | 调用约定 | 失败根因分类 |
|------|------|---------|---------|------|---------|---------|------------|
| rop-1 | 32 | ✅ N/A | ✅ | ✅ | ✅ | ✅ | **PASS** (ret2text) |
| rop-2 | 32 | ✅ 140 | ✅ 140 | ✅ | ❌ 策略错误 | - | 策略错误 |
| rop-3 | 32 | ✅ 140 | ✅ 140 | ✅ | ❌ 无 win 函数 | - | 策略错误 |
| rop-4 | 32 | ✅ 140 | ✅ 140 | ✅ | ❌ 错误地址 | ❌ 参数布局 | 地址+调用约定 |
| rop-5 | 64 | ❌ -1 | ❌ 512 | ✅ | ❌ | - | 测量失败→幻觉 |
| rop-6 | 64 | ❌ -1 | ❌ 128 | ✅ | ❌ | - | 测量失败→少RBP |
| rop-7 | 64 | ❌ -1 | ❌ 512 | ✅ | ❌ | - | 测量失败→幻觉 |
| rop-8 | 64 | ❌ -1 | ❌ 512 | ✅ | ❌ | - | 测量失败→幻觉 |
| rop-9 | 32 | ⚠️ 56 (差4) | ⚠️ 56 | ✅ | ❌ 缺参数 | ❌ | 边界偏移+调用约定 |
| rop-10 | 64 | ❌ 完全失败 | ❌ 100 | ✅ | ❌ 硬编码 | - | 无执行权限 |
