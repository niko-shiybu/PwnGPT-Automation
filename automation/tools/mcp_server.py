"""MCP server exposing PwnGPT CTF tools to OpenHands SDK Agent."""
from __future__ import annotations

import json
import sys
from pathlib import Path

_repo_root = Path(__file__).resolve().parents[2]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from fastmcp import FastMCP

from automation.tools.tool_runner import (
    tool_stack_measure_ret_offset_gdb,
    tool_rop_find_gadgets,
    tool_fmt_measure_write_offset,
    tool_fmt_scan_stack,
    tool_pwntools_got,
    tool_pwntools_symbols,
    tool_disassemble,
)

mcp = FastMCP("pwn-tools")


def _to_json(result) -> str:
    return json.dumps(
        {
            "measured_facts": result.measured_facts,
            "unresolved_facts": [dict(x) for x in result.unresolved_facts],
            "notes": result.notes,
        },
        ensure_ascii=False,
    )


@mcp.tool()
def measure_offset(binary_path: str) -> str:
    """Measure stack offset to return address using GDB/pwntools."""
    return _to_json(tool_stack_measure_ret_offset_gdb(binary_path))


@mcp.tool()
def find_gadgets(binary_path: str) -> str:
    """Find ROP gadgets (pop_rdi, pop_rsi, ret) in the binary."""
    return _to_json(tool_rop_find_gadgets(binary_path))


@mcp.tool()
def measure_fmt_offset(binary_path: str) -> str:
    """Measure format string write offset using pwntools FmtStr."""
    return _to_json(tool_fmt_measure_write_offset(binary_path))


@mcp.tool()
def scan_fmt_stack(binary_path: str) -> str:
    """Scan format string stack positions using AAAA%i$p technique."""
    return _to_json(tool_fmt_scan_stack(binary_path))


@mcp.tool()
def get_got(binary_path: str, symbol: str = "printf") -> str:
    """Get a GOT entry address for a symbol."""
    return _to_json(tool_pwntools_got(binary_path, symbol=symbol))


@mcp.tool()
def get_symbols(binary_path: str) -> str:
    """Get binary symbols (win, flag, main, etc.) via pwntools ELF."""
    return _to_json(tool_pwntools_symbols(binary_path))


@mcp.tool()
def disassemble_func(binary_path: str, function: str = "main") -> str:
    """Disassemble a function in the binary."""
    return _to_json(tool_disassemble(binary_path, function=function))


if __name__ == "__main__":
    mcp.run()
