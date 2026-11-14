# x64dbg-automate 本地 fork（local.8）

不是重写，是把原先住在 `site-packages` 里的猴补丁**上抬成源码**，再用可编辑安装挂回运行时。
来源：`github.com/dariushoule/x64dbg-automate-pyclient` @ `v0.9.2-ghost_fungus` + 本地分支 `local.3`
（补丁号走 `local.4 → local.6`，见 BUG记录 D 组）。

## 为什么

原 `mcp_server_local.py`（0.9.2+local.p2）靠运行时替换 `base._parse_address_or_expression`、
`X64DbgClient.pause` 生效，且物理位置在 `C:\Python314\Lib\site-packages\x64dbg_automate\` ——
`pip install --upgrade` 一次全丢。且 p1 补丁直接改在 `mcp_server.py` 里，重装后只剩 p2，
`run_python` 消失但 local 层照常加载，状态会分叉。

## 装了什么

```
D:\od\x64dbg-automate-fork\      <- 本目录（git 分支 local.3）
  x64dbg_automate\
    __init__.py          + attach 失败时杀掉空跑进程（防孤儿）
    mcp_server.py        上游 + p1(run_python) + on 别名 + drain_first + 地址解析修复
                         + trace 失败附日志尾
    hla_xauto.py         pause() 源码级阻塞态兜底（连发两次，2.25s 门限）
    commands_xauto.py    上游 + p1(execute_command 便捷方法)
    local_ext.py         10 个本地工具；xref 有 deep 模式；skip_call 支持 32 位
    mcp_server_local.py  薄入口：注册 local_ext 后 mcp.run()
  ops\                   verify / xref_baseline / restore_stock / upgrade_upstream
```

安装方式：`pip install -e . --no-build-isolation --no-deps`（setuptools 后端，不联网）。
包版本：`0.9.2+local.8`（`PATCH` 常量、`_XAUTO_MCP_PATCH`、pyproject 三处同步，`local_patch_info` 现场可核）。

## 现场确认补丁是否加载

MCP 工具 `local_patch_info` 会返回 patch 版本、包路径、本地工具清单。或：

```bash
C:\Python314\python.exe -c "import x64dbg_automate as m; print(m.__file__)"
# 必须是 D:\od\x64dbg-automate-fork\x64dbg_automate\__init__.py
```

## ⚠️ 重装/升级时会被 exe 锁坑（实测两次）

宿主（WorkBuddy / Trae）会自动拉起 `x64dbg-automate-mcp.exe` 并**锁定该文件**，于是
`pip install -e .` 在卸载阶段报 `WinError 32`，而元数据此时已被删掉 → `PackageNotFoundError`，
工具全掉。**杀进程没用**，宿主立刻重启它。

两个可用办法：

1. **先退出 MCP 客户端**（或把该 server 停用），再 `pip install -e .`，装完重启客户端。
2. **绕开 console script**：临时删掉 `pyproject.toml` 的 `[project.scripts]` 段 → 安装 → 恢复该段。
   已存在的 `x64dbg-automate-mcp.exe` 只是 launcher（`x64dbg_automate.mcp_server_local:main`），
   源码改了它照样生效，不用重新生成。

装完用 `local_patch_info` 或下面这条确认版本：

```bash
C:\Python314\python.exe -c "import importlib.metadata as m; print(m.version('x64dbg_automate'))"
```

## 回滚（恢复到 pip 官方 0.9.2 + p2 猴补丁）

```powershell
powershell -File ops\restore_stock.ps1
```

备份在 `D:\toolkit\backup\x64dbg_automate_0.9.2_20261114\`（`pkg_original\` = 改之前的整套源码，
含 p1/p2 补丁；`dist-info\` = 原始元数据）。

## 升级上游

```powershell
powershell -File ops\upgrade_upstream.ps1
```

拉 `origin/master` → 新分支 → `git rebase local.3` → 重装 → 跑验证。
冲突集中在 `mcp_server.py`（`toggle_breakpoint` / `wait_for_event` / `_parse_address_or_expression` /
trace 失败分支）、`hla_xauto.py`（`pause`）、`__init__.py`（`_launch_x64dbg` 的孤儿清理），
`local_ext.py` 一般是新增文件不冲突。

## 验证

```powershell
powershell -File ops\verify.ps1                            # 工具/参数/安装健康
C:\Python314\python.exe ops\xref_baseline.py               # xref 离线基线（6 例）
C:\Python314\python.exe ops\xref_baseline.py --live        # 追加真机 fast/deep 对比
```

`verify` 覆盖：安装健康（`__file__` 非 None、dist/pyproject/PATCH 三处版本一致、包路径不在
site-packages，防 D13 那种"装一半"）、59 个工具、`toggle_breakpoint(on=)` 真的转成关闭、
`wait_for_event.drain_first` 默认 False、xref 三类 RIP 相对命中、`find_bytes` 不重复计重叠、
`pause()` 无 debuggee 返回 False。

`xref_baseline` 是**改 xref 实现前必须先跑绿**的基线：4 例现有快路径命中 + 2 例 0F 系
（快路径不命中、deep 必须命中）；`--live` 会在真调试器上对比 fast/deep 的命中差异与耗时。
