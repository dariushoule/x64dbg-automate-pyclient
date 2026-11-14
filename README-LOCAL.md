# x64dbg-automate 本地 fork（local.3）

不是重写，是把原先住在 `site-packages` 里的猴补丁**上抬成源码**，再用可编辑安装挂回运行时。
来源：`github.com/dariushoule/x64dbg-automate-pyclient` @ `v0.9.2-ghost_fungus` + 本地分支 `local.3`。

## 为什么

原 `mcp_server_local.py`（0.9.2+local.p2）靠运行时替换 `base._parse_address_or_expression`、
`X64DbgClient.pause` 生效，且物理位置在 `C:\Python314\Lib\site-packages\x64dbg_automate\` ——
`pip install --upgrade` 一次全丢。且 p1 补丁直接改在 `mcp_server.py` 里，重装后只剩 p2，
`run_python` 消失但 local 层照常加载，状态会分叉。

## 装了什么

```
D:\od\x64dbg-automate-fork\      <- 本目录（git 分支 local.3）
  x64dbg_automate\
    mcp_server.py        上游 + p1(run_python) + A1 别名 + A2 drain_first + 地址解析修复
    hla_xauto.py         pause() 源码级阻塞态兜底（连发两次，2.25s 门限）
    commands_xauto.py    上游 + p1(execute_command 便捷方法)
    local_ext.py         10 个本地工具（原 p2 的 9 个 + local_patch_info）
    mcp_server_local.py  薄入口：注册 local_ext 后 mcp.run()
  ops\                   回滚 / 升级 / 验证 脚本
```

安装方式：`pip install -e . --no-build-isolation --no-deps`（setuptools 后端，不联网）。
包版本：`0.9.2+local.3`。

## 现场确认补丁是否加载

MCP 工具 `local_patch_info` 会返回 patch 版本、包路径、本地工具清单。或：

```bash
C:\Python314\python.exe -c "import x64dbg_automate as m; print(m.__file__)"
# 必须是 D:\od\x64dbg-automate-fork\x64dbg_automate\__init__.py
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
冲突集中在 `mcp_server.py`（`toggle_breakpoint` / `wait_for_event` / `_parse_address_or_expression`）
和 `hla_xauto.py`（`pause`），`local_ext.py` 一般是新增文件不冲突。

## 验证

```powershell
powershell -File ops\verify.ps1
```

覆盖：59 个工具、`toggle_breakpoint(on=)` 真的转成关闭、`wait_for_event.drain_first` 在 schema 里、
xref 三类 RIP 相对指令（lea / call [rip] / mov [rip],imm）全部命中、算式地址解析。
