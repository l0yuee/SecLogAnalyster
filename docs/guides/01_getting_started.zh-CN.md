# 1. 快速上手

**语言：[English](01_getting_started.md) | 中文**

**[指南索引](../index.zh-CN.md)** -- 1. 快速上手 | [2. 日志类型与模式](02_log_types_and_schema.zh-CN.md) | [3. 查询与搜索](03_querying_and_search.zh-CN.md) | [4. 威胁狩猎](04_threat_hunting.zh-CN.md) | [5. 命令行参考](05_cli_reference.zh-CN.md) | [6. Python API](06_python_api.zh-CN.md) | [7. 常用查询](07_recipes.zh-CN.md) | [8. 性能与规模](08_performance_and_scale.zh-CN.md) | [9. 常见问题与已知限制](09_faq_and_limitations.zh-CN.md) | [10. 分布式部署](10_distributed_deployment.zh-CN.md)

---

## seclogx 是做什么的

取证采集获得的 Windows 事件日志（`.evtx`）文件很难直接分析：它是二进制格式，导出后是冗长的 XML，而且写入该日志的数百种提供程序（provider）字段极不统一。为了一次性的案例分析而把这些数据导入 ELK 之类的 SIEM，往往更糟——脆弱的索引映射（mapping）会在你毫无察觉的情况下丢弃你需要的字段。

seclogx 的目标就是让排查的最初几个小时变得高效：

- 指向一个或多个取证采集目录（它们不需要在同一个父目录下，也可以来自不同的主机）。
- 它会**通用地**解析每一个 `.evtx` 通道（channel）——Security、System、Application、Sysmon Operational、PowerShell Operational、WMI-Activity 等等——统一归一化为一张可查询的表。
- 同一次导入过程中，它还会发现并归一化：磁盘上的**计划任务**定义（一种持久化痕迹）、**IIS/nginx/Apache/Tomcat**
  的访问日志*以及*错误/诊断日志（Web 应用会产生的两大日志类别都覆盖，包括 IIS 的
  HTTP.sys/HTTPERR）、**Exchange** CSV 日志（邮件跟踪日志拥有一等列，其余 Exchange
  已识别的 CSV 日志类型将字段保留在通用表中）、**Linux** syslog（BSD/RFC-3164 与 RFC
  5424，含 `auth.log`/`secure` 的内容）、Linux 审计框架（auditd）与 systemd journal
  导出日志、**数据库**日志（MySQL/MariaDB 错误/通用查询/慢查询日志、PostgreSQL、
  MSSQL、Oracle 告警日志）、**腾讯云主机安全**客户端文本日志（YDService、HIDS/YDLive、
  漏洞/基线扫描器、YDFlame/YDUtils/YDQuaraV2、YDEyes），以及 **Windows 注册表**配置单元（SYSTEM/SOFTWARE/SAM/
  SECURITY/DEFAULT，以及每个用户的 NTUSER.DAT/UsrClass.dat）。EVTX 通过 `.evtx` 后缀发现；辅助来源候选文件通过有限大小的内容前缀分类，同时受后缀排除规则和部分格式的文件名/路径提示影响，因此重命名可能影响识别。完整的十二张表全貌见[《2. 日志类型与模式》](02_log_types_and_schema.zh-CN.md)。
- Python `Case` 对象提供 DataFrame 与分块迭代器，命令行提供预览和 CSV 导出，并内置基于 Sigma 规则的威胁狩猎能力，自动打上 MITRE
  ATT&CK 标签，覆盖 Windows 事件日志与 Web 访问日志两类数据。**同样不需要写 SQL**：
  `seclogx search` / `Case.search()` 可以用纯字段/取值条件——精确、模糊或正则匹配——过滤任意一张表。
- 核对报告会指出已发现文件中的部分恢复、解析失败与无法分类情况；不支持的规则也会报告。已知无关后缀和空的辅助文件会被过滤，无权访问的路径可能被跳过，因此它不是完整的采集清单。
- **大日志表支持分块访问。** 日志表访问器、SQL 查询、搜索与时间线都有流式替代方案；`search()` 会在取回结果前估算规模。普通 DataFrame 方法及派生分析仍可能耗尽内存，应逐块处理并释放结果，避免将所有分块再次聚合（见[《3. 查询与搜索》](03_querying_and_search.zh-CN.md)与[《8. 性能与规模》](08_performance_and_scale.zh-CN.md)）。

seclogx 默认面向单台工作站设计，不依赖外部服务。导入耗时及磁盘、内存需求取决于日志格式、记录宽度、并行度与存储性能；分块交付避免整体取回查询结果，但不能限制每个操作的内存。此外还提供一种可选启用、通过环境变量配置的分布式模式，适用于大批量导入、大规模
Sigma 规则集，或多名分析师需要共同使用同一个案例的场景——见[《10.
分布式部署》](10_distributed_deployment.zh-CN.md)；只要不主动开启，上述一切都不会有任何变化。

## 安装

主包已经包含 Rust 解析器：**一次正常安装就同时安装 Python API 和原生扩展**。
分析员不需要额外安装加速包，也不必在每次导入时选择性能模式。优先使用匹配平台的预编译
wheel；从源码安装时，再准备下文列出的构建工具。

### 安装预编译 wheel

打开目标版本对应的、成功完成的 [Product tests and wheels 工作流](https://github.com/l0yuee/SecLogAnalyster/actions/workflows/ci.yml)，
按平台下载并解压 `wheels-windows-x64`、`wheels-linux-x64`、`wheels-macos-arm64` 或
`wheels-macos-x64`。工作流产物可能需要登录 GitHub 才能下载，也有保存期限；所需产物不可用时，
按下文从源码安装。工作流产物与包索引或 GitHub Release 发布是不同的交付渠道。

在 `python314` 中按实际文件名安装解压后的 wheel。例如 Windows x64：

```console
conda activate python314
python -m pip install --only-binary=:all: ./seclogx-0.2.0-cp310-abi3-win_amd64.whl
python -m pip install jupyterlab ipykernel
python -m ipykernel install --user --name python314 --display-name "Python (python314)"
python -m jupyterlab
```

尚无环境时先执行 `conda create -n python314 python=3.14.2 pip`。匹配的 wheel 包含 Rust 扩展
和规则，**分析员无需安装 Rust、Cargo、maturin 或 C/C++ 编译器**。pip 自动安装运行依赖；
`--only-binary=:all:` 在依赖缺少 wheel 时明确报错，避免意外开始源码构建。Linux wheel 需要
glibc 2.28 及以上；操作系统和 CPU 架构必须匹配。仍可能需要 Windows Visual C++
Redistributable 等平台运行库，详见下文。

### 一次性准备机器环境

获取仓库需要 Git，项目环境使用已安装的 conda。Python 包要求 3.10 及以上版本；本项目
使用独立于 `base` 的 **`python314`** 环境，运行启用 GIL 的 CPython 3.14。

从源码安装时，需要 **stable Rust（包含 Cargo）**，以及对应平台的原生编译器和链接器：

| 平台 | 执行 `pip install` 前需要安装的工具 |
| --- | --- |
| Windows | 安装 Visual Studio Build Tools，选择 **“使用 C++ 的桌面开发 / Desktop development with C++”**，包含 MSVC x64/x86 工具和 Windows SDK。然后从 [Rust 官方安装页](https://rust-lang.org/tools/install/)运行 Windows 安装程序，使用 stable MSVC 工具链。详见[官方 MSVC 前置要求](https://rust-lang.github.io/rustup/installation/windows-msvc.html)。 |
| Ubuntu/Debian | 执行 `sudo apt-get update` 和 `sudo apt-get install build-essential curl`，再按 [rustup 官方说明](https://doc.rust-lang.org/book/ch01-01-installation.html)安装 stable Rust。其他 Linux 发行版安装对应的 GCC 或 Clang 及链接器包。 |
| macOS | 执行 `xcode-select --install` 安装 Apple 命令行编译工具，再按 [rustup 官方说明](https://doc.rust-lang.org/book/ch01-01-installation.html)安装 stable Rust。 |

Linux/macOS 的官方 rustup 安装命令如下：

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Cargo 随 Rust 安装，不需要单独安装。安装后重新打开终端，执行 `rustc --version`
和 `cargo --version` 检查。成功的源码构建需要可用的 Rust 与链接器。找不到 Cargo 时，
构建后端可能尝试获取临时 Rust 工具链；预先安装可避免依赖这一联网步骤。原生构建失败
不会静默安装为纯 Python 版本。

DuckDB、PyArrow、pandas、EVTX 和注册表等 Python 依赖由 pip 自动安装。能取得匹配的
依赖 wheel 时，**不需要单独安装 DuckDB 服务端、Arrow C++ 库或 EVTX 命令行工具**。
[PyArrow wheel 包含 Arrow/Parquet C++ 库](https://arrow.apache.org/docs/python/install.html)，
[DuckDB 在 Python 进程中运行](https://duckdb.org/docs/stable/clients/python/overview)。
如果所选 Python/平台没有匹配的依赖 wheel，依赖的源码构建可能另需工具；应选择有 wheel
支持的组合，或遵循相应依赖的源码构建说明。本地分析不需要 Redis、S3 服务或容器环境。

Windows 上导入依赖时若提示缺少 DLL，可能需要安装
[Visual C++ Redistributable](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist)。
它是运行库，与编译工具不同；[PyArrow 安装说明](https://arrow.apache.org/docs/python/install.html)
包含这一情形。

### 安装项目与 Notebook 环境

尚无仓库时，在终端中执行：

```bash
git clone https://github.com/l0yuee/SecLogAnalyster.git
cd SecLogAnalyster
```

尚无 `python314` 环境时，只需创建一次：`conda create -n python314 python=3.14.2 pip`。
已有该环境时直接复用。随后在仓库根目录执行：

```bash
conda activate python314
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install jupyterlab ipykernel
python -m ipykernel install --user --name python314 --display-name "Python (python314)"
seclogx version
seclogx --help
python -m jupyterlab
```

pip 会自动准备构建后端，并以 release 优化编译原生扩展，无需额外执行 maturin，
也无需执行 `pip install ./native`。首次源码构建会下载 Rust crate 和 Python 依赖，
可能需要一定时间。`pip install .` 同样会构建并安装扩展；在本仓库工作时，可编辑安装便于
使用最新源码。普通 wheel 已包含内置规则和参考数据；可编辑安装依赖仓库，应保留该目录。

在 Jupyter 中选择 **Python (python314)**，并在单元格中检查解释器：

```python
import sys
print(sys.executable)
```

从指定环境启动 JupyterLab，不会切换已运行内核。不能激活环境时，脚本使用
`conda run --no-capture-output -n python314 python ...`。只使用 CLI 时不需要安装
JupyterLab 或 ipykernel。

### 升级与部署已构建的 wheel

更新仓库后，在 `python314` 中重新执行 `python -m pip install -e .`，重建扩展，
并**重启已有 Jupyter 内核**。可编辑安装会反映 Python 源码修改，但 Rust 源码变更必须经过
这一步安装/构建才能生效。升级前先结束正在运行的导入任务。

部署维护者可以执行 `python -m pip wheel --no-deps . --wheel-dir dist`，构建匹配平台的 wheel。
安装这个已构建的 wheel 不会再次编译本项目的 Rust 代码，因此分析员机器不需要为 seclogx
本身安装 Rust 或 C/C++ 编译器；依赖 wheel 的可用性及平台运行库要求仍适用。
ABI 与平台边界见[原生组件构建说明](../../native/README.md)。

## 案例工作区（Case workspace）

**案例（Case）**默认位于 `./cases/<name>/`。案例管理命令用 `--dir`，导入和分析命令用
`--case-root` 指定根目录。

```text
cases/<name>/
  case.json                   # 原子提交目录、来源台账、导入历史
  .ingest/<transaction_id>/
    state.json                # 批次状态和进程身份
    report.json               # 逐来源处理结果
    s_evtx/                   # EVTX 临时分片
    s_aux/                    # 辅助来源临时分片；直接输出来源跳过此步骤
    lake/<table>/.../*.parquet # 不再改写的输出；提交前不可查询
    logs/                     # 批次核对日志
    workers/                  # 用于保护清理的活动 worker 身份
  .readers/                   # 保护已有查询快照的读取租约
  jobs/<job_id>.json          # 进度、进程身份和心跳
  jobs/<job_id>.log           # 后台标准输出/错误及报告
  hunts/<run>/               # 完整的狩猎命中结果及摘要
  lake/                      # 兼容旧版案例布局
```

各表保留原有 Hive 分区方式，详见[日志类型与 Schema](02_log_types_and_schema.zh-CN.md)。
配置 S3 后，Parquet 对象位于对象存储；元数据、暂存、读写进程协调和任务文件仍需要共享案例
目录，详见[分布式部署](10_distributed_deployment.zh-CN.md)。

导入先写入私有批次工作区，再通过一次原子目录替换同时发布 Parquet、来源台账和运行历史。
失败批次不会成为查询中的半份结果。来源状态为 `partial` 时，恢复出的数据仍可随批次提交；
应检查报告，区分恢复数据与完整来源。查询连接在建立时固定已提交快照；后台导入提交后，
重新打开已有 Case 才能看到新数据。

同一路径、主机、格式、EVTX 解码/原始 XML 设置及导入契约下，已提交且内容不变的来源在
重试时会跳过，并在 `already_imported` 中报告。不同主机分别保留。内容变化或来源身份变化
会作为新的导入处理；这不是逐行去重。失败批次重试会重新读取其来源，不从保存的字节偏移
续跑。不要手工删除已提交的 `.ingest` 目录；目录虽以点开头，仍可能保存当前查询所需的数据。

兼容的本地 Web/IIS 自动使用原生直接输出。其他输入先暂存再转换；支持的暂存路径在 `auto`
模式下，对至少 16 MiB 的来源选择 Arrow IPC/ZSTD，更小来源使用 gzip NDJSON。EVTX 也支持
Arrow 暂存，最终 Parquet 使用 ZSTD level 1。转换成功后默认删除临时分片，`keep_staging=True`
可以保留用于诊断；原始证据始终保留。保留暂存不提供按偏移续跑能力。

后台任务有独立心跳，以 PID 和进程创建时间识别进程。`c.cancel_job(job_id)` 停止本机所属进程
和 worker。`c.cleanup_ingest()` 清理无活动进程的未提交输出、安全退役的文件，以及超过七天的
已结束任务日志，保留状态与审计 JSON。下次导入也会清理无活动进程的未提交输出。即使协调
进程已经退出，存活的 worker 仍会阻止清理。跨主机任务必须在原启动主机上取消。

同一分区积累足够多的小 Parquet 后，提交成功的导入会自动触发合并。也可通过 `c.compact()`
或 `seclogx compact <case>` 提前请求维护。已有读取者继续使用旧快照，退役文件等读取租约
结束后才回收。目前不支持对 S3 存储执行合并。

### 复现产品测试

CI 使用 CPython 3.14.2，在 Windows x64、Linux x64 和 macOS arm64/x64 上执行同一套已提交
产品测试。运行依赖固定 DuckDB 1.5.5 和 EVTX 0.12.1，对应 SQL 隔离及恢复行为的验证版本；
共享约束文件固定其他验证依赖。准备好源码构建工具后执行：

```console
conda activate python314
python -m pip install -c constraints/python314.txt -e ".[dev,cluster]"
python -m pytest
```

精简合成夹具和运行时构造的故障用例与测试共同提交。[测试说明](../../tests/README.md)包含
收集范围与 wheel 验证方法；这些功能测试不代表大规模吞吐或内存表现。

## 快速上手示例

```bash
seclogx case init incident42
seclogx ingest incident42 --source /evidence/wks01:WKS01 --source /evidence/dc01:DC01
seclogx sources incident42
seclogx fields incident42 events
seclogx search incident42 events --contains Image=mimikatz --eq host=WKS01
seclogx hunt incident42
seclogx timeline incident42 --host WKS01 --event-id 4624 --out logons.csv
```

接下来可以看：

- **[2. 日志类型与模式](02_log_types_and_schema.zh-CN.md)** -- 十二张表各自存放什么，该看什么。
- **[3. 查询与搜索](03_querying_and_search.zh-CN.md)** -- SQL、免 SQL 的 `search()` 接口，以及有界内存交付。
- **[4. 威胁狩猎](04_threat_hunting.zh-CN.md)** -- Sigma 规则与 ATT&CK 标签。
- **[5. 命令行参考](05_cli_reference.zh-CN.md)** / **[6. Python API](06_python_api.zh-CN.md)** -- 完整的命令/方法参考。
- **[7. 常用查询](07_recipes.zh-CN.md)** -- 可直接复制使用的起点。

## 许可证与规则来源

seclogx 自身代码采用 MIT 许可证（见 `LICENSE`）。内置于
`data/sigma_rules/` 下的 Sigma 规则均未经修改地复制自
[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)，采用 Detection Rule License 1.1
授权（见 `data/sigma_rules/LICENSE-DRL-1.1.txt`）；每条规则确切的上游来源与提交（commit）记录在
`data/sigma_rules/SOURCES.md` 中，且每一条匹配结果都会展示原始规则的作者信息。完整许可证文本见仓库根目录的
`README.md`。
