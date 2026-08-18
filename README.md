# DSH Plugin Guard

DeepSeek Harness 插件的安装前安全检查插件。默认离线、只读，不执行被扫描代码，不跟随符号链接，也不会把插件内容发送给大模型或第三方服务。

> 重要：静态扫描只能发现已知风险信号，不能证明插件安全。`REVIEWABLE` 的含义是“可以继续人工审查”，不是“绝对安全”。

## 能检查什么

- 提示词注入：覆盖系统/用户指令、隐藏行为、工具描述投毒、中英文隐蔽指令
- 文件勒索与破坏：递归删除、磁盘格式化、权限破坏、批量加密、赎金文本
- 凭据与数据外传：环境变量枚举、SSH/云凭据、浏览器数据、secret → network 组合链
- 供应链：安装生命周期脚本、下载即执行、未锁定依赖、编码载荷
- 动态执行与越权：`eval`、shell/subprocess、持久化、自修改、关闭 TLS 校验
- DSH 元数据：`package.json` 可解析性和 `dsh.bundle.patch` 激活声明
- Unicode 欺骗：零宽字符与双向控制字符

评分按“唯一规则 + 同规则递减贡献”计算，避免大型插件仅因重复匹配就轻易满分。只要出现关键级问题，或多类高危问题组合，结论会直接变为 `DO_NOT_INSTALL`。

## 安装到 DeepSeek Harness

在本目录生成 tarball，再加入一个单独的 Harness profile：

```bash
npm pack
dsh plugin --profile security add ./dsh-plugin-guard-0.1.0.tgz
dsh --profile security --dump-config
```

配置中应出现 `id: plugin-guard`。随后启动该 profile，模型会获得 `plugin_guard_scan` 工具。

Harness 仍处于 developer preview；本项目按 2026-08-18 可见的 `@deepseek-ai/dsh` RC 插件格式实现。升级 Harness 后应重新运行测试并核对 `dsh.bundle.patch`、Loader 和 `defineTool` 接口。

## 在 Harness 中使用

把待审插件先下载或解压到当前工作区，然后要求 Harness：

```text
使用 plugin_guard_scan 扫描 ./untrusted-plugin，先不要安装或运行它。
```

工具默认只允许扫描 Harness 当前工作目录。需要增加只读扫描根目录时，由用户在启动 Harness 前设置：

```bash
export DSH_PLUGIN_GUARD_ROOTS="/absolute/review/inbox:/another/allowed/root"
```

这个限制用于防止模型把扫描器当成任意文件读取工具。

## 独立命令行

不安装到 Harness 也能直接扫描：

```bash
node ./bin/dsh-plugin-guard.js /path/to/plugin
node ./bin/dsh-plugin-guard.js /path/to/plugin --json
```

退出码：`0` 可继续人工审查；`1` 谨慎；`2` 不要安装；`3` 扫描失败。

## 验证

```bash
npm test
npm run check
```

测试覆盖：干净插件、提示词注入与命令执行组合、凭据外传链、安装脚本、未锁定依赖、扫描根目录边界。

## 安全设计

- 零运行时扫描依赖；不需要 API key。
- 目标文件使用 `lstat`，符号链接直接跳过。
- 单文件、总字节数、文件数和 finding 数都有硬上限。
- 二进制文件不解析；被截断或预算耗尽时 `scanComplete=false`，结论至少为 `CAUTION`。
- 扫描证据限制长度，避免把大段恶意提示词重新注入模型上下文。
- 插件工具限制允许扫描的根目录；CLI 仅扫描用户明确给出的路径。

## 参考方法

规则分类借鉴 NVIDIA SkillSpector 的两阶段安全分析、OpenClaw/Hermes 社区的提示词与凭据防护实践，以及 Agent Skills 供应链研究。此实现刻意把第一版限定为确定性的本地静态扫描；未来可在隔离进程中增加 AST、依赖漏洞库和可选语义复核，但语义模型绝不能直接服从被扫描内容。

## 已知边界

- 不分析图片、加密文件、编译二进制或运行时下载后的真实行为。
- 正则规则可能误报，也可能被高级混淆绕过。
- 不联网查询 OSV/CVE；依赖漏洞需要另行使用可信的 SCA 工具检查。
- 不替代沙箱、最小权限、网络出口控制、人工代码审查和可恢复备份。

发现绕过方式或误报，请先阅读 [SECURITY.md](./SECURITY.md)。
