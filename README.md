# CTF-Agent-CTFy

这是 CTF-Agent-Windows 的独立 CTFy 容器适配项目。它不修改、不覆盖 Windows 桌面交付目录。

## 当前支持

- `qa`：结合 Agent 内置知识库回答题目。
- `instance`：使用 CTFy MCP 工具获取题目信息/靶场，再调用现有附件分析器；只把证据支持的答案写入结果。
- `defence`、`awd`、`engagement`：尚未实现，会返回明确的 `unsupported_run_mode`。
- 不包含 Windows 本地模型；CTFy 运行时必须在平台中配置可用的模型提供商和额度/密钥。密钥由平台注入容器，不要写进镜像或本项目文件。
- `v2-skills`：内置 `solve-challenge` 和 10 套 `ctf-*` Skills 及参考文件，安装在容器 `/skills/`；现有技能发现、检索和分页读取接口可直接读取。

## Skills 镜像更新

已将本机 CTF Skills 复制到 `src/skills/`。`skills-manifest.json` 记录技能名称、102 个参考文件和 SHA-256；补全了 `ctf-web` 上游文档中被引用但本机安装缺失的 `server-side-exec.md`。

在本机已有原 `v1` 镜像时，执行以下命令叠加 Skills：

```powershell
docker build --pull=false -f Dockerfile.skills -t ctf-agent-ctfy:v2-skills -t registry.ctfy.io/687ab0c2-68a7-4474-8198-9d76d2b9f123/ctf-agent:v2-skills .
```

全量构建使用下面的 `Dockerfile`，同样会把 `src/skills/` 加入镜像。新镜像推送后，在 CTFy 填写 `v2-skills` 镜像引用并重新提交审核；原 `v1` 不会自动更新。

## 构建镜像

在本目录运行：

```powershell
docker build -t <镜像仓库>/<命名空间>/ctf-agent-ctfy:1.0 .
docker push <镜像仓库>/<命名空间>/ctf-agent-ctfy:1.0
```

然后在 CTFy Agent 页面填写推送后的镜像地址，并在平台设置模型提供商、模型 ID 和密钥/额度。镜像按 CTFY-0001 schema v2 启动，从 `$CTFY_WORK_DIR` 读取 `task.json`、`README.md`，并原子写入 `result.json`。`CTFY_EVAL_DRY_RUN=1` 时只写入 dry-run 结果，不请求模型。

## 本地快速构建

需要已安装并启动 Docker Desktop。可先执行：

```powershell
docker build -t ctf-agent-ctfy:local .
```

## 推送到 CTFy 仓库

构建完成后运行 `powershell -ExecutionPolicy Bypass -File .\push-ctfy.ps1`。脚本会隐藏输入 CTFy token，推送到本项目配置的专属仓库地址，然后自动登出。

本地直接运行需要提供符合 CTFy 格式的工作目录及平台运行时环境变量；一般通过 CTFy 平台评测/运行，不需要手动拼装这些变量。

## 项目内容

- `ctfy_entrypoint.py`：CTFy v2 输入/结果适配和运行模式路由。
- `src/agent/`：Agent Python 分析器及其知识库索引。
- `src/runtime/pi/`：Pi Agent Core 运行器，容器内通过 npm 安装 Linux 依赖。
- `src/skills/`：11 套 CTF Skills，含密码学、逆向、Web、杂项、取证、PWN、AI/ML、恶意样本、OSINT 和解题记录方法。
- `knowledge-base/`：随镜像携带的知识库。
- `knowledge-base/公众号文章writeup/`：随镜像携带并与索引匹配的 299 篇 PDF。
- `Dockerfile`：构建 Linux 容器镜像。

提示：当前适配没有接入动态 GDB、angr、pwntools，也不会执行上传的二进制文件；逆向/PWN 动态题和需要这些工具的题目可能无法完成。

