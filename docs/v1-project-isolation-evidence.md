# V1 AC-40 工程隔离证据

V1 AC-40 与 V2-AC-40 恢复演练是两个不同的验收项。本证据链只处理 V1 的工程隔离：当前候选不得包含受保护业务词或复制来的业务模块，并且只读参考仓库在验证期间不得发生变化。

## 放行条件

`scripts/validate_v1_project_isolation_evidence.py` 在同一次调用中独立重算：

1. 候选是 clean、非 `SNAPSHOT`、带注释 tag 的精确 Git commit，索引没有 `skip-worktree` 或 `assume-unchanged`；
2. 顶层 tracked inventory、根 Maven 模块顺序、模块 artifact/source 边界、前端 package 名和全部 Java `dev.webstarter` 包路径符合固定通用脚手架结构；
3. 仓库外 `0600` 禁用词文件至少包含一个有效词，候选全部 tracked 文件名和文本零命中；
4. 外部参考仓库的 HEAD、status、worktree diff、index diff 和未跟踪内容集合在验证前后具有完全相同的哈希指纹；
5. 所有候选源码字节仍与注释 tag 指向的 commit 一致。

任一输入缺失、候选漂移、禁用词命中、参考仓库变化、摘要被替换或文件权限过宽都会失败。公开摘要只保存禁用词文件哈希、词数、文件计数、候选源码聚合哈希和参考仓库聚合指纹；不保存词条、参考仓库路径、文件名或内容。

## 本地独立验证

以下命令只允许针对独立 clean 候选和明确指定的只读参考仓库运行。禁用词文件必须位于两个仓库之外且权限为 `0600`：

```bash
python3 -B scripts/validate_v1_project_isolation_evidence.py \
  --repository-root /absolute/clean/candidate \
  --forbidden-terms /absolute/private/forbidden-terms.txt \
  --reference-repository /absolute/read-only/reference-repository \
  --expected-candidate-commit <full-commit> \
  --expected-candidate-tag v2.0.0 \
  --expected-candidate-version 2.0.0 \
  --summary-output /absolute/artifacts/acceptance/v1-ac40-project-isolation-summary.json
```

正式门禁的 `build` 必须同时接收：

```text
--v1-project-isolation-forbidden-terms <private-file>
--v1-project-isolation-reference-repository <reference-git-root>
--v1-project-isolation-summary-artifact artifacts/acceptance/v1-ac40-project-isolation-summary.json
```

`verify` 必须重新提供前两个外部输入；门禁再次现场计算并与 manifest 中绑定的摘要逐字节比较。

## GitHub 发布配置

`release` Environment 必须配置以下受保护输入：

- Variable `WEB_STARTER_REFERENCE_REPOSITORY`：`owner/repository`；
- Variable `WEB_STARTER_REFERENCE_REPOSITORY_COMMIT`：固定的 40 位 commit；
- Secret `WEB_STARTER_FORBIDDEN_TERMS`：逐行维护禁用词。

参考仓库必须是公开 GitHub 仓库，且不得与当前发布仓库同名（大小写不敏感）。发布工作流用匿名 REST 请求核对 public 可见性，然后在隔离 Git 配置且禁用凭据提示的环境中，通过匿名 HTTPS 只拉取受保护 Variable 指定的 40 位 commit。此过程不要求或传入 PAT、GitHub App Token 或 `github.token`。参考仓库仍检出到独立嵌套目录，并拒绝 Git link、dirty checkout 和 commit 漂移。候选验证仍在 `${RUNNER_TEMP}` 的 detached worktree 中进行，因此参考仓库不会进入候选源码、镜像构建上下文或发布 Artifact。

该证据证明所绑定候选和本次验证期间的工程隔离，不证明参考仓库本身的业务正确性，也不替代历史 V1 验收记录、浏览器验收、运行时验收或 V2 恢复演练。
