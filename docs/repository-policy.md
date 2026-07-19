# 仓库策略门禁

仓库提供一个零第三方依赖的策略脚本，用于 AC-39 配置安全和 AC-40 工程隔离的自动化取证。脚本扫描当前已跟踪、待提交和未跟踪但未被 Git 忽略的文件；本地 `.env` 等已忽略文件不属于“可提交文件”集合。

## 秘密扫描

```bash
python3 scripts/repository_policy.py secrets
```

该检查覆盖常见云平台与代码托管 Token、Bearer/JWT、带凭据 URL、私钥材料、证书/密钥文件，以及配置文件中的密码、Token、Pepper、私钥等字面量。环境变量引用、空值及明确的示例占位值不会被当作真实秘密，因此 `.env.example` 可以保留可识别的占位说明。

GitHub Actions 会运行脚本单元测试和此秘密扫描；命中时只输出规则、文件和行号，不输出秘密原文。

## 禁止业务词扫描

禁止词本身不得进入仓库。验收时必须通过以下两种方式之一从仓库外注入，每行一个词：

```bash
WEB_STARTER_FORBIDDEN_TERMS_FILE=/absolute/path/outside/repository/terms.txt \
  python3 scripts/repository_policy.py forbidden
```

或者由执行环境直接注入多行内容：

```bash
WEB_STARTER_FORBIDDEN_TERMS="${EXTERNAL_FORBIDDEN_TERMS}" \
  python3 scripts/repository_policy.py forbidden
```

外部文件若位于仓库内会被拒绝；脚本不会在输出中回显词条。没有注入任何词条时，结果明确为 `SKIP` 且退出码为 `2`，不能作为 AC-40 通过证据。注入词条且全仓零命中时才返回 `PASS` 和退出码 `0`；发现命中时返回 `FAIL` 和退出码 `1`。

普通名称和短语采用不区分大小写的子串匹配；2–5 位全大写字母数字缩写按独立单词匹配，避免误伤通用标识符内部的偶然字符组合。

可以一次执行两项检查：

```bash
python3 scripts/repository_policy.py all
```

`all` 模式中任一失败即退出 `1`，业务词缺少外部输入则退出 `2`。

## 结果边界

- `PASS (0)`：本次扫描覆盖的文件零命中。
- `FAIL (1)`：发现策略违规，不能继续发布。
- `SKIP (2)`：缺少外部输入或配置错误，不等于通过。

该脚本是工作树和当前提交的启发式门禁，不扫描 Git 历史，也不替代凭据轮换、历史清理或专用秘密管理系统。二进制内容不做文本解析，但常见证书、密钥和凭据文件会按文件名或扩展名直接阻断。
