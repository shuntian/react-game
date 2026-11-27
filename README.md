<h1>react-game项目<h1>
1、依据官网game项目开发向导，完成game项目的开发<br>
2、掌握react基本开发流程<br>
3、学习create-react-app的使用<br>

## 独立代码扫描

在 GitHub Actions 中打开 **Independent Code Scan**。工作流在推送到 `master`、PR
目标为 `master`、每周一 11:00（北京时间）时运行，也可手动触发。统计见运行摘要，
明细见 `independent-code-scan` 产物中的 `report.md` 和 `findings.json`。

Semgrep CE 使用仓库规则检查 `src/`，Gitleaks 检查当前 `HEAD` 可达的 Git 历史，
npm audit 根据锁文件向 npm 公共注册表查询依赖告警。High / Critical（包含历史命中）
会使检查失败。扫描器异常会单独标记，并保留其他检查的结果。

本地需要 Python 3.10+、Node 24/npm、Semgrep 1.156.0 和 Gitleaks 8.30.0。
在仓库根目录运行：

```bash
python3 scripts/code-scan/scan.py --output-dir "$(mktemp -d)"
```

退出码 `0` 表示完成且未触及门槛，`1` 表示发现 High / Critical，`2` 表示检查未完成。
