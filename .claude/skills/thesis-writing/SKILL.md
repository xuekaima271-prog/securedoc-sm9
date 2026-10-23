---
name: thesis-writing
description: 新疆科技学院本科毕业论文（设计）写作与排版技能（2026版撰写规范）。凡涉及毕业论文/毕设论文的任何任务都必须使用本技能：撰写、修改、扩写、润色章节或摘要，降重改写、消除 AI 痕迹（AIGC 率）、全文审查与一致性检查，增删图表公式参考文献，检查格式/字数/文献数是否合规，以及把 thesis/ 目录的 Markdown 草稿生成符合学校规范的 Word（.docx）成品或 PDF。即使用户只说"改一下第3章""摘要再精炼些""导出论文""论文格式对不对""查重能过吗""太像AI写的了"，也应使用本技能。
---

# 新疆科技学院毕业论文写作技能

把"分章 Markdown 草稿 → 学校规范 Word 成品"全流程工具化。规范硬性数字（字号/边距/页眉页码/图表公式/GB-T 7714 文献格式）已固化进构建脚本，写作时只需遵守 Markdown 约定。

## 本项目现状（应用对象）

- 论文源文件在 `thesis/`：`01_摘要.md`、`02_第1章_绪论.md` … `10_致谢.md`；总控与素材（实测数据、创新点清单）在 `thesis/00_大纲与格式要求.md`。
- 题目/理工类要求：正文 ≥1 万字、参考文献 ≥13 篇（外文 ≥3）、摘要 300~500 字、关键词 3~5 个。
- 当前基线（2026-xx 实测）：正文 13087 字、文献 17 篇（外文 5）、摘要 406 字、6 章。

## 脚本路径

**本技能装在本项目内，用相对路径调用**（历史文档里写的 `.Codex/skills/...` 是失效路径，不要用）：

```bash
python .claude/skills/thesis-writing/scripts/check_thesis.py --src thesis
python .claude/skills/thesis-writing/scripts/style_check.py  --src thesis
python .claude/skills/thesis-writing/scripts/build_thesis.py --src thesis
```

## 五类任务的入口

### ① 写作 / 修改内容
先读 `references/writing-guide.md`（Markdown 语法约定 + 各章章法 + 学术文风清单），再动笔。
关键约定速记：`>` 行是作者备注不进成品；表题在表前一行 `表 2.1 xxx`；图 `![图 4.1 xxx](路径)`；公式 `$$...\tag{2.1}$$`；正文引用文献写 `[n]`。
改完内容随手跑一次合规检查（见②），避免破坏编号链。

### ② 合规检查（定量体检，硬指标）
```
python .claude/skills/thesis-writing/scripts/check_thesis.py --src thesis
```
输出 PASS/WARN/FAIL 清单：字数、摘要字数、关键词数、文献总数与外文数、序号连续性、标题层级与字数、图表编号与"先文后图"引用、公式编号、正文 [n] 与文献表对应。FAIL 必须处理；WARN 逐条判断。**有 FAIL 时退出码为 1。**

### ③ 文风体检 + 降重 / 去 AI 味
```
python .claude/skills/thesis-writing/scripts/style_check.py --src thesis
```
查 10 类：套话、空泛表述、被动语态、并列结构工整度、段落节律、句长、自称与口语词、术语一致、中英混排、**跨章重复片段**（查重线索）。
要动手改写时读 `references/paraphrase-and-humanize.md`（五级降重策略 + AI 痕迹 8 特征 + **文风基线表**，改写后指标不能漂移）。

### ④ 全文审查 / 一致性检查
读 `references/review-checklist.md`：四轮审查（逻辑链闭环 → 逐章专项 → 一致性 → 格式）+ 分级报告格式（🔴必须改 / 🟡建议改 / 🟢锦上添花）。
用于"通读一遍看有没有问题""答辩前帮我过一遍"这类需求。

### ⑤ 生成 Word / PDF 成品
```
python .claude/skills/thesis-writing/scripts/build_thesis.py --src thesis --refresh-toc
python .claude/skills/thesis-writing/scripts/build_thesis.py --src thesis --pdf   # 同时出 PDF
```
- 封面信息读 `thesis/thesis.json`（缺项会自动提示；`doc_type` 取"论文"或"设计"，决定偶数页页眉措辞）。
- 自动完成：封面（校名 logo）、写作声明扉页、中英摘要、目录域、每章另起一页、奇偶页眉、目录罗马页码/正文阿拉伯页码、三线表、图题下/表题上、LaTeX→Word 原生公式、参考文献五号悬挂。
- `--refresh-toc`/`--pdf` 需本机安装 Word（用 COM 更新目录页码域）；不加此参数则 Word 首次打开时会提示更新域。
- 公式转换依赖 Word 自带 MML2OMML.XSL 与 pip 包 latex2mathml；缺失时公式退化为斜体文本并打印警告。

## 格式问题的权威依据

回答"某处格式该怎样"时查 `references/format-spec.md`（2026 版规范全量提炼：页面、字体、标题层级、图表公式、文献著录、装订顺序）。不确定时以该文件为准，不要凭记忆答。
`assets/school-template.docx` 是学校官方模板转档（`school-template-annotated.docx` 带填写说明），可用 python-docx 打开对照；注意：旧模板奇偶页眉与 2026 规范相反，以规范为准。

## 交付前顺序

1. `check_thesis.py` 全绿（或 WARN 均有解释）
2. `style_check.py` 无 FAIL，指标与文风基线不漂移
3. `build_thesis.py --pdf` 生成成品
4. 人工抽查：封面信息、目录页码、任一章页眉、一张三线表、一处公式
5. 提醒用户：扉页签名须黑色签字笔手写；封面缺项（学院/班级/学号）在 `thesis.json` 补齐后重新构建

## 本技能的红线

- **数据不改**：`00_大纲与格式要求.md` §四 的实测数字是答辩证据，任何改写都不得改动、删减或"约等于化"。
- **造假不做**：不编造文献、实验数据、调试经历。查重压力下最容易出这种事，一旦被发现不可挽回。
- **不越界声明**：本文只完成算法示例与工程测试，不宣称通过商用密码认证或密评——这条限定散见于摘要/摘要/3.2/3.4/结论，改稿时不要删。
- **两份副本同步**：技能同时存在于 `.agents/skills/thesis-writing/` 和 `.claude/skills/thesis-writing/`（Claude Code 视角）。改完任一份，把改动同步到另一份，否则两套规则会打架。
