# -*- coding: utf-8 -*-
"""新疆科技学院毕业论文（2026版规范）合规检查 —— 对 Markdown 草稿做定量体检。

用法：python check_thesis.py [--src thesis]

检查项（依据撰写规范硬性要求）：
  1. 正文字数（中文字符）：理工类 >= 10000
  2. 中文摘要 300~500 字；关键词 3~5 个
  3. 参考文献 >= 13 条，其中外文 >= 3 条；序号连续
  4. 正文引用 [n] 与文献表对应；未被引用的文献给出提醒
  5. 标题：编号连续、层次 <= 4 级、章节标题 <= 15 字且无标点
  6. 图/表：按章连续编号、表题在表上（图题由构建脚本保证在图下）、正文有"如图x.y/见表x.y"式引用
  7. 公式 \\tag 编号按章连续
输出 PASS / WARN / FAIL 清单，存在 FAIL 时退出码为 1。
"""
import argparse
import re
import sys
from pathlib import Path

CJK_RE = re.compile(r"[一-鿿]")
results = []


def report(level, item, detail):
    results.append((level, item, detail))


def strip_notes(text):
    """去掉作者备注（> 引用行）与代码块，只留论文正文。"""
    out, in_code = [], False
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith("```"):
            in_code = not in_code
            continue
        if in_code or s.startswith(">"):
            continue
        out.append(ln)
    return "\n".join(out)


def cjk_count(text):
    return len(CJK_RE.findall(text))


def check_abstract(text):
    body = strip_notes(text)
    m = re.search(r"##\s*摘要\s*\n(.*?)(?=\n##|\Z)", body, re.S)
    cn = m.group(1) if m else ""
    kw_m = re.search(r"关键词\*?\*?\s*[:：]\s*(.+)", cn)
    cn_wo_kw = re.sub(r".*关键词.*", "", cn)
    n = cjk_count(cn_wo_kw)
    if 300 <= n <= 500:
        report("PASS", "中文摘要字数", f"{n} 字（要求 300~500）")
    else:
        report("FAIL" if n < 280 or n > 550 else "WARN", "中文摘要字数", f"{n} 字（要求 300~500）")
    if kw_m:
        kws = [k for k in re.split(r"[;；]", kw_m.group(1).strip()) if k.strip()]
        lvl = "PASS" if 3 <= len(kws) <= 5 else "FAIL"
        report(lvl, "关键词个数", f"{len(kws)} 个（要求 3~5）: {'；'.join(k.strip() for k in kws)}")
    else:
        report("FAIL", "关键词", "未找到『关键词：』行")
    if not re.search(r"##\s*Abstract", body, re.I):
        report("FAIL", "英文摘要", "未找到 Abstract 部分")
    elif not re.search(r"key\s*words?\s*\*?\*?\s*[:：]", body, re.I):
        report("FAIL", "英文关键词", "未找到 Keywords 行")
    else:
        report("PASS", "英文摘要", "存在，且含 Keywords")


def check_references(text):
    body = strip_notes(text)
    entries = re.findall(r"^\[(\d+)\]\s*(.+)$", body, re.M)
    nums = [int(n) for n, _ in entries]
    if nums != list(range(1, len(nums) + 1)):
        report("FAIL", "参考文献序号", f"序号不连续: {nums}")
    total = len(entries)
    foreign = 0
    for _, e in entries:
        letters = len(re.findall(r"[A-Za-z]", e))
        if letters > 0.6 * max(len(e), 1):
            foreign += 1
    report("PASS" if total >= 13 else "FAIL", "参考文献总数", f"{total} 条（要求 ≥13）")
    report("PASS" if foreign >= 3 else "FAIL", "外文文献数", f"{foreign} 条（要求 ≥3）")
    starred = body.count("★")
    if starred:
        report("WARN", "待核实文献", f"{starred} 条带 ★ 标记，定稿前需逐条核对")
    return set(nums)


def check_headings(chapters):
    bad_title = []
    seq_issue = []
    prev_ch = 0
    for text in chapters:
        body = strip_notes(text)
        for m in re.finditer(r"^(#{1,6})\s+(.+)$", body, re.M):
            level, title = len(m.group(1)), m.group(2).strip()
            if level > 4:
                seq_issue.append(f"标题层次超过4级: {title}")
            num_m = re.match(r"^(\d+(?:\.\d+)*)\s+(.*)$", title)
            if level == 1 and num_m:
                ch = int(num_m.group(1).split(".")[0])
                if ch != prev_ch + 1:
                    seq_issue.append(f"章号不连续: 第{prev_ch}章后出现『{title}』")
                prev_ch = ch
            if num_m:
                name = num_m.group(2)
                if len(name) > 15:
                    bad_title.append(f"标题超15字: {title}")
                if re.search(r"[，。；：、！？,.;:!?]", name):
                    bad_title.append(f"标题含标点: {title}")
                depth = num_m.group(1).count(".") + 1
                if depth != level:
                    seq_issue.append(f"编号层级与#号不符: {'#'*level} {title}")
    for msg in seq_issue:
        report("FAIL", "标题结构", msg)
    for msg in bad_title:
        report("WARN", "标题文字", msg)
    if not seq_issue and not bad_title:
        report("PASS", "标题结构", f"共 {prev_ch} 章，编号连续、层次合规、标题文字合规")


def check_figures_tables(chapters):
    problems = []
    n_fig = n_tbl = 0
    for text in chapters:
        body = strip_notes(text)
        ch_m = re.search(r"^#\s+(\d+)\s", body, re.M)
        ch = int(ch_m.group(1)) if ch_m else 0
        for kind, pattern in (("图", r"图\s*(\d+)\.(\d+)"), ("表", r"表\s*(\d+)\.(\d+)")):
            caps = []
            if kind == "表":
                caps = [(int(a), int(b)) for a, b in re.findall(r"^表\s*(\d+)\.(\d+)", body, re.M)]
            else:
                caps = [(int(a), int(b)) for a, b in
                        re.findall(r"!\[图\s*(\d+)\.(\d+)", body)]
            if kind == "图":
                n_fig += len(caps)
            else:
                n_tbl += len(caps)
            for i, (c, s) in enumerate(caps, 1):
                if ch and c != ch:
                    problems.append(f"{kind}{c}.{s} 出现在第{ch}章，章号不符")
                if s != i:
                    problems.append(f"第{ch}章 {kind}编号不连续: {kind}{c}.{s}（期望 {kind}{ch}.{i}）")
            # 正文引用检查：图x.y / 表x.y 在叙述中出现
            for c, s in caps:
                ref_pat = rf"(如|见|由|如下|所示|中)[^\n]*{kind}\s*{c}\.{s}|{kind}\s*{c}\.{s}\s*(所示|给出|列出|可见)"
                mentions = len(re.findall(rf"{kind}\s*{c}\.{s}", body))
                if mentions < 2:  # 只有图题/表题自身出现一次
                    problems.append(f"{kind}{c}.{s} 在正文叙述中未被引用（规范要求先文后图/表）")
    for msg in problems:
        report("WARN", "图表", msg)
    if n_fig == 0:
        report("WARN", "插图", "全文没有一幅插图（![图 x.y 题名](路径)）；架构图/流程图/时序图是答辩硬通货，建议补充")
    if not problems:
        report("PASS", "图表", f"图 {n_fig} 幅、表 {n_tbl} 个，编号与正文引用合规")


def check_equations(chapters):
    problems = []
    for text in chapters:
        body = strip_notes(text)
        ch_m = re.search(r"^#\s+(\d+)\s", body, re.M)
        ch = int(ch_m.group(1)) if ch_m else 0
        tags = [(int(a), int(b)) for a, b in re.findall(r"\\tag\{(\d+)\.(\d+)\}", body)]
        for i, (c, s) in enumerate(tags, 1):
            if ch and c != ch:
                problems.append(f"公式({c}.{s}) 出现在第{ch}章，章号不符")
            if s != i:
                problems.append(f"第{ch}章公式编号不连续: ({c}.{s})（期望 ({ch}.{i})）")
    for msg in problems:
        report("WARN", "公式编号", msg)
    if not problems:
        report("PASS", "公式编号", "按章连续")


def check_citations(chapters, ref_nums):
    cited = set()
    for text in chapters:
        body = strip_notes(text)
        body = re.sub(r"^\s*\|.*$", "", body, flags=re.M)  # 排除表格行
        for m in re.finditer(r"\[(\d+(?:[-,，]\d+)*)\]", body):
            for part in re.split(r"[,，]", m.group(1)):
                if "-" in part:
                    a, b = part.split("-")
                    cited.update(range(int(a), int(b) + 1))
                else:
                    cited.add(int(part))
    if not ref_nums:
        return
    dangling = sorted(c for c in cited if c not in ref_nums)
    uncited = sorted(r for r in ref_nums if r not in cited)
    if dangling:
        report("FAIL", "文献引用", f"正文引用了不存在的文献: {dangling}")
    if uncited:
        report("WARN", "文献引用", f"文献表中未被正文引用: {uncited}（规范：只列直接引用的文献；请在正文补 [n] 或删条目）")
    if not dangling and not uncited:
        report("PASS", "文献引用", f"正文共引用 {len(cited)} 条，与文献表一一对应")
    elif cited:
        report("PASS", "文献引用覆盖", f"正文已标注 {len(cited)} 条: {sorted(cited)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default="thesis")
    args = ap.parse_args()
    src = Path(args.src)

    chapters, conclusion, abstract, refs, ack = [], None, None, None, None
    for md in sorted(src.glob("[0-9][0-9]_*.md")):
        if md.name.startswith("00"):
            continue
        text = md.read_text(encoding="utf-8")
        first_h = next((l.lstrip("#").strip() for l in text.splitlines()
                        if l.strip().startswith("#")), "")
        if first_h.startswith("摘要"):
            abstract = text
        elif first_h.startswith("参考文献"):
            refs = text
        elif first_h.startswith("致谢"):
            ack = text
        elif first_h.startswith("结论"):
            conclusion = text
        elif re.match(r"^\d+\s", first_h):
            chapters.append(text)

    # 1. 字数
    body_texts = chapters + ([conclusion] if conclusion else [])
    total = sum(cjk_count(strip_notes(t)) for t in body_texts)
    report("PASS" if total >= 10000 else "FAIL", "正文字数",
           f"{total} 中文字符（理工类要求 ≥10000，含结论、不含摘要/文献/致谢）")

    if abstract:
        check_abstract(abstract)
    else:
        report("FAIL", "摘要", "未找到摘要文件")
    ref_nums = check_references(refs) if refs else set()
    if not refs:
        report("FAIL", "参考文献", "未找到参考文献文件")
    if not ack:
        report("WARN", "致谢", "未找到致谢文件")
    check_headings(chapters)
    check_figures_tables(chapters)
    check_equations(chapters)
    check_citations(body_texts, ref_nums)

    print("=" * 72)
    order = {"FAIL": 0, "WARN": 1, "PASS": 2}
    n = {"FAIL": 0, "WARN": 0, "PASS": 0}
    for level, item, detail in sorted(results, key=lambda x: order[x[0]]):
        n[level] += 1
        mark = {"PASS": "[PASS]", "WARN": "[WARN]", "FAIL": "[FAIL]"}[level]
        print(f"{mark} {item}: {detail}")
    print("=" * 72)
    print(f"合计: {n['PASS']} 通过 / {n['WARN']} 提醒 / {n['FAIL']} 不合规")
    sys.exit(1 if n["FAIL"] else 0)


if __name__ == "__main__":
    main()
