# -*- coding: utf-8 -*-
"""毕业论文文风体检 —— 查 AI 痕迹、术语一致性、口语化与冗长句。

与 check_thesis.py 的分工：
  check_thesis.py  管"合规"（字数/文献/编号链），有 FAIL 就是硬伤，必须修
  style_check.py   管"文风"（AI 味/一致性/可读性），FAIL 是硬伤，WARN 需逐条判断

用法：
  python style_check.py [--src thesis] [--min-dup 12] [--top 12]

检查项：
  A 套话与连接词    "综上所述""值得注意的是"等高频模板词（AI 特征 1、2）
  B 空泛表述        "有效""良好""进一步"等无信息量修饰（AI 特征 4）
  C 被动语态        "被…"密度（AI 特征 5，中文学术写作应低于英文）
  D 并列结构        连续 （1）（2）（3） 块的长度工整度（AI 特征 3）
  E 段落节律        段落长度分布；过于均匀 = 机器感（AI 特征 6）
  F 句长            >60 字长句与句长标准差（可读性）
  G 自称一致        "本文/本系统"分布，第一人称红线
  H 术语一致        同一概念的多种写法（内置本项目对照表 + 自动孤立变体）
  I 中英混排        汉字与西文之间的空格是否统一（排除图表编号等规范格式）
  J 重复片段        跨章重复的 n 字串，查重前自查雷同（降重线索）

输出 PASS / WARN / FAIL，存在 FAIL 时退出码为 1。
"""
import argparse
import re
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

# ---------------------------------------------------------------- 常量表

# A 类：模板化套话（AI 最爱，全文应少用甚至不用）
CLICHES = [
    "综上所述", "总而言之", "总之", "值得注意的是", "需要指出的是", "不难看出",
    "不言而喻", "众所周知", "显而易见", "毋庸置疑", "换言之", "由此可见",
    "首先", "其次", "最后", "一方面", "另一方面",
]
# 套话容忍上限（全文合计）；"首先/其次/最后"允许出现在并列论述里，给较宽额度
CLICHE_LIMIT = {"综上所述": 3, "总而言之": 2, "总之": 3, "值得注意的是": 4,
                "需要指出的是": 3, "不言而喻": 1, "众所周知": 1, "显而易见": 2,
                "毋庸置疑": 1, "由此可见": 4, "首先": 12, "其次": 12, "最后": 12}

# B 类：无信息量修饰（应换成具体数字或删掉）
VAGUE_WORDS = ["显著", "有效", "良好", "较好", "较高", "较强", "大大", "充分",
               "进一步", "极大", "十分", "非常", "极其", "重要"]

# C 类：口语/主观/网络用语（学术论文红线）
RED_WORDS = ["其实", "说白了", "挺好的", "很明显", "我觉得", "超级", "一下子",
             "搞定", "众所周知", "毋庸置疑", "不言而喻"]

# 第一人称：规范要求第三人称，出现即 FAIL
FIRST_PERSON = ["我们", "笔者", "咱们"]
# "本人"多为"本人私钥/本人收件列表"这类正当用法（=自己的），只在自指语境下提示
SELF_WORD_RE = re.compile(r"本人(认为|提出|完成|所做|所做的工作|研究|设计|觉得|负责)")

# G 类：自称
SELF_REF = ["本文", "本系统", "本研究", "本工作", "本课题", "本项目"]

# H 类：本项目术语对照表 —— 同一概念只应保留一种写法
#   注意：只放"确证是同一概念的不同写法"。形近但含义不同的词不要放，
#   例如「标识密码」(IBC，密码体制大类) 与「标识加密」(IBE，具体方案) 是两回事。
TERM_WATCH = {
    "接收人": ["接收方", "接收者"],
    "发送方": ["发送人", "发送者"],
    "密钥生成中心": ["密钥产生中心", "密钥生成机构"],
    "审计日志": ["审计记录", "审计纪录"],
    "分块上传": ["分片上传", "切片上传"],
    "电子邮箱": ["邮箱地址"],
    "端到端加密": ["端对端加密"],
}
# 自动孤立变体探测：同组内出现次数远低于主流写法的，提示统一。
# ASCII 术语按词边界匹配（避免 E2E 命中 E2EE）；首次出现的「全称（缩写）」定义不算变体。
ORPHAN_GROUPS = [
    ["接收人", "接收方"],
    ["审计日志", "审计记录"],
    ["分块", "分片"],
]
ORPHAN_MAX = 2
# 孤立变体若紧跟在全称后的括号里（缩写定义），跳过
ABBR_DEF_RE = r"（[^）]{0,40}%s[^）]{0,40}）"

CJK = re.compile(r"[\u4e00-\u9fff]")
# 规范自带的"汉字紧邻西文"格式，不算混排问题
NORM_PATTERNS = [
    r"[图表式]\s*\d+(\.\d+)*",      # 图3.1 表4.2 式(2.1)
    r"\[\d+(?:[-,，]\d+)*\]",        # [1] [2,3]
    r"SM\d", r"GB/T\s*\d+",          # 专有名词
    r"\d+(\.\d+)?\s*(cm|mm|MB/s|ms|KB|MB|GB|%)",  # 带单位数值
]

results = []


def report(level, item, detail):
    results.append((level, item, detail))


# ---------------------------------------------------------------- 读取

def strip_notes(text):
    """去掉作者备注（> 行）与代码块，只留论文正文。"""
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


def strip_math(text):
    """去掉行内/行间公式，符号统计不混入正文。"""
    text = re.sub(r"\$\$.*?\$\$", "", text, flags=re.S)
    return re.sub(r"\$[^$\n]*\$", "", text)


def count_term(text, term):
    """统计术语出现次数。纯 ASCII 术语按词边界匹配，避免 E2E 命中 E2EE。"""
    if term.isascii():
        return len(re.findall(rf"(?<![A-Za-z0-9]){re.escape(term)}(?![A-Za-z0-9])", text))
    return text.count(term)


def load(src):
    """按文件名顺序读出各章；返回 [(文件名, 清洗后正文)]，只含正文章 + 结论。"""
    chapters = []
    for md in sorted(Path(src).glob("[0-9][0-9]_*.md")):
        if md.name.startswith("00"):
            continue
        text = md.read_text(encoding="utf-8")
        first_h = next((l.lstrip("#").strip() for l in text.splitlines()
                        if l.strip().startswith("#")), "")
        if re.match(r"^\d+\s", first_h) or first_h.startswith("结论"):
            chapters.append((md.name, strip_math(strip_notes(text))))
    return chapters


def paragraphs(body):
    """切出正文段落（排除标题行、图表行、表格行）。"""
    out = []
    for p in body.split("\n\n"):
        p = p.strip()
        if not p or p.startswith("#") or p.startswith("![") or p.startswith("|"):
            continue
        if re.match(r"^表\s*\d+\.\d+", p) or len(CJK.findall(p)) < 20:
            continue
        out.append(p)
    return out


# ---------------------------------------------------------------- 检查项

def check_cliches(chapters):
    total = Counter()
    where = defaultdict(list)
    for name, body in chapters:
        for w in CLICHES:
            n = body.count(w)
            if n:
                total[w] += n
                where[w].append(f"{name[:2]}章×{n}")
    bad = []
    for w, n in total.items():
        limit = CLICHE_LIMIT.get(w, 3)
        if n > limit:
            bad.append(f"『{w}』{n} 次（建议 ≤{limit}）：{'、'.join(where[w])}")
    if bad:
        for msg in bad:
            report("WARN", "套话", msg)
    used = sum(total.values())
    report("PASS" if not bad else "WARN", "套话总量",
           f"模板化连接词共 {used} 处" + (f"，其中超标 {len(bad)} 类" if bad else "，控制良好"))


def check_vague(chapters):
    all_text = "\n".join(b for _, b in chapters)
    hits = [(w, all_text.count(w)) for w in VAGUE_WORDS]
    hits = [(w, n) for w, n in hits if n]
    if not hits:
        report("PASS", "空泛表述", "未发现无信息量修饰词")
        return
    total = sum(n for _, n in hits)
    detail = "、".join(f"{w}={n}" for w, n in sorted(hits, key=lambda x: -x[1])[:8])
    report("WARN" if total > 15 else "PASS", "空泛表述",
           f"共 {total} 处：{detail}（能给数字就别用形容词）")


def check_passive(chapters):
    total, samples = 0, []
    for name, body in chapters:
        for m in re.finditer(r"被[^\u4e00-\u9fff]{0,2}[\u4e00-\u9fff]{1,8}", body):
            total += 1
            if len(samples) < 8:
                samples.append(f"{name[:2]}章“{m.group(0)}”")
    n_chars = sum(len(CJK.findall(b)) for _, b in chapters)
    rate = total / max(n_chars, 1) * 10000
    if rate > 15:
        report("WARN", "被动语态",
               f"{total} 处，密度 {rate:.1f}/万字（偏高）；例：{'、'.join(samples[:5])}")
    else:
        report("PASS", "被动语态", f"{total} 处，密度 {rate:.1f}/万字（健康）")


def check_parallel(chapters):
    """连续 （n） 并列块：各项长度过于接近 = AI 特征 3。

    并列项在 Markdown 里通常各自成段（中间有空行），所以按段落而非按行判断。
    """
    blocks = []
    for name, body in chapters:
        cur = []
        for para in body.split("\n\n"):
            p = para.strip()
            if re.match(r"^（\d+）", p):
                cur.append((name, p))
            else:
                if len(cur) >= 3:
                    blocks.append(cur)
                cur = []
        if len(cur) >= 3:
            blocks.append(cur)
    if not blocks:
        report("PASS", "并列结构", "无连续编号并列块")
        return
    uniform = []
    for blk in blocks:
        lens = [len(CJK.findall(x[1])) for _, x in blk]
        if statistics.mean(lens) < 6:
            continue
        cv = statistics.pstdev(lens) / max(statistics.mean(lens), 1)
        if cv < 0.15:
            uniform.append((blk[0][0], blk[0][1], lens, cv))
    if uniform:
        for name, head, lens, cv in uniform[:6]:
            report("WARN", "并列结构",
                   f"{name[:2]}章 “{head[:24]}…” 各项字数 {lens}（离散度 {cv:.2f}，过于工整）"
                   f"——让详略拉开差距，或改为自然段落串联")
    else:
        detail = "；".join(f"{b[0][0][:2]}章{b[0][1][:12]}…共{len(b)}项" for b in blocks[:4])
        report("PASS", "并列结构", f"{len(blocks)} 个并列块，详略搭配自然（{detail}）")


def check_rhythm(chapters):
    lens = []
    for name, body in chapters:
        lens += [len(CJK.findall(p)) for p in paragraphs(body)]
    if len(lens) < 10:
        report("WARN", "段落节律", f"正文段落仅 {len(lens)} 段，样本不足")
        return
    mean, sd = statistics.mean(lens), statistics.pstdev(lens)
    cv = sd / max(mean, 1)
    buckets = Counter(min(n // 100 * 100, 500) for n in lens)
    dist = "  ".join(f"{k}-{k+99}:{buckets[k]}" for k in sorted(buckets))
    if cv < 0.35:
        report("WARN", "段落节律",
               f"{len(lens)} 段，均 {mean:.0f} 字，离散度 {cv:.2f}（偏均匀，机器感）；分布 {dist}")
    else:
        report("PASS", "段落节律",
               f"{len(lens)} 段，均 {mean:.0f} 字，中位 {statistics.median(lens):.0f} 字，"
               f"离散度 {cv:.2f}（自然）；分布 {dist}")


def check_sentences(chapters):
    sents = []
    for name, body in chapters:
        for s in re.split(r"[。；！？\n]", body):
            n = len(CJK.findall(s))
            if n > 4:
                sents.append((name, n, s.strip()))
    if not sents:
        report("WARN", "句长", "未切出有效句子")
        return
    lens = [n for _, n, _ in sents]
    longs = [(nm, n, s) for nm, n, s in sents if n > 60]
    report("PASS", "句长",
           f"{len(sents)} 句，均 {statistics.mean(lens):.1f} 字，标准差 {statistics.pstdev(lens):.1f}")
    if longs:
        for nm, n, s in sorted(longs, key=lambda x: -x[1])[:5]:
            report("WARN", "超长句", f"{nm[:2]}章 {n} 字：{s[:46]}…")


def check_self_reference(chapters):
    all_text = "\n".join(b for _, b in chapters)
    counts = [(w, all_text.count(w)) for w in SELF_REF]
    counts = [(w, n) for w, n in counts if n]
    red = [(w, all_text.count(w)) for w in RED_WORDS if all_text.count(w)]
    fp = [(w, all_text.count(w)) for w in FIRST_PERSON if all_text.count(w)]
    weird = SELF_WORD_RE.findall(all_text)
    if fp:
        report("FAIL", "第一人称", f"出现 {fp}（规范要求第三人称，须改为“本文/本系统”）")
    if weird:
        report("WARN", "第一人称", f"“本人{weird[0]}…” 等自指表述 {len(weird)} 处，建议改为“本文”")
    if red:
        report("WARN", "口语词", "、".join(f"{w}={n}" for w, n in red))
    if not fp and not red and not weird:
        report("PASS", "口语与自称", "无第一人称、无口语化表述")
    # 自称变体：本文/本系统分工明确，但混入 本课题/本研究/本工作 属不一致
    variants = [(w, n) for w, n in counts if w in ("本研究", "本工作", "本课题", "本项目")]
    base = "、".join(f"{w}={n}" for w, n in counts)
    if variants:
        report("WARN", "自称分布",
               f"{base} —— {'、'.join(w for w, _ in variants)} 建议统一为“本文”")
    else:
        report("PASS", "自称分布", f"{base}（本文=论文自身，本系统=所实现的系统，分工清晰）")


def check_terms(chapters):
    all_text = "\n".join(b for _, b in chapters)
    issues = []
    for canon, variants in TERM_WATCH.items():
        nc = count_term(all_text, canon)
        for v in variants:
            nv = count_term(all_text, v)
            if nv and nc:
                issues.append(f"“{canon}”({nc}) 与 “{v}”({nv}) 混用 → 统一为“{canon}”")
            elif nv and not nc:
                issues.append(f"出现 “{v}”({nv}) 但全文无 “{canon}” → 确认是否应统一")
    for grp in ORPHAN_GROUPS:
        counts = [(w, count_term(all_text, w)) for w in grp]
        counts = [(w, n) for w, n in counts if n]
        if len(counts) < 2:
            continue
        main = max(counts, key=lambda x: x[1])
        for w, n in counts:
            if w == main[0] or n > ORPHAN_MAX:
                continue
            if re.search(ABBR_DEF_RE % re.escape(w), all_text):
                continue  # 首次出现的缩写定义，正常
            issues.append(
                f"孤立变体 “{w}”({n}) vs 主流 “{main[0]}”({main[1]}) → 改用“{main[0]}”")
    if issues:
        for msg in issues:
            report("WARN", "术语一致", msg)
    else:
        report("PASS", "术语一致", "未发现同概念多写法")


def check_mixed_spacing(chapters):
    hits = []
    for name, body in chapters:
        # 行内代码（字段名、表达式）不参与中英混排判断
        probe = re.sub(r"`[^`\n]*`", "", body)
        for m in re.finditer(r".{0,8}[\u4e00-\u9fff][A-Za-z0-9].{0,8}", probe):
            frag = m.group(0)
            if any(re.search(p, frag) for p in NORM_PATTERNS):
                continue
            hits.append(f"{name[:2]}章“{frag}”")
    if hits:
        report("WARN", "中英混排",
               f"{len(hits)} 处汉字与西文之间无空格（全文多数处有空格，需统一）："
               + "；".join(hits[:6]))
    else:
        report("PASS", "中英混排", "汉字与西文之间空格统一")


def clean_with_map(body):
    """返回 (只含汉字的串, 汉字下标→原文下标)。用于匹配去标点、显示带标点。"""
    chars, idx = [], []
    for i, ch in enumerate(body):
        if CJK.match(ch):
            chars.append(ch)
            idx.append(i)
    return "".join(chars), idx


def check_duplicates(chapters, n_min, src):
    """跨章重复片段 —— 查重前自查雷同。题目、固定术语属正常重复，剔除后再报。"""
    cleaned = {}
    chapters_dict = dict(chapters)
    for name, body in chapters:
        cleaned[name] = clean_with_map(body)

    grams = {}
    for name, (clean, _) in cleaned.items():
        for i in range(len(clean) - n_min + 1):
            grams.setdefault(clean[i:i + n_min], set()).add(name[:2])
    repeated = {g: frozenset(c) for g, c in grams.items() if len(c) > 1}
    if not repeated:
        report("PASS", "重复片段", f"无跨章重复的 {n_min} 字串")
        return

    # 合并为极大重复区段：在某章内自左向右延伸，直到共有章集合发生变化
    regions = {}
    for name, (clean, _) in cleaned.items():
        i = 0
        while i <= len(clean) - n_min:
            chs = repeated.get(clean[i:i + n_min])
            if not chs:
                i += 1
                continue
            j = i + n_min
            while j < len(clean) and repeated.get(clean[j - n_min + 1:j + 1]) == chs:
                j += 1
            regions.setdefault((name, i, j), chs)
            i = j

    title = ""
    tj = Path(src) / "thesis.json"
    if tj.exists():
        import json
        try:
            title = re.sub(r"[^\u4e00-\u9fff]", "",
                           json.loads(tj.read_text(encoding="utf-8")).get("title", ""))
        except Exception:
            title = ""

    keep = {}
    for (name, i, j), chs in regions.items():
        clean, idx = cleaned[name]
        seg = clean[i:j]
        if any(seg != other[0] and seg in other[0] for other in regions):
            continue
        # 论文题目（含前后虚词）造成的必然重复，剔除
        if title and any(seg[k:k + 8] in title for k in range(max(len(seg) - 7, 1))):
            continue
        shown = chapters_dict[name][idx[i]:idx[j - 1] + 1].replace("\n", " ")
        keep.setdefault((seg, chs), shown)
    if not keep:
        report("PASS", "重复片段", f"无跨章重复的 {n_min} 字串（仅题目类必然重复）")
        return
    items = sorted(keep.items(), key=lambda kv: (-len(kv[0][0]), kv[0][0]))
    report("WARN", "重复片段",
           f"{len(items)} 处 {n_min} 字以上跨章重复（查重自查线索，非必然要改）：")
    for (seg, chs), shown in items:
        report("WARN", "重复片段", f"  [{'/'.join(sorted(chs))}章] {shown}")


# ---------------------------------------------------------------- 主流程

def main():
    ap = argparse.ArgumentParser(description="毕业论文文风体检")
    ap.add_argument("--src", default="thesis")
    ap.add_argument("--min-dup", type=int, default=12, help="重复片段最小字数（默认 12）")
    ap.add_argument("--top", type=int, default=10, help="每类最多列几条")
    args = ap.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    chapters = load(args.src)
    if not chapters:
        print(f"[FAIL] 未在 {args.src} 找到正文文件（NN_*.md）")
        return 1

    print(f"文风体检：{args.src}　共 {len(chapters)} 章，"
          f"{sum(len(CJK.findall(b)) for _, b in chapters)} 中文字符\n")

    check_cliches(chapters)
    check_vague(chapters)
    check_passive(chapters)
    check_parallel(chapters)
    check_rhythm(chapters)
    check_sentences(chapters)
    check_self_reference(chapters)
    check_terms(chapters)
    check_mixed_spacing(chapters)
    check_duplicates(chapters, args.min_dup, args.src)

    print("=" * 72)
    order = {"FAIL": 0, "WARN": 1, "PASS": 2}
    n = {"FAIL": 0, "WARN": 0, "PASS": 0}
    for level, item, detail in sorted(results, key=lambda x: (order[x[0]], x[1])):
        n[level] += 1
        print(f"[{level}] {item}: {detail}")
    print("=" * 72)
    print(f"合计: {n['PASS']} 通过 / {n['WARN']} 提醒 / {n['FAIL']} 不合规")
    print("说明：WARN 是线索不是判决——逐条判断，该改的改，误报的忽略。")
    return 1 if n["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
