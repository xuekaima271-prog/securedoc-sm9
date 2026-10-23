// 按《新疆科技学院本科毕业论文（设计）撰写规范（2026版）》把 thesis/*.md 生成 Word 文档
// 用法: node build-docx.mjs  → 输出 ../论文_基于国密SM9的端到端加密文档投递系统.docx
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  WidthType, BorderStyle, AlignmentType, VerticalAlign, HeadingLevel,
  PageNumber, NumberFormat, Header, Footer, TableOfContents, StyleLevel,
  Math as MathEl, MathRun, MathSubScript, MathSuperScript, MathSubSuperScript,
  TabStopType, LineRuleType, ImageRun, UnderlineType,
} from "docx";

const DIR = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.join(DIR, "..");
const TITLE = "基于国密SM9的端到端加密文档投递系统";
const TITLE_EN = "Design and Implementation of an Enterprise End-to-End Encrypted Document Delivery System Based on SM9";
const SCHOOL_HEADER = "新疆科技学院本科毕业论文";

// —— 字号（半磅）：小二36 小三30 四号28 小四24 五号21
const SZ = { h1: 36, h2: 30, h3: 28, body: 24, small: 21 };
const FONT = { ascii: "Times New Roman", hAnsi: "Times New Roman", eastAsia: "宋体" };
const LINE13 = { line: 312, lineRule: LineRuleType.AUTO };   // 多倍行距 1.3
const LINE1 = { line: 240, lineRule: LineRuleType.AUTO };    // 单倍（表格/页眉脚）
const INDENT2 = 480;      // 小四下首行缩进2字符 ≈ 24pt
const HALF_LINE = 156, ONE_LINE = 312, TWO_LINE = 624;
const CONTENT_W = 8504;   // A4 宽 11906 − 左右边距 2×1701

const run = (text, o = {}) => new TextRun({ text, font: FONT, size: o.size ?? SZ.body, bold: o.bold, italics: o.italics, subScript: o.sub, superScript: o.sup });

// ———————————————————————— 数学式 ————————————————————————
function preLatex(s) {
  return s
    .replace(/\\text\{([^}]*)\}/g, "$1")
    .replace(/\\parallel/g, " ∥ ").replace(/\\quad/g, "  ")
    .replace(/\\forall/g, "∀").replace(/\\in\b/g, " ∈ ")
    .replace(/\\cdot/g, "·").replace(/\\bmod/g, " mod ")
    .replace(/\\times/g, "×").replace(/\\rightarrow/g, " → ")
    .replace(/\\ /g, " ").replace(/\s+/g, " ").trim();
}
function tokenize(s) {
  const items = []; let i = 0;
  const word = /[A-Za-z0-9']+/y;
  while (i < s.length) {
    const ch = s[i];
    if (ch === "_" || ch === "^") {
      let grp; i++;
      if (s[i] === "{") { const j = s.indexOf("}", i); grp = s.slice(i + 1, j); i = j + 1; }
      else { grp = s[i]; i++; }
      let last = items[items.length - 1];
      if (!last) { last = { base: "" }; items.push(last); }
      if (ch === "_") last.sub = (last.sub || "") + grp; else last.sup = (last.sup || "") + grp;
      continue;
    }
    word.lastIndex = i; const m = word.exec(s);
    if (m && m.index === i) { items.push({ base: m[0] }); i = word.lastIndex; }
    else { items.push({ base: ch }); i++; }
  }
  // 合并相邻纯文本
  const merged = [];
  for (const it of items) {
    const prev = merged[merged.length - 1];
    if (prev && !prev.sub && !prev.sup && !it.sub && !it.sup) prev.base += it.base;
    else merged.push(it);
  }
  return merged;
}
function mathChildren(latex) {
  return tokenize(preLatex(latex)).map(it => {
    if (it.sub && it.sup) return new MathSubSuperScript({ children: [new MathRun(it.base)], subScript: [new MathRun(it.sub)], superScript: [new MathRun(it.sup)] });
    if (it.sub) return new MathSubScript({ children: [new MathRun(it.base)], subScript: [new MathRun(it.sub)] });
    if (it.sup) return new MathSuperScript({ children: [new MathRun(it.base)], superScript: [new MathRun(it.sup)] });
    return new MathRun(it.base);
  });
}
function inlineMathRuns(latex) {
  const out = [];
  for (const it of tokenize(preLatex(latex))) {
    const ital = /[A-Za-z]/.test(it.base);
    out.push(run(it.base, { italics: ital }));
    if (it.sub) out.push(run(it.sub, { italics: true, sub: true }));
    if (it.sup) out.push(run(it.sup, { italics: true, sup: true }));
  }
  return out;
}

// ——————————————————— 行内文本 → TextRun[]（**粗体**、$公式$、`代码`） ———————————————————
function runsFromText(text, o = {}) {
  const out = [];
  const re = /(\*\*[^*]+\*\*)|(\$[^$]+\$)|(`[^`]+`)/g;
  let idx = 0, m;
  while ((m = re.exec(text))) {
    if (m.index > idx) out.push(run(text.slice(idx, m.index), o));
    if (m[1]) out.push(run(m[1].slice(2, -2), { ...o, bold: true }));
    else if (m[2]) out.push(...inlineMathRuns(m[2].slice(1, -1)));
    else out.push(run(m[3].slice(1, -1), o));
    idx = re.index + m[0].length; idx = m.index + m[0].length;
  }
  if (idx < text.length) out.push(run(text.slice(idx), o));
  return out;
}

const bodyPara = (text, extra = {}) => new Paragraph({
  children: runsFromText(text), spacing: { ...LINE13 },
  indent: { firstLine: INDENT2 }, alignment: AlignmentType.JUSTIFIED, ...extra,
});

// ———————————————————————— 三线表 ————————————————————————
function threeLineTable(headerCells, rows) {
  const n = headerCells.length;
  const colW = Math.floor(CONTENT_W / n);
  const NONE = { style: BorderStyle.NONE, size: 0, color: "auto" };
  const cellPara = (t, bold) => new Paragraph({
    children: runsFromText(t, { size: SZ.small, bold }),
    alignment: AlignmentType.CENTER, spacing: { ...LINE1 },
  });
  const mk = (cells, isHeader) => new TableRow({
    tableHeader: isHeader,
    children: cells.map(c => new TableCell({
      children: [cellPara(c, isHeader)],
      width: { size: colW, type: WidthType.DXA },
      verticalAlign: VerticalAlign.CENTER,
      borders: isHeader
        ? { top: NONE, left: NONE, right: NONE, bottom: { style: BorderStyle.SINGLE, size: 6, color: "000000" } }
        : { top: NONE, left: NONE, right: NONE, bottom: NONE },
    })),
  });
  return new Table({
    columnWidths: Array(n).fill(colW),
    width: { size: CONTENT_W, type: WidthType.DXA },
    borders: {
      top: { style: BorderStyle.SINGLE, size: 12, color: "000000" },
      bottom: { style: BorderStyle.SINGLE, size: 12, color: "000000" },
      left: NONE, right: NONE, insideHorizontal: NONE, insideVertical: NONE,
    },
    rows: [mk(headerCells, true), ...rows.map(r => mk(r, false))],
  });
}

const caption = (text) => new Paragraph({
  children: runsFromText(text.replace(/^(表|图)\s*(\d+\.\d+)\s*/, "$1$2  "), { size: SZ.small }),
  alignment: AlignmentType.CENTER, spacing: { ...LINE13, before: 80, after: 80 },
});

const figurePlaceholder = (hint) => new Paragraph({
  children: [run(`【插图占位：${hint}——定稿前请用绘图工具绘制后替换本框】`, { size: SZ.small })],
  alignment: AlignmentType.CENTER, spacing: { before: 120, after: 120, ...LINE1 },
  border: {
    top: { style: BorderStyle.DASHED, size: 4, color: "999999", space: 8 },
    bottom: { style: BorderStyle.DASHED, size: 4, color: "999999", space: 8 },
    left: { style: BorderStyle.DASHED, size: 4, color: "999999", space: 8 },
    right: { style: BorderStyle.DASHED, size: 4, color: "999999", space: 8 },
  },
});

// ———————————————————————— Markdown 章节解析 ————————————————————————
function parseChapter(file, { firstHeadingNoBreak = false, unnumberedH1 = false } = {}) {
  const lines = fs.readFileSync(path.join(SRC, file), "utf8").split(/\r?\n/);
  const blocks = [];
  let i = 0, firstH1 = true;
  const spacedNum = (t) => t.replace(/^(\d+(?:\.\d+)*)\s+/, "$1  ");
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim() || line.trim().startsWith(">")) { i++; continue; }

    if (line.startsWith("```mermaid")) {           // mermaid → 占位框 + 图题
      while (i < lines.length && lines[i].trim() !== "```") i++;
      i++; // skip closing ```
      while (i < lines.length && !lines[i].trim()) i++;
      const cap = lines[i] && /^图\s*\d+\.\d+/.test(lines[i].trim()) ? lines[i].trim() : null;
      if (cap) i++;
      blocks.push(figurePlaceholder(cap ? cap.replace(/^图\s*\d+\.\d+\s*/, "") : "示意图"));
      if (cap) blocks.push(caption(cap));
      continue;
    }
    if (/^#{1,4}\s/.test(line)) {                   // 标题
      const level = line.match(/^#+/)[0].length;
      let text = line.replace(/^#+\s*/, "").trim();
      if (level === 1) {
        const opts = {
          heading: HeadingLevel.HEADING_1,
          children: [run(unnumberedH1 ? text : spacedNum(text), { size: SZ.h1, bold: true })],
        };
        if (!(firstH1 && firstHeadingNoBreak)) opts.pageBreakBefore = true;
        blocks.push(new Paragraph(opts));
        firstH1 = false;
      } else {
        const hl = [null, null, HeadingLevel.HEADING_2, HeadingLevel.HEADING_3, HeadingLevel.HEADING_4][level];
        const size = [null, null, SZ.h2, SZ.h3, SZ.body][level];
        blocks.push(new Paragraph({ heading: hl, children: [run(spacedNum(text), { size, bold: true })] }));
      }
      i++; continue;
    }
    if (/^\$\$/.test(line.trim())) {                // 块级公式
      let f = line.trim();
      while (!/\$\$$/.test(f) || f === "$$") { i++; f += " " + lines[i].trim(); }
      f = f.replace(/^\$\$/, "").replace(/\$\$$/, "");
      const tag = (f.match(/\\tag\{([^}]+)\}/) || [])[1];
      f = f.replace(/\\tag\{[^}]+\}/, "").trim();
      blocks.push(new Paragraph({
        children: [
          new MathEl({ children: mathChildren(f) }),
          ...(tag ? [run(`\t（${tag}）`)] : []),
        ],
        tabStops: [{ type: TabStopType.RIGHT, position: CONTENT_W }],
        indent: { firstLine: INDENT2 * 2.5 }, spacing: { ...LINE13, before: 80, after: 80 },
      }));
      i++; continue;
    }
    if (/^表\s*\d+\.\d+/.test(line.trim())) {       // 表题（其后紧跟表格）
      blocks.push(caption(line.trim()));
      i++; while (i < lines.length && !lines[i].trim()) i++;
      if (lines[i] && lines[i].trim().startsWith("|")) {
        const tbl = [];
        while (i < lines.length && lines[i].trim().startsWith("|")) {
          tbl.push(lines[i].trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map(c => c.trim()));
          i++;
        }
        tbl.splice(1, 1); // 去掉分隔行 |---|
        blocks.push(threeLineTable(tbl[0], tbl.slice(1)));
      }
      continue;
    }
    if (line.trim().startsWith("|")) { i++; continue; }  // 无表题的散表：跳过（当前不存在）
    // 普通段落（可能跨行折叠：md 单段单行书写，这里按行即段）
    blocks.push(bodyPara(line.trim()));
    i++;
  }
  return blocks;
}

// ———————————————————————— 摘要 ————————————————————————
function parseAbstract() {
  const t = fs.readFileSync(path.join(SRC, "01_摘要.md"), "utf8");
  const seg = (start, end) => {
    const s = t.indexOf(start); const e = t.indexOf(end, s);
    return t.slice(s + start.length, e === -1 ? undefined : e).trim();
  };
  const zhBody = seg("## 摘要", "**关键词**").split(/\r?\n/).filter(l => l.trim() && !l.startsWith(">")).join("");
  const zhKw = t.match(/\*\*关键词\*\*：(.+)/)[1].trim();
  const enBody = seg("## Abstract", "**Key words**").split(/\r?\n/).filter(l => l.trim()).join(" ");
  const enKw = t.match(/\*\*Key words\*\*: (.+)/)[1].trim();
  return { zhBody, zhKw, enBody, enKw };
}

// ———————————————————————— 参考文献 / 致谢 ————————————————————————
function parseReferences() {
  const lines = fs.readFileSync(path.join(SRC, "09_参考文献.md"), "utf8").split(/\r?\n/);
  const out = [];
  for (const l of lines) {
    if (l.startsWith("## 统计核对")) break;
    if (/^\[\d+\]/.test(l.trim())) {
      out.push(new Paragraph({
        children: runsFromText(l.trim().replace(/^\[(\d+)\]\s*★?\s*/, "[$1] "), { size: SZ.small }),
        indent: { left: 420, hanging: 420 }, spacing: { ...LINE13 },
      }));
    }
  }
  return out;
}
function parseAcknowledgement() {
  const lines = fs.readFileSync(path.join(SRC, "10_致谢.md"), "utf8").split(/\r?\n/);
  return lines.filter(l => l.trim() && !l.startsWith("#") && !l.trim().startsWith(">"))
    .map(l => bodyPara(l.trim()));
}

// ———————————————————————— 页眉/页脚 ————————————————————————
const headerOf = (text) => new Header({
  children: [new Paragraph({
    children: [run(text, { size: SZ.small })], alignment: AlignmentType.CENTER,
    spacing: { ...LINE1 },
    border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: "000000", space: 2 } },
  })],
});
const emptyHeader = () => new Header({ children: [new Paragraph({ children: [] })] });
const pageFooter = () => new Footer({
  children: [new Paragraph({
    children: [new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: SZ.small })],
    alignment: AlignmentType.CENTER, spacing: { ...LINE1 },
  })],
});
const emptyFooter = () => new Footer({ children: [new Paragraph({ children: [] })] });

const fmHeading = (text) => new Paragraph({   // 参考文献/致谢标题：小三粗体居中 段前1行 段后2行
  style: "FMHeading",
  children: [run(text, { size: SZ.h2, bold: true })],
});
const absHeading = (text) => new Paragraph({  // 摘要类标题（不进目录）
  children: [run(text, { size: SZ.h2, bold: true })],
  alignment: AlignmentType.CENTER, spacing: { before: HALF_LINE, after: HALF_LINE, ...LINE13 },
});

// ———————————————————————— 封面 / 扉页（按学校统一封面复刻） ————————————————————————
const LOGO_PATH = path.join(SRC, "..", ".claude", "skills", "thesis-writing", "assets", "cover-logo.png");

function coverBlocks() {
  const blank = "＿＿＿＿＿＿＿＿＿＿";   // 全角下划线，空白字段打印可见
  const uline = (t, size) => new TextRun({ text: t, font: FONT, size, underline: { type: UnderlineType.SINGLE } });
  const field = (label, value) => new Paragraph({
    children: [run(label, { size: SZ.h3 }), value ? uline(`　${value}　`, SZ.h3) : run(blank, { size: SZ.h3 })],
    alignment: AlignmentType.CENTER, spacing: { before: 120, after: 120, ...LINE13 },
  });
  const blocks = [
    new Paragraph({ children: [run("单位代码：13561", { size: SZ.body })], spacing: { ...LINE1 } }),
    new Paragraph({ children: [run("学    号：＿＿＿＿＿＿", { size: SZ.body })], spacing: { after: 400, ...LINE1 } }),
  ];
  if (fs.existsSync(LOGO_PATH)) {
    blocks.push(new Paragraph({
      children: [new ImageRun({ type: "png", data: fs.readFileSync(LOGO_PATH), transformation: { width: 356, height: 82 } })],
      alignment: AlignmentType.CENTER, spacing: { before: 400, after: 200 },
    }));
  }
  blocks.push(
    new Paragraph({ children: [run("本科毕业论文（设计）", { size: 44, bold: true })], alignment: AlignmentType.CENTER, spacing: { before: 200, after: 700, ...LINE13 } }),
    field("题    目：", TITLE),
    field("学    院：", ""),
    field("专业班级：", ""),
    field("姓    名：", ""),
    field("学    号：", ""),
    field("指导教师：", ""),
    new Paragraph({ children: [run("二〇二六年　月　日", { size: SZ.h3 })], alignment: AlignmentType.CENTER, spacing: { before: 700, ...LINE13 } }),
  );
  return blocks;
}
function titlePageBlocks() {
  const sigRight = (t) => new Paragraph({
    children: [run(t)], alignment: AlignmentType.RIGHT, spacing: { before: 240, after: 240, ...LINE13 },
  });
  const subTitle = (t) => new Paragraph({
    children: [run(t, { size: SZ.h3, bold: true })], alignment: AlignmentType.CENTER,
    spacing: { before: 360, after: 240, ...LINE13 },
  });
  return [
    absHeading("新疆科技学院学位论文写作声明和使用授权说明"),
    subTitle("学位论文写作声明"),
    bodyPara("本人郑重声明：所呈交的学位论文，是本人在导师的指导下，独立进行研究工作所取得的成果。除文中已经注明引用的内容外，本论文不含任何其他个人或集体已经发表或撰写过的作品或成果。对本文的研究做出重要贡献的个人和集体，均已在文中以明确方式标明。本声明的法律结果由本人承担。"),
    sigRight("论文作者签名：　　　　　　日期：　　年　　月　　日"),
    subTitle("学位论文使用授权说明"),
    bodyPara("本人完全了解新疆科技学院关于收集、保存、使用学位论文的规定，即：按照学校要求提交学位论文的印刷本和电子版本；学校有权保存学位论文的印刷本和电子版，并提供目录检索与阅览服务；学校可以采用影印、缩印、数字化或其它复制手段保存论文；在不以赢利为目的的前提下，学校可以将学位论文编入有关数据库，提供网上服务。（保密论文在解密后遵守此规定）"),
    sigRight("论文作者签名：　　　　　　导师签名：　　　　　　"),
    sigRight("日期：　　年　　月　　日"),
  ];
}

// ———————————————————————— 组装文档 ————————————————————————
const abs = parseAbstract();
const marginA4 = { top: 1418, bottom: 1418, left: 1701, right: 1701, header: 850, footer: 850 };
const noHF = { headers: { default: emptyHeader(), even: emptyHeader() }, footers: { default: emptyFooter(), even: emptyFooter() } };

const doc = new Document({
  features: { updateFields: true },
  evenAndOddHeaderAndFooters: true,
  styles: {
    default: {
      document: { run: { font: FONT, size: SZ.body }, paragraph: { spacing: { ...LINE13 } } },
    },
    paragraphStyles: [
      { id: "Heading1", name: "heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FONT, size: SZ.h1, bold: true, color: "000000" },
        paragraph: { alignment: AlignmentType.CENTER, spacing: { before: HALF_LINE, after: HALF_LINE, ...LINE13 }, outlineLevel: 0 } },
      { id: "Heading2", name: "heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FONT, size: SZ.h2, bold: true, color: "000000" },
        paragraph: { alignment: AlignmentType.LEFT, spacing: { before: 0, after: 0, ...LINE13 }, outlineLevel: 1 } },
      { id: "Heading3", name: "heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FONT, size: SZ.h3, bold: true, color: "000000" },
        paragraph: { alignment: AlignmentType.LEFT, spacing: { before: 0, after: 0, ...LINE13 }, outlineLevel: 2 } },
      { id: "Heading4", name: "heading 4", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FONT, size: SZ.body, bold: false, color: "000000" },
        paragraph: { alignment: AlignmentType.LEFT, spacing: { before: 0, after: 0, ...LINE13 }, outlineLevel: 3 } },
      { id: "FMHeading", name: "FMHeading", basedOn: "Normal", next: "Normal",
        run: { font: FONT, size: SZ.h2, bold: true, color: "000000" },
        paragraph: { alignment: AlignmentType.CENTER, spacing: { before: ONE_LINE, after: TWO_LINE, ...LINE13 } } },
    ],
  },
  sections: [
    // 1 封面（无页眉页脚页码）
    { properties: { page: { margin: marginA4 } }, ...noHF, children: coverBlocks() },
    // 2 扉页
    { properties: { page: { margin: marginA4 } }, ...noHF, children: titlePageBlocks() },
    // 3 中文摘要（不编页码、无页眉）
    { properties: { page: { margin: marginA4 } }, ...noHF, children: [
      absHeading("摘  要"),
      new Paragraph({ children: runsFromText(abs.zhBody), indent: { firstLine: INDENT2 }, spacing: { before: HALF_LINE, after: HALF_LINE, ...LINE13 }, alignment: AlignmentType.JUSTIFIED }),
      new Paragraph({ children: [] }),
      new Paragraph({ children: [run("关键词：", { bold: true }), run(abs.zhKw)], spacing: { before: HALF_LINE, after: HALF_LINE, ...LINE13 } }),
    ] },
    // 4 英文摘要
    { properties: { page: { margin: marginA4 } }, ...noHF, children: [
      new Paragraph({ children: [run(TITLE_EN, { size: SZ.h2 })], alignment: AlignmentType.CENTER, spacing: { before: HALF_LINE, after: HALF_LINE, ...LINE13 } }),
      absHeading("ABSTRACT"),
      new Paragraph({ children: runsFromText(abs.enBody), indent: { firstLine: INDENT2 }, spacing: { before: HALF_LINE, after: HALF_LINE, ...LINE13 }, alignment: AlignmentType.JUSTIFIED }),
      new Paragraph({ children: [] }),
      new Paragraph({ children: [run("Keywords: ", { bold: true }), run(abs.enKw)], spacing: { before: HALF_LINE, after: HALF_LINE, ...LINE13 } }),
    ] },
    // 5 目录（罗马页码、无页眉）
    { properties: { page: { margin: marginA4, pageNumbers: { start: 1, formatType: NumberFormat.UPPER_ROMAN } } },
      headers: { default: emptyHeader(), even: emptyHeader() },
      footers: { default: pageFooter(), even: pageFooter() },
      children: [
        new Paragraph({ children: [run("目录", { size: SZ.h2, bold: true })], alignment: AlignmentType.CENTER, spacing: { before: ONE_LINE, after: TWO_LINE, ...LINE13 } }),
        new TableOfContents("目录", {
          hyperlink: true, headingStyleRange: "1-3",
          stylesWithLevels: [new StyleLevel("FMHeading", 1)],
        }),
      ] },
    // 6 正文（阿拉伯页码从1起；奇数页眉=题目，偶数页眉=校名）
    { properties: { page: { margin: marginA4, pageNumbers: { start: 1, formatType: NumberFormat.DECIMAL } } },
      headers: { default: headerOf(TITLE), even: headerOf(SCHOOL_HEADER) },
      footers: { default: pageFooter(), even: pageFooter() },
      children: [
        ...parseChapter("02_第1章_绪论.md", { firstHeadingNoBreak: true }),
        ...parseChapter("03_第2章_相关技术基础.md"),
        ...parseChapter("04_第3章_系统需求分析.md"),
        ...parseChapter("05_第4章_系统总体设计.md"),
        ...parseChapter("06_第5章_系统详细设计与实现.md"),
        ...parseChapter("07_第6章_系统测试.md"),
        ...parseChapter("08_结论.md", { unnumberedH1: true }),
      ] },
    // 7 参考文献（页眉=参考文献）
    { properties: { page: { margin: marginA4 } },
      headers: { default: headerOf("参考文献"), even: headerOf("参考文献") },
      footers: { default: pageFooter(), even: pageFooter() },
      children: [fmHeading("参考文献"), ...parseReferences()] },
    // 8 致谢（页眉=致 谢）
    { properties: { page: { margin: marginA4 } },
      headers: { default: headerOf("致　谢"), even: headerOf("致　谢") },
      footers: { default: pageFooter(), even: pageFooter() },
      children: [fmHeading("致　谢"), ...parseAcknowledgement()] },
  ],
});

const OUT = path.join(SRC, `论文_${TITLE}.docx`);
Packer.toBuffer(doc).then(buf => {
  fs.writeFileSync(OUT, buf);
  console.log("written:", OUT, buf.length, "bytes");
});
