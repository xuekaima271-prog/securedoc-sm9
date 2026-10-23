from pathlib import Path
from math import atan2, cos, sin, pi

from PIL import Image, ImageDraw, ImageFont


OUT = Path(__file__).resolve().parents[1] / "thesis" / "images"
OUT.mkdir(parents=True, exist_ok=True)

FONT_CANDIDATES = [
    Path(r"C:\Windows\Fonts\msyh.ttc"),
    Path(r"C:\Windows\Fonts\simhei.ttf"),
    Path(r"C:\Windows\Fonts\simsun.ttc"),
]
FONT_PATH = next(p for p in FONT_CANDIDATES if p.exists())

INK = "#172033"
MUTED = "#526174"
BLUE = "#2E5E91"
BLUE_DARK = "#1D456F"
BLUE_LIGHT = "#EAF2FA"
CYAN_LIGHT = "#E8F5F5"
GREEN = "#2F7659"
GREEN_LIGHT = "#EAF5EF"
AMBER = "#9B661F"
AMBER_LIGHT = "#FBF1DD"
RED = "#A34A48"
RED_LIGHT = "#F9EAEA"
GRAY = "#7B8794"
GRAY_LIGHT = "#F2F4F7"
WHITE = "#FFFFFF"


def font(size, bold=False):
    return ImageFont.truetype(str(FONT_PATH), size=size, index=1 if bold and FONT_PATH.suffix == ".ttc" else 0)


def canvas(width, height):
    im = Image.new("RGB", (width, height), WHITE)
    return im, ImageDraw.Draw(im)


def text_size(draw, text, fnt, spacing=8):
    box = draw.multiline_textbbox((0, 0), text, font=fnt, spacing=spacing, align="center")
    return box[2] - box[0], box[3] - box[1]


def centered_text(draw, box, text, fnt, fill=INK, spacing=8, align="center"):
    x1, y1, x2, y2 = box
    w, h = text_size(draw, text, fnt, spacing)
    x = x1 + (x2 - x1 - w) / 2
    y = y1 + (y2 - y1 - h) / 2
    draw.multiline_text((x, y), text, font=fnt, fill=fill, spacing=spacing, align=align)


def rounded_box(draw, box, text, *, fill=BLUE_LIGHT, outline=BLUE, radius=24,
                width=4, fnt=None, text_fill=INK, spacing=8):
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)
    centered_text(draw, box, text, fnt or font(34), text_fill, spacing)


def line_arrow(draw, start, end, *, fill=BLUE_DARK, width=5, head=18, dash=None):
    if dash:
        x1, y1 = start
        x2, y2 = end
        dist = ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5
        ux, uy = (x2 - x1) / dist, (y2 - y1) / dist
        pos = 0
        while pos < dist - head:
            e = min(pos + dash[0], dist - head)
            draw.line((x1 + ux * pos, y1 + uy * pos, x1 + ux * e, y1 + uy * e), fill=fill, width=width)
            pos += dash[0] + dash[1]
    else:
        draw.line((start, end), fill=fill, width=width)
    angle = atan2(end[1] - start[1], end[0] - start[0])
    p1 = (end[0] - head * cos(angle - pi / 6), end[1] - head * sin(angle - pi / 6))
    p2 = (end[0] - head * cos(angle + pi / 6), end[1] - head * sin(angle + pi / 6))
    draw.polygon([end, p1, p2], fill=fill)


def label(draw, xy, text, *, fill=MUTED, size=26, anchor="mm", bold=False):
    draw.text(xy, text, font=font(size, bold), fill=fill, anchor=anchor)


def save(im, name, dpi=240):
    path = OUT / name
    im.save(path, dpi=(dpi, dpi), optimize=True)
    print(path)


def figure_3_1():
    im, d = canvas(2200, 1260)
    d.rounded_rectangle((70, 70, 2130, 1190), radius=34, outline="#C9D2DD", width=4, fill="#FBFCFE")

    role_f = font(38, True)
    item_f = font(37)
    roles = [
        ((130, 170, 560, 430), "普通员工\nEMPLOYEE", BLUE_LIGHT, BLUE),
        ((130, 500, 560, 760), "系统管理员\nSYS_ADMIN", AMBER_LIGHT, AMBER),
        ((130, 830, 560, 1090), "安全审计员\nSECURITY_\nAUDITOR", GREEN_LIGHT, GREEN),
    ]
    employee = [
        (790, 135, 1210, 300, "登录与密钥初始化"),
        (1390, 135, 1950, 300, "加密投递与多人接收"),
        (790, 345, 1210, 510, "收件解密与\n完整性校验"),
        (1390, 345, 1950, 510, "换设备确定性\n重签发"),
    ]
    admin = [
        (790, 565, 1210, 730, "创建与启停用户"),
        (1390, 565, 1950, 730, "调整角色并防止自锁"),
    ]
    auditor = [
        (790, 805, 1210, 970, "审计日志查询与\n链校验"),
        (1390, 805, 1950, 970, "安全事件与\n签发记录"),
    ]
    # 先画关系线，再画实心功能框，使经过其他框的连线被自然遮蔽，不压住文字。
    for y, color, targets in [
        (300, BLUE, [(790, 217), (1390, 217), (790, 427), (1390, 427)]),
        (630, AMBER, [(790, 647), (1390, 647)]),
        (960, GREEN, [(790, 887), (1390, 887)]),
    ]:
        x0 = 560
        d.line((x0, y, 680, y), fill=color, width=6)
        for tx, ty in targets:
            d.line((680, y, 680, ty), fill=color, width=4)
            line_arrow(d, (680, ty), (tx, ty), fill=color, width=4, head=16)

    for box, txt, fill, outline in roles:
        rounded_box(d, box, txt, fill=fill, outline=outline, radius=28, fnt=role_f)
    for row, fill, outline in [(employee, BLUE_LIGHT, BLUE), (admin, AMBER_LIGHT, AMBER), (auditor, GREEN_LIGHT, GREEN)]:
        for x1, y1, x2, y2, txt in row:
            rounded_box(d, (x1, y1, x2, y2), txt, fill=fill, outline=outline, radius=22, fnt=item_f)

    rounded_box(d, (790, 1035, 1950, 1135), "共同约束：业务库不持久化明文与私钥；关键操作可审计", fill=GRAY_LIGHT,
                outline=GRAY, radius=20, fnt=font(36, True), text_fill=INK)
    save(im, "fig3-1-use-cases.png")


def figure_4_1():
    im, d = canvas(2400, 1350)
    zone_f = font(44, True)
    box_f = font(36)
    small_f = font(30)

    zones = [
        ((90, 110, 735, 1130), "浏览器加密端", BLUE_LIGHT, BLUE),
        ((875, 110, 1520, 1130), "应用服务器（盲存储）", GREEN_LIGHT, GREEN),
        ((1660, 110, 2310, 1130), "KGC 密钥中心", AMBER_LIGHT, AMBER),
    ]
    for box, title, fill, outline in zones:
        d.rounded_rectangle(box, radius=32, fill=fill, outline=outline, width=5)
        x1, y1, x2, _ = box
        d.rounded_rectangle((x1, y1, x2, y1 + 105), radius=28, fill=outline)
        centered_text(d, (x1, y1, x2, y1 + 105), title, zone_f, WHITE)

    rounded_box(d, (155, 300, 670, 510), "WebWorker\nSM4-CBC / SM3 / SM9-IBE", fill=WHITE, outline=BLUE, fnt=box_f)
    rounded_box(d, (155, 660, 670, 870), "浏览器本地保存\n业务数据库不持久化私钥", fill=WHITE, outline=BLUE, fnt=box_f)
    line_arrow(d, (412, 510), (412, 660), fill=BLUE, width=5)

    rounded_box(d, (940, 270, 1455, 430), "认证会话与方法级 RBAC", fill=WHITE, outline=GREEN, fnt=box_f)
    rounded_box(d, (940, 520, 1455, 720), "文件盲存储服务\n密文分块 / 信封\n加密元数据", fill=WHITE, outline=GREEN, fnt=box_f)
    rounded_box(d, (940, 810, 1455, 970), "审计哈希链与安全事件", fill=WHITE, outline=GREEN, fnt=box_f)

    rounded_box(d, (1725, 300, 2245, 510), "主密钥安全存储\nPBKDF2 + AES-256-GCM", fill=WHITE, outline=AMBER, fnt=box_f)
    rounded_box(d, (1725, 660, 2245, 870), "身份登记与私钥签发\n首发 / 重签发全程留痕", fill=WHITE, outline=AMBER, fnt=box_f)
    line_arrow(d, (1985, 510), (1985, 660), fill=AMBER, width=5)

    line_arrow(d, (735, 565), (875, 565), fill=BLUE_DARK, width=7, head=22)
    label(d, (805, 525), "密文与信封", size=34)
    line_arrow(d, (875, 760), (735, 760), fill=GREEN, width=6, head=20)
    label(d, (805, 805), "密文返回", size=34)
    line_arrow(d, (1520, 620), (1660, 620), fill=AMBER, width=7, head=22)
    label(d, (1590, 575), "签发申请", size=34)
    line_arrow(d, (1660, 820), (1520, 820), fill=AMBER, width=6, head=20)
    label(d, (1590, 865), "私钥包", size=34)

    rounded_box(d, (650, 1180, 1050, 1290), "对象存储\nLocal / MinIO", fill=GRAY_LIGHT, outline=GRAY, fnt=small_f)
    rounded_box(d, (1120, 1180, 1520, 1290), "业务数据库\nH2 / MySQL 8", fill=GRAY_LIGHT, outline=GRAY, fnt=small_f)
    rounded_box(d, (1780, 1180, 2180, 1290), "KGC 独立数据库", fill=GRAY_LIGHT, outline=GRAY, fnt=small_f)
    line_arrow(d, (1120, 1080), (850, 1180), fill=GRAY, width=4, head=15)
    line_arrow(d, (1250, 1130), (1320, 1180), fill=GRAY, width=4, head=15)
    line_arrow(d, (1985, 1130), (1985, 1180), fill=GRAY, width=4, head=15)
    save(im, "fig4-1-architecture.png")


def figure_4_2():
    im, d = canvas(2500, 1750)
    actors = [(330, "发送方浏览器"), (1250, "应用服务器"), (2170, "KGC")]
    for x, name in actors:
        rounded_box(d, (x - 240, 70, x + 240, 190), name, fill=BLUE_LIGHT if x == 330 else (GREEN_LIGHT if x == 1250 else AMBER_LIGHT),
                    outline=BLUE if x == 330 else (GREEN if x == 1250 else AMBER), fnt=font(44, True), radius=22)
        d.line((x, 190, x, 1650), fill="#98A4B2", width=4)

    steps = [
        (270, 330, 1250, "请求 SM9 主公钥", BLUE, False),
        (360, 1250, 2170, "代理查询主公钥", AMBER, False),
        (450, 2170, 1250, "返回主公钥", AMBER, False),
        (540, 1250, 330, "返回主公钥", BLUE, False),
        (650, 330, 330, "生成随机 DEK 与分块 IV", BLUE, True),
        (760, 330, 330, "SM4-CBC 分块加密并计算 SM3", BLUE, True),
        (870, 330, 330, "加密文件名、类型与备注", BLUE, True),
        (980, 330, 330, "按每位接收人身份生成 SM9 信封", BLUE, True),
        (1110, 330, 1250, "初始化投递：加密元数据、信封、分块清单", GREEN, False),
        (1260, 330, 1250, "循环上传密文分块：摘要与 IV", GREEN, False),
        (1370, 1250, 1250, "服务端复算 SM3；失配即拒绝", GREEN, True),
        (1530, 330, 1250, "提交完成：状态置为 AVAILABLE", GREEN, False),
    ]
    for y, x1, x2, txt, color, self_call in steps:
        if self_call:
            side = 270 if x1 == 330 else 290
            d.line((x1, y, x1 + side, y), fill=color, width=5)
            d.line((x1 + side, y, x1 + side, y + 70), fill=color, width=5)
            line_arrow(d, (x1 + side, y + 70), (x1, y + 70), fill=color, width=5, head=18)
            label(d, (x1 + side / 2, y - 24), txt, size=37)
        else:
            direction_right = x2 > x1
            start = (x1 + (16 if direction_right else -16), y)
            end = (x2 - (16 if direction_right else -16), y)
            line_arrow(d, start, end, fill=color, width=5, head=18)
            label(d, ((x1 + x2) / 2, y - 26), txt, size=37)

    rounded_box(d, (65, 1210, 270, 1460), "逐块\n循环", fill=GREEN_LIGHT, outline=GREEN,
                radius=22, fnt=font(36, True), text_fill=GREEN)
    rounded_box(d, (1710, 1300, 2380, 1470), "摘要失配：拒绝该块并记录安全事件", fill=RED_LIGHT,
                outline=RED, radius=22, fnt=font(31, True), text_fill=RED)
    line_arrow(d, (1540, 1405), (1710, 1405), fill=RED, width=5, head=18)
    save(im, "fig4-2-send-sequence.png")


def entity_box(d, box, name, fields, color=BLUE):
    x1, y1, x2, y2 = box
    d.rounded_rectangle(box, radius=18, fill=WHITE, outline=color, width=4)
    d.rounded_rectangle((x1, y1, x2, y1 + 72), radius=16, fill=color)
    centered_text(d, (x1, y1, x2, y1 + 72), name, font(42, True), WHITE)
    d.multiline_text((x1 + 24, y1 + 92), fields, font=font(36), fill=INK, spacing=9)


def figure_4_3():
    im, d = canvas(2500, 1700)
    boxes = {
        "roles": (120, 160, 600, 470),
        "user_roles": (850, 180, 1330, 500),
        "users": (1600, 140, 2140, 540),
        "user_keys": (1600, 760, 2140, 1110),
        "files": (850, 760, 1330, 1160),
        "file_chunks": (120, 1260, 600, 1600),
        "file_recipients": (850, 1260, 1430, 1600),
    }
    entity_box(d, boxes["roles"], "roles", "PK  id\n    role_code\n    role_name")
    entity_box(d, boxes["user_roles"], "user_roles", "PK  id\nFK  user_id\nFK  role_id", GREEN)
    entity_box(d, boxes["users"], "users", "PK  id\n    username\n    password_hash\n    status", BLUE_DARK)
    entity_box(d, boxes["user_keys"], "user_keys", "PK  id\nFK  user_id\n    sm9_identity\n    key_status", AMBER)
    entity_box(d, boxes["files"], "files", "PK  id (UUID)\nFK  sender_id\n    encrypted_metadata\n    status", GREEN)
    entity_box(d, boxes["file_chunks"], "file_chunks", "PK  id\nFK  file_id\n    chunk_index\n    digest / iv", BLUE)
    entity_box(d, boxes["file_recipients"], "file_recipients", "PK  id\nFK  file_id\nFK  recipient_id\n    key_envelope", AMBER)

    # roles 1 -- n user_roles
    line_arrow(d, (600, 315), (850, 315), fill=GREEN, width=5, head=16)
    label(d, (635, 275), "1", size=36, bold=True)
    label(d, (815, 275), "N", size=36, bold=True)
    # users 1 -- n user_roles
    line_arrow(d, (1600, 350), (1330, 350), fill=GREEN, width=5, head=16)
    label(d, (1560, 310), "1", size=36, bold=True)
    label(d, (1370, 310), "N", size=36, bold=True)
    # users 1 -- 1 user_keys
    line_arrow(d, (1870, 540), (1870, 760), fill=AMBER, width=5, head=16)
    label(d, (1825, 600), "1", size=36, bold=True)
    label(d, (1825, 710), "1", size=36, bold=True)
    # users 1 -- n files
    d.line((1600, 470, 1470, 470), fill=GREEN, width=5)
    d.line((1470, 470, 1470, 960), fill=GREEN, width=5)
    line_arrow(d, (1470, 960), (1330, 960), fill=GREEN, width=5, head=16)
    label(d, (1560, 425), "1", size=36, bold=True)
    label(d, (1370, 920), "N", size=36, bold=True)
    label(d, (1445, 700), "发送", size=34, fill=GREEN)
    # files 1 -- n chunks
    d.line((850, 1030, 720, 1030), fill=BLUE, width=5)
    d.line((720, 1030, 720, 1430), fill=BLUE, width=5)
    line_arrow(d, (720, 1430), (600, 1430), fill=BLUE, width=5, head=16)
    label(d, (810, 990), "1", size=36, bold=True)
    label(d, (640, 1390), "N", size=36, bold=True)
    # files 1 -- n recipients
    line_arrow(d, (1090, 1160), (1090, 1260), fill=AMBER, width=5, head=16)
    label(d, (1040, 1185), "1", size=36, bold=True)
    label(d, (1040, 1235), "N", size=36, bold=True)
    # users 1 -- n recipients
    d.line((2140, 430, 2310, 430), fill=AMBER, width=5)
    d.line((2310, 430, 2310, 1450), fill=AMBER, width=5)
    d.line((2310, 1450, 1430, 1450), fill=AMBER, width=5)
    line_arrow(d, (1430, 1450), (1430, 1450), fill=AMBER, width=5, head=16)
    label(d, (2180, 390), "1", size=36, bold=True)
    label(d, (1480, 1410), "N", size=36, bold=True)
    label(d, (2260, 900), "接收", size=34, fill=AMBER)

    d.rounded_rectangle((120, 600, 650, 1050), radius=24, fill=GRAY_LIGHT, outline=GRAY, width=4)
    label(d, (385, 650), "独立审计与安全表", size=40, bold=True, fill=INK)
    d.multiline_text((165, 720), "audit_logs\nlogin_attempts\nsecurity_events\nkgc_private_key_issues", font=font(34), fill=MUTED, spacing=18)
    label(d, (385, 1010), "不设业务外键，保留追溯能力", size=31, fill=MUTED)
    save(im, "fig4-3-er.png")


def figure_5_1():
    im, d = canvas(2400, 1500)
    lane_w = 1020
    lanes = [
        (120, "发送端封装流程", BLUE, BLUE_LIGHT),
        (1260, "接收端解封流程", GREEN, GREEN_LIGHT),
    ]
    for x, title, color, fill in lanes:
        d.rounded_rectangle((x, 80, x + lane_w, 1410), radius=34, fill="#FBFCFE", outline=color, width=5)
        d.rounded_rectangle((x, 80, x + lane_w, 190), radius=30, fill=color)
        centered_text(d, (x, 80, x + lane_w, 190), title, font(52, True), WHITE)

    left_steps = [
        (280, "生成 128 bit 随机 DEK"),
        (500, "按 4 MiB 分块并生成独立 IV"),
        (720, "SM4-CBC 加密文件与元数据"),
        (940, "计算每块 SM3 密文摘要"),
        (1160, "按接收人身份封装 DEK 信封"),
    ]
    right_steps = [
        (280, "以本地 SM9 私钥解封 DEK"),
        (500, "逐块下载密文、摘要与 IV"),
        (720, "浏览器复算 SM3 摘要\n失配则中止并告警"),
        (940, "摘要一致后执行 SM4-CBC 解密"),
        (1160, "拼装文件并还原明文元数据"),
    ]
    for x0, steps, color, fill in [(120, left_steps, BLUE, BLUE_LIGHT), (1260, right_steps, GREEN, GREEN_LIGHT)]:
        for idx, (y, txt) in enumerate(steps):
            rounded_box(d, (x0 + 150, y, x0 + 870, y + 135), txt, fill=fill, outline=color, radius=22, fnt=font(43))
            if idx < len(steps) - 1:
                line_arrow(d, (x0 + 510, y + 135), (x0 + 510, steps[idx + 1][0]), fill=color, width=5, head=18)

    label(d, (1680, 900), "摘要一致", size=34, fill=GREEN)
    save(im, "fig5-1-crypto-flow.png")


def figure_5_2():
    im, d = canvas(2200, 1540)
    flow = [
        (760, 70, 1440, 190, "接收首次签发或重签发请求", BLUE, BLUE_LIGHT),
        (760, 300, 1440, 430, "校验服务令牌与请求参数", BLUE, BLUE_LIGHT),
        (760, 540, 1440, 680, "核对身份格式、用户与登记绑定", AMBER, AMBER_LIGHT),
        (760, 800, 1440, 940, "加载加密主私钥并在内存解封", RED, RED_LIGHT),
        (760, 1060, 1440, 1200, "按 SM9 私钥提取公式\n确定性计算 de_B", GREEN, GREEN_LIGHT),
        (760, 1320, 1440, 1460, "写入签发流水与审计后返回私钥包", GREEN, GREEN_LIGHT),
    ]
    for idx, (x1, y1, x2, y2, txt, color, fill) in enumerate(flow):
        rounded_box(d, (x1, y1, x2, y2), txt, fill=fill, outline=color, radius=24, fnt=font(39, True if idx in (0, 5) else False))
        if idx < len(flow) - 1:
            line_arrow(d, ((x1 + x2) / 2, y2), ((x1 + x2) / 2, flow[idx + 1][1]), fill=BLUE_DARK, width=5, head=18)

    rounded_box(d, (80, 520, 560, 715), "校验失败\n返回 401 / 400\n不产生私钥", fill=RED_LIGHT, outline=RED, radius=22, fnt=font(41, True), text_fill=RED)
    line_arrow(d, (760, 610), (560, 610), fill=RED, width=5, head=18)
    label(d, (650, 570), "不通过", size=34, fill=RED)

    rounded_box(d, (1640, 930, 2100, 1130), "同一主密钥 + 同一身份\n→ 私钥逐字节一致\n→ 历史密文可恢复", fill=GRAY_LIGHT, outline=GRAY, radius=22, fnt=font(38, True))
    line_arrow(d, (1440, 1130), (1640, 1030), fill=GRAY, width=5, head=18)
    save(im, "fig5-2-key-issue-flow.png")


if __name__ == "__main__":
    figure_3_1()
    figure_4_1()
    figure_4_2()
    figure_4_3()
    figure_5_1()
    figure_5_2()
