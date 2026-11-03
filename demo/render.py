"""Render the narrated demo video: real command output + edge-tts narration.

Usage: python demo/render.py   (needs ffmpeg, edge-tts, Pillow and patchgap on PATH)
Every terminal scene runs its commands for real and shows the actual output;
each scene lasts exactly as long as its narration.
"""
import asyncio
import os
import re
import shutil
import subprocess
import sys
import textwrap

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BUILD = os.path.join(HERE, "build")
OUT = os.path.join(ROOT, "demo.mp4")
W, H, FPS = 1280, 720, 24
VOICE = "en-US-AndrewNeural"
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_B = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
SANS_B = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
SANS = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
BG, FG = (24, 26, 33), (220, 223, 228)
ANSI = {"31": (255, 95, 95), "32": (95, 215, 120), "33": (240, 200, 80), "2": (130, 135, 145), "36": (90, 200, 230)}
PROMPT = "ops@laptop $ "

SCENES = [
    {"kind": "title", "title": "patchgap", "sub": "a critical Linux CVE is public.\nyour distro hasn't shipped the fix. now what?",
     "say": "This is patchgap, a small open source tool for the gap between a Linux CVE going public and your distro "
            "shipping the fix. It tells you which hosts are exposed right now, applies a vetted, reversible stopgap, "
            "and takes it off again once you're patched."},
    {"kind": "bullets", "title": "The problem",
     "bullets": ["CVE-2026-98432: kernel TCP use-after-free, CVSS 9.8",
                 "Debian fixed it Oct 16. RHEL and Amazon Linux by Nov 2.",
                 "Ubuntu 22.04 / 24.04 on Nov 3: fix only in -proposed",
                 "   HN \"WTF Ubuntu?\": 1500+ points",
                 "Ad-hoc nft rules nobody remembers to remove"],
     "say": "Take C V E 2026 98432, a remote kernel bug rated nine point eight. Debian fixed it within a day, and Red Hat "
            "and Amazon Linux shipped kernels by November second. Ubuntu L T S kernels were still only in the proposed "
            "pocket, and the Hacker News thread was full of people pasting firewall one-liners and checking by hand "
            "which boxes had rebooted."},
    {"kind": "term", "cmds": ["patchgap check -i examples/fleet/fleet.json --cve CVE-2026-98432; echo \"exit $?\""],
     "say": "Here's a small example fleet, with real distro versions from the feed. patchgap check looks at the kernel "
            "that's actually running, not just what's installed. web one is exposed, with the fix only in proposed. "
            "web two has the stopgap active. The Debian box is fixed. The RHEL box has the fixed kernel installed but "
            "hasn't rebooted, and the Amazon Linux box just needs the update. Exit code one means exposed and unmitigated. "
            "It can also collect over S S H with a read-only shell script."},
    {"kind": "term", "cmds": ["patchgap mitigate CVE-2026-98432 --force"],
     "say": "patchgap mitigate is a dry run by default. It shows the stopgap, what it can break, its limits, and the "
            "sources it came from, here Red Hat's bulletin and Ubuntu's page, then the exact steps: write a rules "
            "file, syntax-check it with nft, then load it. Even Ubuntu says only the kernel update really fixes it, "
            "and patchgap says that up front."},
    {"kind": "term", "cmds": ["cat demo/ci-apply.txt"],
     "show": ["sudo patchgap mitigate CVE-2026-98432 --force --apply  # on a throwaway CI runner"],
     "say": "This is a real run on a throwaway GitHub Actions runner from the project's C I. With apply, it loads the "
            "table, verifies it's live, and records it. Status now says fix pending plus mitigated, with exit code two. "
            "Revert removes it cleanly. When the image had already blocked the Copy Fail module itself, patchgap "
            "noticed and changed nothing."},
    {"kind": "bullets", "title": "Safe by default",
     "bullets": ["Dry run unless --apply; --apply needs root",
                 "nft -c / sshd -t before loading; verify after, roll back on failure",
                 "Only touches its own files; state in /var/lib/patchgap",
                 "cleanup removes stopgaps once the running kernel is fixed",
                 "Feed: Debian, Ubuntu, Red Hat, ALAS data, with a source URL on each entry"],
     "say": "Nothing changes without apply. Configs are syntax-checked before loading and verified after, with rollback "
            "on failure. patchgap cleanup takes a stopgap off only when the running system is fixed, so a kernel that's "
            "installed but not booted keeps it. The feed is generated from the Debian, Ubuntu, Red Hat and Amazon "
            "trackers, with a source URL on every entry. Distros it doesn't cover show as unknown."},
    {"kind": "bullets", "title": "Try it",
     "bullets": ["curl -fsSL https://raw.githubusercontent.com/",
                 "   hamarshehmhmd/patchgap/main/install.sh | sh",
                 "patchgap check     patchgap check --hosts hosts.txt",
                 "",
                 "GNU AGPL-3.0 (commercial licenses available)"],
     "say": "Install it with one line and run patchgap check. It's licensed under the GNU A G P L version 3, with "
            "commercial licenses available from the author. It's on GitHub at hamarsheh m h m d slash patchgap."},
]


async def tts(text, path):
    import edge_tts
    for attempt in range(8):  # the edge-tts service occasionally returns no audio; retry
        try:
            await edge_tts.Communicate(text, VOICE, rate="+4%").save(path)
            return
        except Exception:
            if os.path.exists(path):
                os.remove(path)
            if attempt == 7:
                raise
            await asyncio.sleep(5)


def duration(path):
    out = subprocess.check_output(["ffprobe", "-v", "error", "-show_entries", "format=duration",
                                   "-of", "csv=p=0", path], text=True)
    return float(out.strip())


def run_cmd(cmd, cwd):
    env = dict(os.environ, FORCE_COLOR="1")
    env.pop("NO_COLOR", None)
    env["PATH"] = os.path.dirname(shutil.which("patchgap")) + os.pathsep + env["PATH"]
    full = cmd
    p = subprocess.run(["bash", "-c", "shopt -s nullglob; " + full], cwd=cwd, capture_output=True, text=True, env=env)
    out = (p.stdout + p.stderr).rstrip("\n")
    # pretty-print hook JSON
    if out.startswith("{"):
        import json
        try:
            out = json.dumps(json.loads(out), indent=2)
        except ValueError:
            pass
    return out


def parse_ansi(line):
    """Return [(text, color, bold)] spans for a line with SGR codes."""
    spans, color, bold = [], FG, False
    for part in re.split(r"(\x1b\[[0-9;]*m)", line):
        m = re.match(r"\x1b\[([0-9;]*)m", part)
        if m:
            for code in (m.group(1) or "0").split(";"):
                if code == "0":
                    color, bold = FG, False
                elif code == "1":
                    bold = True
                elif code in ANSI:
                    color = ANSI[code]
        elif part:
            spans.append((part, color, bold))
    return spans


class Term:
    def __init__(self):
        self.font = ImageFont.truetype(MONO, 15)
        self.bold = ImageFont.truetype(MONO_B, 15)
        self.cw = self.font.getlength("M")
        self.lh = 21
        self.cols = int((W - 80) / self.cw)

    def wrap(self, spans):
        lines, cur, n = [], [], 0
        for text, c, b in spans:
            while text:
                room = self.cols - n
                if len(text) <= room:
                    cur.append((text, c, b)); n += len(text); text = ""
                else:
                    cut = text.rfind(" ", 0, room + 1)
                    cut = cut if cut > 0 else room
                    cur.append((text[:cut], c, b)); lines.append(cur); cur, n = [], 0
                    text = "    " + text[cut:].lstrip(" ")
        lines.append(cur)
        return lines

    def frame(self, lines, cursor=False):
        img = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(img)
        d.rounded_rectangle([20, 14, W - 20, H - 14], 12, fill=(30, 33, 41), outline=(60, 64, 76))
        for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
            d.ellipse([40 + i * 24, 30, 54 + i * 24, 44], fill=c)
        d.text((W // 2, 37), "~/patchgap — bash", font=ImageFont.truetype(SANS, 15), fill=(150, 155, 165), anchor="mm")
        visible = lines[-30:]
        y = 64
        for ln in visible:
            x = 40
            for text, c, b in ln:
                d.text((x, y), text, font=self.bold if b else self.font, fill=c)
                x += self.cw * len(text)
            y += self.lh
        if cursor:
            last = visible[-1] if visible else []
            x = 40 + self.cw * sum(len(t) for t, _, _ in last)
            d.rectangle([x, y - self.lh + 3, x + self.cw - 2, y - 4], fill=FG)
        return img


def card(scene):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    if scene["kind"] == "title":
        d.text((W // 2, 280), scene["title"], font=ImageFont.truetype(MONO_B, 84), fill=(95, 215, 120), anchor="mm")
        d.multiline_text((W // 2, 420), scene["sub"], font=ImageFont.truetype(SANS, 34), fill=FG, anchor="mm",
                         align="center", spacing=12)
        d.text((W // 2, 620), "github.com/hamarshehmhmd/patchgap  ·  GNU AGPL-3.0", font=ImageFont.truetype(SANS, 22),
               fill=(150, 155, 165), anchor="mm")
    else:
        d.text((90, 90), scene["title"], font=ImageFont.truetype(SANS_B, 52), fill=(95, 215, 120))
        f = ImageFont.truetype(SANS, 29)
        y = 200
        for b in scene["bullets"]:
            if b and not b.startswith("   "):
                d.text((90, y), "•", font=f, fill=(240, 200, 80))
            d.text((130, y), b.strip(), font=f, fill=FG)
            y += 58 if b.startswith("   ") or not b else 62
    return img


class Writer:
    def __init__(self, path, audio):
        self.p = subprocess.Popen(["ffmpeg", "-y", "-loglevel", "error", "-f", "rawvideo", "-pix_fmt", "rgb24",
                                   "-s", f"{W}x{H}", "-r", str(FPS), "-i", "-", "-i", audio,
                                   "-af", "apad", "-c:v", "libx264", "-preset", "medium", "-crf", "23",
                                   "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "128k", "-ar", "44100",
                                   "-shortest", path], stdin=subprocess.PIPE)
        self.n = 0

    def put(self, img, count=1):
        data = img.tobytes()
        for _ in range(count):
            self.p.stdin.write(data)
        self.n += count

    def close(self):
        self.p.stdin.close()
        self.p.wait()
        if self.p.returncode:
            sys.exit("ffmpeg failed")


def render_scene(i, scene, workdir):
    audio = os.path.join(BUILD, f"s{i}.mp3")
    if not os.path.exists(audio):
        asyncio.run(tts(scene["say"], audio))
    total = int((duration(audio) + 0.7) * FPS)
    path = os.path.join(BUILD, f"s{i}.mp4")
    w = Writer(path, audio)
    if scene["kind"] != "term":
        w.put(card(scene), total)
        w.close()
        return path
    t = Term()
    shown = scene.get("show", scene["cmds"])
    outputs = [run_cmd(c, workdir) for c in scene["cmds"]]
    # When a scene's displayed command differs from what runs (heredoc), show
    # the display lines; the last displayed line always maps to the last command.
    steps = []
    if len(shown) != len(scene["cmds"]):
        steps = [(s, "") for s in shown[:-1]] + [(shown[-1], outputs[-1])]
    else:
        steps = list(zip(shown, outputs))
    # timing budget: typing ~ 30 chars/s, then pause, spread over the narration
    typing = sum(len(s) for s, _ in steps) / 32 * FPS
    pause = max(6, int((total - typing) / max(1, len(steps))) - 4)
    lines = []
    for cmd, out in steps:
        prompt = [(PROMPT, (95, 215, 120), True)]
        for k in range(0, len(cmd) + 1, 2):
            frame = t.frame(lines + t.wrap(prompt + [(cmd[:k], FG, False)]), cursor=True)
            w.put(frame)
        lines += t.wrap(prompt + [(cmd, FG, False)])
        for ol in out.splitlines():
            lines += t.wrap(parse_ansi(ol))
        lines.append([])
        hold = min(pause, max(0, total - w.n))
        w.put(t.frame(lines), hold)
    final = t.frame(lines + t.wrap([(PROMPT, (95, 215, 120), True)]), cursor=True)
    if w.n < total:
        w.put(final, total - w.n)
    w.close()
    return path


def main():
    os.makedirs(BUILD, exist_ok=True)
    workdir = ROOT
    parts = [render_scene(i, s, workdir) for i, s in enumerate(SCENES)]
    with open(os.path.join(BUILD, "list.txt"), "w") as fh:
        fh.writelines(f"file '{p}'\n" for p in parts)
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i",
                    os.path.join(BUILD, "list.txt"), "-c:v", "libx264", "-crf", "23", "-pix_fmt", "yuv420p",
                    "-c:a", "aac", "-b:a", "128k", "-movflags", "+faststart", OUT], check=True)
    with open(os.path.join(BUILD, "narration.txt"), "w") as fh:
        fh.write("\n\n".join(s["say"] for s in SCENES) + "\n")
    print(OUT, round(duration(OUT), 1), "s")


if __name__ == "__main__":
    main()
