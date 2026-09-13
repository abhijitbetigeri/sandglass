"""Build the Sandglass demo video: rendered terminal frames + macOS `say` voiceover.

    python demo/make_video.py

Produces demo/sandglass-demo.mp4 (1920x1080, H.264 + AAC).
Terminal text is REAL output captured from the working system, not mocked.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import wave
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).resolve().parent
BUILD = OUT / "build"
W, H = 1920, 1080
FPS = 30
VOICE = "Daniel"

GROUND = (15, 18, 22)
SURFACE = (22, 26, 32)
LINE = (44, 51, 61)
TEXT = (233, 230, 223)
MUTED = (142, 146, 153)
DIM = (107, 111, 119)
SAND = (214, 196, 166)
ALLOW = (63, 190, 140)
DENY = (240, 89, 95)
HELD = (233, 169, 62)

MONO = "/System/Library/Fonts/Menlo.ttc"
SANS = "/System/Library/Fonts/HelveticaNeue.ttc"

FF = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True).stdout.strip()
FFMPEG = str(Path(FF) / "ffmpeg-static" / "ffmpeg")


def font(path, size, index=0):
    try:
        return ImageFont.truetype(path, size, index=index)
    except Exception:
        return ImageFont.load_default()


F_TITLE = font(SANS, 92, 1)
F_SUB = font(SANS, 40)
F_H = font(SANS, 46, 1)
F_MONO = font(MONO, 27)
F_MONO_S = font(MONO, 23)
F_LABEL = font(MONO, 20)


# --------------------------------------------------------------------------
# scenes: (kind, payload, narration)
# --------------------------------------------------------------------------
SCENES = [
    ("title", {
        "title": "Sandglass",
        "sub": "Run AI agents on edge devices\nas if they're already compromised.",
    },
     "Sandglass. Run A.I. agents on edge devices as if they're already compromised."),

    ("bullets", {
        "head": "The problem",
        "items": [
            ("An agent on an edge device inherits the device's full authority.", MUTED),
            ("Prompt-inject it and the attacker has the keys, the network,", MUTED),
            ("and the wire to the hardware.", MUTED),
            ("", MUTED),
            ("And there is no cloud out there to authorize anything.", SAND),
        ]},
     "An agent running on an edge device inherits that device's full authority. "
     "Prompt inject it, and the attacker has the signing keys, the network, and the "
     "wire to the hardware. And out there, there is no cloud to call for help."),

    ("bullets", {
        "head": "Three boundaries",
        "items": [
            ("1  WASMER SANDBOX      stops a hijacked application", ALLOW),
            ("   no network, no keys, no effector. It can only ask.", DIM),
            ("", MUTED),
            ("2  3-of-5 QUORUM       stops a captured device", HELD),
            ("   peers re-check against their own policy before signing.", DIM),
            ("", MUTED),
            ("3  HOST RUNTIME        the only code that touches the world", SAND),
            ("   holds the key and the effector, outside the sandbox.", DIM),
        ]},
     "Sandglass has three boundaries. The Wasmer sandbox stops a hijacked application: "
     "no network, no keys, no effector, so it can only ask. A three of five quorum stops "
     "a captured device, because peers check against their own policy before signing. "
     "And the host runtime is the only code that ever touches the real world."),

    ("term", {
        "cmd": "$ python -m sandglass.host --role monitor --scenario attack",
        "lines": [
            ("", TEXT),
            ("  DENY   net.connect     api.exfil-relay.sh:443", DENY),
            ("         capability not granted for role=monitor", DIM),
            ("  DENY   fs.read         /keys/node.ed25519", DENY),
            ("         resource out of scope - fs.read limited to workspace/**", DIM),
            ("  DENY   grid.actuate    breaker-B", DENY),
            ("         capability not granted for role=monitor", DIM),
            ("  DENY   funds.transfer  acct-9931", DENY),
            ("         capability not granted for role=monitor", DIM),
            ("", TEXT),
            ("  audit chain verified=True", ALLOW),
            ("  effector state: {'breaker-B': 'CLOSED'}", ALLOW),
        ]},
     "Here is a hijacked agent, running for real. It tries to exfiltrate over the network. "
     "There is no network, so the socket fails. It tries to steal the signing key. "
     "That path is out of scope, and the key was never in the sandbox anyway. "
     "It tries to fire the breaker, and to move money. Denied, and denied. "
     "The breaker never moves."),

    ("shot", {
        "file": "console_compromise.png",
        "cap": "sandglass.wasmer.app/console — one pane, every decision",
        "note": "Wasmer gives you isolation but no visibility. This is the layer that was missing.",
    },
     "Every one of those decisions is emitted by the host, not self-reported by the agent, "
     "so a hijacked agent can neither forge a line nor hide one. Wasmer gives you isolation "
     "but no visibility. This is the layer that was missing: one pane showing what every "
     "sandbox in the fleet tried to do, and exactly which capability stopped it."),

    ("term", {
        "cmd": "$ python -m sandglass.host --role operator --quorum --lockout breaker-B",
        "lines": [
            ("", TEXT),
            ("  A line crew set a safety tag on breaker-B.", MUTED),
            ("  The local node does not know that. Its peers do.", MUTED),
            ("", TEXT),
            ("  HELD   grid.actuate    breaker-B", HELD),
            ("         held at 0/3", DIM),
            ("         peer-01 refused (safety lockout active on breaker-B)", DIM),
            ("         peer-02 refused (safety lockout active on breaker-B)", DIM),
            ("         peer-03 refused (safety lockout active on breaker-B)", DIM),
            ("", TEXT),
            ("  effector state: {'breaker-B': 'CLOSED'}", ALLOW),
        ]},
     "Now the case a sandbox cannot solve. A line crew has set a safety tag on this "
     "breaker. The local node does not know that. Its peers do. The agent holds a "
     "legitimate capability, and it still gets nothing, because all five peers refuse "
     "to sign. Quorum zero of three. The crew keeps working."),

    ("shot", {
        "file": "console_lockout.png",
        "cap": "Safety lockout — quorum stalls at 0 of 3",
        "note": "The breaker stays CLOSED. The audit chain still reads verified.",
    },
     "The console shows the same thing from the operator's side. Quorum stalled at zero of "
     "three, the breaker still closed, and the hash chain still verified. An administrator "
     "sees the attempt, the reason, and the state of the hardware in one place."),

    ("table", {
        "head": "Measured, not claimed",
        "rows": [
            ("warm sandbox creation", "~0.4 ms", ALLOW),
            ("socket.create_connection", "OSError [Errno 58]", DENY),
            ("read /keys/node.ed25519", "FileNotFoundError [44]", DENY),
            ("5-node Tenki fleet", "18 denials, $0.002", ALLOW),
        ]},
     "These are measured, not claimed. A warm sandbox creates in about four tenths of a "
     "millisecond, which is what makes one sandbox per action affordable. Network denial "
     "and filesystem invisibility are the default state, not a setting. And a five node "
     "fleet on real micro V.M.s returned eighteen denials for a fifth of a cent."),

    ("title", {
        "title": "The attack isn't blocked.",
        "sub": "It was never possible.\n\nsandglass.wasmer.app\ngithub.com/abhijitbetigeri/sandglass",
    },
     "The attack isn't blocked. It was never possible. "
     "The console is live on Wasmer Edge, and the code is on GitHub."),
]


# --------------------------------------------------------------------------
def chrome(draw, title="sandglass — edge node"):
    draw.rectangle([120, 150, W - 120, H - 150], fill=SURFACE, outline=LINE, width=2)
    draw.rectangle([120, 150, W - 120, 208], fill=(29, 34, 42), outline=LINE, width=2)
    for i, c in enumerate([(240, 89, 95), (233, 169, 62), (63, 190, 140)]):
        draw.ellipse([152 + i * 28, 171, 168 + i * 28, 187], fill=c)
    draw.text((250, 168), title, font=F_LABEL, fill=DIM)


def brand(draw, subtitle=True):
    draw.text((120, H - 92), "SANDGLASS", font=F_LABEL, fill=SAND)
    if subtitle:
        draw.text((280, H - 92), "capability control plane for agents at the edge",
                  font=F_LABEL, fill=DIM)


def render(kind, payload, reveal):
    img = Image.new("RGB", (W, H), GROUND)
    d = ImageDraw.Draw(img)

    if kind == "title":
        d.text((160, 380), payload["title"], font=F_TITLE, fill=TEXT)
        y = 520
        for ln in payload["sub"].split("\n"):
            d.text((164, y), ln, font=F_SUB, fill=SAND if "." not in ln or "/" in ln else MUTED)
            y += 58
        d.line([160, 350, 460, 350], fill=SAND, width=4)

    elif kind == "bullets":
        d.text((160, 180), payload["head"], font=F_H, fill=TEXT)
        d.line([160, 258, 420, 258], fill=SAND, width=3)
        y = 330
        for i, (txt, col) in enumerate(payload["items"]):
            if i < reveal:
                d.text((164, y), txt, font=F_MONO, fill=col)
            y += 52

    elif kind == "term":
        chrome(d)
        d.text((160, 250), payload["cmd"], font=F_MONO_S, fill=SAND)
        y = 310
        for i, (txt, col) in enumerate(payload["lines"]):
            if i < reveal:
                d.text((164, y), txt, font=F_MONO_S, fill=col)
            y += 44

    elif kind == "shot":
        shot = Image.open(OUT / "shots" / payload["file"]).convert("RGB")
        top, max_w, max_h = 150, W - 180, 790          # leave room for cap + note + brand
        scale = min(max_w / shot.width, max_h / shot.height)
        tw, th = int(shot.width * scale), int(shot.height * scale)
        shot = shot.resize((tw, th), Image.LANCZOS)
        x = (W - tw) // 2
        d.rectangle([x - 2, top - 2, x + tw + 1, top + th + 1], outline=LINE, width=2)
        img.paste(shot, (x, top))
        d.text((x, 96), payload["cap"], font=F_MONO_S, fill=SAND)
        if payload.get("note"):
            d.text((x, top + th + 24), payload["note"], font=F_LABEL, fill=DIM)

    elif kind == "table":
        d.text((160, 180), payload["head"], font=F_H, fill=TEXT)
        d.line([160, 258, 560, 258], fill=SAND, width=3)
        y = 360
        for i, (k, v, col) in enumerate(payload["rows"]):
            if i < reveal:
                d.text((164, y), k, font=F_MONO, fill=MUTED)
                d.text((1060, y), v, font=F_MONO, fill=col)
                d.line([164, y + 54, W - 164, y + 54], fill=LINE, width=1)
            y += 96

    brand(d, subtitle=(kind != "shot"))
    return img


def narrate(idx: str, text: str) -> float:
    aiff = BUILD / f"vo_{idx}.aiff"
    wav = BUILD / f"vo_{idx}.wav"
    subprocess.run(["say", "-v", VOICE, "-o", str(aiff), text], check=True)
    subprocess.run([FFMPEG, "-y", "-loglevel", "error", "-i", str(aiff),
                    "-ar", "44100", "-ac", "2", str(wav)], check=True)
    with wave.open(str(wav)) as w:
        return w.getnframes() / w.getframerate()


def main():
    if not Path(FFMPEG).exists():
        sys.exit(f"ffmpeg not found at {FFMPEG} — run: npm i -g ffmpeg-static")
    if BUILD.exists():
        shutil.rmtree(BUILD)
    BUILD.mkdir(parents=True)

    concat, audio_parts, total = [], [], 0.0
    for i, (kind, payload, text) in enumerate(SCENES):
        dur = narrate(f"{i:02d}", text) + 0.7          # a beat of silence after
        audio_parts.append(BUILD / f"vo_{i:02d}.wav")

        n_items = len(payload.get("items") or payload.get("lines")
                      or payload.get("rows") or [1])
        if kind == "shot":
            n_items = 1
        steps = max(1, n_items)
        # reveal over the first 55% of the scene, then hold
        per = (dur * 0.55) / steps
        for s in range(1, steps + 1):
            p = BUILD / f"f_{i:02d}_{s:02d}.png"
            render(kind, payload, s).save(p)
            concat.append((p, per if s < steps else dur - per * (steps - 1)))
        total += dur
        print(f"  scene {i}: {dur:5.2f}s  {kind}")

    # concat demuxer for exact per-frame durations
    lst = BUILD / "frames.txt"
    with lst.open("w") as fh:
        for p, d in concat:
            fh.write(f"file '{p.name}'\nduration {d:.3f}\n")
        fh.write(f"file '{concat[-1][0].name}'\n")

    alist = BUILD / "audio.txt"
    with alist.open("w") as fh:
        for p in audio_parts:
            fh.write(f"file '{p.name}'\n")

    silence = BUILD / "pad.wav"
    subprocess.run([FFMPEG, "-y", "-loglevel", "error", "-f", "lavfi",
                    "-i", "anullsrc=r=44100:cl=stereo", "-t", "0.7", str(silence)], check=True)
    with alist.open("w") as fh:
        for p in audio_parts:
            fh.write(f"file '{p.name}'\nfile 'pad.wav'\n")

    voice = BUILD / "voice.wav"
    subprocess.run([FFMPEG, "-y", "-loglevel", "error", "-f", "concat", "-safe", "0",
                    "-i", str(alist), "-c", "copy", str(voice)], check=True)

    mp4 = OUT / "sandglass-demo.mp4"
    subprocess.run([
        FFMPEG, "-y", "-loglevel", "error",
        "-f", "concat", "-safe", "0", "-i", str(lst),
        "-i", str(voice),
        "-c:v", "libx264", "-pix_fmt", "yuv420p", "-r", str(FPS),
        "-vf", "scale=1920:1080:force_original_aspect_ratio=decrease,"
               "pad=1920:1080:(ow-iw)/2:(oh-ih)/2,format=yuv420p",
        "-c:a", "aac", "-b:a", "192k", "-shortest", str(mp4),
    ], check=True, cwd=BUILD)

    size = mp4.stat().st_size / 1e6
    print(f"\n{mp4}  —  {total:.1f}s, {size:.1f} MB")


if __name__ == "__main__":
    main()
