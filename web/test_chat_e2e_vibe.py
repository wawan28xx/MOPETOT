"""E2E smoke test: satu panggilan vibe CLI beneran via modul chat."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import chat

cfg = chat.get_llm_config()
print("provider:", cfg["provider"], "| model:", cfg["model"], "| configured:", cfg["configured"])
assert cfg["configured"], "vibe CLI tidak terdeteksi"

reply = chat.ask_assistant(
    None, None, [],
    "Balas PERSIS dengan satu kata: PONG (jangan gunakan tools apa pun)."
)
print("reply:", reply[:200])
print("E2E VIBE OK")
