"""Synthetic Linux x86-64 memory images and the ISF that describes them (M8 phase 4).

Our own work, stdlib only: no Volatility code, no data from any real kernel or image. The
generator writes a 16 MiB physical map (page tables, `linux_banner`, `init_task` and a
circular `tasks` list of `task_struct`s with mm / cred / argv) and a minimal ISF
(`cyberlab-synthetic-6.1.0.json.xz`) so that the real Volatility 3 stacks the layers, matches
the banner and runs `linux.pslist` / `linux.psaux` offline. Images are built at test time in
the test work dir, never committed and never larger than 32 MiB.

    python -m samples.memgen --scenario linux_benign --format lime --out /work/x.lime \\
        --isf-out /work/cyberlab-synthetic-6.1.0.json.xz
"""

from samples.memgen.image import LayoutFull, MemoryImage, Proc, Scenario, build
from samples.memgen.kernel import BANNER, ISF_NAME, UNKNOWN_BANNER, isf, isf_json, isf_xz
from samples.memgen.scenarios import SCENARIOS, scenario
from samples.memgen.wrappers import FORMATS, wrap

MAX_IMAGE_BYTES = 32 * 1024**2


def image_bytes(name: str, fmt: str = "raw") -> bytes:
    """One scenario's image in one container format."""
    data = wrap(build(scenario(name)), fmt)
    if len(data) > MAX_IMAGE_BYTES:  # pragma: no cover - the layout is 16 MiB
        raise LayoutFull("a synthetic image must stay within 32 MiB")
    return data


__all__ = [
    "BANNER",
    "FORMATS",
    "ISF_NAME",
    "MAX_IMAGE_BYTES",
    "SCENARIOS",
    "UNKNOWN_BANNER",
    "LayoutFull",
    "MemoryImage",
    "Proc",
    "Scenario",
    "build",
    "image_bytes",
    "isf",
    "isf_json",
    "isf_xz",
    "scenario",
    "wrap",
]
