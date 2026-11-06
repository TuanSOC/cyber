"""`heuristic:disk_double_extension@1` (medium): `name.<document ext>.<executable ext>` (spaces
before the last dot included) and names holding U+202E (right-to-left override). Name evidence:
deleted entries count too. `.lnk` is not an executable extension here: Windows names every
Recent-items shortcut `<document>.<ext>.lnk`."""

from cyberlab_jobs.disk import DiskFileRecord

from disk_worker.detections.base import (
    Context,
    FileFacts,
    Finding,
    Rule,
    directory_of,
    shown,
)
from disk_worker.detections.file_rules import file_finding

RTLO = chr(0x202E)
DOCUMENT_EXTENSIONS = frozenset(
    "pdf doc docx docm xls xlsx xlsm ppt pptx rtf txt csv odt ods odp jpg jpeg png gif bmp "
    "mp3 mp4 avi mov wav zip rar 7z htm html".split()
)
EXECUTABLE_EXTENSIONS = frozenset(
    "exe scr com pif bat cmd vbs vbe js jse wsf wsh hta ps1 msi cpl jar".split()
)
CONFIDENCE = 0.7


def _split(name: str) -> tuple[str, str] | None:
    parts = name.rsplit(".", 2)
    if len(parts) != 3 or not parts[0].strip():
        return None
    return parts[1].strip().casefold(), parts[2].strip().casefold()


class DoubleExtension(Rule):
    def check_file(self, file: DiskFileRecord, facts: FileFacts, ctx: Context) -> list[Finding]:
        if file.type == "dir" or file.stream is not None:
            return []
        name = file.name
        values: dict[str, object] = {
            "name": shown(name, 255),
            "directory": shown(directory_of(file.path)),
        }
        if RTLO in name:
            outer = name.rsplit(".", 1)[-1].casefold() if "." in name else ""
            values["outer"] = shown(outer, 32)
            return [
                file_finding(
                    "disk_rtlo_name",
                    "medium",
                    0.8,
                    file,
                    facts,
                    ctx,
                    values,
                    attributes={"name": shown(name, 255)},
                )
            ]
        split = _split(name)
        if split is None:
            return []
        inner, outer = split
        if inner not in DOCUMENT_EXTENSIONS or outer not in EXECUTABLE_EXTENSIONS:
            return []
        values.update(inner=inner, outer=outer)
        return [
            file_finding(
                "disk_double_extension",
                "medium",
                CONFIDENCE,
                file,
                facts,
                ctx,
                values,
                attributes={"name": shown(name, 255)},
            )
        ]
