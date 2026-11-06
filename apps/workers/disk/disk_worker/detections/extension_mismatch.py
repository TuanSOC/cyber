"""`heuristic:disk_extension_mismatch@1` (medium): PE / ELF content under a data extension
(`.jpg`, `.txt`, `.dat`, ...). Executable-ish extensions (`.tmp`, `.mui`, `.bin`, no extension)
are not data extensions: installers and resource files use them legitimately."""

from cyberlab_jobs.disk import DiskFileRecord

from disk_worker.detections.base import Context, FileFacts, Finding, Rule, shown
from disk_worker.detections.file_rules import EXEC_MAGIC, MAGIC_LABEL, file_finding, size_text

DATA_EXTENSIONS = frozenset(
    "jpg jpeg png gif bmp txt log dat doc docx xls xlsx ppt pptx pdf rtf csv mp3 mp4 avi mov "
    "wav ini xml json htm html".split()
)
CONFIDENCE = 0.7


def extension(file: DiskFileRecord) -> str | None:
    ext = (
        file.ext
        if file.ext is not None
        else (file.name.rsplit(".", 1)[-1] if "." in file.name else None)
    )
    return ext.strip().casefold() if ext else None


class ExtensionMismatch(Rule):
    def check_file(self, file: DiskFileRecord, facts: FileFacts, ctx: Context) -> list[Finding]:
        if file.type != "reg" or file.stream is not None or file.magic not in EXEC_MAGIC:
            return []
        ext = extension(file)
        if ext not in DATA_EXTENSIONS:
            return []
        return [
            file_finding(
                "disk_extension_mismatch",
                "medium",
                CONFIDENCE,
                file,
                facts,
                ctx,
                {
                    "path": shown(file.path),
                    "size": size_text(file),
                    "magic": MAGIC_LABEL[file.magic or "pe"],
                    "ext": ext,
                },
                attributes={"ext": ext},
            )
        ]
