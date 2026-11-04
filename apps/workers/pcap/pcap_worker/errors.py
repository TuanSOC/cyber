class JobFailed(Exception):
    """Terminal job failure with a stable error code reported to ingest."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
