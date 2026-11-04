"""Test-only stand-in for `static_worker.probe`: reports the cwd it was started in.

Run by tests/integration (`run_probe` with MODULE patched) as the tool uid; prints one
contract-valid `string` record so the result travels the normal probe output path.
"""

import json
import os

print(json.dumps({"kind": "string", "value": os.getcwd(), "encoding": "ascii"}))
