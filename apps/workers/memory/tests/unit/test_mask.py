# ruff: noqa: E501 - test data tables (long literal command lines, paths and regions)
"""The secret masker (RT13): one case per pattern, the masked shape, and a benign corpus that
must come out unchanged."""

import pytest

from dataset.baselines import LINUX_HISTORY, windows_server, windows_workstation
from memory_worker.detections.mask import excerpt, mask, mask_value


def test_masked_value_keeps_two_characters_and_the_length() -> None:
    assert mask_value("P@ssw0rd12") == "P@********(10)"
    assert mask_value("abcd") == "****(4)"  # short values keep nothing
    assert mask_value("x") == "*(1)"


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("app.exe password=P@ssw0rd12 --verbose", "P@ssw0rd12"),
        ("set pwd=Sup3rSecret&& run", "Sup3rSecret"),
        ("connect passwd='quoted secret value'", "quoted secret value"),
        ('wmic /node:10.0.0.9 /user:admin /password:"Winter 2026" process list', "Winter 2026"),
        ("New-LocalUser -Name bob -Password Pa55word!x", "Pa55word!x"),
        ("mysql -u root -pHunter2pass appdb", "Hunter2pass"),
        ("mysqldump.exe -h db -uroot -pS3cr3tDump shop > shop.sql", "S3cr3tDump"),
        ("sshpass -p 'Tr0ub4dor&3' ssh root@10.0.0.31 uptime", "Tr0ub4dor&3"),
        ("sshpass -pPlainPw123 scp a b:", "PlainPw123"),
        ("net use \\\\fs01\\share /user:CORP\\alice S3cretPass! /persistent:no", "S3cretPass!"),
        ("net user bob N3wPassw0rd /add", "N3wPassw0rd"),
        ("curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig' https://x", "eyJhbGciOiJIUzI1NiJ9.e30.sig"),
        ("curl -H 'Authorization: Basic YWxpY2U6c2VjcmV0' https://x", "YWxpY2U6c2VjcmV0"),
        ("deploy --token=ghp_abcdefghijklmnop1234", "ghp_abcdefghijklmnop1234"),
        ("cli --api-key 0123456789abcdef", "0123456789abcdef"),
        ("cli --client-secret=zyxwvu987654 --secret topsecret99", "zyxwvu987654"),
        ("cli --secret topsecret99", "topsecret99"),
        ("aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
        ("export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
        ("git clone https://bob:hunter22pw@git.example.com/repo.git", "hunter22pw"),
        ("echo '-----BEGIN RSA PRIVATE KEY-----MIIEowIBAAKCAQEA7x-----END RSA PRIVATE KEY-----' > k", "MIIEowIBAAKCAQEA7x"),
        ("echo -----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXktdjE truncated", " b3BlbnNzaC1rZXktdjE truncated"),
    ],
)
def test_every_pattern_masks_its_secret(text: str, secret: str) -> None:
    masked = mask(text)
    assert secret not in masked
    assert mask_value(secret) in masked


def test_overlapping_rules_mask_once() -> None:
    assert mask("tool --password=abcdefgh") == "tool --password=ab******(8)"


def test_mask_is_deterministic_and_idempotent_on_masked_text() -> None:
    text = "mysql -u root -pHunter2pass appdb"
    assert mask(text) == mask(text)
    assert mask(mask(text)) == mask(text)


def test_excerpt_masks_before_cutting() -> None:
    text = "x" * 270 + " password=VeryLongSecretValue123"
    out = excerpt(text, 300)
    assert len(out) == 300 and out.endswith("...")
    assert "VeryLong" not in out and "password=Ve***" in out


BENIGN = [
    "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule",
    "C:\\Windows\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p -s NcbService",
    "runas /user:CORP\\admin cmd.exe",
    "ssh -p 2222 deploy@10.0.0.40",
    "export PGPASSWORD_FILE=/etc/app/pgpass",
    "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Scripts\\backup.ps1",
    "git log --oneline 3f2a9c1d4b5e6f708192a3b4c5d6e7f801234567",  # 40 hex chars: a digest
    "java -Dpassword.file=/etc/app/pw.txt -jar app.jar",
    "chrome.exe --type=renderer --field-trial-handle=1780,i,4825739011729480317,10373516233911512042,262144",
    "net use Z: \\\\fs01\\share /persistent:yes",
    "net user bob /delete",
    "cd $(pwd)/build && make -j8",
    "bypass the proxy: set NO_PROXY=localhost",
]


@pytest.mark.parametrize("text", BENIGN)
def test_benign_text_is_unchanged(text: str) -> None:
    assert mask(text) == text


def test_baseline_command_lines_are_unchanged() -> None:
    """Every command line of the benign Windows baselines and every benign history line
    survives the masker byte for byte (no false masking on realistic text)."""
    lines = [p["cmdline"] for d in (windows_workstation(), windows_server()) for p in d.processes]
    lines += [line for line in LINUX_HISTORY if "-pHunter2pass" not in line]
    for line in filter(None, lines):
        assert mask(line) == line, line
