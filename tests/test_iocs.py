from app.analyzers.iocs import (
    defang_email,
    defang_url,
    extract_iocs,
    valid_base58check,
    valid_bech32,
)
from tests.corpus import ioc_text


def test_extracts_every_ioc_type():
    r = extract_iocs(ioc_text().decode())
    assert "hxxp[://]update[.]evil-cdn[.]xyz/payload.bin" in r["urls"]
    assert any(u.startswith("hxxps[://]files[.]badhost[.]top") for u in r["urls"])
    assert {"value": "185[.]220[.]101[.]4", "scope": "public"} in r["ipv4"]
    assert {"value": "192[.]168[.]1[.]10", "scope": "private"} in r["ipv4"]
    assert "ops[@]ransom-group[.]ru" in r["emails"]
    assert "telemetry[.]microsoft[.]com" in r["domains"]
    assert "C:\\Users\\Public\\Libraries\\svch0st.exe" in r["windows_paths"]
    assert "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater" in r["registry_keys"]
    assert set(r["bitcoin_addresses"]) == {
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
    }


def test_network_indicators_are_never_live():
    r = extract_iocs(ioc_text().decode())
    for key in ("urls", "domains", "emails"):
        for v in r[key]:
            assert "[.]" in v or "[://]" in v
    assert all("[.]" in ip["value"] for ip in r["ipv4"])


def test_defang_helpers():
    assert defang_url("https://a.b.c/x.y") == "hxxps[://]a[.]b[.]c/x.y"
    assert defang_email("a.b@c.d") == "a.b[@]c[.]d"


def test_bitcoin_checksums():
    assert valid_base58check("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    assert not valid_base58check("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")
    assert valid_bech32("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
    assert not valid_bech32("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdx")


def test_no_false_positives_on_dll_names_and_versions():
    r = extract_iocs("loads kernel32.dll and ntdll.dll, setup.py, version 1.2.3")
    assert r["domains"] == [] and r["ipv4"] == []


def test_paths_with_spaces():
    r = extract_iocs(r"run C:\Program Files (x86)\Acme Tool\bin\acme.exe now")
    assert r["windows_paths"] == [r"C:\Program Files (x86)\Acme Tool\bin\acme.exe"]


def test_per_type_cap():
    text = " ".join(f"http://h{i}.example.com/" for i in range(500))
    assert len(extract_iocs(text)["urls"]) == 100
