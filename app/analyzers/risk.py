"""Turn analyzer output into an explained 0-100 risk score.

Each finding carries a severity with a fixed weight. The score is the sum of
weights, capped at 100, so every point on the final number can be traced back
to a line in the findings list.
"""

from __future__ import annotations

WEIGHTS = {"critical": 45, "high": 25, "medium": 12, "low": 4, "info": 0}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_EXEC_EXTS = {
    "exe",
    "scr",
    "dll",
    "js",
    "jse",
    "vbs",
    "vbe",
    "wsf",
    "lnk",
    "hta",
    "bat",
    "cmd",
    "ps1",
    "jar",
    "msi",
    "iso",
    "com",
    "pif",
    "cpl",
}


def level_for(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 45:
        return "high"
    if score >= 20:
        return "medium"
    if score >= 5:
        return "low"
    return "clean"


class Findings:
    def __init__(self) -> None:
        self.items: list[dict] = []

    def add(self, fid: str, severity: str, title: str, detail: str = "", category: str = "general") -> None:
        self.items.append({"id": fid, "severity": severity, "title": title, "detail": detail,
                           "category": category, "weight": WEIGHTS[severity]})  # fmt: skip


def _pdf_findings(f: Findings, pdf: dict) -> None:
    kw = pdf["keywords"]
    js = kw["JavaScript"] + kw["JS"]
    auto = kw["OpenAction"] + kw["AA"]
    if js and auto:
        f.add(
            "pdf.js_autorun",
            "high",
            "JavaScript that runs on open",
            f"{js} JavaScript reference(s) plus {auto} automatic action(s) (/OpenAction or /AA)",
            "pdf",
        )
    elif js:
        f.add("pdf.javascript", "medium", "Embedded JavaScript", f"{js} /JavaScript or /JS name(s)", "pdf")
    elif auto:
        f.add("pdf.autoaction", "low", "Automatic action on open", f"{auto} /OpenAction or /AA", "pdf")
    if kw["Launch"]:
        f.add("pdf.launch", "high", "Launch action", "/Launch can start external programs", "pdf")
    if kw["EmbeddedFile"] or kw["EmbeddedFiles"]:
        f.add(
            "pdf.embedded_file", "medium", "Embedded file attachment", "the PDF carries another file inside it", "pdf"
        )
    if kw["XFA"] or kw["RichMedia"]:
        f.add("pdf.active_content", "medium", "XFA forms or RichMedia", "complex active content", "pdf")
    if kw["SubmitForm"] or kw["ImportData"] or kw["GoToR"] or kw["GoToE"]:
        f.add(
            "pdf.remote_actions",
            "low",
            "Form submission / remote go-to actions",
            "can send data out or open other documents",
            "pdf",
        )
    if pdf["obfuscated_names"]:
        f.add(
            "pdf.obfuscated_names",
            "high",
            "Hex-obfuscated PDF names",
            "names like /J#61vaScript are written to dodge naive scanners: "
            + ", ".join(sorted(pdf["obfuscated_names"])),
            "pdf",
        )
    if pdf["incremental_updates"]:
        f.add(
            "pdf.incremental",
            "info",
            "Incremental updates",
            f"{pdf['incremental_updates']} revision(s) appended after the original save",
            "pdf",
        )
    if pdf["header_offset"] and pdf["header_offset"] > 0:
        f.add(
            "pdf.header_offset",
            "medium",
            "PDF header not at offset 0",
            f"%PDF- found at byte {pdf['header_offset']}; common in polyglot tricks",
            "pdf",
        )
    if kw["URI"]:
        f.add("pdf.uri", "info", "Links", f"{kw['URI']} /URI action(s)", "pdf")
    if pdf["encrypted"]:
        f.add("pdf.encrypted", "info", "Encrypted PDF", "content streams could not be inspected", "pdf")


def _office_findings(f: Findings, office: dict) -> None:
    if office.get("container") == "ooxml":
        if office.get("macros"):
            f.add("office.macros", "high", "VBA macros present", ", ".join(office["macros"][:3]), "office")
        elif office.get("macro_enabled_content_type"):
            f.add("office.macro_content_type", "medium", "Macro-enabled content type", "", "office")
        if office.get("template_injection"):
            f.add(
                "office.template_injection",
                "critical",
                "Remote template injection",
                "attachedTemplate relationship points outside the document",
                "office",
            )
        for rel in office.get("external_relationships", []):
            if rel["kind"] in ("template_injection", "hyperlink"):
                continue
            f.add(
                "office.external_rel", rel["severity"], f"External relationship: {rel['kind']}", rel["target"], "office"
            )
        links = sum(1 for r in office.get("external_relationships", []) if r["kind"] == "hyperlink")
        if links:
            f.add("office.hyperlinks", "info", "External hyperlinks", f"{links} link(s)", "office")
        if office.get("dde"):
            f.add("office.dde", "high", "DDE field", "Dynamic Data Exchange can run commands", "office")
        if office.get("activex"):
            f.add("office.activex", "medium", "ActiveX controls", f"{len(office['activex'])} part(s)", "office")
        if office.get("embedded_objects"):
            f.add("office.embedded", "low", "Embedded objects", ", ".join(office["embedded_objects"][:3]), "office")
    elif office.get("container") == "ole":
        if office.get("has_macros"):
            f.add(
                "office.ole_macros",
                "high",
                "VBA macro storage in legacy document",
                ", ".join(office["macros"]),
                "office",
            )
        if office.get("embedded_ole_native"):
            f.add(
                "office.ole_native",
                "medium",
                "Embedded Ole10Native package",
                "a packaged file is embedded in the document",
                "office",
            )
        if office.get("encrypted_package"):
            f.add(
                "office.encrypted",
                "low",
                "Password-protected Office file",
                "encrypted documents hide their content from scanners",
                "office",
            )


def build_risk(report: dict) -> dict:
    f = Findings()
    t = report["type"]
    mm = report["mismatch"]

    if mm["mismatch"] or mm["double_extension"] or mm["severity"] != "info":
        title = "Deceptive double extension" if mm["double_extension"] else "Extension does not match content"
        f.add("type.mismatch", mm["severity"], title, mm["reason"], "identity")
    if t["category"] == "executable":
        f.add("type.executable", "medium", "Executable content", t["label"], "identity")
    elif t["category"] == "script":
        f.add("type.script", "low", "Script content", t["label"], "identity")

    ent = report["entropy"]
    if ent.get("likely_packed_or_encrypted"):
        f.add(
            "entropy.high",
            "medium",
            "High entropy",
            f"overall {ent['overall']:.2f} bits/byte; "
            f"{ent['high_blocks']} of {len(ent['blocks'])} blocks above {ent['high_threshold']}",
            "entropy",
        )

    pe = report.get("pe")
    if pe:
        if pe["packer_hints"]:
            f.add("pe.packer", "high", "Packer section names", ", ".join(pe["packer_hints"]), "pe")
        if pe["wx_sections"]:
            f.add("pe.wx", "medium", "Writable + executable sections", ", ".join(pe["wx_sections"]), "pe")
        if pe["overlay_size"]:
            f.add("pe.overlay", "low", "Overlay data", f"{pe['overlay_size']} bytes after the last section", "pe")

    strings = report["strings"]
    if strings["suspicious"]:
        n = len(strings["suspicious"])
        sev = "high" if n >= 4 else "medium" if n >= 2 else "low"
        f.add(
            "strings.suspicious",
            sev,
            "Suspicious API / command strings",
            ", ".join(s["token"] for s in strings["suspicious"][:6]),
            "strings",
        )
    iocs = report["iocs"]["counts"]
    if iocs["bitcoin_addresses"]:
        f.add("ioc.bitcoin", "medium", "Bitcoin address", "often seen in ransom notes and extortion", "ioc")
    public_ips = sum(1 for ip in report["iocs"]["ipv4"] if ip["scope"] == "public")
    if public_ips:
        f.add("ioc.ip", "low", "Hard-coded public IP addresses", f"{public_ips} address(es)", "ioc")
    if iocs["urls"]:
        f.add("ioc.urls", "info", "URLs found", f"{iocs['urls']} URL(s), defanged in report", "ioc")
    if iocs["registry_keys"]:
        persistence = any("\\run" in k.lower() for k in report["iocs"]["registry_keys"])
        f.add(
            "ioc.registry",
            "medium" if persistence else "low",
            "Registry paths" + (" (Run key persistence)" if persistence else ""),
            f"{iocs['registry_keys']} key(s)",
            "ioc",
        )

    img = report.get("image")
    if img:
        if img.get("bomb"):
            f.add("image.bomb", "high", "Decompression bomb", "pixel count exceeds the safety limit", "image")
        if img.get("gps"):
            g = img["gps"]
            f.add(
                "image.gps",
                "medium",
                "GPS location embedded",
                f"{g['latitude']}, {g['longitude']} - a privacy leak if shared",
                "image",
            )
        if img.get("edited_with"):
            f.add("image.edited", "info", "Edited with image software", str(img["edited_with"]), "image")
        if img.get("modified_after_capture"):
            f.add(
                "image.modified",
                "info",
                "Modified after capture",
                "EXIF DateTime is later than DateTimeOriginal",
                "image",
            )

    if report.get("pdf"):
        _pdf_findings(f, report["pdf"])
    if report.get("office"):
        _office_findings(f, report["office"])

    arc = report.get("archive")
    if arc:
        if arc["bomb_indicators"]:
            f.add("archive.bomb", "high", "Decompression bomb indicators", "; ".join(arc["bomb_indicators"]), "archive")
        if arc["encrypted_entries"]:
            f.add(
                "archive.encrypted",
                "low",
                "Password-protected entries",
                f"{arc['encrypted_entries']} entr(ies) can't be inspected",
                "archive",
            )
        risky = [e["name"] for e in arc["entries"] if e["name"].lower().rsplit(".", 1)[-1] in _EXEC_EXTS]
        if risky:
            f.add(
                "archive.executables", "medium", "Executable or script inside archive", ", ".join(risky[:5]), "archive"
            )

    app = report["appended"]
    if app["appended_type"] and app["appended_type"] != "text":
        f.add(
            "polyglot.appended",
            "high",
            "Polyglot: second file appended",
            f"{app['appended_label']} starts at byte {app['logical_end']} after the end of the "
            f"{t['label']}"
            + (f"; contains {', '.join(app['appended_entries'][:5])}" if app.get("appended_entries") else ""),
            "structure",
        )
        hidden_exec = [n for n in app.get("appended_entries", []) if n.lower().rsplit(".", 1)[-1] in _EXEC_EXTS]
        if hidden_exec:
            f.add(
                "polyglot.hidden_executable",
                "high",
                "Executable inside the appended archive",
                ", ".join(hidden_exec[:5]),
                "structure",
            )
    elif app["appended_bytes"] and not app["padding_only"]:
        sev = "medium" if app["appended_bytes"] > 1024 else "low"
        f.add(
            "structure.appended",
            sev,
            "Data after end of file",
            f"{app['appended_bytes']} bytes after logical end at {app['logical_end']}",
            "structure",
        )
    if app["prepended_bytes"]:
        f.add(
            "structure.prepended",
            "high",
            "Data before archive start",
            f"{app['prepended_bytes']} bytes precede the first ZIP header",
            "structure",
        )
    embedded_exec = [e for e in app["embedded"] if e["kind"] in ("exe", "elf")]
    if embedded_exec and t["id"] not in ("exe", "dll"):
        f.add(
            "structure.embedded_exec",
            "high",
            "Embedded executable",
            f"{embedded_exec[0]['label']} at byte {embedded_exec[0]['offset']}",
            "structure",
        )
    elif embedded_exec:
        f.add(
            "structure.embedded_exec",
            "medium",
            "Executable embedded inside executable",
            f"{len(embedded_exec)} hit(s); dropper behaviour or resources",
            "structure",
        )

    if report.get("analysis_incomplete"):
        f.add(
            "analysis.partial",
            "low",
            "Analysis hit a time or size cap",
            "some checks stopped early; treat the result as partial",
            "general",
        )

    items = sorted(f.items, key=lambda x: SEVERITY_ORDER.index(x["severity"]))
    score = min(100, sum(i["weight"] for i in items))
    return {"score": score, "level": level_for(score), "findings": items}
