// FileForensics UI.
// Rule for this file: anything derived from the uploaded file is written with
// textContent or element attributes we control. No innerHTML, no eval, no inline
// handlers; the CSP (with Trusted Types) would block them anyway.

"use strict";

(function () {
  const $ = (id) => document.getElementById(id);
  let maxBytes = 15 * 1024 * 1024;
  let lastReport = null;

  // ------------------------------------------------------------ helpers

  function el(tag, opts, children) {
    const node = document.createElement(tag);
    if (opts) {
      if (opts.cls) node.className = opts.cls;
      if (opts.text !== undefined && opts.text !== null) node.textContent = String(opts.text);
      if (opts.attrs) for (const [k, v] of Object.entries(opts.attrs)) node.setAttribute(k, String(v));
    }
    if (children) for (const c of children) if (c) node.appendChild(c);
    return node;
  }

  function clear(node) { node.replaceChildren(); }

  function fmtBytes(n) {
    if (n < 1024) return n + " B";
    const units = ["KB", "MB", "GB"];
    let v = n / 1024, i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return v.toFixed(v < 10 ? 2 : 1) + " " + units[i] + " (" + n.toLocaleString() + " bytes)";
  }

  function kv(dl, rows) {
    clear(dl);
    for (const [k, v] of rows) {
      if (v === null || v === undefined || v === "") continue;
      dl.appendChild(el("dt", { text: k }));
      dl.appendChild(v instanceof Node ? el("dd", null, [v]) : el("dd", { text: v }));
    }
  }

  function setStatus(msg, kind) {
    const s = $("status");
    s.textContent = msg || "";
    s.classList.toggle("is-error", kind === "error");
    s.classList.toggle("is-busy", kind === "busy");
  }

  function safeLink(url, label) {
    // Only ever link to OpenStreetMap; the URL is rebuilt from numbers, not taken from the file.
    const a = el("a", { text: label, attrs: { href: url, rel: "noopener noreferrer", target: "_blank" } });
    return a;
  }

  // ------------------------------------------------------------ clock / limits

  function tick() {
    const d = new Date();
    $("clock").textContent = d.toISOString().slice(11, 19) + " UTC";
  }
  tick();
  setInterval(tick, 1000);

  fetch("/api/limits", { headers: { Accept: "application/json" } })
    .then((r) => (r.ok ? r.json() : null))
    .then((j) => {
      if (j && Number.isFinite(j.max_upload_bytes)) {
        maxBytes = j.max_upload_bytes;
        $("limits").textContent = "max " + Math.round(maxBytes / 1048576) + " MB · one file · not stored";
      }
    })
    .catch(() => {});

  // ------------------------------------------------------------ upload

  const drop = $("dropzone");
  const input = $("file-input");

  ["dragenter", "dragover"].forEach((ev) =>
    drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("is-over"); }));
  ["dragleave", "drop"].forEach((ev) =>
    drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("is-over"); }));
  drop.addEventListener("drop", (e) => {
    const files = e.dataTransfer && e.dataTransfer.files;
    if (files && files.length) submit(files[0]);
  });
  input.addEventListener("change", () => { if (input.files.length) submit(input.files[0]); });
  // Stop a file dropped outside the bag from navigating the tab to it.
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("drop", (e) => e.preventDefault());

  async function submit(file) {
    if (file.size > maxBytes) {
      setStatus("That file is " + fmtBytes(file.size) + ". The limit is " + Math.round(maxBytes / 1048576) + " MB.", "error");
      return;
    }
    if (file.size === 0) { setStatus("That file is empty.", "error"); return; }
    setStatus("Logging " + file.name + " into evidence and examining", "busy");
    drop.setAttribute("aria-busy", "true");
    const body = new FormData();
    body.append("file", file, file.name);
    try {
      const res = await fetch("/api/analyze", { method: "POST", body, headers: { Accept: "application/json" } });
      let data = null;
      try { data = await res.json(); } catch (_) { data = null; }
      if (!res.ok) {
        const msg = data && data.error && data.error.message ? data.error.message : "Analysis failed (HTTP " + res.status + ").";
        setStatus(msg, "error");
        return;
      }
      lastReport = data;
      render(data);
      setStatus("Examination complete in " + Math.round(data.timings_ms.total) + " ms.");
      $("report").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (_) {
      setStatus("Could not reach the server.", "error");
    } finally {
      drop.removeAttribute("aria-busy");
      input.value = "";
    }
  }

  $("btn-reset").addEventListener("click", () => {
    $("report").hidden = true;
    lastReport = null;
    setStatus("");
    window.scrollTo({ top: 0, behavior: "smooth" });
    input.focus();
  });

  $("btn-download").addEventListener("click", () => {
    if (!lastReport) return;
    const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = el("a", { attrs: { href: url, download: "fileforensics-" + lastReport.hashes.sha256.slice(0, 16) + ".json" } });
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });

  // ------------------------------------------------------------ render

  function render(r) {
    $("report").hidden = false;

    $("t-case").textContent = r.case_id;
    $("t-name").textContent = r.file.name;
    $("t-size").textContent = fmtBytes(r.file.size);
    $("t-sha").textContent = r.hashes.sha256;
    $("t-time").textContent = r.analyzed_at.replace("T", " ").replace("+00:00", " UTC");
    $("t-tool").textContent = r.tool.name + " v" + r.tool.version;

    const stamp = $("stamp");
    stamp.className = "stamp lvl-" + r.risk.level;
    $("stamp-score").textContent = r.risk.score;
    $("stamp-level").textContent = r.risk.level;
    $("verdict-type").textContent = r.type.label + (r.mismatch.mismatch ? " (extension says otherwise)" : "");

    renderFindings(r.risk.findings);
    renderIdent(r);
    renderHashes(r.hashes);
    renderHex(r.hex_preview.hex, r.type.magic_offset, r.type.magic_length);
    renderEntropy(r.entropy);
    renderStrings(r.strings, r.iocs);
    renderImage(r.image);
    renderPdf(r.pdf);
    renderOffice(r.office, r.archive);
    renderStructure(r);
  }

  function renderFindings(items) {
    const list = $("findings");
    clear(list);
    $("findings-empty").hidden = items.length > 0;
    for (const f of items) {
      list.appendChild(el("li", { cls: "finding sev-" + f.severity }, [
        el("span", { cls: "sev", text: f.severity }),
        el("div", null, [
          el("div", { cls: "finding__title", text: f.title }),
          f.detail ? el("div", { cls: "finding__detail", text: f.detail }) : null,
        ]),
        el("span", { cls: "finding__pts", text: "+" + f.weight }),
      ]));
    }
  }

  function renderIdent(r) {
    const m = r.mismatch;
    kv($("ident"), [
      ["Detected", r.type.label],
      ["MIME", r.type.mime],
      ["Category", r.type.category],
      ["Confidence", r.type.confidence],
      ["Claimed ext.", m.claimed_extension ? "." + m.claimed_extension : "(none)"],
      ["Expected ext.", r.type.extensions.length ? r.type.extensions.map((e) => "." + e).join(" ") : "-"],
      ["Verdict", (m.mismatch ? "MISMATCH · " : "") + m.severity.toUpperCase() + " · " + m.reason],
    ]);
    const ev = $("ident-evidence");
    clear(ev);
    for (const e of r.type.evidence) ev.appendChild(el("li", { text: e }));
  }

  function renderHashes(h) {
    const tbody = $("hashes").tBodies[0];
    clear(tbody);
    for (const algo of ["md5", "sha1", "sha256"]) {
      const btn = el("button", { cls: "btn btn--ghost btn--tiny", text: "copy", attrs: { type: "button" } });
      btn.addEventListener("click", () => {
        if (navigator.clipboard) navigator.clipboard.writeText(h[algo]).then(() => {
          btn.textContent = "copied";
          setTimeout(() => (btn.textContent = "copy"), 1200);
        }).catch(() => {});
      });
      tbody.appendChild(el("tr", null, [
        el("th", { text: algo.toUpperCase(), attrs: { scope: "row" } }),
        el("td", { text: h[algo] }),
        el("td", null, [btn]),
      ]));
    }
  }

  function renderHex(hex, magicOff, magicLen) {
    const box = $("hex");
    clear(box);
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.slice(i, i + 2), 16));
    const isMagic = (i) => magicLen > 0 && i >= magicOff && i < magicOff + magicLen;
    for (let row = 0; row < bytes.length; row += 16) {
      const hexSpan = el("span", { cls: "hex__bytes" });
      const ascii = el("span", { cls: "hex__ascii" });
      for (let i = row; i < row + 16; i++) {
        if (i === row + 8) hexSpan.appendChild(el("span", { cls: "hex__gap", text: " " }));
        if (i >= bytes.length) { hexSpan.appendChild(el("span", { cls: "hex__b", text: "   " })); continue; }
        const b = bytes[i];
        const cls = "hex__b" + (b === 0 ? " is-zero" : "") + (isMagic(i) ? " is-magic" : "");
        hexSpan.appendChild(el("span", { cls, text: b.toString(16).padStart(2, "0") + " " }));
        const ch = b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".";
        ascii.appendChild(el("span", { cls: "hex__c" + (isMagic(i) ? " is-magic" : ""), text: ch }));
      }
      box.appendChild(el("div", { cls: "hex__row" }, [
        el("span", { cls: "hex__off", text: row.toString(16).padStart(8, "0") }),
        hexSpan,
        ascii,
      ]));
    }
    if (!bytes.length) box.appendChild(el("div", { text: "(empty)" }));
  }

  // ------------------------------------------------------------ entropy chart

  let lastEntropy = null;

  function renderEntropy(e) {
    lastEntropy = e;
    drawEntropy();
    kv($("entropy"), [
      ["Overall", e.overall.toFixed(4) + " bits/byte (max 8)"],
      ["Block size", e.block_size ? e.block_size + " bytes × " + e.blocks.length + " blocks" : "-"],
      ["High blocks", e.high_blocks + " ≥ " + e.high_threshold],
      ["Assessment", e.assessment],
    ]);
  }

  function drawEntropy() {
    const e = lastEntropy;
    if (!e) return;
    const canvas = $("entropy-chart");
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth || 800;
    const h = canvas.clientHeight || 200;
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    const padL = 34, padR = 8, padT = 10, padB = 22;
    const cw = w - padL - padR, ch = h - padT - padB;
    const y = (v) => padT + ch - (v / 8) * ch;

    ctx.font = "11px ui-monospace, Consolas, monospace";
    ctx.fillStyle = "#57503f";
    ctx.strokeStyle = "rgba(31,28,23,.15)";
    ctx.lineWidth = 1;
    for (let v = 0; v <= 8; v += 2) {
      ctx.beginPath();
      ctx.moveTo(padL, y(v) + 0.5);
      ctx.lineTo(w - padR, y(v) + 0.5);
      ctx.stroke();
      ctx.fillText(String(v), 8, y(v) + 4);
    }

    const n = e.blocks.length;
    if (n) {
      const bw = cw / n;
      for (let i = 0; i < n; i++) {
        const v = e.blocks[i];
        ctx.fillStyle = v >= e.high_threshold ? "#a8261c" : v >= 6 ? "#b26a00" : "#23365a";
        const top = y(v);
        ctx.fillRect(padL + i * bw + (bw > 3 ? 0.5 : 0), top, Math.max(1, bw - (bw > 3 ? 1 : 0)), padT + ch - top);
      }
    }

    ctx.strokeStyle = "#a8261c";
    ctx.setLineDash([5, 4]);
    ctx.beginPath();
    ctx.moveTo(padL, y(e.high_threshold) + 0.5);
    ctx.lineTo(w - padR, y(e.high_threshold) + 0.5);
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = "#a8261c";
    ctx.fillText("packed/encrypted ≥ " + e.high_threshold, padL + 6, y(e.high_threshold) - 5);

    ctx.fillStyle = "#57503f";
    ctx.fillText("offset 0", padL, h - 6);
    const endLabel = "end";
    ctx.fillText(endLabel, w - padR - ctx.measureText(endLabel).width, h - 6);
  }

  let resizeTimer = null;
  window.addEventListener("resize", () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(drawEntropy, 120);
  });

  // ------------------------------------------------------------ strings / iocs

  const IOC_LABELS = {
    urls: "URLs (defanged)",
    domains: "Domains (defanged)",
    ipv4: "IPv4 addresses",
    emails: "Email addresses",
    windows_paths: "Windows paths",
    registry_keys: "Registry keys",
    bitcoin_addresses: "Bitcoin addresses",
  };

  function renderStrings(s, iocs) {
    kv($("strings-summary"), [
      ["Strings", s.total.toLocaleString() + " (" + s.ascii + " ASCII, " + s.utf16le + " UTF-16LE)" + (s.capped ? " · capped" : "")],
      ["Suspicious", s.suspicious.length ? s.suspicious.map((x) => x.token).join(", ") : "none"],
    ]);
    const box = $("iocs");
    clear(box);
    let any = false;
    for (const [key, label] of Object.entries(IOC_LABELS)) {
      const items = iocs[key] || [];
      if (!items.length) continue;
      any = true;
      const ul = el("ul");
      for (const it of items.slice(0, 40)) {
        if (typeof it === "object") {
          ul.appendChild(el("li", null, [el("span", { text: it.value + " " }), el("span", { cls: "ioc__scope", text: "(" + it.scope + ")" })]));
        } else {
          ul.appendChild(el("li", { text: it }));
        }
      }
      if (items.length > 40) ul.appendChild(el("li", { text: "… " + (items.length - 40) + " more in the JSON report" }));
      box.appendChild(el("section", { cls: "ioc" }, [el("h3", { text: label + " · " + items.length }), ul]));
    }
    if (!any) box.appendChild(el("p", { cls: "note", text: "No indicators of compromise found in the extracted strings." }));

    const list = $("strings-list");
    clear(list);
    for (const st of s.sample) {
      list.appendChild(el("li", null, [
        el("span", { cls: "strings__off", text: "0x" + st.offset.toString(16).padStart(6, "0") }),
        el("span", { cls: "strings__enc", text: st.encoding }),
        el("span", { text: st.value }),
      ]));
    }
  }

  // ------------------------------------------------------------ type-specific

  function renderImage(img) {
    const sec = $("sec-image");
    sec.hidden = !img;
    if (!img) return;
    const exif = img.exif || {};
    let gpsNode = "none";
    if (img.gps) {
      const lat = Number(img.gps.latitude), lon = Number(img.gps.longitude);
      const url = "https://www.openstreetmap.org/?mlat=" + lat + "&mlon=" + lon + "#map=15/" + lat + "/" + lon;
      gpsNode = el("span", null, [
        el("span", { text: lat.toFixed(6) + ", " + lon.toFixed(6) + (img.gps.altitude_m !== undefined ? " · " + img.gps.altitude_m + " m · " : " · ") }),
        safeLink(url, "open in OpenStreetMap"),
      ]);
    }
    const rows = [
      ["Format", img.parsed ? img.format + " · " + img.width + "×" + img.height + " · " + img.mode : img.error],
      ["Camera", [exif.Make, exif.Model].filter(Boolean).join(" ")],
      ["Lens", exif.LensModel],
      ["Software", exif.Software],
      ["Captured", img.timestamps && img.timestamps.original],
      ["Modified", img.timestamps && img.timestamps.modified],
      ["GPS", gpsNode],
      ["Artist", exif.Artist],
      ["Serial no.", exif.BodySerialNumber],
      ["EXIF tags", img.exif_tag_count],
    ];
    for (const [k, v] of Object.entries(img.text_chunks || {})) rows.push(["Text: " + k, v]);
    kv($("image"), rows);
  }

  function renderPdf(pdf) {
    const sec = $("sec-pdf");
    sec.hidden = !pdf;
    if (!pdf) return;
    const grid = $("pdf-keywords");
    clear(grid);
    const hot = new Set(["JavaScript", "JS", "OpenAction", "AA", "Launch", "EmbeddedFile", "EmbeddedFiles", "XFA", "RichMedia"]);
    for (const [k, v] of Object.entries(pdf.keywords)) {
      grid.appendChild(el("div", { cls: "kw" + (v && hot.has(k) ? " is-hot" : "") }, [
        el("span", { text: "/" + k }), el("span", { text: v }),
      ]));
    }
    const info = pdf.info || {};
    kv($("pdf"), [
      ["Version", pdf.version],
      ["Objects", pdf.objects + " objects · " + pdf.streams.streams + " streams (" + pdf.streams.flate_streams + " Flate, " + pdf.streams.inflated_bytes + " bytes inflated)"],
      ["Revisions", pdf.incremental_updates + " incremental update(s)" + (pdf.linearized ? " · linearized" : "")],
      ["Obfuscated", Object.keys(pdf.obfuscated_names).length ? Object.keys(pdf.obfuscated_names).join(", ") : "none"],
      ["Title", info.Title],
      ["Author", info.Author],
      ["Creator", info.Creator],
      ["Producer", info.Producer],
      ["Created", pdf.dates.CreationDate || info.CreationDate],
      ["Modified", pdf.dates.ModDate || info.ModDate],
      ["Links", pdf.uris.length ? pdf.uris.slice(0, 10).join("  ") : null],
    ]);
  }

  function renderOffice(office, archive) {
    const sec = $("sec-office");
    sec.hidden = !office && !archive;
    const list = $("office-list");
    clear(list);
    const rows = [];
    if (office && office.container === "ooxml") {
      rows.push(["Container", "OOXML (ZIP)"]);
      rows.push(["Macros", office.macros && office.macros.length ? office.macros.join(", ") : "none"]);
      rows.push(["Template inj.", office.template_injection ? "YES" : "no"]);
      rows.push(["DDE", office.dde ? "YES" : "no"]);
      rows.push(["ActiveX", (office.activex || []).length]);
      rows.push(["Embedded", (office.embedded_objects || []).length]);
      for (const rel of office.external_relationships || []) list.appendChild(el("li", { text: rel.kind + " → " + rel.target }));
    } else if (office && office.container === "ole") {
      rows.push(["Container", "OLE2 compound file"]);
      rows.push(["Macros", office.has_macros ? office.macros.join(", ") : "none"]);
      rows.push(["Streams", office.entry_count]);
      rows.push(["Encrypted", office.encrypted_package ? "yes" : "no"]);
      for (const s of (office.streams || []).slice(0, 30)) list.appendChild(el("li", { text: s.kind + "  " + s.name + "  (" + s.size + " B)" }));
    }
    if (archive) {
      rows.push(["Entries", archive.entry_count]);
      rows.push(["Uncompressed", fmtBytes(archive.total_uncompressed_declared) + " declared"]);
      rows.push(["Max ratio", archive.max_entry_ratio ? archive.max_entry_ratio + ":1" : "-"]);
      rows.push(["Bomb checks", archive.bomb_indicators.length ? archive.bomb_indicators.join("; ") : "passed"]);
      if (!office) for (const e of archive.entries.slice(0, 30)) list.appendChild(el("li", { text: e.name + "  " + e.uncompressed + " B" + (e.encrypted ? "  [encrypted]" : "") }));
    }
    kv($("office"), rows);
  }

  function renderStructure(r) {
    const a = r.appended;
    let appended = "none";
    if (a.appended_bytes) {
      appended = a.appended_bytes + " bytes after logical end (offset " + a.logical_end + ")" +
        (a.appended_label ? " · looks like " + a.appended_label : a.padding_only ? " · padding" : "");
    }
    const t = r.timings_ms;
    const rows = [
      ["Logical end", a.logical_end !== null ? String(a.logical_end) : "n/a for this format"],
      ["Appended", appended],
      ["Embedded", a.embedded.length ? a.embedded.slice(0, 6).map((e) => e.label + " @" + e.offset).join("; ") : "none found"],
    ];
    if (r.pe) {
      rows.push(["PE", r.pe.format + " · " + r.pe.machine + (r.pe.compile_time ? " · built " + r.pe.compile_time : "")]);
      rows.push(["Sections", r.pe.sections.map((s) => s.name + " (" + s.entropy + ")").join(", ")]);
      if (r.pe.overlay_size) rows.push(["Overlay", r.pe.overlay_size + " bytes at " + r.pe.overlay_offset]);
    }
    rows.push(["Timings", Object.entries(t).map(([k, v]) => k + " " + v + "ms").join(" · ")]);
    rows.push(["Storage", "processed in memory; upload discarded after this response"]);
    kv($("structure"), rows);
  }
})();
