/**
 * ArborPress Markdown-Editor
 *
 * Split-View (Textarea links / Preview rechts), formatierte Toolbar
 * und optionaler Vollbild-Modus für den Post-Editor im Admin-Interface.
 *
 * Voraussetzungen:
 *  - DOM-Element mit id="ap-editor-wrap" (enthält Textarea + Preview-Div)
 *  - API-Endpoint POST /api/v1/admin/markdown/preview
 *
 * Keine externen Abhängigkeiten – reines Vanilla-JS.
 */

(function () {
  "use strict";

  // ────────────────────────────────────────────────────────────
  // Konfiguration
  // ────────────────────────────────────────────────────────────
  const PREVIEW_DEBOUNCE_MS = 350;
  const PREVIEW_ENDPOINT = "/api/v1/admin/markdown/preview";

  // ────────────────────────────────────────────────────────────
  // Init
  // ────────────────────────────────────────────────────────────
  function init() {
    const wrap = document.getElementById("ap-editor-wrap");
    if (!wrap) return;

    const textarea = wrap.querySelector("textarea[name='body']");
    if (!textarea) return;

    // Toolbar + Preview bauen
    buildToolbar(wrap, textarea);
    buildSplitView(wrap, textarea);

    // Initiale Preview
    triggerPreview(textarea.value, wrap.querySelector(".ap-preview-content"));
  }

  // ────────────────────────────────────────────────────────────
  // Toolbar
  // ────────────────────────────────────────────────────────────
  const TOOLBAR_ACTIONS = [
    { label: "B",        title: "Fett (Strg+B)",        before: "**", after: "**", sample: "Fettschrift" },
    { label: "I",        title: "Kursiv (Strg+I)",       before: "*",  after: "*",  sample: "Kursiv"      },
    { label: "~~",       title: "Durchgestrichen",       before: "~~", after: "~~", sample: "Text"        },
    { label: "—",        title: "Trenner",               type: "block", text: "\n\n---\n\n",              },
    { label: "</>",      title: "Inline-Code",           before: "`",  after: "`",  sample: "code"        },
    { label: "⌨ Block", title: "Code-Block",            type: "block", text: "\n\n```\n\n```\n\n"        },
    { label: "❝",        title: "Zitat",                 type: "line-prefix", prefix: "> "               },
    { label: "🔗",       title: "Link",                  type: "link"                                     },
    { label: "🖼",       title: "Bild",                  type: "image"                                    },
    { label: "• Liste",  title: "Ungeordnete Liste",     type: "line-prefix", prefix: "- "               },
    { label: "1. Liste", title: "Geordnete Liste",       type: "line-prefix", prefix: "1. "              },
    { label: "H2",       title: "Überschrift 2",         type: "line-prefix", prefix: "## "              },
    { label: "H3",       title: "Überschrift 3",         type: "line-prefix", prefix: "### "             },
  ];

  function buildToolbar(wrap, textarea) {
    const bar = document.createElement("div");
    bar.className = "ap-editor-toolbar";

    TOOLBAR_ACTIONS.forEach(function (action) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.textContent = action.label;
      btn.title = action.title || action.label;
      btn.addEventListener("click", function (e) {
        e.preventDefault();
        applyAction(textarea, action);
        textarea.focus();
      });
      bar.appendChild(btn);
    });

    // Trennstrich + View-Toggle-Buttons
    bar.appendChild(makeSep());
    bar.appendChild(makeViewToggle(wrap));

    wrap.insertBefore(bar, wrap.firstChild);

    // Keyboard-Shortcuts
    textarea.addEventListener("keydown", function (e) {
      if (e.ctrlKey || e.metaKey) {
        if (e.key === "b") { e.preventDefault(); applyAction(textarea, TOOLBAR_ACTIONS[0]); }
        if (e.key === "i") { e.preventDefault(); applyAction(textarea, TOOLBAR_ACTIONS[1]); }
      }
    });
  }

  function makeSep() {
    const s = document.createElement("span");
    s.className = "ap-toolbar-sep";
    s.setAttribute("aria-hidden", "true");
    return s;
  }

  function makeViewToggle(wrap) {
    const grp = document.createElement("span");
    grp.className = "ap-toolbar-view-group";

    [
      { id: "edit",      label: "✏ Nur Editor",    title: "Nur Eingabe anzeigen"         },
      { id: "split",     label: "⬛⬜ Split",        title: "Editor + Preview nebeneinander" },
      { id: "preview",   label: "👁 Nur Preview",   title: "Nur Vorschau anzeigen"        },
    ].forEach(function (v) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.textContent = v.label;
      btn.title = v.title;
      btn.dataset.view = v.id;
      btn.addEventListener("click", function () {
        setViewMode(wrap, v.id);
        grp.querySelectorAll("button").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
      });
      if (v.id === "split") btn.classList.add("active");
      grp.appendChild(btn);
    });
    return grp;
  }

  // ────────────────────────────────────────────────────────────
  // Split-View Aufbau
  // ────────────────────────────────────────────────────────────
  function buildSplitView(wrap, textarea) {
    // Container erzeugen
    const container = document.createElement("div");
    container.className = "ap-editor-split active-split";

    // Textarea-Seite
    const editorPane = document.createElement("div");
    editorPane.className = "ap-editor-pane";
    editorPane.appendChild(textarea); // Textarea hierher verschieben

    // Preview-Seite
    const previewPane = document.createElement("div");
    previewPane.className = "ap-preview-pane";
    const previewLabel = document.createElement("div");
    previewLabel.className = "ap-preview-label";
    previewLabel.textContent = "Vorschau";
    const previewContent = document.createElement("div");
    previewContent.className = "ap-preview-content ap-prose";
    previewPane.appendChild(previewLabel);
    previewPane.appendChild(previewContent);

    container.appendChild(editorPane);
    container.appendChild(previewPane);
    wrap.appendChild(container);

    // Debounced Live-Preview
    let debounceTimer = null;
    textarea.addEventListener("input", function () {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(function () {
        triggerPreview(textarea.value, previewContent);
      }, PREVIEW_DEBOUNCE_MS);
    });
  }

  // ────────────────────────────────────────────────────────────
  // View-Modi
  // ────────────────────────────────────────────────────────────
  function setViewMode(wrap, mode) {
    const container = wrap.querySelector(".ap-editor-split");
    if (!container) return;
    container.className = "ap-editor-split ap-view-" + mode;
  }

  // ────────────────────────────────────────────────────────────
  // API-Preview
  // ────────────────────────────────────────────────────────────
  function triggerPreview(markdown, target) {
    if (!target) return;
    fetch(PREVIEW_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
      },
      body: JSON.stringify({ text: markdown }),
    })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        target.innerHTML = data.html || "";
      })
      .catch(function () {
        target.innerHTML = '<p style="color:var(--admin-danger)">Vorschau nicht verfügbar</p>';
      });
  }

  // ────────────────────────────────────────────────────────────
  // Aktionen auf Textarea
  // ────────────────────────────────────────────────────────────
  // Inline-Dialog (ersetzt browser prompt() – barrierefrei, kein
  // Dialog-Blockieren durch Popup-Blocker)
  // ────────────────────────────────────────────────────────────
  function showInlineDialog({ label, placeholder, defaultValue, onConfirm }) {
    // Entferne evtl. vorhandenen Dialog
    const prev = document.getElementById("ap-inline-dialog");
    if (prev) prev.remove();

    const dlg = document.createElement("div");
    dlg.id = "ap-inline-dialog";
    dlg.setAttribute("role", "dialog");
    dlg.setAttribute("aria-modal", "true");
    dlg.setAttribute("aria-label", label);

    const lbl = document.createElement("label");
    lbl.textContent = label;
    lbl.setAttribute("for", "ap-inline-dialog-input");

    const input = document.createElement("input");
    input.type = "url";
    input.id = "ap-inline-dialog-input";
    input.placeholder = placeholder || "";
    input.value = defaultValue || "";
    input.setAttribute("autocomplete", "off");

    const btnOk = document.createElement("button");
    btnOk.type = "button";
    btnOk.textContent = "OK";
    btnOk.className = "ap-dlg-ok";

    const btnCancel = document.createElement("button");
    btnCancel.type = "button";
    btnCancel.textContent = "Abbrechen";
    btnCancel.className = "ap-dlg-cancel";

    dlg.appendChild(lbl);
    dlg.appendChild(input);
    dlg.appendChild(btnOk);
    dlg.appendChild(btnCancel);
    document.body.appendChild(dlg);

    input.focus();
    input.select();

    function close(value) {
      dlg.remove();
      if (value !== null) onConfirm(value.trim());
    }

    btnOk.addEventListener("click",     () => close(input.value));
    btnCancel.addEventListener("click",  () => close(null));
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter")  { e.preventDefault(); close(input.value); }
      if (e.key === "Escape") { e.preventDefault(); close(null); }
    });
  }

  // ────────────────────────────────────────────────────────────
  // Preview: sichere HTML-Einfügung über DOMParser
  // (verhindert Script-Ausführung aus der Preview-Antwort)
  // ────────────────────────────────────────────────────────────
  function setPreviewHTML(container, html) {
    // DOMParser parst HTML in einem inaktiven Dokument –
    // kein Script-Kontext, kein Laden von Ressourcen.
    const parser  = new DOMParser();
    const doc     = parser.parseFromString(html, "text/html");
    // Alle <script>-Elemente (falls vorhanden) entfernen
    doc.querySelectorAll("script, noscript").forEach(el => el.remove());
    // Inhalt des <body> importieren und einsetzen
    container.replaceChildren(
      ...Array.from(doc.body.childNodes).map(n => document.importNode(n, true))
    );
  }

  // ────────────────────────────────────────────────────────────
  // API-Preview
  // ────────────────────────────────────────────────────────────
  function triggerPreview(markdown, target) {
    if (!target) return;
    fetch(PREVIEW_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
      },
      body: JSON.stringify({ text: markdown }),
    })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        setPreviewHTML(target, data.html || "");
      })
      .catch(function () {
        target.textContent = "Vorschau nicht verfügbar";
      });
  }

  // ────────────────────────────────────────────────────────────
  // Aktionen auf Textarea
  // ────────────────────────────────────────────────────────────
  function applyAction(textarea, action) {
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const selected = textarea.value.substring(start, end);
    const val = textarea.value;
    let newText, cursorStart, cursorEnd;

    if (action.type === "block") {
      newText = val.substring(0, start) + action.text + val.substring(end);
      cursorStart = cursorEnd = start + action.text.length;
      textarea.value = newText;
      textarea.setSelectionRange(cursorStart, cursorEnd);
      textarea.dispatchEvent(new Event("input"));
    } else if (action.type === "line-prefix") {
      // Zeilenanfang finden
      const lineStart = val.lastIndexOf("\n", start - 1) + 1;
      const insert = action.prefix + selected;
      newText = val.substring(0, lineStart) + insert + val.substring(end);
      cursorStart = lineStart + action.prefix.length;
      cursorEnd = cursorStart + selected.length;
      textarea.value = newText;
      textarea.setSelectionRange(cursorStart, cursorEnd);
      textarea.dispatchEvent(new Event("input"));
    } else if (action.type === "link") {
      showInlineDialog({
        label: "Link-URL eingeben",
        placeholder: "https://",
        defaultValue: "https://",
        onConfirm(href) {
          if (!href) return;
          const label = selected || "Linktext";
          const md = `[${label}](${href})`;
          const nv = val.substring(0, start) + md + val.substring(end);
          textarea.value = nv;
          textarea.setSelectionRange(start + 1, start + 1 + label.length);
          textarea.focus();
          textarea.dispatchEvent(new Event("input"));
        },
      });
    } else if (action.type === "image") {
      showInlineDialog({
        label: "Bild-URL eingeben",
        placeholder: "https://",
        defaultValue: "https://",
        onConfirm(src) {
          if (!src) return;
          const alt = selected || "Beschreibung";
          const md = `![${alt}](${src})`;
          const nv = val.substring(0, start) + md + val.substring(end);
          textarea.value = nv;
          textarea.setSelectionRange(start + 2, start + 2 + alt.length);
          textarea.focus();
          textarea.dispatchEvent(new Event("input"));
        },
      });
    } else {
      // wrap: before/after
      const text = selected || action.sample || "";
      const md = action.before + text + action.after;
      newText = val.substring(0, start) + md + val.substring(end);
      cursorStart = start + action.before.length;
      cursorEnd = cursorStart + text.length;
      textarea.value = newText;
      textarea.setSelectionRange(cursorStart, cursorEnd);
      textarea.dispatchEvent(new Event("input"));  // Preview aktualisieren
    }
  }

  // ────────────────────────────────────────────────────────────
  // Start
  // ────────────────────────────────────────────────────────────
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
