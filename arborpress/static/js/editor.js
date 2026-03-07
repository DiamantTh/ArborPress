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
  function applyAction(textarea, action) {
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const selected = textarea.value.substring(start, end);
    const val = textarea.value;
    let newText, cursorStart, cursorEnd;

    if (action.type === "block") {
      newText = val.substring(0, start) + action.text + val.substring(end);
      cursorStart = cursorEnd = start + action.text.length;
    } else if (action.type === "line-prefix") {
      // Zeilenanfang finden
      const lineStart = val.lastIndexOf("\n", start - 1) + 1;
      const insert = action.prefix + selected;
      newText = val.substring(0, lineStart) + insert + val.substring(end);
      cursorStart = lineStart + action.prefix.length;
      cursorEnd = cursorStart + selected.length;
    } else if (action.type === "link") {
      const href = prompt("URL eingeben:", "https://");
      if (!href) return;
      const label = selected || "Linktext";
      const md = `[${label}](${href})`;
      newText = val.substring(0, start) + md + val.substring(end);
      cursorStart = start + 1;
      cursorEnd = start + 1 + label.length;
    } else if (action.type === "image") {
      const src = prompt("Bild-URL eingeben:", "https://");
      if (!src) return;
      const alt = selected || "Beschreibung";
      const md = `![${alt}](${src})`;
      newText = val.substring(0, start) + md + val.substring(end);
      cursorStart = start + 2;
      cursorEnd = start + 2 + alt.length;
    } else {
      // wrap: before/after
      const text = selected || action.sample || "";
      const md = action.before + text + action.after;
      newText = val.substring(0, start) + md + val.substring(end);
      cursorStart = start + action.before.length;
      cursorEnd = cursorStart + text.length;
    }

    textarea.value = newText;
    textarea.setSelectionRange(cursorStart, cursorEnd);
    textarea.dispatchEvent(new Event("input"));  // Preview aktualisieren
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
