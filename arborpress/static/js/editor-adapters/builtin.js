/**
 * ArborPress Built-in Markdown Editor – Adapter "builtin"
 *
 * Registriert sich bei ArborPressEditor als Adapter-ID "builtin".
 * Voraussetzung: editor-registry.js muss vor diesem Skript geladen sein.
 *
 * Features
 * ────────
 *  - Split-View (Textarea links, Server-Preview rechts)
 *  - Toolbar mit 13 Aktionen + View-Toggle (Edit / Split / Preview)
 *  - Inline-Dialog statt window.prompt() (CSP-konform, barrierefrei)
 *  - DOMParser-basierte Preview (kein script-injection möglich)
 *  - Ctrl+B / Ctrl+I Shortcuts
 *  - Keine externen Dependencies
 */

(function () {
  "use strict";

  // ────────────────────────────────────────────────────────────
  // Toolbar-Konfiguration
  // ────────────────────────────────────────────────────────────
  var TOOLBAR_ACTIONS = [
    { label: "B",        title: "Fett (Strg+B)",   before: "**", after: "**", sample: "Fettschrift" },
    { label: "I",        title: "Kursiv (Strg+I)", before: "*",  after: "*",  sample: "Kursiv"      },
    { label: "~~",       title: "Durchgestrichen", before: "~~", after: "~~", sample: "Text"        },
    { label: "—",        title: "Trenner",          type: "block", text: "\n\n---\n\n"              },
    { label: "</>",      title: "Inline-Code",      before: "`",  after: "`",  sample: "code"       },
    { label: "⌨ Block", title: "Code-Block",       type: "block", text: "\n\n```\n\n```\n\n"       },
    { label: "❝",        title: "Zitat",            type: "line-prefix", prefix: "> "              },
    { label: "🔗",       title: "Link",             type: "link"                                    },
    { label: "🖼",       title: "Bild",             type: "image"                                   },
    { label: "• Liste",  title: "Ungeordnete Liste",type: "line-prefix", prefix: "- "              },
    { label: "1. Liste", title: "Geordnete Liste",  type: "line-prefix", prefix: "1. "             },
    { label: "H2",       title: "Überschrift 2",    type: "line-prefix", prefix: "## "             },
    { label: "H3",       title: "Überschrift 3",    type: "line-prefix", prefix: "### "            },
  ];

  // ────────────────────────────────────────────────────────────
  // Adapter-Factory
  // ────────────────────────────────────────────────────────────
  function builtinFactory(textarea, wrap, config) {
    var PREVIEW_ENDPOINT = config.previewEndpoint;
    var DEBOUNCE_MS      = config.debounce;
    var debounceTimer    = null;
    var previewContent   = null;

    // Toolbar mounten
    var bar = buildToolbar(wrap, textarea, TOOLBAR_ACTIONS, triggerPreview);
    wrap.insertBefore(bar, wrap.firstChild);

    // Keyboard-Shortcuts
    textarea.addEventListener("keydown", function (e) {
      if (e.ctrlKey || e.metaKey) {
        if (e.key === "b") { e.preventDefault(); applyAction(textarea, TOOLBAR_ACTIONS[0]); }
        if (e.key === "i") { e.preventDefault(); applyAction(textarea, TOOLBAR_ACTIONS[1]); }
      }
    });

    // Split-View aufbauen
    previewContent = buildSplitView(wrap, textarea);

    // Debounced Live-Preview verdrahten
    textarea.addEventListener("input", function () {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(function () {
        triggerPreview(textarea.value, previewContent, PREVIEW_ENDPOINT);
      }, DEBOUNCE_MS);
    });

    // Initiale Preview
    triggerPreview(textarea.value, previewContent, PREVIEW_ENDPOINT);

    // ── Adapter-Interface ────────────────────────────────────
    return {
      getValue: function ()     { return textarea.value; },
      setValue: function (text) {
        textarea.value = text;
        textarea.dispatchEvent(new Event("input"));
      },
      focus:   function ()      { textarea.focus(); },
      destroy: function ()      {
        clearTimeout(debounceTimer);
        // Toolbar + Split-View entfernen, Textarea zurück in wrap
        var split = wrap.querySelector(".ap-editor-split");
        if (split) {
          wrap.appendChild(textarea);
          split.remove();
        }
        if (bar && bar.parentNode) bar.remove();
      },
    };
  }

  // ────────────────────────────────────────────────────────────
  // Toolbar-Bau
  // ────────────────────────────────────────────────────────────
  function buildToolbar(wrap, textarea) {
    var bar = document.createElement("div");
    bar.className = "ap-editor-toolbar";
    bar.setAttribute("role", "toolbar");
    bar.setAttribute("aria-label", "Formatierungs-Toolbar");

    TOOLBAR_ACTIONS.forEach(function (action) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.textContent = action.label;
      var ariaLabel = action.title || action.label;
      btn.title = ariaLabel;
      btn.setAttribute("aria-label", ariaLabel);
      btn.addEventListener("click", function (e) {
        e.preventDefault();
        applyAction(textarea, action);
        textarea.focus();
      });
      bar.appendChild(btn);
    });

    bar.appendChild(makeSep());
    bar.appendChild(makeViewToggle(wrap));
    return bar;
  }

  function makeSep() {
    var s = document.createElement("span");
    s.className = "ap-toolbar-sep";
    s.setAttribute("aria-hidden", "true");
    return s;
  }

  function makeViewToggle(wrap) {
    var grp = document.createElement("span");
    grp.className = "ap-toolbar-view-group";

    [
      { id: "edit",    label: "✏ Nur Editor",  title: "Nur Eingabe anzeigen"           },
      { id: "split",   label: "⬛⬜ Split",      title: "Editor + Preview nebeneinander" },
      { id: "preview", label: "👁 Nur Preview", title: "Nur Vorschau anzeigen"          },
    ].forEach(function (v) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.textContent = v.label;
      btn.title = v.title;
      btn.setAttribute("aria-label", v.title);
      btn.dataset.view = v.id;
      btn.addEventListener("click", function () {
        setViewMode(wrap, v.id);
        grp.querySelectorAll("button").forEach(function (b) { b.classList.remove("active"); });
        btn.classList.add("active");
      });
      if (v.id === "split") btn.classList.add("active");
      grp.appendChild(btn);
    });
    return grp;
  }

  // ────────────────────────────────────────────────────────────
  // Split-View
  // ────────────────────────────────────────────────────────────
  function buildSplitView(wrap, textarea) {
    var container = document.createElement("div");
    container.className = "ap-editor-split active-split";

    var editorPane = document.createElement("div");
    editorPane.className = "ap-editor-pane";
    editorPane.appendChild(textarea);

    var previewPane = document.createElement("div");
    previewPane.className = "ap-preview-pane";

    var previewLabel = document.createElement("div");
    previewLabel.className = "ap-preview-label";
    previewLabel.textContent = "Vorschau";

    var previewContent = document.createElement("div");
    previewContent.className = "ap-preview-content ap-prose";

    previewPane.appendChild(previewLabel);
    previewPane.appendChild(previewContent);
    container.appendChild(editorPane);
    container.appendChild(previewPane);
    wrap.appendChild(container);

    return previewContent;
  }

  function setViewMode(wrap, mode) {
    var container = wrap.querySelector(".ap-editor-split");
    if (!container) return;
    container.className = "ap-editor-split ap-view-" + mode;
  }

  // ────────────────────────────────────────────────────────────
  // Preview (sicher via DOMParser, kein innerHTML)
  // ────────────────────────────────────────────────────────────
  function triggerPreview(markdown, target, endpoint) {
    if (!target) return;
    fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
      },
      body: JSON.stringify({ text: markdown }),
    })
      .then(function (r) { return r.json(); })
      .then(function (data) { setPreviewHTML(target, data.html || ""); })
      .catch(function ()   { target.textContent = "Vorschau nicht verfügbar"; });
  }

  function setPreviewHTML(container, html) {
    var parser = new DOMParser();
    var doc    = parser.parseFromString(html, "text/html");
    doc.querySelectorAll("script, noscript").forEach(function (el) { el.remove(); });
    container.replaceChildren(
      Array.from(doc.body.childNodes).map(function (n) {
        return document.importNode(n, true);
      })
    );
  }

  // ────────────────────────────────────────────────────────────
  // Inline-Dialog (statt window.prompt)
  // ────────────────────────────────────────────────────────────
  function showInlineDialog(opts) {
    var prev = document.getElementById("ap-inline-dialog");
    if (prev) prev.remove();

    var dlg = document.createElement("div");
    dlg.id = "ap-inline-dialog";
    dlg.setAttribute("role", "dialog");
    dlg.setAttribute("aria-modal", "true");
    dlg.setAttribute("aria-label", opts.label);

    var lbl = document.createElement("label");
    lbl.textContent = opts.label;
    lbl.setAttribute("for", "ap-inline-dialog-input");

    var input = document.createElement("input");
    input.type = opts.type || "text";
    input.id = "ap-inline-dialog-input";
    input.placeholder = opts.placeholder || "";
    input.value = opts.defaultValue || "";
    input.setAttribute("autocomplete", "off");

    var btnOk = document.createElement("button");
    btnOk.type = "button"; btnOk.textContent = "OK"; btnOk.className = "ap-dlg-ok";

    var btnCancel = document.createElement("button");
    btnCancel.type = "button"; btnCancel.textContent = "Abbrechen"; btnCancel.className = "ap-dlg-cancel";

    dlg.appendChild(lbl); dlg.appendChild(input);
    dlg.appendChild(btnOk); dlg.appendChild(btnCancel);
    document.body.appendChild(dlg);
    input.focus(); input.select();

    function close(value) {
      dlg.remove();
      if (value !== null) opts.onConfirm(value.trim());
    }

    btnOk.addEventListener("click",    function () { close(input.value); });
    btnCancel.addEventListener("click", function () { close(null); });
    input.addEventListener("keydown", function (e) {
      if (e.key === "Enter")  { e.preventDefault(); close(input.value); }
      if (e.key === "Escape") { e.preventDefault(); close(null); }
    });
  }

  // ────────────────────────────────────────────────────────────
  // Textarea-Aktionen
  // ────────────────────────────────────────────────────────────
  function applyAction(textarea, action) {
    var start    = textarea.selectionStart;
    var end      = textarea.selectionEnd;
    var selected = textarea.value.substring(start, end);
    var val      = textarea.value;
    var newText, cursorStart, cursorEnd;

    if (action.type === "block") {
      newText = val.substring(0, start) + action.text + val.substring(end);
      cursorStart = cursorEnd = start + action.text.length;
      textarea.value = newText;
      textarea.setSelectionRange(cursorStart, cursorEnd);
      textarea.dispatchEvent(new Event("input"));

    } else if (action.type === "line-prefix") {
      var lineStart = val.lastIndexOf("\n", start - 1) + 1;
      var insert    = action.prefix + selected;
      newText       = val.substring(0, lineStart) + insert + val.substring(end);
      cursorStart   = lineStart + action.prefix.length;
      cursorEnd     = cursorStart + selected.length;
      textarea.value = newText;
      textarea.setSelectionRange(cursorStart, cursorEnd);
      textarea.dispatchEvent(new Event("input"));

    } else if (action.type === "link") {
      showInlineDialog({
        label: "Link-URL eingeben", placeholder: "https://",
        defaultValue: "https://", type: "url",
        onConfirm: function (href) {
          if (!href) return;
          var label = selected || "Linktext";
          var md    = "[" + label + "](" + href + ")";
          textarea.value = val.substring(0, start) + md + val.substring(end);
          textarea.setSelectionRange(start + 1, start + 1 + label.length);
          textarea.focus();
          textarea.dispatchEvent(new Event("input"));
        },
      });

    } else if (action.type === "image") {
      showInlineDialog({
        label: "Bild-URL eingeben", placeholder: "/media/... oder https://",
        defaultValue: "", type: "text",
        onConfirm: function (src) {
          if (!src) return;
          var alt = selected || "Beschreibung";
          var md  = "![" + alt + "](" + src + ")";
          textarea.value = val.substring(0, start) + md + val.substring(end);
          textarea.setSelectionRange(start + 2, start + 2 + alt.length);
          textarea.focus();
          textarea.dispatchEvent(new Event("input"));
        },
      });

    } else {
      var text  = selected || action.sample || "";
      var md    = action.before + text + action.after;
      newText   = val.substring(0, start) + md + val.substring(end);
      cursorStart = start + action.before.length;
      cursorEnd   = cursorStart + text.length;
      textarea.value = newText;
      textarea.setSelectionRange(cursorStart, cursorEnd);
      textarea.dispatchEvent(new Event("input"));
    }
  }

  // ────────────────────────────────────────────────────────────
  // Registrierung
  // ────────────────────────────────────────────────────────────
  if (typeof window.ArborPressEditor === "undefined") {
    console.error(
      "editor-adapters/builtin.js: ArborPressEditor-Registry nicht gefunden. " +
      "editor-registry.js muss vor diesem Skript geladen werden."
    );
    return;
  }

  window.ArborPressEditor.register("builtin", builtinFactory);

}());
