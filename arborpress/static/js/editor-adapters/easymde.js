/**
 * ArborPress Editor-Adapter: EasyMDE
 *
 * Bindet EasyMDE (https://easymde.tk) als Adapter-ID "easymde" ein.
 *
 * Voraussetzung
 * ─────────────
 * EasyMDE via CDN oder lokal einbinden BEVOR dieser Adapter geladen wird:
 *
 *   <link rel="stylesheet"
 *         href="https://cdn.jsdelivr.net/npm/easymde/dist/easymde.min.css">
 *   <script src="https://cdn.jsdelivr.net/npm/easymde/dist/easymde.min.js"></script>
 *
 * Dann in config.toml:
 *   [web]
 *   admin_editor = "easymde"
 *
 * Konfiguration
 * ─────────────
 * Die data-Attribute des #ap-editor-wrap Elements können überschrieben werden:
 *   data-ap-preview-endpoint="/api/v1/admin/markdown/preview"  (standard)
 *
 * Hinweis: EasyMDE rendert clientseitig via `marked`; der ArborPress-Server-
 * Preview (via previewEndpoint) wird NICHT genutzt – EasyMDE hat eigene Preview.
 * Das bedeutet, dass die Preview ggf. von der serverseitigen Ausgabe abweicht,
 * wenn ArborPress-spezifische Markdown-Erweiterungen genutzt werden.
 */

(function () {
  "use strict";

  if (typeof window.ArborPressEditor === "undefined") {
    console.error("easymde.js: ArborPressEditor-Registry fehlt. editor-registry.js zuerst laden.");
    return;
  }

  if (typeof EasyMDE === "undefined") {
    console.error(
      "easymde.js: EasyMDE nicht gefunden. " +
      "CDN-Script (easymde.min.js) muss vor diesem Adapter geladen werden."
    );
    return;
  }

  window.ArborPressEditor.register("easymde", function (textarea, wrap, config) {
    // Textarea sichtbar halten – EasyMDE erwartet ein sichtbares Element
    textarea.style.display = "";

    var mde = new EasyMDE({
      element: textarea,
      spellChecker: false,
      autosave: { enabled: false },
      renderingConfig: { codeSyntaxHighlighting: false },
      toolbar: [
        "bold", "italic", "strikethrough", "|",
        "heading-2", "heading-3", "|",
        "quote", "unordered-list", "ordered-list", "|",
        "link", "image", "|",
        "code", "|",
        "preview", "side-by-side", "fullscreen",
      ],
    });

    return {
      getValue:  function ()     { return mde.value(); },
      setValue:  function (text) { mde.value(text); },
      focus:     function ()     { mde.codemirror.focus(); },
      destroy:   function ()     { mde.toTextArea(); mde.gui.el.remove(); },
    };
  });

}());
