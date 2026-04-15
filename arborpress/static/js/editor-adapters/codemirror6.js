/**
 * ArborPress Editor-Adapter: CodeMirror 6
 *
 * Bindet CodeMirror 6 als reinen Textarea-Ersatz (kein Split-View) ein.
 * Adapter-ID: "codemirror6"
 *
 * Voraussetzung
 * ─────────────
 * CodeMirror 6 Core + Markdown-Extension laden BEVOR dieser Adapter geladen.
 * Einfachste Option via ESM-CDN – als <script type="module"> im Template:
 *
 *   <script type="module">
 *     import { EditorView, basicSetup } from "https://esm.sh/codemirror@6";
 *     import { markdown }              from "https://esm.sh/@codemirror/lang-markdown@6";
 *     window._CM6 = { EditorView, basicSetup, markdown };
 *   </script>
 *
 * Dann in config.toml:
 *   [web]
 *   admin_editor = "codemirror6"
 *
 * Hinweis
 * ───────
 * Dieser Adapter liefert nur den CodeMirror-Editor ohne Split-View.
 * Für eine Split-View mit Server-Preview geladen werden, empfiehlt sich
 * der "builtin"-Adapter oder ein kombinierter Adapter, der CodeMirror als
 * Eingabefeld im Editor-Pane des builtin-Layouts nutzt.
 */

(function () {
  "use strict";

  if (typeof window.ArborPressEditor === "undefined") {
    console.error("codemirror6.js: ArborPressEditor-Registry fehlt. editor-registry.js zuerst laden.");
    return;
  }

  window.ArborPressEditor.register("codemirror6", function (textarea, wrap) {
    var CM6 = window._CM6;
    if (!CM6 || !CM6.EditorView) {
      console.error(
        "codemirror6.js: window._CM6 nicht gefunden. " +
        "Bitte CodeMirror 6 als ESM-Modul laden und unter window._CM6 ablegen."
      );
      return {
        getValue: function () { return textarea.value; },
        setValue: function (t) { textarea.value = t; },
        focus:    function () { textarea.focus(); },
        destroy:  function () {},
      };
    }

    // Textarea verstecken; CM6 übernimmt
    textarea.style.display = "none";

    var view = new CM6.EditorView({
      doc: textarea.value,
      extensions: [
        CM6.basicSetup,
        CM6.markdown(),
        // Inhalt bei jeder Änderung in textarea spiegeln
        // (Registry-beforesubmit-Hook ruft getValue() auf)
        CM6.EditorView.updateListener.of(function (update) {
          if (update.docChanged) {
            textarea.value = view.state.doc.toString();
          }
        }),
      ],
      parent: wrap,
    });

    return {
      getValue:  function ()     { return view.state.doc.toString(); },
      setValue:  function (text) {
        view.dispatch({
          changes: { from: 0, to: view.state.doc.length, insert: text },
        });
      },
      focus:    function ()      { view.focus(); },
      destroy:  function ()      { view.destroy(); textarea.style.display = ""; },
    };
  });

}());
