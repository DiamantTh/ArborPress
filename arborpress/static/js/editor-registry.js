/**
 * ArborPress Editor Registry
 *
 * Adapter-Framework für auswechselbare Markdown-Editoren.
 *
 * Konzept
 * ───────
 * Jeder Editor-Adapter registriert sich selbst per
 *   ArborPressEditor.register("my-id", adapterFactory);
 *
 * Die Registry mountet beim Seitenaufruf automatisch den Adapter
 * dessen ID im data-ap-editor-Attribut des Wrapper-Elements steht:
 *   <div id="ap-editor-wrap" data-ap-editor="my-id" ...>
 *
 * Adapter-Interface
 * ─────────────────
 * Ein Adapter ist eine Funktion, die folgende Signatur hat:
 *
 *   function adapterFactory(textarea, wrap, config) → AdapterInstance
 *
 * Parameter:
 *   textarea  – das originale <textarea> für den Markdown-Inhalt
 *   wrap      – das #ap-editor-wrap DOM-Element (Mountpunkt)
 *   config    – Objekt aus den data-* Attributen des wrap-Elements:
 *               {
 *                 previewEndpoint: string  (URL für Server-Preview)
 *                 debounce:        number  (ms, default 350)
 *               }
 *
 * Rückgabe (AdapterInstance):
 *   {
 *     getValue()        → string   – aktuellen Markdown-Inhalt lesen
 *     setValue(text)    → void     – Inhalt programmatisch setzen
 *     focus()           → void     – Editor fokussieren
 *     destroy()         → void     – Ressourcen freigeben, DOM aufräumen
 *   }
 *
 * Hinweis: getValue() MUSS vor jedem Form-Submit den Inhalt in die
 * ursprüngliche <textarea> schreiben; die Registry tut dies automatisch
 * (beforesubmit-Hook).  Adaptern mit eigenem contenteditable (z.B. Quill)
 * genügt die getValue()-Implementierung; die Registry kopiert den Wert.
 *
 * Eigene Adapter einbinden
 * ────────────────────────
 * 1.  Datei unter static/js/editor-adapters/<id>.js ablegen.
 * 2.  In config.toml: [web] admin_editor = "<id>"
 *     Das Template lädt dann automatisch editor-adapters/<id>.js
 *     nach dieser Registry (oder das Skript via CDN einbinden und
 *     manuell im <head> laden – registry muss davor stehen).
 * 3.  In der Adapter-Datei:
 *       ArborPressEditor.register("<id>", function(textarea, wrap, cfg) { … });
 *
 * Beispiel-Adapter finden sich in editor-adapters/easymde.js und
 * editor-adapters/codemirror6.js.
 */

(function (global) {
  "use strict";

  // ─────────────────────────────────────────────────────────────────────────
  // Interne Registry
  // ─────────────────────────────────────────────────────────────────────────
  var _adapters  = {};
  var _instances = [];   // { instance, textarea } für beforesubmit-sync

  // ─────────────────────────────────────────────────────────────────────────
  // Öffentliche API
  // ─────────────────────────────────────────────────────────────────────────
  var ArborPressEditor = {

    /**
     * Adapter unter gegebener ID registrieren.
     * @param {string}   id       – eindeutiger Bezeichner (z.B. "builtin", "easymde")
     * @param {Function} factory  – adapterFactory(textarea, wrap, config) → instance
     */
    register: function (id, factory) {
      if (typeof factory !== "function") {
        throw new Error("ArborPressEditor.register: factory muss eine Funktion sein");
      }
      _adapters[id] = factory;
    },

    /**
     * Alle gefundenen #ap-editor-wrap Elemente mounten.
     * Wird von DOMContentLoaded ausgelöst; kann auch manuell
     * gerufen werden (z.B. bei dynamisch eingefügten Formularen).
     */
    mount: function () {
      var wraps = document.querySelectorAll("[data-ap-editor]");
      wraps.forEach(function (wrap) {
        ArborPressEditor.mountOne(wrap);
      });
    },

    /**
     * Einen einzelnen Wrapper mounten.
     * @param {HTMLElement} wrap
     * @returns {object|null} AdapterInstance oder null bei Fehler
     */
    mountOne: function (wrap) {
      var id       = wrap.dataset.apEditor || "builtin";
      var factory  = _adapters[id];

      if (!factory) {
        console.warn(
          "ArborPressEditor: Kein Adapter für \"" + id + "\" registriert. " +
          "Verfügbare Adapter: " + (Object.keys(_adapters).join(", ") || "(keine)") + ". " +
          "Fallback auf <textarea>."
        );
        return null;
      }

      var textarea = wrap.querySelector("textarea");
      if (!textarea) {
        console.warn("ArborPressEditor: Kein <textarea> in", wrap);
        return null;
      }

      // Config aus data-* Attributen lesen
      var config = {
        previewEndpoint: wrap.dataset.apPreviewEndpoint || "/api/v1/admin/markdown/preview",
        debounce:        parseInt(wrap.dataset.apDebounce || "350", 10),
      };

      var instance;
      try {
        instance = factory(textarea, wrap, config);
      } catch (err) {
        console.error("ArborPressEditor: Fehler beim Mounten von Adapter \"" + id + "\":", err);
        return null;
      }

      // Plausibilitätsprüfung
      ["getValue", "setValue", "focus", "destroy"].forEach(function (method) {
        if (typeof instance[method] !== "function") {
          console.warn(
            "ArborPressEditor: Adapter \"" + id + "\" hat keine Methode \"" + method + "\""
          );
        }
      });

      // Für beforesubmit-Sync registrieren
      _instances.push({ instance: instance, textarea: textarea });

      // Form-Submit-Hook: Adapter-Inhalt → textarea schreiben
      var form = wrap.closest("form");
      if (form) {
        form.addEventListener("submit", function () {
          try {
            textarea.value = instance.getValue();
          } catch (_) { /* adapter-fehler sollen submit nicht blockieren */ }
        });
      }

      return instance;
    },

    /**
     * Alle gemounteten Instanzen zerstören (z.B. bei SPA-Navigation).
     */
    destroyAll: function () {
      _instances.forEach(function (entry) {
        try { entry.instance.destroy(); } catch (_) {}
      });
      _instances = [];
    },

    /** Gibt alle registrierten Adapter-IDs zurück. */
    list: function () {
      return Object.keys(_adapters);
    },
  };

  // ─────────────────────────────────────────────────────────────────────────
  // Auto-Mount bei DOMContentLoaded
  // ─────────────────────────────────────────────────────────────────────────
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () { ArborPressEditor.mount(); });
  } else {
    // Skript nach DOMContentLoaded geladen
    ArborPressEditor.mount();
  }

  global.ArborPressEditor = ArborPressEditor;

}(window));
