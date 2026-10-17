.PHONY: help demo test lint check build run db-upgrade

PREFIX ?= /tmp/arborpress-dev

help: ## Diese Hilfe anzeigen
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

demo: ## Demo-HTML aus aktuellen Theme-CSS-Dateien regenerieren (lokal, nicht in Git)
	@echo "🎨  Demo aktualisieren …"
	@poetry run python scripts/update_demo.py
	@echo "→ docs/demo.html lokal aktuell"

test: ## Unit-Tests ausführen
	poetry run pytest tests/ -v

lint: ## Code-Qualität prüfen (ruff)
	poetry run ruff check arborpress/

check: ## Projektmetadaten und Lockfile prüfen
	poetry check --lock

build: ## sdist und Wheel bauen
	poetry build

db-upgrade: ## Datenbank der PREFIX-Instanz auf neueste Migration bringen
	poetry run arborpress --prefix "$(PREFIX)" db upgrade

run: ## Entwicklungsserver für PREFIX starten
	poetry run arborpress --prefix "$(PREFIX)" serve --dev
