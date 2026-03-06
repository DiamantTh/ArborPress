.PHONY: help demo test lint run db-upgrade

help: ## Diese Hilfe anzeigen
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

demo: ## Demo-HTML aus aktuellen Theme-CSS-Dateien regenerieren (lokal, nicht in Git)
	@echo "🎨  Demo aktualisieren …"
	@python scripts/update_demo.py
	@echo "→ docs/demo.html lokal aktuell"

test: ## Unit-Tests ausführen
	python -m pytest tests/ -v

lint: ## Code-Qualität prüfen (ruff)
	ruff check arborpress/

db-upgrade: ## Datenbank auf neueste Migration bringen
	alembic upgrade head

run: ## Entwicklungsserver starten  (config.toml wird benötigt)
	python -m arborpress.cli.main dev
