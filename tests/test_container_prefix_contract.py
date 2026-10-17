from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_runtime_images_use_explicit_prefix_and_only_persist_instance_state() -> None:
    for name in ("Containerfile.ubuntu", "Containerfile.almalinux"):
        contents = (ROOT / "container" / name).read_text(encoding="utf-8")
        runtime = contents.split(" AS runtime", maxsplit=1)[1]

        assert 'ARBORPRESS_PREFIX="/srv/arborpress"' in runtime
        assert "/srv/arborpress/app/bin:" in runtime
        assert "ln -s /opt/venv /srv/arborpress/app/runtime/venv" in runtime
        assert "ln -s /opt/python314 /srv/arborpress/app/runtime/python314" in runtime
        assert "ln -s ../runtime/venv/bin/arborpress" in runtime
        assert 'WORKDIR /\n' in runtime
        assert 'VOLUME ["/srv/arborpress/instance"]' in runtime
        assert 'ARG PIP_EXTRAS=""' in contents
        assert 'for extra in $(printf \'%s\' "$PIP_EXTRAS" | tr \',\' \' \')' in contents
        assert "/app/media" not in runtime
        assert "/app/logs" not in runtime
        assert "/opt/app-root/src" not in runtime
        assert "/data" not in runtime
        assert "/opt/poetry" not in runtime
        assert "node" not in runtime.lower()


def test_compose_examples_share_one_prefix_and_instance_volume() -> None:
    compose_files = sorted((ROOT / "container").glob("compose*.yml"))
    assert len(compose_files) == 4
    for compose_file in compose_files:
        contents = compose_file.read_text(encoding="utf-8")

        assert "ARBORPRESS_PREFIX: /srv/arborpress" in contents
        assert "arborpress_instance:/srv/arborpress/instance" in contents
        assert "app_media:" not in contents
        assert "app_logs:" not in contents
        assert "/app/media" not in contents
        assert "/app/logs" not in contents
        assert "/opt/app-root/src" not in contents


def test_container_entrypoint_upgrades_then_starts_with_same_prefix() -> None:
    contents = (ROOT / "container" / "entrypoint.sh").read_text(encoding="utf-8")

    migration = 'arborpress --prefix "$ARBORPRESS_PREFIX" db upgrade'
    server = 'exec arborpress --prefix "$ARBORPRESS_PREFIX" serve'
    assert migration in contents
    assert server in contents
    assert contents.index(migration) < contents.index(server)
    assert "/data" not in contents
