import os
import re
import asyncio
from pathlib import Path

import asyncpg

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

REPO_ROOT = Path(__file__).resolve().parent.parent
DB_DSN = os.environ.get(
    "CLOUDPATH_DB_DSN",
    "postgresql://cloudpath:cloudpath@localhost:5432/cloudpath",
)


def _migration_files():
    files = sorted(REPO_ROOT.glob("migration_*.sql"))
    files.sort(key=lambda p: [int(n) for n in re.findall(r"\d+", p.stem)[:1]] or [0])
    return files


async def main():
    conn = await asyncpg.connect(dsn=DB_DSN, command_timeout=30)
    try:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                filename TEXT PRIMARY KEY,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """)

        applied = {r["filename"] for r in await conn.fetch("SELECT filename FROM schema_migrations")}

        schema_path = REPO_ROOT / "schema.sql"
        if "schema.sql" not in applied:
            print("Applying schema.sql ...")
            await conn.execute(schema_path.read_text(encoding="utf-8"))
            await conn.execute(
                "INSERT INTO schema_migrations (filename) VALUES ($1)", "schema.sql"
            )
        else:
            print("schema.sql already applied, skipping.")

        for path in _migration_files():
            if path.name in applied:
                print(f"{path.name} already applied, skipping.")
                continue
            print(f"Applying {path.name} ...")
            await conn.execute(path.read_text(encoding="utf-8"))
            await conn.execute(
                "INSERT INTO schema_migrations (filename) VALUES ($1)", path.name
            )

        print("Done.")
    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main())
