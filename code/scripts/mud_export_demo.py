from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dib.evaluation.mud_export import write_mud_file
from dib.registry import db, services


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export one site's locally Active facts through the lifecycle registry."
    )
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--site-id", required=True)
    parser.add_argument("--device-type", required=True)
    parser.add_argument("--output-dir", default="outputs/mud_export")
    args = parser.parse_args(argv)

    os.environ["DIB_DATABASE_URL"] = args.database_url
    db._engine = None
    db._SessionLocal = None
    output_dir = Path(args.output_dir)
    session = db.get_session()
    try:
        result = services.export_active_mud(session, args.site_id, args.device_type)
        destination = output_dir / f"{args.site_id}-{args.device_type.replace('/', '_')}.json"
        write_mud_file(destination, result)
    finally:
        session.close()
    print(
        f"Exported {result.exported_ace_count} locally Active ACEs "
        f"({len(result.skipped_endpoints)} unrepresentable) to {destination}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
