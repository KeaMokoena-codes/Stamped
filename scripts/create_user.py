"""Add an explicitly chosen demo user to the configured Stamped database."""

import argparse
from datetime import datetime, timezone

from access import Role, connect_database


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--user-id", required=True)
    parser.add_argument("--display-name", required=True)
    parser.add_argument("--role", required=True, choices=[role.value for role in Role])
    args = parser.parse_args()

    with connect_database() as connection:
        connection.execute(
            "INSERT INTO users (user_id, display_name, role, created_at, active) "
            "VALUES (?, ?, ?, ?, 1)",
            (
                args.user_id,
                args.display_name,
                args.role,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        connection.commit()

    print(f"Added user {args.user_id!r} with role {args.role!r}.")


if __name__ == "__main__":
    main()
