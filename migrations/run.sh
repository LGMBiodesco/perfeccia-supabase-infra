#!/bin/sh
set -eu

psql_base() {
  psql \
    --no-psqlrc \
    --host "$POSTGRES_HOST" \
    --port "$POSTGRES_PORT" \
    --username postgres \
    --dbname "$POSTGRES_DB" \
    "$@"
}

psql_base --set ON_ERROR_STOP=1 <<'SQL'
create schema if not exists app_migrations;
revoke all on schema app_migrations from public, anon, authenticated;

create table if not exists app_migrations.schema_migrations (
  version text primary key,
  checksum text not null,
  applied_at timestamptz not null default now()
);

revoke all on app_migrations.schema_migrations from public, anon, authenticated;
SQL

for migration in /migrations/[0-9][0-9][0-9]_*.sql; do
  [ -f "$migration" ] || continue

  version="$(basename "$migration")"
  checksum="$(sha256sum "$migration" | awk '{print $1}')"
  case "$version:$checksum" in
    *[!A-Za-z0-9_.:-]*)
      echo "Unsafe migration metadata: $version" >&2
      exit 1
      ;;
  esac

  if ! applied_checksum="$(
    psql_base --tuples-only --no-align \
      --command "select checksum from app_migrations.schema_migrations where version = '$version'" \
      | tr -d '[:space:]'
  )"; then
    echo "Could not inspect migration state for $version." >&2
    exit 1
  fi

  if [ -n "$applied_checksum" ]; then
    if [ "$applied_checksum" != "$checksum" ]; then
      echo "Migration $version changed after it was applied; refusing to continue." >&2
      exit 1
    fi
    echo "Skipping $version (already applied)."
    continue
  fi

  echo "Applying $version..."
  psql_base \
    --set ON_ERROR_STOP=1 \
    --single-transaction \
    --file "$migration" \
    --command "insert into app_migrations.schema_migrations (version, checksum) values ('$version', '$checksum')"
done

echo "Application database migrations are current."
