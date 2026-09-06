# Supabase self-hosted for PerfeccIA

This is the Supabase Docker configuration adapted for the `deploy_app_01`
EasyPanel project. It is derived from the official `self-hosted/v0.8.0`
configuration and intentionally excludes the optional Logs/Analytics override.

## Resource envelope

The container memory limits total 4,832 MiB (4.72 GiB), leaving a small safety
margin beneath the 5 GiB budget. Database and Storage data use named Docker
volumes so that deployments do not write application data into the Git checkout.

## Deployment requirements

- Create the Compose service from this directory on the `master` branch.
- Store all runtime secrets only in EasyPanel environment variables. Never add a
  `.env` file to this repository.
- Do not expose Postgres or Supavisor ports publicly.
- Add an HTTPS domain only to `api-gw` on port `8000`. Studio is protected by
  the dashboard credentials at that gateway.
- Keep signup, email provider, and OAuth disabled until the migration plan is
  ready; this pilot is infrastructure-only.

## Operational baseline

- Back up the database volume before migrations and verify a restore in a
  separate environment.
- Monitor the aggregate memory limit and storage growth before onboarding users.
- Upgrade through a reviewed upstream Supabase self-hosted release, not image
  tags chosen independently.
