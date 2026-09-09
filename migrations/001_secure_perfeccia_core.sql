create extension if not exists pgcrypto with schema extensions;

create schema if not exists app_private;
revoke all on schema app_private from public, anon, authenticated;

create table if not exists public.app_documents (
  path text primary key,
  data jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint app_documents_path_format check (
    path <> ''
    and path !~ '^/'
    and path !~ '/$'
    and path !~ '//'
  ),
  constraint app_documents_data_object check (jsonb_typeof(data) = 'object')
);

comment on table public.app_documents is
  'Browser-reachable application documents. Every operation is constrained by RLS.';

create table if not exists app_private.documents (
  path text primary key,
  data jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint private_documents_path_format check (
    path <> ''
    and path !~ '^/'
    and path !~ '/$'
    and path !~ '//'
  ),
  constraint private_documents_data_object check (jsonb_typeof(data) = 'object')
);

comment on table app_private.documents is
  'Server-only billing, secrets, usage, checkout, invitations and audit documents.';

create table if not exists app_private.master_identity (
  singleton boolean primary key default true check (singleton),
  user_id uuid not null unique references auth.users(id) on delete restrict,
  email text not null,
  pinned_at timestamptz not null default now()
);

revoke all on all tables in schema app_private from public, anon, authenticated;

create or replace function app_private.touch_updated_at()
returns trigger
language plpgsql
set search_path = pg_catalog
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists app_documents_touch_updated_at on public.app_documents;
create trigger app_documents_touch_updated_at
before update on public.app_documents
for each row execute function app_private.touch_updated_at();

drop trigger if exists private_documents_touch_updated_at on app_private.documents;
create trigger private_documents_touch_updated_at
before update on app_private.documents
for each row execute function app_private.touch_updated_at();

create index if not exists app_documents_path_prefix_idx
  on public.app_documents (path text_pattern_ops);
create index if not exists app_documents_data_gin_idx
  on public.app_documents using gin (data jsonb_path_ops);
create index if not exists private_documents_path_prefix_idx
  on app_private.documents (path text_pattern_ops);
create index if not exists private_documents_data_gin_idx
  on app_private.documents using gin (data jsonb_path_ops);

create or replace function app_private.path_parts(requested_path text)
returns text[]
language sql
immutable
strict
set search_path = pg_catalog
as $$
  select string_to_array(requested_path, '/');
$$;

create or replace function app_private.path_part(requested_path text, part_index integer)
returns text
language sql
immutable
strict
set search_path = pg_catalog
as $$
  select (string_to_array(requested_path, '/'))[part_index];
$$;

create or replace function app_private.path_depth(requested_path text)
returns integer
language sql
immutable
strict
set search_path = pg_catalog
as $$
  select cardinality(string_to_array(requested_path, '/'));
$$;

create or replace function app_private.document_data(requested_path text)
returns jsonb
language sql
stable
security definer
set search_path = pg_catalog
as $$
  select document.data
  from public.app_documents as document
  where document.path = requested_path;
$$;

create or replace function app_private.is_verified_user()
returns boolean
language sql
stable
security definer
set search_path = pg_catalog
as $$
  select exists (
    select 1
    from auth.users as user_account
    where user_account.id = auth.uid()
      and user_account.email_confirmed_at is not null
  );
$$;

create or replace function app_private.current_user_email()
returns text
language sql
stable
security definer
set search_path = pg_catalog
as $$
  select lower(user_account.email)
  from auth.users as user_account
  where user_account.id = auth.uid()
    and user_account.email_confirmed_at is not null;
$$;

create or replace function app_private.master_email()
returns text
language sql
stable
security definer
set search_path = pg_catalog
as $$
  select lower(identity.email)
  from app_private.master_identity as identity
  where identity.singleton = true;
$$;

create or replace function app_private.is_master()
returns boolean
language sql
stable
security definer
set search_path = pg_catalog
as $$
  select app_private.is_verified_user()
    and exists (
      select 1
      from app_private.master_identity as identity
      where identity.singleton = true
        and identity.user_id = auth.uid()
    );
$$;

create or replace function app_private.is_platform_admin()
returns boolean
language sql
stable
security definer
set search_path = pg_catalog
as $$
  select app_private.is_master()
    or (
      app_private.is_verified_user()
      and lower(coalesce(app_private.document_data(
        'platformAdmins/' || app_private.current_user_email()
      )->>'ownerUid', '')) = auth.uid()::text
      and lower(coalesce(app_private.document_data(
        'platformAdmins/' || app_private.current_user_email()
      )->>'enabled', 'false')) = 'true'
    );
$$;

create or replace function app_private.is_moderator()
returns boolean
language sql
stable
security definer
set search_path = pg_catalog
as $$
  select app_private.is_verified_user()
    and lower(coalesce(app_private.document_data(
      'platformAdmins/' || app_private.current_user_email()
    )->>'ownerUid', '')) = auth.uid()::text
    and lower(coalesce(app_private.document_data(
      'platformAdmins/' || app_private.current_user_email()
    )->>'enabled', 'false')) = 'true'
    and lower(coalesce(app_private.document_data(
      'platformAdmins/' || app_private.current_user_email()
    )->>'moderatorEnabled', 'false')) = 'true';
$$;

create or replace function app_private.can_manage_platform_access()
returns boolean
language sql
stable
security definer
set search_path = pg_catalog
as $$
  select app_private.is_master() or app_private.is_moderator();
$$;

create or replace function app_private.owns_tenant(tenant_id text)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog
as $$
  select tenant_id <> 'sou'
    and app_private.is_verified_user()
    and coalesce(app_private.document_data('tenants/' || tenant_id)->>'ownerUid', '') = auth.uid()::text;
$$;

create or replace function app_private.has_hair_admin_access(tenant_id text)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog
as $$
  select tenant_id <> 'sou'
    and app_private.is_verified_user()
    and lower(coalesce(app_private.document_data(
      'tenants/' || tenant_id || '/apps/hair/members/' || auth.uid()::text
    )->>'enabled', 'false')) = 'true'
    and coalesce(app_private.document_data(
      'tenants/' || tenant_id || '/apps/hair/members/' || auth.uid()::text
    )->>'role', '') in ('owner', 'admin');
$$;

create or replace function app_private.can_manage_tenant(tenant_id text)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog
as $$
  select tenant_id <> 'sou'
    and (
      app_private.is_master()
      or app_private.owns_tenant(tenant_id)
      or app_private.has_hair_admin_access(tenant_id)
    );
$$;

create or replace function app_private.can_edit_tattoo_prompts()
returns boolean
language sql
stable
security definer
set search_path = pg_catalog
as $$
  select app_private.is_master()
    or app_private.is_moderator()
    or (
      app_private.is_verified_user()
      and lower(coalesce(app_private.document_data(
        'platformAdmins/' || app_private.current_user_email()
      )->>'ownerUid', '')) = auth.uid()::text
      and lower(coalesce(app_private.document_data(
        'platformAdmins/' || app_private.current_user_email()
      )->>'promptEnabled', 'false')) = 'true'
    );
$$;

create or replace function app_private.json_array_contains_email(
  payload jsonb,
  field_name text,
  expected_email text
)
returns boolean
language sql
immutable
set search_path = pg_catalog
as $$
  select jsonb_typeof(payload->field_name) = 'array'
    and exists (
      select 1
      from jsonb_array_elements_text(payload->field_name) as item(value)
      where lower(item.value) = lower(expected_email)
    );
$$;

create or replace function app_private.public_settings_are_safe(payload jsonb)
returns boolean
language sql
immutable
set search_path = pg_catalog
as $$
  select not exists (
    select 1
    from jsonb_object_keys(payload) as item(key)
    where item.key not in (
      'businessName', 'landingKicker', 'landingTitle', 'landingDescription',
      'landingLogo', 'primaryColor', 'accentColor', 'step6Enabled',
      'styleReferenceEnabled', 'discountEnabled', 'discountPercent',
      'quoteWhatsappNumber', 'quoteWhatsappMessage', 'landingImages',
      'landingImageSources', 'styles', 'updatedAt', 'securitySanitizedAt'
    )
  );
$$;

create or replace function app_private.prompt_fields_unchanged(old_data jsonb, new_data jsonb)
returns boolean
language sql
immutable
set search_path = pg_catalog
as $$
  select (old_data->'promptBlocks') is not distinct from (new_data->'promptBlocks')
    and (old_data->'referencePromptBlocks') is not distinct from (new_data->'referencePromptBlocks')
    and (old_data->'negativePrompt') is not distinct from (new_data->'negativePrompt')
    and (old_data->'referenceNegativePrompt') is not distinct from (new_data->'referenceNegativePrompt');
$$;

create or replace function app_private.can_read_document(requested_path text, payload jsonb)
returns boolean
language plpgsql
stable
security definer
set search_path = pg_catalog
as $$
declare
  parts text[] := app_private.path_parts(requested_path);
  depth integer := cardinality(parts);
  tenant_id text := parts[2];
begin
  if parts[1] = 'platformAccess' and depth = 2 then
    return app_private.can_manage_platform_access();
  end if;

  if parts[1] = 'platformAdmins' and depth = 2 then
    return app_private.can_manage_platform_access()
      or (
        app_private.is_verified_user()
        and lower(parts[2]) = app_private.current_user_email()
        and coalesce(payload->>'ownerUid', '') = auth.uid()::text
      );
  end if;

  if parts[1] = 'tenants' and depth = 2 then
    return app_private.is_master() or app_private.owns_tenant(tenant_id);
  end if;

  if parts[1] = 'tenants' and depth = 4 and parts[3] = 'settings' then
    return parts[4] = 'public'
      or app_private.is_master()
      or app_private.owns_tenant(tenant_id);
  end if;

  if parts[1] = 'tenants' and depth = 4 and parts[3] = 'landing' then
    return app_private.is_master()
      or app_private.owns_tenant(tenant_id)
      or (
        parts[4] = 'published'
        and coalesce(app_private.document_data('tenants/' || tenant_id)->>'landingStatus', '') = 'published'
      );
  end if;

  if parts[1] = 'tenants' and depth >= 4 and parts[3] = 'apps' and parts[4] = 'hair' then
    if depth = 4 then
      return app_private.is_verified_user();
    end if;
    if depth = 6 and parts[5] = 'members' then
      return app_private.is_master()
        or app_private.can_manage_tenant(tenant_id)
        or (app_private.is_verified_user() and parts[6] = auth.uid()::text);
    end if;
    if depth = 6 and parts[5] = 'settings' then
      return (parts[6] = 'public' and app_private.is_verified_user())
        or (parts[6] = 'admin' and app_private.can_manage_tenant(tenant_id));
    end if;
    if depth >= 8 and parts[5] = 'users' then
      return app_private.is_verified_user() and parts[6] = auth.uid()::text;
    end if;
    return false;
  end if;

  if parts[1] = 'platformUsers' and depth >= 2 then
    return app_private.is_verified_user() and parts[2] = auth.uid()::text;
  end if;

  if parts[1] = 'tattooerApplications' and depth = 2 then
    return app_private.is_master()
      or (app_private.is_verified_user() and parts[2] = auth.uid()::text);
  end if;

  return false;
end;
$$;

create or replace function app_private.can_insert_document(requested_path text, payload jsonb)
returns boolean
language plpgsql
stable
security definer
set search_path = pg_catalog
as $$
declare
  parts text[] := app_private.path_parts(requested_path);
  depth integer := cardinality(parts);
  tenant_id text := parts[2];
  target_email text;
begin
  if not app_private.is_verified_user() then
    return false;
  end if;

  if parts[1] = 'platformAccess' and depth = 2 then
    return app_private.is_master();
  end if;

  if parts[1] = 'platformAdmins' and depth = 2 then
    target_email := lower(parts[2]);
    return app_private.is_master()
      or (
        app_private.is_moderator()
        and target_email <> app_private.master_email()
        and lower(coalesce(payload->>'moderatorEnabled', 'false')) <> 'true'
      );
  end if;

  if parts[1] = 'tenants' and depth = 2 then
    return tenant_id <> 'sou'
      and app_private.is_platform_admin()
      and coalesce(payload->>'ownerUid', '') = auth.uid()::text;
  end if;

  if parts[1] = 'tenants' and depth = 4 and parts[3] = 'settings' then
    return app_private.can_manage_tenant(tenant_id)
      and parts[4] in ('admin', 'public')
      and (parts[4] <> 'public' or app_private.public_settings_are_safe(payload))
      and (
        parts[4] <> 'admin'
        or app_private.can_edit_tattoo_prompts()
        or not (payload ?| array['promptBlocks', 'referencePromptBlocks', 'negativePrompt', 'referenceNegativePrompt'])
      );
  end if;

  if parts[1] = 'tenants' and depth = 4 and parts[3] = 'landing' then
    return app_private.can_manage_tenant(tenant_id);
  end if;

  if parts[1] = 'tenants' and depth >= 4 and parts[3] = 'apps' and parts[4] = 'hair' then
    return app_private.can_manage_tenant(tenant_id);
  end if;

  if parts[1] = 'platformUsers' and depth >= 2 then
    return parts[2] = auth.uid()::text;
  end if;

  if parts[1] = 'tattooerApplications' and depth = 2 then
    return parts[2] = auth.uid()::text
      and lower(coalesce(payload->>'email', '')) = app_private.current_user_email()
      and coalesce(payload->>'status', '') = 'pending';
  end if;

  return false;
end;
$$;

create or replace function app_private.can_update_document(
  requested_path text,
  old_data jsonb,
  new_data jsonb
)
returns boolean
language plpgsql
stable
security definer
set search_path = pg_catalog
as $$
declare
  parts text[] := app_private.path_parts(requested_path);
  depth integer := cardinality(parts);
  tenant_id text := parts[2];
  target_email text;
  master_address text := app_private.master_email();
begin
  if not app_private.is_verified_user() then
    return false;
  end if;

  if parts[1] = 'platformAccess' and depth = 2 then
    if parts[2] = 'moderators' then
      return app_private.is_master();
    end if;
    if not app_private.can_manage_platform_access() then
      return false;
    end if;
    if not app_private.json_array_contains_email(new_data, 'emails', master_address) then
      return false;
    end if;
    if parts[2] = 'hairAccess' then
      return app_private.json_array_contains_email(new_data, 'landingBetaEmails', master_address)
        and app_private.json_array_contains_email(new_data, 'generationEmails', master_address);
    end if;
    if parts[2] = 'promptAccess' then
      return app_private.json_array_contains_email(new_data, 'hairEmails', master_address);
    end if;
    return true;
  end if;

  if parts[1] = 'platformAdmins' and depth = 2 then
    target_email := lower(parts[2]);
    return app_private.is_master()
      or (
        app_private.is_moderator()
        and target_email <> master_address
        and (new_data->'moderatorEnabled') is not distinct from (old_data->'moderatorEnabled')
      );
  end if;

  if parts[1] = 'tenants' and depth = 2 then
    return tenant_id <> 'sou'
      and (
        app_private.is_master()
        or (
          app_private.owns_tenant(tenant_id)
          and (new_data->'ownerUid') is not distinct from (old_data->'ownerUid')
        )
      );
  end if;

  if parts[1] = 'tenants' and depth = 4 and parts[3] = 'settings' then
    return app_private.can_manage_tenant(tenant_id)
      and parts[4] in ('admin', 'public')
      and (parts[4] <> 'public' or app_private.public_settings_are_safe(new_data))
      and (
        parts[4] <> 'admin'
        or app_private.can_edit_tattoo_prompts()
        or app_private.prompt_fields_unchanged(old_data, new_data)
      );
  end if;

  if parts[1] = 'tenants' and depth = 4 and parts[3] = 'landing' then
    return app_private.can_manage_tenant(tenant_id);
  end if;

  if parts[1] = 'tenants' and depth >= 4 and parts[3] = 'apps' and parts[4] = 'hair' then
    return app_private.can_manage_tenant(tenant_id);
  end if;

  if parts[1] = 'platformUsers' and depth >= 2 then
    return parts[2] = auth.uid()::text;
  end if;

  if parts[1] = 'tattooerApplications' and depth = 2 then
    return app_private.is_master()
      or (
        parts[2] = auth.uid()::text
        and lower(coalesce(new_data->>'email', '')) = app_private.current_user_email()
        and (new_data->'status') is not distinct from (old_data->'status')
      );
  end if;

  return false;
end;
$$;

create or replace function app_private.can_delete_document(requested_path text, payload jsonb)
returns boolean
language plpgsql
stable
security definer
set search_path = pg_catalog
as $$
declare
  parts text[] := app_private.path_parts(requested_path);
  depth integer := cardinality(parts);
  tenant_id text := parts[2];
  target_email text := lower(parts[2]);
begin
  if not app_private.is_verified_user() then
    return false;
  end if;

  if parts[1] = 'platformAdmins' and depth = 2 then
    return app_private.is_master()
      or (app_private.is_moderator() and target_email <> app_private.master_email());
  end if;

  if parts[1] = 'tenants' and depth = 2 then
    return tenant_id <> 'sou' and app_private.is_master();
  end if;

  if parts[1] = 'tenants' and depth >= 4 then
    return app_private.can_manage_tenant(tenant_id);
  end if;

  if parts[1] = 'platformUsers' and depth >= 2 then
    return parts[2] = auth.uid()::text;
  end if;

  if parts[1] = 'tattooerApplications' and depth = 2 then
    return app_private.is_master();
  end if;

  return false;
end;
$$;

create or replace function app_private.can_update_existing_document(
  requested_path text,
  new_data jsonb
)
returns boolean
language sql
stable
security definer
set search_path = pg_catalog
as $$
  select app_private.can_update_document(
    requested_path,
    app_private.document_data(requested_path),
    new_data
  );
$$;

create or replace function public.read_public_document(requested_path text)
returns jsonb
language plpgsql
stable
security definer
set search_path = pg_catalog
as $$
declare
  parts text[] := app_private.path_parts(requested_path);
  payload jsonb;
begin
  if cardinality(parts) <> 4 or parts[1] <> 'tenants' or parts[2] = 'sou' then
    return null;
  end if;

  if not (
    (parts[3] = 'settings' and parts[4] = 'public')
    or (
      parts[3] = 'landing'
      and parts[4] = 'published'
      and coalesce(app_private.document_data('tenants/' || parts[2])->>'landingStatus', '') = 'published'
    )
  ) then
    return null;
  end if;

  select document.data into payload
  from public.app_documents as document
  where document.path = requested_path;

  return payload;
end;
$$;

create or replace function app_private.pin_master_identity(master_user_id uuid, master_email text)
returns void
language plpgsql
security definer
set search_path = pg_catalog
as $$
declare
  existing app_private.master_identity%rowtype;
begin
  if master_user_id is null or nullif(lower(trim(master_email)), '') is null then
    raise exception 'Master identity requires a UID and email';
  end if;

  select * into existing
  from app_private.master_identity
  where singleton = true
  for update;

  if found and existing.user_id <> master_user_id then
    raise exception 'Master identity is already pinned to another UID';
  end if;

  insert into app_private.master_identity (singleton, user_id, email)
  values (true, master_user_id, lower(trim(master_email)))
  on conflict (singleton) do update
    set email = excluded.email;
end;
$$;

revoke all on function public.read_public_document(text) from public;
grant execute on function public.read_public_document(text) to anon, authenticated;

revoke all on all functions in schema app_private from public, anon, authenticated;
grant usage on schema app_private to anon, authenticated;
grant execute on function app_private.can_read_document(text, jsonb) to authenticated;
grant execute on function app_private.can_insert_document(text, jsonb) to authenticated;
grant execute on function app_private.can_update_document(text, jsonb, jsonb) to authenticated;
grant execute on function app_private.can_update_existing_document(text, jsonb) to authenticated;
grant execute on function app_private.can_delete_document(text, jsonb) to authenticated;
grant execute on function app_private.is_verified_user() to authenticated;
grant execute on function app_private.can_manage_tenant(text) to authenticated;
grant execute on function app_private.pin_master_identity(uuid, text) to service_role;

alter table public.app_documents enable row level security;

drop policy if exists app_documents_select on public.app_documents;
create policy app_documents_select
on public.app_documents
for select
to authenticated
using (app_private.can_read_document(path, data));

drop policy if exists app_documents_insert on public.app_documents;
create policy app_documents_insert
on public.app_documents
for insert
to authenticated
with check (app_private.can_insert_document(path, data));

drop policy if exists app_documents_update on public.app_documents;
create policy app_documents_update
on public.app_documents
for update
to authenticated
using (app_private.can_read_document(path, data))
with check (app_private.can_update_existing_document(path, data));

drop policy if exists app_documents_delete on public.app_documents;
create policy app_documents_delete
on public.app_documents
for delete
to authenticated
using (app_private.can_delete_document(path, data));

revoke all on public.app_documents from public, anon;
grant select, insert, update, delete on public.app_documents to authenticated;

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values
  ('tenant-public', 'tenant-public', true, 15728640, array['image/jpeg', 'image/png', 'image/webp']),
  ('tenant-private', 'tenant-private', false, 15728640, array['image/jpeg', 'image/png', 'image/webp']),
  ('user-private', 'user-private', false, 15728640, array['image/jpeg', 'image/png', 'image/webp']),
  ('hair-private', 'hair-private', false, 15728640, array['image/jpeg', 'image/png', 'image/webp'])
on conflict (id) do update set
  public = excluded.public,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists tenant_public_read on storage.objects;
create policy tenant_public_read
on storage.objects
for select
to anon, authenticated
using (
  bucket_id = 'tenant-public'
  and app_private.path_part(name, 1) <> 'sou'
  and app_private.path_part(name, 2) in ('styles', 'landing', 'branding')
);

drop policy if exists tenant_public_insert on storage.objects;
create policy tenant_public_insert
on storage.objects
for insert
to authenticated
with check (
  bucket_id = 'tenant-public'
  and app_private.path_part(name, 1) <> 'sou'
  and app_private.path_part(name, 2) in ('styles', 'landing', 'branding')
  and app_private.can_manage_tenant(app_private.path_part(name, 1))
);

drop policy if exists tenant_public_update on storage.objects;
create policy tenant_public_update
on storage.objects
for update
to authenticated
using (
  bucket_id = 'tenant-public'
  and app_private.can_manage_tenant(app_private.path_part(name, 1))
)
with check (
  bucket_id = 'tenant-public'
  and app_private.path_part(name, 1) <> 'sou'
  and app_private.path_part(name, 2) in ('styles', 'landing', 'branding')
  and app_private.can_manage_tenant(app_private.path_part(name, 1))
);

drop policy if exists tenant_public_delete on storage.objects;
create policy tenant_public_delete
on storage.objects
for delete
to authenticated
using (
  bucket_id = 'tenant-public'
  and app_private.can_manage_tenant(app_private.path_part(name, 1))
);

drop policy if exists tenant_private_owner_access on storage.objects;
create policy tenant_private_owner_access
on storage.objects
for select
to authenticated
using (
  bucket_id = 'tenant-private'
  and app_private.can_manage_tenant(app_private.path_part(name, 1))
);

drop policy if exists tenant_private_owner_insert on storage.objects;
create policy tenant_private_owner_insert
on storage.objects
for insert
to authenticated
with check (
  bucket_id = 'tenant-private'
  and app_private.can_manage_tenant(app_private.path_part(name, 1))
);

drop policy if exists tenant_private_owner_update on storage.objects;
create policy tenant_private_owner_update
on storage.objects
for update
to authenticated
using (
  bucket_id = 'tenant-private'
  and app_private.can_manage_tenant(app_private.path_part(name, 1))
)
with check (
  bucket_id = 'tenant-private'
  and app_private.can_manage_tenant(app_private.path_part(name, 1))
);

drop policy if exists tenant_private_owner_delete on storage.objects;
create policy tenant_private_owner_delete
on storage.objects
for delete
to authenticated
using (
  bucket_id = 'tenant-private'
  and app_private.can_manage_tenant(app_private.path_part(name, 1))
);

drop policy if exists user_private_read on storage.objects;
create policy user_private_read
on storage.objects
for select
to authenticated
using (
  bucket_id = 'user-private'
  and app_private.is_verified_user()
  and app_private.path_part(name, 1) = auth.uid()::text
);

drop policy if exists user_private_insert on storage.objects;
create policy user_private_insert
on storage.objects
for insert
to authenticated
with check (
  bucket_id = 'user-private'
  and app_private.is_verified_user()
  and app_private.path_part(name, 1) = auth.uid()::text
  and (
    (
      app_private.path_depth(name) = 5
      and app_private.path_part(name, 2) = 'generations'
      and app_private.path_part(name, 4) = 'input'
      and app_private.path_part(name, 5) ~ '^(skin|design|reference)\.(jpg|jpeg|png|webp)$'
    )
    or (
      app_private.path_depth(name) = 3
      and app_private.path_part(name, 2) = 'quotes'
      and app_private.path_part(name, 3) ~ '^quote_[A-Za-z0-9_-]+\.(jpg|jpeg|png|webp)$'
    )
  )
);

drop policy if exists user_private_update on storage.objects;
create policy user_private_update
on storage.objects
for update
to authenticated
using (
  bucket_id = 'user-private'
  and app_private.path_part(name, 1) = auth.uid()::text
  and (
    app_private.path_part(name, 4) = 'input'
    or app_private.path_part(name, 2) = 'quotes'
  )
)
with check (
  bucket_id = 'user-private'
  and app_private.path_part(name, 1) = auth.uid()::text
  and (
    app_private.path_part(name, 4) = 'input'
    or app_private.path_part(name, 2) = 'quotes'
  )
);

drop policy if exists user_private_delete on storage.objects;
create policy user_private_delete
on storage.objects
for delete
to authenticated
using (
  bucket_id = 'user-private'
  and app_private.path_part(name, 1) = auth.uid()::text
  and (
    app_private.path_part(name, 4) = 'input'
    or app_private.path_part(name, 2) = 'quotes'
  )
);

revoke all on app_private.master_identity from public, anon, authenticated;
revoke all on app_private.documents from public, anon, authenticated;

