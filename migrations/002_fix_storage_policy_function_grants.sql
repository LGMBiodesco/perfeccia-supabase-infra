-- Storage policies execute as anon/authenticated and must be able to evaluate
-- these immutable path parsers. They expose no data and perform no writes.
grant execute on function app_private.path_parts(text) to anon, authenticated;
grant execute on function app_private.path_part(text, integer) to anon, authenticated;
grant execute on function app_private.path_depth(text) to anon, authenticated;

