create policy related_profiles_read on public.profiles for select to authenticated using(exists(select 1 from public.tasks where author_id=profiles.id) or exists(select 1 from public.task_history where actor_id=profiles.id));
create function private.validate_object() returns trigger language plpgsql security definer set search_path='' as $$
begin
if auth.uid() is null or not private.is_manager() then raise exception 'Доступ запрещён'; end if;
if new.id<>old.id then raise exception 'ID неизменяем'; end if;
if new.deleted_at is not null and exists(select 1 from public.tasks where object_id=old.id and deleted_at is null) then raise exception 'Сначала удалите задачи объекта'; end if;
return new;
end $$;
revoke all on function private.validate_object() from public,anon,authenticated;
create trigger validate_object before update on public.objects for each row execute function private.validate_object();
