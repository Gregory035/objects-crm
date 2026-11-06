
create schema if not exists private;
create type public.task_status as enum ('new','in_progress','review','accepted','rework');
create table public.profiles(id uuid primary key references auth.users(id), name text not null, role text not null check(role in ('manager','worker')));
create table public.objects(id uuid primary key default gen_random_uuid(), name text not null check(length(trim(name))>0), address text not null, deleted_at timestamptz);
create table public.tasks(id uuid primary key default gen_random_uuid(), title text not null check(length(trim(title))>0), description text not null default '', object_id uuid not null references public.objects(id), assignee_id uuid not null references public.profiles(id), author_id uuid not null default auth.uid() references public.profiles(id), status public.task_status not null default 'new', created_at timestamptz not null default now(), deleted_at timestamptz, transition_comment text);
create table public.task_history(id uuid primary key default gen_random_uuid(), task_id uuid not null references public.tasks(id), actor_id uuid not null references public.profiles(id), from_status public.task_status, to_status public.task_status not null, comment text, created_at timestamptz not null default now());
create index on public.tasks(assignee_id);
create index on public.tasks(object_id);
create index on public.tasks(author_id);
create index on public.task_history(task_id,created_at);
create index on public.task_history(actor_id);
alter table public.profiles enable row level security;
alter table public.objects enable row level security;
alter table public.tasks enable row level security;
alter table public.task_history enable row level security;
create function private.is_manager() returns boolean language sql stable security definer set search_path='' as $$
 select auth.uid() is not null and exists(select 1 from public.profiles where id=auth.uid() and role='manager')
$$;
revoke all on function private.is_manager() from public;
grant usage on schema private to authenticated;
grant execute on function private.is_manager() to authenticated;
create policy profiles_read on public.profiles for select to authenticated using(id=(select auth.uid()) or (select private.is_manager()));
create policy objects_read on public.objects for select to authenticated using(deleted_at is null and ((select private.is_manager()) or exists(select 1 from public.tasks t where t.object_id=objects.id and t.assignee_id=(select auth.uid()) and t.deleted_at is null)));
create policy objects_insert on public.objects for insert to authenticated with check((select private.is_manager()) and deleted_at is null);
create policy objects_update on public.objects for update to authenticated using((select private.is_manager())) with check((select private.is_manager()));
create policy tasks_read on public.tasks for select to authenticated using(deleted_at is null and ((select private.is_manager()) or assignee_id=(select auth.uid())));
create policy tasks_insert on public.tasks for insert to authenticated with check((select private.is_manager()) and author_id=(select auth.uid()) and status='new' and deleted_at is null);
create policy tasks_update on public.tasks for update to authenticated using(deleted_at is null and ((select private.is_manager()) or assignee_id=(select auth.uid()))) with check((select private.is_manager()) or assignee_id=(select auth.uid()));
create policy history_read on public.task_history for select to authenticated using(exists(select 1 from public.tasks t where t.id=task_id));
revoke all on public.profiles,public.objects,public.tasks,public.task_history from anon,authenticated;
grant select on public.profiles,public.objects,public.tasks,public.task_history to authenticated;
grant insert,update on public.objects,public.tasks to authenticated;
create function private.validate_task() returns trigger language plpgsql security definer set search_path='' as $$
declare mgr boolean:=private.is_manager();
begin
 if auth.uid() is null then raise exception 'Требуется вход'; end if;
 if not exists(select 1 from public.profiles where id=new.assignee_id and role='worker') then raise exception 'Исполнитель не найден'; end if;
 if not exists(select 1 from public.objects where id=new.object_id and deleted_at is null) then raise exception 'Объект недоступен'; end if;
 if TG_OP='INSERT' then
   if not mgr or new.status<>'new' then raise exception 'Создание запрещено'; end if;
   new.author_id:=auth.uid(); new.created_at:=now(); new.deleted_at:=null; new.transition_comment:=null;
 else
   if old.deleted_at is not null then raise exception 'Задача удалена'; end if;
   if new.id<>old.id or new.author_id<>old.author_id or new.created_at<>old.created_at then raise exception 'Системные поля неизменяемы'; end if;
   if not mgr and (old.assignee_id<>auth.uid() or row(new.title,new.description,new.object_id,new.assignee_id,new.deleted_at) is distinct from row(old.title,old.description,old.object_id,old.assignee_id,old.deleted_at)) then raise exception 'Изменение данных запрещено'; end if;
   if new.status<>old.status then
     if row(new.title,new.description,new.object_id,new.assignee_id,new.deleted_at) is distinct from row(old.title,old.description,old.object_id,old.assignee_id,old.deleted_at) then raise exception 'Меняйте статус отдельно от данных'; end if;
     if not ((not mgr and old.assignee_id=auth.uid() and ((old.status in ('new','rework') and new.status='in_progress') or (old.status='in_progress' and new.status='review'))) or (mgr and old.status='review' and new.status in ('accepted','rework'))) then raise exception 'Недопустимый переход статуса'; end if;
     if new.status='rework' and coalesce(length(trim(new.transition_comment)),0)=0 then raise exception 'Укажите причину доработки'; end if;
   else new.transition_comment:=old.transition_comment;
   end if;
 end if;
 return new;
end $$;
create trigger validate_task before insert or update on public.tasks for each row execute function private.validate_task();
create function private.record_status() returns trigger language plpgsql security definer set search_path='' as $$
begin
 if auth.uid() is null then raise exception 'Требуется вход'; end if;
 if TG_OP='INSERT' then
 insert into public.task_history(task_id,actor_id,to_status) values(new.id,auth.uid(),new.status);
 elsif old.status<>new.status then
 insert into public.task_history(task_id,actor_id,from_status,to_status,comment) values(new.id,auth.uid(),old.status,new.status,nullif(trim(new.transition_comment),''));
 end if;
 return new;
end $$;
create trigger record_status after insert or update on public.tasks for each row execute function private.record_status();
revoke all on function private.validate_task(),private.record_status() from public,anon,authenticated;

