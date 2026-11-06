alter policy tasks_read on public.tasks using((select private.is_manager()) or (deleted_at is null and assignee_id=(select auth.uid())));
alter policy objects_read on public.objects using((select private.is_manager()) or (deleted_at is null and exists(select 1 from public.tasks t where t.object_id=objects.id and t.assignee_id=(select auth.uid()) and t.deleted_at is null)));
