-- Device limits enforced strictly for every shop enrolled from 10 Oct 2026.
-- The launch grace period (a phone that is "already working" is let in over the plan limit, marked OVER PLAN)
-- now applies ONLY to shops that already existed before 10 Oct 2026. A new shop on the 500 plan cannot link a
-- third phone, full stop - the Admin must replace/remove one of the two, or upgrade the plan.
-- Only the grace condition changed from the previous version of register_device.
create or replace function public.register_device(p_shop_id text, p_device_id text, p_label text default null, p_existing boolean default false, p_admin_pin text default null, p_accept_upgrade boolean default false)
returns jsonb language plpgsql security definer set search_path to 'public' as $function$
declare
  v_plan   text;
  v_limit  integer;
  v_count  integer;
  v_dev    text := left(coalesce(p_device_id, ''), 80);
  v_label  text := nullif(left(coalesce(p_label, ''), 80), '');
  v_status text;
  v_seen   timestamptz;
  v_over   boolean;
  v_has    boolean := false;
  v_admin  text;
  v_start  timestamptz;
  v_shop_created timestamptz;
begin
  if length(v_dev) < 6 then
    return jsonb_build_object('ok', false, 'code', 'bad_device');
  end if;

  select coalesce(s.plan, 'small'), s.created_at into v_plan, v_shop_created
    from public.shops s where s.id::text = p_shop_id for update;
  if not found then
    return jsonb_build_object('ok', false, 'code', 'no_shop');
  end if;
  v_limit := public.plan_device_limit(v_plan);

  select d.status, d.last_seen, d.over_plan into v_status, v_seen, v_over
    from public.shop_devices d where d.shop_id = p_shop_id and d.device_id = v_dev;
  v_has := found;

  if v_has and v_status = 'active' and v_seen > now() - interval '30 days' then
    update public.shop_devices d set last_seen = now(), label = coalesce(v_label, d.label)
     where d.shop_id = p_shop_id and d.device_id = v_dev;
    select count(*) into v_count from public.shop_devices d
     where d.shop_id = p_shop_id and d.status = 'active' and d.last_seen > now() - interval '30 days';
    return jsonb_build_object('ok', true, 'count', v_count, 'limit', v_limit, 'plan', v_plan, 'over_plan', v_over);
  end if;

  if v_has and v_status = 'removed' and p_existing then
    return jsonb_build_object('ok', false, 'code', 'removed', 'limit', v_limit, 'plan', v_plan);
  end if;

  select count(*) into v_count from public.shop_devices d
   where d.shop_id = p_shop_id and d.status = 'active' and d.last_seen > now() - interval '30 days'
     and d.device_id <> v_dev;

  if p_admin_pin is not null then
    select t.name into v_admin from public.staff t
     where t.shop_id::text = p_shop_id and t.pin = p_admin_pin and t.role = 'admin' and t.active is not false
     limit 1;
    if v_admin is null then
      return jsonb_build_object('ok', false, 'code', 'bad_pin', 'count', v_count, 'limit', v_limit, 'plan', v_plan);
    end if;
  end if;

  if v_has and v_status = 'removed' and v_admin is null then
    return jsonb_build_object('ok', false, 'code', 'needs_admin', 'count', v_count, 'limit', v_limit, 'plan', v_plan);
  end if;

  if v_count < v_limit then
    insert into public.shop_devices (shop_id, device_id, label) values (p_shop_id, v_dev, v_label)
    on conflict (shop_id, device_id) do update
      set status = 'active', last_seen = now(), label = coalesce(excluded.label, public.shop_devices.label),
          over_plan = false, removed_by = null, removed_at = null;
    return jsonb_build_object('ok', true, 'count', v_count + 1, 'limit', v_limit, 'plan', v_plan, 'over_plan', false);
  end if;

  -- Launch grace: ONLY for shops that existed before 10 Oct 2026 (and only in the first three weeks).
  if p_existing and not v_has and v_shop_created < timestamptz '2026-10-10 00:00:00+03' then
    select coalesce(min(d.first_seen), now()) into v_start from public.shop_devices d;
    if now() < v_start + interval '21 days' then
      insert into public.shop_devices (shop_id, device_id, label, over_plan) values (p_shop_id, v_dev, v_label, true)
      on conflict (shop_id, device_id) do nothing;
      return jsonb_build_object('ok', true, 'count', v_count + 1, 'limit', v_limit, 'plan', v_plan, 'over_plan', true);
    end if;
  end if;

  if v_plan = 'large' then
    if p_accept_upgrade and v_admin is not null then
      update public.shops s set plan = 'xl' where s.id::text = p_shop_id;
      insert into public.shop_devices (shop_id, device_id, label) values (p_shop_id, v_dev, v_label)
      on conflict (shop_id, device_id) do update
        set status = 'active', last_seen = now(), label = coalesce(excluded.label, public.shop_devices.label),
            over_plan = false, removed_by = null, removed_at = null;
      return jsonb_build_object('ok', true, 'upgraded', true, 'count', v_count + 1,
                                'limit', public.plan_device_limit('xl'), 'plan', 'xl', 'price', public.plan_monthly_price('xl'));
    end if;
    return jsonb_build_object('ok', false, 'code', 'needs_upgrade', 'count', v_count, 'limit', v_limit,
                              'plan', v_plan, 'price', public.plan_monthly_price('xl'));
  end if;

  return jsonb_build_object('ok', false, 'code', 'limit', 'count', v_count, 'limit', v_limit, 'plan', v_plan);
end;
$function$;
-- keep it closed to browsers: only the shop-auth function (service role) may call it
revoke execute on function public.register_device(text, text, text, boolean, text, boolean) from anon, authenticated, public;
