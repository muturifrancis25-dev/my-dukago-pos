-- Build 99 (security advisor follow-up). Applied to the live project 2026-10-19.
--
-- 1. license_status: anyone holding a shop id could read that shop's name, Shop Code and latest licence payment
--    (M-Pesa code, amount) without signing in. Now the full answer is given only to a session of that same shop;
--    anyone else gets just what a phone needs to lock or unlock the till (active, status, expiry, plan, prices).
--    Phones normally have a signed-in session (it renews itself), so the licence screen keeps showing everything.
create or replace function public.license_status(p_shop_id text)
returns jsonb language sql stable security definer set search_path to 'public' as $function$
  select case when public.jwt_shop_id()::text = p_shop_id then
    jsonb_build_object(
      'ok', true,
      'active', s.active is not false,
      'license_status', s.license_status,
      'note', s.license_note,
      'expires_at', s.license_expires_at,
      'plan', coalesce(s.plan, 'small'),
      'cycle', coalesce(s.license_cycle, 'monthly'),
      'monthly_price', public.plan_monthly_price(coalesce(s.plan, 'small')),
      'yearly_price', public.plan_yearly_price(coalesce(s.plan, 'small')),
      'shop_code', s.shop_code,
      'name', s.name,
      'request', (
        select jsonb_build_object(
                 'status', r.status, 'mpesa_code', r.mpesa_code, 'amount', r.amount, 'months', r.months, 'cycle', r.cycle,
                 'requested_at', r.requested_at, 'decided_at', r.decided_at, 'note', r.decision_note)
          from public.license_payment_requests r
         where r.shop_id = p_shop_id
         order by r.requested_at desc
         limit 1))
  else
    jsonb_build_object(
      'ok', true,
      'active', s.active is not false,
      'license_status', s.license_status,
      'note', s.license_note,
      'expires_at', s.license_expires_at,
      'plan', coalesce(s.plan, 'small'),
      'cycle', coalesce(s.license_cycle, 'monthly'),
      'monthly_price', public.plan_monthly_price(coalesce(s.plan, 'small')),
      'yearly_price', public.plan_yearly_price(coalesce(s.plan, 'small')),
      'request', null)
  end
  from public.shops s
  where s.id::text = p_shop_id;
$function$;

-- 2. pin_clash: fixed search_path (advisor: function_search_path_mutable). It only compares two strings.
alter function public.pin_clash(text, text) set search_path = public;
