-- Run AFTER the app build "2026-10-10-access-rpc-via-function-45" (or newer) is live on every phone.
-- The licence/device functions take an Admin PIN. Called straight from the browser they let anyone with the public key
-- guess Admin PINs with no limit; from now on they are only reachable through the shop-auth function (rate limited).
revoke execute on function public.register_device(text, text, text, boolean, text, boolean) from public, anon, authenticated;
revoke execute on function public.remove_device(text, text, text) from public, anon, authenticated;
revoke execute on function public.shop_devices_list(text, text) from public, anon, authenticated;
revoke execute on function public.submit_license_payment(text, text, text, integer, text) from public, anon, authenticated;
grant  execute on function public.register_device(text, text, text, boolean, text, boolean) to service_role;
grant  execute on function public.remove_device(text, text, text) to service_role;
grant  execute on function public.shop_devices_list(text, text) to service_role;
grant  execute on function public.submit_license_payment(text, text, text, integer, text) to service_role;
-- Trigger function: nobody needs to call it directly.
revoke execute on function public.license_request_decided() from public, anon, authenticated;
-- Fixed search_path on the helper functions flagged by the advisor.
alter function public.next_po_number(uuid) set search_path = public;
alter function public.gen_shop_code() set search_path = public;
alter function public.check_pin_prefix_collision() set search_path = public;
alter function public.plan_monthly_price(text) set search_path = public;
alter function public.plan_yearly_price(text) set search_path = public;
alter function public.plan_device_limit(text) set search_path = public;
