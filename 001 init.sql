-- المستودع الرقمي التعليمي – المدرسة الثانوية السابعة بالدوادمي
-- 001_init.sql : شغّله في Supabase > SQL Editor (مرة واحدة)

create extension if not exists pgcrypto;

-- ========== Types ==========
create type user_role      as enum ('super_admin','content_manager','teacher','viewer');
create type account_status as enum ('pending','active','disabled');
create type content_status as enum ('draft','pending_review','approved','rejected','needs_revision');

-- ========== Helpers ==========
create or replace function set_updated_at() returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end $$;

-- ========== profiles ==========
create table profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default '',
  email text not null,
  subject text,
  role user_role not null default 'viewer',
  status account_status not null default 'pending',
  auth_provider text default 'email',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  last_sign_in_at timestamptz
);
create unique index profiles_email_uq on profiles (lower(email));

-- دوال الصلاحيات (security definer لتجنب التكرار الذاتي في RLS)
create or replace function auth_role() returns user_role
language sql stable security definer set search_path = public as $$
  select role from profiles where id = auth.uid() and status = 'active' $$;

create or replace function is_active() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from profiles where id = auth.uid() and status = 'active') $$;

create or replace function is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(auth_role() = 'super_admin', false) $$;

create or replace function is_staff() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(auth_role() in ('super_admin','content_manager'), false) $$;

create or replace function can_contribute() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(auth_role() in ('super_admin','content_manager','teacher'), false) $$;

-- ========== content_categories ==========
create table content_categories (
  id uuid primary key default gen_random_uuid(),
  parent_id uuid references content_categories(id) on delete cascade,
  name text not null,
  slug text not null unique,
  icon text,
  sort_order int not null default 0,
  is_active boolean not null default true,
  created_at timestamptz not null default now()
);
create index on content_categories (parent_id);

-- ========== educational_content ==========
create table educational_content (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references profiles(id) on delete restrict default auth.uid(),
  category_id uuid not null references content_categories(id),
  title text not null check (char_length(title) between 3 and 200),
  description text check (char_length(description) <= 2000),
  subject text,
  grade text not null default 'all' check (grade in ('first','second','third','all')),
  unit text,
  lesson_title text,
  learning_outcome text,
  target_skill text,
  content_type text not null check (content_type in
    ('pdf','pptx','docx','video','image','link','quiz','interactive')),
  digital_tool text,
  external_url text check (external_url is null or external_url ~* '^https?://'),
  keywords text[] not null default '{}',
  thumbnail_path text,
  allow_download boolean not null default false,
  status content_status not null default 'draft',
  review_notes text,
  reviewed_by uuid references profiles(id),
  reviewed_at timestamptz,
  published_at timestamptz,
  view_count int not null default 0,
  download_count int not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  search_tsv tsvector generated always as (
    to_tsvector('simple', coalesce(title,'')||' '||coalesce(description,'')||' '||
      coalesce(subject,'')||' '||coalesce(lesson_title,''))) stored
);
create index on educational_content (owner_id);
create index on educational_content (status, published_at desc);
create index on educational_content (category_id);
create index on educational_content (subject);
create index on educational_content using gin (search_tsv);
create index on educational_content using gin (keywords);
create trigger trg_content_updated before update on educational_content
  for each row execute function set_updated_at();

-- ========== content_files ==========
create table content_files (
  id uuid primary key default gen_random_uuid(),
  content_id uuid not null references educational_content(id) on delete cascade,
  owner_id uuid not null references profiles(id) default auth.uid(),
  storage_path text not null unique,       -- {owner_id}/{content_id}/{filename}
  file_name text not null,
  mime_type text not null,
  size_bytes bigint not null check (size_bytes > 0 and size_bytes <= 52428800),
  created_at timestamptz not null default now(),
  check (lower(file_name) !~ '\.(exe|bat|cmd|com|msi|sh|js|jar|vbs|ps1|scr|dll|apk|php|html?)$')
);
create index on content_files (content_id);

-- ========== content_tags ==========
create table content_tags (
  id uuid primary key default gen_random_uuid(),
  content_id uuid not null references educational_content(id) on delete cascade,
  tag text not null check (char_length(tag) between 1 and 60),
  unique (content_id, tag)
);
create index on content_tags (tag);

-- ========== content_activity ==========
create table content_activity (
  id uuid primary key default gen_random_uuid(),
  content_id uuid not null references educational_content(id) on delete cascade,
  user_id uuid references profiles(id) on delete set null default auth.uid(),
  action text not null check (action in ('view','download')),
  created_at timestamptz not null default now()
);
create index on content_activity (content_id, action);

-- ========== invitations ==========
create table invitations (
  id uuid primary key default gen_random_uuid(),
  email text not null,
  role user_role not null default 'teacher',
  token_hash text not null unique default encode(gen_random_bytes(32),'hex'),
  invited_by uuid not null references profiles(id) default auth.uid(),
  expires_at timestamptz not null default now() + interval '7 days',
  accepted_at timestamptz,
  accepted_by uuid references profiles(id),
  revoked_at timestamptz,
  created_at timestamptz not null default now()
);
create index on invitations (lower(email));
-- دعوة واحدة فعّالة لكل بريد
create unique index invitations_open_uq on invitations (lower(email))
  where accepted_at is null and revoked_at is null;

-- ========== notifications ==========
create table notifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references profiles(id) on delete cascade,
  type text not null,
  title text not null,
  body text,
  content_id uuid references educational_content(id) on delete set null,
  is_read boolean not null default false,
  created_at timestamptz not null default now()
);
create index on notifications (user_id, is_read, created_at desc);

-- ========== audit_logs ==========
create table audit_logs (
  id uuid primary key default gen_random_uuid(),
  actor_id uuid references profiles(id) on delete set null,
  action text not null,
  entity text,
  entity_id uuid,
  details jsonb not null default '{}',
  created_at timestamptz not null default now()
);
create index on audit_logs (created_at desc);

-- ========== platform_settings ==========
create table platform_settings (
  key text primary key,
  value text not null,
  updated_by uuid references profiles(id),
  updated_at timestamptz not null default now()
);

-- ========== Triggers ==========

-- إنشاء الملف الشخصي (الحالة: pending دائمًا، دون أي صلاحية)
create or replace function handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into profiles (id, email, full_name, auth_provider)
  values (new.id, new.email,
    coalesce(new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'name', ''),
    coalesce(new.raw_app_meta_data->>'provider','email'))
  on conflict (id) do nothing;
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function handle_new_user();

-- عند توثيق البريد: تُفعَّل الدعوة المطابقة (إن وُجدت) لمرة واحدة فقط
create or replace function handle_email_verified() returns trigger
language plpgsql security definer set search_path = public as $$
declare inv invitations;
begin
  if new.email_confirmed_at is not null and old.email_confirmed_at is null then
    select * into inv from invitations
     where lower(email) = lower(new.email) and accepted_at is null
       and revoked_at is null and expires_at > now()
     order by created_at desc limit 1 for update;
    if found then
      update profiles set role = inv.role, status = 'active' where id = new.id;
      update invitations set accepted_at = now(), accepted_by = new.id where id = inv.id;
      insert into notifications (user_id,type,title,body)
      values (new.id,'account_approved','تم تفعيل حسابك','يمكنك الآن استخدام المستودع الرقمي.');
    end if;
  end if;
  return new;
end $$;
create trigger on_auth_user_verified after update of email_confirmed_at on auth.users
  for each row execute function handle_email_verified();

-- تحديث آخر دخول
create or replace function handle_last_sign_in() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  update profiles set last_sign_in_at = new.last_sign_in_at where id = new.id;
  return new;
end $$;
create trigger on_auth_user_signin after update of last_sign_in_at on auth.users
  for each row execute function handle_last_sign_in();

-- منع رفع الصلاحيات ذاتيًا: غير المديرة لا تغيّر role/status/email
create or replace function guard_profile_update() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is not null and not is_admin() then
    if new.role <> old.role or new.status <> old.status
       or new.email <> old.email or new.id <> old.id then
      raise exception 'غير مصرح بتعديل الدور أو الحالة أو البريد';
    end if;
  end if;
  new.updated_at = now();
  return new;
end $$;
create trigger trg_guard_profile before update on profiles
  for each row execute function guard_profile_update();

-- حماية حقول المحتوى وحالات الانتقال
create or replace function guard_content_update() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return new; end if;
  if new.owner_id <> old.owner_id then
    raise exception 'لا يمكن تغيير صاحبة العمل';
  end if;
  if not is_staff() then
    if old.status in ('approved') then
      raise exception 'لا يمكن تعديل عمل معتمد، تواصلي مع الإدارة';
    end if;
    if new.status not in ('draft','pending_review') then
      raise exception 'غير مصرح بتغيير الحالة';
    end if;
    new.review_notes = old.review_notes;
    new.reviewed_by  = old.reviewed_by;
    new.reviewed_at  = old.reviewed_at;
    new.published_at = old.published_at;
    new.view_count = old.view_count;
    new.download_count = old.download_count;
  end if;
  if new.status is distinct from old.status then
    if new.status = 'approved' then new.published_at = now(); end if;
    if new.status in ('approved','rejected','needs_revision') then
      new.reviewed_by = auth.uid(); new.reviewed_at = now();
    end if;
  end if;
  return new;
end $$;
create trigger trg_guard_content before update on educational_content
  for each row execute function guard_content_update();

create or replace function guard_content_insert() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is not null and not is_staff() and new.status not in ('draft','pending_review') then
    raise exception 'غير مصرح بإنشاء عمل بهذه الحالة';
  end if;
  new.owner_id = coalesce(new.owner_id, auth.uid());
  return new;
end $$;
create trigger trg_guard_content_ins before insert on educational_content
  for each row execute function guard_content_insert();

-- إشعار المعلمة عند تغيّر حالة عملها
create or replace function notify_status_change() returns trigger
language plpgsql security definer set search_path = public as $$
declare t text; b text;
begin
  if new.status is distinct from old.status and new.status in ('approved','rejected','needs_revision') then
    t := case new.status when 'approved' then 'تم اعتماد عملك'
                         when 'rejected' then 'تم رفض عملك'
                         else 'عملك يحتاج إلى تعديل' end;
    b := coalesce(new.review_notes, new.title);
    insert into notifications (user_id,type,title,body,content_id)
    values (new.owner_id,'content_'||new.status,t,b,new.id);
  end if;
  if new.status = 'pending_review' and old.status is distinct from 'pending_review' then
    insert into notifications (user_id,type,title,body,content_id)
    select id,'review_requested','عمل جديد بانتظار المراجعة',new.title,new.id
      from profiles where role in ('super_admin','content_manager') and status='active';
  end if;
  return new;
end $$;
create trigger trg_notify_status after update on educational_content
  for each row execute function notify_status_change();

-- تسجيل المشاهدة/التحميل (للأعمال المعتمدة فقط)
create or replace function record_activity(p_content uuid, p_action text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not is_active() or p_action not in ('view','download') then return; end if;
  if not exists (select 1 from educational_content where id = p_content and status='approved') then return; end if;
  insert into content_activity (content_id,user_id,action) values (p_content,auth.uid(),p_action);
  if p_action = 'view' then
    update educational_content set view_count = view_count + 1 where id = p_content;
  else
    update educational_content set download_count = download_count + 1 where id = p_content;
  end if;
end $$;

-- تسجيل العمليات الإدارية
create or replace function log_action(p_action text, p_entity text, p_entity_id uuid, p_details jsonb default '{}')
returns void language plpgsql security definer set search_path = public as $$
begin
  if is_staff() then
    insert into audit_logs (actor_id,action,entity,entity_id,details)
    values (auth.uid(),p_action,p_entity,p_entity_id,p_details);
  end if;
end $$;

-- ========== RLS ==========
alter table profiles            enable row level security;
alter table content_categories  enable row level security;
alter table educational_content enable row level security;
alter table content_files       enable row level security;
alter table content_tags        enable row level security;
alter table content_activity    enable row level security;
alter table invitations         enable row level security;
alter table notifications       enable row level security;
alter table audit_logs          enable row level security;
alter table platform_settings   enable row level security;

-- profiles: كل مستخدمة ترى ملفها فقط (الإدارة ترى الجميع). الأسماء العامة عبر view أدناه.
create policy profiles_select on profiles for select to authenticated
  using (id = auth.uid() or is_staff());
create policy profiles_update_self on profiles for update to authenticated
  using (id = auth.uid()) with check (id = auth.uid());
create policy profiles_update_admin on profiles for update to authenticated
  using (is_admin()) with check (is_admin());

-- عرض آمن لأسماء الناشرات فقط (بدون بريد أو بيانات حساسة)
create view public_profiles with (security_invoker = false) as
  select id, full_name, subject from profiles where status = 'active';
revoke all on public_profiles from anon;
grant select on public_profiles to authenticated;

-- categories
create policy cat_select on content_categories for select to authenticated using (is_active() );
create policy cat_admin  on content_categories for all to authenticated
  using (is_admin()) with check (is_admin());

-- educational_content
create policy content_select on educational_content for select to authenticated using (
  is_active() and (status = 'approved' or owner_id = auth.uid() or is_staff()));
create policy content_insert on educational_content for insert to authenticated
  with check (can_contribute() and owner_id = auth.uid());
create policy content_update_own on educational_content for update to authenticated
  using (owner_id = auth.uid() and can_contribute() and status <> 'approved')
  with check (owner_id = auth.uid());
create policy content_update_staff on educational_content for update to authenticated
  using (is_staff()) with check (is_staff());
create policy content_delete_own on educational_content for delete to authenticated
  using (owner_id = auth.uid() and can_contribute() and status in ('draft','rejected','needs_revision'));
create policy content_delete_admin on educational_content for delete to authenticated
  using (is_admin());

-- content_files / tags تتبع ظهور المحتوى الأب
create policy files_select on content_files for select to authenticated using (
  exists (select 1 from educational_content c where c.id = content_id and is_active()
          and (c.status='approved' or c.owner_id=auth.uid() or is_staff())));
create policy files_insert on content_files for insert to authenticated with check (
  owner_id = auth.uid() and exists (select 1 from educational_content c
    where c.id = content_id and c.owner_id = auth.uid() and c.status <> 'approved'));
create policy files_delete on content_files for delete to authenticated using (
  is_staff() or (owner_id = auth.uid() and exists (select 1 from educational_content c
    where c.id = content_id and c.status <> 'approved')));

create policy tags_select on content_tags for select to authenticated using (
  exists (select 1 from educational_content c where c.id = content_id and is_active()
          and (c.status='approved' or c.owner_id=auth.uid() or is_staff())));
create policy tags_write on content_tags for all to authenticated
  using (exists (select 1 from educational_content c where c.id = content_id
         and (is_staff() or (c.owner_id=auth.uid() and c.status <> 'approved'))))
  with check (exists (select 1 from educational_content c where c.id = content_id
         and (is_staff() or (c.owner_id=auth.uid() and c.status <> 'approved'))));

-- activity: القراءة للإدارة فقط؛ الكتابة عبر record_activity()
create policy activity_select on content_activity for select to authenticated using (is_staff());

-- invitations: المديرة فقط
create policy inv_admin on invitations for all to authenticated
  using (is_admin()) with check (is_admin());

-- notifications: صاحبة الإشعار فقط
create policy notif_select on notifications for select to authenticated using (user_id = auth.uid());
create policy notif_update on notifications for update to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy notif_delete on notifications for delete to authenticated using (user_id = auth.uid());

-- audit_logs: قراءة المديرة فقط (لا كتابة مباشرة)
create policy audit_select on audit_logs for select to authenticated using (is_admin());

-- platform_settings: قراءة للجميع (اسم المنصة والشعار)، تعديل للمديرة
create policy settings_select on platform_settings for select to anon, authenticated using (true);
create policy settings_admin on platform_settings for all to authenticated
  using (is_admin()) with check (is_admin());

-- ========== Storage ==========
-- المسار: {owner_uid}/{content_id}/{file}
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types) values
 ('content-files','content-files',false,52428800, array[
   'application/pdf','application/vnd.ms-powerpoint',
   'application/vnd.openxmlformats-officedocument.presentationml.presentation',
   'application/msword',
   'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
   'video/mp4','video/webm','image/png','image/jpeg','image/webp']),
 ('thumbnails','thumbnails',false,5242880, array['image/png','image/jpeg','image/webp'])
on conflict (id) do nothing;

create policy st_insert on storage.objects for insert to authenticated with check (
  bucket_id in ('content-files','thumbnails') and can_contribute()
  and (storage.foldername(name))[1] = auth.uid()::text);

create policy st_select on storage.objects for select to authenticated using (
  bucket_id in ('content-files','thumbnails') and is_active() and (
    (storage.foldername(name))[1] = auth.uid()::text or is_staff()
    or exists (select 1 from educational_content c
        where c.status = 'approved'
          and c.id::text = (storage.foldername(name))[2])));

create policy st_update on storage.objects for update to authenticated using (
  bucket_id in ('content-files','thumbnails') and (storage.foldername(name))[1] = auth.uid()::text);

create policy st_delete on storage.objects for delete to authenticated using (
  bucket_id in ('content-files','thumbnails')
  and ((storage.foldername(name))[1] = auth.uid()::text or is_admin()));

-- ========== Seed: الأقسام السبعة والتصنيفات الفرعية ==========
insert into content_categories (name, slug, icon, sort_order) values
 ('الدروس الرقمية التفاعلية','interactive-lessons','MonitorPlay',1),
 ('الإنفوجرافيك والملخصات','infographics-summaries','ChartPie',2),
 ('التقويم الإلكتروني','e-assessment','ClipboardCheck',3),
 ('المحاكاة والتعلم الافتراضي','simulation-virtual','FlaskConical',4),
 ('إنتاج الطالبات للمحتوى الرقمي','student-production','Clapperboard',5),
 ('الذكاء الاصطناعي والمواطنة الرقمية','ai-digital-citizenship','BrainCircuit',6),
 ('المكتبة والمصادر الرقمية','digital-library','Library',7);

insert into content_categories (parent_id, name, slug, sort_order)
select p.id, s.name, p.slug||'-'||s.n, s.n from content_categories p
join (values
 ('interactive-lessons',1,'دروس تفاعلية'),('interactive-lessons',2,'عروض تعليمية'),
 ('interactive-lessons',3,'أنشطة تعلم ذاتي'),('interactive-lessons',4,'مصادر إثرائية'),
 ('interactive-lessons',5,'روابط الدروس الرقمية'),
 ('infographics-summaries',1,'خرائط مفاهيم'),('infographics-summaries',2,'ملخصات الوحدات'),
 ('infographics-summaries',3,'بطاقات تعليمية'),('infographics-summaries',4,'رسوم توضيحية'),
 ('infographics-summaries',5,'مطويات رقمية'),
 ('e-assessment',1,'اختبارات قصيرة'),('e-assessment',2,'بنوك أسئلة'),
 ('e-assessment',3,'اختبارات قبلية وبعدية'),('e-assessment',4,'نماذج تقييم إلكترونية'),
 ('e-assessment',5,'أنشطة تغذية راجعة'),
 ('simulation-virtual',1,'تجارب افتراضية'),('simulation-virtual',2,'محاكاة علمية'),
 ('simulation-virtual',3,'جولات افتراضية'),('simulation-virtual',4,'تطبيقات استكشافية'),
 ('simulation-virtual',5,'بيئات تعلم تفاعلية'),
 ('student-production',1,'فيديوهات تعليمية'),('student-production',2,'مشروعات رقمية'),
 ('student-production',3,'بودكاست'),('student-production',4,'عروض تقديمية'),
 ('student-production',5,'إنفوجرافيك من إنتاج الطالبات'),
 ('ai-digital-citizenship',1,'أنشطة الذكاء الاصطناعي'),('ai-digital-citizenship',2,'تطبيقات تعليمية ذكية'),
 ('ai-digital-citizenship',3,'التحقق من صحة المعلومات'),('ai-digital-citizenship',4,'الأمن السيبراني'),
 ('ai-digital-citizenship',5,'الخصوصية والأمان الرقمي'),('ai-digital-citizenship',6,'أخلاقيات استخدام الذكاء الاصطناعي'),
 ('digital-library',1,'كتب إلكترونية'),('digital-library',2,'مراجع تعليمية'),
 ('digital-library',3,'روابط مصادر موثوقة'),('digital-library',4,'فيديوهات تعليمية'),
 ('digital-library',5,'منصات تعليمية')
) as s(parent_slug,n,name) on s.parent_slug = p.slug and p.parent_id is null;

insert into platform_settings (key, value) values
 ('school_name','المدرسة الثانوية السابعة بالدوادمي'),
 ('platform_name','المستودع الرقمي التعليمي'),
 ('tagline','محتوانا الرقمي.. تعلم يتجاوز الحدود'),
 ('allowed_email_domains','');

-- ========== أول مديرة (نفّذيه يدويًا مرة واحدة بعد إنشاء حسابك وتوثيق بريدك) ==========
-- update profiles set role='super_admin', status='active' where lower(email)=lower('PUT_ADMIN_EMAIL_HERE');
