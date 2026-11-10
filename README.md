# Glio Clients

Glio's client CRM: one file per client (contacts, services, retainer, renewal, onboarding checklist, ads, access & logins, activity log), shared by the team, with "new client assigned to you" alerts.

- **Frontend:** a single `index.html` (plain HTML + JavaScript, no build step), served by GitHub Pages.
- **Backend:** a Supabase project (logins + Postgres database). All security is enforced in the database by row-level security (RLS) in `supabase-crm.sql`.
- **No AI service and no paid dependency is required.** Everything is standard and portable: the data is ordinary Postgres you can export at any time.

## Roles

| Role | Can do |
|---|---|
| Admin | Everything: manage the team, delete and restore clients, download backups |
| Member | Add and edit clients, tick the checklist, write in the activity log |
| Viewer | Read only |

The **first person to sign up** on a fresh project becomes the admin. Everyone else must be added on the **Team** page first, then creates their account with that same email. Anyone else who signs up sees nothing.

The CRM never stores passwords: the database itself refuses text like `password: …` in notes, access details and the activity log.

## One-time setup

1. **Supabase project.** Create a free project at supabase.com.
2. **Database.** Open *SQL Editor*, paste the whole of `supabase-crm.sql`, run it, then run the diagnostic at the bottom of the file. Expect `tables_ok = 4`, `policy_count = 12`, `password_guard = true`, `realtime_tables = 3`.
3. **Keys.** In *Project Settings → API*, copy the **Project URL** and the **publishable (anon) key** into `SUPABASE_URL` and `SUPABASE_KEY` near the top of the script in `index.html`. Never use the `service_role` / secret key here.
4. **Auth URLs.** In *Authentication → URL Configuration*, set **Site URL** to the CRM's address (e.g. `https://crm.bashari.tech`) and add the same address under **Redirect URLs**.
5. **GitHub Pages.** Repository *Settings → Pages*: deploy from branch `main`, folder `/ (root)`.
6. **Domain.** Put the subdomain in a `CNAME` file in the repo root (one line: `crm.bashari.tech`), and at your DNS provider add a **CNAME** record for that subdomain pointing to `<github-username>.github.io`. Then tick **Enforce HTTPS** in *Settings → Pages* once it's available.
7. **First login.** Open the site, choose **Create account**, and sign up yourself first. You become the admin. Then add your teammates on the **Team** page.

## Making changes

- Edit `index.html`, then check the script still parses:
  `python3 -c "import re;open('/tmp/c.js','w').write(re.findall(r'<script>\n(.*?)</script>',open('index.html').read(),re.S)[0])" && node --check /tmp/c.js`
- Database changes go in a **new numbered block** at the end of `supabase-crm.sql` (never edit earlier blocks; keep everything idempotent), and must be run by hand in the Supabase SQL editor. Pushing to GitHub only ships the page.
