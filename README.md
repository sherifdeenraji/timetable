# Weekly timetable

A clean weekly timetable for students. Add your classes and tasks, see your whole week at a glance, and export it as a PDF or an image.

![Weekly timetable](public/preview.png)

**Live:** https://timetable-bh6.pages.dev <!-- replace with your real URL -->

## Features

- Sign up with your name, email and a PIN; every person gets their own timetable.
- Week grid on big screens; a day-by-day view on phones (toggle between them any time).
- Tasks can repeat on any set of days, each set with its own time.
- Publish your timetable so friends can use it as a starting point for theirs.
- Export the week as a print-ready A4 PDF or a PNG image.
- Edits save online automatically, with a local copy so a flaky connection loses nothing.

## How it's built

No framework, no build step: one [index.html](index.html) (markup, styles and script), [Cloudflare Pages Functions](functions/api) for the API, and a Cloudflare D1 (SQLite) database for storage. PINs are stored as salted PBKDF2 hashes, never as plain text; five wrong PINs lock an account for 15 minutes.

## Deploy (Cloudflare dashboard)

1. Create a Pages project from this repository (no build command, output directory `/`).
2. Create a D1 database: **Storage & Databases → D1 → Create** (name it `timetable`).
3. Open the database **Console** and paste in the contents of [schema.sql](schema.sql) to create the tables.
4. In the Pages project: **Settings → Bindings → Add → D1 database**, variable name **`DB`**, select the database. Remove any old `TIMETABLE` KV binding.
5. Redeploy. Then:
   - replace `https://timetable-bh6.pages.dev` in `index.html` (the `og:` meta tags and this README) with your real URL, and
   - export your own timetable as an image and save it as `public/preview.png` (about 1200×630) so shared links show a preview.

## Analytics

Signups, sign-ins (with IP), failed PIN attempts, saves, exports and publishes are logged to the `events` table, and every save stores a copy of the timetable in `snapshots`. Query them in the D1 console:

```sql
-- everyone who signed up
SELECT email, first_name, last_name, created_at FROM users ORDER BY created_at;

-- how often each person changes their schedule
SELECT u.email, COUNT(*) AS saves, MAX(s.created_at) AS last_change
FROM snapshots s JOIN users u ON u.id = s.user_id
GROUP BY u.id ORDER BY saves DESC;

-- what people actually do
SELECT type, COUNT(*) AS n FROM events GROUP BY type ORDER BY n DESC;

-- failed sign-ins, with who was targeted and from where
SELECT e.created_at, u.email AS account, e.meta
FROM events e LEFT JOIN users u ON u.id = e.user_id
WHERE e.type = 'failed_signin' ORDER BY e.created_at DESC;
```

Forgot PIN? There is no reset flow yet: delete that person's row in the `users` table (D1 console) and let them sign up again, or update it by hand.
