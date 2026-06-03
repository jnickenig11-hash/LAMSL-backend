LAMSL Backend API

This small backend provides endpoints used by the LAMSL frontend during local development.

Base URL: http://localhost:3000

Endpoints:

- GET /api/content
  - Returns site editable content JSON (from `data/content.json`).

- POST /api/update
  - Saves content JSON. Body: full content object.

- POST /api/subscribe
  - Body: { email }

- POST /api/upload-image
  - Form field `photo` (multipart/form-data). Saves to `uploads/` and returns path.

- POST /api/log-admin-action
  - Body: { action, user, details }

- GET /ef-images
  - Returns EF (event) image metadata from `ef_images_metadata.json`.

- POST /upload-ef
  - Form field `photo` (multipart/form-data), optional `caption`. Saves to `EF_Images/` and updates metadata.

- POST /remove-ef-photo
  - Body: { filename }

- POST /notify-schedule-update
  - Body: { ... } — logs schedule notifications to `logs/notifications.log`.

- POST /notify-announcement
  - Body: { title, body } — logs announcement notifications.

- POST /upload-team-photo
  - Form fields `photo`, `team`, `division`. Saves under `teamProfile images/<division>/<team>/` and updates `team_profile_metadata.json`.

Notes:
- All logged items are appended to files in `logs/` for local inspection.
- For Windows PowerShell, use `curl.exe` or `Invoke-RestMethod` to POST JSON.

Admin API key
-------------
Set the `ADMIN_API_KEY` environment variable on Render to the same secret value used by your admin client.

Example header when calling the backend:

- `x-admin-key: <secret>`
- or `Authorization: Bearer <secret>`

For browser-based admin access, set the secret locally in the browser before saving content:

```js
localStorage.setItem('LAMSL_ADMIN_KEY', '<secret>');
```

Health check
-----------

A simple automated healthcheck script is provided to verify the backend is responsive.

Usage:

PowerShell:

```powershell
.\healthcheck.ps1
```

Bash:

```bash
./healthcheck.sh
```

Or run directly with Node:

```bash
BASE_URL=http://localhost:3000 node healthcheck.js
```

The script checks `/health`, `/api/content`, and `/ef-images` and exits with code `0` on success.
