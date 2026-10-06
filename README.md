# Rebel Ink Tattoos

Custom tattoos · cover-ups · laser removal · paramedical  
Member portal + admin panel with shared storage across devices.

## Render Web Service

- **Build command:** leave empty (or `npm install` — no dependencies required)
- **Start command:** `node server.js`

### Environment variables (optional)

| Variable | Default | Purpose |
|----------|---------|---------|
| `PORT` | `3000` | Server port (Render sets this) |
| `ADMIN_EMAIL` | `admin@rebelink.com` | Admin login email |
| `ADMIN_PASSWORD` | `Admin123!` | Admin password (change in production) |
| `JWT_SECRET` | built-in default | Token signing secret |

## Local run

```bash
node server.js
```

Open http://localhost:3000

## Admin

Log in via **Admin** in the nav using `ADMIN_EMAIL` / `ADMIN_PASSWORD`.

- Approve new members
- Review bookings and set **Approved — client go-ahead**
- Notes appear on the member portal (refreshes every 10s)

## How data is stored

Members and bookings are saved in `data/users.json`.  
All devices share the same file while the server is running.

**Note:** On Render’s free tier the filesystem is ephemeral (data can reset on redeploy). For permanent storage, attach a persistent disk or migrate to a database.

## Member flow

1. Client creates account → status **pending**
2. Admin approves member
3. Client logs in and books
4. Admin approves booking → client sees **Approved — you are good to go**

## Contact

Phone / WhatsApp: **+1 (402) 517-5821**
