import { Hono } from 'hono';
import { neon } from '@neondatabase/serverless';
import { SignJWT, jwtVerify } from 'jose';

type Bindings = {
  DATABASE_URL: string;
  JWT_SECRET: string;
};
type Variables = {
  username: string;
};

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ============================================================
// CORS Middleware
// ============================================================
app.use('*', async (c, next) => {
  c.header('Access-Control-Allow-Origin', '*');
  c.header('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  c.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  c.header('Access-Control-Max-Age', '86400');

  if (c.req.method === 'OPTIONS') {
    return c.body(null, 204);
  }
  await next();
});

// ============================================================
// Helper: Buat JWT token (berlaku 8 jam)
// ============================================================
async function createToken(username: string, secret: string) {
  const key = new TextEncoder().encode(secret);
  return await new SignJWT({ username })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('8h')
    .sign(key);
}

// ============================================================
// Helper: Verifikasi JWT token
// ============================================================
async function verifyToken(token: string, secret: string) {
  const key = new TextEncoder().encode(secret);
  const { payload } = await jwtVerify(token, key);
  return payload;
}

// ============================================================
// Middleware: Proteksi endpoint yang butuh token
// ============================================================
const protectedPaths = ['/ncr', '/ncr/*', '/auditors'];
protectedPaths.forEach(path => {
  app.use(path, async (c, next) => {
    const authHeader = c.req.header('Authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ status: 'error', message: 'Unauthorized: Missing token' }, 401);
    }

    try {
      const token = authHeader.substring(7);
      await verifyToken(token, c.env.JWT_SECRET);
      // ✅ Token valid — lanjutkan tanpa c.set()
      await next();
    } catch (err: any) {
      return c.json({ 
        status: 'error', 
        message: 'Unauthorized: Invalid or expired token',
        detail: err.message 
      }, 401);
    }
  });
});

// ============================================================
// Endpoint: GET / — health check
// ============================================================
app.get('/', (c) => c.json({
  status: 'ok',
  message: 'NCR API is running',
  endpoints: ['/auth/login', '/ncr', '/ncr/:id', '/auditors', '/debug'],
  auth_required: true
}));

// ============================================================
// Endpoint: POST /auth/login
// ============================================================
app.post('/auth/login', async (c) => {
  try {
    const body = await c.req.json();
    const username = (body.username || '').trim();
    const userid = (body.userid || '').trim();

    if (!username || !userid) {
      return c.json({ status: 'error', message: 'Username dan UserID wajib diisi' }, 400);
    }

    const sql = neon(c.env.DATABASE_URL);
    const rows = await sql`
      SELECT username, userid, layerno, userrule, email
      FROM public.user_profiles
      WHERE LOWER(username) = LOWER(${username})
        AND userid = ${userid}
      LIMIT 1
    `;

    if (rows.length === 0) {
      return c.json({ status: 'error', message: 'Name / ID does not match' }, 401);
    }

    const user = rows[0];
    const token = await createToken(user.username, c.env.JWT_SECRET);

    return c.json({
      status: 'ok',
      message: 'Login berhasil',
      token,
      user: {
        username: user.username,
        userid: user.userid,
        layerno: user.layerno,
        userrule: user.userrule,
        email: user.email
      }
    });

  } catch (err: any) {
    console.error('Login error:', err);
    return c.json({ status: 'error', message: err.message }, 500);
  }
});

// ============================================================
// Endpoint: GET /ncr — daftar semua NCR (PROTECTED)
// ============================================================
app.get('/ncr', async (c) => {
  try {
    const sql = neon(c.env.DATABASE_URL);
    const rows = await sql`
      SELECT 
        id_no, type, category, issued_by, issued_date,
        shift_time, customer_name, part_no, affected_qty,
        sampling_qty, reject_qty_declared, detection_location,
        detail_nc, nc_picture, ok_picture, nc_category, nc_mode,
        how_it_detected, interim_action, sorting_repair_rework_required,
        sorting_rework_pic, interim_remarks, final_reject_qty,
        total_man_hour, total_ok, interim_act_by, interim_action_date,
        root_cause_occ, root_cause_escape, factor_5m1e,
        rc_analysis_by, rc_analysis_date, corrective_act_occur,
        corrective_act_skip, ca_by, ca_date, pa_occ, pa_skip,
        pa_by, pa_date, validate_capa_by, validate_capa_date,
        validation_ca_occ, validation_ca_skip, validation_result,
        status_nc, approved_by, close_date, congratulation_msg, period
      FROM public.ncmr_pdr_master
      ORDER BY issued_date DESC NULLS LAST, id_no DESC
    `;
    return c.json({ status: 'ok', total: rows.length, data: rows });
  } catch (err: any) {
    return c.json({ status: 'error', message: err.message }, 500);
  }
});

// ============================================================
// Endpoint: GET /ncr/:id — detail 1 NCR (PROTECTED)
// ============================================================
app.get('/ncr/:id', async (c) => {
  try {
    const id = c.req.param('id');
    const sql = neon(c.env.DATABASE_URL);
    const rows = await sql`
      SELECT * FROM public.ncmr_pdr_master WHERE id_no = ${id}
    `;
    if (rows.length === 0) {
      return c.json({ status: 'error', message: 'NCR not found: ' + id }, 404);
    }
    return c.json({ status: 'ok', data: rows[0] });
  } catch (err: any) {
    return c.json({ status: 'error', message: err.message }, 500);
  }
});

// ============================================================
// Endpoint: GET /auditors — daftar auditor untuk dropdown PIC
// (PROTECTED)
// ============================================================
app.get('/auditors', async (c) => {
  try {
    const sql = neon(c.env.DATABASE_URL);
    const rows = await sql`
      SELECT 
        username   AS "AuditorName",
        email      AS "Email",
        email2     AS "Email2",
        n1email    AS "N+1Email",
        qms1       AS "qms1",
        qms2       AS "qms2",
        userrule   AS "QAEng"
      FROM public.user_profiles
      WHERE username IS NOT NULL AND username != ''
      ORDER BY username
    `;
    return c.json({ status: 'ok', rows });
  } catch (err: any) {
    return c.json({ status: 'error', message: err.message }, 500);
  }
});

// ============================================================
// Endpoint: GET /debug — cek koneksi database & env
// ============================================================
app.get('/debug', async (c) => {
  const sql = neon(c.env.DATABASE_URL);
  const db = await sql`SELECT current_database() AS db`;
  const cols = await sql`
    SELECT column_name 
    FROM information_schema.columns 
    WHERE table_name = 'user_profiles'
    ORDER BY ordinal_position
  `;
  return c.json({
    database: db[0].db,
    columns: cols.map(r => r.column_name),
    has_jwt_secret: !!c.env.JWT_SECRET
  });
});

export default app;