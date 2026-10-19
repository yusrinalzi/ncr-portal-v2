import { Hono } from 'hono';
import { neon } from '@neondatabase/serverless';
import { SignJWT, jwtVerify } from 'jose';

type Bindings = {
  DATABASE_URL: string;
  JWT_SECRET: string;
  AWS_ACCESS_KEY_ID: string;
  AWS_SECRET_ACCESS_KEY: string;
  AWS_ENDPOINT_URL_S3: string;
  AWS_REGION: string;
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
const protectedPaths = ['/ncr', '/ncr/*', '/auditors', '/upload/*'];
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
        id_no, sort_order, type, category, issued_by, issued_date,
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
      ORDER BY sort_order ASC
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
// ============================================================
// Endpoint: POST /ncr — buat NCR baru
// ============================================================
app.post('/ncr', async (c) => {
  try {
    const body = await c.req.json();
    
    // Validasi field wajib
    const type = (body.type || '').trim().toUpperCase();
    if (!type || !['PDR', 'NCMR', '8D'].includes(type)) {
      return c.json({ status: 'error', message: 'Type harus PDR, NCMR, atau 8D' }, 400);
    }
    
    const sql = neon(c.env.DATABASE_URL);
    
    // ============================================================
    // 1. Auto-generate ID No
    // Format: {TYPE}-P{periode}-{nomor}
    // Contoh: NCMR-P7-009
    // ============================================================
    const now = new Date();
    const fiscalPeriod = getFiscalPeriod(now); // P1-P12
    const prefix = type; // PDR, NCMR, 8D
    
    // Cari nomor terakhir untuk periode ini
    const lastRows = await sql`
      SELECT id_no FROM public.ncmr_pdr_master
      WHERE id_no LIKE ${prefix + '-P' + fiscalPeriod + '-%'}
      ORDER BY id_no DESC
      LIMIT 1
    `;
    
    let nextNum = 1;
    if (lastRows.length > 0) {
      const lastId = lastRows[0].id_no;
      const match = lastId.match(/-(\d+)$/);
      if (match) nextNum = parseInt(match[1]) + 1;
    }
    
    const idNo = `${prefix}-P${fiscalPeriod}-${String(nextNum).padStart(3, '0')}`;
    
    // ============================================================
    // 2. Siapkan data
    // ============================================================
    const issuedBy = (body.issuedBy || '').trim();
    const issuedDate = parseDate(body.issuedDate) || now.toISOString().split('T')[0];
    
    const row = {
      id_no: idNo,
      type: type,
      category: body.category || null,
      issued_by: issuedBy || null,
      issued_date: issuedDate,
      shift_time: body.shiftTime || null,
      customer_name: body.customerName || null,
      part_no: body.partNo || null,
      affected_qty: parseIntOrNull(body.affectedQty),
      sampling_qty: parseIntOrNull(body.samplingQty),
      reject_qty_declared: parseIntOrNull(body.rejectQtyDeclared),
      detection_location: body.detectionLocation || null,
      detail_nc: body.detailNC || null,
      nc_picture: body.ncPicture || null,
      ok_picture: body.okPicture || null,
      nc_category: body.ncCategory || null,
      nc_mode: body.ncMode || null,
      how_it_detected: body.howItDetected || null,
      interim_action: body.interimAction || null,
      sorting_repair_rework_required: body.sortingRepairReworkRequired || null,
      sorting_rework_pic: body.sortingReworkPIC || null,
      interim_remarks: body.interimRemarks || null,
      final_reject_qty: parseIntOrNull(body.finalRejectQty),
      total_man_hour: parseNumericOrNull(body.totalManHour),
      total_ok: parseIntOrNull(body.totalOK),
      interim_act_by: body.interimActBy || null,
      interim_action_date: parseDate(body.interimActionDate),
      root_cause_occ: body.rootCauseOcc || null,
      root_cause_escape: body.rootCauseEscape || null,
      factor_5m1e: body.factor5m1e || null,
      rc_analysis_by: body.rcAnalysisBy || null,
      rc_analysis_date: parseDate(body.rcAnalysisDate),
      corrective_act_occur: body.correctiveActOccur || null,
      corrective_act_skip: body.correctiveActSkip || null,
      ca_by: body.caBy || null,
      ca_date: parseDate(body.caDate),
      pa_occ: body.paOcc || null,
      pa_skip: body.paSkip || null,
      pa_by: body.paBy || null,
      pa_date: parseDate(body.paDate),
      validate_capa_by: body.validateCapaBy || null,
      validate_capa_date: parseDate(body.validateCapaDate),
      validation_ca_occ: body.validationCaOcc || null,
      validation_ca_skip: body.validationCaSkip || null,
      validation_result: body.validationResult || null,
      status_nc: body.statusNC || 'Open',
      approved_by: body.approvedBy || null,
      close_date: parseDate(body.closeDate),
      congratulation_msg: body.congratulationMsg || null,
      period: body.period || getPeriodLabel(now)
    };
    
    // ============================================================
    // 3. Insert ke database
    // ============================================================
    const inserted = await sql`
      INSERT INTO public.ncmr_pdr_master (
        sort_order, id_no, type, category, issued_by, issued_date, shift_time,
        customer_name, part_no, affected_qty, sampling_qty, reject_qty_declared,
        detection_location, detail_nc, nc_picture, ok_picture, nc_category,
        nc_mode, how_it_detected, interim_action,
        sorting_repair_rework_required, sorting_rework_pic, interim_remarks,
        final_reject_qty, total_man_hour, total_ok, interim_act_by,
        interim_action_date, root_cause_occ, root_cause_escape, factor_5m1e,
        rc_analysis_by, rc_analysis_date, corrective_act_occur,
        corrective_act_skip, ca_by, ca_date, pa_occ, pa_skip, pa_by, pa_date,
        validate_capa_by, validate_capa_date, validation_ca_occ,
        validation_ca_skip, validation_result, status_nc, approved_by,
        close_date, congratulation_msg, period
      ) VALUES (
        nextval('ncmr_sort_order_seq'), ${row.id_no}, ${row.type}, ${row.category}, ${row.issued_by}, ${row.issued_date},
        ${row.shift_time}, ${row.customer_name}, ${row.part_no}, ${row.affected_qty},
        ${row.sampling_qty}, ${row.reject_qty_declared}, ${row.detection_location},
        ${row.detail_nc}, ${row.nc_picture}, ${row.ok_picture}, ${row.nc_category},
        ${row.nc_mode}, ${row.how_it_detected}, ${row.interim_action},
        ${row.sorting_repair_rework_required}, ${row.sorting_rework_pic},
        ${row.interim_remarks}, ${row.final_reject_qty}, ${row.total_man_hour},
        ${row.total_ok}, ${row.interim_act_by}, ${row.interim_action_date},
        ${row.root_cause_occ}, ${row.root_cause_escape}, ${row.factor_5m1e},
        ${row.rc_analysis_by}, ${row.rc_analysis_date}, ${row.corrective_act_occur},
        ${row.corrective_act_skip}, ${row.ca_by}, ${row.ca_date}, ${row.pa_occ},
        ${row.pa_skip}, ${row.pa_by}, ${row.pa_date}, ${row.validate_capa_by},
        ${row.validate_capa_date}, ${row.validation_ca_occ},
        ${row.validation_ca_skip}, ${row.validation_result}, ${row.status_nc},
        ${row.approved_by}, ${row.close_date}, ${row.congratulation_msg},
        ${row.period}
      )
      RETURNING *
    `;
    
    return c.json({
      status: 'ok',
      message: 'NCR berhasil dibuat',
      idNo: idNo,
      data: inserted[0]
    });
    
  } catch (err: any) {
    console.error('POST /ncr error:', err);
    return c.json({ status: 'error', message: err.message }, 500);
  }
});

// ============================================================
// Helper functions
// ============================================================
function getFiscalPeriod(date: Date): number {
  // Periode fiskal: April = P1, Maret = P12
  const month = date.getMonth(); // 0=Jan
  return ((month - 3 + 12) % 12) + 1;
}

function getPeriodLabel(date: Date): string {
  const months = ['Jan','Feb','Mar','Apr','Mei','Jun','Jul','Agu','Sep','Okt','Nov','Des'];
  const m = months[date.getMonth()];
  const y = String(date.getFullYear()).slice(-2);
  return `${m}-${y}`;
}

function parseIntOrNull(val: any): number | null {
  if (val === null || val === undefined || val === '') return null;
  const n = parseInt(String(val).replace(/[^\d-]/g, ''));
  return isNaN(n) ? null : n;
}

function parseNumericOrNull(val: any): number | null {
  if (val === null || val === undefined || val === '') return null;
  const n = parseFloat(String(val).replace(/[^\d.-]/g, ''));
  return isNaN(n) ? null : n;
}

function parseDate(val: any): string | null {
  if (!val) return null;
  const s = String(val).trim();
  if (!s) return null;
  
  // Format ISO: YYYY-MM-DD
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;
  
  // Format D/M/YYYY atau DD/MM/YYYY
  const match = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
  if (match) {
    const [, d, m, y] = match;
    return `${y}-${m.padStart(2,'0')}-${d.padStart(2,'0')}`;
  }
  
  // Coba parse sebagai Date
  const d = new Date(s);
  if (!isNaN(d.getTime())) return d.toISOString().split('T')[0];
  
  return null;
}

// ============================================================
// Endpoint: PATCH /ncr/:id — update NCR per step (D2-D8)
// ============================================================
app.patch('/ncr/:id', async (c) => {
  try {
    const idNo = c.req.param('id');
    const body = await c.req.json();
    const step = (body.step || '').toUpperCase();
    const data = body.data || {};

    if (!step || !['D2','D3','D4','D5','D6','D7','D8'].includes(step)) {
      return c.json({ status: 'error', message: 'Step harus D2-D8' }, 400);
    }

    const sql = neon(c.env.DATABASE_URL);

    // Cek NCR ada
    const existing = await sql`
      SELECT id_no FROM public.ncmr_pdr_master WHERE id_no = ${idNo} LIMIT 1
    `;
    if (existing.length === 0) {
      return c.json({ status: 'error', message: 'NCR not found: ' + idNo }, 404);
    }

    // ============================================================
    // Build SET clause dinamis berdasarkan step
    // ============================================================
    const setClauses: string[] = [];
    const values: any[] = [];

    function addField(column: string, value: any, transform?: (v: any) => any) {
      if (value === undefined) return; // skip field yang tidak dikirim
      const transformed = transform ? transform(value) : value;
      setClauses.push(`${column} = $${values.length + 1}`);
      values.push(transformed);
    }

    // Helper: konversi ke INTEGER
    const toInt = (v: any) => {
      if (v === null || v === undefined || v === '') return null;
      const n = parseInt(String(v).replace(/[^\d-]/g, ''));
      return isNaN(n) ? null : n;
    };

    // Helper: konversi ke NUMERIC
    const toNum = (v: any) => {
      if (v === null || v === undefined || v === '') return null;
      const n = parseFloat(String(v).replace(/[^\d.-]/g, ''));
      return isNaN(n) ? null : n;
    };

    // Helper: konversi ke DATE
    const toDate = (v: any) => {
      if (!v || v === '') return null;
      const s = String(v).trim();
      if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;
      const m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
      if (m) return `${m[3]}-${m[2].padStart(2,'0')}-${m[1].padStart(2,'0')}`;
      const d = new Date(s);
      return isNaN(d.getTime()) ? null : d.toISOString().split('T')[0];
    };

    // ============================================================
    // Mapping step → field
    // ============================================================
    if (step === 'D2') {
      addField('issued_by', data.issuedBy);
      addField('shift_time', data.shiftTime);
      addField('part_no', data.partNo);
      addField('customer_name', data.customerName);
      addField('detection_location', data.detectionLocation);
      addField('affected_qty', data.affectedQty, toInt);
      addField('sampling_qty', data.samplingQty, toInt);
      addField('reject_qty_declared', data.rejectQtyDeclared, toInt);
      addField('nc_mode', data.ncMode);
      addField('nc_category', data.ncCategory);
      addField('detail_nc', data.detailNC);
      addField('how_it_detected', data.howItDetected);
      addField('interim_action', data.interimAction);
      addField('sorting_repair_rework_required', data.sortingRepairReworkRequired);
      addField('sorting_rework_pic', data.sortingReworkPIC);
      addField('nc_picture', data.ncPicture);
      addField('ok_picture', data.okPicture);
      addField('interim_act_by', data.interimActBy);
      addField('rc_analysis_by', data.rcAnalysisBy);
      addField('ca_by', data.caBy);
      addField('validate_capa_by', data.validateCapaBy);
      addField('pa_by', data.paBy);
      addField('approved_by', data.approvedBy);
    }

    if (step === 'D3') {
      addField('interim_act_by', data.interimActBy);
      addField('interim_action_date', data.interimActionDate, toDate);
      addField('interim_remarks', data.interimRemarks);
      addField('total_ok', data.totalOK, toInt);
      addField('final_reject_qty', data.finalRejectQty, toInt);
      addField('total_man_hour', data.totalManHour, toNum);
    }

    if (step === 'D4') {
      addField('root_cause_occ', data.rootCauseOcc);
      addField('root_cause_escape', data.rootCauseEscape);
      addField('factor_5m1e', data.factor5m1e);
      addField('rc_analysis_by', data.rcAnalysisBy);
      addField('rc_analysis_date', data.rcAnalysisDate, toDate);
    }

    if (step === 'D5') {
      addField('corrective_act_occur', data.correctiveActOccur);
      addField('corrective_act_skip', data.correctiveActSkip);
      addField('ca_by', data.caBy);
      addField('ca_date', data.caDate, toDate);
    }

    if (step === 'D6') {
      addField('validation_ca_occ', data.validationCaOcc);
      addField('validation_ca_skip', data.validationCaSkip);
      addField('validate_capa_by', data.validateCapaBy);
      addField('validate_capa_date', data.validateCapaDate, toDate);
      addField('validation_result', data.validationResult);
    }

    if (step === 'D7') {
      addField('pa_occ', data.paOcc);
      addField('pa_skip', data.paSkip);
      addField('pa_by', data.paBy);
      addField('pa_date', data.paDate, toDate);
    }

    if (step === 'D8') {
      addField('approved_by', data.approvedBy);
      addField('close_date', data.closeDate, toDate);
      addField('congratulation_msg', data.congratulationMsg);
      addField('status_nc', data.statusNC);
    }

    // Update status ke In Progress (kecuali D8)
    if (step !== 'D8') {
      setClauses.push(`status_nc = CASE WHEN status_nc = 'Closed' THEN 'Closed' ELSE 'In Progress' END`);
    }

    // Selalu update updated_at
    setClauses.push(`updated_at = NOW()`);

    if (setClauses.length === 0) {
      return c.json({ status: 'error', message: 'Tidak ada field yang diupdate' }, 400);
    }

    // ============================================================
    // Jalankan UPDATE
    // ============================================================
    values.push(idNo); // parameter terakhir untuk WHERE
    const query = `
      UPDATE public.ncmr_pdr_master 
      SET ${setClauses.join(', ')}
      WHERE id_no = $${values.length}
      RETURNING *
    `;

    const result = await sql.query(query, values);

    return c.json({
      status: 'ok',
      message: `Step ${step} berhasil diupdate`,
      data: result[0]
    });

  } catch (err: any) {
    console.error(`PATCH /ncr/${c.req.param('id')} error:`, err);
    return c.json({ status: 'error', message: err.message }, 500);
  }
});

// ============================================================
// Endpoint: POST /upload/presign — generate presigned URL
// ============================================================
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

app.post('/upload/presign', async (c) => {
  try {
    const body = await c.req.json();
    const filename = (body.filename || '').trim();
    const contentType = (body.contentType || 'image/jpeg').trim();
    const idNo = (body.idNo || '').trim();
    const kind = (body.kind || 'nc').trim(); // 'nc' atau 'ok'
    
    if (!filename) {
      return c.json({ status: 'error', message: 'filename wajib diisi' }, 400);
    }

    // Setup S3 client
    const s3 = new S3Client({
      region: c.env.AWS_REGION,
      endpoint: c.env.AWS_ENDPOINT_URL_S3,
      credentials: {
        accessKeyId: c.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: c.env.AWS_SECRET_ACCESS_KEY,
      },
      forcePathStyle: true,
    });

    // Generate key (path) di bucket
    const timestamp = Date.now();
    const cleanName = filename.replace(/[^a-zA-Z0-9._-]/g, '_');
    const prefix = idNo ? `${idNo}/` : 'misc/';
    const key = `${prefix}${kind}_${timestamp}_${cleanName}`;

    // Buat presigned URL untuk PUT (berlaku 5 menit)
    const command = new PutObjectCommand({
      Bucket: 'ncr-images',
      Key: key,
      ContentType: contentType,
    });

    const uploadUrl = await getSignedUrl(s3, command, { expiresIn: 300 });

    // URL publik untuk baca
    const endpoint = c.env.AWS_ENDPOINT_URL_S3.replace(/\/$/, '');
    const publicUrl = `${endpoint}/ncr-images/${key}`;

    return c.json({
      status: 'ok',
      uploadUrl,
      publicUrl,
      key,
      expiresIn: 300,
    });

  } catch (err: any) {
    console.error('POST /upload/presign error:', err);
    return c.json({ status: 'error', message: err.message }, 500);
  }
});

export default app;