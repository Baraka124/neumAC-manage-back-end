// ============ NEUMOCARE HOSPITAL MANAGEMENT SYSTEM API ============
// VERSION 5.4 - ALL BUGS FIXED
// --- ORIGINAL FIXES --- 
// FIX 1: Rotation dates - formatDate() used instead of .split() on Joi Date objects
// FIX 2: Absence creation - total_days + current_status NOT NULL columns populated
// FIX 3: Absence FK - recorded_by nullable-safe + full_name in JWT
// FIX 4: rotation_category Joi/DB enum mismatch corrected
// FIX 5: research_lines added to rolePermissions
// FIX 6: Duplicate on-call routes removed
// FIX 8: full_name added to JWT payload  
// FIX 9: Absence PUT recalculates total_days + current_status
// --- NEW FIXES ---
// FIX 10: /api/auth/me — req.user.userId → req.user.id (JWT field mismatch causing 401)
// FIX 11: POST + PUT /api/medical-staff — can_be_pi, can_be_coi, has_phd, phd_field now persisted
// FIX 12: Joi schema for medicalStaff — can_be_pi/coi/phd added (were stripped by stripUnknown)
// FIX 13: PUT /api/training-units — unit_type + unit_description now updated (were silently lost)
// FIX 14: PUT /api/training-units — department_name refreshed when department_id changes
// FIX 15: DELETE /api/rotations — soft delete (terminated_early) instead of hard delete
// FIX 16: Analytics active project stages aligned to current_stage field values
// FIX 17: POST /api/research-lines — accepts research_line_name alias + keywords field
// FIX 18: POST /api/clinical-trials — phase defaults to Phase I for non-interventional studies
// =================================================================

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const Joi = require('joi');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
require('dotenv').config();

// ── Notification system (Resend API — free, no extra npm install) ────────
// Set RESEND_API_KEY and NOTIFY_EMAIL in Railway environment variables
const NOTIFY_EMAIL  = process.env.NOTIFY_EMAIL  || '';
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const FROM_EMAIL    = 'neumDesk <notifications@neumac.health>';
const APP_URL       = process.env.APP_URL || process.env.FRONTEND_URL || 'https://baraka124.github.io/neumAC-manage-Frontend-end';

async function sendNotification(subject, html, urgent = false) {
  if (!NOTIFY_EMAIL) return;  // silently skip if not configured
  if (!RESEND_API_KEY) {
    // Dev mode: log to console
    console.log(`[NOTIFY] ${subject}\n${html.replace(/<[^>]+>/g, ' ')}`);
    return;
  }
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: FROM_EMAIL,
        to: [NOTIFY_EMAIL],
        subject: urgent ? `🔴 ${subject}` : `📋 ${subject}`,
        html: `<div style="font-family:sans-serif;max-width:600px;margin:0 auto">
          <div style="background:#0a1628;padding:16px 20px;border-radius:8px 8px 0 0">
            <span style="color:#48cae4;font-weight:700;font-size:16px">neumDesk</span>
            <span style="color:rgba(255,255,255,.4);font-size:12px;margin-left:8px">Clinical Operations</span>
          </div>
          <div style="background:#fff;padding:20px 24px;border:1px solid #e5e7eb;border-top:none;border-radius:0 0 8px 8px">
            ${html}
          </div>
          <p style="color:#9ca3af;font-size:11px;margin-top:8px;text-align:center">
            neumDesk · ${new Date().toLocaleDateString('en-GB', { weekday:'long', day:'numeric', month:'long', year:'numeric' })}
          </p>
        </div>`
      })
    });
    if (!res.ok) console.error('[NOTIFY] Failed:', res.status, await res.text());
  } catch (e) {
    console.error('[NOTIFY] Error:', e.message);
  }
}

// Helper: get physician name from DB
async function getPhysicianName(id) {
  if (!id) return 'Unknown';
  try {
    const { data } = await supabase.from('medical_staff').select('full_name').eq('id', id).single();
    return data?.full_name || 'Unknown';
  } catch { return 'Unknown'; }
}

// ============ INITIALIZATION ============
const app = express();
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;

// ============ CONFIGURATION ============
const {
  SUPABASE_URL,
  SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY,
  JWT_SECRET = process.env.JWT_SECRET,
  NODE_ENV = 'production',
  ALLOWED_ORIGINS: ENV_ALLOWED_ORIGINS
} = process.env;

// Safe default origins. The production site is neumact.org; the legacy
// GitHub Pages host and localhost are kept for migration/dev. If the
// ALLOWED_ORIGINS env var is set on the host it overrides this entirely.
const ALLOWED_ORIGINS_STRING = ENV_ALLOWED_ORIGINS ||
  'https://neumact.org,https://www.neumact.org,https://baraka124.github.io,http://localhost:3000,http://localhost:8080';
const allowedOrigins = ALLOWED_ORIGINS_STRING.split(',').map(origin => origin.trim());

console.log('🌐 CORS Configuration:', { allowedOrigins, nodeEnv: NODE_ENV });

// B11 FIX: Never fall back to a hardcoded JWT secret — fail fast at startup
if (!JWT_SECRET) {
  console.error('❌ JWT_SECRET environment variable is required and must not be empty');
  process.exit(1);
}
if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('❌ Missing required environment variables');
  process.exit(1);
}

// ============ SUPABASE CLIENT ============
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
  db: { schema: 'public' }
});

// ============ FILE UPLOAD CONFIGURATION ============
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|pdf|doc|docx|xls|xlsx|txt/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    if (extname && mimetype) return cb(null, true);
    cb(new Error('Only document and image files are allowed'));
  }
});


const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    const isAllowed = allowedOrigins.some(allowedOrigin => {
      if (allowedOrigin === '*') return true;
      if (allowedOrigin === origin) return true;
      if (allowedOrigin.includes('*')) {
        const regex = new RegExp(allowedOrigin.replace(/\*/g, '.*'));
        return regex.test(origin);
      }
      return false;
    });
    if (isAllowed) {
      callback(null, true);
    } else {
      console.log(`❌ CORS blocked for origin: ${origin}`);
      callback(new Error(`CORS policy: Origin ${origin} not allowed`));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH', 'HEAD'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin', 'X-API-Key', 'X-Request-ID'],
  exposedHeaders: ['Content-Range', 'X-Content-Range'],
  maxAge: 86400,
  preflightContinue: false,
  optionsSuccessStatus: 204
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.some(o => o === '*' || o === origin || origin.includes(o))) {
    res.header('Access-Control-Allow-Origin', origin);
  } else if (NODE_ENV === 'development') {
    res.header('Access-Control-Allow-Origin', '*');
  }
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin, X-API-Key');
  res.header('Access-Control-Expose-Headers', 'Content-Range, X-Content-Range');
  res.header('Access-Control-Max-Age', '86400');
  if (req.method === 'OPTIONS') return res.status(200).end();
  next();
});

// ============ RATE LIMITERS ============
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  message: { error: 'Too many requests from this IP' },
  standardHeaders: true,
  legacyHeaders: false
});

// Separate limiter for public website endpoints (unauthenticated).
// Sizing rationale: a single page view fans out to several API calls
// (e.g. the /line detail page makes ~7: line, trials, projects, members,
// staff, trial-lines, publications). A real visitor browsing 8–10 pages
// in a session therefore issues 50–90 requests legitimately. The old
// cap of 120/15min was being exhausted by normal browsing + dev testing,
// returning 429s that rendered as blank pages. 600/15min preserves
// scraper protection (a scraper pulling thousands of rows still trips it)
// while giving real multi-call page loads ample headroom.
const publicApiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 600,
  message: { error: 'Rate limit exceeded for public API. Please try again shortly.' },
  standardHeaders: true,
  legacyHeaders: false,
  // Never count CORS preflights against the budget.
  skip: (req) => req.method === 'OPTIONS',
  // Optional dev/allowlist bypass: set RATELIMIT_BYPASS_IPS="ip1,ip2"
  // to exempt known development machines while testing.
  keyGenerator: (req) => req.ip
});

// IPs that bypass the public limiter entirely (set in env during dev).
const RL_BYPASS = (process.env.RATELIMIT_BYPASS_IPS || '')
  .split(',').map(s => s.trim()).filter(Boolean);
const publicApiLimiterGuarded = (req, res, next) => {
  if (RL_BYPASS.length && RL_BYPASS.includes(req.ip)) return next();
  return publicApiLimiter(req, res, next);
};

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 50,
  message: { error: 'Too many login attempts' },
  skipSuccessfulRequests: true
});

app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:', 'https:'],
      scriptSrc: ["'self'", "'unsafe-inline'"]
    }
  }
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
// /uploads static route moved below authenticateToken declaration (see B-SEC5 fix)

app.use((req, res, next) => {
  console.log(`📡 [${new Date().toISOString()}] ${req.method} ${req.url} - Origin: ${req.headers.origin || 'no-origin'}`);
  next();
});

// ── Maintenance mode — see maintenanceCheck middleware registered on /api below ──

// ============ UTILITY FUNCTIONS ============
const generateId = (prefix) => `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).substr(2, 9)}`;

// FIX 1 SUPPORT: formatDate now safely handles both strings AND Date objects
// (Joi.date() converts strings to Date objects, so .split() would crash on them)
const formatDate = (dateInput) => {
  if (!dateInput) return '';
  try {
    // If it's already a Date object (from Joi conversion), use toISOString()
    if (dateInput instanceof Date) {
      return isNaN(dateInput.getTime()) ? '' : dateInput.toISOString().split('T')[0];
    }
    // If it's a string, parse it
    const date = new Date(dateInput);
    if (isNaN(date.getTime())) return '';
    return date.toISOString().split('T')[0];
  } catch {
    return '';
  }
};

const calculateDays = (start, end) => {
  try {
    const startDate = new Date(start instanceof Date ? start : start);
    const endDate = new Date(end instanceof Date ? end : end);
    if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) return 0;
    const diffTime = Math.abs(endDate - startDate);
    return Math.ceil(diffTime / (1000 * 60 * 60 * 24)) + 1;
  } catch {
    return 0;
  }
};

// FIX 2 SUPPORT: Derive current_status from start/end dates automatically
const deriveAbsenceStatus = (startDate, endDate) => {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const start = new Date(startDate instanceof Date ? startDate : startDate);
  const end = new Date(endDate instanceof Date ? endDate : endDate);
  start.setHours(0, 0, 0, 0);
  end.setHours(23, 59, 59, 999);
  if (start <= today && end >= today) return 'currently_absent';
  if (end < today) return 'returned_to_duty';
  return 'planned_leave';
};

const generatePassword = () => crypto.randomBytes(8).toString('hex');
const hashPassword = async (password) => await bcrypt.hash(password, 10);

// ============ VALIDATION SCHEMAS ============
const schemas = {
  medicalStaff: Joi.object({
    full_name: Joi.string().required(),
    staff_type: Joi.string().min(1).max(80).required(), // dynamic — validated against staff_types table at runtime
    staff_id: Joi.string().optional(),
    employment_status: Joi.string().valid('active', 'on_leave', 'inactive').default('active'),
    professional_email: Joi.string().email().optional().allow('', null), // FIX: email is not always available (residents, external staff)
    department_id: Joi.string().uuid().optional().allow(null),
    academic_degree: Joi.string().optional().allow('', null),       // legacy free-text, kept for backcompat
    academic_degree_id: Joi.string().uuid().optional().allow(null), // new FK to academic_degrees table
    specialization: Joi.string().optional().allow('', null),
    // training_year kept for display/legacy; residency_start_date drives auto-calc
    training_year: Joi.string().optional().allow('', null),
    // Residency date tracking (MIR 4-year programme)
    residency_start_date:    Joi.string().optional().allow('', null), // YYYY-MM-DD, day always 01
    residency_year_override: Joi.string().valid('R1','R2','R3','R4','R4+').optional().allow('', null),
    // Extended fields (Bug 12 fix: Joi was stripping these silently)
    mobile_phone: Joi.string().optional().allow('', null),
    medical_license: Joi.string().optional().allow('', null),       // legacy, kept for backcompat
    has_medical_license: Joi.boolean().optional().default(false),   // new boolean
    clinical_certificate: Joi.string().optional().allow('', null),
    clinical_study_certificate: Joi.string().optional().allow('', null),
    clinical_study_certificates: Joi.array().items(Joi.string()).optional().allow(null),
    other_certificate: Joi.string().optional().allow('', null),
    certificate_status: Joi.string().optional().allow('', null),
    special_notes: Joi.string().optional().allow('', null),
    can_supervise_residents: Joi.boolean().optional().default(false),
    // B5 FIX: Removed duplicate can_be_pi / can_be_coi declarations (were defined twice;
    // the second definition at lines ~272 silently overwrote these)
    resident_category: Joi.string().valid('department_internal', 'rotating_other_dept', 'external_resident').optional().allow(null),
    home_department: Joi.string().optional().allow('', null),
    home_department_id: Joi.string().uuid().optional().allow(null),
    external_institution: Joi.string().optional().allow('', null),
    external_contact_name: Joi.string().optional().allow('', null),
    external_contact_email: Joi.string().email().optional().allow('', null),
    external_contact_phone: Joi.string().optional().allow('', null),
    is_chief_of_department: Joi.boolean().optional().default(false),
    is_research_coordinator: Joi.boolean().optional().default(false),
    is_resident_manager: Joi.boolean().optional().default(false),
    is_oncall_manager: Joi.boolean().optional().default(false),
    hospital_id: Joi.string().uuid().optional().allow(null),
    // Research capability fields (added via migration)
    can_be_pi:  Joi.boolean().optional().default(false),
    can_be_coi: Joi.boolean().optional().default(false),
    has_phd:    Joi.boolean().optional().default(false),
    phd_field:  Joi.string().optional().allow('', null),
    // Public profile fields — surfaced on neumact.org's team page when is_public=true
    is_public:        Joi.boolean().optional().default(false),
    public_bio:       Joi.string().max(2000).optional().allow('', null),
    public_photo_url: Joi.string().uri().optional().allow('', null)
  }),

  announcement: Joi.object({
    title: Joi.string().required(),
    content: Joi.string().required(),
    priority_level: Joi.string().valid('low', 'normal', 'high', 'urgent').default('normal'),
    target_audience: Joi.string().valid('all_staff', 'all', 'attending_only', 'residents_only').default('all_staff'),
    publish_start_date: Joi.date().optional(),
    publish_end_date: Joi.date().optional()
  }),

  // FIX 4: rotation_category values now match the DB CHECK constraint exactly:
  // DB allows: 'clinical_rotation', 'elective_rotation', 'research_block', 'administrative_duty'
  // Old Joi had 'research_rotation' (not in DB) and was missing 'research_block' + 'administrative_duty'
  rotation: Joi.object({
    resident_id: Joi.string().uuid().required(),
    training_unit_id: Joi.string().uuid().required(),
    start_date: Joi.date().required(),
    end_date: Joi.date().required(),
    rotation_status: Joi.string().valid('scheduled', 'active', 'completed', 'extended', 'terminated_early').optional().default('scheduled'),
    rotation_category: Joi.string()
      .valid('clinical_rotation', 'elective_rotation', 'research_block', 'administrative_duty')
      .optional().default('clinical_rotation'),
    supervising_attending_id: Joi.string().uuid().required(),
    rotation_id: Joi.string().optional(),
    clinical_notes: Joi.string().optional().allow(''),
    supervisor_evaluation: Joi.string().optional().allow(''),
    goals: Joi.string().optional().allow(''),
    notes: Joi.string().optional().allow('')
  }),

  onCall: Joi.object({
    duty_date: Joi.date().required(),
    shift_type: Joi.string().valid('primary_call', 'backup_call', 'float_physician').default('primary_call'),
    coverage_area_id: Joi.string().uuid().optional().allow(null, ''),
    start_time: Joi.string().pattern(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/).required(),
    end_time: Joi.string().pattern(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/).required(),
    primary_physician_id: Joi.string().uuid().required(),
    backup_physician_id: Joi.string().uuid().optional().allow(null),
    coverage_notes: Joi.string().optional().allow(''),
    schedule_id: Joi.string().optional(),
    created_by: Joi.string().uuid().optional().allow(null)
  }),

  // FIX 2 SUPPORT: absenceRecord schema — total_days and current_status are derived server-side,
  // not required from client
  absenceRecord: Joi.object({
    staff_member_id: Joi.string().uuid().required(),
    absence_type: Joi.string().valid('planned', 'unplanned').required(),
    absence_reason: Joi.string().valid('vacation', 'conference', 'sick_leave', 'training', 'personal', 'other').required(),
    start_date: Joi.date().required(),
    end_date: Joi.date().required(),
    coverage_arranged: Joi.boolean().default(false),
    covering_staff_id: Joi.string().uuid().optional().allow(null),
    coverage_notes: Joi.string().optional().allow(''),
    hod_notes: Joi.string().optional().allow('')
  }),

  register: Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(8).required(),
    full_name: Joi.string().required(),
    user_role: Joi.string().valid('system_admin', 'department_head', 'resident_manager', 'medical_resident', 'attending_physician').required(),
    department_id: Joi.string().uuid().optional(),
    phone_number: Joi.string().optional()
  }),

  userProfile: Joi.object({
    full_name: Joi.string().optional(),
    phone_number: Joi.string().optional(),
    notifications_enabled: Joi.boolean().optional(),
    absence_notifications: Joi.boolean().optional(),
    announcement_notifications: Joi.boolean().optional()
  }),

  changePassword: Joi.object({
    current_password: Joi.string().required(),
    new_password: Joi.string().min(8).required()
  }),

  forgotPassword: Joi.object({
    email: Joi.string().email().required()
  }),

  resetPassword: Joi.object({
    token: Joi.string().required(),
    new_password: Joi.string().min(8).required()
  }),

  department: Joi.object({
    name: Joi.string().required(),
    code: Joi.string().required(),
    description: Joi.string().optional().allow('', null),
    head_of_department_id: Joi.string().uuid().optional().allow(null, ''),
    hospital_id: Joi.string().uuid().optional().allow(null, ''),
    contact_email: Joi.string().email().optional().allow('', null),
    contact_phone: Joi.string().optional().allow('', null),
    status: Joi.string().valid('active', 'inactive').default('active')
  }),

  trainingUnit: Joi.object({
    unit_name: Joi.string().required(),
    unit_code: Joi.string().required(),
    department_id: Joi.string().uuid().required(),
    supervising_attending_id: Joi.string().uuid().optional().allow(null, ''),
    maximum_residents: Joi.number().integer().min(1).default(5),
    unit_status: Joi.string().valid('active', 'inactive', 'under_renovation').default('active'),
    unit_type: Joi.string().valid('training_unit', 'clinical_unit', 'icu', 'outpatient', 'surgical', 'research').default('training_unit'),
    unit_description: Joi.string().optional().allow('', null),
    specialty: Joi.string().optional().allow('', null),
    location_building: Joi.string().optional().allow('', null),
    location_floor: Joi.string().optional().allow('', null)
  }),

  notification: Joi.object({
    title: Joi.string().required(),
    message: Joi.string().required(),
    recipient_id: Joi.string().uuid().optional(),
    recipient_role: Joi.string().valid('all', 'system_admin', 'department_head', 'resident_manager', 'medical_resident', 'attending_physician').default('all'),
    notification_type: Joi.string().valid('info', 'warning', 'alert', 'reminder').default('info'),
    priority: Joi.string().valid('low', 'normal', 'high', 'urgent').default('normal')
  }),

  systemSettings: Joi.object({
    hospital_name: Joi.string().required(),
    default_department_id: Joi.string().uuid().optional(),
    max_residents_per_unit: Joi.number().integer().min(1).default(10),
    default_rotation_duration: Joi.number().integer().min(1).max(24).default(12),
    enable_audit_logging: Joi.boolean().default(true),
    require_mfa: Joi.boolean().default(false),
    maintenance_mode: Joi.boolean().default(false),
    notifications_enabled: Joi.boolean().default(true),
    absence_notifications: Joi.boolean().default(true),
    announcement_notifications: Joi.boolean().default(true)
  })
,

  // ── Emergency Callouts ──────────────────────────────────────────────
  emergencyCallout: Joi.object({
    staff_id:        Joi.string().uuid().required(),
    called_at:       Joi.string().required(),
    end_time:        Joi.string().allow('', null).optional(),
    reason_category: Joi.string().max(80).allow('', null).optional(),
    notes:           Joi.string().max(1000).allow('', null).optional(),
    time_type:       Joi.string().valid('night','weekend','daytime','holiday').default('night'),
    coverage_area_id: Joi.string().uuid().optional().allow(null, ''),
  }),

  // ── Research Line ────────────────────────────────────────────────────
  researchLine: Joi.object({
    research_line_name: Joi.string().min(2).max(200).required(),
    line_number:        Joi.number().integer().min(1).optional(),
    description:        Joi.string().max(2000).allow('', null).optional(),
    capabilities:       Joi.string().max(2000).allow('', null).optional(),
    keywords:           Joi.array().items(Joi.string()).optional(),
    active:             Joi.boolean().optional(),
    sort_order:         Joi.number().integer().optional(),
    coordinator_id:     Joi.string().uuid().allow('', null).optional(),
  }),

  // ── Clinical Trial ───────────────────────────────────────────────────
  clinicalTrial: Joi.object({
    title:                     Joi.string().min(2).max(400).required(),
    protocol_id:               Joi.string().max(100).allow('', null).optional(),
    research_line_id:          Joi.string().uuid().allow('', null).optional(),
    principal_investigator_id: Joi.string().uuid().allow('', null).optional(),
    phase:                     Joi.string().max(40).allow('', null).optional(),
    status:                    Joi.string().valid('Reclutando','Activo','Completado','En preparación','Suspendido').allow('', null).optional().default('En preparación'),
    enrollment_target:         Joi.number().integer().min(0).allow(null).optional(),
    actual_enrollment:         Joi.number().integer().min(0).allow(null).optional(),
    start_date:                Joi.string().allow('', null).optional(),
    end_date:                  Joi.string().allow('', null).optional(),
    description:               Joi.string().max(4000).allow('', null).optional(),
    sponsor:                   Joi.string().max(200).allow('', null).optional(),
    eudract_number:            Joi.string().max(100).allow('', null).optional(),
    clinicaltrials_id:         Joi.string().max(100).allow('', null).optional(),
  }),

  // ── Innovation Project ───────────────────────────────────────────────
  innovationProject: Joi.object({
    title:             Joi.string().min(2).max(400).required(),
    research_line_id:  Joi.string().uuid().allow('', null).optional(),
    lead_id:           Joi.string().uuid().allow('', null).optional(),
    current_stage:     Joi.string().valid('Idea','Prototipo','Piloto','Validación','Escalamiento','Comercialización').allow('', null).optional(),
    category:          Joi.string().valid('Dispositivo','Salud Digital','IA / ML','Tecnología Quirúrgica').default('Salud Digital'),
    development_stage: Joi.string().valid('Fase Piloto','En Desarrollo','Validación','Validación Clínica').default('En Desarrollo'),
    funding_status:    Joi.string().max(60).allow('', null).optional(),
    description:       Joi.string().max(4000).default(''),
    budget:            Joi.number().min(0).allow(null).optional(),
    start_date:        Joi.string().allow('', null).optional(),
    expected_end_date: Joi.string().allow('', null).optional(),
    patent_status:     Joi.string().max(60).allow('', null).optional(),
  }),

  // ── News / Post ──────────────────────────────────────────────────────
  newsPost: Joi.object({
    title:              Joi.string().min(2).max(400).required(),
    post_type:          Joi.string().valid('update','article','publication','photo_story').required(),
    body:               Joi.string().max(20000).allow('', null).optional(),
    author_id:          Joi.string().uuid().allow('', null).optional(),
    research_line_id:   Joi.string().uuid().allow('', null).optional(),
    is_public:          Joi.boolean().optional(),
    status:             Joi.string().valid('draft','published','archived').default('draft'),
    expires_at:         Joi.string().allow('', null).optional(),
    featured_image_url: Joi.string().max(2000).allow('', null).optional(),
    journal_name:       Joi.string().max(200).allow('', null).optional(),
    authors_text:       Joi.string().max(2000).allow('', null).optional(),
    doi:                Joi.string().max(200).allow('', null).optional(),
    word_count:         Joi.number().integer().min(0).allow(null).optional(),
  }),

  // ── Certificate ──────────────────────────────────────────────────────
  certificate: Joi.object({
    certificate_name: Joi.string().min(2).max(200).required(),
    issued_date:      Joi.string().allow('', null).optional(),
    renewal_months:   Joi.number().integer().min(0).allow(null).optional(),
    notes:            Joi.string().max(1000).allow('', null).optional(),
  }),

  // ── Staff Type ───────────────────────────────────────────────────────
  staffType: Joi.object({
    type_key:         Joi.string().min(2).max(60).pattern(/^[a-z0-9_]+$/).required(),
    display_name:     Joi.string().min(2).max(80).required(),
    badge_class:      Joi.string().max(60).allow('', null).optional(),
    is_resident_type: Joi.boolean().optional(),
    active:           Joi.boolean().optional(),
    sort_order:       Joi.number().integer().optional(),
    description:      Joi.string().max(500).allow('', null).optional(),
  }),

  // ── Rotation Service ─────────────────────────────────────────────────
  rotationService: Joi.object({
    name:          Joi.string().min(2).max(200).required(),
    service_type:  Joi.string().max(60).allow('', null).optional(),
    contact_name:  Joi.string().max(200).allow('', null).optional(),
    contact_email: Joi.string().email({ tlds: false }).allow('', null).optional(),
    contact_phone: Joi.string().max(40).allow('', null).optional(),
    notes:         Joi.string().max(1000).allow('', null).optional(),
    active:        Joi.boolean().optional(),
  })
};

// ============ VALIDATION MIDDLEWARE ============
const validate = (schema) => (req, res, next) => {
  try {
    const { error, value } = schema.validate(req.body, { abortEarly: false, stripUnknown: true });
    if (error) {
      return res.status(400).json({
        error: 'Validation failed',
        details: error.details.map(detail => ({
          field: detail.path.join('.'),
          message: detail.message
        }))
      });
    }
    req.validatedData = value;
    next();
  } catch (err) {
    console.warn('Validation middleware error:', err.message);
    req.validatedData = req.body;
    next();
  }
};

// ============ AUTHENTICATION MIDDLEWARE ============
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
  if (!token) {
    if (req.method === 'OPTIONS') return next();
    return res.status(401).json({ error: 'Authentication required', message: 'No access token provided' });
  }
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token', message: 'Access token is invalid or expired' });
    req.user = user;
    next();
  });
};

// B-SEC5: /uploads served only to authenticated users — must be after authenticateToken is defined
app.use('/uploads', authenticateToken, express.static(path.join(__dirname, 'uploads')));

// ============ MAINTENANCE MODE MIDDLEWARE ============
// Reads maintenance_mode from DB on each /api request (cached 30s).
// Admins pass through regardless of route — the actual "you will still
// have access" promise the UI makes. Previously this only exempted
// /api/auth and /api/settings by path, with no admin check at all,
// meaning it blocked admins from everything else too.
let _maintenanceCache = { value: false, at: 0 }
app.use('/api', async (req, res, next) => {
  if (req.path.startsWith('/api/auth')) return next()
  const now = Date.now()
  if (now - _maintenanceCache.at > 30000) {
    try {
      const { data } = await supabase.from('system_settings').select('maintenance_mode').limit(1).single()
      _maintenanceCache = { value: data?.maintenance_mode === true, at: now }
    } catch { _maintenanceCache.at = now }
  }
  if (!_maintenanceCache.value) return next()
  // Maintenance mode is on — only now is it worth decoding the token
  // early, to check admin status before authenticateToken runs later.
  // Skipping this in the normal (not-in-maintenance) case avoids
  // verifying every JWT twice on every single request.
  const header = req.headers.authorization
  let user = null
  if (header?.startsWith('Bearer ')) {
    try { user = jwt.verify(header.slice(7), JWT_SECRET) } catch { /* not authenticated */ }
  }
  if (user?.admin_level >= 1) { req.user = user; return next() }
  if (req.path === '/api/auth/me') return next()
  return res.status(503).json({ error: 'maintenance', message: 'System is under scheduled maintenance. Please try again shortly.' })
})

// ============ PERMISSION SYSTEM ============
// Per-user, per-module permissions stored in user_permissions table.
// No presets, no role inheritance — every permission is explicit.
// admin_level on app_users controls who CAN assign permissions (not what they have).

const loadUserPermissions = async (userId) => {
  const { data, error } = await supabase
    .from('user_permissions')
    .select('module, can_read, can_write')
    .eq('user_id', userId)
  if (error) throw error
  const map = new Map()
  for (const p of (data || [])) map.set(p.module, p)
  return map
}

const checkPermission = (resource, action) => {
  return async (req, res, next) => {
    if (req.method === 'OPTIONS') return next()
    if (!req.user?.id) return res.status(401).json({ error: 'Authentication required' })
    if (!req.permissions) {
      try { req.permissions = await loadUserPermissions(req.user.id) }
      catch (e) { return res.status(500).json({ error: 'Could not load permissions' }) }
    }
    const perm = req.permissions.get(resource)
    const needsWrite = ['create', 'update', 'delete', 'write'].includes(action)
    const allowed = perm && (needsWrite ? perm.can_write : perm.can_read)
    if (!allowed) {
      return res.status(403).json({
        error: 'Insufficient permissions',
        message: `You do not have ${action} access to ${resource}`
      })
    }
    next()
  }
}

const isAdmin = async (req, res, next) => {
  try {
    const { data } = await supabase
      .from('app_users')
      .select('admin_level')
      .eq('id', req.user.id)
      .single()
    if (!data || data.admin_level < 1) {
      return res.status(403).json({ error: 'Admin access required' })
    }
    req.user.admin_level = data.admin_level
    next()
  } catch (e) {
    res.status(500).json({ error: 'Could not verify admin status' })
  }
}

// ============ AUDIT LOGGING ============
// req is optional — pass it when available to capture user + IP context
const auditLog = async (action, resource, resource_id = '', details = {}, req = null) => {
  try {
    const row = {
      action, resource, resource_id: resource_id || null,
      ip_address: req ? (req.ip || req.headers['x-forwarded-for'] || '') : '',
      user_agent: req ? (req.headers['user-agent'] || '') : '',
      user_name:  req?.user?.full_name || null,
      user_role:  req?.user?.role      || null,
      details: JSON.stringify(details),
      created_at: new Date().toISOString()
    }
    // Only attach user_id when we have one — FK points to auth.users
    if (req?.user?.id) row.user_id = req.user.id
    await supabase.from('audit_logs').insert(row)
  } catch (error) {
    console.error('Audit logging failed (non-fatal):', error.message)
  }
};

// ============================================================================
// ========================== API ENDPOINTS ===================================
// ============================================================================

// ===== 1. ROOT & HEALTH CHECK =====
app.get('/', (req, res) => {
  res.json({
    service: 'NeumoCare Hospital Management System API',
    version: '5.4.0',
    status: 'operational',
    environment: NODE_ENV,
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

app.get('/health', apiLimiter, (req, res) => {
  res.json({
    status: 'healthy',
    service: 'NeumoCare Hospital Management System API',
    version: '5.4.0',
    timestamp: new Date().toISOString(),
    environment: NODE_ENV,
    cors: { allowed_origins: allowedOrigins, your_origin: req.headers.origin || 'not-specified' },
    database: SUPABASE_URL ? 'Connected' : 'Not connected',
    uptime: process.uptime()
  });
});

app.get('/api/debug/tables', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const testPromises = [
      supabase.from('resident_rotations').select('id').limit(1),
      supabase.from('oncall_schedule').select('id').limit(1),
      supabase.from('staff_absence_records').select('id').limit(1),
      supabase.from('medical_staff').select('id').limit(1),
      supabase.from('training_units').select('id').limit(1),
      supabase.from('departments').select('id').limit(1),
      supabase.from('app_users').select('id').limit(1),
      supabase.from('audit_logs').select('id').limit(1),
      supabase.from('notifications').select('id').limit(1),
      supabase.from('clinical_status_updates').select('id').limit(1),
      supabase.from('absence_audit_log').select('id').limit(1)
    ];
    const results = await Promise.allSettled(testPromises);
    const names = ['resident_rotations','oncall_schedule','staff_absence_records','medical_staff',
      'training_units','departments','app_users','audit_logs','notifications',
      'clinical_status_updates','absence_audit_log'];
    const tableStatus = Object.fromEntries(
      names.map((name, i) => [name, results[i].status === 'fulfilled' && !results[i].value.error ? '✅ Accessible' : '❌ Error'])
    );
    res.json({ message: 'Table accessibility test', status: tableStatus });
  } catch (error) {
    res.status(500).json({ error: 'Debug test failed', message: error.message });
  }
});

app.get('/api/debug/cors', apiLimiter, (req, res) => {
  const origin = req.headers.origin || 'no-origin-header';
  const isAllowed = allowedOrigins.includes(origin) || allowedOrigins.includes('*');
  res.json({ your_origin: origin, allowed_origins: allowedOrigins, is_allowed: isAllowed });
});

app.get('/api/debug/live-status', authenticateToken, async (req, res) => {
  try {
    const today = new Date().toISOString();
    const { data, error } = await supabase
      .from('clinical_status_updates')
      .select('*').gt('expires_at', today).eq('is_active', true)
      .order('created_at', { ascending: false }).limit(1).single();
    if (error) return res.json({ success: false, error: error.message, code: error.code });
    res.json({ success: true, result: data });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ===== 2. AUTHENTICATION =====
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log('🔐 Login attempt for:', email);

    // B2 FIX: Removed hardcoded admin bypass (was: admin@neumocare.org / password123)
    // B2 FIX: Removed unauthenticated fallback — unknown users must exist in DB

    if (!email || !password) {
      return res.status(400).json({ error: 'Validation failed', message: 'Email and password are required' });
    }

    const { data: user, error } = await supabase
      .from('app_users')
      .select('id, email, full_name, user_role, job_title, admin_level, department_id, password_hash, account_status, medical_staff_id')
      .eq('email', email.toLowerCase()).single();

    if (error || !user) {
      return res.status(401).json({ error: 'Authentication failed', message: 'Invalid email or password' });
    }

    if (user.account_status !== 'active') {
      return res.status(403).json({ error: 'Account disabled', message: 'Your account has been deactivated' });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash || '');
    if (!validPassword) {
      return res.status(401).json({ error: 'Authentication failed', message: 'Invalid email or password' });
    }

    // Load this user's explicit permissions from DB
    const permMap = await loadUserPermissions(user.id)
    const permissions = Array.from(permMap.values())

    // Real linked staff record, if any — replaces runtime email/name
    // guessing on the frontend with the actual stored relationship.
    let linkedStaff = null;
    if (user.medical_staff_id) {
      const { data: staffRow } = await supabase
        .from('medical_staff')
        .select('id, full_name, professional_email, staff_type, specialization, public_photo_url')
        .eq('id', user.medical_staff_id)
        .maybeSingle();
      linkedStaff = staffRow || null;
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.user_role, full_name: user.full_name },
      JWT_SECRET, { expiresIn: '24h' }
    );
    const { password_hash, ...userWithoutPassword } = user;
    res.json({ token, user: { ...userWithoutPassword, permissions, linked_staff: linkedStaff }, expires_in: '24h' });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error', message: error.message });
  }
});

app.post('/api/auth/logout', authenticateToken, apiLimiter, async (req, res) => {
  res.json({ message: 'Logged out successfully', timestamp: new Date().toISOString() });
});

// Token validation endpoint — called on mount to verify session is still valid
app.get('/api/auth/me', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('app_users')
      .select('id, email, full_name, user_role, job_title, admin_level, account_status, department_id, medical_staff_id')
      .eq('id', req.user.id)
      .single()
    if (error || !data) return res.status(401).json({ error: 'User not found' })
    if (data.account_status !== 'active') return res.status(401).json({ error: 'Account suspended or inactive' })
    const permMap = await loadUserPermissions(req.user.id)
    const permissions = Array.from(permMap.values())
    let linkedStaff = null;
    if (data.medical_staff_id) {
      const { data: staffRow } = await supabase
        .from('medical_staff')
        .select('id, full_name, professional_email, staff_type, specialization, public_photo_url')
        .eq('id', data.medical_staff_id)
        .maybeSingle();
      linkedStaff = staffRow || null;
    }
    res.json({ ...data, permissions, linked_staff: linkedStaff })
  } catch (e) { res.status(401).json({ error: 'Session validation failed' }) }
});

app.post('/api/auth/register', authenticateToken, checkPermission('users', 'create'), validate(schemas.register), async (req, res) => {
  try {
    const { email, password, ...userData } = req.validatedData || req.body;
    const passwordHash = await bcrypt.hash(password, 10);
    const { data, error } = await supabase.from('app_users')
      .insert([{ ...userData, email: email.toLowerCase(), password_hash: passwordHash, account_status: 'active', created_at: new Date().toISOString(), updated_at: new Date().toISOString() }])
      .select('id, email, full_name, user_role, department_id').single();
    if (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'User already exists' });
      throw error;
    }
    res.status(201).json({ message: 'User registered successfully', user: data });
  } catch (error) {
    res.status(500).json({ error: 'Failed to register user', message: error.message });
  }
});

app.post('/api/auth/forgot-password', authLimiter, validate(schemas.forgotPassword), async (req, res) => {
  try {
    const { email } = req.validatedData || req.body;
    const { data: user } = await supabase.from('app_users').select('id, email, full_name').eq('email', email.toLowerCase()).single();
    // Always return 200 — never reveal whether the email exists (prevents enumeration)
    if (user) {
      const resetToken = jwt.sign({ userId: user.id, email: user.email, purpose: 'password_reset' }, JWT_SECRET, { expiresIn: '1h' });
      const tokenExpiry = new Date(Date.now() + 60 * 60 * 1000).toISOString();
      // Store token hash in DB so it can be invalidated after use
      await supabase.from('app_users').update({
        reset_token: resetToken,
        reset_token_expires_at: tokenExpiry,
        updated_at: new Date().toISOString()
      }).eq('id', user.id);
      const resetLink = `${APP_URL}?reset_token=${resetToken}`;
      await sendNotification(
        'Password reset request — neumDesk',
        `<h2 style="margin:0 0 12px;color:#0a1628">Password Reset</h2>
        <p style="color:#374151">Hello <strong>${user.full_name || user.email}</strong>,</p>
        <p style="color:#374151">A password reset was requested for your neumDesk account. Click the link below to set a new password. This link expires in <strong>1 hour</strong>.</p>
        <a href="${resetLink}" style="display:inline-block;margin:12px 0;padding:10px 20px;background:#00b3b3;color:#fff;text-decoration:none;border-radius:6px;font-size:13px;font-weight:600">Reset my password →</a>
        <p style="color:#9ca3af;font-size:12px;margin-top:16px">If you did not request this reset, you can safely ignore this email. Your password will not change.</p>`
      );
    }
    res.json({ message: 'If an account with that email exists, a reset link has been sent.' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to process password reset', message: error.message });
  }
});

app.post('/api/auth/reset-password', authLimiter, validate(schemas.resetPassword), async (req, res) => {
  try {
    const { token, new_password } = req.validatedData || req.body;
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch {
      return res.status(400).json({ error: 'Invalid or expired token', message: 'The reset link is invalid or has expired. Please request a new one.' });
    }
    if (decoded.purpose !== 'password_reset') {
      return res.status(400).json({ error: 'Invalid token', message: 'This token cannot be used for password reset.' });
    }
    // Verify token matches what's stored (prevents token reuse after a new reset was requested)
    const { data: user } = await supabase.from('app_users')
      .select('id, reset_token, reset_token_expires_at')
      .eq('email', decoded.email).single();
    if (!user || user.reset_token !== token) {
      return res.status(400).json({ error: 'Token already used', message: 'This reset link has already been used or superseded. Please request a new one.' });
    }
    if (new Date(user.reset_token_expires_at) < new Date()) {
      return res.status(400).json({ error: 'Token expired', message: 'This reset link has expired. Please request a new one.' });
    }
    const passwordHash = await bcrypt.hash(new_password, 10);
    const { error } = await supabase.from('app_users')
      .update({
        password_hash: passwordHash,
        reset_token: null,
        reset_token_expires_at: null,
        updated_at: new Date().toISOString()
      })
      .eq('email', decoded.email);
    if (error) throw error;
    res.json({ message: 'Password reset successfully. You can now log in with your new password.' });
  } catch (error) {
    res.status(400).json({ error: 'Failed to reset password', message: error.message });
  }
});

// ===== 2b. PERMISSION MANAGEMENT =====
// GET /api/permissions/users — list all users with their current permission tags (admin only)
app.get('/api/permissions/users', authenticateToken, isAdmin, apiLimiter, async (req, res) => {
  try {
    const { data: users, error } = await supabase
      .from('app_users')
      .select('id, full_name, email, user_role, job_title, admin_level, account_status, medical_staff_id')
      .order('full_name')
    if (error) throw error

    const { data: perms } = await supabase
      .from('user_permissions')
      .select('user_id, module, can_read, can_write, granted_by, granted_at')

    // Group permissions by user
    const permsByUser = {}
    for (const p of (perms || [])) {
      if (!permsByUser[p.user_id]) permsByUser[p.user_id] = []
      permsByUser[p.user_id].push(p)
    }

    // Resolve linked staff records in one batch query, not N+1
    const staffIds = users.map(u => u.medical_staff_id).filter(Boolean);
    let staffById = {};
    if (staffIds.length) {
      const { data: staffRows } = await supabase
        .from('medical_staff')
        .select('id, full_name, specialization, staff_type')
        .in('id', staffIds);
      staffById = Object.fromEntries((staffRows || []).map(s => [s.id, s]));
    }

    res.json({
      success: true,
      data: users.map(u => ({
        ...u,
        permissions: permsByUser[u.id] || [],
        linked_staff: u.medical_staff_id ? (staffById[u.medical_staff_id] || null) : null,
      }))
    })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

// PUT /api/permissions/:userId/:module — grant or revoke a specific module permission
// Body: { can_read: bool, can_write: bool }
// Constraint: admin cannot grant more than they themselves have
app.put('/api/permissions/:userId/:module', authenticateToken, isAdmin, apiLimiter, async (req, res) => {
  try {
    const { userId, module } = req.params
    const { can_read = false, can_write = false } = req.body

    // Safety: an admin cannot revoke their own access — same protection
    // already applied to the admin-level toggle below. Without this, an
    // admin could click their own way down to zero modules (including
    // 'settings', the page this control lives on) with no one else able
    // to restore it short of direct database access.
    if (userId === req.user.id && !can_read && !can_write) {
      return res.status(403).json({ error: 'You cannot revoke your own access to ' + module + '. Ask another admin to do this if needed.' })
    }

    // Safety: admin cannot grant more than they themselves have
    const adminPerms = await loadUserPermissions(req.user.id)
    const adminHas = adminPerms.get(module)
    if (can_read && !adminHas?.can_read) {
      return res.status(403).json({ error: 'You cannot grant read access to ' + module + ' because you do not have it yourself' })
    }
    if (can_write && !adminHas?.can_write) {
      return res.status(403).json({ error: 'You cannot grant write access to ' + module + ' because you do not have it yourself' })
    }

    // Upsert — if both false, remove the row entirely (clean revoke)
    if (!can_read && !can_write) {
      await supabase.from('user_permissions').delete().eq('user_id', userId).eq('module', module)
      return res.json({ success: true, action: 'revoked', module })
    }

    const { data, error } = await supabase
      .from('user_permissions')
      .upsert({
        user_id: userId,
        module,
        can_read,
        can_write,
        granted_by: req.user.id,
        updated_at: new Date().toISOString()
      }, { onConflict: 'user_id,module' })
      .select()

    if (error) throw error
    res.json({ success: true, action: 'granted', data: data?.[0] })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

// PUT /api/permissions/:userId/admin — toggle admin_level (admin only, cannot self-demote)
app.put('/api/permissions/:userId/admin-level', authenticateToken, isAdmin, apiLimiter, async (req, res) => {
  try {
    const { userId } = req.params
    const { admin_level } = req.body
    if (userId === req.user.id) {
      return res.status(403).json({ error: 'You cannot change your own admin level' })
    }
    const { error } = await supabase
      .from('app_users')
      .update({ admin_level: admin_level ? 1 : 0, updated_at: new Date().toISOString() })
      .eq('id', userId)
    if (error) throw error
    res.json({ success: true, admin_level })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

// ===== 3. USER MANAGEMENT =====
app.get('/api/users', authenticateToken, checkPermission('users', 'read'), apiLimiter, async (req, res) => {
  try {
    const { page = 1, limit = 20, role, department_id, status } = req.query;
    const offset = (page - 1) * limit;
    let query = supabase.from('app_users')
      .select('id, email, full_name, user_role, department_id, phone_number, account_status, created_at, updated_at', { count: 'exact' });
    if (role) query = query.eq('user_role', role);
    if (department_id) query = query.eq('department_id', department_id);
    if (status) query = query.eq('account_status', status);
    const { data, error, count } = await query.order('created_at', { ascending: false }).range(offset, offset + limit - 1);
    if (error) throw error;
    res.json({ data: data || [], pagination: { page: parseInt(page), limit: parseInt(limit), total: count || 0, totalPages: Math.ceil((count || 0) / limit) } });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch users', message: error.message });
  }
});

// B1 FIX: Static sub-routes must come BEFORE /:id — otherwise Express matches 'change-password'
// and 'profile' as the :id parameter, making these endpoints unreachable.

// ===== 4. USER PROFILE =====
app.get('/api/users/profile', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { data, error } = await supabase.from('app_users')
      .select('id, email, full_name, user_role, department_id, phone_number, notifications_enabled, absence_notifications, announcement_notifications, created_at, updated_at')
      .eq('id', req.user.id).single();
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch user profile', message: error.message });
  }
});

app.put('/api/users/profile', authenticateToken, validate(schemas.userProfile), async (req, res) => {
  try {
    const { data, error } = await supabase.from('app_users')
      .update({ ...(req.validatedData || req.body), updated_at: new Date().toISOString() })
      .eq('id', req.user.id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update profile', message: error.message });
  }
});

app.put('/api/users/change-password', authenticateToken, validate(schemas.changePassword), async (req, res) => {
  try {
    const { current_password, new_password } = req.validatedData || req.body;
    const { data: user, error: fetchError } = await supabase.from('app_users').select('password_hash').eq('id', req.user.id).single();
    if (fetchError) throw fetchError;
    const validPassword = await bcrypt.compare(current_password, user.password_hash || '');
    if (!validPassword) return res.status(401).json({ error: 'Current password is incorrect' });
    const passwordHash = await bcrypt.hash(new_password, 10);
    const { error } = await supabase.from('app_users').update({ password_hash: passwordHash, updated_at: new Date().toISOString() }).eq('id', req.user.id);
    if (error) throw error;
    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to change password', message: error.message });
  }
});

app.get('/api/users/:id', authenticateToken, checkPermission('users', 'read'), apiLimiter, async (req, res) => {
  try {
    const { data, error } = await supabase.from('app_users')
      .select('id, email, full_name, user_role, department_id, phone_number, account_status, created_at, updated_at')
      .eq('id', req.params.id).single();
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'User not found' });
      throw error;
    }
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch user', message: error.message });
  }
});

app.post('/api/users', authenticateToken, checkPermission('users', 'create'), validate(schemas.register), async (req, res) => {
  try {
    const { email, password, ...userData } = req.validatedData || req.body;
    const passwordHash = await bcrypt.hash(password, 10);
    const { data, error } = await supabase.from('app_users')
      .insert([{ ...userData, email: email.toLowerCase(), password_hash: passwordHash, account_status: 'active', created_at: new Date().toISOString(), updated_at: new Date().toISOString() }])
      .select('id, email, full_name, user_role, department_id').single();
    if (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'User already exists' });
      throw error;
    }
    res.status(201).json({ message: 'User created successfully', user: data });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create user', message: error.message });
  }
});

app.put('/api/users/:id', authenticateToken, checkPermission('users', 'update'), validate(schemas.userProfile), async (req, res) => {
  try {
    const { data, error } = await supabase.from('app_users')
      .update({ ...(req.validatedData || req.body), updated_at: new Date().toISOString() })
      .eq('id', req.params.id).select('id, email, full_name, user_role, department_id').single();
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'User not found' });
      throw error;
    }
    res.json({ message: 'User updated successfully', user: data });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update user', message: error.message });
  }
});

app.delete('/api/users/:id', authenticateToken, checkPermission('users', 'delete'), apiLimiter, async (req, res) => {
  try {
    const { error } = await supabase.from('app_users')
      .update({ account_status: 'inactive', updated_at: new Date().toISOString() }).eq('id', req.params.id);
    if (error) throw error;
    res.json({ message: 'User deactivated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete user', message: error.message });
  }
});

app.put('/api/users/:id/activate', authenticateToken, checkPermission('users', 'update'), apiLimiter, async (req, res) => {
  try {
    const { error } = await supabase.from('app_users').update({ account_status: 'active', updated_at: new Date().toISOString() }).eq('id', req.params.id);
    if (error) throw error;
    res.json({ message: 'User activated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to activate user', message: error.message });
  }
});

app.put('/api/users/:id/deactivate', authenticateToken, checkPermission('users', 'update'), apiLimiter, async (req, res) => {
  try {
    const { error } = await supabase.from('app_users').update({ account_status: 'inactive', updated_at: new Date().toISOString() }).eq('id', req.params.id);
    if (error) throw error;
    res.json({ message: 'User deactivated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to deactivate user', message: error.message });
  }
});



// ===== 5. MEDICAL STAFF =====
app.get('/api/medical-staff', authenticateToken, checkPermission('medical_staff', 'read'), apiLimiter, async (req, res) => {
  try {
    const { search, staff_type, employment_status, department_id, page = 1, limit = 500 } = req.query;
    const offset = (page - 1) * limit;
    let query = supabase.from('medical_staff')
      .select('*, departments!medical_staff_department_id_fkey(name, code), hospitals!medical_staff_hospital_id_fkey(id, name, code, parent_complex), home_dept:departments!medical_staff_home_department_id_fkey(id, name, code), degree:academic_degrees!medical_staff_academic_degree_id_fkey(id, name, abbreviation)', { count: 'exact' });
    if (search) query = query.or(`full_name.ilike.%${search}%,staff_id.ilike.%${search}%,professional_email.ilike.%${search}%`);
    if (staff_type) query = query.eq('staff_type', staff_type);
    // Exclude inactive by default; pass ?employment_status=inactive to retrieve them
    if (employment_status) {
      if (employment_status === 'all') {
        // no filter — return everyone including inactive (used for name-resolution lookups)
      } else {
        query = query.eq('employment_status', employment_status);
      }
    } else {
      query = query.neq('employment_status', 'inactive');
    }
    if (department_id) query = query.eq('department_id', department_id);
    const { data, error, count } = await query.order('full_name').range(offset, offset + limit - 1);
    if (error) throw error;
    const transformedData = (data || []).map(item => ({
      ...item,
      department: item.departments ? { name: item.departments.name, code: item.departments.code } : null
    }));
    res.json({ data: transformedData, pagination: { page: parseInt(page), limit: parseInt(limit), total: count || 0, totalPages: Math.ceil((count || 0) / limit) } });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch medical staff', message: error.message });
  }
});

app.get('/api/medical-staff/:id', authenticateToken, checkPermission('medical_staff', 'read'), apiLimiter, async (req, res) => {
  try {
    const { data, error } = await supabase.from('medical_staff')
      .select('*, departments!medical_staff_department_id_fkey(name, code), hospitals!medical_staff_hospital_id_fkey(id, name, code, parent_complex), home_dept:departments!medical_staff_home_department_id_fkey(id, name, code), degree:academic_degrees!medical_staff_academic_degree_id_fkey(id, name, abbreviation)').eq('id', req.params.id).single();
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Medical staff not found' });
      throw error;
    }
    res.json({ ...data, department: data.departments ? { name: data.departments.name, code: data.departments.code } : null });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch staff details', message: error.message });
  }
});

app.post('/api/medical-staff', authenticateToken, checkPermission('medical_staff', 'create'), validate(schemas.medicalStaff), async (req, res) => {
  try {
    const dataSource = req.validatedData || req.body;

    // Validate department assignment
    if (dataSource.department_id) {
      const { data: dept } = await supabase.from('departments')
        .select('is_external, name, status')
        .eq('id', dataSource.department_id)
        .single();
      if (dept?.status === 'inactive') {
        return res.status(400).json({ error: 'Invalid department', message: 'Department is inactive.' });
      }
      // External departments only valid for affiliated staff
      const affiliation = dataSource.affiliation_type || 'primary';
      if (dept?.is_external && affiliation === 'primary') {
        return res.status(400).json({
          error: 'Invalid department',
          message: `${dept.name} is an external rotation service. Primary staff must belong to the home department. Set affiliation_type to "affiliated" for clinicians from external departments who participate in the rotation programme.`
        });
      }
    }

    const staffData = {
      full_name: dataSource.full_name,
      staff_type: dataSource.staff_type,
      staff_id: dataSource.staff_id || generateId('MD'),
      professional_email: dataSource.professional_email,
      employment_status: dataSource.employment_status || 'active',
      department_id: dataSource.department_id || null,
      affiliation_type: dataSource.affiliation_type || 'primary',
      primary_dept_name: dataSource.primary_dept_name || null,
      academic_degree: dataSource.academic_degree || null,
      academic_degree_id: dataSource.academic_degree_id || null,
      specialization: dataSource.specialization || null,
      training_year: dataSource.training_year || null,
      residency_start_date:    dataSource.residency_start_date || null,
      residency_year_override: dataSource.residency_year_override || null,
      has_medical_license: dataSource.has_medical_license || false,
      clinical_study_certificate: dataSource.clinical_certificate || null,
      certificate_status: dataSource.certificate_status || null,
      resident_category: dataSource.resident_category || null,
      primary_clinic: dataSource.primary_clinic || null,
      work_phone: dataSource.work_phone || null,
      medical_license: dataSource.medical_license || null,
      can_supervise_residents: dataSource.can_supervise_residents || false,
      special_notes: dataSource.special_notes || null,
      resident_type: dataSource.resident_type || null,
      home_department: dataSource.home_department || null,
      home_department_id: dataSource.home_department_id || null,
      external_institution: dataSource.external_institution || null,
      external_contact_name: dataSource.external_contact_name || null,
      external_contact_email: dataSource.external_contact_email || null,
      external_contact_phone: dataSource.external_contact_phone || null,
      years_experience: dataSource.years_experience || null,
      biography: dataSource.biography || null,
      date_of_birth: dataSource.date_of_birth || null,
      mobile_phone: dataSource.mobile_phone || null,
      office_phone: dataSource.office_phone || null,
      training_level: dataSource.training_level || null,
      hospital_id: dataSource.hospital_id || null,
      can_be_pi:   dataSource.can_be_pi   ?? false,
      can_be_coi:  dataSource.can_be_coi  ?? false,
      has_phd:     dataSource.has_phd     ?? false,
      phd_field:   dataSource.phd_field   || null,
      is_public:        dataSource.is_public        ?? false,
      public_bio:       dataSource.public_bio        || null,
      public_photo_url: dataSource.public_photo_url  || null,
      updated_at: new Date().toISOString()
    };
    const { data, error } = await supabase.from('medical_staff').insert([staffData]).select().single();
    if (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'Duplicate entry', message: 'A staff member with this email or ID already exists' });
      throw error;
    }
    res.status(201).json(data);
  } catch (error) {
    console.error('Failed to create medical staff:', error);
    res.status(500).json({ error: 'Failed to create medical staff', message: error.message });
  }
});

app.put('/api/medical-staff/:id', authenticateToken, checkPermission('medical_staff', 'update'), validate(schemas.medicalStaff), async (req, res) => {
  try {
    const dataSource = req.validatedData || req.body;
    // FIX: DB column is TEXT — keep training_year as string, no parseInt conversion
    // parseInt('PGY-2') → NaN → null, silently erasing valid values
    const trainingYearValue = dataSource.training_year || dataSource.resident_year || null;
    const updateData = {
      full_name: dataSource.full_name,
      staff_type: dataSource.staff_type,
      staff_id: dataSource.staff_id,
      employment_status: dataSource.employment_status,
      professional_email: dataSource.professional_email,
      department_id: dataSource.department_id || null,
      academic_degree: dataSource.academic_degree || null,
      academic_degree_id: dataSource.academic_degree_id || null,
      specialization: dataSource.specialization || null,
      training_year: trainingYearValue,
      residency_start_date:    dataSource.residency_start_date || null,
      residency_year_override: dataSource.residency_year_override || null,
      has_medical_license: dataSource.has_medical_license ?? false,
      clinical_study_certificate: dataSource.clinical_certificate || null,
      certificate_status: dataSource.certificate_status || null,
      resident_category: dataSource.resident_category || null,
      external_institution: dataSource.external_institution || null,
      home_department: dataSource.home_department || null,
      home_department_id: dataSource.home_department_id || null,
      external_contact_name: dataSource.external_contact_name || null,
      external_contact_email: dataSource.external_contact_email || null,
      external_contact_phone: dataSource.external_contact_phone || null,
      can_supervise_residents: dataSource.can_supervise_residents || false,
      is_research_coordinator: dataSource.is_research_coordinator || false,
      is_resident_manager:     dataSource.is_resident_manager     || false,
      is_oncall_manager:       dataSource.is_oncall_manager       || false,
      is_chief_of_department:  dataSource.is_chief_of_department  || false,
      mobile_phone: dataSource.mobile_phone || null,
      special_notes: dataSource.special_notes || null,
      hospital_id: dataSource.hospital_id || null,
      can_be_pi:   dataSource.can_be_pi   ?? false,
      can_be_coi:  dataSource.can_be_coi  ?? false,
      has_phd:     dataSource.has_phd     ?? false,
      phd_field:   dataSource.phd_field   || null,
      clinical_study_certificates: Array.isArray(dataSource.clinical_study_certificates) ? dataSource.clinical_study_certificates : (dataSource.clinical_study_certificates || null),
      is_public:        dataSource.is_public        ?? false,
      public_bio:       dataSource.public_bio        || null,
      public_photo_url: dataSource.public_photo_url  || null,
      updated_at: new Date().toISOString()
    };
    // Read current staff_type BEFORE update so we can detect type changes
    const prevStaff = await supabase.from('medical_staff').select('staff_type').eq('id', req.params.id).single();
    const { data, error } = await supabase.from('medical_staff').update(updateData).eq('id', req.params.id).select().single();
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Medical staff not found' });
      throw error;
    }

    // If marking inactive: scan for future records that are now orphaned
    const warnings = [];
    if (dataSource.employment_status === 'inactive') {
      const today = new Date().toISOString().split('T')[0];
      const [rotationCheck, oncallCheck, absenceCheck] = await Promise.all([
        supabase.from('resident_rotations')
          .select('id, training_unit_id, start_date, end_date, rotation_status')
          .eq('resident_id', req.params.id)
          .in('rotation_status', ['active','scheduled'])
          .gte('end_date', today),
        supabase.from('oncall_schedule')
          .select('id, duty_date, shift_type')
          .eq('primary_physician_id', req.params.id)
          .gte('duty_date', today),
        supabase.from('staff_absence_records')
          .select('id, start_date, end_date')
          .eq('staff_member_id', req.params.id)
          .in('current_status', ['pending','active'])
      ]);
      if (rotationCheck.data?.length) warnings.push({ type: 'rotations', count: rotationCheck.data.length, message: `${rotationCheck.data.length} future rotation(s) still assigned` });
      if (oncallCheck.data?.length) warnings.push({ type: 'oncall', count: oncallCheck.data.length, message: `${oncallCheck.data.length} future on-call shift(s) unassigned` });
      if (absenceCheck.data?.length) warnings.push({ type: 'absences', count: absenceCheck.data.length, message: `${absenceCheck.data.length} active absence record(s) remain` });
      // Flag oncall conflicts
      if (oncallCheck.data?.length) {
        const ids = oncallCheck.data.map(o => o.id);
        await supabase.from('oncall_schedule').update({ has_conflict: true }).in('id', ids);
      }
    }

    // If staff type changes FROM a resident type TO a non-resident type,
    // terminate their active/scheduled rotations automatically
    if (prevStaff.data && prevStaff.data.staff_type !== dataSource.staff_type) {
      const [prevType, newType] = await Promise.all([
        supabase.from('staff_types').select('is_resident_type').eq('type_key', prevStaff.data.staff_type).single(),
        supabase.from('staff_types').select('is_resident_type').eq('type_key', dataSource.staff_type).single()
      ]);
      const wasResident = prevType.data?.is_resident_type;
      const nowResident = newType.data?.is_resident_type;
      if (wasResident && !nowResident) {
        // Promoted to attending — terminate their rotations
        const { data: terminated } = await supabase.from('resident_rotations')
          .update({ rotation_status: 'terminated_early', updated_at: new Date().toISOString() })
          .eq('resident_id', req.params.id)
          .in('rotation_status', ['active','scheduled'])
          .select('id');
        if (terminated?.length) {
          warnings.push({ type: 'rotations_terminated', count: terminated.length, message: `${terminated.length} rotation(s) automatically terminated — staff promoted from resident to attending` });
        }
      }
    }

    res.json({ ...data, _warnings: warnings });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update medical staff', message: error.message });
  }
});

app.delete('/api/medical-staff/:id', authenticateToken, checkPermission('medical_staff', 'delete'), apiLimiter, async (req, res) => {
  try {
    const { data, error } = await supabase.from('medical_staff')
      .update({ employment_status: 'inactive', updated_at: new Date().toISOString() })
      .eq('id', req.params.id).select('full_name, staff_id').single();
    if (error) throw error;
    res.json({ message: 'Medical staff deactivated successfully', staff_name: data.full_name });
  } catch (error) {
    res.status(500).json({ error: 'Failed to deactivate medical staff', message: error.message });
  }
});

// ===== 6. DEPARTMENTS =====
app.get('/api/departments', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { include_inactive, type } = req.query;
    let query = supabase.from('departments')
      .select('*, medical_staff!departments_head_of_department_id_fkey(full_name, professional_email), hospital:hospitals!departments_hospital_id_fkey(id, name, code, parent_complex)')
      .order('display_order', { ascending: true })
      .order('name', { ascending: true });

    // Default: active only
    if (!include_inactive || include_inactive !== 'true') {
      query = query.eq('status', 'active');
    }
    // Optional: filter by type — 'home' or 'external'
    if (type === 'home')     query = query.eq('is_primary', true);
    if (type === 'external') query = query.eq('is_external', true);

    const { data, error } = await query;
    if (error) throw error;
    res.json((data || []).map(item => ({
      ...item,
      head_of_department: {
        full_name: item.medical_staff?.full_name || null,
        professional_email: item.medical_staff?.professional_email || null
      },
      // Explicit type flags for frontend
      is_primary:  item.is_primary  || false,
      is_external: item.is_external || false,
      service_type: item.service_type || 'rotation_service'
    })));
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch departments', message: error.message });
  }
});

app.get('/api/departments/:id', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { data, error } = await supabase.from('departments')
      .select('*, medical_staff!departments_head_of_department_id_fkey(full_name, professional_email, staff_type)').eq('id', req.params.id).single();
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Department not found' });
      throw error;
    }
    res.json({ ...data, head_of_department: { full_name: data.medical_staff?.full_name || null, professional_email: data.medical_staff?.professional_email || null } });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch department details', message: error.message });
  }
});

app.post('/api/departments', authenticateToken, checkPermission('departments', 'create'), validate(schemas.department), async (req, res) => {
  try {
    const { data, error } = await supabase.from('departments')
      .insert([{ ...(req.validatedData || req.body), created_at: new Date().toISOString(), updated_at: new Date().toISOString() }]).select().single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create department', message: error.message });
  }
});

app.put('/api/departments/:id', authenticateToken, checkPermission('departments', 'update'), validate(schemas.department), async (req, res) => {
  try {
    const { data, error } = await supabase.from('departments')
      .update({ ...(req.validatedData || req.body), updated_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Department not found' });
      throw error;
    }
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update department', message: error.message });
  }
});

// GET /api/departments/:id/impact — pre-delete impact scan
app.get('/api/departments/:id/impact', authenticateToken, checkPermission('departments', 'delete'), async (req, res) => {
  try {
    const deptId = req.params.id;
    const [
      { data: dept },
      { data: activeStaff },
      { data: activeUnits },
      { data: activeRotations }
    ] = await Promise.all([
      supabase.from('departments').select('name, code').eq('id', deptId).single(),
      supabase.from('medical_staff').select('id, full_name, staff_type, employment_status')
        .eq('department_id', deptId).eq('employment_status', 'active'),
      supabase.from('training_units').select('id, unit_name, unit_status')
        .eq('department_id', deptId).eq('unit_status', 'active'),
      supabase.from('resident_rotations').select('id, rotation_status, training_unit_id, supervisor_id')
        .eq('rotation_status', 'active')
        .in('training_unit_id',
          (await supabase.from('training_units').select('id').eq('department_id', deptId)).data?.map(u => u.id) || []
        )
    ]);
    res.json({
      department: dept,
      impact: {
        activeStaff:     activeStaff     || [],
        activeUnits:     activeUnits     || [],
        activeRotations: activeRotations || [],
        canDelete: (activeStaff?.length === 0 && activeRotations?.length === 0)
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to check department impact', message: error.message });
  }
});

// DELETE /api/departments/:id — soft delete with optional staff/unit reassignment
app.delete('/api/departments/:id', authenticateToken, checkPermission('departments', 'delete'), async (req, res) => {
  try {
    const deptId = req.params.id;
    const { reassignments } = req.body || {};  // { staffDeptId, unitsDeptId } — target dept IDs

    // Re-check impact at delete time (race-condition safety)
    const [{ data: activeStaff }, { data: activeUnits }] = await Promise.all([
      supabase.from('medical_staff').select('id').eq('department_id', deptId).eq('employment_status', 'active'),
      supabase.from('training_units').select('id').eq('department_id', deptId).eq('unit_status', 'active')
    ]);

    const hasActiveStaff = (activeStaff || []).length > 0;
    const hasActiveUnits = (activeUnits || []).length > 0;

    // Block if there are active records but no reassignment targets provided
    if ((hasActiveStaff || hasActiveUnits) && !reassignments) {
      return res.status(409).json({
        error: 'Department has active dependencies',
        message: `This department has ${activeStaff?.length || 0} active staff and ${activeUnits?.length || 0} active units. Provide reassignment targets or reassign manually first.`,
        activeStaff: activeStaff?.length || 0,
        activeUnits: activeUnits?.length || 0
      });
    }

    // Apply reassignments if provided
    if (reassignments?.staffDeptId && hasActiveStaff) {
      const { error: staffErr } = await supabase.from('medical_staff')
        .update({ department_id: reassignments.staffDeptId, updated_at: new Date().toISOString() })
        .eq('department_id', deptId).eq('employment_status', 'active');
      if (staffErr) throw staffErr;
    }
    if (reassignments?.unitsDeptId && hasActiveUnits) {
      const { error: unitErr } = await supabase.from('training_units')
        .update({ department_id: reassignments.unitsDeptId, updated_at: new Date().toISOString() })
        .eq('department_id', deptId).eq('unit_status', 'active');
      if (unitErr) throw unitErr;
    }

    // Soft-delete the department
    const { data, error } = await supabase.from('departments')
      .update({ status: 'inactive', updated_at: new Date().toISOString() })
      .eq('id', deptId).select('name').single();
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Department not found' });
      throw error;
    }

    await auditLog('DELETE', 'departments', deptId, {
      name: data.name,
      reassignments: reassignments || null
    });

    res.json({
      message: 'Department deactivated successfully',
      name: data.name,
      reassigned: !!reassignments
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to deactivate department', message: error.message });
  }
});

// ===== 7. TRAINING UNITS =====
app.get('/api/training-units', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { department_id, unit_status } = req.query;
    let query = supabase.from('training_units')
      .select('*, departments!training_units_department_id_fkey(name, code), medical_staff!training_units_supervisor_id_fkey(full_name, professional_email)')
      .order('unit_name');
    if (department_id) query = query.eq('department_id', department_id);
    // Exclude inactive by default; pass ?unit_status=inactive to retrieve them
    if (unit_status) {
      query = query.eq('unit_status', unit_status);
    } else {
      query = query.neq('unit_status', 'inactive');
    }
    const { data, error } = await query;
    if (error) throw error;
    res.json((data || []).map(item => ({
      ...item,
      unit_type: item.unit_type || 'training_unit',
      department: item.departments ? { name: item.departments.name, code: item.departments.code } : null,
      supervisor: { full_name: item.medical_staff?.full_name || null, professional_email: item.medical_staff?.professional_email || null }
    })));
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch training units', message: error.message });
  }
});

app.get('/api/training-units/:id', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { data, error } = await supabase.from('training_units')
      .select('*, departments!training_units_department_id_fkey(name, code), medical_staff!training_units_supervisor_id_fkey(full_name, professional_email)')
      .eq('id', req.params.id).single();
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Training unit not found' });
      throw error;
    }
    res.json({ ...data, department: data.departments ? { name: data.departments.name, code: data.departments.code } : null, supervisor: { full_name: data.medical_staff?.full_name || null } });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch training unit details', message: error.message });
  }
});

app.post('/api/training-units', authenticateToken, checkPermission('training_units', 'create'), validate(schemas.trainingUnit), async (req, res) => {
  try {
    const dataSource = req.validatedData || req.body;
    let departmentName = 'Unknown Department';
    if (dataSource.department_id) {
      const { data: dept } = await supabase.from('departments').select('name').eq('id', dataSource.department_id).single();
      if (dept) departmentName = dept.name;
    }
    const unitData = {
      unit_name: dataSource.unit_name, unit_code: dataSource.unit_code,
      department_name: departmentName, department_id: dataSource.department_id,
      maximum_residents: dataSource.maximum_residents,
      default_supervisor_id: dataSource.supervising_attending_id || null,
      supervisor_id: dataSource.supervising_attending_id || null,
      unit_status: dataSource.unit_status || 'active',
      unit_type: dataSource.unit_type || 'training_unit',
      specialty: dataSource.specialty || null,
      unit_description: dataSource.unit_description || dataSource.specialty || null,
      location_building: dataSource.location_building || null,
      location_floor: dataSource.location_floor || null
    };
    const { data, error } = await supabase.from('training_units').insert([unitData]).select().single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create training unit', message: error.message });
  }
});

app.put('/api/training-units/:id', authenticateToken, checkPermission('training_units', 'update'), validate(schemas.trainingUnit), async (req, res) => {
  try {
    const dataSource = req.validatedData || req.body;
    // FIX: Joi field 'supervising_attending_id' must map to DB columns 'supervisor_id' + 'default_supervisor_id'
    // stripUnknown:true would drop supervising_attending_id since it's not a DB column name
    // GAP 2 FIX: Check if reducing capacity would breach existing rotations
    if (dataSource.maximum_residents) {
      const { data: currentUnit } = await supabase
        .from('training_units')
        .select('maximum_residents')
        .eq('id', req.params.id)
        .single();
      if (currentUnit && dataSource.maximum_residents < currentUnit.maximum_residents) {
        const today = new Date().toISOString().split('T')[0];
        const { data: activeRots } = await supabase
          .from('resident_rotations')
          .select('id')
          .eq('training_unit_id', req.params.id)
          .in('rotation_status', ['active', 'scheduled'])
          .gte('end_date', today);
        const occupied = activeRots?.length || 0;
        if (occupied > dataSource.maximum_residents) {
          return res.status(409).json({
            error: 'Capacity conflict',
            message: `Cannot reduce capacity to ${dataSource.maximum_residents} — unit currently has ${occupied} active/scheduled rotations`,
            occupied, requested: dataSource.maximum_residents
          });
        }
      }
    }

    const updateData = {
      unit_name:         dataSource.unit_name,
      unit_code:         dataSource.unit_code,
      department_id:     dataSource.department_id,
      maximum_residents: dataSource.maximum_residents,
      unit_status:       dataSource.unit_status || 'active',
      updated_at:        new Date().toISOString()
    };
    if (dataSource.supervising_attending_id) {
      updateData.supervisor_id         = dataSource.supervising_attending_id;
      updateData.default_supervisor_id = dataSource.supervising_attending_id;
    } else if (dataSource.supervising_attending_id === null) {
      updateData.supervisor_id         = null;
      updateData.default_supervisor_id = null;
    }
    if (dataSource.specialty !== undefined)          updateData.specialty          = dataSource.specialty || null;
    if (dataSource.location_building !== undefined)  updateData.location_building  = dataSource.location_building || null;
    if (dataSource.location_floor !== undefined)     updateData.location_floor     = dataSource.location_floor || null;
    if (dataSource.unit_type !== undefined)          updateData.unit_type          = dataSource.unit_type || 'training_unit';
    if (dataSource.unit_description !== undefined)   updateData.unit_description   = dataSource.unit_description || null;
    // Also refresh department_name to stay in sync with department_id changes
    if (dataSource.department_id) {
      try {
        const { data: dept } = await supabase.from('departments').select('name').eq('id', dataSource.department_id).single();
        if (dept) updateData.department_name = dept.name;
      } catch (_) {}
    }

    const { data, error } = await supabase.from('training_units')
      .update(updateData).eq('id', req.params.id).select().single();
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Training unit not found' });
      throw error;
    }
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update training unit', message: error.message });
  }
});

// DELETE /api/training-units/:id — soft delete
app.delete('/api/training-units/:id', authenticateToken, checkPermission('training_units', 'delete'), async (req, res) => {
  try {
    const { data, error } = await supabase.from('training_units')
      .update({ unit_status: 'inactive', updated_at: new Date().toISOString() })
      .eq('id', req.params.id).select('unit_name').single();
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Training unit not found' });
      throw error;
    }
    res.json({ message: 'Training unit deactivated successfully', unit_name: data.unit_name });
  } catch (error) {
    res.status(500).json({ error: 'Failed to deactivate training unit', message: error.message });
  }
});

// ===== 8. RESIDENT ROTATIONS =====
app.get('/api/rotations', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { resident_id, rotation_status, training_unit_id, start_date, end_date, page = 1, limit = 500 } = req.query;
    const offset = (page - 1) * limit;
    let query = supabase.from('resident_rotations').select(`
        *, resident:medical_staff!resident_rotations_resident_id_fkey(full_name, professional_email, staff_type),
        supervising_attending:medical_staff!resident_rotations_supervising_attending_id_fkey(full_name, professional_email),
        training_unit:training_units!resident_rotations_training_unit_id_fkey(unit_name, unit_code)
      `, { count: 'exact' });
    if (resident_id) query = query.eq('resident_id', resident_id);
    // Exclude terminated_early by default; pass ?rotation_status=terminated_early to retrieve them
    if (rotation_status) {
      query = query.eq('rotation_status', rotation_status);
    } else {
      query = query.neq('rotation_status', 'terminated_early');
    }
    if (training_unit_id) query = query.eq('training_unit_id', training_unit_id);
    if (start_date) query = query.gte('start_date', start_date);
    if (end_date) query = query.lte('end_date', end_date);
    const { data, error, count } = await query.order('start_date', { ascending: false }).range(offset, offset + limit - 1);
    if (error) throw error;
    // Filter out orphan rotations where the resident record no longer exists
    const cleanData = (data || []).filter(item => item.resident !== null);
    res.json({
      data: cleanData.map(item => ({
        ...item,
        resident: { full_name: item.resident.full_name, professional_email: item.resident.professional_email, staff_type: item.resident.staff_type },
        supervising_attending: item.supervising_attending ? { full_name: item.supervising_attending.full_name } : null,
        training_unit: item.training_unit ? { unit_name: item.training_unit.unit_name, unit_code: item.training_unit.unit_code } : null
      })),
      pagination: { page: parseInt(page), limit: parseInt(limit), total: count || 0, totalPages: Math.ceil((count || 0) / limit) }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch rotations', message: error.message });
  }
});

app.get('/api/rotations/current', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const today = formatDate(new Date());
    const { data, error } = await supabase.from('resident_rotations')
      .select('*, resident:medical_staff!resident_rotations_resident_id_fkey(full_name), training_unit:training_units!resident_rotations_training_unit_id_fkey(unit_name)')
      .lte('start_date', today).gte('end_date', today).eq('rotation_status', 'active').order('start_date');
    if (error) throw error;
    res.json(data || []);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch current rotations', message: error.message });
  }
});

// GET /api/rotations/availability
// Returns occupancy for a training unit over a date range so the frontend
// can warn when capacity would be exceeded.
// Query params: training_unit_id (required), start_date, end_date, exclude_id
app.get('/api/rotations/availability', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { training_unit_id, start_date, end_date, exclude_id } = req.query
    if (!training_unit_id) return res.status(400).json({ error: 'training_unit_id is required' })

    // Fetch the unit to get its capacity
    const { data: unit, error: unitErr } = await supabase
      .from('training_units')
      .select('id, unit_name, maximum_residents, current_resident_count')
      .eq('id', training_unit_id)
      .single()
    if (unitErr) throw unitErr
    if (!unit) return res.status(404).json({ error: 'Training unit not found' })

    const capacity = unit.maximum_residents || 999

    // Fetch overlapping active/scheduled rotations for this unit in the date range
    let query = supabase
      .from('resident_rotations')
      .select('id, resident_id, start_date, end_date, rotation_status, resident:medical_staff!resident_rotations_resident_id_fkey(id, full_name)')
      .eq('training_unit_id', training_unit_id)
      .in('rotation_status', ['active', 'scheduled'])

    if (start_date && end_date) {
      // Overlapping: existing.start <= new.end AND existing.end >= new.start
      query = query.lte('start_date', end_date).gte('end_date', start_date)
    }

    if (exclude_id) query = query.neq('id', exclude_id)

    const { data: overlapping, error: rotErr } = await query.order('start_date')
    if (rotErr) throw rotErr

    const occupied = overlapping?.length || 0
    const available = Math.max(0, capacity - occupied)

    res.json({
      unit_id:    unit.id,
      unit_name:  unit.unit_name,
      capacity,
      occupied,
      available,
      is_full:    occupied >= capacity,
      overlapping: (overlapping || []).map(r => ({
        id:         r.id,
        resident_id: r.resident_id,
        resident_name: r.resident?.full_name || null,
        start_date: r.start_date,
        end_date:   r.end_date,
        status:     r.rotation_status
      }))
    })
  } catch (error) {
    res.status(500).json({ error: 'Failed to check rotation availability', message: error.message })
  }
})
// ══════════════════════════════════════════════════════════════════════════════
// UNIT STAFF — who works in each training unit (operational staffing)
// GET  /api/training-units/:id/staff   → list attendings for a unit
// POST /api/training-units/:id/staff   → add attending to unit
// DELETE /api/training-units/:unitId/staff/:staffId → remove
// GET  /api/staff/:id/units            → which units does this person belong to
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/training-units/:id/staff', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('unit_staff')
      .select(`
        id, role, assigned_from, assigned_until,
        staff:medical_staff!unit_staff_staff_id_fkey(
          id, full_name, staff_type, employment_status, professional_email
        )
      `)
      .eq('unit_id', req.params.id)
      .is('assigned_until', null)   // active only — no end date means current
      .order('role')
      .order('created_at');
    if (error) throw error;
    res.json({ success: true, data: data || [] });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch unit staff', message: e.message });
  }
});

app.post('/api/training-units/:id/staff', authenticateToken,
  checkPermission('training_units', 'update'), async (req, res) => {
  try {
    const { staff_id, role = 'primary' } = req.body;
    if (!staff_id) return res.status(400).json({ error: 'staff_id is required' });
    const { data, error } = await supabase.from('unit_staff').insert([{
      unit_id: req.params.id, staff_id, role,
      assigned_from: formatDate(new Date()),
      created_at: new Date().toISOString(), updated_at: new Date().toISOString()
    }]).select(`
      id, role, assigned_from,
      staff:medical_staff!unit_staff_staff_id_fkey(id, full_name, staff_type, employment_status)
    `).single();
    if (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'This clinician is already assigned to this unit' });
      throw error;
    }
    res.status(201).json({ success: true, data });
  } catch (e) {
    res.status(500).json({ error: 'Failed to assign staff to unit', message: e.message });
  }
});

app.delete('/api/training-units/:unitId/staff/:staffId', authenticateToken,
  checkPermission('training_units', 'update'), async (req, res) => {
  try {
    const { error } = await supabase.from('unit_staff')
      .update({ assigned_until: formatDate(new Date()), updated_at: new Date().toISOString() })
      .eq('unit_id', req.params.unitId)
      .eq('staff_id', req.params.staffId)
      .is('assigned_until', null);
    if (error) throw error;
    res.json({ success: true, message: 'Clinician removed from unit' });
  } catch (e) {
    res.status(500).json({ error: 'Failed to remove staff from unit', message: e.message });
  }
});

// Which units does a staff member belong to? (used in staff profile + absence impact)
app.get('/api/staff/:id/units', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('unit_staff')
      .select(`
        id, role, assigned_from,
        unit:training_units!unit_staff_unit_id_fkey(
          id, unit_name, unit_code, unit_type, unit_status, department_id
        )
      `)
      .eq('staff_id', req.params.id)
      .is('assigned_until', null)
      .order('role');
    if (error) throw error;
    res.json({ success: true, data: data || [] });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch staff units', message: e.message });
  }
});



app.post('/api/rotations', authenticateToken, checkPermission('resident_rotations', 'create'), validate(schemas.rotation), async (req, res) => {
  try {
    const dataSource = req.validatedData || req.body;

    // FIX 1: Joi.date() turns strings into Date objects. Use formatDate() which handles both.
    const startDate = formatDate(dataSource.start_date);
    const endDate   = formatDate(dataSource.end_date);

    if (!startDate || !endDate) {
      return res.status(400).json({ error: 'Invalid date format', message: 'start_date and end_date must be valid dates' });
    }

    console.log('Creating rotation with dates:', { startDate, endDate });

    // Overlap check
    // FIX: Only 'scheduled', 'active', 'extended' are truly blocking — completed/terminated/cancelled are not
    const { data: existingRotations, error: checkError } = await supabase.from('resident_rotations')
      .select('id, start_date, end_date, rotation_status')
      .eq('resident_id', dataSource.resident_id)
      .in('rotation_status', ['scheduled', 'active', 'extended'])
      .not('end_date', 'lt', startDate).not('start_date', 'gt', endDate);
    if (checkError) throw checkError;
    if (existingRotations && existingRotations.length > 0) {
      return res.status(409).json({ error: 'Scheduling conflict', message: 'Resident already has a rotation during these dates', conflicts: existingRotations });
    }

    // GAP 1 FIX: Check unit capacity for the requested date range
    const { data: unitForCap, error: unitCapErr } = await supabase
      .from('training_units')
      .select('id, unit_name, maximum_residents')
      .eq('id', dataSource.training_unit_id)
      .single();
    if (unitCapErr) throw unitCapErr;
    if (unitForCap) {
      const { data: overlappingInUnit } = await supabase
        .from('resident_rotations')
        .select('id, resident_id, start_date, end_date')
        .eq('training_unit_id', dataSource.training_unit_id)
        .in('rotation_status', ['active', 'scheduled'])
        .lte('start_date', endDate)
        .gte('end_date', startDate);
      const occupied = overlappingInUnit?.length || 0;
      if (occupied >= unitForCap.maximum_residents) {
        return res.status(409).json({
          error: 'Unit at capacity',
          message: `"${unitForCap.unit_name}" is full for this period (${occupied}/${unitForCap.maximum_residents} slots occupied)`,
          occupied, capacity: unitForCap.maximum_residents
        });
      }
    }

    const rotationData = {
      ...dataSource,
      start_date: startDate,
      end_date: endDate,
      rotation_id: dataSource.rotation_id || generateId('ROT'),
      clinical_notes: dataSource.clinical_notes || '',
      supervisor_evaluation: dataSource.supervisor_evaluation || '',
      goals: dataSource.goals || '',
      notes: dataSource.notes || '',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    // Auto-fill supervisor from unit default if not explicitly provided
    if (!rotationData.supervising_attending_id && unitForCap) {
      const { data: unitFull } = await supabase
        .from('training_units')
        .select('default_supervisor_id')
        .eq('id', dataSource.training_unit_id)
        .single();
      if (unitFull?.default_supervisor_id) {
        rotationData.supervising_attending_id = unitFull.default_supervisor_id;
      }
    }

    const { data, error } = await supabase.from('resident_rotations').insert([rotationData]).select().single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (error) {
    console.error('Failed to create rotation:', error);
    res.status(500).json({ error: 'Failed to create rotation', message: error.message });
  }
});

// FIX 1: PUT /api/rotations/:id — same formatDate() fix
app.put('/api/rotations/:id', authenticateToken, checkPermission('resident_rotations', 'update'), validate(schemas.rotation), async (req, res) => {
  try {
    const dataSource = req.validatedData || req.body;

    // FIX 1: Joi.date() gives Date objects — use formatDate() not .split()
    const startDate = formatDate(dataSource.start_date);
    const endDate   = formatDate(dataSource.end_date);

    if (!startDate || !endDate) {
      return res.status(400).json({ error: 'Invalid date format', message: 'start_date and end_date must be valid dates' });
    }

    const rotationData = {
      ...dataSource,
      start_date: startDate,
      end_date: endDate,
      clinical_notes: dataSource.clinical_notes || '',
      supervisor_evaluation: dataSource.supervisor_evaluation || '',
      goals: dataSource.goals || '',
      notes: dataSource.notes || '',
      updated_at: new Date().toISOString()
    };

    const { data, error } = await supabase.from('resident_rotations').update(rotationData).eq('id', req.params.id).select().single();
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Rotation not found' });
      throw error;
    }

    // ── NOTIFICATION: Rotation ending soon with no successor scheduled ───
    try {
      const endDate = new Date(rotationData.end_date + 'T00:00:00');
      const today   = new Date(); today.setHours(0,0,0,0);
      const daysLeft = Math.round((endDate - today) / 86400000);
      if (daysLeft >= 0 && daysLeft <= 7) {
        // Check if a replacement rotation exists for this unit after end_date
        const { data: nextRots } = await supabase.from('resident_rotations')
          .select('id').eq('training_unit_id', rotationData.training_unit_id)
          .in('rotation_status', ['scheduled','active'])
          .gte('start_date', rotationData.end_date).limit(1);
        if (!nextRots || nextRots.length === 0) {
          const resName = await getPhysicianName(rotationData.resident_id);
          const { data: unit } = await supabase.from('training_units').select('unit_name').eq('id', rotationData.training_unit_id).single();
          const unitName = unit?.unit_name || 'Unknown unit';
          sendNotification(
            `Rotation ending soon — no successor: ${unitName}`,
            `<h2 style="margin:0 0 12px;color:#0a1628">Rotation slot opening soon</h2>
            <p style="color:#374151"><strong>${resName}</strong>'s rotation at <strong>${unitName}</strong> 
            ends on <strong>${rotationData.end_date}</strong> (${daysLeft} day${daysLeft!==1?'s':''} from today).</p>
            <p style="color:#f59e0b;font-weight:600">⚠ No successor has been scheduled for this unit.</p>
            <a href="${APP_URL}" style="display:inline-block;margin-top:8px;padding:8px 16px;background:#00b3b3;color:#fff;text-decoration:none;border-radius:6px;font-size:13px">Assign rotation →</a>`,
            daysLeft <= 3
          );
        }
      }
    } catch (notifErr) {
      console.error('[NOTIFY] Rotation check error:', notifErr.message);
    }

    res.json(data);
  } catch (error) {
    console.error('Failed to update rotation:', error);
    res.status(500).json({ error: 'Failed to update rotation', message: error.message });
  }
});

app.delete('/api/rotations/:id', authenticateToken, checkPermission('resident_rotations', 'delete'), apiLimiter, async (req, res) => {
  try {
    // Soft delete — preserve audit history by marking as terminated_early
    const { data, error } = await supabase.from('resident_rotations')
      .update({ rotation_status: 'terminated_early', updated_at: new Date().toISOString() })
      .eq('id', req.params.id)
      .select('rotation_id')
      .single();
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Rotation not found' });
      throw error;
    }
    res.json({ message: 'Rotation terminated successfully', rotation_id: data.rotation_id });
  } catch (error) {
    res.status(500).json({ error: 'Failed to terminate rotation', message: error.message });
  }
});

// ===== 9. ON-CALL SCHEDULE =====
// FIX 6: Duplicate on-call route block removed. Only one set of handlers here.
app.get('/api/oncall', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { start_date, end_date, physician_id } = req.query;
    let query = supabase.from('oncall_schedule').select(`
        *, primary_physician:medical_staff!oncall_schedule_primary_physician_id_fkey(full_name, professional_email, mobile_phone),
        backup_physician:medical_staff!oncall_schedule_backup_physician_id_fkey(full_name, professional_email, mobile_phone),
        coverage_area:coverage_areas(id,name,code,color)
      `).order('duty_date');
    if (start_date) query = query.gte('duty_date', start_date);
    if (end_date) query = query.lte('duty_date', end_date);
    if (physician_id) query = query.or(`primary_physician_id.eq.${physician_id},backup_physician_id.eq.${physician_id}`);
    const { data, error } = await query;
    if (error) throw error;
    res.json((data || []).map(item => ({
      id: item.id, duty_date: item.duty_date, shift_type: item.shift_type,
      start_time: item.start_time, end_time: item.end_time,
      primary_physician_id: item.primary_physician_id, backup_physician_id: item.backup_physician_id,
      coverage_area_id: item.coverage_area_id || null,
      coverage_area: item.coverage_area || null, coverage_notes: item.coverage_notes || '',
      schedule_id: item.schedule_id, created_at: item.created_at,
      primary_physician: item.primary_physician ? { full_name: item.primary_physician.full_name, professional_email: item.primary_physician.professional_email, mobile_phone: item.primary_physician.mobile_phone } : null,
      backup_physician: item.backup_physician ? { full_name: item.backup_physician.full_name, professional_email: item.backup_physician.professional_email } : null
    })));
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch on-call schedule', message: error.message });
  }
});

app.get('/api/oncall/today', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const today = formatDate(new Date());
    const { data, error } = await supabase.from('oncall_schedule').select(`
        *, primary_physician:medical_staff!oncall_schedule_primary_physician_id_fkey(full_name, professional_email, mobile_phone, staff_type),
        backup_physician:medical_staff!oncall_schedule_backup_physician_id_fkey(full_name, professional_email, mobile_phone)
      `).eq('duty_date', today);
    if (error) throw error;
    res.json(data || []);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch today\'s on-call', message: error.message });
  }
});

app.get('/api/oncall/upcoming', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const today = formatDate(new Date());
    const nextWeek = formatDate(new Date(Date.now() + 7 * 24 * 60 * 60 * 1000));
    const { data, error } = await supabase.from('oncall_schedule')
      .select('*, primary_physician:medical_staff!oncall_schedule_primary_physician_id_fkey(full_name, professional_email)')
      .gte('duty_date', today).lte('duty_date', nextWeek).order('duty_date');
    if (error) throw error;
    res.json(data || []);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch upcoming on-call', message: error.message });
  }
});

app.post('/api/oncall', authenticateToken, checkPermission('oncall_schedule', 'create'), validate(schemas.onCall), async (req, res) => {
  try {
    const d = req.validatedData || req.body;
    const scheduleData = {
      duty_date:            formatDate(d.duty_date),
      shift_type:           d.shift_type || 'primary_call',
      start_time:           d.start_time,
      end_time:             d.end_time,
      primary_physician_id: d.primary_physician_id,
      backup_physician_id:  d.backup_physician_id  || null,
      coverage_notes:       d.coverage_notes       || null,
      coverage_area_id:     d.coverage_area_id     || null,
      schedule_id:          generateId('SCH'),   // always server-generated — never trust client value
      created_by:           req.user.id,
      created_at:           new Date().toISOString(),
      updated_at:           new Date().toISOString()
    };
    const { data, error } = await supabase.from('oncall_schedule').insert([scheduleData]).select().single();
    if (error) throw error;

    // ── NOTIFICATION: On-call scheduled without backup ───────────────────
    if (!scheduleData.backup_physician_id) {
      getPhysicianName(scheduleData.primary_physician_id).then(async name => {
        // Check if this area requires coverage
        let areaName = 'Unknown area';
        if (scheduleData.coverage_area_id) {
          const { data: area } = await supabase.from('coverage_areas').select('name,requires_coverage').eq('id', scheduleData.coverage_area_id).single();
          if (area) {
            areaName = area.name;
            if (!area.requires_coverage) return; // only notify for required areas
          }
        }
        sendNotification(
          `On-call without backup — ${areaName} on ${scheduleData.duty_date}`,
          `<h2 style="margin:0 0 12px;color:#0a1628">On-call shift has no backup</h2>
          <p style="color:#374151"><strong>${name}</strong> is scheduled for <strong>${areaName}</strong> 
          on <strong>${scheduleData.duty_date}</strong> with no backup assigned.</p>
          <p style="color:#f59e0b;font-weight:600">⚠ Consider assigning a backup physician.</p>
          <a href="${APP_URL}" style="display:inline-block;margin-top:8px;padding:8px 16px;background:#00b3b3;color:#fff;text-decoration:none;border-radius:6px;font-size:13px">Open neumDesk →</a>`,
          false
        );
      });
    }

    res.status(201).json(data);
  } catch (error) {
    if (error.code === '23505') {
      // Check which unique constraint was violated
      const isAreaDuplicate = error.constraint === 'oncall_one_primary_per_area_per_day'
        || error.detail?.includes('coverage_area_id');
      const isScheduleIdDuplicate = error.constraint?.includes('schedule_id')
        || error.detail?.includes('schedule_id');
      if (isAreaDuplicate)
        return res.status(409).json({ error: 'Duplicate schedule', message: 'A primary call already exists for this area and date. Choose a different coverage area.' });
      if (isScheduleIdDuplicate)
        return res.status(409).json({ error: 'Duplicate schedule', message: 'ID collision — please try saving again.' });
      // Unknown 23505 — log and return detail
      return res.status(409).json({ error: 'Duplicate entry', message: error.detail || error.message });
    }
    if (error.code === '42703')
      return res.status(500).json({ error: 'Schema mismatch', message: 'Run the coverage_areas migration in Supabase first. Column missing: ' + error.message });
    res.status(500).json({ error: 'Failed to create on-call schedule', message: error.message });
  }
});

app.put('/api/oncall/:id', authenticateToken, checkPermission('oncall_schedule', 'update'), validate(schemas.onCall), async (req, res) => {
  try {
    const d = req.validatedData || req.body;
    const scheduleData = {
      duty_date:            formatDate(d.duty_date),
      shift_type:           d.shift_type || 'primary_call',
      start_time:           d.start_time,
      end_time:             d.end_time,
      primary_physician_id: d.primary_physician_id,
      backup_physician_id:  d.backup_physician_id  || null,
      coverage_notes:       d.coverage_notes       || null,
      coverage_area_id:     d.coverage_area_id     || null,
      updated_at:           new Date().toISOString()
    };
    const { data, error } = await supabase.from('oncall_schedule').update(scheduleData).eq('id', req.params.id).select().single();
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Schedule not found' });
      if (error.code === '23505')    return res.status(409).json({ error: 'Duplicate schedule', message: 'A primary call already exists for this area and date.' });
      if (error.code === '42703')    return res.status(500).json({ error: 'Schema mismatch', message: 'Run the coverage_areas migration in Supabase first. Column missing: ' + error.message });
      throw error;
    }
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update on-call schedule', message: error.message });
  }
});

app.delete('/api/oncall/:id', authenticateToken, checkPermission('oncall_schedule', 'delete'), apiLimiter, async (req, res) => {
  try {
    const { error } = await supabase.from('oncall_schedule').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ message: 'On-call schedule deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete on-call schedule', message: error.message });
  }
});

// ===== 10. STAFF ABSENCE RECORDS =====
app.get('/api/absence-records', authenticateToken, checkPermission('staff_absence', 'read'), apiLimiter, async (req, res) => {
  try {
    const { staff_member_id, absence_type, current_status, start_date, end_date, coverage_arranged, absence_reason, page = 1, limit = 500 } = req.query;
    const offset = (page - 1) * limit;
    let query = supabase.from('staff_absence_records').select(`
        *, staff_member:medical_staff!staff_absence_records_staff_member_id_fkey(id, full_name, professional_email, staff_type, department_id),
        covering_staff:medical_staff!staff_absence_records_covering_staff_id_fkey(id, full_name, professional_email),
        recorded_by_user:app_users!staff_absence_records_recorded_by_fkey(id, full_name, email)
      `, { count: 'exact' });
    if (staff_member_id) query = query.eq('staff_member_id', staff_member_id);
    if (absence_type) query = query.eq('absence_type', absence_type);
    // Exclude cancelled (soft-deleted) records by default; pass ?current_status=cancelled to retrieve them
    if (current_status) {
      query = query.eq('current_status', current_status);
    } else {
      query = query.neq('current_status', 'cancelled');
    }
    if (coverage_arranged) query = query.eq('coverage_arranged', coverage_arranged === 'true');
    if (absence_reason) query = query.eq('absence_reason', absence_reason);
    if (start_date) query = query.gte('start_date', start_date);
    if (end_date) query = query.lte('end_date', end_date);
    const { data, error, count } = await query.order('start_date', { ascending: false }).range(offset, offset + limit - 1);
    if (error) throw error;
    res.json({
      success: true,
      data: (data || []).map(item => ({ ...item, staff_member: item.staff_member || null, covering_staff: item.covering_staff || null, recorded_by: item.recorded_by_user || null })),
      pagination: { page: parseInt(page), limit: parseInt(limit), total: count || 0, totalPages: Math.ceil((count || 0) / limit) }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch absence records', message: error.message });
  }
});

app.get('/api/absence-records/current', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { data, error } = await supabase.from('staff_absence_records').select(`
        *, staff_member:medical_staff!staff_absence_records_staff_member_id_fkey(id, full_name, professional_email, staff_type),
        covering_staff:medical_staff!staff_absence_records_covering_staff_id_fkey(id, full_name)
      `).eq('current_status', 'currently_absent').order('start_date');
    if (error) throw error;
    res.json({ success: true, data: data || [], count: data?.length || 0 });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch current absences', message: error.message });
  }
});

app.get('/api/absence-records/upcoming', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const today = formatDate(new Date());
    const nextWeek = formatDate(new Date(Date.now() + 7 * 24 * 60 * 60 * 1000));
    const { data, error } = await supabase.from('staff_absence_records').select(`
        *, staff_member:medical_staff!staff_absence_records_staff_member_id_fkey(id, full_name, professional_email, staff_type)
      `).eq('current_status', 'planned_leave').gte('start_date', today).lte('start_date', nextWeek).order('start_date');
    if (error) throw error;
    res.json({ success: true, data: data || [], count: data?.length || 0 });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch upcoming absences', message: error.message });
  }
});

// B4 FIX: Static sub-routes must come before /:id to avoid Express matching
// 'staff', 'dashboard' etc. as the :id param
app.get('/api/absence-records/staff/:staffId', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { limit = 20, page = 1 } = req.query;
    const offset = (page - 1) * limit;
    const { data, error, count } = await supabase.from('staff_absence_records').select('*', { count: 'exact' })
      .eq('staff_member_id', req.params.staffId).order('start_date', { ascending: false }).range(offset, offset + limit - 1);
    if (error) throw error;
    res.json({ success: true, data: data || [], pagination: { page: parseInt(page), limit: parseInt(limit), total: count || 0, totalPages: Math.ceil((count || 0) / limit) } });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch staff absence history', message: error.message });
  }
});

app.get('/api/absence-records/dashboard/stats', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const today = formatDate(new Date());
    const nextWeek = formatDate(new Date(Date.now() + 7 * 24 * 60 * 60 * 1000));
    const [total, current, upcoming, withoutCoverage, byType, byReason] = await Promise.all([
      supabase.from('staff_absence_records').select('*', { count: 'exact', head: true }),
      supabase.from('staff_absence_records').select('*', { count: 'exact', head: true }).eq('current_status', 'currently_absent'),
      supabase.from('staff_absence_records').select('*', { count: 'exact', head: true }).eq('current_status', 'planned_leave').gte('start_date', today).lte('start_date', nextWeek),
      supabase.from('staff_absence_records').select('*', { count: 'exact', head: true }).eq('coverage_arranged', false).eq('current_status', 'currently_absent'),
      supabase.from('staff_absence_records').select('absence_type'),
      supabase.from('staff_absence_records').select('absence_reason')
    ]);
    const typeCounts = {}, reasonCounts = {};
    byType.data?.forEach(i => { typeCounts[i.absence_type] = (typeCounts[i.absence_type] || 0) + 1; });
    byReason.data?.forEach(i => { reasonCounts[i.absence_reason] = (reasonCounts[i.absence_reason] || 0) + 1; });
    res.json({ success: true, data: { total: total.count || 0, currently_absent: current.count || 0, upcoming: upcoming.count || 0, without_coverage: withoutCoverage.count || 0, by_type: typeCounts, by_reason: reasonCounts, coverage_rate: total.count ? Math.round(((total.count - withoutCoverage.count) / total.count) * 100) : 100 } });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch absence stats', message: error.message });
  }
});

app.get('/api/absence-records/:id', authenticateToken, checkPermission('staff_absence', 'read'), apiLimiter, async (req, res) => {
  try {
    const { data, error } = await supabase.from('staff_absence_records').select(`
        *, staff_member:medical_staff!staff_absence_records_staff_member_id_fkey(id, full_name, professional_email, staff_type, department_id),
        covering_staff:medical_staff!staff_absence_records_covering_staff_id_fkey(id, full_name, professional_email),
        recorded_by_user:app_users!staff_absence_records_recorded_by_fkey(id, full_name, email)
      `).eq('id', req.params.id).single();
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Absence record not found' });
      throw error;
    }
    res.json({ success: true, data: { ...data, recorded_by: data.recorded_by_user || null } });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch absence record', message: error.message });
  }
});

// FIX 2 + FIX 3: POST /api/absence-records
// - total_days now calculated and sent (NOT NULL constraint)
// - current_status now derived from dates and sent (NOT NULL constraint)  
// - recorded_by uses req.user.id with null fallback (FK safety)
app.post('/api/absence-records', authenticateToken, checkPermission('staff_absence', 'create'), validate(schemas.absenceRecord), async (req, res) => {
  try {
    const dataSource = req.validatedData || req.body;
    console.log('📝 Creating absence record:', dataSource);

    // FIX 1 applied: Joi.date() converts start/end to Date objects — use formatDate()
    const startDateStr = formatDate(dataSource.start_date);
    const endDateStr   = formatDate(dataSource.end_date);

    if (!startDateStr || !endDateStr) {
      return res.status(400).json({ error: 'Invalid date format', message: 'start_date and end_date must be valid dates' });
    }

    const startDate = new Date(startDateStr);
    const endDate   = new Date(endDateStr);

    if (endDate < startDate) {
      return res.status(400).json({ error: 'Invalid date range', message: 'End date must be after start date' });
    }

    // FIX 2: Calculate total_days (NOT NULL in DB)
    const totalDays = calculateDays(startDateStr, endDateStr);

    // FIX 2: Derive current_status from dates (NOT NULL in DB)
    const currentStatus = deriveAbsenceStatus(startDateStr, endDateStr);

    const absenceData = {
      staff_member_id:      dataSource.staff_member_id,
      absence_type:         dataSource.absence_type,
      absence_reason:       dataSource.absence_reason,
      start_date:           startDateStr,
      end_date:             endDateStr,
      total_days:           totalDays,
      current_status:       currentStatus,
      coverage_arranged:    dataSource.coverage_arranged || false,
      covering_staff_id:    dataSource.covering_staff_id || null,
      coverage_notes:       dataSource.coverage_notes || '',
      hod_notes:            dataSource.hod_notes || '',
      recorded_by:          req.user.id || null,
      recorded_at:          new Date().toISOString(),
      last_updated:         new Date().toISOString(),
      // Recurring fields
      is_recurring:         dataSource.is_recurring || false,
      recurrence_pattern:   dataSource.recurrence_pattern || null,
      recurrence_end_date:  dataSource.recurrence_end_date || null,
    };

    console.log('💾 Inserting absence record:', absenceData);

    const { data, error } = await supabase.from('staff_absence_records').insert([absenceData]).select().single();
    if (error) {
      console.error('❌ Database error:', error);
      if (error.code === '23503') return res.status(400).json({ error: 'Invalid reference', message: 'Staff member or recorded_by user not found.' });
      if (error.code === '23505') return res.status(409).json({ error: 'Duplicate entry', message: 'An absence record already exists for this staff member during this period' });
      throw error;
    }

    // Generate recurring instances in background
    if (absenceData.is_recurring && absenceData.recurrence_pattern && absenceData.recurrence_end_date) {
      setImmediate(async () => {
        try {
          const instances = [];
          let cursor = new Date(startDateStr);
          const recEnd = new Date(absenceData.recurrence_end_date);
          const durationDays = Math.round((new Date(endDateStr) - new Date(startDateStr)) / 86400000);

          const advance = (d) => {
            const next = new Date(d);
            if (absenceData.recurrence_pattern === 'weekly')    next.setDate(next.getDate() + 7);
            if (absenceData.recurrence_pattern === 'biweekly')  next.setDate(next.getDate() + 14);
            if (absenceData.recurrence_pattern === 'monthly')   next.setMonth(next.getMonth() + 1);
            return next;
          };

          cursor = advance(cursor); // skip original
          while (cursor <= recEnd) {
            const instanceEnd = new Date(cursor);
            instanceEnd.setDate(instanceEnd.getDate() + durationDays);
            const iStart = cursor.toISOString().split('T')[0];
            const iEnd   = instanceEnd.toISOString().split('T')[0];
            instances.push({
              ...absenceData,
              start_date: iStart,
              end_date: iEnd,
              total_days: calculateDays(iStart, iEnd),
              current_status: deriveAbsenceStatus(iStart, iEnd),
              is_recurring: true,
              recurrence_parent_id: data.id,
              recorded_at: new Date().toISOString(),
              last_updated: new Date().toISOString(),
            });
            cursor = advance(cursor);
          }
          if (instances.length > 0) {
            await supabase.from('staff_absence_records').insert(instances);
            console.log(`✅ Generated ${instances.length} recurring instances for absence ${data.id}`);
          }
        } catch (e) { console.warn('Recurring absence generation failed (non-fatal):', e.message); }
      });
    }

    console.log('✅ Absence record created:', data.id);
    // ── NOTIFICATION: Absence without coverage ──────────────────────
    if (!absenceData.coverage_arranged) {
      getPhysicianName(absenceData.staff_member_id).then(name => {
        const reason = (absenceData.absence_reason || 'absence').replace(/_/g,' ');
        sendNotification(
          `No coverage arranged — ${name}`,
          `<h2 style="margin:0 0 12px;color:#0a1628">Absence recorded without coverage</h2>
          <p style="color:#374151"><strong>${name}</strong> is absent (${reason}) 
          from <strong>${absenceData.start_date}</strong> to <strong>${absenceData.end_date}</strong>.</p>
          <p style="color:#ef4444;font-weight:600">⚠ No cover arranged — action required.</p>
          <a href="${APP_URL}" style="display:inline-block;margin-top:8px;padding:8px 16px;background:#00b3b3;color:#fff;text-decoration:none;border-radius:6px;font-size:13px">Open neumDesk →</a>`,
          true
        );
      });
    }
    res.status(201).json({ success: true, data, message: 'Absence record created successfully' });

    // Flag has_conflict on any oncall shifts that overlap this absence
    setImmediate(async () => {
      try {
        const { data: conflicts } = await supabase.from('oncall_schedule')
          .select('id')
          .gte('duty_date', startDateStr)
          .lte('duty_date', endDateStr)
          .or(`primary_physician_id.eq.${absenceData.staff_member_id},backup_physician_id.eq.${absenceData.staff_member_id}`);
        if (conflicts?.length) {
          const ids = conflicts.map(c => c.id);
          await supabase.from('oncall_schedule').update({ has_conflict: true }).in('id', ids);
        }
      } catch (e) { console.warn('Conflict flag update failed (non-fatal):', e.message); }
    });
  } catch (error) {
    console.error('💥 Failed to create absence record:', error);
    res.status(500).json({ error: 'Failed to create absence record', message: error.message });
  }
});

// FIX 9: PUT /api/absence-records/:id — recalculates total_days and current_status on update
app.put('/api/absence-records/:id', authenticateToken, checkPermission('staff_absence', 'update'), validate(schemas.absenceRecord), async (req, res) => {
  try {
    const dataSource = req.validatedData || req.body;

    const { data: currentRecord, error: fetchError } = await supabase.from('staff_absence_records').select('*').eq('id', req.params.id).single();
    if (fetchError) {
      if (fetchError.code === 'PGRST116') return res.status(404).json({ error: 'Absence record not found' });
      throw fetchError;
    }

    // FIX 1: formatDate handles Joi Date objects
    const startDateStr = formatDate(dataSource.start_date);
    const endDateStr   = formatDate(dataSource.end_date);

    // FIX 9: Recalculate total_days and current_status when dates may have changed
    const totalDays    = calculateDays(startDateStr, endDateStr);
    const currentStatus = deriveAbsenceStatus(startDateStr, endDateStr);

    const updateData = {
      staff_member_id:   dataSource.staff_member_id,
      absence_type:      dataSource.absence_type,
      absence_reason:    dataSource.absence_reason,
      start_date:        startDateStr,
      end_date:          endDateStr,
      total_days:        totalDays,       // FIX 9
      current_status:    currentStatus,   // FIX 9
      coverage_arranged: dataSource.coverage_arranged,
      covering_staff_id: dataSource.covering_staff_id || null,
      coverage_notes:    dataSource.coverage_notes || '',
      hod_notes:         dataSource.hod_notes || '',
      last_updated:      new Date().toISOString()
    };

    const { data, error } = await supabase.from('staff_absence_records').update(updateData).eq('id', req.params.id).select().single();
    if (error) throw error;

    // Audit changed fields
    const changedFields = [];
    const fieldsToCheck = ['staff_member_id','absence_type','absence_reason','start_date','end_date','coverage_arranged','covering_staff_id','coverage_notes','hod_notes'];
    for (const field of fieldsToCheck) {
      if (String(currentRecord[field] || '') !== String(dataSource[field] || '')) {
        changedFields.push({ absence_record_id: req.params.id, changed_field: field, old_value: String(currentRecord[field] || ''), new_value: String(dataSource[field] || ''), change_type: 'updated', changed_by: req.user.id || null, changed_at: new Date().toISOString() });
      }
    }
    if (changedFields.length > 0) {
      try { await supabase.from('absence_audit_log').insert(changedFields); } catch (e) { console.warn('Audit log failed:', e.message); }
    }

    res.json({ success: true, data, message: 'Absence record updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update absence record', message: error.message });
  }
});

app.put('/api/absence-records/:id/return', authenticateToken, checkPermission('staff_absence', 'update'), apiLimiter, async (req, res) => {
  try {
    const { return_date, notes } = req.body;
    const { data: currentRecord, error: fetchError } = await supabase.from('staff_absence_records').select('*').eq('id', req.params.id).single();
    if (fetchError) {
      if (fetchError.code === 'PGRST116') return res.status(404).json({ error: 'Absence record not found' });
      throw fetchError;
    }
    if (currentRecord.current_status === 'returned_to_duty') return res.status(400).json({ error: 'Already returned', message: 'Staff has already been marked as returned' });
    const effectiveReturnDate = return_date || formatDate(new Date());
    const returnNoteText = `[RETURNED EARLY: ${new Date().toISOString()}] ${notes || 'Staff returned early'}`;
    // FIX 9 applied: recalculate total_days for the new end date
    const newTotalDays = calculateDays(currentRecord.start_date, effectiveReturnDate);
    const { data, error } = await supabase.from('staff_absence_records').update({
      end_date: effectiveReturnDate,
      total_days: newTotalDays,
      current_status: 'returned_to_duty',
      hod_notes: currentRecord.hod_notes ? `${currentRecord.hod_notes}\n${returnNoteText}` : returnNoteText,
      last_updated: new Date().toISOString()
    }).eq('id', req.params.id).select().single();
    if (error) throw error;
    try {
      await supabase.from('absence_audit_log').insert({ absence_record_id: req.params.id, changed_field: 'current_status', old_value: currentRecord.current_status, new_value: 'returned_to_duty', change_type: 'status_changed', changed_by: req.user.id || null, changed_at: new Date().toISOString() });
    } catch (e) { console.warn('Audit log failed:', e.message); }
    res.json({ success: true, data, message: 'Staff marked as returned successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to mark staff as returned', message: error.message });
  }
});

app.delete('/api/absence-records/:id', authenticateToken, checkPermission('staff_absence', 'delete'), apiLimiter, async (req, res) => {
  try {
    const { data: record, error: fetchError } = await supabase.from('staff_absence_records').select('*').eq('id', req.params.id).single();
    if (fetchError) {
      if (fetchError.code === 'PGRST116') return res.status(404).json({ error: 'Absence record not found' });
      throw fetchError;
    }
    const cancelNote = `[CANCELLED: ${new Date().toISOString()}] Cancelled by ${req.user.full_name || req.user.email || 'system'}`;
    const { data, error } = await supabase.from('staff_absence_records').update({
      current_status: 'cancelled',
      hod_notes: record.hod_notes ? `${record.hod_notes}\n${cancelNote}` : cancelNote,
      last_updated: new Date().toISOString()
    }).eq('id', req.params.id).select().single();
    if (error) throw error;
    try {
      await supabase.from('absence_audit_log').insert({ absence_record_id: req.params.id, changed_field: 'current_status', old_value: record.current_status, new_value: 'cancelled', change_type: 'status_changed', changed_by: req.user.id || null, changed_at: new Date().toISOString() });
    } catch (e) { console.warn('Audit log failed:', e.message); }
    res.json({ success: true, data, message: 'Absence record cancelled successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to cancel absence record', message: error.message });
  }
});


// ── Absence hard-delete (purge) ──────────────────────────────────────────────
// Permanently removes the record + its audit log entries from the DB.
// Only system_admin / department_head. Used for table hygiene — NOT for audit cancellation.
app.delete('/api/absence-records/:id/purge', authenticateToken, checkPermission('staff_absence', 'delete'), apiLimiter, async (req, res) => {
  try {
    const allowedRoles = ['system_admin', 'department_head'];
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden', message: 'Only system administrators and department heads can permanently delete absence records' });
    }
    // Confirm record exists first
    const { data: record, error: fetchError } = await supabase.from('staff_absence_records').select('id, current_status').eq('id', req.params.id).single();
    if (fetchError) {
      if (fetchError.code === 'PGRST116') return res.status(404).json({ error: 'Not found', message: 'Absence record not found' });
      throw fetchError;
    }
    // Delete audit log entries first (FK constraint)
    const { error: auditError } = await supabase.from('absence_audit_log').delete().eq('absence_record_id', req.params.id);
    if (auditError) console.warn('Failed to purge audit log entries:', auditError.message);
    // Hard delete the record
    const { error } = await supabase.from('staff_absence_records').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true, message: 'Absence record permanently deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete absence record', message: error.message });
  }
});

app.get('/api/absence-records/:id/audit-log', authenticateToken, checkPermission('staff_absence', 'read'), apiLimiter, async (req, res) => {
  try {
    const { data, error } = await supabase.from('absence_audit_log').select(`*, changed_by_user:app_users!absence_audit_log_changed_by_fkey(id, full_name, email)`).eq('absence_record_id', req.params.id).order('changed_at', { ascending: false });
    if (error) throw error;
    res.json({ success: true, data: (data || []).map(item => ({ ...item, changed_by: item.changed_by_user || null })) });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch audit log', message: error.message });
  }
});

// ===== 11. ANNOUNCEMENTS =====
app.get('/api/announcements', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const today = formatDate(new Date());
    const { data, error } = await supabase.from('department_announcements').select('*')
      .lte('publish_start_date', today).or(`publish_end_date.gte.${today},publish_end_date.is.null`)
      .order('publish_start_date', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch announcements', message: error.message });
  }
});

app.post('/api/announcements', authenticateToken, checkPermission('communications', 'create'), validate(schemas.announcement), async (req, res) => {
  try {
    const dataSource = req.validatedData || req.body;
    const { data, error } = await supabase.from('department_announcements').insert([{
      title: dataSource.title, content: dataSource.content, type: 'announcement',
      priority_level: dataSource.priority_level || 'normal', target_audience: dataSource.target_audience || 'all_staff',
      visible_to_roles: ['system_admin', 'department_head', 'medical_resident'],
      publish_start_date: dataSource.publish_start_date ? formatDate(dataSource.publish_start_date) : formatDate(new Date()),
      publish_end_date: dataSource.publish_end_date ? formatDate(dataSource.publish_end_date) : null,
      created_by: req.user.id, created_by_name: req.user.full_name || 'System',
      created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
      announcement_id: generateId('ANN')
    }]).select().single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create announcement', message: error.message });
  }
});

app.put('/api/announcements/:id', authenticateToken, checkPermission('communications', 'update'), validate(schemas.announcement), async (req, res) => {
  try {
    const { data, error } = await supabase.from('department_announcements')
      .update({ ...(req.validatedData || req.body), updated_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Announcement not found' });
      throw error;
    }
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update announcement', message: error.message });
  }
});

app.delete('/api/announcements/:id', authenticateToken, checkPermission('communications', 'delete'), apiLimiter, async (req, res) => {
  try {
    const { error } = await supabase.from('department_announcements').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ message: 'Announcement deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete announcement', message: error.message });
  }
});

// ===== 12. LIVE STATUS =====
app.get('/api/live-status/current', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const today = new Date().toISOString();
    const { data, error } = await supabase.from('clinical_status_updates').select('*')
      .gt('expires_at', today).eq('is_active', true).order('created_at', { ascending: false }).limit(1).single();
    if (error) {
      if (error.code === 'PGRST116') return res.json({ success: true, data: null, message: 'No clinical status available' });
      throw error;
    }
    res.json({ success: true, data, message: 'Clinical status retrieved successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch clinical status', message: error.message });
  }
});

app.post('/api/live-status', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { status_text, author_id, expires_in_hours = 8 } = req.body;
    if (!status_text?.trim()) return res.status(400).json({ error: 'Validation failed', message: 'Status text is required' });
    if (!author_id) return res.status(400).json({ error: 'Validation failed', message: 'Author ID is required' });
    const { data: author, error: authorError } = await supabase.from('medical_staff').select('id, full_name, department_id').eq('id', author_id).single();
    if (authorError || !author) return res.status(400).json({ error: 'Invalid author', message: 'Selected author not found in medical staff' });
    const expiresAt = new Date(Date.now() + expires_in_hours * 60 * 60 * 1000);
    const { data, error } = await supabase.from('clinical_status_updates').insert([{
      status_text: status_text.trim(), author_id: author.id, author_name: author.full_name,
      department_id: author.department_id, created_at: new Date().toISOString(), expires_at: expiresAt.toISOString(), is_active: true
    }]).select().single();
    if (error) throw error;
    res.status(201).json({ success: true, data, message: 'Clinical status updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to save clinical status', message: error.message });
  }
});

app.get('/api/live-status/history', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { limit = 20, offset = 0 } = req.query;
    const parsedLimit = Math.min(parseInt(limit), 100);
    const parsedOffset = Math.max(0, parseInt(offset));
    const { data, error, count } = await supabase.from('clinical_status_updates').select('*', { count: 'exact' })
      .order('created_at', { ascending: false }).range(parsedOffset, parsedOffset + parsedLimit - 1);
    if (error) throw error;
    res.json({ success: true, data: data || [], pagination: { total: count || 0, limit: parsedLimit, offset: parsedOffset } });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch status history', message: error.message });
  }
});

app.put('/api/live-status/:id', authenticateToken, checkPermission('communications', 'update'), apiLimiter, async (req, res) => { // B7 FIX: added checkPermission — was accessible to all authenticated users
  try {
    const { status_text, expires_at, is_active } = req.body
    const updatePayload = { updated_at: new Date().toISOString() }
    if (status_text !== undefined) updatePayload.status_text = status_text
    if (expires_at  !== undefined) updatePayload.expires_at  = expires_at
    if (is_active   !== undefined) updatePayload.is_active   = is_active
    const { data, error } = await supabase.from('clinical_status_updates').update(updatePayload).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json({ success: true, data });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update clinical status', message: error.message });
  }
});

app.delete('/api/live-status/:id', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { error } = await supabase.from('clinical_status_updates').update({ is_active: false }).eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true, message: 'Clinical status cleared' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete clinical status', message: error.message });
  }
});

// ===== 13. LIVE UPDATES =====
app.get('/api/live-updates', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { data, error } = await supabase.from('live_updates').select('*').order('created_at', { ascending: false }).limit(20);
    if (error) {
      if (error.code === '42P01') return res.json({ success: true, data: [], message: 'No live updates available' });
      throw error;
    }
    res.json({ success: true, data: data || [] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch live updates', message: error.message });
  }
});

app.post('/api/live-updates', authenticateToken, checkPermission('communications', 'create'), apiLimiter, async (req, res) => {
  try {
    const { type, title, content, metrics, alerts, priority } = req.body;
    const updateData = { type: type || 'stats_update', title: title || 'Live Department Update', content, metrics: metrics || {}, alerts: alerts || {}, priority: priority || 'normal', author_id: req.user.id, created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
    const { data, error } = await supabase.from('live_updates').insert([updateData]).select().single();
    if (error) return res.json({ id: 'mock-' + Date.now(), ...updateData });
    res.status(201).json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create live update', message: error.message });
  }
});

// ===== 14. NOTIFICATIONS =====
// DB schema: id, user_id(FK→app_users), title, message, type, read(boolean), created_at
// Previous code used non-existent columns (recipient_id, is_read, read_at, recipient_role).
// Fixed to match actual DB columns.
app.get('/api/notifications/unread', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { count, error } = await supabase.from('notifications').select('*', { count: 'exact', head: true })
      .eq('user_id', req.user.id).eq('read', false);
    if (error) throw error;
    res.json({ unread_count: count || 0 });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch unread count', message: error.message });
  }
});

app.delete('/api/notifications/:id', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { error } = await supabase.from('notifications')
      .delete()
      .eq('id', req.params.id)
      .eq('user_id', req.user.id);
    if (error) throw error;
    res.json({ message: 'Notification deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete notification', message: error.message });
  }
});

app.post('/api/notifications', authenticateToken, checkPermission('communications', 'create'), async (req, res) => {
  try {
    const { title, message, type = 'info', user_id, recipient_role } = req.body;
    if (!title || !message) return res.status(400).json({ error: 'title and message are required' });
    let inserts = [];
    if (user_id) {
      inserts = [{ user_id, title, message, type, read: false, created_at: new Date().toISOString() }];
    } else if (recipient_role && recipient_role !== 'all') {
      const { data: users } = await supabase.from('app_users').select('id').eq('user_role', recipient_role).eq('account_status', 'active');
      inserts = (users || []).map(u => ({ user_id: u.id, title, message, type, read: false, created_at: new Date().toISOString() }));
    } else {
      const { data: users } = await supabase.from('app_users').select('id').eq('account_status', 'active');
      inserts = (users || []).map(u => ({ user_id: u.id, title, message, type, read: false, created_at: new Date().toISOString() }));
    }
    if (!inserts.length) return res.status(400).json({ error: 'No recipients found' });
    const { data, error } = await supabase.from('notifications').insert(inserts).select();
    if (error) throw error;
    res.status(201).json({ message: `Notification sent to ${inserts.length} recipient(s)`, data });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create notification', message: error.message });
  }
});

// ===== 15. AUDIT LOGS =====
app.get('/api/audit-logs', authenticateToken, checkPermission('audit_logs', 'read'), apiLimiter, async (req, res) => {
  try {
    const { page = 1, limit = 50, user_id, resource, start_date, end_date } = req.query;
    const offset = (page - 1) * limit;
    let query = supabase.from('audit_logs').select('*, user:app_users!audit_logs_user_id_fkey(full_name, email)', { count: 'exact' }).order('created_at', { ascending: false });
    if (user_id) query = query.eq('user_id', user_id);
    if (resource) query = query.eq('resource', resource);
    if (start_date) query = query.gte('created_at', start_date);
    if (end_date) query = query.lte('created_at', end_date);
    const { data, error, count } = await query.range(offset, offset + limit - 1);
    if (error) throw error;
    res.json({ data: data || [], pagination: { page: parseInt(page), limit: parseInt(limit), total: count || 0, totalPages: Math.ceil((count || 0) / limit) } });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch audit logs', message: error.message });
  }
});

// ===== 16. ATTACHMENTS =====
// Separate memory-storage multer instance for uploads that go straight to
// Supabase Storage (no local disk involved at all -- avoids the data-loss
// risk the disk-storage instance below has on Railway's ephemeral filesystem).
const uploadToMemory = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 }, // 8MB
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|webp|gif/;
    const ok = allowed.test(path.extname(file.originalname).toLowerCase()) && allowed.test(file.mimetype);
    if (ok) return cb(null, true);
    cb(new Error('Only JPEG, PNG, WEBP, or GIF images are allowed'));
  }
});

// POST /api/upload/news-image — uploads directly to the public news-images
// Supabase Storage bucket and returns the public URL. Used by the news post
// editor's image picker instead of requiring users to paste an external URL.
app.post('/api/upload/news-image', authenticateToken, checkPermission('news_posts', 'create'), uploadToMemory.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    const ext = path.extname(req.file.originalname).toLowerCase() || '.jpg';
    const fileName = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}${ext}`;

    const { error: uploadError } = await supabase.storage
      .from('news-images')
      .upload(fileName, req.file.buffer, { contentType: req.file.mimetype, cacheControl: '3600' });
    if (uploadError) throw uploadError;

    const { data: urlData } = supabase.storage.from('news-images').getPublicUrl(fileName);
    res.json({ success: true, url: urlData.publicUrl });
  } catch (e) {
    res.status(500).json({ error: 'Upload failed', message: e.message });
  }
});

// POST /api/upload/staff-photo — uploads a staff member's public profile
// photo directly to Supabase Storage and returns the public URL. Used by
// the medical staff edit modal's "Public Profile" tab instead of requiring
// a manually pasted URL.
app.post('/api/upload/staff-photo', authenticateToken, checkPermission('medical_staff', 'update'), uploadToMemory.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    const ext = path.extname(req.file.originalname).toLowerCase() || '.jpg';
    const fileName = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}${ext}`;

    const { error: uploadError } = await supabase.storage
      .from('staff-photos')
      .upload(fileName, req.file.buffer, { contentType: req.file.mimetype, cacheControl: '3600' });
    if (uploadError) throw uploadError;

    const { data: urlData } = supabase.storage.from('staff-photos').getPublicUrl(fileName);
    res.json({ success: true, url: urlData.publicUrl });
  } catch (e) {
    res.status(500).json({ error: 'Upload failed', message: e.message });
  }
});

app.post('/api/attachments/upload', authenticateToken, checkPermission('attachments', 'create'), upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    const { entity_type, entity_id, description } = req.body;
    const attachmentData = { filename: req.file.filename, original_filename: req.file.originalname, file_path: `/uploads/${req.file.filename}`, file_size: req.file.size, mime_type: req.file.mimetype, entity_type, entity_id, description: description || '', uploaded_by: req.user.id, uploaded_at: new Date().toISOString() };
    const { data, error } = await supabase.from('attachments').insert([attachmentData]).select().single();
    if (error) throw error;
    res.status(201).json({ message: 'File uploaded successfully', attachment: data });
  } catch (error) {
    res.status(500).json({ error: 'Failed to upload file', message: error.message });
  }
});

app.get('/api/attachments/entity/:entityType/:entityId', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { data, error } = await supabase.from('attachments').select('*').eq('entity_type', req.params.entityType).eq('entity_id', req.params.entityId).order('uploaded_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch attachments', message: error.message });
  }
});

app.delete('/api/attachments/:id', authenticateToken, checkPermission('attachments', 'delete'), apiLimiter, async (req, res) => {
  try {
    const { data: attachment, error: fetchError } = await supabase.from('attachments').select('file_path').eq('id', req.params.id).single();
    if (fetchError) throw fetchError;
    if (attachment.file_path) {
      const filePath = path.join(__dirname, attachment.file_path);
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    }
    const { error } = await supabase.from('attachments').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ message: 'Attachment deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete attachment', message: error.message });
  }
});

// ===== 17. DASHBOARD =====
app.get('/api/system-stats', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const today = formatDate(new Date());
    // FIX 8: Use staff_types table to find resident/attending keys dynamically
    const { data: staffTypes } = await supabase.from('staff_types').select('type_key, is_resident_type').eq('is_active', true);
    const residentKeys  = (staffTypes || []).filter(t =>  t.is_resident_type).map(t => t.type_key);
    const attendingKeys = (staffTypes || []).filter(t => !t.is_resident_type).map(t => t.type_key);
    const [totalStaff, activeAttending, activeResidents, todayOnCall, currentlyAbsent, activeRotations] = await Promise.all([
      supabase.from('medical_staff').select('*', { count: 'exact', head: true }),
      supabase.from('medical_staff').select('*', { count: 'exact', head: true }).in('staff_type', attendingKeys.length ? attendingKeys : ['__none__']).eq('employment_status', 'active'),
      supabase.from('medical_staff').select('*', { count: 'exact', head: true }).in('staff_type', residentKeys.length ? residentKeys : ['__none__']).eq('employment_status', 'active'),
      supabase.from('oncall_schedule').select('*', { count: 'exact', head: true }).eq('duty_date', today),
      supabase.from('staff_absence_records').select('*', { count: 'exact', head: true }).eq('current_status', 'currently_absent'),
      supabase.from('resident_rotations').select('*', { count: 'exact', head: true }).eq('rotation_status', 'active')
    ]);
    res.json({
      success: true,
      data: {
        totalStaff: totalStaff.count || 0, activeAttending: activeAttending.count || 0,
        activeResidents: activeResidents.count || 0, onCallNow: todayOnCall.count || 0,
        activeRotations: activeRotations.count || 0, currentlyAbsent: currentlyAbsent.count || 0,
        departmentStatus: 'normal', nextShiftChange: new Date(Date.now() + 6 * 60 * 60 * 1000).toISOString(),
        timestamp: new Date().toISOString()
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch system statistics', message: error.message });
  }
});

app.get('/api/dashboard/upcoming-events', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const today = formatDate(new Date());
    const nextWeek = formatDate(new Date(Date.now() + 7 * 24 * 60 * 60 * 1000));
    const [rotations, oncall, absences] = await Promise.all([
      supabase.from('resident_rotations').select('*, resident:medical_staff!resident_rotations_resident_id_fkey(full_name), training_unit:training_units!resident_rotations_training_unit_id_fkey(unit_name)').gte('start_date', today).lte('start_date', nextWeek).eq('rotation_status', 'scheduled').order('start_date').limit(5),
      supabase.from('oncall_schedule').select('*, primary_physician:medical_staff!oncall_schedule_primary_physician_id_fkey(full_name)').gte('duty_date', today).lte('duty_date', nextWeek).order('duty_date').limit(5),
      supabase.from('staff_absence_records').select('*, staff_member:medical_staff!staff_absence_records_staff_member_id_fkey(full_name)').eq('current_status', 'planned_leave').gte('start_date', today).lte('start_date', nextWeek).order('start_date').limit(5)
    ]);
    res.json({ upcoming_rotations: rotations.data || [], upcoming_oncall: oncall.data || [], upcoming_absences: absences.data || [] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch upcoming events', message: error.message });
  }
});

// ===== 18. SYSTEM SETTINGS =====
// ===== AUDIT LOG =====
app.get('/api/audit-log', authenticateToken, apiLimiter, async (req, res) => {
  try {
    // Only system_admin and department_head can read audit log
    if (!['system_admin','department_head'].includes(req.user.user_role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    const { table_name, record_id, limit = 50, page = 1 } = req.query;
    const offset = (page - 1) * limit;
    let query = supabase.from('audit_log')
      .select('*, changed_by_user:app_users!audit_log_changed_by_fkey(full_name, email)', { count: 'exact' })
      .order('changed_at', { ascending: false })
      .range(offset, offset + parseInt(limit) - 1);
    if (table_name) query = query.eq('table_name', table_name);
    if (record_id) query = query.eq('record_id', record_id);
    const { data, error, count } = await query;
    if (error) throw error;
    res.json({ data, pagination: { page: parseInt(page), limit: parseInt(limit), total: count || 0 } });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch audit log', message: err.message });
  }
});

app.get('/api/settings', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { data, error } = await supabase.from('system_settings').select('*').limit(1).single();
    if (error) return res.json({ hospital_name: 'NeumoCare Hospital', max_residents_per_unit: 10, default_rotation_duration: 12, enable_audit_logging: true, require_mfa: false, maintenance_mode: false, notifications_enabled: true, absence_notifications: true, announcement_notifications: true, is_default: true });
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch system settings', message: error.message });
  }
});

app.put('/api/settings', authenticateToken, checkPermission('system_settings', 'update'), validate(schemas.systemSettings), async (req, res) => {
  try {
    const payload = req.validatedData || req.body;
    // Fetch existing row to get its id (avoids upsert without onConflict creating duplicates)
    const { data: existing } = await supabase.from('system_settings').select('id').limit(1).single();
    let data, error;
    if (existing?.id) {
      ({ data, error } = await supabase.from('system_settings')
        .update({ ...payload, updated_at: new Date().toISOString() })
        .eq('id', existing.id).select().single());
    } else {
      ({ data, error } = await supabase.from('system_settings')
        .insert([{ ...payload, created_at: new Date().toISOString(), updated_at: new Date().toISOString() }])
        .select().single());
    }
    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update system settings', message: error.message });
  }
});

// ===== 19. SEARCH & AVAILABLE DATA =====
app.get('/api/available-data', authenticateToken, apiLimiter, async (req, res) => {
  try {
    // FIX 8: Replaced hardcoded 'medical_resident' / 'attending_physician' strings with
    // dynamic lookup from staff_types table so renamed types still work
    const [departments, staffTypes, allActiveStaff, trainingUnits] = await Promise.all([
      supabase.from('departments').select('id, name, code').eq('status', 'active').order('name'),
      supabase.from('staff_types').select('type_key, is_resident_type').eq('is_active', true),
      supabase.from('medical_staff').select('id, full_name, training_year, specialization, staff_type').eq('employment_status', 'active').order('full_name'),
      supabase.from('training_units').select('id, unit_name, unit_code, maximum_residents').eq('unit_status', 'active').order('unit_name')
    ]);
    const residentKeys = new Set((staffTypes.data || []).filter(t => t.is_resident_type).map(t => t.type_key));
    const attendingKeys = new Set((staffTypes.data || []).filter(t => !t.is_resident_type).map(t => t.type_key));
    const staff = allActiveStaff.data || [];
    const residents  = staff.filter(s => residentKeys.has(s.staff_type)).map(s => ({ id: s.id, full_name: s.full_name, training_year: s.training_year }));
    const attendings = staff.filter(s => attendingKeys.has(s.staff_type)).map(s => ({ id: s.id, full_name: s.full_name, specialization: s.specialization }));
    res.json({ success: true, data: { departments: departments.data || [], residents, attendings, trainingUnits: trainingUnits.data || [] } });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch available data', message: error.message });
  }
});

app.get('/api/search/medical-staff', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q || q.length < 2) return res.json([]);
    const { data, error } = await supabase.from('medical_staff').select('id, full_name, professional_email, staff_type, staff_id')
      .or(`full_name.ilike.%${q}%,staff_id.ilike.%${q}%,professional_email.ilike.%${q}%`).limit(10);
    if (error) throw error;
    res.json(data || []);
  } catch (error) {
    res.status(500).json({ error: 'Failed to search medical staff', message: error.message });
  }
});

// ===== 20. CALENDAR =====
app.get('/api/calendar/events', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { start_date, end_date } = req.query;
    if (!start_date || !end_date) return res.status(400).json({ error: 'Start date and end date are required' });
    const [rotations, oncall, absences] = await Promise.all([
      supabase.from('resident_rotations').select('id, start_date, end_date, rotation_status, resident:medical_staff!resident_rotations_resident_id_fkey(full_name), training_unit:training_units!resident_rotations_training_unit_id_fkey(unit_name)').gte('end_date', start_date).lte('start_date', end_date),
      supabase.from('oncall_schedule').select('id, duty_date, shift_type, primary_physician:medical_staff!oncall_schedule_primary_physician_id_fkey(full_name)').gte('duty_date', start_date).lte('duty_date', end_date),
      supabase.from('staff_absence_records').select('id, start_date, end_date, absence_reason, current_status, staff_member:medical_staff!staff_absence_records_staff_member_id_fkey(full_name)').gte('end_date', start_date).lte('start_date', end_date).not('current_status', 'eq', 'cancelled')
    ]);
    const events = [];
    (rotations.data || []).forEach(r => events.push({ id: r.id, title: `${r.resident?.full_name || 'Resident'} - ${r.training_unit?.unit_name || 'Unit'}`, start: r.start_date, end: r.end_date, type: 'rotation', status: r.rotation_status, color: r.rotation_status === 'active' ? 'blue' : 'gray' }));
    (oncall.data || []).forEach(s => events.push({ id: s.id, title: `On-call: ${s.primary_physician?.full_name || 'Physician'}`, start: s.duty_date, end: s.duty_date, type: 'oncall', shift_type: s.shift_type, color: s.shift_type === 'primary_call' ? 'red' : 'yellow' }));
    (absences.data || []).forEach(a => events.push({ id: a.id, title: `${a.staff_member?.full_name || 'Staff'} - ${a.absence_reason}`, start: a.start_date, end: a.end_date, type: 'absence', color: a.current_status === 'currently_absent' ? 'red' : 'green' }));
    res.json(events);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch calendar events', message: error.message });
  }
});

// ===== 21. RESEARCH LINES =====
app.get('/api/research-lines', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { data: viewData, error: viewError } = await supabase.from('research_lines_with_coordinators').select('*').order('sort_order');
    if (!viewError && viewData) {
      return res.json({ success: true, data: viewData.map(line => ({ id: line.id, line_number: line.line_number, research_line_name: line.name, short_name: line.short_name, description: line.description, capabilities: line.capabilities, sort_order: line.sort_order, active: line.active, coordinator_id: line.coordinator_id, coordinator_name: line.full_name, coordinator_email: line.professional_email, coordinator_type: line.staff_type })) });
    }
    const { data, error } = await supabase.from('research_lines').select('*').order('sort_order');
    if (error) throw error;
    res.json({ success: true, data: data.map(line => ({ id: line.id, line_number: line.line_number, research_line_name: line.name, short_name: line.short_name, description: line.description, capabilities: line.capabilities, sort_order: line.sort_order, active: line.active, coordinator_id: line.coordinator_id, coordinator_name: null })) });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ── PUBLIC (no auth) — website-facing research lines ──────────────────────────
// Used by the public website to render the research lines grid/accordion.
// Returns only active lines with coordinator name. No sensitive fields exposed.
// ================================================================
// PUBLIC WEBSITE: TEAM
// GET /api/team/website — staff marked is_public = true
// No authentication required — publicApiLimiter only
// ================================================================
app.get('/api/team/website', publicApiLimiterGuarded, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('medical_staff')
      .select(`
        id, full_name, title, staff_type, specialization,
        public_bio, public_photo_url, is_public, affiliation_type, primary_dept_name, can_be_pi,
        is_chief_of_department,
        orcid_id, scholar_url, researchgate_url, pubmed_query,
        department:departments!medical_staff_department_id_fkey(name, is_primary, is_external),
        research_lines:research_lines!research_lines_coordinator_id_fkey(
          id, line_number, name, short_name,
          clinical_trials(id, status, title, phase, featured_in_website),
          innovation_projects(id, current_stage, funding_status, title)
        )
      `)
      .eq('employment_status', 'active')
      .order('full_name', { ascending: true });

    if (error) throw error;

    // Get latest publication per person from news_posts authors_text
    // (lightweight join — authors_text contains full_name substrings)
    const { data: recentPubs } = await supabase
      .from('news_posts')
      .select('id, title, journal_name, published_at, doi, authors_text, author_id')
      .eq('status', 'published')
      .eq('post_type', 'publication')
      .not('journal_name', 'is', null)
      .order('published_at', { ascending: false })
      .limit(50);

    const team = (data || []).map(m => {
      const displayName = m.title ? `${m.title} ${m.full_name}` : m.full_name;
      const line = m.research_lines?.[0] || null;

      // Trials for this line
      const lineTrials = (line?.clinical_trials || []).filter(t => t.featured_in_website);
      const activeTrials = lineTrials.filter(t =>
        ['Reclutando','Activo','Active','Recruiting'].includes(t.status)
      );
      const recruitingTrials = lineTrials.filter(t =>
        ['Reclutando','Recruiting'].includes(t.status)
      );

      // Projects for this line
      const lineProjects = line?.innovation_projects || [];
      const activeProjects = lineProjects.filter(p => p.current_stage !== 'completed');
      const seekingProjects = lineProjects.filter(p => p.funding_status === 'seeking');

      // Latest publication where this person is named as author
      const personPubs = (recentPubs || []).filter(p =>
        p.author_id === m.id ||
        (p.authors_text && m.full_name && p.authors_text.toLowerCase().includes(m.full_name.toLowerCase().split(' ').slice(-1)[0]))
      );
      const latestPub = personPubs[0] || null;
      const recentPubsForPerson = personPubs.slice(0, 3).map(p => ({
        title: p.title, journal: p.journal_name,
        year: p.published_at ? new Date(p.published_at).getFullYear() : null,
        doi: p.doi || null,
      }));

      // Collaboration status
      let collabStatus = null;
      if (recruitingTrials.length > 0) collabStatus = 'recruiting';
      else if (seekingProjects.length > 0) collabStatus = 'seeking_partner';
      else if (activeTrials.length > 0) collabStatus = 'active';

      return {
        id:               m.id,
        full_name:        m.full_name,
        display_name:     displayName,
        title:            m.title || null,
        staff_type:       m.staff_type,
        specialization:   m.specialization || null,
        public_bio:       m.public_bio || null,
        public_photo_url: m.is_public ? (m.public_photo_url || null) : null,
        affiliation_type: m.affiliation_type || 'primary',
        primary_dept_name: m.primary_dept_name || m.department?.name || null,
        is_external:      m.department?.is_external || false,
        can_be_pi:        m.can_be_pi || false,
        is_chief_of_department: m.is_chief_of_department || false,
        coordinates_line: line ? {
          id:           line.id,
          line_number:  line.line_number,
          name:         line.name,
          short_name:   line.short_name || line.name,
        } : null,
        // Live contextual data — counts only, not full lists
        active_trials:    activeTrials.length,
        recruiting_trials: recruitingTrials.length,
        active_projects:  activeProjects.length,
        seeking_partner:  seekingProjects.length > 0,
        latest_pub:       latestPub ? {
          title:        latestPub.title,
          journal:      latestPub.journal_name,
          year:         latestPub.published_at ? new Date(latestPub.published_at).getFullYear() : null,
          doi:          latestPub.doi || null,
        } : null,
        recent_pubs:       recentPubsForPerson,
        publication_count: personPubs.length,
        collab_status:    collabStatus,
      };
    });

    res.json({ data: team, meta: { total: team.length } });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch team', message: error.message });
  }
});

app.get('/api/research-lines/website', publicApiLimiterGuarded, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('research_lines')
      .select(`
        id, line_number, name, short_name, description, capabilities, keywords, sort_order,
        coordinator:medical_staff!research_lines_coordinator_id_fkey(
          id, full_name, specialization, public_bio, public_photo_url, is_public
        ),
        clinical_trials(id, status, featured_in_website),
        innovation_projects(id, current_stage)
      `)
      .eq('active', true)
      .eq('is_public', true)
      .order('sort_order');
    if (error) throw error;
    const lines = (data || []).map(l => ({
      id:           l.id,
      line_number:  l.line_number,
      name:         l.name,
      short_name:   l.short_name || l.name,
      description:  l.description,
      capabilities: l.capabilities,
      keywords:     l.keywords,
      coordinator:  l.coordinator ? { ...l.coordinator, public_photo_url: l.coordinator.is_public ? l.coordinator.public_photo_url : null } : null,
      active_trials:  (l.clinical_trials || []).filter(t => t.featured_in_website && ['Reclutando','Activo','Active','Recruiting'].includes(t.status)).length,
      total_trials:   (l.clinical_trials || []).filter(t => t.featured_in_website).length,
      active_projects:(l.innovation_projects || []).filter(p => p.current_stage !== 'completed').length,
    }));
    res.json({ data: lines, meta: { total: lines.length } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET /api/research-lines/:id/website — single-line detail for line.html.
// Returns deep_content (long-form page text, may be null if not yet
// written), full coordinator profile, and a derived team list built from
// trial/project investigator fields — there's no dedicated team-membership
// table, so "who works on this line" is inferred from who's named as PI,
// co-investigator, or sub-investigator on that line's public trials/projects.
// Trial/project lists themselves are NOT duplicated here — the frontend
// calls the existing /api/clinical-trials/website?line=:id and
// /api/innovation-projects/website?line=:id endpoints for those, same as
// clinical.html and innovation.html already do, so there's one source of
// truth for trial/project data rather than two.
app.get('/api/research-lines/:id/website', publicApiLimiterGuarded, async (req, res) => {
  try {
    const { id } = req.params;

    const { data: line, error: lineError } = await supabase
      .from('research_lines')
      .select(`
        id, line_number, name, short_name, description, capabilities, keywords, deep_content, deep_content_updated_at, track_record,
        coordinator:medical_staff!research_lines_coordinator_id_fkey(
          id, full_name, title, specialization, public_bio, public_photo_url, is_public,
          can_be_pi, is_chief_of_department
        )
      `)
      .eq('id', id)
      .eq('active', true)
      .eq('is_public', true)
      .maybeSingle();
    if (lineError) throw lineError;
    if (!line) return res.status(404).json({ error: 'Research line not found' });

    // Pull investigator ids off this line's trials and projects to build
    // the team list. Plus explicit memberships from research_line_members,
    // which covers staff whose involvement isn't captured by being named
    // PI/co-investigator on a trial — e.g. engineers, coordinators, data
    // staff supporting the line directly.
    const [{ data: trials }, { data: projects }, { data: explicitMembers }] = await Promise.all([
      supabase.from('clinical_trials')
        .select('id, title, protocol_id, principal_investigator_id, co_investigators, sub_investigators, status')
        .eq('research_line_id', id)
        .eq('featured_in_website', true),
      supabase.from('innovation_projects')
        .select('lead_investigator_id, co_investigators, current_stage')
        .eq('research_line_id', id)
        .eq('featured_in_website', true),
      supabase.from('research_line_members')
        .select('staff_id, role_on_line, sort_order')
        .eq('research_line_id', id)
        .order('sort_order'),
    ]);

    const teamIds = new Set();
    if (line.coordinator?.id) teamIds.add(line.coordinator.id);
    (trials || []).forEach(t => {
      if (t.principal_investigator_id) teamIds.add(t.principal_investigator_id);
      (t.co_investigators || []).forEach(i => i && teamIds.add(i));
      (t.sub_investigators || []).forEach(i => i && teamIds.add(i));
    });
    (projects || []).forEach(p => {
      if (p.lead_investigator_id) teamIds.add(p.lead_investigator_id);
      (p.co_investigators || []).forEach(i => i && teamIds.add(i));
    });
    const roleByStaffId = {};
    (explicitMembers || []).forEach(m => {
      if (m.staff_id) {
        teamIds.add(m.staff_id);
        roleByStaffId[m.staff_id] = m.role_on_line;
      }
    });
    teamIds.delete(null);
    teamIds.delete(undefined);

    let team = [];
    if (teamIds.size) {
      const { data: staff } = await supabase
        .from('medical_staff')
        .select('id, full_name, title, specialization, public_bio, public_photo_url, is_public, can_be_pi, is_chief_of_department')
        .in('id', Array.from(teamIds));
      team = (staff || []).map(s => ({
        ...s,
        public_photo_url: s.is_public ? s.public_photo_url : null,
        role_on_line: roleByStaffId[s.id] || null,
      }));
    }

    const activeTrialCount = (trials || []).filter(t => ['Reclutando','Activo','Active','Recruiting'].includes(t.status)).length;
    const activeProjectCount = (projects || []).filter(p => p.current_stage !== 'completed').length;

    res.json({
      data: {
        id:            line.id,
        line_number:   line.line_number,
        name:          line.name,
        short_name:    line.short_name || line.name,
        description:   line.description,
        capabilities:  line.capabilities,
        keywords:      line.keywords,
        track_record:  line.track_record || [],
        deep_content:  line.deep_content || null,
        deep_content_updated_at: line.deep_content_updated_at || null,
        coordinator:   line.coordinator ? { ...line.coordinator, public_photo_url: line.coordinator.is_public ? line.coordinator.public_photo_url : null } : null,
        team,
        trials_list:   (trials || []).map(t => ({ id: t.id, title: t.title, protocol_id: t.protocol_id })),
        active_trials:   activeTrialCount,
        total_trials:    (trials || []).length,
        active_projects: activeProjectCount,
        total_projects:  (projects || []).length,
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/research-lines', authenticateToken, checkPermission('research_lines', 'create'), validate(schemas.researchLine), async (req, res) => {
  try {
    // Accept both 'name' (DB field) and 'research_line_name' (frontend form field)
    const { line_number, description, capabilities, sort_order, active, keywords } = req.body;
    const name = req.body.name || req.body.research_line_name;
    if (!name) return res.status(400).json({ error: 'Research line name is required' });
    const { data, error } = await supabase.from('research_lines').insert([{ line_number: line_number || null, name, description: description || '', capabilities: (capabilities !== undefined && capabilities !== null) ? capabilities : 'Alcance y capacidades', sort_order: sort_order || 0, active: active !== undefined ? active : true, keywords: Array.isArray(keywords) ? keywords : [], created_at: new Date().toISOString(), updated_at: new Date().toISOString() }]).select().single();
    if (error) throw error;
    res.status(201).json({ success: true, data, message: 'Research line created successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/research-lines/:id', authenticateToken, checkPermission('research_lines', 'update'), validate(schemas.researchLine), async (req, res) => {
  try {
    // B6 FIX: Whitelist updatable fields — do not pass req.body directly to prevent
    // clients from overwriting id, created_at, line_number (unique) or injecting garbage fields
    const { description, capabilities, sort_order, active, keywords, coordinator_id } = req.body;
    const name = req.body.name || req.body.research_line_name;
    const updatePayload = { updated_at: new Date().toISOString() };
    if (name !== undefined)           updatePayload.name           = name;
    if (description !== undefined)    updatePayload.description    = description;
    if (capabilities !== undefined)   updatePayload.capabilities   = capabilities;
    if (sort_order !== undefined)     updatePayload.sort_order     = sort_order;
    if (active !== undefined)         updatePayload.active         = active;
    if (keywords !== undefined)       updatePayload.keywords       = Array.isArray(keywords) ? keywords : [];
    if (coordinator_id !== undefined) updatePayload.coordinator_id = coordinator_id || null;
    const { data, error } = await supabase.from('research_lines').update(updatePayload).eq('id', req.params.id).select().single();
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Research line not found' });
      throw error;
    }
    res.json({ success: true, data, message: 'Research line updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/research-lines/:id', authenticateToken, checkPermission('research_lines', 'delete'), async (req, res) => {
  try {
    const { permanent } = req.query;
    if (permanent === 'true') {
      const { error } = await supabase.from('research_lines').delete().eq('id', req.params.id);
      if (error) throw error;
      return res.json({ success: true, message: 'Research line permanently deleted' });
    }
    const { data, error } = await supabase.from('research_lines').update({ active: false, updated_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json({ success: true, data, message: 'Research line deactivated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/research-lines/:id/coordinator', authenticateToken, checkPermission('research_lines', 'update'), async (req, res) => {
  try {
    const { coordinator_id } = req.body;
    if (coordinator_id) {
      const { data: staff, error: staffError } = await supabase.from('medical_staff').select('id, full_name').eq('id', coordinator_id).single();
      if (staffError || !staff) return res.status(400).json({ error: 'Invalid coordinator', message: 'Selected coordinator not found' });
    }
    const { data, error } = await supabase.from('research_lines').update({ coordinator_id: coordinator_id || null, updated_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json({ success: true, data, message: coordinator_id ? 'Coordinator assigned successfully' : 'Coordinator removed successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== 22. CLINICAL STUDIES =====
app.get('/api/clinical-trials/website', publicApiLimiterGuarded, async (req, res) => {
  try {
    const { line, phase, status, search } = req.query;
    let query = supabase.from('clinical_trials')
      .select('*, research_line:research_lines(name, short_name, line_number), clinical_trial_lines(research_line_id, research_lines(id, line_number, name, short_name))')
      .eq('featured_in_website', true).order('display_order');
    if (line && line !== 'All Lines') {
      // A trial matches if this line is its primary line OR one of its
      // additional lines (clinical_trial_lines) — a trial can span more
      // than one line, so filtering by primary alone would silently hide
      // it from a line that genuinely includes it.
      const { data: viaJoin } = await supabase.from('clinical_trial_lines').select('clinical_trial_id').eq('research_line_id', line);
      const additionalIds = (viaJoin || []).map(r => r.clinical_trial_id);
      if (additionalIds.length) {
        query = query.or(`research_line_id.eq.${line},id.in.(${additionalIds.join(',')})`);
      } else {
        query = query.eq('research_line_id', line);
      }
    }
    if (phase && phase !== 'All Phases') query = query.eq('phase', phase);
    if (status && status !== 'All Status') query = query.eq('status', status);
    if (search) query = query.or(`title.ilike.%${search}%,protocol_id.ilike.%${search}%`);
    const { data, error } = await query.limit(50);
    if (error) throw error;
    const normalized = (data || []).map(t => {
      const { clinical_trial_lines, ...rest } = t;
      return { ...rest, additional_lines: (clinical_trial_lines || []).map(r => r.research_lines).filter(Boolean) };
    });
    res.json({ data: normalized, meta: { total: normalized.length } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/clinical-trials', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { research_line_id, phase, status, page = 1, limit = 50 } = req.query;
    const offset = (page - 1) * limit;
    let query = supabase.from('clinical_trials').select(`
      *, research_lines(name, line_number),
      pi:medical_staff!clinical_trials_principal_investigator_id_fkey(id, full_name, professional_email),
      dm:medical_staff!clinical_trials_data_manager_id_fkey(id, full_name),
      clinical_trial_lines(research_line_id, research_lines(id, line_number, name, short_name))
    `, { count: 'exact' });
    if (research_line_id) query = query.eq('research_line_id', research_line_id);
    if (phase) query = query.eq('phase', phase);
    if (status) query = query.eq('status', status);
    const { data, error, count } = await query.order('display_order').order('created_at', { ascending: false }).range(offset, offset + limit - 1);
    if (error) throw error;
    const normalized = (data || []).map(t => {
      const { clinical_trial_lines, ...rest } = t;
      return { ...rest, additional_lines: (clinical_trial_lines || []).map(r => r.research_lines).filter(Boolean) };
    });
    res.json({ success: true, data: normalized, pagination: { page: parseInt(page), limit: parseInt(limit), total: count || 0, totalPages: Math.ceil((count || 0) / limit) } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/clinical-trials', authenticateToken, checkPermission('research_lines', 'create'), validate(schemas.clinicalTrial), async (req, res) => {
  try {
    const body = { ...req.body };
    const VALID_PHASES = ['Phase I','Phase II','Phase III','Phase IV'];
    if (!VALID_PHASES.includes(body.phase)) body.phase = 'Phase I';
    if (!body.protocol_id) body.protocol_id = `PROT-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2,6).toUpperCase()}`;
    // Ensure array fields are arrays
    body.target_diseases  = Array.isArray(body.target_diseases)  ? body.target_diseases  : [];
    body.tags             = Array.isArray(body.tags)             ? body.tags             : [];
    body.co_investigators = Array.isArray(body.co_investigators) ? body.co_investigators : [];
    body.sub_investigators= Array.isArray(body.sub_investigators)? body.sub_investigators: [];
    body.milestones       = Array.isArray(body.milestones)       ? body.milestones       : [];
    body.external_team    = Array.isArray(body.external_team)    ? body.external_team.map(m => ({ name: m.name?.trim()||null, institution: m.institution?.trim()||null, role: m.role?.trim()||null, email: m.email?.trim()||null })).filter(m=>m.name||m.institution) : [];
    body.team_roles       = (typeof body.team_roles === 'object' && !Array.isArray(body.team_roles)) ? body.team_roles : {};
    body.data_manager_id  = body.data_manager_id || null;
    // Scope: if general, scope_note required; if specific, clear scope_note
    if (body.scope_type === 'general' && !body.scope_note) body.scope_note = null;
    if (body.scope_type === 'specific') body.scope_note = null;
    const { additional_line_ids, ...trialBody } = body;
    const { data, error } = await supabase.from('clinical_trials')
      .insert([{ ...trialBody, created_at: new Date().toISOString(), updated_at: new Date().toISOString() }])
      .select('*, research_lines(name, line_number), pi:medical_staff!clinical_trials_principal_investigator_id_fkey(id, full_name)').single();
    if (error) throw error;

    if (Array.isArray(additional_line_ids) && additional_line_ids.length) {
      const rows = additional_line_ids
        .filter(lid => lid && lid !== data.research_line_id)
        .map(lid => ({ clinical_trial_id: data.id, research_line_id: lid }));
      if (rows.length) await supabase.from('clinical_trial_lines').insert(rows);
    }

    res.status(201).json({ success: true, data, message: 'Clinical study created successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/clinical-trials/:id', authenticateToken, checkPermission('research_lines', 'update'), validate(schemas.clinicalTrial), async (req, res) => {
  try {
    const VALID_PHASES = ['Phase I','Phase II','Phase III','Phase IV'];
    const VALID_STATUSES = ['Reclutando','Activo','Completado','En preparación','Suspendido'];
    const VALID_ETHICS = ['pending','approved','exempt','not_required'];
    const VALID_FUNDING = ['not_applicable','seeking','funded','completed'];
    const VALID_SCOPE = ['specific','general'];
    const VALID_POPULATION = ['adult','paediatric','mixed','not_applicable'];
    const b = req.body;
    const updatePayload = {
      updated_at: new Date().toISOString(),
      ...(b.title                       !== undefined && { title: b.title }),
      ...(b.research_line_id            !== undefined && { research_line_id: b.research_line_id || null }),
      ...(b.phase                       !== undefined && { phase: VALID_PHASES.includes(b.phase) ? b.phase : 'Phase I' }),
      ...(b.status                      !== undefined && VALID_STATUSES.includes(b.status) && { status: b.status }),
      ...(b.description                 !== undefined && { description: b.description }),
      ...(b.inclusion_criteria          !== undefined && { inclusion_criteria: b.inclusion_criteria }),
      ...(b.exclusion_criteria          !== undefined && { exclusion_criteria: b.exclusion_criteria }),
      ...(b.principal_investigator_id   !== undefined && { principal_investigator_id: b.principal_investigator_id || null }),
      ...(b.co_investigators            !== undefined && { co_investigators: Array.isArray(b.co_investigators) ? b.co_investigators : [] }),
      ...(b.sub_investigators           !== undefined && { sub_investigators: Array.isArray(b.sub_investigators) ? b.sub_investigators : [] }),
      ...(b.contact_email               !== undefined && { contact_email: b.contact_email }),
      ...(b.featured_in_website         !== undefined && { featured_in_website: b.featured_in_website }),
      ...(b.display_order               !== undefined && { display_order: b.display_order }),
      ...(b.start_date                  !== undefined && { start_date: b.start_date || null }),
      ...(b.end_date                    !== undefined && { end_date: b.end_date || null }),
      ...(b.estimated_end_date          !== undefined && { estimated_end_date: b.estimated_end_date || null }),
      ...(b.actual_end_date             !== undefined && { actual_end_date: b.actual_end_date || null }),
      ...(b.sponsor_name                !== undefined && { sponsor_name: b.sponsor_name }),
      ...(b.sponsor_type                !== undefined && { sponsor_type: b.sponsor_type }),
      ...(b.study_type                  !== undefined && { study_type: b.study_type }),
      ...(b.enrollment_target           !== undefined && { enrollment_target: b.enrollment_target || null }),
      ...(b.actual_enrollment           !== undefined && { actual_enrollment: b.actual_enrollment || null }),
      ...(b.funding_amount              !== undefined && { funding_amount: b.funding_amount || null }),
      ...(b.tags                        !== undefined && { tags: Array.isArray(b.tags) ? b.tags : [] }),
      ...(b.milestones                  !== undefined && { milestones: Array.isArray(b.milestones) ? b.milestones : [] }),
      // New fields
      ...(b.protocol_finalized          !== undefined && { protocol_finalized: Boolean(b.protocol_finalized) }),
      ...(b.ethics_status               !== undefined && { ethics_status: VALID_ETHICS.includes(b.ethics_status) ? b.ethics_status : null }),
      ...(b.funding_status              !== undefined && { funding_status: VALID_FUNDING.includes(b.funding_status) ? b.funding_status : 'not_applicable' }),
      ...(b.target_diseases             !== undefined && { target_diseases: Array.isArray(b.target_diseases) ? b.target_diseases : [] }),
      ...(b.scope_type                  !== undefined && { scope_type: VALID_SCOPE.includes(b.scope_type) ? b.scope_type : 'specific' }),
      ...(b.scope_note                  !== undefined && { scope_note: b.scope_note ? b.scope_note.slice(0, 150) : null }),
      ...(b.is_multicentre              !== undefined && { is_multicentre: Boolean(b.is_multicentre) }),
      ...(b.participating_centres       !== undefined && { participating_centres: b.participating_centres || null }),
      ...(b.population_type             !== undefined && { population_type: VALID_POPULATION.includes(b.population_type) ? b.population_type : 'adult' }),
      // Team fields
      ...(b.data_manager_id             !== undefined && { data_manager_id: b.data_manager_id || null }),
      ...(b.team_roles                  !== undefined && { team_roles: (typeof b.team_roles === 'object' && !Array.isArray(b.team_roles)) ? b.team_roles : {} }),
      ...(b.external_team               !== undefined && { external_team: Array.isArray(b.external_team) ? b.external_team.map(m => ({
        name:        m.name?.trim()        || null,
        institution: m.institution?.trim() || null,
        role:        m.role?.trim()        || null,
        email:       m.email?.trim()       || null,
      })).filter(m => m.name || m.institution) : [] }),
    };
    // If scope changed to specific, clear scope_note
    if (updatePayload.scope_type === 'specific') updatePayload.scope_note = null;
    const { data, error } = await supabase.from('clinical_trials').update(updatePayload).eq('id', req.params.id)
      .select(`*, research_lines(name, line_number),
        pi:medical_staff!clinical_trials_principal_investigator_id_fkey(id, full_name),
        dm:medical_staff!clinical_trials_data_manager_id_fkey(id, full_name)
      `).single();
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Clinical trial not found' });
      throw error;
    }

    // Additional lines this trial spans, beyond its primary research_line_id.
    // Frontend sends the full desired set each save; sync by replacing.
    if (Array.isArray(b.additional_line_ids)) {
      await supabase.from('clinical_trial_lines').delete().eq('clinical_trial_id', req.params.id);
      const rows = b.additional_line_ids
        .filter(lid => lid && lid !== data.research_line_id)
        .map(lid => ({ clinical_trial_id: req.params.id, research_line_id: lid }));
      if (rows.length) await supabase.from('clinical_trial_lines').insert(rows);
    }
    const { data: additionalLines } = await supabase
      .from('clinical_trial_lines')
      .select('research_line_id, research_lines(id, line_number, name, short_name)')
      .eq('clinical_trial_id', req.params.id);
    data.additional_lines = (additionalLines || []).map(r => r.research_lines).filter(Boolean);

    res.json({ success: true, data, message: 'Clinical study updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/clinical-trials/:id', authenticateToken, checkPermission('research_lines', 'delete'), async (req, res) => {
  try {
    const { error } = await supabase.from('clinical_trials').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true, message: 'Clinical trial deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== 23. INNOVATION PROJECTS =====
app.get('/api/innovation-projects/website', publicApiLimiterGuarded, async (req, res) => {
  try {
    const { line } = req.query;
    let query = supabase.from('innovation_projects')
      .select('*, research_line:research_lines(name), innovation_project_lines(research_line_id, research_lines(id, line_number, name, short_name))')
      .eq('featured_in_website', true).order('display_order');
    if (line) {
      const { data: viaJoin } = await supabase.from('innovation_project_lines').select('innovation_project_id').eq('research_line_id', line);
      const additionalIds = (viaJoin || []).map(r => r.innovation_project_id);
      if (additionalIds.length) {
        query = query.or(`research_line_id.eq.${line},id.in.(${additionalIds.join(',')})`);
      } else {
        query = query.eq('research_line_id', line);
      }
    }
    const { data, error } = await query;
    if (error) throw error;
    const normalized = (data || []).map(p => {
      const { innovation_project_lines, ...rest } = p;
      return { ...rest, additional_lines: (innovation_project_lines || []).map(r => r.research_lines).filter(Boolean) };
    });
    res.json({ data: normalized, meta: { total: normalized.length } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/innovation-projects', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { research_line_id, category, stage, page = 1, limit = 50 } = req.query;
    const offset = (page - 1) * limit;
    let query = supabase.from('innovation_projects').select(`
      *, research_lines(name, line_number),
      lead:medical_staff!innovation_projects_lead_investigator_id_fkey(id, full_name),
      innovation_project_lines(research_line_id, research_lines(id, line_number, name, short_name))
    `, { count: 'exact' });
    if (research_line_id) query = query.eq('research_line_id', research_line_id);
    if (category) query = query.eq('category', category);
    if (stage) query = query.eq('current_stage', stage);
    const { data, error, count } = await query.order('display_order').order('created_at', { ascending: false }).range(offset, offset + limit - 1);
    if (error) throw error;
    const normalized = (data || []).map(p => {
      const { innovation_project_lines, ...rest } = p;
      return { ...rest, additional_lines: (innovation_project_lines || []).map(r => r.research_lines).filter(Boolean) };
    });
    res.json({ success: true, data: normalized, pagination: { page: parseInt(page), limit: parseInt(limit), total: count || 0, totalPages: Math.ceil((count || 0) / limit) } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/innovation-projects', authenticateToken, checkPermission('research_lines', 'create'), validate(schemas.innovationProject), async (req, res) => {
  try {
    const body = { ...req.body };

    // current_stage now uses English values — drop old Spanish mapping
    if (!body.current_stage) body.current_stage = 'development';
    // Keep development_stage in sync for backward compat (Spanish UI fallback)
    const STAGE_MAP_EN = { concept:'Fase Piloto', development:'En Desarrollo', pilot:'Fase Piloto', validation:'Validación', scaling:'Validación', completed:'Validación' };
    body.development_stage = STAGE_MAP_EN[body.current_stage] || 'En Desarrollo';

    // New fields
    body.project_url    = body.project_url    || null;
    body.repo_url       = body.repo_url       || null;
    body.demo_url       = body.demo_url       || null;
    body.project_nature = body.project_nature || 'clinical_innovation';
    body.is_featured    = body.is_featured    || false;

    // Array fields
    body.target_diseases  = Array.isArray(body.target_diseases)  ? body.target_diseases  : [];
    body.keywords         = Array.isArray(body.keywords)         ? body.keywords         : [];
    body.co_investigators = Array.isArray(body.co_investigators) ? body.co_investigators : [];
    body.partner_needs    = Array.isArray(body.partner_needs)    ? body.partner_needs    : [];
    body.tags             = Array.isArray(body.tags)             ? body.tags             : [];
    body.milestones       = Array.isArray(body.milestones)       ? body.milestones       : [];
    body.external_team    = Array.isArray(body.external_team)    ? body.external_team.map(m => ({ name: m.name?.trim()||null, institution: m.institution?.trim()||null, role: m.role?.trim()||null, email: m.email?.trim()||null })).filter(m=>m.name||m.institution) : [];
    body.team_roles       = (typeof body.team_roles === 'object' && !Array.isArray(body.team_roles)) ? body.team_roles : {};
    if (body.scope_type === 'specific') body.scope_note = null;
    if (body.scope_note) body.scope_note = body.scope_note.slice(0, 150);

    const { additional_line_ids, ...projectBody } = body;
    const { data, error } = await supabase.from('innovation_projects')
      .insert([{ ...projectBody, created_at: new Date().toISOString(), updated_at: new Date().toISOString() }])
      .select('*, research_lines(name, line_number), lead:medical_staff!innovation_projects_lead_investigator_id_fkey(id, full_name)').single();
    if (error) throw error;

    if (Array.isArray(additional_line_ids) && additional_line_ids.length) {
      const rows = additional_line_ids
        .filter(lid => lid && lid !== data.research_line_id)
        .map(lid => ({ innovation_project_id: data.id, research_line_id: lid }));
      if (rows.length) await supabase.from('innovation_project_lines').insert(rows);
    }

    res.status(201).json({ data, message: 'Innovation project created successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/innovation-projects/:id', authenticateToken, checkPermission('research_lines', 'update'), validate(schemas.innovationProject), async (req, res) => {
  try {
    const VALID_STAGES = ['Idea','Prototipo','Piloto','Validación','Escalamiento','Comercialización'];
    const VALID_FUNDING = ['not_applicable','seeking','funded','completed'];
    const VALID_SCOPE = ['specific','general'];
    const VALID_POPULATION = ['adult','paediatric','mixed','not_applicable'];
    const VALID_REGULATORY = ['none','ce_mdr','samd','aemps','fda','other'];
    const STAGE_MAP = {'Idea':'En Desarrollo','Prototipo':'En Desarrollo','Piloto':'Fase Piloto','Validación':'Validación Clínica','Escalamiento':'Validación Clínica','Comercialización':'Validación Clínica'};
    const b = req.body;
    const updatePayload = {
      updated_at: new Date().toISOString(),
      ...(b.title               !== undefined && { title: b.title }),
      ...(b.category            !== undefined && { category: b.category }),
      ...(b.current_stage !== undefined && VALID_STAGES.includes(b.current_stage) && {
        current_stage: b.current_stage,
        development_stage: STAGE_MAP[b.current_stage] || 'En Desarrollo'
      }),
      ...(b.description         !== undefined && { description: b.description }),
      ...(b.clinical_rationale  !== undefined && { clinical_rationale: b.clinical_rationale }),
      ...(b.research_line_id    !== undefined && { research_line_id: b.research_line_id || null }),
      ...(b.lead_investigator_id!== undefined && { lead_investigator_id: b.lead_investigator_id || null }),
      ...(b.co_investigators    !== undefined && { co_investigators: Array.isArray(b.co_investigators) ? b.co_investigators : [] }),
      ...(b.partner_needs       !== undefined && { partner_needs: Array.isArray(b.partner_needs) ? b.partner_needs : [] }),
      ...(b.partner_found       !== undefined && { partner_found: Boolean(b.partner_found) }),
      ...(b.partner_name        !== undefined && { partner_name: b.partner_name || null }),
      ...(b.funding_status      !== undefined && { funding_status: VALID_FUNDING.includes(b.funding_status) ? b.funding_status : 'not_applicable' }),
      ...(b.funding_source      !== undefined && { funding_source: b.funding_source || null }),
      ...(b.budget              !== undefined && { budget: b.budget || null }),
      ...(b.trl_level           !== undefined && { trl_level: b.trl_level || null }),
      ...(b.ip_status           !== undefined && { ip_status: b.ip_status || null }),
      ...(b.keywords            !== undefined && { keywords: Array.isArray(b.keywords) ? b.keywords : [] }),
      ...(b.tags                !== undefined && { tags: Array.isArray(b.tags) ? b.tags : [] }),
      ...(b.milestones          !== undefined && { milestones: Array.isArray(b.milestones) ? b.milestones : [] }),
      ...(b.featured_in_website !== undefined && { featured_in_website: b.featured_in_website }),
      ...(b.is_featured         !== undefined && { is_featured: Boolean(b.is_featured) }),
      ...(b.display_order       !== undefined && { display_order: b.display_order }),
      ...(b.start_date          !== undefined && { start_date: b.start_date || null }),
      ...(b.estimated_end_date  !== undefined && { estimated_end_date: b.estimated_end_date || null }),
      // New fields
      ...(b.scope_finalized     !== undefined && { scope_finalized: Boolean(b.scope_finalized) }),
      ...(b.target_diseases     !== undefined && { target_diseases: Array.isArray(b.target_diseases) ? b.target_diseases : [] }),
      ...(b.scope_type          !== undefined && { scope_type: VALID_SCOPE.includes(b.scope_type) ? b.scope_type : 'specific' }),
      ...(b.scope_note          !== undefined && { scope_note: b.scope_note ? b.scope_note.slice(0, 150) : null }),
      ...(b.regulatory_pathway  !== undefined && { regulatory_pathway: VALID_REGULATORY.includes(b.regulatory_pathway) ? b.regulatory_pathway : 'none' }),
      ...(b.population_type     !== undefined && { population_type: VALID_POPULATION.includes(b.population_type) ? b.population_type : 'adult' }),
      // Team fields
      ...(b.team_roles          !== undefined && { team_roles: (typeof b.team_roles === 'object' && !Array.isArray(b.team_roles)) ? b.team_roles : {} }),
      ...(b.external_team       !== undefined && { external_team: Array.isArray(b.external_team) ? b.external_team.map(m => ({
        name:        m.name?.trim()        || null,
        institution: m.institution?.trim() || null,
        role:        m.role?.trim()        || null,
        email:       m.email?.trim()       || null,
      })).filter(m => m.name || m.institution) : [] }),
    };
    if (updatePayload.scope_type === 'specific') updatePayload.scope_note = null;
    const { data, error } = await supabase.from('innovation_projects').update(updatePayload).eq('id', req.params.id)
      .select('*, research_lines(name, line_number), lead:medical_staff!innovation_projects_lead_investigator_id_fkey(id, full_name)').single();
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Innovation project not found' });
      throw error;
    }

    if (Array.isArray(b.additional_line_ids)) {
      await supabase.from('innovation_project_lines').delete().eq('innovation_project_id', req.params.id);
      const rows = b.additional_line_ids
        .filter(lid => lid && lid !== data.research_line_id)
        .map(lid => ({ innovation_project_id: req.params.id, research_line_id: lid }));
      if (rows.length) await supabase.from('innovation_project_lines').insert(rows);
    }
    const { data: additionalLines } = await supabase
      .from('innovation_project_lines')
      .select('research_line_id, research_lines(id, line_number, name, short_name)')
      .eq('innovation_project_id', req.params.id);
    data.additional_lines = (additionalLines || []).map(r => r.research_lines).filter(Boolean);

    res.json({ success: true, data, message: 'Innovation project updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/innovation-projects/:id', authenticateToken, checkPermission('research_lines', 'delete'), async (req, res) => {
  try {
    const { error } = await supabase.from('innovation_projects').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true, message: 'Innovation project deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== 24. ANALYTICS =====
app.get('/api/analytics/research-dashboard', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const [{ data: researchLines }, { data: trials }, { data: projects }] = await Promise.all([
      supabase.from('research_lines').select('id, line_number, name, active, coordinator_id'),
      supabase.from('clinical_trials').select('id, protocol_id, title, phase, status, research_line_id, research_line:research_lines(name)'),
      supabase.from('innovation_projects').select('id, title, category, current_stage, research_line_id, partner_needs, research_line:research_lines(name)')
    ]);
    const trialsByPhase = { 'Phase I': 0, 'Phase II': 0, 'Phase III': 0, 'Phase IV': 0 };
    const trialsByStatus = { 'Reclutando': 0, 'Activo': 0, 'Completado': 0, 'En preparación': 0 };
    const projectsByStage = { 'Idea': 0, 'Prototipo': 0, 'Piloto': 0, 'Validación': 0, 'Escalamiento': 0, 'Comercialización': 0 };
    const projectsByCategory = { 'Dispositivo': 0, 'Salud Digital': 0, 'IA / ML': 0, 'Tecnología Quirúrgica': 0 };
    const partnerNeeds = {};
    // Map legacy development_stage values → current_stage keys
    const DEV_STAGE_MAP = { 'En Desarrollo': 'Prototipo', 'Fase Piloto': 'Piloto', 'Validación Clínica': 'Validación' };
    trials?.forEach(t => { if (trialsByPhase[t.phase] !== undefined) trialsByPhase[t.phase]++; if (trialsByStatus[t.status] !== undefined) trialsByStatus[t.status]++; });
    projects?.forEach(p => {
      const stage = p.current_stage || DEV_STAGE_MAP[p.development_stage] || null;
      if (stage && projectsByStage[stage] !== undefined) projectsByStage[stage]++;
      if (projectsByCategory[p.category] !== undefined) projectsByCategory[p.category]++;
      p.partner_needs?.forEach(n => { partnerNeeds[n] = (partnerNeeds[n] || 0) + 1; });
    });
    const activeTrialsCount = (trialsByStatus['Activo'] || 0) + (trialsByStatus['Reclutando'] || 0);
    const activeProjectsCount = (projectsByStage['Piloto'] || 0) + (projectsByStage['Validación'] || 0) + (projectsByStage['Escalamiento'] || 0) + (projectsByStage['Comercialización'] || 0);
    res.json({ success: true, data: { summary: { totalResearchLines: researchLines?.length || 0, activeResearchLines: researchLines?.filter(l => l.active !== false).length || 0, totalTrials: trials?.length || 0, totalStudies: trials?.length || 0, activeTrials: activeTrialsCount, activeStudies: activeTrialsCount, totalProjects: projects?.length || 0, activeProjects: activeProjectsCount }, clinicalTrials: { byPhase: trialsByPhase, byStatus: trialsByStatus }, innovationProjects: { byStage: projectsByStage, byCategory: projectsByCategory, partnerNeeds: Object.entries(partnerNeeds).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count) } } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/analytics/research-lines-performance', authenticateToken, apiLimiter, async (req, res) => {
  try {
    // B8 FIX: Was N+1 — one query per research line for trials, projects, and coordinator.
    // Now fetches everything in 3 bulk queries and groups in memory.
    const [
      { data: researchLines },
      { data: allTrials },
      { data: allProjects },
      { data: allStaff }
    ] = await Promise.all([
      supabase.from('research_lines').select('id, line_number, name, coordinator_id, active'),
      supabase.from('clinical_trials').select('id, phase, status, research_line_id'),
      supabase.from('innovation_projects').select('id, category, current_stage, development_stage, research_line_id'),
      supabase.from('medical_staff').select('id, full_name')
    ]);

    const staffMap = Object.fromEntries((allStaff || []).map(s => [s.id, s.full_name]));
    const ACTIVE_PROJECT_STAGES = ['Prototipo', 'Piloto', 'Validación', 'Escalamiento'];
    const COMMERCIALIZED_STAGES = ['Comercialización'];
    const projectStage = (p) => p.current_stage || p.development_stage || '';

    const performance = (researchLines || []).map(line => {
      const trials   = (allTrials   || []).filter(t => t.research_line_id === line.id);
      const projects = (allProjects || []).filter(p => p.research_line_id === line.id);
      return {
        id: line.id, line_number: line.line_number, name: line.name, active: line.active,
        coordinator: line.coordinator_id ? (staffMap[line.coordinator_id] || null) : null,
        stats: {
          totalTrials:      trials.length,
          activeTrials:     trials.filter(t => ['Activo','Reclutando'].includes(t.status)).length,
          completedTrials:  trials.filter(t => t.status === 'Completado').length,
          totalProjects:    projects.length,
          activeProjects:   projects.filter(p => ACTIVE_PROJECT_STAGES.includes(projectStage(p))).length,
          commercialized:   projects.filter(p => COMMERCIALIZED_STAGES.includes(projectStage(p))).length
        }
      };
    });

    performance.sort((a, b) => (a.line_number || 999) - (b.line_number || 999));
    res.json({ success: true, data: performance });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/analytics/partner-collaborations', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { data: projects } = await supabase.from('innovation_projects').select('id, title, category, partner_needs, research_line_id, research_line:research_lines(name)');
    const partnerNeeds = {};
    projects?.forEach(p => { p.partner_needs?.forEach(n => { partnerNeeds[n] = (partnerNeeds[n] || 0) + 1; }); });
    res.json({ success: true, data: { totalProjectsWithPartners: projects?.filter(p => p.partner_needs?.length > 0).length || 0, totalPartnerNeeds: Object.values(partnerNeeds).reduce((a, b) => a + b, 0), uniquePartnerNeeds: Object.keys(partnerNeeds).length, partnerNeeds: Object.entries(partnerNeeds).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count) } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/analytics/clinical-trials-timeline', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { years = 3 } = req.query;
    const { data: trials } = await supabase.from('clinical_trials').select('id, protocol_id, title, phase, status, created_at');
    const startDate = new Date();
    startDate.setFullYear(startDate.getFullYear() - parseInt(years));
    const monthlyData = {};
    trials?.forEach(t => {
      const created = new Date(t.created_at);
      if (created >= startDate) {
        const monthKey = `${created.getFullYear()}-${String(created.getMonth() + 1).padStart(2, '0')}`;
        monthlyData[monthKey] = (monthlyData[monthKey] || 0) + 1;
      }
    });
    res.json({ success: true, data: { timeline: Object.entries(monthlyData).map(([month, count]) => ({ month, count })).sort((a, b) => a.month.localeCompare(b.month)), totalInPeriod: trials?.filter(t => new Date(t.created_at) >= startDate).length || 0 } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/analytics/summary', authenticateToken, checkPermission('research_lines', 'read'), apiLimiter, async (req, res) => {
  try {
    const [{ count: totalRL }, { count: totalTrials }, { count: activeTrials }, { count: totalProj }, { count: activeProj }] = await Promise.all([
      supabase.from('research_lines').select('*', { count: 'exact', head: true }),
      supabase.from('clinical_trials').select('*', { count: 'exact', head: true }),
      supabase.from('clinical_trials').select('*', { count: 'exact', head: true }).in('status', ['Activo','Reclutando']),
      supabase.from('innovation_projects').select('*', { count: 'exact', head: true }),
      supabase.from('innovation_projects').select('*', { count: 'exact', head: true }).in('current_stage', ['Piloto','Validación','Escalamiento','Comercialización'])
    ]);
    res.json({ success: true, data: { researchLines: totalRL || 0, clinicalTrials: { total: totalTrials || 0, active: activeTrials || 0 }, innovationProjects: { total: totalProj || 0, active: activeProj || 0 } } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/analytics/export/:type', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { type } = req.params;
    const { format = 'csv' } = req.query;
    let data = [], filename = '';
    switch (type) {
      case 'clinical-trials': { const { data: d } = await supabase.from('clinical_trials').select('protocol_id, title, phase, status, created_at').order('created_at', { ascending: false }); data = d || []; filename = 'clinical-trials-report'; break; }
      case 'innovation-projects': { const { data: d } = await supabase.from('innovation_projects').select('title, category, current_stage, created_at').order('created_at', { ascending: false }); data = d || []; filename = 'innovation-projects-report'; break; }
      case 'research-lines': { const { data: d } = await supabase.from('research_lines').select('line_number, name, description, active, created_at').order('line_number'); data = d || []; filename = 'research-lines-report'; break; }
      default: return res.status(400).json({ error: 'Invalid export type' });
    }
    if (!data.length) return res.status(404).json({ error: 'No data to export' });
    const headers = Object.keys(data[0]).join(',');
    const rows = data.map(item => Object.values(item).map(v => typeof v === 'string' ? `"${v.replace(/"/g, '""')}"` : v).join(','));
    const csv = [headers, ...rows].join('\n');
    res.header('Content-Type', 'text/csv');
    res.header('Content-Disposition', `attachment; filename=${filename}-${formatDate(new Date())}.csv`);
    res.send(csv);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ===== 25. HOSPITALS =====
// network_type stored in parent_complex: 'CHUAC' | 'SERGAS' | 'external'
// CHUAC ⊂ SERGAS. External = private/national/international outside SERGAS.
app.get('/api/hospitals', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { network_type, is_active } = req.query;
    let query = supabase.from('hospitals').select('*').order('name');
    if (network_type) query = query.eq('parent_complex', network_type);
    if (is_active !== undefined) query = query.eq('is_active', is_active === 'true');
    const { data, error } = await query;
    if (error) throw error;
    res.json({ success: true, data: data || [] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch hospitals', message: error.message });
  }
});

app.get('/api/hospitals/:id', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { data, error } = await supabase.from('hospitals').select('*').eq('id', req.params.id).single();
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Hospital not found' });
      throw error;
    }
    res.json({ success: true, data });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch hospital', message: error.message });
  }
});

// Any authenticated user can register a new hospital (inline from staff form)
app.post('/api/hospitals', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { name, code, city, region = 'Galicia', address, type, network_type, parent_complex } = req.body;
    if (!name) return res.status(400).json({ error: 'Hospital name is required' });
    const resolvedComplex = parent_complex || network_type || 'external';
    const autoCode = code || (name.toUpperCase().replace(/[^A-Z0-9]/g, '').substring(0, 8) + '-' + Date.now().toString(36).toUpperCase());
    const { data, error } = await supabase.from('hospitals').insert([{
      name, code: autoCode, city: city || null, region,
      address: address || null, type: type || null,
      parent_complex: resolvedComplex,
      is_active: true,
      created_at: new Date().toISOString(), updated_at: new Date().toISOString()
    }]).select().single();
    if (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'A hospital with this code already exists' });
      throw error;
    }
    res.status(201).json({ success: true, data, message: 'Hospital created successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create hospital', message: error.message });
  }
});

app.put('/api/hospitals/:id', authenticateToken, checkPermission('departments', 'update'), async (req, res) => {
  try {
    const { name, code, city, region, address, type, parent_complex, is_active } = req.body;
    const { data, error } = await supabase.from('hospitals')
      .update({ name, code, city, region, address, type, parent_complex, is_active, updated_at: new Date().toISOString() })
      .eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json({ success: true, data });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update hospital', message: error.message });
  }
});

// ===== 26. CLINICAL UNITS =====
// /api/clinical-units → redirected to training_units (merged tables)
app.get('/api/clinical-units', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { department_id, status } = req.query;
    let query = supabase.from('training_units')
      .select('*, departments!training_units_department_id_fkey(name, code)')
      .order('unit_name');
    if (department_id) query = query.eq('department_id', department_id);
    if (status) query = query.eq('unit_status', status);
    else query = query.neq('unit_status', 'inactive');
    const { data, error } = await query;
    if (error) throw error;
    // Return in clinical_units shape for backwards compatibility
    res.json({ success: true, data: (data || []).map(u => ({
      id: u.id, name: u.unit_name, code: u.unit_code,
      department_id: u.department_id, unit_type: u.unit_type || 'training_unit',
      status: u.unit_status, description: u.unit_description,
      supervisor_id: u.supervisor_id,
      department: u.departments ? { name: u.departments.name, code: u.departments.code } : null
    }))});
  } catch (error) {
    res.json({ success: true, data: [], message: 'No units found' });
  }
});

app.get('/api/clinical-units/:id', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { data, error } = await supabase.from('clinical_units')
      .select('*, departments!clinical_units_department_id_fkey(name, code)')
      .eq('id', req.params.id).single();
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Clinical unit not found' });
      throw error;
    }
    res.json({ success: true, data });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch clinical unit', message: error.message });
  }
});

app.post('/api/clinical-units', authenticateToken, checkPermission('departments', 'create'), async (req, res) => {
  try {
    const { name, code, department_id, unit_type = 'clinical', description, supervisor_id } = req.body;
    if (!name || !code) return res.status(400).json({ error: 'name and code are required' });
    const { data, error } = await supabase.from('clinical_units').insert([{
      name, code, department_id: department_id || null,
      unit_type, status: 'active', description: description || null,
      supervisor_id: supervisor_id || null,
      created_at: new Date().toISOString(), updated_at: new Date().toISOString()
    }]).select().single();
    if (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'A clinical unit with this code already exists' });
      throw error;
    }
    res.status(201).json({ success: true, data, message: 'Clinical unit created successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create clinical unit', message: error.message });
  }
});

app.put('/api/clinical-units/:id', authenticateToken, checkPermission('departments', 'update'), async (req, res) => {
  try {
    const { data, error } = await supabase.from('clinical_units')
      .update({ ...req.body, updated_at: new Date().toISOString() })
      .eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json({ success: true, data });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update clinical unit', message: error.message });
  }
});

app.delete('/api/clinical-units/:id', authenticateToken, checkPermission('departments', 'delete'), async (req, res) => {
  try {
    const { data, error } = await supabase.from('clinical_units')
      .update({ status: 'inactive', updated_at: new Date().toISOString() })
      .eq('id', req.params.id).select('name').single();
    if (error) throw error;
    res.json({ success: true, message: `Clinical unit "${data.name}" deactivated` });
  } catch (error) {
    res.status(500).json({ error: 'Failed to deactivate clinical unit', message: error.message });
  }
});

app.get('/api/clinical-units/:id/staff', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { data, error } = await supabase.from('clinical_unit_assignments')
      .select('*, staff:medical_staff!clinical_unit_assignments_staff_id_fkey(id, full_name, professional_email, staff_type, employment_status)')
      .eq('clinical_unit_id', req.params.id).eq('status', 'active').order('created_at');
    if (error) throw error;
    res.json({ success: true, data: data || [] });
  } catch (error) {
    res.json({ success: true, data: [] });
  }
});

app.post('/api/clinical-units/:id/staff', authenticateToken, checkPermission('departments', 'update'), async (req, res) => {
  try {
    const { staff_id, assignment_type = 'attending', start_date } = req.body;
    if (!staff_id) return res.status(400).json({ error: 'staff_id is required' });
    const { data, error } = await supabase.from('clinical_unit_assignments').insert([{
      clinical_unit_id: req.params.id, staff_id,
      assignment_type, start_date: start_date || formatDate(new Date()),
      status: 'active',
      created_at: new Date().toISOString(), updated_at: new Date().toISOString()
    }]).select().single();
    if (error) throw error;
    res.status(201).json({ success: true, data });
  } catch (error) {
    res.status(500).json({ error: 'Failed to assign staff to clinical unit', message: error.message });
  }
});

app.delete('/api/clinical-units/:unitId/staff/:assignmentId', authenticateToken, checkPermission('departments', 'update'), async (req, res) => {
  try {
    const { error } = await supabase.from('clinical_unit_assignments')
      .update({ status: 'inactive', end_date: formatDate(new Date()), updated_at: new Date().toISOString() })
      .eq('id', req.params.assignmentId);
    if (error) throw error;
    res.json({ success: true, message: 'Staff removed from clinical unit' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to remove staff from clinical unit', message: error.message });
  }
});

// ===== 27. PARTNERS (Research) =====
app.get('/api/partners', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { type, search } = req.query;
    let query = supabase.from('partners').select('*').order('name');
    if (type) query = query.eq('type', type);
    if (search) query = query.ilike('name', `%${search}%`);
    const { data, error } = await query;
    if (error) throw error;
    res.json({ success: true, data: data || [] });
  } catch (error) {
    res.json({ success: true, data: [] });
  }
});
// POST /api/contact — PUBLIC, no auth required
app.post('/api/contact', apiLimiter, async (req, res) => {
  try {
    const { name, organisation, email, area_of_interest, message } = req.body;
    if (!name || !email) {
      return res.status(400).json({ error: 'Name and email are required' });
    }
    const { error } = await supabase
      .from('contact_submissions')
      .insert([{ name, organisation, email, area_of_interest, message }]);
    if (error) throw error;
    res.json({ success: true, message: 'Message received' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
app.post('/api/partners', authenticateToken, checkPermission('research_lines', 'create'), async (req, res) => {
  try {
    const { name, type, website, main_contact_name, main_contact_email, main_contact_phone, address, logo_url } = req.body;
    if (!name) return res.status(400).json({ error: 'Partner name is required' });
    const { data, error } = await supabase.from('partners').insert([{
      name, type: type || null, website: website || null,
      main_contact_name: main_contact_name || null,
      main_contact_email: main_contact_email || null,
      main_contact_phone: main_contact_phone || null,
      address: address || null, logo_url: logo_url || null,
      created_at: new Date().toISOString(), updated_at: new Date().toISOString()
    }]).select().single();
    if (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'A partner with this name already exists' });
      throw error;
    }
    res.status(201).json({ success: true, data, message: 'Partner created successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create partner', message: error.message });
  }
});

app.put('/api/partners/:id', authenticateToken, checkPermission('research_lines', 'update'), async (req, res) => {
  try {
    const { data, error } = await supabase.from('partners')
      .update({ ...req.body, updated_at: new Date().toISOString() })
      .eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json({ success: true, data });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update partner', message: error.message });
  }
});

app.delete('/api/partners/:id', authenticateToken, checkPermission('research_lines', 'delete'), async (req, res) => {
  try {
    const { error } = await supabase.from('partners').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true, message: 'Partner deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete partner', message: error.message });
  }
});

app.get('/api/partner-needs', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { data, error } = await supabase.from('partner_needs').select('*').order('need_name');
    if (error) throw error;
    res.json({ success: true, data: data || [] });
  } catch (error) {
    res.json({ success: true, data: [] });
  }
});

app.post('/api/partner-needs', authenticateToken, checkPermission('research_lines', 'create'), async (req, res) => {
  try {
    const { need_name, category } = req.body;
    if (!need_name) return res.status(400).json({ error: 'need_name is required' });
    const { data, error } = await supabase.from('partner_needs').insert([{
      need_name, category: category || null, created_at: new Date().toISOString()
    }]).select().single();
    if (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'This partner need already exists' });
      throw error;
    }
    res.status(201).json({ success: true, data });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create partner need', message: error.message });
  }
});

app.get('/api/innovation-projects/:id/partners', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { data, error } = await supabase.from('project_partners')
      .select('*, partner:partners!project_partners_partner_id_fkey(*)')
      .eq('project_id', req.params.id);
    if (error) throw error;
    res.json({ success: true, data: data || [] });
  } catch (error) {
    res.json({ success: true, data: [] });
  }
});

app.post('/api/innovation-projects/:id/partners', authenticateToken, checkPermission('research_lines', 'update'), async (req, res) => {
  try {
    const { partner_id, role } = req.body;
    if (!partner_id) return res.status(400).json({ error: 'partner_id is required' });
    const { data, error } = await supabase.from('project_partners').insert([{
      project_id: req.params.id, partner_id, role: role || null, created_at: new Date().toISOString()
    }]).select().single();
    if (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'This partner is already linked to this project' });
      throw error;
    }
    res.status(201).json({ success: true, data });
  } catch (error) {
    res.status(500).json({ error: 'Failed to link partner to project', message: error.message });
  }
});

app.delete('/api/innovation-projects/:projectId/partners/:partnerId', authenticateToken, checkPermission('research_lines', 'update'), async (req, res) => {
  try {
    const { error } = await supabase.from('project_partners')
      .delete().eq('project_id', req.params.projectId).eq('partner_id', req.params.partnerId);
    if (error) throw error;
    res.json({ success: true, message: 'Partner unlinked from project' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to unlink partner', message: error.message });
  }
});


// ============================================================================
// ========================== ROTATION SERVICES ================================
// ============================================================================
// Wraps the departments table filtered by service_type.
// 'home_department' = Neumología (read-only, not shown in rotation services list)
// 'rotation_service' = external services residents rotate through
// 'external_institution' = fully external institutions

app.get('/api/rotation-services', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { include_home } = req.query
    let query = supabase.from('departments')
      .select('id, name, code, service_type, contact_name, contact_email, contact_phone, status')
      .order('name')
    if (include_home !== 'true') {
      query = query.eq('service_type', 'rotation_service')
    } else {
      query = query.in('service_type', ['rotation_service', 'home_department'])
    }
    const { data, error } = await query
    if (error) throw error
    res.json({ success: true, data: data || [] })
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch rotation services', message: err.message })
  }
})

app.post('/api/rotation-services', authenticateToken, checkPermission('system_settings', 'create'), validate(schemas.rotationService), async (req, res) => {
  try {
    const { name, service_type, contact_name, contact_email, contact_phone } = req.body
    if (!name?.trim()) return res.status(400).json({ error: 'Name is required' })
    const code = name.trim().toUpperCase().replace(/[^A-Z0-9]/g, '-').replace(/-+/g, '-').slice(0, 20)
    const { data, error } = await supabase.from('departments').insert([{
      name: name.trim(),
      code: `${code}-${Date.now().toString(36).slice(-4).toUpperCase()}`,
      service_type: service_type || 'rotation_service',
      contact_name: contact_name || null,
      contact_email: contact_email || null,
      contact_phone: contact_phone || null,
      status: 'active',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    }]).select().single()
    if (error) throw error
    res.status(201).json({ success: true, data })
  } catch (err) {
    res.status(500).json({ error: 'Failed to create rotation service', message: err.message })
  }
})

app.put('/api/rotation-services/:id', authenticateToken, checkPermission('system_settings', 'update'), async (req, res) => {
  try {
    const { name, contact_name, contact_email, contact_phone, active } = req.body
    const updates = { updated_at: new Date().toISOString() }
    if (name         !== undefined) updates.name          = name.trim()
    if (contact_name !== undefined) updates.contact_name  = contact_name || null
    if (contact_email!== undefined) updates.contact_email = contact_email || null
    if (contact_phone!== undefined) updates.contact_phone = contact_phone || null
    if (active       !== undefined) updates.status        = active ? 'active' : 'inactive'
    const { data, error } = await supabase.from('departments')
      .update(updates)
      .eq('id', req.params.id)
      .eq('service_type', 'rotation_service')
      .select().single()
    if (error) throw error
    if (!data) return res.status(404).json({ error: 'Rotation service not found' })
    res.json({ success: true, data })
  } catch (err) {
    res.status(500).json({ error: 'Failed to update rotation service', message: err.message })
  }
})

app.delete('/api/rotation-services/:id', authenticateToken, checkPermission('system_settings', 'delete'), async (req, res) => {
  try {
    // Check if any medical_staff references this service
    const { count } = await supabase.from('medical_staff')
      .select('*', { count: 'exact', head: true })
      .eq('home_department_id', req.params.id)
    if (count > 0) {
      // Soft delete — deactivate so existing staff records remain valid
      const { data, error } = await supabase.from('departments')
        .update({ status: 'inactive', updated_at: new Date().toISOString() })
        .eq('id', req.params.id).neq('service_type', 'home_department').select().single()
      if (error) throw error
      return res.json({ success: true, action: 'deactivated', message: `Service deactivated — ${count} staff member(s) still reference it.`, data })
    }
    const { error } = await supabase.from('departments')
      .delete().eq('id', req.params.id).neq('service_type', 'home_department')
    if (error) throw error
    res.json({ success: true, action: 'deleted', message: 'Rotation service deleted.' })
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete rotation service', message: err.message })
  }
})

// ============ STAFF TYPES ROUTES ============
// These routes serve the dynamic staff_types table — replacing hardcoded enums everywhere.

// GET /api/staff-types — public to all authenticated users (needed for dropdowns app-wide)
app.get('/api/staff-types', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const includeInactive = req.query.include_inactive === 'true';
    let query = supabase.from('staff_types').select('*').order('display_order', { ascending: true }).order('display_name', { ascending: true });
    if (!includeInactive) query = query.eq('is_active', true);
    const { data, error } = await query;
    if (error) throw error;
    return res.json({ success: true, data: data || [] });
  } catch (err) {
    console.error('GET /api/staff-types error:', err.message);
    return res.status(500).json({ error: 'Failed to fetch staff types', message: err.message });
  }
});

// POST /api/staff-types — create a new staff type (admin / dept head only)
app.post('/api/staff-types', authenticateToken, checkPermission('staff_types', 'create'), validate(schemas.staffType), async (req, res) => {
  try {
    const schema = Joi.object({
      type_key:        Joi.string().min(2).max(60).pattern(/^[a-z0-9_]+$/).required()
                         .messages({ 'string.pattern.base': 'type_key must be lowercase letters, numbers and underscores only' }),
      display_name:    Joi.string().min(2).max(80).required(),
      badge_class:     Joi.string().max(40).default('badge-secondary'),
      is_resident_type: Joi.boolean().default(false),
      can_supervise:   Joi.boolean().default(false),
      is_active:       Joi.boolean().default(true),
      display_order:   Joi.number().integer().min(0).default(0),
    });
    const { error: ve, value } = schema.validate(req.body);
    if (ve) return res.status(400).json({ error: 'Validation error', message: ve.details[0].message });

    // Check uniqueness of type_key
    const { data: existing } = await supabase.from('staff_types').select('id').eq('type_key', value.type_key).single();
    if (existing) return res.status(409).json({ error: 'Conflict', message: `A staff type with key "${value.type_key}" already exists` });

    const { data, error } = await supabase.from('staff_types').insert(value).select().single();
    if (error) throw error;
    return res.status(201).json({ success: true, data });
  } catch (err) {
    console.error('POST /api/staff-types error:', err.message);
    return res.status(500).json({ error: 'Failed to create staff type', message: err.message });
  }
});

// PUT /api/staff-types/:id — update a staff type
app.put('/api/staff-types/:id', authenticateToken, checkPermission('staff_types', 'update'), async (req, res) => {
  try {
    const schema = Joi.object({
      display_name:    Joi.string().min(2).max(80),
      badge_class:     Joi.string().max(40),
      is_resident_type: Joi.boolean(),
      can_supervise:   Joi.boolean(),
      is_active:       Joi.boolean(),
      display_order:   Joi.number().integer().min(0),
      // type_key intentionally NOT updatable — it's referenced as a string in medical_staff records
    });
    const { error: ve, value } = schema.validate(req.body);
    if (ve) return res.status(400).json({ error: 'Validation error', message: ve.details[0].message });

    const { data, error } = await supabase.from('staff_types').update({ ...value, updated_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Staff type not found' });
    return res.json({ success: true, data });
  } catch (err) {
    console.error('PUT /api/staff-types/:id error:', err.message);
    return res.status(500).json({ error: 'Failed to update staff type', message: err.message });
  }
});

// DELETE /api/staff-types/:id — soft-delete (deactivate) unless no staff uses it, then hard delete
app.delete('/api/staff-types/:id', authenticateToken, checkPermission('staff_types', 'delete'), async (req, res) => {
  try {
    // First check if any medical_staff records reference this type_key
    const { data: typeRow } = await supabase.from('staff_types').select('type_key').eq('id', req.params.id).single();
    if (!typeRow) return res.status(404).json({ error: 'Staff type not found' });

    const { count } = await supabase.from('medical_staff').select('*', { count: 'exact', head: true }).eq('staff_type', typeRow.type_key);

    if (count > 0) {
      // Soft delete — deactivate so it no longer appears in dropdowns but data integrity is preserved
      const { data, error } = await supabase.from('staff_types').update({ is_active: false, updated_at: new Date().toISOString() }).eq('id', req.params.id).select().single();
      if (error) throw error;
      return res.json({ success: true, action: 'deactivated', message: `Staff type deactivated (${count} staff member(s) still reference it). It will no longer appear in dropdowns.`, data });
    } else {
      // Hard delete — safe, nothing references it
      const { error } = await supabase.from('staff_types').delete().eq('id', req.params.id);
      if (error) throw error;
      return res.json({ success: true, action: 'deleted', message: 'Staff type permanently deleted.' });
    }
  } catch (err) {
    console.error('DELETE /api/staff-types/:id error:', err.message);
    return res.status(500).json({ error: 'Failed to delete staff type', message: err.message });
  }
});


// ============ NEWS & POSTS ROUTES ============

// GET /api/news — authenticated, returns all posts (incl. internal)
app.get('/api/news', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { status, type, is_public, page = 1, limit = 100 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    let query = supabase
      .from('news_posts')
      .select(`*, author:medical_staff!news_posts_author_id_fkey(id, full_name, staff_type), research_line:research_lines!news_posts_research_line_id_fkey(id, line_number, name)`)
      .order('created_at', { ascending: false })
      .range(offset, offset + parseInt(limit) - 1);
    if (status) query = query.eq('status', status);
    if (type)   query = query.eq('post_type', type);
    if (is_public !== undefined) query = query.eq('is_public', is_public === 'true');
    const { data, error } = await query;
    if (error) throw error;
    res.json({ data: data || [] });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch news', message: err.message });
  }
});

// GET /api/news/website — PUBLIC, returns only published+public posts
app.get('/api/news/website', publicApiLimiterGuarded, async (req, res) => {
  try {
    const { type, line, limit = 20, featured_only } = req.query;

    let query = supabase
      .from('news_posts')
      .select(`
        id, post_type, title, body, featured_image_url, image_urls,
        word_count, expires_at, published_at, created_at,
        journal_name, authors_text, doi, is_featured, is_public, show_on_homepage,
        author:medical_staff!news_posts_author_id_fkey(id, full_name),
        research_line:research_lines!news_posts_research_line_id_fkey(id, line_number, name)
      `)
      .eq('status', 'published')
      .eq('is_public', true)
      .is('deleted_at', null)
      .or('expires_at.is.null,expires_at.gt.' + new Date().toISOString())
      // Featured posts first, then by date
      .order('is_featured', { ascending: false })
      .order('published_at', { ascending: false })
      .limit(parseInt(limit));

    if (type) query = query.eq('post_type', type);
    if (line) query = query.eq('research_line_id', line);
    if (featured_only === 'true') query = query.eq('is_featured', true);

    const { data, error } = await query;
    if (error) throw error;

    const posts = data || [];
    res.json({
      data: posts,
      meta: {
        total:    posts.length,
        featured: posts.filter(p => p.is_featured).length
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch news', message: err.message });
  }
});

// ══════════════════════════════════════════════════════════════
// NOTIFICATIONS
// ══════════════════════════════════════════════════════════════

// GET /api/notifications — fetch for current user
app.get('/api/notifications', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { limit = 20, unread_only } = req.query
    let query = supabase.from('notifications')
      .select('id, title, message, type, read, link, action_view, created_at')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false })
      .limit(parseInt(limit))
    if (unread_only === 'true') query = query.eq('read', false)
    const { data, error } = await query
    if (error) throw error
    const unreadCount = (data || []).filter(n => !n.read).length
    res.json({ success: true, data: data || [], unread_count: unreadCount })
  } catch (e) { res.status(500).json({ error: e.message }) }
})

// PUT /api/notifications/:id/read — mark one as read
app.put('/api/notifications/:id/read', authenticateToken, apiLimiter, async (req, res) => {
  try {
    await supabase.from('notifications').update({ read: true })
      .eq('id', req.params.id).eq('user_id', req.user.id)
    res.json({ success: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})

// PUT /api/notifications/read-all — mark all as read
app.put('/api/notifications/read-all', authenticateToken, apiLimiter, async (req, res) => {
  try {
    await supabase.from('notifications').update({ read: true })
      .eq('user_id', req.user.id).eq('read', false)
    res.json({ success: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})

// Internal helper — create a notification for a user (called from other routes)
const createNotification = async (userId, title, message, type = 'info', link = null, actionView = null) => {
  try {
    await supabase.from('notifications').insert({
      user_id: userId, title, message, type, read: false,
      link, action_view: actionView, created_at: new Date().toISOString()
    })
  } catch (e) { console.error('createNotification failed:', e.message) }
}

// ══════════════════════════════════════════════════════════════
// ICAL FEED — on-call schedule subscription
// ══════════════════════════════════════════════════════════════

app.get('/api/ical/oncall', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('oncall_schedule')
      .select('id, duty_date, shift_type, start_time, end_time, coverage_notes, primary_physician:medical_staff!oncall_schedule_primary_physician_id_fkey(full_name)')
      .is('deleted_at', null)
      .gte('duty_date', new Date(Date.now() - 7 * 86400000).toISOString().split('T')[0])
      .order('duty_date', { ascending: true })
      .limit(180)
    if (error) throw error

    const shifts = data || []
    const now = new Date().toISOString().replace(/[-:]/g,'').split('.')[0] + 'Z'
    const lines = [
      'BEGIN:VCALENDAR',
      'VERSION:2.0',
      'PRODID:-//neumDesk//CHUAC Neumologia On-Call//ES',
      'CALSCALE:GREGORIAN',
      'METHOD:PUBLISH',
      'X-WR-CALNAME:CHUAC Neumologia - Guardias',
      'X-WR-CALDESC:Guardias del Servicio de Neumologia CHUAC',
    ]

    for (const s of shifts) {
      const dateStr = s.duty_date.replace(/-/g,'')
      const start = s.start_time ? dateStr + 'T' + s.start_time.replace(/:/g,'').slice(0,6) : dateStr
      const end   = s.end_time   ? dateStr + 'T' + s.end_time.replace(/:/g,'').slice(0,6)   : dateStr
      const allDay = !s.start_time
      lines.push('BEGIN:VEVENT')
      lines.push('UID:oncall-' + s.id + '@neumaCtorg')
      lines.push('DTSTAMP:' + now)
      if (allDay) {
        lines.push('DTSTART;VALUE=DATE:' + dateStr)
        lines.push('DTEND;VALUE=DATE:' + dateStr)
      } else {
        lines.push('DTSTART:' + start)
        lines.push('DTEND:' + end)
      }
      const shiftLabel = s.shift_type === 'primary_call' ? 'Guardia Principal' : s.shift_type === 'backup' ? 'Guardia Backup' : s.shift_type || 'Guardia'
      const physician = s.primary_physician?.full_name || 'Sin asignar'
      lines.push('SUMMARY:' + shiftLabel + ' - ' + physician)
      if (s.coverage_notes) lines.push('DESCRIPTION:' + s.coverage_notes.split('\n').join('\\n'))
      lines.push('END:VEVENT')
    }

    lines.push('END:VCALENDAR')
    res.setHeader('Content-Type', 'text/calendar; charset=utf-8')
    res.setHeader('Content-Disposition', 'attachment; filename="guardias-neumologia.ics"')
    res.send(lines.join('\r\n'))
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

// ══════════════════════════════════════════════════════════════
// SOFT-DELETE RECOVERY — restore recently deleted records
// ══════════════════════════════════════════════════════════════

app.put('/api/restore/:table/:id', authenticateToken, isAdmin, apiLimiter, async (req, res) => {
  try {
    const ALLOWED = ['medical_staff','resident_rotations','oncall_schedule','staff_absence_records','news_posts']
    const { table, id } = req.params
    if (!ALLOWED.includes(table)) return res.status(400).json({ error: 'Table not restorable' })
    const { error } = await supabase.from(table).update({ deleted_at: null }).eq('id', id)
    if (error) throw error
    res.json({ success: true, table, id })
  } catch (e) { res.status(500).json({ error: e.message }) }
})

// ══════════════════════════════════════════════════════════════
// DATA EXPORT — CSV generation server-side
// ══════════════════════════════════════════════════════════════

const toCSV = (rows, cols) => {
  const header = cols.map(c => '"' + c.label + '"').join(',')
  const body = rows.map(r => cols.map(c => {
    const v = c.fn ? c.fn(r) : (r[c.key] ?? '')
    return '"' + String(v).replace(/"/g, '""') + '"'
  }).join(',')).join('\n')
  return header + '\n' + body
}

app.get('/api/export/staff', authenticateToken, checkPermission('medical_staff', 'read'), async (req, res) => {
  try {
    const { data, error } = await supabase.from('medical_staff')
      .select('full_name, staff_type, employment_status, primary_clinic, work_phone, professional_email, created_at')
      .is('deleted_at', null).order('full_name')
    if (error) throw error
    const csv = toCSV(data || [], [
      { key: 'full_name', label: 'Full Name' },
      { key: 'staff_type', label: 'Staff Type' },
      { key: 'employment_status', label: 'Status' },
      { key: 'primary_clinic', label: 'Clinic' },
      { key: 'work_phone', label: 'Phone' },
      { key: 'professional_email', label: 'Email' },
      { key: 'created_at', label: 'Added', fn: r => r.created_at?.split('T')[0] || '' },
    ])
    res.setHeader('Content-Type', 'text/csv; charset=utf-8')
    res.setHeader('Content-Disposition', 'attachment; filename="staff-export.csv"')
    res.send('﻿' + csv) // BOM for Excel UTF-8
  } catch (e) { res.status(500).json({ error: e.message }) }
})

app.get('/api/export/rotations', authenticateToken, checkPermission('resident_rotations', 'read'), async (req, res) => {
  try {
    const { data, error } = await supabase.from('resident_rotations')
      .select('start_date, end_date, rotation_status, resident:medical_staff!resident_rotations_resident_id_fkey(full_name), unit:training_units!resident_rotations_training_unit_id_fkey(unit_name)')
      .is('deleted_at', null).order('start_date', { ascending: false }).limit(500)
    if (error) throw error
    const csv = toCSV(data || [], [
      { key: 'resident', label: 'Resident', fn: r => r.resident?.full_name || '' },
      { key: 'unit', label: 'Training Unit', fn: r => r.unit?.unit_name || '' },
      { key: 'start_date', label: 'Start Date' },
      { key: 'end_date', label: 'End Date' },
      { key: 'rotation_status', label: 'Status' },
    ])
    res.setHeader('Content-Type', 'text/csv; charset=utf-8')
    res.setHeader('Content-Disposition', 'attachment; filename="rotations-export.csv"')
    res.send('﻿' + csv)
  } catch (e) { res.status(500).json({ error: e.message }) }
})

app.get('/api/export/absences', authenticateToken, checkPermission('staff_absence', 'read'), async (req, res) => {
  try {
    const { data, error } = await supabase.from('staff_absence_records')
      .select('start_date, end_date, reason, status, staff:medical_staff!staff_absence_records_staff_id_fkey(full_name)')
      .is('deleted_at', null).order('start_date', { ascending: false }).limit(500)
    if (error) throw error
    const csv = toCSV(data || [], [
      { key: 'staff', label: 'Staff Member', fn: r => r.staff?.full_name || '' },
      { key: 'reason', label: 'Reason' },
      { key: 'start_date', label: 'Start Date' },
      { key: 'end_date', label: 'End Date' },
      { key: 'status', label: 'Status' },
    ])
    res.setHeader('Content-Type', 'text/csv; charset=utf-8')
    res.setHeader('Content-Disposition', 'attachment; filename="absences-export.csv"')
    res.send('﻿' + csv)
  } catch (e) { res.status(500).json({ error: e.message }) }
})

app.get('/api/export/oncall', authenticateToken, checkPermission('oncall_schedule', 'read'), async (req, res) => {
  try {
    const { from, to } = req.query
    let query = supabase.from('oncall_schedule')
      .select('duty_date, shift_type, start_time, end_time, coverage_notes, primary_physician:medical_staff!oncall_schedule_primary_physician_id_fkey(full_name)')
      .is('deleted_at', null).order('duty_date', { ascending: true })
    if (from) query = query.gte('duty_date', from)
    if (to) query = query.lte('duty_date', to)
    const { data, error } = await query.limit(500)
    if (error) throw error
    const csv = toCSV(data || [], [
      { key: 'duty_date', label: 'Date' },
      { key: 'primary_physician', label: 'Physician', fn: r => r.primary_physician?.full_name || '' },
      { key: 'shift_type', label: 'Shift Type' },
      { key: 'start_time', label: 'Start Time' },
      { key: 'end_time', label: 'End Time' },
      { key: 'coverage_notes', label: 'Notes' },
    ])
    res.setHeader('Content-Type', 'text/csv; charset=utf-8')
    res.setHeader('Content-Disposition', 'attachment; filename="oncall-export.csv"')
    res.send('﻿' + csv)
  } catch (e) { res.status(500).json({ error: e.message }) }
})

// POST /api/news — create
app.post('/api/news', authenticateToken, checkPermission('news_posts', 'create'), apiLimiter, validate(schemas.newsPost), async (req, res) => {
  try {
    const { title, post_type, body, author_id, research_line_id, is_public,
            status, expires_at, featured_image_url, image_urls,
            journal_name, authors_text, doi, word_count } = req.body;
    if (!title) return res.status(400).json({ error: 'Title is required' });
    if (post_type === 'publication' && !journal_name && !doi) {
      return res.status(400).json({ error: 'Publications require at least a journal name or DOI' });
    }
    // Sanitise image_urls — max 5, must be strings
    const VALID_TYPES = ['update','article','publication','highlight'];
    const cleanImages = Array.isArray(image_urls)
      ? image_urls.filter(u => typeof u === 'string' && u.trim()).slice(0, 5)
      : (featured_image_url ? [featured_image_url] : []);
    const payload = {
      title,
      post_type: VALID_TYPES.includes(post_type) ? post_type : 'update',
      body: body || null,
      author_id: author_id || null,
      research_line_id: research_line_id || null,
      is_public: is_public === true || is_public === 'true',
      status: status || 'draft',
      expires_at: expires_at || null,
      image_urls: cleanImages,
      featured_image_url: cleanImages[0] || featured_image_url || null,
      journal_name: journal_name || null,
      authors_text: authors_text || null,
      doi: doi || null,
      word_count: body ? body.trim().split(/\s+/).filter(Boolean).length : (word_count || null),
      published_at: req.body.published_at
        ? new Date(req.body.published_at).toISOString()
        : status === 'published' ? new Date().toISOString() : null
    };
    const { data, error } = await supabase.from('news_posts').insert(payload).select().single();
    if (error) throw error;
    res.status(201).json({ data });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create post', message: err.message });
  }
});

// PUT /api/news/:id — update
app.put('/api/news/:id', authenticateToken, checkPermission('news_posts', 'update'), apiLimiter, validate(schemas.newsPost), async (req, res) => {
  try {
    const { id } = req.params;
    const b = req.body;
    // Whitelist only real columns — prevent joined fields from reaching Supabase
    const VALID_TYPES = ['update','article','publication','highlight'];
    const VALID_STATUSES = ['draft','published','archived'];
    const cleanImages = Array.isArray(b.image_urls)
      ? b.image_urls.filter(u => typeof u === 'string' && u.trim()).slice(0, 5)
      : undefined;
    const updates = {
      updated_at: new Date().toISOString(),
      ...(b.title              !== undefined && { title: b.title }),
      ...(b.post_type          !== undefined && { post_type: VALID_TYPES.includes(b.post_type) ? b.post_type : 'update' }),
      ...(b.body               !== undefined && { body: b.body || null }),
      ...(b.author_id          !== undefined && { author_id: b.author_id || null }),
      ...(b.research_line_id   !== undefined && { research_line_id: b.research_line_id || null }),
      ...(b.is_public          !== undefined && { is_public: b.is_public === true || b.is_public === 'true' }),
      ...(b.status             !== undefined && VALID_STATUSES.includes(b.status) && { status: b.status }),
      ...(b.expires_at         !== undefined && { expires_at: b.expires_at || null }),
      ...(cleanImages !== undefined && { image_urls: cleanImages, featured_image_url: cleanImages[0] || null }),
      ...(cleanImages === undefined && b.featured_image_url !== undefined && { featured_image_url: b.featured_image_url || null }),
      ...(b.journal_name       !== undefined && { journal_name: b.journal_name || null }),
      ...(b.authors_text       !== undefined && { authors_text: b.authors_text || null }),
      ...(b.doi                !== undefined && { doi: b.doi || null }),
      ...(b.published_at       !== undefined && { published_at: b.published_at ? new Date(b.published_at).toISOString() : null }),
    };

    // is_featured: enforce max 5 featured posts
    if (b.is_featured !== undefined) {
      const featuring = b.is_featured === true || b.is_featured === 'true';
      if (featuring) {
        const { data: current } = await supabase.from('news_posts')
          .select('id').eq('is_featured', true).neq('id', id);
        if ((current || []).length >= 5) {
          return res.status(409).json({
            error: 'Featured limit reached',
            message: 'Maximum 5 posts can be featured on the homepage at once. Un-feature an existing post first.'
          });
        }
      }
      updates.is_featured = featuring;
    }
    if (b.body) updates.word_count = b.body.trim().split(/\s+/).filter(Boolean).length;
    else if (b.body === '' || b.body === null) updates.word_count = null;
    if (b.status === 'published' && !updates.published_at) updates.published_at = new Date().toISOString();
    else if (b.status && b.status !== 'published' && !b.published_at) updates.published_at = null;
    const { data, error } = await supabase.from('news_posts').update(updates).eq('id', id)
      .select('*, author:medical_staff!news_posts_author_id_fkey(id, full_name), research_line:research_lines!news_posts_research_line_id_fkey(id, line_number, name)')
      .single();
    if (error) throw error;
    res.json({ data });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update post', message: err.message });
  }
});

// DELETE /api/news/:id
app.delete('/api/news/:id', authenticateToken, checkPermission('news_posts', 'delete'), apiLimiter, async (req, res) => {
  try {
    const { error } = await supabase.from('news_posts').delete().eq('id', req.params.id);
    if (error) throw error;
    res.status(204).send();
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete post', message: err.message });
  }
});

// ============================================================================
// ========================== ACADEMIC DEGREES ================================
// ============================================================================

app.get('/api/academic-degrees', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { data, error, count } = await supabase
      .from('academic_degrees')
      .select('*', { count: 'exact' })
      .eq('is_active', true)
      .order('display_order');
    if (error) {
      console.error('GET /api/academic-degrees Supabase error:', JSON.stringify(error));
      throw error;
    }
    console.log(`GET /api/academic-degrees → ${data?.length ?? 0} rows (count=${count})`);
    res.json(data || []);
  } catch (err) {
    console.error('GET /api/academic-degrees caught:', err.message);
    res.status(500).json({ error: 'Failed to fetch academic degrees', message: err.message });
  }
});

app.post('/api/academic-degrees', authenticateToken, checkPermission('departments', 'create'), async (req, res) => {
  try {
    const { name, abbreviation, display_order } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: 'name is required' });
    const { data, error } = await supabase
      .from('academic_degrees')
      .insert([{ name: name.trim(), abbreviation: abbreviation?.trim() || null, display_order: display_order || 0 }])
      .select().single();
    if (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'A degree with this name already exists' });
      throw error;
    }
    res.status(201).json(data);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create academic degree', message: err.message });
  }
});

app.put('/api/academic-degrees/:id', authenticateToken, checkPermission('departments', 'update'), async (req, res) => {
  try {
    const { name, abbreviation, display_order, is_active } = req.body;
    const { data, error } = await supabase
      .from('academic_degrees')
      .update({ name, abbreviation, display_order, is_active, updated_at: new Date().toISOString() })
      .eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update academic degree', message: err.message });
  }
});

app.delete('/api/academic-degrees/:id', authenticateToken, checkPermission('departments', 'update'), async (req, res) => {
  try {
    // Soft delete — mark inactive, keep FK integrity
    const { error } = await supabase
      .from('academic_degrees')
      .update({ is_active: false, updated_at: new Date().toISOString() })
      .eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete academic degree', message: err.message });
  }
});

// ============================================================================
// ========================== STAFF CERTIFICATES ==============================
// ============================================================================

// GET all certificates for a staff member
app.get('/api/medical-staff/:id/certificates', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('staff_certificates')
      .select('*')
      .eq('staff_id', req.params.id)
      .order('expiry_date', { ascending: true });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch certificates', message: err.message });
  }
});

// POST — add a certificate
app.post('/api/medical-staff/:id/certificates', authenticateToken, checkPermission('medical_staff', 'update'), validate(schemas.certificate), async (req, res) => {
  try {
    const { certificate_name, issued_date, renewal_months, notes } = req.body;
    if (!certificate_name?.trim()) return res.status(400).json({ error: 'certificate_name is required' });
    // Compute the actual expiry date — this was never being set, meaning every
    // certificate silently showed as permanently valid regardless of reality.
    let expiry_date = null;
    if (issued_date) {
      const d = new Date(issued_date + 'T00:00:00');
      if (!isNaN(d.getTime())) {
        d.setMonth(d.getMonth() + (renewal_months || 24));
        expiry_date = d.toISOString().split('T')[0];
      }
    }
    const { data, error } = await supabase
      .from('staff_certificates')
      .insert([{
        staff_id: req.params.id,
        certificate_name: certificate_name.trim(),
        issued_date: issued_date || null,
        renewal_months: renewal_months || 24,
        expiry_date,
        notes: notes || null
      }])
      .select().single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (err) {
    res.status(500).json({ error: 'Failed to add certificate', message: err.message });
  }
});

// PUT — edit a certificate
app.put('/api/medical-staff/:staffId/certificates/:certId', authenticateToken, checkPermission('medical_staff', 'update'), async (req, res) => {
  try {
    const { certificate_name, issued_date, renewal_months, notes } = req.body;
    let expiry_date = null;
    if (issued_date) {
      const d = new Date(issued_date + 'T00:00:00');
      if (!isNaN(d.getTime())) {
        d.setMonth(d.getMonth() + (renewal_months || 24));
        expiry_date = d.toISOString().split('T')[0];
      }
    }
    const { data, error } = await supabase
      .from('staff_certificates')
      .update({ certificate_name, issued_date, renewal_months, expiry_date, notes, updated_at: new Date().toISOString() })
      .eq('id', req.params.certId)
      .eq('staff_id', req.params.staffId)
      .select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update certificate', message: err.message });
  }
});

// DELETE — remove a certificate
app.delete('/api/medical-staff/:staffId/certificates/:certId', authenticateToken, checkPermission('medical_staff', 'update'), async (req, res) => {
  try {
    const { error } = await supabase
      .from('staff_certificates')
      .delete()
      .eq('id', req.params.certId)
      .eq('staff_id', req.params.staffId);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete certificate', message: err.message });
  }
});




// ============================================================================
// ======================== EMERGENCY CALLOUTS (DUTY LOG) =====================
// ============================================================================

// GET — list callouts, filterable by staff_id, month, year
app.get('/api/emergency-callouts', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { staff_id, month, year, limit = 100 } = req.query
    // Try with join first, fall back to plain select if join fails
    let query = supabase
      .from('emergency_callouts')
      .select('*, staff:medical_staff(id,full_name,staff_type)')
      .order('called_at', { ascending: false })
      .limit(Number(limit))
    if (staff_id) query = query.eq('staff_id', staff_id)
    if (year)  query = query.gte('called_at', `${year}-01-01`).lte('called_at', `${year}-12-31T23:59:59`)
    if (month && year) {
      const pad = String(month).padStart(2,'0')
      const last = new Date(year, month, 0).getDate()
      query = query.gte('called_at', `${year}-${pad}-01`).lte('called_at', `${year}-${pad}-${last}T23:59:59`)
    }
    const { data, error, count } = await query
    if (error) throw error
    res.json({ data: data || [], count: (data || []).length })
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch callouts', message: err.message })
  }
})

// POST — log a new callout
app.post('/api/emergency-callouts', authenticateToken, checkPermission('oncall_schedule', 'create'), validate(schemas.emergencyCallout), async (req, res) => {
  try {
    const { staff_id, called_at, end_time, reason_category, notes, time_type } = req.body
    if (!staff_id) return res.status(400).json({ error: 'staff_id is required' })
    if (!called_at) return res.status(400).json({ error: 'called_at is required' })
    const { data, error } = await supabase
      .from('emergency_callouts')
      .insert([{
        staff_id,
        called_at,
        end_time: end_time || null,
        reason_category: reason_category || 'unspecified',
        notes: notes || null,
        time_type: time_type || 'night',
        coverage_area_id: coverage_area_id || null,
        created_by: null,  // app_users.id ≠ auth.users.id — FK requires auth.users
        created_at: new Date().toISOString()
      }])
      .select('*, staff:medical_staff(id,full_name,staff_type)')
      .single()
    if (error) throw error
    res.status(201).json(data)
  } catch (err) {
    res.status(500).json({ error: 'Failed to log callout', message: err.message })
  }
})

// PUT — edit a callout
app.put('/api/emergency-callouts/:id', authenticateToken, checkPermission('oncall_schedule', 'update'), validate(schemas.emergencyCallout), async (req, res) => {
  try {
    const { called_at, end_time, reason_category, notes, time_type } = req.body
    const { data, error } = await supabase
      .from('emergency_callouts')
      .update({ called_at, end_time, reason_category, notes, time_type, updated_at: new Date().toISOString() })
      .eq('id', req.params.id).select('*, staff:medical_staff(id,full_name,staff_type)').single()
    if (error) throw error
    res.json(data)
  } catch (err) {
    res.status(500).json({ error: 'Failed to update callout', message: err.message })
  }
})

// DELETE — remove a callout
app.delete('/api/emergency-callouts/:id', authenticateToken, checkPermission('oncall_schedule', 'delete'), async (req, res) => {
  try {
    const { error } = await supabase.from('emergency_callouts').delete().eq('id', req.params.id)
    if (error) throw error
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete callout', message: err.message })
  }
})

// GET summary — aggregated per staff for a period
app.get('/api/emergency-callouts/summary', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { year = new Date().getFullYear(), month } = req.query
    let from = `${year}-01-01`, to = `${year}-12-31T23:59:59`
    if (month) {
      const pad = String(month).padStart(2,'0')
      const last = new Date(year, month, 0).getDate()
      from = `${year}-${pad}-01`; to = `${year}-${pad}-${last}T23:59:59`
    }
    const { data, error } = await supabase
      .from('emergency_callouts')
      .select('staff_id, time_type, called_at')
      .gte('called_at', from).lte('called_at', to)
    if (error) throw error
    // Aggregate per staff
    const summary = {}
    for (const row of (data || [])) {
      if (!summary[row.staff_id]) summary[row.staff_id] = { staff_id: row.staff_id, total: 0, night: 0, weekend: 0, daytime: 0, holiday: 0 }
      summary[row.staff_id].total++
      summary[row.staff_id][row.time_type || 'night']++
    }
    res.json(Object.values(summary))
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch summary', message: err.message })
  }
})


// ===== OPS METRICS (Daily Briefing pulse tiles) =====

// GET today's metrics
app.get('/api/ops-metrics', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const date = req.query.date || new Date().toISOString().slice(0, 10)
    const { data, error } = await supabase
      .from('ops_metrics')
      .select('*, posted_by_user:app_users!ops_metrics_posted_by_fkey(id,full_name)')
      .eq('valid_for_date', date)
      .order('posted_at', { ascending: false })
    if (error) throw error
    // Deduplicate — keep latest per metric_key
    const seen = new Set()
    const deduped = (data || []).filter(r => {
      if (seen.has(r.metric_key)) return false
      seen.add(r.metric_key); return true
    })
    res.json({ data: deduped, date })
  } catch (err) {
    if (err.message?.includes('does not exist') || err.code === '42P01')
      return res.json({ data: [], date, _tableNotFound: true })
    res.status(500).json({ error: 'Failed to fetch ops metrics', message: err.message })
  }
})

// POST / upsert a metric (or batch of metrics from daily briefing)
app.post('/api/ops-metrics', authenticateToken, checkPermission('communications', 'create'), async (req, res) => {
  try {
    const metrics = Array.isArray(req.body) ? req.body : [req.body]
    const date = new Date().toISOString().slice(0, 10)
    const rows = metrics
      .filter(m => m.metric_key && m.metric_value !== undefined)
      .map(m => ({
        metric_key:    m.metric_key,
        metric_value:  parseInt(m.metric_value) || 0,
        metric_sub:    m.metric_sub || null,
        metric_value2: m.metric_value2 != null ? parseInt(m.metric_value2) : null,
        posted_by:     req.user.id,
        posted_at:     new Date().toISOString(),
        valid_for_date: date,
        expires_at:    m.expires_at || null,
      }))
    if (!rows.length) return res.status(400).json({ error: 'No valid metrics in request' })
    // Delete existing for today + these keys, then insert fresh
    const keys = rows.map(r => r.metric_key)
    await supabase.from('ops_metrics').delete()
      .eq('valid_for_date', date).in('metric_key', keys)
    const { data, error } = await supabase.from('ops_metrics').insert(rows).select()
    if (error) throw error
    res.status(201).json({ data, count: data.length })
  } catch (err) {
    if (err.message?.includes('does not exist') || err.code === '42P01')
      return res.status(503).json({ error: 'ops_metrics table not found', message: 'Run the ops_metrics SQL migration first.' })
    res.status(500).json({ error: 'Failed to save metrics', message: err.message })
  }
})

// DELETE a single metric
app.delete('/api/ops-metrics/:id', authenticateToken, checkPermission('communications', 'update'), async (req, res) => {
  try {
    const { error } = await supabase.from('ops_metrics').delete().eq('id', req.params.id)
    if (error) throw error
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete metric', message: err.message })
  }
})

// ===== COVERAGE AREAS =====

app.get('/api/coverage-areas', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('coverage_areas')
      .select('*')
      .order('display_order', { ascending: true })
    if (error) throw error
    res.json({ success: true, data: data || [] })
  } catch (err) {
    if (err.code === '42P01') return res.json({ success: true, data: [], _tableNotFound: true })
    res.status(500).json({ error: 'Failed to fetch coverage areas', message: err.message })
  }
})

app.post('/api/coverage-areas', authenticateToken, checkPermission('system_settings', 'create'), async (req, res) => {
  try {
    const { name, code, color, applies_weekends, display_order, requires_coverage } = req.body
    if (!name?.trim()) return res.status(400).json({ error: 'Name is required' })
    const row = {
      name: name.trim(),
      code: (code || name).trim().toUpperCase().replace(/\s+/g, '_').slice(0, 20),
      color: color || '#00b3b3',
      applies_weekends: applies_weekends !== false,
      requires_coverage: requires_coverage === true,
      display_order: display_order || 0,
      is_active: true
    }
    const { data, error } = await supabase.from('coverage_areas').insert([row]).select().single()
    if (error) throw error
    res.status(201).json({ success: true, data })
  } catch (err) {
    if (err.code === '42P01') return res.status(503).json({ error: 'coverage_areas table not found. Run migration first.' })
    res.status(500).json({ error: 'Failed to create coverage area', message: err.message })
  }
})

app.put('/api/coverage-areas/:id', authenticateToken, checkPermission('system_settings', 'update'), async (req, res) => {
  try {
    const { name, color, applies_weekends, requires_coverage, display_order, is_active } = req.body
    const updates = {}
    if (name !== undefined) updates.name = name.trim()
    if (color !== undefined) updates.color = color
    if (applies_weekends !== undefined) updates.applies_weekends = applies_weekends
    if (requires_coverage !== undefined) updates.requires_coverage = requires_coverage
    if (display_order !== undefined) updates.display_order = display_order
    if (is_active !== undefined) updates.is_active = is_active
    if (Object.keys(updates).length === 0) return res.json({ success: true, message: 'Nothing to update' })
    const { data, error } = await supabase.from('coverage_areas').update(updates).eq('id', req.params.id).select().single()
    if (error) throw error
    res.json({ success: true, data })
  } catch (err) {
    res.status(500).json({ error: 'Failed to update coverage area', message: err.message })
  }
})

app.delete('/api/coverage-areas/:id', authenticateToken, checkPermission('system_settings', 'delete'), async (req, res) => {
  try {
    // Check if any schedules use this area
    const { data: inUse } = await supabase
      .from('oncall_schedule')
      .select('id')
      .eq('coverage_area_id', req.params.id)
      .limit(1)
    if (inUse && inUse.length > 0)
      return res.status(409).json({ error: 'Area is in use by existing schedules. Deactivate instead.' })
    const { error } = await supabase.from('coverage_areas').delete().eq('id', req.params.id)
    if (error) throw error
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete coverage area', message: err.message })
  }
})

// ===== ONCALL BATCH INSERT =====
app.post('/api/oncall/batch', authenticateToken, checkPermission('oncall_schedule', 'create'), async (req, res) => {
  try {
    const { shifts } = req.body
    if (!Array.isArray(shifts) || shifts.length === 0)
      return res.status(400).json({ error: 'shifts array is required' })
    if (shifts.length > 200)
      return res.status(400).json({ error: 'Maximum 200 shifts per batch' })

    const rows = shifts.map(s => ({
      duty_date:            formatDate(new Date(s.duty_date)),
      shift_type:           ['primary_call','backup_call','float_physician'].includes(s.shift_type) ? s.shift_type : 'primary_call',
      coverage_area_id:     s.coverage_area_id || null,
      start_time:           s.start_time || '15:00',
      end_time:             s.end_time   || '08:00',
      primary_physician_id: s.primary_physician_id,
      backup_physician_id:  s.backup_physician_id  || null,
      coverage_notes:       s.coverage_notes       || null,
      schedule_id:          generateId('SCH'),
      created_by:           req.user.id,
      created_at:           new Date().toISOString(),
      updated_at:           new Date().toISOString(),
    }))

    // Validate required fields
    const invalid = rows.filter(r => !r.primary_physician_id || !r.duty_date)
    if (invalid.length > 0)
      return res.status(400).json({ error: `${invalid.length} shifts missing required fields (primary_physician_id, duty_date)` })

    const { data, error } = await supabase
      .from('oncall_schedule')
      .insert(rows)
      .select()

    if (error) throw error
    res.status(201).json({ success: true, count: data.length, data })
  } catch (err) {
    // Unique constraint violation — one primary per area per day
    if (err.code === '23505')
      return res.status(409).json({
        error: 'Duplicate primary call',
        message: 'One or more dates already have a primary call for the same area. Review conflicts and retry.',
        detail: err.detail
      })
    res.status(500).json({ error: 'Batch insert failed', message: err.message })
  }
})

// ===== 404 HANDLER =====
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found', message: `The requested endpoint ${req.method} ${req.path} does not exist`, timestamp: new Date().toISOString() });
});

// ===== GLOBAL ERROR HANDLER =====
app.use((err, req, res, next) => {
  console.error(`[${new Date().toISOString()}] ${req.method} ${req.url} - Error:`, err.message);
  if (err.message?.includes('CORS')) return res.status(403).json({ error: 'CORS error', message: 'Request blocked by CORS policy', your_origin: req.headers.origin, allowed_origins: allowedOrigins });
  if (err.message?.includes('JWT') || err.name === 'JsonWebTokenError') return res.status(401).json({ error: 'Authentication error', message: 'Invalid or expired authentication token' });
  res.status(500).json({ error: 'Internal server error', message: NODE_ENV === 'development' ? err.message : 'An unexpected error occurred', timestamp: new Date().toISOString() });
});


// ============ SERVER STARTUP ============
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`
    ======================================================
    🏥 NEUMOCARE HOSPITAL MANAGEMENT SYSTEM API v5.4
    ======================================================
    ✅ 18 BUGS FIXED (original 9 + 9 new)
    ✅ FIX 10: auth/me JWT field mismatch — req.user.userId→req.user.id
    ✅ FIX 11: medical-staff POST+PUT now persist can_be_pi/coi/phd fields
    ✅ FIX 12: Joi schema includes can_be_pi/coi/phd (no longer stripped)
    ✅ FIX 13: training-units PUT now updates unit_type + unit_description
    ✅ FIX 14: training-units PUT refreshes department_name on dept change
    ✅ FIX 15: rotations DELETE is now soft delete (terminated_early)
    ✅ FIX 16: analytics project stages aligned to current_stage field
    ✅ FIX 17: research-lines POST accepts research_line_name + keywords
    ✅ FIX 18: clinical-trials phase defaults for non-interventional studies
    ✅ Dynamic staff_types — /api/staff-types CRUD routes
    ======================================================
    Server running on port: ${PORT}
    Environment: ${NODE_ENV}
    ======================================================
  `);
});


// ── Test notification endpoint ───────────────────────────────────────────
app.post('/api/notify/test', authenticateToken, async (req, res) => {
  try {
    await sendNotification(
      'neumDesk notification test',
      `<h2 style="color:#0a1628">Notifications are working</h2>
      <p style="color:#374151">This is a test notification from neumDesk. You will receive alerts for:</p>  
      <ul style="color:#374151;padding-left:20px">
        <li>Absences with no coverage arranged</li>
        <li>On-call shifts with no backup assigned (required areas only)</li>
        <li>Rotations ending within 7 days with no successor scheduled</li>
      </ul>
      <p style="color:#6b7280;font-size:13px">Sent to: ${NOTIFY_EMAIL || 'not configured'}</p>`,
      false
    );
    res.json({ ok: true, to: NOTIFY_EMAIL || 'not configured (set NOTIFY_EMAIL env var)' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

process.on('SIGTERM', () => { server.close(() => process.exit(0)); });
process.on('SIGINT', () => { server.close(() => process.exit(0)); });

module.exports = app;  
