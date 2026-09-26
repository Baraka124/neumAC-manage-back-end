// neumDesk V46.14 · Phase 5.3D · Operational Visibility & Field Projection · 2026-09-24
// Stable production filename: projection.js. Update this file in place.
//
// Pure projection layer: no database, HTTP or Supabase dependencies.
// Authority decides WHETHER an actor may access a resource and at which
// visibility. This module decides WHICH FIELDS may leave the backend.
//
// Security invariant:
//   ALLOW_LIMITED must never serialize a full database row.

'use strict';

const VISIBILITIES = Object.freeze(['summary', 'operational', 'full']);

const PROJECTION_CATALOG = Object.freeze({
  staff: Object.freeze({
    summary: 'Professional identity and public/departmental context only.',
    operational: 'Summary plus work contact and operational staffing attributes; excludes personal/HR/security fields.',
    full: 'Complete professional record returned to an actor with full profile authority.'
  }),
  leave: Object.freeze({
    summary: 'Availability signal only; no reason, notes, recorder or detailed leave metadata.',
    operational: 'Dates/status/coverage needed for departmental work; excludes leave reason/type, private notes and audit identity.',
    full: 'Complete leave record.'
  }),
  rotation: Object.freeze({
    summary: 'Resident, unit, dates and status.',
    operational: 'Summary plus supervisor, category and effective temporal fields; excludes evaluations, goals and clinical notes.',
    full: 'Complete rotation record.'
  }),
  oncall: Object.freeze({
    summary: 'Duty date, coverage area and assigned professional names.',
    operational: 'Summary plus shift/time and professional work-contact context; excludes private mobile numbers and free-text coverage notes.',
    full: 'Complete on-call record.'
  })
});

function safeVisibility(value) {
  return VISIBILITIES.includes(value) ? value : 'summary';
}

function pick(source, keys) {
  const out = {};
  if (!source || typeof source !== 'object') return out;
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(source, key)) out[key] = source[key];
  }
  return out;
}

function cleanObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return value;
  return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined));
}

function projectDepartment(value) {
  if (!value || typeof value !== 'object') return value || null;
  return cleanObject(pick(value, ['id', 'name', 'code']));
}

function projectHospital(value) {
  if (!value || typeof value !== 'object') return value || null;
  return cleanObject(pick(value, ['id', 'name', 'code', 'parent_complex']));
}

function projectAcademicDegree(value) {
  if (!value || typeof value !== 'object') return value || null;
  return cleanObject(pick(value, ['id', 'name', 'abbreviation']));
}

function projectPersonRef(value, visibility = 'summary') {
  if (!value || typeof value !== 'object') return value || null;
  const level = safeVisibility(visibility);
  const base = pick(value, ['id', 'full_name', 'title', 'staff_type', 'specialization', 'public_photo_url']);
  if (level === 'operational' || level === 'full') {
    Object.assign(base, pick(value, ['professional_email', 'work_phone', 'office_phone']));
  }
  if (level === 'full') Object.assign(base, value);
  delete base.mobile_phone; // nested operational references never expose personal mobile by default
  return cleanObject(base);
}

function projectStaff(row, visibility = 'summary') {
  if (!row || typeof row !== 'object') return row;
  const level = safeVisibility(visibility);
  if (level === 'full') return { ...row };

  const summaryKeys = [
    'id', 'staff_id', 'full_name', 'title', 'staff_type', 'resident_category',
    'resident_type', 'training_year', 'training_level', 'specialization',
    'affiliation_type', 'primary_clinic', 'department_id', 'home_department',
    'home_department_id', 'hospital_id', 'public_photo_url', 'is_public',
    'public_bio', 'orcid_id', 'has_phd', 'phd_field', 'is_chief_of_department'
  ];
  const operationalKeys = [
    'professional_email', 'work_phone', 'office_phone', 'employment_status',
    'can_supervise_residents', 'is_resident_manager', 'is_oncall_manager',
    'residency_start_date', 'residency_end_date_calc', 'residency_year_calc',
    'residency_year_override', 'can_be_pi', 'can_be_coi', 'academic_degree',
    'academic_degree_id', 'certificate_status'
  ];

  const out = pick(row, summaryKeys);
  if (level === 'operational') Object.assign(out, pick(row, operationalKeys));

  if (Object.prototype.hasOwnProperty.call(row, 'department')) out.department = projectDepartment(row.department);
  if (Object.prototype.hasOwnProperty.call(row, 'departments')) out.departments = projectDepartment(row.departments);
  if (Object.prototype.hasOwnProperty.call(row, 'home_dept')) out.home_dept = projectDepartment(row.home_dept);
  if (Object.prototype.hasOwnProperty.call(row, 'hospital')) out.hospital = projectHospital(row.hospital);
  if (Object.prototype.hasOwnProperty.call(row, 'hospitals')) out.hospitals = projectHospital(row.hospitals);
  if (Object.prototype.hasOwnProperty.call(row, 'degree')) out.degree = projectAcademicDegree(row.degree);

  // Explicitly excluded from summary/operational projections:
  // date_of_birth, mobile_phone, medical_license, special_notes, biography,
  // external_contact_*, clinical study certificates, deleted_at and raw private notes.
  return cleanObject(out);
}

function projectLeave(row, visibility = 'summary') {
  if (!row || typeof row !== 'object') return row;
  const level = safeVisibility(visibility);
  if (level === 'full') return { ...row };

  const base = pick(row, [
    'id', 'staff_member_id', 'start_date', 'end_date', 'actual_start_date',
    'actual_return_date', 'current_status'
  ]);
  base.availability = row.current_status === 'cancelled' || row.current_status === 'returned_to_duty'
    ? 'available'
    : 'unavailable';
  base.staff_member = projectPersonRef(row.staff_member, 'summary');

  if (level === 'operational') {
    Object.assign(base, pick(row, [
      'coverage_arranged', 'covering_staff_id', 'total_days', 'days_remaining',
      'is_recurring', 'recurrence_pattern', 'recurrence_end_date'
    ]));
    base.covering_staff = projectPersonRef(row.covering_staff, 'summary');
  }

  // Intentionally excluded from non-full views:
  // absence_type, absence_reason, coverage_notes, hod_notes, recorded_by,
  // recurrence_parent_id and internal audit/provenance fields.
  return cleanObject(base);
}

function projectRotation(row, visibility = 'summary') {
  if (!row || typeof row !== 'object') return row;
  const level = safeVisibility(visibility);
  if (level === 'full') return { ...row };

  const base = pick(row, [
    'id', 'rotation_id', 'resident_id', 'training_unit_id', 'start_date',
    'end_date', 'rotation_status'
  ]);
  base.resident = projectPersonRef(row.resident, 'summary');
  if (row.training_unit) base.training_unit = cleanObject(pick(row.training_unit, ['id', 'unit_name', 'unit_code']));

  if (level === 'operational') {
    Object.assign(base, pick(row, [
      'supervising_attending_id', 'rotation_category', 'actual_start_date',
      'actual_end_date', 'termination_recorded_at', 'created_at', 'updated_at'
    ]));
    base.supervising_attending = projectPersonRef(row.supervising_attending, 'summary');
  }

  // Intentionally excluded from non-full views:
  // clinical_notes, supervisor_evaluation, goals, notes and deletion metadata.
  return cleanObject(base);
}

function projectOnCall(row, visibility = 'summary') {
  if (!row || typeof row !== 'object') return row;
  const level = safeVisibility(visibility);
  if (level === 'full') return { ...row };

  const base = pick(row, [
    'id', 'schedule_id', 'duty_date', 'primary_physician_id',
    'backup_physician_id', 'resident_physician_id', 'coverage_area_id'
  ]);
  base.primary_physician = projectPersonRef(row.primary_physician, 'summary');
  base.backup_physician = projectPersonRef(row.backup_physician, 'summary');
  base.resident_physician = projectPersonRef(row.resident_physician, 'summary');
  if (row.coverage_area) base.coverage_area = cleanObject(pick(row.coverage_area, ['id', 'name', 'code', 'color']));

  if (level === 'operational') {
    Object.assign(base, pick(row, ['shift_type', 'start_time', 'end_time', 'has_conflict']));
    base.primary_physician = projectPersonRef(row.primary_physician, 'operational');
    base.backup_physician = projectPersonRef(row.backup_physician, 'operational');
  }

  // Intentionally excluded from non-full views:
  // mobile_phone, coverage_notes, created_by and internal timestamps.
  return cleanObject(base);
}

function projectLeaveStats(stats, visibility = 'summary') {
  if (!stats || typeof stats !== 'object') return stats;
  const level = safeVisibility(visibility);
  if (level === 'full') return { ...stats };
  const operational = pick(stats, ['currently_absent', 'upcoming', 'without_coverage', 'coverage_rate']);
  if (level === 'operational') return operational;
  return pick(stats, ['currently_absent', 'upcoming']);
}

function project(domain, row, visibility) {
  switch (domain) {
    case 'staff': return projectStaff(row, visibility);
    case 'leave': return projectLeave(row, visibility);
    case 'rotation': return projectRotation(row, visibility);
    case 'oncall': return projectOnCall(row, visibility);
    default: throw new Error(`Unknown projection domain: ${domain}`);
  }
}

function catalog() {
  return PROJECTION_CATALOG;
}

module.exports = Object.freeze({
  VISIBILITIES,
  PROJECTION_CATALOG,
  safeVisibility,
  projectPersonRef,
  projectStaff,
  projectLeave,
  projectRotation,
  projectOnCall,
  projectLeaveStats,
  project,
  catalog
});
