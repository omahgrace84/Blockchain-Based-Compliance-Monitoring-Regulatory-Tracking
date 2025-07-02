;; Audit Coordinator Contract
;; Coordinates compliance audits and maintains audit trails

;; Constants
(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_UNAUTHORIZED (err u500))
(define-constant ERR_NOT_FOUND (err u501))
(define-constant ERR_INVALID_INPUT (err u502))
(define-constant ERR_AUDIT_LOCKED (err u503))

;; Data Variables
(define-data-var next-audit-id uint u1)
(define-data-var audit-fee uint u5000000) ;; 5 STX in microSTX

;; Data Maps
(define-map compliance-audits
  { audit-id: uint }
  {
    plan-id: uint,
    organization: (string-ascii 100),
    audit-type: (string-ascii 50),
    scope: (string-ascii 300),
    auditor: principal,
    scheduled-date: uint,
    completion-date: uint,
    status: (string-ascii 20),
    findings-count: uint,
    compliance-score: uint,
    created-by: principal,
    created-at: uint
  }
)

(define-map audit-findings
  { audit-id: uint, finding-id: uint }
  {
    finding-type: (string-ascii 50),
    severity: uint,
    description: (string-ascii 500),
    recommendation: (string-ascii 300),
    status: (string-ascii 20),
    identified-by: principal,
    identified-at: uint,
    resolved-at: uint
  }
)

(define-map audit-evidence
  { audit-id: uint, evidence-id: uint }
  {
    evidence-type: (string-ascii 50),
    evidence-hash: (buff 32),
    description: (string-ascii 200),
    submitted-by: principal,
    verified: bool,
    submitted-at: uint
  }
)

(define-map audit-reports
  { audit-id: uint }
  {
    executive-summary: (string-ascii 500),
    detailed-findings: (string-ascii 1000),
    recommendations: (string-ascii 500),
    next-audit-date: uint,
    report-hash: (buff 32),
    published-at: uint
  }
)

(define-map authorized-auditors principal bool)
(define-map audit-schedules principal (list 20 uint))

;; Authorization Functions
(define-public (add-auditor (auditor principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (ok (map-set authorized-auditors auditor true))
  )
)

(define-public (remove-auditor (auditor principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (ok (map-delete authorized-auditors auditor))
  )
)

;; Core Functions
(define-public (schedule-audit
  (plan-id uint)
  (organization (string-ascii 100))
  (audit-type (string-ascii 50))
  (scope (string-ascii 300))
  (auditor principal)
  (scheduled-date uint))
  (let
    (
      (audit-id (var-get next-audit-id))
      (current-time (unwrap-panic (get-block-info? time (- block-height u1))))
    )
    (asserts! (default-to false (map-get? authorized-auditors auditor)) ERR_UNAUTHORIZED)
    (asserts! (> (len organization) u0) ERR_INVALID_INPUT)
    (asserts! (> scheduled-date current-time) ERR_INVALID_INPUT)

    (map-set compliance-audits
      { audit-id: audit-id }
      {
        plan-id: plan-id,
        organization: organization,
        audit-type: audit-type,
        scope: scope,
        auditor: auditor,
        scheduled-date: scheduled-date,
        completion-date: u0,
        status: "scheduled",
        findings-count: u0,
        compliance-score: u0,
        created-by: tx-sender,
        created-at: current-time
      }
    )

    ;; Add to auditor's schedule
    (let
      (
        (current-schedule (default-to (list) (map-get? audit-schedules auditor)))
      )
      (map-set audit-schedules auditor (unwrap-panic (as-max-len? (append current-schedule audit-id) u20)))
    )

    (var-set next-audit-id (+ audit-id u1))

    (print {
      event: "audit-scheduled",
      audit-id: audit-id,
      organization: organization,
      auditor: auditor,
      scheduled-date: scheduled-date
    })

    (ok audit-id)
  )
)

(define-public (start-audit (audit-id uint))
  (let
    (
      (audit (unwrap! (map-get? compliance-audits { audit-id: audit-id }) ERR_NOT_FOUND))
      (current-time (unwrap-panic (get-block-info? time (- block-height u1))))
    )
    (asserts! (is-eq tx-sender (get auditor audit)) ERR_UNAUTHORIZED)
    (asserts! (is-eq (get status audit) "scheduled") ERR_INVALID_INPUT)

    (map-set compliance-audits
      { audit-id: audit-id }
      (merge audit { status: "in-progress" })
    )

    (print {
      event: "audit-started",
      audit-id: audit-id,
      auditor: tx-sender
    })

    (ok true)
  )
)

(define-public (add-finding
  (audit-id uint)
  (finding-type (string-ascii 50))
  (severity uint)
  (description (string-ascii 500))
  (recommendation (string-ascii 300)))
  (let
    (
      (audit (unwrap! (map-get? compliance-audits { audit-id: audit-id }) ERR_NOT_FOUND))
      (finding-id (+ (get findings-count audit) u1))
      (current-time (unwrap-panic (get-block-info? time (- block-height u1))))
    )
    (asserts! (is-eq tx-sender (get auditor audit)) ERR_UNAUTHORIZED)
    (asserts! (is-eq (get status audit) "in-progress") ERR_INVALID_INPUT)
    (asserts! (> (len description) u0) ERR_INVALID_INPUT)
    (asserts! (<= severity u5) ERR_INVALID_INPUT)

    (map-set audit-findings
      { audit-id: audit-id, finding-id: finding-id }
      {
        finding-type: finding-type,
        severity: severity,
        description: description,
        recommendation: recommendation,
        status: "open",
        identified-by: tx-sender,
        identified-at: current-time,
        resolved-at: u0
      }
    )

    ;; Update audit findings count
    (map-set compliance-audits
      { audit-id: audit-id }
      (merge audit {
        findings-count: finding-id
      })
    )

    (print {
      event: "finding-added",
      audit-id: audit-id,
      finding-id: finding-id,
      severity: severity,
      type: finding-type
    })

    (ok finding-id)
  )
)

(define-public (submit-audit-evidence
  (audit-id uint)
  (evidence-type (string-ascii 50))
  (evidence-hash (buff 32))
  (description (string-ascii 200)))
  (let
    (
      (audit (unwrap! (map-get? compliance-audits { audit-id: audit-id }) ERR_NOT_FOUND))
      (evidence-id (+ (get findings-count audit) u1))
      (current-time (unwrap-panic (get-block-info? time (- block-height u1))))
    )
    (asserts! (is-eq (get status audit) "in-progress") ERR_INVALID_INPUT)
    (asserts! (> (len description) u0) ERR_INVALID_INPUT)

    (map-set audit-evidence
      { audit-id: audit-id, evidence-id: evidence-id }
      {
        evidence-type: evidence-type,
        evidence-hash: evidence-hash,
        description: description,
        submitted-by: tx-sender,
        verified: false,
        submitted-at: current-time
      }
    )

    (print {
      event: "evidence-submitted",
      audit-id: audit-id,
      evidence-id: evidence-id,
      type: evidence-type,
      submitted-by: tx-sender
    })

    (ok evidence-id)
  )
)

(define-public (verify-evidence
  (audit-id uint)
  (evidence-id uint)
  (is-valid bool))
  (let
    (
      (audit (unwrap! (map-get? compliance-audits { audit-id: audit-id }) ERR_NOT_FOUND))
      (evidence (unwrap! (map-get? audit-evidence { audit-id: audit-id, evidence-id: evidence-id }) ERR_NOT_FOUND))
    )
    (asserts! (is-eq tx-sender (get auditor audit)) ERR_UNAUTHORIZED)

    (map-set audit-evidence
      { audit-id: audit-id, evidence-id: evidence-id }
      (merge evidence { verified: is-valid })
    )

    (print {
      event: "evidence-verified",
      audit-id: audit-id,
      evidence-id: evidence-id,
      valid: is-valid,
      verified-by: tx-sender
    })

    (ok true)
  )
)

(define-public (complete-audit
  (audit-id uint)
  (compliance-score uint)
  (executive-summary (string-ascii 500))
  (detailed-findings (string-ascii 1000))
  (recommendations (string-ascii 500))
  (next-audit-date uint)
  (report-hash (buff 32)))
  (let
    (
      (audit (unwrap! (map-get? compliance-audits { audit-id: audit-id }) ERR_NOT_FOUND))
      (current-time (unwrap-panic (get-block-info? time (- block-height u1))))
    )
    (asserts! (is-eq tx-sender (get auditor audit)) ERR_UNAUTHORIZED)
    (asserts! (is-eq (get status audit) "in-progress") ERR_INVALID_INPUT)
    (asserts! (<= compliance-score u100) ERR_INVALID_INPUT)

    ;; Update audit status
    (map-set compliance-audits
      { audit-id: audit-id }
      (merge audit {
        completion-date: current-time,
        status: "completed",
        compliance-score: compliance-score
      })
    )

    ;; Create audit report
    (map-set audit-reports
      { audit-id: audit-id }
      {
        executive-summary: executive-summary,
        detailed-findings: detailed-findings,
        recommendations: recommendations,
        next-audit-date: next-audit-date,
        report-hash: report-hash,
        published-at: current-time
      }
    )

    (print {
      event: "audit-completed",
      audit-id: audit-id,
      compliance-score: compliance-score,
      completed-by: tx-sender
    })

    (ok true)
  )
)

;; Read-only Functions
(define-read-only (get-audit (audit-id uint))
  (map-get? compliance-audits { audit-id: audit-id })
)

(define-read-only (get-finding (audit-id uint) (finding-id uint))
  (map-get? audit-findings { audit-id: audit-id, finding-id: finding-id })
)

(define-read-only (get-evidence (audit-id uint) (evidence-id uint))
  (map-get? audit-evidence { audit-id: audit-id, evidence-id: evidence-id })
)

(define-read-only (get-audit-report (audit-id uint))
  (map-get? audit-reports { audit-id: audit-id })
)

(define-read-only (get-auditor-schedule (auditor principal))
  (map-get? audit-schedules auditor)
)

(define-read-only (is-authorized-auditor (auditor principal))
  (default-to false (map-get? authorized-auditors auditor))
)

(define-read-only (get-audit-fee)
  (var-get audit-fee)
)

(define-read-only (get-next-audit-id)
  (var-get next-audit-id)
)
