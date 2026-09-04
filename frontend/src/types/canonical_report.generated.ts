/* Generated from canonical_report.schema.json. Do not edit. */

export type Code = string;
export type Reason = string;
/**
 * @maxItems 256
 */
export type Items = AdvisoryItem[];
export type Present = boolean;
/**
 * @maxItems 64
 */
export type Notes = string[];
export type Present1 = boolean;
export type CaptureDurationSeconds = number | null;
export type CaptureStartTime = string | null;
export type FileTimePrecision = string;
export type OriginalPacketBytes = number | null;
export type PacketCount = number;
export type PacketSizeLimit = number | null;
export type PacketSizeLimitMaxInferred = number | null;
export type PacketSizeLimitMinInferred = number | null;
export type TruncatedPacketsPresent = boolean;
export type ChainIndex = number;
export type DerSha256 = string;
export type EffectiveStrengthBits = number | null;
/**
 * Mandatory visibility/confidence state for every applicable evidence field.
 */
export type EvidenceState =
  "observed" | "verified" | "inferred" | "incomplete" | "conflicting" | "not_observable" | "indeterminate";
export type ExpiresWithinWarningWindow = boolean | null;
export type Issuer = string | null;
export type NotAfter = string | null;
export type NotBefore = string | null;
export type PublicKeyAlgorithm = string | null;
export type PublicKeyCurve = string | null;
export type PublicKeySize = number | null;
/**
 * Whether the certificate was offered by the TLS server or the client.
 */
export type CertificateRole = "server" | "client";
export type SerialNumber = string | null;
export type SignatureAlgorithm = string | null;
export type SourceFrames = number[];
export type Subject = string | null;
export type SyntaxError = string | null;
export type SyntaxValid = boolean;
export type Uid = string;
export type ValidAtAnalysisTime = boolean | null;
export type ValidAtCaptureTime = boolean | null;
export type CertificateObserved = boolean;
export type IdentityMatch = boolean | null;
/**
 * @maxItems 8
 */
export type IdentityMismatchReasons =
  | []
  | [string]
  | [string, string]
  | [string, string, string]
  | [string, string, string, string]
  | [string, string, string, string, string]
  | [string, string, string, string, string, string]
  | [string, string, string, string, string, string, string]
  | [string, string, string, string, string, string, string, string];
/**
 * @maxItems 8
 */
export type IndeterminateReasons =
  | []
  | [string]
  | [string, string]
  | [string, string, string]
  | [string, string, string, string]
  | [string, string, string, string, string]
  | [string, string, string, string, string, string]
  | [string, string, string, string, string, string, string]
  | [string, string, string, string, string, string, string, string];
/**
 * @maxItems 8
 */
export type PathInvalidReasonsAtAnalysisTime =
  | []
  | [string]
  | [string, string]
  | [string, string, string]
  | [string, string, string, string]
  | [string, string, string, string, string]
  | [string, string, string, string, string, string]
  | [string, string, string, string, string, string, string]
  | [string, string, string, string, string, string, string, string];
/**
 * @maxItems 8
 */
export type PathInvalidReasonsAtCaptureTime =
  | []
  | [string]
  | [string, string]
  | [string, string, string]
  | [string, string, string, string]
  | [string, string, string, string, string]
  | [string, string, string, string, string, string]
  | [string, string, string, string, string, string, string]
  | [string, string, string, string, string, string, string, string];
export type PathValidAtAnalysisTime = boolean | null;
export type PathValidAtCaptureTime = boolean | null;
export type ReferenceIdentity = string | null;
/**
 * Where the hostname/IP used for identity matching came from.
 */
export type ReferenceIdentitySource = "sni" | "configured";
/**
 * Revocation outcome. Without imported OCSP/CRL evidence this is unknown.
 */
export type RevocationStatus = "good" | "revoked" | "unknown" | "stale";
export type SyntaxValid1 = boolean | null;
export type TrustProfileId = string;
export type TrustStoreDigest = string;
export type Certificates = CertificateEvidence[];
export type AffectedEndpoint = string;
export type Code1 = string;
export type FieldPath = string;
export type FrameNumber = number | null;
export type RecordKey = string;
export type EvidenceRecordType = "flow" | "session" | "handshake" | "certificate";
/**
 * @maxItems 32
 */
export type EvidenceReferences = EvidenceReference[];
export type FindingId = string;
/**
 * Serialized policy outcomes. Pass/present results are not emitted as findings.
 */
export type FindingOutcome = "negative" | "indeterminate";
export type PolicyEvaluationTime = string;
export type PolicyPackVersion = string;
export type PolicyProfile = string;
export type Rationale = string;
export type RemediationId = string;
export type RuleEffectiveFrom = string;
export type RuleEffectiveUntil = string | null;
export type FindingSeverity = "high" | "medium" | "low" | "informational";
/**
 * @maxItems 8
 */
export type Standards =
  | []
  | [string]
  | [string, string]
  | [string, string, string]
  | [string, string, string, string]
  | [string, string, string, string, string]
  | [string, string, string, string, string, string]
  | [string, string, string, string, string, string, string]
  | [string, string, string, string, string, string, string, string];
export type Title = string;
export type Findings = Finding[];
export type StreamDirection = "orig" | "resp";
export type End = number;
export type Exact = boolean;
export type Start = number;
export type ConflictingByteRanges = ByteRange[];
export type ConnState = string;
export type GapBytes = number;
export type GapBytesExact = boolean;
export type History = string;
export type MissedBytes = number;
/**
 * Recoverable transport facts that do not by themselves degrade quality.
 */
export type ObservedCondition = "out_of_order_segments" | "duplicate_segments";
export type ObservedConditions = ObservedCondition[];
export type Host = string;
export type Port = number;
export type OrigBytes = number;
export type Proto = "tcp" | "udp" | "icmp" | "icmp6" | "unknown";
/**
 * Machine-readable primary reason when quality is not complete.
 */
export type ReconstructionReasonCode =
  | "missing_syn"
  | "missing_fin"
  | "midstream_start"
  | "snaplen_truncation"
  | "overlapping_retransmission_conflict"
  | "segment_gap"
  | "capture_loss";
/**
 * Stream-reconstruction outcome. Distinct from `EvidenceState`.
 */
export type ReconstructionQuality = "complete" | "incomplete" | "conflicting";
export type RespBytes = number;
export type Uid1 = string;
export type Flows = Flow[];
export type Algorithm = string | null;
export type Code2 = string | null;
export type Name = string | null;
export type Established = boolean;
export type HelloRetryRequest = boolean;
export type DhParamSize = number | null;
export type Mechanism = string | null;
export type PskKeyExchangeModes = string[];
export type SelectedGroup = string | null;
export type SelectedGroupCode = number | null;
export type SourceFields = string[];
export type LastAlert = string | null;
export type FrameNumber1 = number | null;
export type HistoryLetter = string;
/**
 * Handshake/record kinds reconstructed from Zeek `ssl_history` letters.
 */
export type HandshakeMessageKind =
  | "direction_flip"
  | "hello_request"
  | "client_hello"
  | "server_hello"
  | "hello_retry_request"
  | "hello_verify_request"
  | "new_session_ticket"
  | "end_of_early_data"
  | "encrypted_extensions"
  | "certificate"
  | "server_key_exchange"
  | "certificate_request"
  | "server_hello_done"
  | "certificate_verify"
  | "client_key_exchange"
  | "finished"
  | "certificate_url"
  | "certificate_status"
  | "supplemental_data"
  | "key_update"
  | "message_hash"
  | "change_cipher_spec"
  | "alert"
  | "heartbeat"
  | "unknown";
export type Messages = HandshakeMessage[];
export type Resumed = boolean;
export type SslHistory = string;
export type Uid2 = string;
export type ClientSupportedVersions = string[];
export type LegacyRecordVersion = string | null;
export type Selected = string | null;
export type ServerSupportedVersion = string | null;
/**
 * Where the selected TLS version was taken from. Never ClientHello offers.
 */
export type VersionSource = "supported_versions" | "legacy_record";
/**
 * How much of the handshake is passively visible.
 */
export type HandshakeVisibility = "full" | "partial" | "not_observable";
export type Handshakes = TlsHandshake[];
export type AffectedEndpoint1 = string;
export type CheckCategory = "transport" | "mail_protocol" | "tls_handshake" | "certificate";
export type CheckId = string;
export type Code3 = string;
export type PolicyCheckOutcome = "pass" | "fail" | "unknown" | "not_observable";
export type CoverageProtocol = "smtp" | "imap" | "pop3" | "unclassified";
export type RecordKey1 = string;
export type Title1 = string;
/**
 * @maxItems 16384
 */
export type PolicyChecks = PolicyCheck[];
export type AssessmentState = "complete" | "limited" | "none";
export type ApplicableCount = number;
export type FailedCount = number;
export type NotObservableCount = number;
export type PassedCount = number;
export type UnknownCount = number;
export type AffectedEndpoint2 = string;
export type AssetCriticality = "critical" | "high" | "medium" | "low" | "unknown";
export type BlastRadius = "organization" | "multi_asset" | "single_endpoint" | "unknown";
export type Code4 = string;
export type AssetCriticality1 = number;
export type BlastRadius1 = number;
export type Confidence = number;
export type Exposure = number;
export type Recurrence = number;
export type Severity = number;
/**
 * @minItems 1
 * @maxItems 4096
 */
export type ContributingFindingIds = [string, ...string[]];
/**
 * @minItems 1
 * @maxItems 4096
 */
export type ContributingOccurrences = [OccurrenceRef, ...OccurrenceRef[]];
export type FindingId1 = string;
export type RecordKey2 = string;
export type SessionUid = string | null;
/**
 * @maxItems 1024
 */
export type EvidenceReferences1 = EvidenceReference[];
export type ExposureClass = "public" | "partner" | "internal" | "isolated" | "unknown";
export type FindingId2 = string;
export type PolicyEvaluationTime1 = string;
export type PolicyPackVersion1 = string;
export type PolicyProfile1 = string;
export type Rationale1 = string;
export type RecurrenceCount = number;
export type RemediationId1 = string;
export type RuleEffectiveFrom1 = string;
export type RuleEffectiveUntil1 = string | null;
export type Score = number;
export type ScoringSchemaVersion = "securemail.scoring/v1";
/**
 * @maxItems 8
 */
export type Standards1 =
  | []
  | [string]
  | [string, string]
  | [string, string, string]
  | [string, string, string, string]
  | [string, string, string, string, string]
  | [string, string, string, string, string, string]
  | [string, string, string, string, string, string, string]
  | [string, string, string, string, string, string, string, string];
export type Title2 = string;
export type UniqueOccurrences = number;
/**
 * @maxItems 4096
 */
export type PrioritizedFindings = ScoredEndpointFinding[];
export type RiskScore = number | null;
export type SchemaVersion = "securemail.posture/v1";
export type ScoringSchemaVersion1 = "securemail.scoring/v1";
export type AnalysisTime = string;
export type AnalyzerBundleDigest = string;
export type CaptureSha256 = string;
export type ConfigurationDigest = string;
export type NormalizationSchemaVersion = "v1";
export type PolicyPackVersion2 = string;
/**
 * Built-in Step 7 policy packs. Organization packs are deferred.
 */
export type PolicyProfile2 = "ietf_current" | "nist_federal" | "historical_at_capture";
export type TrustStoreDigest1 = string | null;
export type SchemaVersion1 = "v2";
export type Corroboration = "zeek" | "zeek+tshark";
export type Argument = string | null;
export type Command = string | null;
export type FrameNumber2 = number | null;
/**
 * Bounded protocol-event kinds recorded on an `EmailSession`.
 */
export type SessionEventKind =
  "request" | "reply" | "capability" | "starttls" | "confirmation" | "ambiguous_banner" | "unexpected";
export type ReplyCode = number | null;
/**
 * Analyzer that produced a protocol observation.
 */
export type EventSource = "zeek" | "tshark" | "ssl";
export type Tag = string | null;
export type Text = string | null;
export type Events = ProtocolEvent[];
export type DowngradeConsistent = boolean;
export type EvidenceFrames = number[];
/**
 * Terminal STARTTLS/STLS state-machine outcome.
 */
export type UpgradeState =
  "advertised" | "requested" | "accepted" | "tls_established" | "plaintext_fallback" | "violation";
export type IdentificationConfidence = number | null;
/**
 * Resolved application protocol. Distinct from `port_hint`.
 */
export type MailProtocol = "smtp" | "imap" | "pop3";
export type EvidenceFrames1 = number[];
export type Source = ("alpn" | "none") | null;
/**
 * Protocol identity derived from payload / analyzer events, not ports.
 */
export type PayloadEvidence = "smtp" | "imap" | "pop3" | "indeterminate" | "none";
/**
 * Well-known-port inference only. Never used as protocol proof.
 */
export type PortHint = "smtp" | "imap" | "pop3" | "none";
export type Uid3 = string;
export type Sessions = EmailSession[];
/**
 * @maxItems 64
 */
export type Exceptions = string[];
export type ConflictingFlowCount = number;
export type IncompleteFlowCount = number;
export type NotObservableCertificateCount = number;
export type NotObservableCheckCount = number;
/**
 * @maxItems 32
 */
export type Notes1 = string[];
export type TruncatedPacketsPresent1 = boolean;
export type UnknownCheckCount = number;
export type AnalysisRunId = string | null;
export type AnalyzerBundleDigest1 = string;
/**
 * Whether a requested provenance field could be populated from evidence.
 */
export type Availability = "present" | "unavailable" | "not_applicable";
export type Name1 = string;
export type Sha256 = string | null;
/**
 * @maxItems 32
 */
export type ArtifactHashes = ArtifactHash[];
export type CaptureId = string | null;
export type CaseId = string | null;
export type ConfigurationDigest1 = string;
export type GeneratedAt = string;
export type OsContainer = string | null;
export type PolicyPackVersion3 = string;
export type PolicyProfile3 = string;
export type FindingCount = number;
export type NotObservableCount1 = number;
export type RiskScore1 = number | null;
export type UnknownCount1 = number;
export type RandomSeed = string | null;
/**
 * @minItems 1
 * @maxItems 16
 */
export type Fonts =
  | [FontResource]
  | [FontResource, FontResource]
  | [FontResource, FontResource, FontResource]
  | [FontResource, FontResource, FontResource, FontResource]
  | [FontResource, FontResource, FontResource, FontResource, FontResource]
  | [FontResource, FontResource, FontResource, FontResource, FontResource, FontResource]
  | [FontResource, FontResource, FontResource, FontResource, FontResource, FontResource, FontResource]
  | [FontResource, FontResource, FontResource, FontResource, FontResource, FontResource, FontResource, FontResource]
  | [
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource
    ]
  | [
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource
    ]
  | [
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource
    ]
  | [
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource
    ]
  | [
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource
    ]
  | [
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource
    ]
  | [
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource
    ]
  | [
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource,
      FontResource
    ];
export type Family = string;
export type Filename = string;
export type Sha2561 = string;
export type Style = "normal" | "italic";
export type Weight = number;
export type HtmlRenderer = "securemail.html/v1";
export type PdfRenderer = "weasyprint";
export type PdfRendererVersion = string;
export type TemplateName = "report.html.j2";
export type TemplateSha256 = string;
export type SchemaVersion2 = "securemail.report/v1";
export type Algorithm1 = string | null;
export type Availability1 = "unavailable";
export type Timestamp = string | null;
export type SourceCaptureSha256 = string;
/**
 * @minItems 1
 * @maxItems 16
 */
export type SourceRecords =
  | [SourceRecord]
  | [SourceRecord, SourceRecord]
  | [SourceRecord, SourceRecord, SourceRecord]
  | [SourceRecord, SourceRecord, SourceRecord, SourceRecord]
  | [SourceRecord, SourceRecord, SourceRecord, SourceRecord, SourceRecord]
  | [SourceRecord, SourceRecord, SourceRecord, SourceRecord, SourceRecord, SourceRecord]
  | [SourceRecord, SourceRecord, SourceRecord, SourceRecord, SourceRecord, SourceRecord, SourceRecord]
  | [SourceRecord, SourceRecord, SourceRecord, SourceRecord, SourceRecord, SourceRecord, SourceRecord, SourceRecord]
  | [
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord
    ]
  | [
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord
    ]
  | [
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord
    ]
  | [
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord
    ]
  | [
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord
    ]
  | [
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord
    ]
  | [
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord
    ]
  | [
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord,
      SourceRecord
    ];
export type Identifier = string | null;
export type SourceRecordKind = "case" | "capture" | "analysis_run";
export type Timezone = "UTC";
export type TrustStoreDigest2 = string | null;
export type WorkingCopySha256 = string | null;
export type SchemaVersion3 = "securemail.report/v1";
export type Message = string;
export type Stage = string;
/**
 * @maxItems 256
 */
export type StageErrors = StageError[];
/**
 * @maxItems 256
 */
export type SuppressedFindings = Finding[];

/**
 * Authoritative report object. HTML and PDF are presentations of this model.
 */
export interface CanonicalReport {
  advisory?: AdvisorySection;
  analyst_conclusions?: AnalystSection;
  evidence: EvidenceDocument;
  exceptions?: Exceptions;
  limitations: CaptureLimitations;
  manifest: ReportManifest;
  schema_version?: SchemaVersion3;
  stage_errors?: StageErrors;
  suppressed_findings?: SuppressedFindings;
}
/**
 * Shadow-mode ML output. Empty unless `report --advisory` ran.
 */
export interface AdvisorySection {
  items?: Items;
  present?: Present;
}
/**
 * One shadow-mode ML item shown in the Advisory / ML report section.
 */
export interface AdvisoryItem {
  code: Code;
  reason: Reason;
}
export interface AnalystSection {
  notes?: Notes;
  present?: Present1;
}
/**
 * v2 canonical JSON envelope produced by `securemail analyze`.
 */
export interface EvidenceDocument {
  capture_preflight: CapturePreflight;
  certificates?: Certificates;
  findings?: Findings;
  flows?: Flows;
  handshakes?: Handshakes;
  policy_checks?: PolicyChecks;
  posture: PostureAssessment;
  run_identity: AnalysisRun;
  schema_version?: SchemaVersion1;
  sessions?: Sessions;
}
/**
 * capinfos facts recorded before any analyzer mutates a working copy.
 */
export interface CapturePreflight {
  capture_duration_seconds?: CaptureDurationSeconds;
  capture_start_time?: CaptureStartTime;
  file_time_precision: FileTimePrecision;
  original_packet_bytes?: OriginalPacketBytes;
  packet_count: PacketCount;
  packet_size_limit?: PacketSizeLimit;
  packet_size_limit_max_inferred?: PacketSizeLimitMaxInferred;
  packet_size_limit_min_inferred?: PacketSizeLimitMinInferred;
  truncated_packets_present: TruncatedPacketsPresent;
}
/**
 * One extracted X.509 certificate. Path/identity live on `validation` for leaves.
 */
export interface CertificateEvidence {
  chain_index: ChainIndex;
  der_sha256: DerSha256;
  effective_strength_bits?: EffectiveStrengthBits;
  evidence_state: EvidenceState;
  expires_within_warning_window?: ExpiresWithinWarningWindow;
  issuer?: Issuer;
  not_after?: NotAfter;
  not_before?: NotBefore;
  public_key_algorithm?: PublicKeyAlgorithm;
  public_key_curve?: PublicKeyCurve;
  public_key_size?: PublicKeySize;
  role: CertificateRole;
  serial_number?: SerialNumber;
  signature_algorithm?: SignatureAlgorithm;
  source_frames?: SourceFrames;
  subject?: Subject;
  syntax_error?: SyntaxError;
  syntax_valid: SyntaxValid;
  uid: Uid;
  valid_at_analysis_time?: ValidAtAnalysisTime;
  valid_at_capture_time?: ValidAtCaptureTime;
  validation?: CertificateValidation | null;
}
/**
 * Independent chain and identity outcomes. Attached to server leaves only.
 */
export interface CertificateValidation {
  certificate_observed: CertificateObserved;
  identity_match?: IdentityMatch;
  identity_mismatch_reasons?: IdentityMismatchReasons;
  indeterminate_reasons?: IndeterminateReasons;
  path_invalid_reasons_at_analysis_time?: PathInvalidReasonsAtAnalysisTime;
  path_invalid_reasons_at_capture_time?: PathInvalidReasonsAtCaptureTime;
  path_valid_at_analysis_time?: PathValidAtAnalysisTime;
  path_valid_at_capture_time?: PathValidAtCaptureTime;
  reference_identity?: ReferenceIdentity;
  reference_identity_source?: ReferenceIdentitySource | null;
  revocation_status: RevocationStatus;
  syntax_valid?: SyntaxValid1;
  trust_profile_id: TrustProfileId;
  trust_store_digest: TrustStoreDigest;
}
/**
 * Deterministic policy judgment. Never mutates the underlying evidence.
 */
export interface Finding {
  affected_endpoint: AffectedEndpoint;
  basis_state: EvidenceState;
  code: Code1;
  evaluation_state: EvidenceState;
  evidence_references?: EvidenceReferences;
  finding_id: FindingId;
  outcome: FindingOutcome;
  policy_evaluation_time: PolicyEvaluationTime;
  policy_pack_version: PolicyPackVersion;
  policy_profile: PolicyProfile;
  rationale: Rationale;
  remediation_id: RemediationId;
  rule_effective_from: RuleEffectiveFrom;
  rule_effective_until?: RuleEffectiveUntil;
  severity: FindingSeverity;
  standards?: Standards;
  title: Title;
}
/**
 * Canonical pointer at a contributing evidence field. No JSON array indexes.
 */
export interface EvidenceReference {
  evidence_state: EvidenceState;
  field_path: FieldPath;
  frame_number?: FrameNumber;
  record_key: RecordKey;
  record_type: EvidenceRecordType;
}
/**
 * Canonical per-connection evidence derived from Zeek `conn.log` plus recon facts.
 */
export interface Flow {
  conflicting_byte_ranges?: ConflictingByteRanges;
  conn_state: ConnState;
  evidence_state: EvidenceState;
  gap_bytes: GapBytes;
  gap_bytes_exact?: GapBytesExact;
  history: History;
  missed_bytes: MissedBytes;
  observed_conditions?: ObservedConditions;
  orig: FlowEndpoint;
  orig_bytes: OrigBytes;
  proto: Proto;
  reason_code?: ReconstructionReasonCode | null;
  reconstruction_quality: ReconstructionQuality;
  resp: FlowEndpoint;
  resp_bytes: RespBytes;
  uid: Uid1;
}
/**
 * Half-open `[start, end)` range in relative TCP sequence space.
 */
export interface ByteRange {
  direction: StreamDirection;
  end: End;
  exact?: Exact;
  start: Start;
}
export interface FlowEndpoint {
  host: Host;
  port: Port;
}
/**
 * TLS handshake record linked to a `Flow` by Zeek `uid`.
 */
export interface TlsHandshake {
  certificate_verify_signature: HandshakeSignatureEvidence;
  certificate_verify_state: EvidenceState;
  cipher_suite: CipherSuiteEvidence;
  established: Established;
  evidence_state: EvidenceState;
  hello_retry_request: HelloRetryRequest;
  key_exchange: KeyExchangeEvidence;
  last_alert?: LastAlert;
  messages?: Messages;
  resumed: Resumed;
  server_certificate_state: EvidenceState;
  ssl_history: SslHistory;
  uid: Uid2;
  version: TlsVersionEvidence;
  visibility: HandshakeVisibility;
}
/**
 * TLS handshake CertificateVerify signature algorithm, not the X.509 cert signature.
 */
export interface HandshakeSignatureEvidence {
  algorithm?: Algorithm;
  evidence_state: EvidenceState;
}
/**
 * Selected cipher suite identified by canonical IANA name and hex code.
 */
export interface CipherSuiteEvidence {
  code?: Code2;
  evidence_state: EvidenceState;
  name?: Name;
}
/**
 * Version-aware key-exchange classification. No weakness or FS judgment.
 */
export interface KeyExchangeEvidence {
  dh_param_size?: DhParamSize;
  evidence_state: EvidenceState;
  mechanism?: Mechanism;
  psk_key_exchange_modes?: PskKeyExchangeModes;
  selected_group?: SelectedGroup;
  selected_group_code?: SelectedGroupCode;
  source_fields?: SourceFields;
}
/**
 * One evidence-linked handshake or record message.
 */
export interface HandshakeMessage {
  direction: StreamDirection;
  evidence_state: EvidenceState;
  frame_number?: FrameNumber1;
  history_letter: HistoryLetter;
  kind: HandshakeMessageKind;
}
/**
 * Negotiated version. `supported_versions` wins over the legacy record version.
 */
export interface TlsVersionEvidence {
  client_supported_versions?: ClientSupportedVersions;
  evidence_state: EvidenceState;
  legacy_record_version?: LegacyRecordVersion;
  selected?: Selected;
  server_supported_version?: ServerSupportedVersion;
  source?: VersionSource | null;
}
/**
 * One applicable policy evaluation. Genuine non-applicability is omitted.
 */
export interface PolicyCheck {
  affected_endpoint: AffectedEndpoint1;
  category: CheckCategory;
  check_id: CheckId;
  code: Code3;
  evidence_state: EvidenceState;
  outcome: PolicyCheckOutcome;
  protocol: CoverageProtocol;
  record_key: RecordKey1;
  record_type: EvidenceRecordType;
  title: Title1;
}
export interface PostureAssessment {
  assessment_state: AssessmentState;
  coverage: CoverageMatrix;
  prioritized_findings?: PrioritizedFindings;
  risk_score?: RiskScore;
  schema_version?: SchemaVersion;
  scoring_schema_version?: ScoringSchemaVersion1;
}
export interface CoverageMatrix {
  by_category?: ByCategory;
  by_protocol?: ByProtocol;
  by_protocol_and_category?: ByProtocolAndCategory;
  overall: CoverageCounts;
}
export interface ByCategory {
  [k: string]: CoverageCounts;
}
export interface CoverageCounts {
  applicable_count: ApplicableCount;
  failed_count: FailedCount;
  not_observable_count: NotObservableCount;
  passed_count: PassedCount;
  unknown_count: UnknownCount;
}
export interface ByProtocol {
  [k: string]: CoverageCounts;
}
export interface ByProtocolAndCategory {
  [k: string]: {
    [k: string]: CoverageCounts;
  };
}
/**
 * Prioritized endpoint finding with named score components.
 */
export interface ScoredEndpointFinding {
  affected_endpoint: AffectedEndpoint2;
  asset_criticality: AssetCriticality;
  basis_state: EvidenceState;
  blast_radius: BlastRadius;
  code: Code4;
  components: ScoreComponents;
  contributing_finding_ids: ContributingFindingIds;
  contributing_occurrences: ContributingOccurrences;
  evaluation_state: EvidenceState;
  evidence_references?: EvidenceReferences1;
  exposure: ExposureClass;
  finding_id: FindingId2;
  outcome: FindingOutcome;
  policy_evaluation_time: PolicyEvaluationTime1;
  policy_pack_version: PolicyPackVersion1;
  policy_profile: PolicyProfile1;
  rationale: Rationale1;
  recurrence_count: RecurrenceCount;
  remediation_id: RemediationId1;
  rule_effective_from: RuleEffectiveFrom1;
  rule_effective_until?: RuleEffectiveUntil1;
  score: Score;
  scoring_schema_version?: ScoringSchemaVersion;
  severity: FindingSeverity;
  standards?: Standards1;
  title: Title2;
  unique_occurrences: UniqueOccurrences;
}
/**
 * Hand-computable addends. Sum is the published score (naturally ≤ 100).
 */
export interface ScoreComponents {
  asset_criticality: AssetCriticality1;
  blast_radius: BlastRadius1;
  confidence: Confidence;
  exposure: Exposure;
  recurrence: Recurrence;
  severity: Severity;
}
/**
 * One contributing session-level finding. Evidence is retained, not dropped.
 */
export interface OccurrenceRef {
  finding_id: FindingId1;
  record_key: RecordKey2;
  record_type: EvidenceRecordType;
  session_uid?: SessionUid;
}
/**
 * Identity record for one analysis of one capture.
 */
export interface AnalysisRun {
  analysis_time: AnalysisTime;
  analyzer_bundle_digest: AnalyzerBundleDigest;
  capture_sha256: CaptureSha256;
  configuration_digest: ConfigurationDigest;
  normalization_schema_version: NormalizationSchemaVersion;
  policy_pack_version: PolicyPackVersion2;
  policy_profile: PolicyProfile2;
  trust_store_digest?: TrustStoreDigest1;
}
/**
 * Protocol-tagged session with independent port and payload fields.
 */
export interface EmailSession {
  corroboration?: Corroboration;
  events?: Events;
  evidence_state: EvidenceState;
  explicit_upgrade?: ExplicitUpgrade | null;
  identification_confidence?: IdentificationConfidence;
  implicit_tls?: ImplicitTls | null;
  payload_evidence: PayloadEvidence;
  port_hint: PortHint;
  protocol?: MailProtocol | null;
  uid: Uid3;
}
/**
 * One redacted, length-bounded command/response/capability observation.
 */
export interface ProtocolEvent {
  argument?: Argument;
  command?: Command;
  direction: StreamDirection;
  frame_number?: FrameNumber2;
  kind: SessionEventKind;
  reply_code?: ReplyCode;
  source?: EventSource | null;
  tag?: Tag;
  text?: Text;
}
/**
 * STARTTLS/STLS assessment. `downgrade_consistent` is never proof of attack.
 */
export interface ExplicitUpgrade {
  downgrade_consistent?: DowngradeConsistent;
  evidence_frames?: EvidenceFrames;
  evidence_state: EvidenceState;
  state?: UpgradeState | null;
}
/**
 * Implicit-TLS correlation. Port alone never sets `correlated_protocol`.
 */
export interface ImplicitTls {
  correlated_protocol?: MailProtocol | null;
  evidence_frames?: EvidenceFrames1;
  evidence_state: EvidenceState;
  source?: Source;
}
/**
 * Visibility and reconstruction limits that must not be read as a pass.
 */
export interface CaptureLimitations {
  conflicting_flow_count: ConflictingFlowCount;
  incomplete_flow_count: IncompleteFlowCount;
  not_observable_certificate_count: NotObservableCertificateCount;
  not_observable_check_count: NotObservableCheckCount;
  notes?: Notes1;
  truncated_packets_present: TruncatedPacketsPresent1;
  unknown_check_count: UnknownCheckCount;
}
/**
 * Provenance wrapper around one `EvidenceDocument`.
 */
export interface ReportManifest {
  analysis_run_id?: AnalysisRunId;
  analyzer_bundle_digest: AnalyzerBundleDigest1;
  artifact_hashes?: ArtifactHashes;
  capture_id?: CaptureId;
  case_id?: CaseId;
  configuration_digest: ConfigurationDigest1;
  dependency_versions?: DependencyVersions;
  generated_at: GeneratedAt;
  os_container?: OsContainer;
  os_container_availability: Availability;
  policy_pack_version: PolicyPackVersion3;
  policy_profile: PolicyProfile3;
  posture_summary: PostureSummary;
  random_seed?: RandomSeed;
  renderer: RendererManifest;
  schema_version?: SchemaVersion2;
  signature: SignatureMetadata;
  source_capture_sha256: SourceCaptureSha256;
  source_records: SourceRecords;
  timezone?: Timezone;
  trust_store_digest?: TrustStoreDigest2;
  working_copy_availability: Availability;
  working_copy_sha256?: WorkingCopySha256;
}
/**
 * Named content hash. `sha256` is required only when `availability` is present.
 */
export interface ArtifactHash {
  availability: Availability;
  name: Name1;
  sha256?: Sha256;
}
export interface DependencyVersions {
  [k: string]: string;
}
/**
 * Headline posture copied from `evidence.posture`. Not independently scored.
 */
export interface PostureSummary {
  assessment_state: AssessmentState;
  finding_count: FindingCount;
  not_observable_count: NotObservableCount1;
  risk_score?: RiskScore1;
  unknown_count: UnknownCount1;
}
/**
 * How this JSON is turned into HTML/PDF. Upgrade these pins deliberately.
 */
export interface RendererManifest {
  fonts: Fonts;
  html_renderer?: HtmlRenderer;
  pdf_renderer?: PdfRenderer;
  pdf_renderer_version: PdfRendererVersion;
  template_name?: TemplateName;
  template_sha256: TemplateSha256;
}
/**
 * Pinned bundled font used by HTML and PDF presentation.
 */
export interface FontResource {
  family: Family;
  filename: Filename;
  sha256: Sha2561;
  style?: Style;
  weight: Weight;
}
/**
 * Detached signing/timestamping is out of Step 9; record unavailability.
 */
export interface SignatureMetadata {
  algorithm?: Algorithm1;
  availability?: Availability1;
  timestamp?: Timestamp;
}
/**
 * Identifier for a record the report was assembled from.
 */
export interface SourceRecord {
  availability: Availability;
  identifier?: Identifier;
  kind: SourceRecordKind;
}
/**
 * Inspectable stage failure. Empty when the analysis completed.
 */
export interface StageError {
  evidence_state: EvidenceState;
  message: Message;
  stage: Stage;
}
