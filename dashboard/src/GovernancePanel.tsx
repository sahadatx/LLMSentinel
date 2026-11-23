import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { TableFooter } from "./TableControls";

type PolicyVersion = {
  id: string;
  revision: string;
  sha256: string;
  policy: Record<string, unknown>;
  signature: Record<string, unknown> | null;
  created_by: string;
  created_at: string;
  status: string;
  approved_by: string | null;
  approved_at: string | null;
  activated_at: string | null;
  dry_run_complete?: boolean;
};
type Incident = {
  id: string;
  tenant_id: string;
  title: string;
  summary: string;
  severity: string;
  status: string;
  assignee: string | null;
  created_at: string;
  updated_at: string;
  activity: { at: string; actor: string; action: string; status: string; assignee?: string | null; comment?: string }[];
};
type Sample = {
  id: string;
  category: string;
  prompt: string;
  expected_disposition: "allow" | "block";
  attack_family: string;
  technique: string;
  language: string;
  source: string;
  review_status: string;
  split: "train" | "validation" | "holdout";
  label_version: string;
  reviewer: string | null;
  reviewed_at: string | null;
  review_count: number;
  inter_reviewer_agreement: number | null;
};
type ApiKey = {
  id: string;
  tenant_id: string;
  role: string;
  name: string;
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
};
type Props = { section: "policies" | "incidents" | "evaluations" | "identity"; apiUrl: string; token: string };

const TAXONOMY: Record<string, { disposition: "allow" | "block"; family: string; technique: string }> = {
  benign: { disposition: "allow", family: "benign", technique: "none" },
  "prompt-injection": { disposition: "block", family: "prompt_injection", technique: "direct_instruction_override" },
  "secret-disclosure": { disposition: "block", family: "sensitive_information_disclosure", technique: "direct_exfiltration_request" },
  "roleplay-injection": { disposition: "block", family: "prompt_injection", technique: "roleplay_jailbreak" },
  "developer-override": { disposition: "block", family: "prompt_injection", technique: "developer_role_override" },
  "encoded-injection": { disposition: "block", family: "prompt_injection", technique: "encoded_instruction_payload" },
};

async function api<T>(url: string, token: string, init?: RequestInit): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 15_000);
  try {
    const response = await fetch(url, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...init?.headers,
      },
      credentials: "omit",
      cache: "no-store",
      signal: controller.signal,
    });
    const text = await response.text();
    let payload: unknown = null;
    try { payload = text ? JSON.parse(text) : null; } catch { payload = text; }
    if (!response.ok) {
      const rawDetail = typeof payload === "object" && payload && "detail" in payload
        ? (payload as { detail: unknown }).detail
        : null;
      const detail = Array.isArray(rawDetail)
        ? rawDetail.map((item) => isRecord(item) ? String(item.msg ?? item.type ?? "Invalid value") : String(item)).join(" · ")
        : typeof rawDetail === "string" ? rawDetail : `Gateway returned HTTP ${response.status}`;
      throw new Error(detail);
    }
    return payload as T;
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === "AbortError") throw new Error("Gateway control request timed out after 15 seconds.");
    throw cause;
  } finally {
    window.clearTimeout(timeout);
  }
}

function PanelHeader({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: ReactNode }) {
  return <div className="governance-heading"><div><div className="eyebrow">{eyebrow}</div><h2>{title}</h2><p>{description}</p></div>{action}</div>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function formatRate(value: unknown): string {
  return typeof value === "number" && Number.isFinite(value) ? `${(value * 100).toFixed(1)}%` : "—";
}

function formatTime(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function KpiCard({ label, value, note, tone = "", available = true }: { label: string; value: string | number; note: string; tone?: string; available?: boolean }) {
  const displayValue = available ? value : "—";
  return <article className={`governance-kpi ${tone}`}><span>{label}</span><strong>{typeof displayValue === "number" ? displayValue.toLocaleString() : displayValue}</strong><small>{available ? note : "Awaiting a successful gateway snapshot"}</small></article>;
}

function StatusTag({ value, tone = "neutral" }: { value: string; tone?: "neutral" | "good" | "warn" | "bad" }) {
  return <span className={`governance-status governance-status-${tone}`}>{value.replaceAll("_", " ")}</span>;
}

export default function GovernancePanel({ section, apiUrl, token }: Props) {
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadedAt, setLoadedAt] = useState<Date | null>(null);
  const [policyVersions, setPolicyVersions] = useState<PolicyVersion[]>([]);
  const [activePolicy, setActivePolicy] = useState<Record<string, unknown> | null>(null);
  const [policyDraft, setPolicyDraft] = useState("");
  const [signatureDraft, setSignatureDraft] = useState("");
  const [policyQuery, setPolicyQuery] = useState("");
  const [policyStatus, setPolicyStatus] = useState("all");
  const [policyPage, setPolicyPage] = useState(1);
  const [policyPageSize, setPolicyPageSize] = useState(10);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [incidentTitle, setIncidentTitle] = useState("");
  const [incidentSummary, setIncidentSummary] = useState("");
  const [incidentSeverity, setIncidentSeverity] = useState("medium");
  const [incidentQuery, setIncidentQuery] = useState("");
  const [incidentStatus, setIncidentStatus] = useState("all");
  const [incidentSeverityFilter, setIncidentSeverityFilter] = useState("all");
  const [incidentPage, setIncidentPage] = useState(1);
  const [incidentPageSize, setIncidentPageSize] = useState(10);
  const [samples, setSamples] = useState<Sample[]>([]);
  const [datasetDigest, setDatasetDigest] = useState("");
  const [holdoutAccess, setHoldoutAccess] = useState(false);
  const [runs, setRuns] = useState<Record<string, unknown>[]>([]);
  const [evaluationResult, setEvaluationResult] = useState<Record<string, unknown> | null>(null);
  const [selectedSampleId, setSelectedSampleId] = useState("");
  const [sampleQuery, setSampleQuery] = useState("");
  const [sampleReviewFilter, setSampleReviewFilter] = useState("all");
  const [samplePage, setSamplePage] = useState(1);
  const [samplePageSize, setSamplePageSize] = useState(15);
  const [runQuery, setRunQuery] = useState("");
  const [runPage, setRunPage] = useState(1);
  const [runPageSize, setRunPageSize] = useState(10);
  const [newSampleId, setNewSampleId] = useState("");
  const [newSamplePrompt, setNewSamplePrompt] = useState("");
  const [newSampleCategory, setNewSampleCategory] = useState("prompt-injection");
  const [newSampleLanguage, setNewSampleLanguage] = useState("en");
  const [newSampleSplit, setNewSampleSplit] = useState("train");
  const [labels, setLabels] = useState({ category: "prompt-injection", expected_disposition: "block", attack_family: "prompt_injection", technique: "direct_instruction_override", language: "en" });
  const [evaluationSplit, setEvaluationSplit] = useState("validation");
  const [reviewedOnly, setReviewedOnly] = useState(false);
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [keyName, setKeyName] = useState("");
  const [keyTenant, setKeyTenant] = useState("");
  const [keyRole, setKeyRole] = useState("user");
  const [keyExpires, setKeyExpires] = useState(90);
  const [keyQuery, setKeyQuery] = useState("");
  const [keyStatus, setKeyStatus] = useState("all");
  const [keyPage, setKeyPage] = useState(1);
  const [keyPageSize, setKeyPageSize] = useState(10);
  const [issuedToken, setIssuedToken] = useState("");
  const [copied, setCopied] = useState(false);

  const url = useCallback((path: string) => `${apiUrl}${path}`, [apiUrl]);
  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      if (section === "policies") {
        const result = await api<{ versions: PolicyVersion[]; active_policy: Record<string, unknown> }>(url("/v1/control/policies"), token);
        setPolicyVersions(result.versions);
        setActivePolicy(result.active_policy);
        setPolicyDraft((current) => current || JSON.stringify(result.active_policy, null, 2));
      } else if (section === "incidents") {
        const result = await api<{ incidents: Incident[] }>(url("/v1/control/incidents"), token);
        setIncidents(result.incidents);
      } else if (section === "evaluations") {
        const [sampleResult, runResult] = await Promise.all([
          api<{ samples: Sample[]; dataset_sha256: string; holdout_access: boolean }>(url("/v1/control/evaluations/samples?limit=1000"), token),
          api<{ runs: Record<string, unknown>[] }>(url("/v1/control/evaluations/runs"), token),
        ]);
        setSamples(sampleResult.samples);
        setDatasetDigest(sampleResult.dataset_sha256);
        setHoldoutAccess(sampleResult.holdout_access);
        setRuns(runResult.runs);
      } else {
        const result = await api<{ keys: ApiKey[] }>(url("/v1/identity/api-keys"), token);
        setKeys(result.keys);
      }
      setLoadedAt(new Date());
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to load control-plane data.");
    } finally {
      setLoading(false);
    }
  }, [section, token, url]);

  useEffect(() => { void load(); }, [load]);

  const selectedSample = useMemo(() => samples.find((sample) => sample.id === selectedSampleId) ?? null, [samples, selectedSampleId]);
  const filteredSamples = useMemo(() => {
    const query = sampleQuery.trim().toLocaleLowerCase();
    return samples.filter((sample) =>
      (sampleReviewFilter === "all" || sample.review_status === sampleReviewFilter) &&
      (!query || `${sample.id} ${sample.category} ${sample.attack_family} ${sample.technique} ${sample.language} ${sample.prompt}`.toLocaleLowerCase().includes(query)),
    );
  }, [sampleQuery, sampleReviewFilter, samples]);
  const visibleSamples = filteredSamples.slice((samplePage - 1) * samplePageSize, samplePage * samplePageSize);
  const filteredPolicies = useMemo(() => {
    const query = policyQuery.trim().toLocaleLowerCase();
    return [...policyVersions]
      .filter((version) => (policyStatus === "all" || version.status === policyStatus) &&
        (!query || `${version.revision} ${version.sha256} ${version.created_by} ${version.approved_by ?? ""} ${version.status}`.toLocaleLowerCase().includes(query)))
      .sort((left, right) => Number(right.revision) - Number(left.revision));
  }, [policyQuery, policyStatus, policyVersions]);
  const visiblePolicies = filteredPolicies.slice((policyPage - 1) * policyPageSize, policyPage * policyPageSize);
  const filteredIncidents = useMemo(() => {
    const query = incidentQuery.trim().toLocaleLowerCase();
    return [...incidents]
      .filter((incident) => (incidentStatus === "all" || incident.status === incidentStatus) &&
        (incidentSeverityFilter === "all" || incident.severity === incidentSeverityFilter) &&
        (!query || `${incident.id} ${incident.title} ${incident.summary} ${incident.assignee ?? ""} ${incident.tenant_id}`.toLocaleLowerCase().includes(query)))
      .sort((left, right) => Date.parse(right.updated_at) - Date.parse(left.updated_at));
  }, [incidentQuery, incidentSeverityFilter, incidentStatus, incidents]);
  const visibleIncidents = filteredIncidents.slice((incidentPage - 1) * incidentPageSize, incidentPage * incidentPageSize);
  const filteredKeys = useMemo(() => {
    const query = keyQuery.trim().toLocaleLowerCase();
    const now = Date.now();
    return [...keys]
      .filter((key) => {
        const revoked = Boolean(key.revoked_at);
        const expiresSoon = !revoked && Date.parse(key.expires_at) <= now + 30 * 24 * 60 * 60 * 1000;
        return (keyStatus === "all" || (keyStatus === "active" && !revoked) || (keyStatus === "revoked" && revoked) || (keyStatus === "expiring" && expiresSoon)) &&
          (!query || `${key.id} ${key.name} ${key.tenant_id} ${key.role}`.toLocaleLowerCase().includes(query));
      })
      .sort((left, right) => Date.parse(right.created_at) - Date.parse(left.created_at));
  }, [keyQuery, keyStatus, keys]);
  const visibleKeys = filteredKeys.slice((keyPage - 1) * keyPageSize, keyPage * keyPageSize);
  const filteredRuns = useMemo(() => {
    const query = runQuery.trim().toLocaleLowerCase();
    return runs.filter((run) => !query || `${run.id ?? ""} ${run.policy_sha256 ?? ""} ${run.dataset_sha256 ?? ""} ${JSON.stringify(run.metrics ?? {})}`.toLocaleLowerCase().includes(query));
  }, [runQuery, runs]);
  const visibleRuns = filteredRuns.slice((runPage - 1) * runPageSize, runPage * runPageSize);
  const reviewCounts = useMemo(() => ({
    reviewed: samples.filter((sample) => sample.review_status === "human_reviewed" && sample.review_count >= 2).length,
    waiting: samples.filter((sample) => sample.review_status !== "human_reviewed").length,
    disagreement: samples.filter((sample) => sample.review_status === "adjudication_required").length,
    synthetic: samples.filter((sample) => sample.review_status === "synthetic_unreviewed").length,
  }), [samples]);
  const latestEvaluation = evaluationResult ?? runs[0] ?? null;
  const latestMetrics = latestEvaluation && isRecord(latestEvaluation.metrics) ? latestEvaluation.metrics : null;
  const overallMetrics = latestMetrics && isRecord(latestMetrics.overall) ? latestMetrics.overall : null;
  const pageResetKey = `${section}:${policyQuery}:${policyStatus}:${incidentQuery}:${incidentStatus}:${incidentSeverityFilter}:${sampleQuery}:${sampleReviewFilter}:${runQuery}:${keyQuery}:${keyStatus}`;
  useEffect(() => {
    setPolicyPage(1);
    setIncidentPage(1);
    setSamplePage(1);
    setRunPage(1);
    setKeyPage(1);
    setSelectedSampleId("");
  }, [pageResetKey]);
  useEffect(() => {
    setPolicyPage((page) => Math.min(page, Math.max(1, Math.ceil(filteredPolicies.length / policyPageSize))));
  }, [filteredPolicies.length, policyPageSize]);
  useEffect(() => {
    setIncidentPage((page) => Math.min(page, Math.max(1, Math.ceil(filteredIncidents.length / incidentPageSize))));
  }, [filteredIncidents.length, incidentPageSize]);
  useEffect(() => {
    setSamplePage((page) => Math.min(page, Math.max(1, Math.ceil(filteredSamples.length / samplePageSize))));
  }, [filteredSamples.length, samplePageSize]);
  useEffect(() => {
    setRunPage((page) => Math.min(page, Math.max(1, Math.ceil(filteredRuns.length / runPageSize))));
  }, [filteredRuns.length, runPageSize]);
  useEffect(() => {
    setKeyPage((page) => Math.min(page, Math.max(1, Math.ceil(filteredKeys.length / keyPageSize))));
  }, [filteredKeys.length, keyPageSize]);
  useEffect(() => {
    if (!selectedSample) return;
    setLabels({ category: selectedSample.category, expected_disposition: selectedSample.expected_disposition, attack_family: selectedSample.attack_family, technique: selectedSample.technique, language: selectedSample.language });
  }, [selectedSample]);

  const perform = async (work: () => Promise<void>, success: string) => {
    setBusy(true); setError(""); setNotice("");
    try { await work(); setNotice(success); await load(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "The operation failed."); }
    finally { setBusy(false); }
  };

  const stagePolicy = () => perform(async () => {
    const policy = JSON.parse(policyDraft) as Record<string, unknown>;
    const signature = signatureDraft.trim() ? JSON.parse(signatureDraft) as Record<string, unknown> : null;
    await api(url("/v1/control/policies"), token, { method: "POST", body: JSON.stringify({ policy, signature }) });
  }, "Policy version staged. A different platform administrator must approve it before activation.");

  const policyAction = (id: string, action: "approve" | "activate" | "evaluate") => perform(async () => {
    const init: RequestInit = action === "evaluate" ? { method: "POST", body: JSON.stringify({ split: "validation", reviewed_only: true }) } : { method: "POST", body: "{}" };
    const result = await api<Record<string, unknown>>(url(`/v1/control/policies/${id}/${action}`), token, init);
    if (action === "evaluate") setEvaluationResult(result);
  }, action === "approve" ? "Policy approved by this reviewer." : action === "activate" ? "Policy activated. The active revision and digest have been updated." : "Policy candidate evaluated against the validation split.");

  const createIncident = () => perform(async () => {
    await api(url("/v1/control/incidents"), token, { method: "POST", body: JSON.stringify({ title: incidentTitle, summary: incidentSummary, severity: incidentSeverity }) });
    setIncidentTitle(""); setIncidentSummary("");
  }, "Incident created and recorded in the tenant audit trail.");

  const changeIncident = (incident: Incident, status: string, assignee: string | null = incident.assignee) => perform(async () => {
    const comment = status === incident.status ? "Assignee updated" : `Status changed to ${status}`;
    await api(url(`/v1/control/incidents/${incident.id}`), token, { method: "PATCH", body: JSON.stringify({ status, assignee, comment }) });
  }, `Incident updated: ${status.replaceAll("_", " ")}.`);

  const runEvaluation = () => perform(async () => {
    const result = await api<Record<string, unknown>>(url("/v1/control/evaluations/run"), token, { method: "POST", body: JSON.stringify({ split: evaluationSplit, reviewed_only: reviewedOnly }) });
    setEvaluationResult(result);
    setRuns((current) => [result, ...current.filter((run) => run.id !== result.id)]);
  }, "Evaluation run saved with dataset and policy digests.");

  const reviewSample = () => selectedSample && perform(async () => {
    const taxonomy = TAXONOMY[labels.category];
    if (!taxonomy) throw new Error("Choose a supported category before submitting a label vote.");
    const language = labels.language.trim().toLowerCase();
    if (!/^[a-z0-9]{1,8}(?:-[a-z0-9]{1,8})*$/.test(language)) throw new Error("Use a language tag such as en, bn, zh-hans, or x-private.");
    await api(url(`/v1/control/evaluations/samples/${selectedSample.id}/review`), token, { method: "POST", body: JSON.stringify({ category: labels.category, expected_disposition: taxonomy.disposition, attack_family: taxonomy.family, technique: taxonomy.technique, language }) });
  }, "Independent vote recorded with reviewer provenance. Samples count as human-reviewed only after two matching votes.");

  const addSample = () => perform(async () => {
    const taxonomy = TAXONOMY[newSampleCategory];
    if (!taxonomy) throw new Error("Choose a supported evaluation category.");
    const language = newSampleLanguage.trim().toLowerCase();
    if (!/^[a-z0-9]{1,8}(?:-[a-z0-9]{1,8})*$/.test(language)) throw new Error("Use a language tag such as en, bn, zh-hans, or x-private.");
    const sampleId = newSampleId.trim() || `CUSTOM-${Date.now()}`;
    await api(url("/v1/control/evaluations/samples"), token, { method: "POST", body: JSON.stringify({ id: sampleId, category: newSampleCategory, prompt: newSamplePrompt.trim(), expected_disposition: taxonomy.disposition, attack_family: taxonomy.family, technique: taxonomy.technique, language, source: "human_authored", split: newSampleSplit, label_version: "2.0" }) });
    setNewSampleId(""); setNewSamplePrompt("");
  }, "Evaluation sample added as unreviewed. A second evaluator must review its label.");

  const createKey = () => perform(async () => {
    const result = await api<{ token: string }>(url("/v1/identity/api-keys"), token, { method: "POST", body: JSON.stringify({ name: keyName.trim(), tenant_id: keyTenant.trim() || null, role: keyRole, expires_in_days: keyExpires }) });
    setIssuedToken(result.token); setCopied(false); setKeyName("");
  }, "API key created. Copy the secret now; it will not be displayed again.");

  const revokeKey = (key: ApiKey) => perform(async () => {
    await api(url(`/v1/identity/api-keys/${key.id}`), token, { method: "DELETE" });
  }, "API key revoked.");

  const rotateKey = (key: ApiKey) => perform(async () => {
    const result = await api<{ key: ApiKey; token: string }>(url(`/v1/identity/api-keys/${key.id}/rotate`), token, { method: "POST", body: "{}" });
    setIssuedToken(result.token); setCopied(false);
  }, "API key rotated. The old credential is revoked; copy the replacement now.");

  const copyIssuedToken = async () => {
    try {
      await navigator.clipboard.writeText(issuedToken);
      setCopied(true);
    } catch {
      setError("Clipboard access is unavailable. Select and copy the credential manually before leaving this page.");
    }
  };

  const accessNote = <div className="callout-note"><strong>Access requirement</strong><span>Governance APIs fail closed unless gateway authentication is enabled and your verified role is authorized. The default local demo policy disables authentication; configure OIDC/JWKS role mapping, then enter a verified token in Gateway settings.</span></div>;

  const loadingState = loading ? <div className="governance-loading" role="status" aria-live="polite"><span className="loading-indicator" /> Loading verified tenant data…</div> : null;
  const noticeState = error
    ? <div className="governance-alert governance-alert-error" role="alert"><strong>Could not complete this request</strong><span>{error}</span><button type="button" className="clear-button" onClick={() => void load()}>Retry</button></div>
    : notice
      ? <div className="governance-alert governance-alert-success" role="status"><strong>Update saved</strong><span>{notice}</span></div>
      : null;
  const refreshMeta = <span className="snapshot-note">{loadedAt ? "Updated " + formatTime(loadedAt.toISOString()) : "No successful snapshot"}</span>;
  const hasSnapshot = loadedAt !== null;

  if (section === "policies") {
    const activeCount = policyVersions.filter((version) => version.status === "active").length;
    const approvalCount = policyVersions.filter((version) => version.status === "staged").length;
    const dryRunCount = policyVersions.filter((version) => version.status === "approved" && !version.dry_run_complete).length;
    return <section className="governance-page">
      <PanelHeader eyebrow="POLICY GOVERNANCE · DUAL CONTROL" title="Policy lifecycle" description="Validate a candidate, collect an independent approval, evaluate it against reviewed validation data, then activate or roll back by immutable revision." action={<span className={`pill ${activePolicy ? "pill-green" : "pill-muted"}`}>{activePolicy ? `ACTIVE · ${String(activePolicy.revision ?? "revision available")}` : hasSnapshot ? "NO ACTIVE POLICY" : "NO POLICY SNAPSHOT"}</span>} />
      {noticeState}
      {accessNote}
      <div className="governance-kpi-grid" aria-label="Policy lifecycle summary">
        <KpiCard label="Active revisions" value={activeCount} note="Current runtime policy in this returned history" available={hasSnapshot} />
        <KpiCard label="Awaiting approval" value={approvalCount} note="Requires a different platform administrator" tone={approvalCount ? "warning" : ""} available={hasSnapshot} />
        <KpiCard label="Awaiting dry-run" value={dryRunCount} note="Approved revisions not yet evaluated" tone={dryRunCount ? "warning" : ""} available={hasSnapshot} />
        <KpiCard label="Policy revisions" value={policyVersions.length} note="Versions in the loaded control-plane response" available={hasSnapshot} />
      </div>
      <div className="governance-grid">
        <section className="panel governance-card">
          <div className="eyebrow">CANDIDATE EDITOR</div><h3>Stage policy version</h3>
          <p className="governance-description">The gateway validates the policy schema and signature before storing a candidate. Staging does not change the active policy.</p>
          <form className="governance-form" onSubmit={(event) => { event.preventDefault(); void stagePolicy(); }}>
            <label className="settings-field"><span>Policy JSON <small>Runtime-compatible policy document</small></span><textarea className="governance-editor" value={policyDraft} onChange={(event) => setPolicyDraft(event.target.value)} spellCheck={false} required rows={16} aria-label="Candidate policy JSON" /></label>
            <label className="settings-field"><span>Detached signature JSON <small>Required when policy integrity enforces signing</small></span><textarea className="governance-signature" value={signatureDraft} onChange={(event) => setSignatureDraft(event.target.value)} placeholder='{"algorithm":"Ed25519","key_id":"release-2026","policy_sha256":"…","signature":"…"}' spellCheck={false} rows={5} aria-label="Detached signature JSON" /></label>
            <button type="submit" className="save-button" disabled={busy || loading || !hasSnapshot || !policyDraft.trim()}>{busy ? "Validating…" : "Validate and stage"}</button>
          </form>
          <p className="governance-hint">Only L1/L2 input controls are editable here because the current reviewed corpus evaluates input allow/block outcomes. Output DLP, tool authorization, identity, quotas, and integrations require a signed deployment rollout.</p>
        </section>
        <section className="panel governance-card">
          <div className="governance-section-title"><div><div className="eyebrow">VERSION HISTORY</div><h3>Review and deployment state</h3></div><div className="governance-header-actions">{refreshMeta}<button type="button" className="clear-button" onClick={() => void load()} disabled={loading}>{loading ? "Refreshing…" : "Refresh"}</button></div></div>
          <div className="governance-table-toolbar">
            <label className="settings-field"><span>Search revisions</span><input type="search" value={policyQuery} onChange={(event) => setPolicyQuery(event.target.value)} placeholder="Revision, digest, reviewer" /></label>
            <label className="settings-field"><span>Lifecycle state</span><select value={policyStatus} onChange={(event) => setPolicyStatus(event.target.value)}><option value="all">All states</option><option value="staged">Staged</option><option value="approved">Approved</option><option value="active">Active</option></select></label>
            <button type="button" className="clear-button" disabled={policyStatus === "all" && !policyQuery} onClick={() => { setPolicyQuery(""); setPolicyStatus("all"); }}>Clear filters</button>
            <span className="governance-result-count">{hasSnapshot ? `${filteredPolicies.length.toLocaleString()} matching · ${policyVersions.length.toLocaleString()} loaded` : "Policy snapshot unavailable"}</span>
          </div>
          <div className="table-scroll">
            <table className="audit-table governance-table"><caption className="visually-hidden">Policy revisions and approval workflow</caption><thead><tr><th scope="col">Revision</th><th scope="col">State</th><th scope="col">Policy digest</th><th scope="col">Submitted / approved</th><th scope="col">Governance actions</th></tr></thead>
              <tbody>{visiblePolicies.map((version) => <tr key={version.id}>
                <td><strong>r{version.revision}</strong><small>{formatTime(version.created_at)}</small></td>
                <td><StatusTag value={version.status} tone={version.status === "active" ? "good" : version.status === "staged" ? "warn" : "neutral"} /></td>
                <td><code className="governance-digest" title={version.sha256}>{version.sha256}</code></td>
                <td><span>{version.created_by}</span><small>{version.approved_by ? "Approved by " + version.approved_by : "Independent approval pending"}</small></td>
                <td><div className="governance-actions">
                  {version.status === "staged" && <button type="button" className="clear-button" disabled={busy || !hasSnapshot} onClick={() => void policyAction(version.id, "approve")}>Approve</button>}
                  {version.status !== "active" && version.status !== "staged" && <><button type="button" className="clear-button" disabled={busy || !hasSnapshot} onClick={() => void policyAction(version.id, "evaluate")}>Dry-run</button><button type="button" className="save-button" disabled={busy || !hasSnapshot || (!version.dry_run_complete && !version.activated_at)} title={!version.dry_run_complete && !version.activated_at ? "A non-empty reviewed dry-run is required before activation" : undefined} onClick={() => void policyAction(version.id, "activate")}>{version.activated_at ? "Rollback here" : "Activate"}</button></>}
                  {version.status === "approved" && !version.dry_run_complete && <small className="governance-hint">Run a reviewed dry-run before activation.</small>}
                </div></td>
              </tr>)}</tbody>
            </table>
            {!loading && !error && !visiblePolicies.length && <div className="workspace-empty"><strong>{policyVersions.length ? "No policy revisions match" : "No policy revisions returned"}</strong><p>{policyVersions.length ? "Clear or adjust the filters to review another revision." : "Stage a candidate policy to begin the approval workflow."}</p></div>}
            {loadingState}
          </div>
          {hasSnapshot && <TableFooter label="policy revisions" total={filteredPolicies.length} page={policyPage} pageSize={policyPageSize} onPageChange={setPolicyPage} onPageSizeChange={(size) => { setPolicyPageSize(size); setPolicyPage(1); }} />}
        </section>
      </div>
    </section>;
  }

  if (section === "incidents") {
    const openCount = incidents.filter((incident) => !["resolved", "false_positive"].includes(incident.status)).length;
    const urgentCount = incidents.filter((incident) => ["critical", "high"].includes(incident.severity) && !["resolved", "false_positive"].includes(incident.status)).length;
    const containedCount = incidents.filter((incident) => incident.status === "contained").length;
    return <section className="governance-page">
      <PanelHeader eyebrow="SECURITY OPERATIONS · TENANT-SCOPED" title="Incident workflow" description="Create a redacted incident record, assign an owner, track containment, and preserve a status timeline. Do not enter customer prompts, responses, credentials, or source data." action={<span className="pill pill-muted">{hasSnapshot ? `${incidents.length.toLocaleString()} LOADED` : "NO VERIFIED SNAPSHOT"}</span>} />
      {noticeState}
      {accessNote}
      <div className="governance-kpi-grid" aria-label="Incident queue summary">
        <KpiCard label="Open incidents" value={openCount} note="Not resolved or marked false positive" tone={openCount ? "warning" : ""} available={hasSnapshot} />
        <KpiCard label="High or critical" value={urgentCount} note="Unresolved urgent incidents" tone={urgentCount ? "danger" : ""} available={hasSnapshot} />
        <KpiCard label="Contained" value={containedCount} note="Containment recorded in the workflow" available={hasSnapshot} />
        <KpiCard label="Loaded records" value={incidents.length} note="Tenant-scoped records returned by the gateway" available={hasSnapshot} />
      </div>
      <section className="panel governance-card">
        <div className="eyebrow">NEW CASE</div><h3>Open security incident</h3>
        <p className="governance-description">Add impact and control context only. Secrets and active HTML are redacted before storage.</p>
        <form className="governance-form" onSubmit={(event) => { event.preventDefault(); void createIncident(); }}>
          <div className="governance-form-grid">
            <label className="settings-field"><span>Incident title <small>Required · 3–200 characters</small></span><input value={incidentTitle} onChange={(event) => setIncidentTitle(event.target.value)} maxLength={200} minLength={3} required placeholder="Unexpected tool authorization" /></label>
            <label className="settings-field"><span>Severity</span><select value={incidentSeverity} onChange={(event) => setIncidentSeverity(event.target.value)}><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>
          </div>
          <label className="settings-field"><span>Summary <small>Maximum 4,000 characters</small></span><textarea value={incidentSummary} onChange={(event) => setIncidentSummary(event.target.value)} maxLength={4000} placeholder="Describe impact, affected control and containment context. Do not paste prompts, tokens or source data." /></label>
          <div className="governance-form-actions"><button type="submit" className="save-button" disabled={busy || loading || !hasSnapshot || incidentTitle.trim().length < 3}>{busy ? "Opening incident…" : "Create incident"}</button><span>Owner and status can be updated from the queue.</span></div>
        </form>
      </section>
      <section className="panel governance-card">
        <div className="governance-section-title"><div><div className="eyebrow">CASE QUEUE</div><h3>Recent incidents</h3><p>Default order is most recently updated. Each row keeps its response timeline.</p></div><div className="governance-header-actions">{refreshMeta}<button type="button" className="clear-button" onClick={() => void load()} disabled={loading}>{loading ? "Refreshing…" : "Refresh"}</button></div></div>
        <div className="governance-table-toolbar">
          <label className="settings-field"><span>Search incidents</span><input type="search" value={incidentQuery} onChange={(event) => setIncidentQuery(event.target.value)} placeholder="Title, owner, tenant, incident ID" /></label>
          <label className="settings-field"><span>Status</span><select value={incidentStatus} onChange={(event) => setIncidentStatus(event.target.value)}><option value="all">All statuses</option><option value="open">Open</option><option value="triaged">Triaged</option><option value="contained">Contained</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option></select></label>
          <label className="settings-field"><span>Severity</span><select value={incidentSeverityFilter} onChange={(event) => setIncidentSeverityFilter(event.target.value)}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>
          <button type="button" className="clear-button" disabled={incidentStatus === "all" && incidentSeverityFilter === "all" && !incidentQuery} onClick={() => { setIncidentQuery(""); setIncidentStatus("all"); setIncidentSeverityFilter("all"); }}>Clear filters</button>
          <span className="governance-result-count">{hasSnapshot ? `${filteredIncidents.length.toLocaleString()} matching · ${incidents.length.toLocaleString()} loaded` : "Incident snapshot unavailable"}</span>
        </div>
        <div className="table-scroll">
          <table className="audit-table governance-table"><caption className="visually-hidden">Tenant security incident queue</caption><thead><tr><th scope="col">Incident / response timeline</th><th scope="col">Severity</th><th scope="col">Status</th><th scope="col">Owner</th><th scope="col">Last updated</th><th scope="col">Update status</th></tr></thead>
            <tbody>{visibleIncidents.map((incident) => <tr key={incident.id}>
              <td><strong>{incident.title}</strong><span className="probe-description" title={incident.summary}>{incident.summary || "No summary provided"}</span><code>{incident.id}</code><details className="incident-timeline"><summary>{incident.activity.length} timeline event(s)</summary>{incident.activity.map((item, index) => <div key={item.at + "-" + index}><time>{formatTime(item.at)}</time><span>{item.actor} · {item.action} · {item.status.replaceAll("_", " ")}</span>{item.comment && <small>{item.comment}</small>}</div>)}</details></td>
              <td><StatusTag value={incident.severity} tone={incident.severity === "critical" ? "bad" : incident.severity === "high" ? "warn" : "neutral"} /></td>
              <td><StatusTag value={incident.status} tone={["resolved", "contained"].includes(incident.status) ? "good" : "neutral"} /></td>
              <td><input className="table-inline-input" aria-label={"Assign owner for " + incident.title} defaultValue={incident.assignee ?? ""} placeholder="Unassigned" disabled={busy || !hasSnapshot} onBlur={(event) => { const next = event.target.value.trim() || null; if (next !== incident.assignee) void changeIncident(incident, incident.status, next); }} /></td>
              <td><time>{formatTime(incident.updated_at)}</time></td>
              <td><select className="table-inline-select" aria-label={"Update status for " + incident.title} value={incident.status} onChange={(event) => void changeIncident(incident, event.target.value)} disabled={busy || !hasSnapshot}><option value="open">Open</option><option value="triaged">Triaged</option><option value="contained">Contained</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option></select></td>
            </tr>)}</tbody>
          </table>
          {!loading && !error && !visibleIncidents.length && <div className="workspace-empty"><strong>{incidents.length ? "No incidents match these filters" : "No incidents recorded"}</strong><p>{incidents.length ? "Adjust the search, status or severity filter." : "New incident records will appear here for this verified tenant."}</p></div>}
          {loadingState}
        </div>
        {hasSnapshot && <TableFooter label="incidents" total={filteredIncidents.length} page={incidentPage} pageSize={incidentPageSize} onPageChange={setIncidentPage} onPageSizeChange={(size) => { setIncidentPageSize(size); setIncidentPage(1); }} />}
      </section>
    </section>;
  }

  if (section === "evaluations") {
    const byCategory = latestMetrics && isRecord(latestMetrics.by_category) ? Object.entries(latestMetrics.by_category) : [];
    const byLanguage = latestMetrics && isRecord(latestMetrics.by_language) ? Object.entries(latestMetrics.by_language) : [];
    const runSplit = latestMetrics && typeof latestMetrics.split === "string" ? latestMetrics.split : evaluationSplit;
    const runReviewedOnly = latestMetrics?.reviewed_only === true;
    return <section className="governance-page">
      <PanelHeader eyebrow="MODEL SECURITY QUALITY · LABEL PROVENANCE" title="Evaluation & data labeling" description="Maintain explicit attack labels, language and split metadata; require independent review consensus; and bind each regression run to exact policy and dataset digests." action={<div className="governance-header-actions"><span className="pill pill-muted">{hasSnapshot ? `${samples.length.toLocaleString()} LOADED · ${runs.length.toLocaleString()} RUNS` : "NO VERIFIED SNAPSHOT"}</span><button type="button" className="clear-button" onClick={() => void load()} disabled={loading}>{loading ? "Refreshing…" : "Refresh"}</button></div>} />
      {noticeState}
      {accessNote}
      <div className="governance-kpi-grid" aria-label="Evaluation data quality summary">
        <KpiCard label="Human-reviewed" value={reviewCounts.reviewed} note="Two or more votes with matching consensus" available={hasSnapshot} />
        <KpiCard label="Review queue" value={reviewCounts.waiting} note="Unreviewed, in review, or needs adjudication" tone={reviewCounts.waiting ? "warning" : ""} available={hasSnapshot} />
        <KpiCard label="Disagreement" value={reviewCounts.disagreement} note="Independent votes do not have consensus" tone={reviewCounts.disagreement ? "danger" : ""} available={hasSnapshot} />
        <KpiCard label="Review coverage" value={samples.length ? Math.round(reviewCounts.reviewed / samples.length * 100) + "%" : "—"} note="Only the returned dataset snapshot is counted" available={hasSnapshot} />
      </div>
      <div className="governance-dataset-note">
        <div><strong>Dataset snapshot</strong><span>{hasSnapshot ? `${samples.length.toLocaleString()} sample records returned · ${holdoutAccess ? "holdout access enabled for this role" : "holdout prompts excluded for this role"}` : "No verified sample snapshot · holdout access status unavailable"}</span></div>
        <code title={datasetDigest}>{datasetDigest || "Dataset digest unavailable"}</code>
      </div>
      <section className="panel governance-card">
        <div className="governance-section-title"><div><div className="eyebrow">DETERMINISTIC REGRESSION</div><h3>Run active policy evaluation</h3><p>TPR, FPR and benign-block rate are meaningful only for the exact selected sample set. Mixed or synthetic labels are reported as such.</p></div><StatusTag value={latestMetrics ? runReviewedOnly ? "human reviewed" : "mixed or synthetic" : "not evaluated"} tone={latestMetrics ? runReviewedOnly ? "good" : "warn" : "neutral"} /></div>
        <form className="governance-run-form" onSubmit={(event) => { event.preventDefault(); void runEvaluation(); }}>
          <label className="settings-field"><span>Dataset split</span><select value={evaluationSplit} onChange={(event) => setEvaluationSplit(event.target.value)}><option value="train">Train</option><option value="validation">Validation</option><option value="holdout">Holdout · aggregate result only</option></select></label>
          <label className="governance-check"><input type="checkbox" checked={reviewedOnly} onChange={(event) => setReviewedOnly(event.target.checked)} /><span>Use human-reviewed labels only</span></label>
          <button type="submit" className="save-button" disabled={busy || loading || !hasSnapshot}>{busy ? "Running evaluation…" : "Run evaluation"}</button>
        </form>
        {overallMetrics && <div className="evaluation-result" aria-live="polite">
          <div className="evaluation-result-heading"><div><div className="eyebrow">LATEST SAVED RUN · {runSplit.toUpperCase()}</div><h3>Detection quality</h3><p>{String(overallMetrics.samples ?? 0)} samples · {runReviewedOnly ? "reviewed-only subset" : "all labels in selected split"} · policy {String(latestEvaluation?.policy_sha256 ?? "").slice(0, 12)} · dataset {String(latestEvaluation?.dataset_sha256 ?? "").slice(0, 12)}</p></div><StatusTag value={String(latestMetrics?.evidence_quality ?? "unknown")} tone={latestMetrics?.evidence_quality === "human_reviewed" ? "good" : "warn"} /></div>
          <div className="governance-kpi-grid evaluation-kpi-grid">
            <KpiCard label="True positive rate" value={formatRate(overallMetrics.tpr)} note={String(overallMetrics.tp ?? 0) + " detected / " + String((Number(overallMetrics.tp) || 0) + (Number(overallMetrics.fn) || 0)) + " attack samples"} />
            <KpiCard label="False positive rate" value={formatRate(overallMetrics.fpr)} note={String(overallMetrics.fp ?? 0) + " benign prompts blocked" } tone={Number(overallMetrics.fp) > 0 ? "warning" : ""} />
            <KpiCard label="Precision" value={formatRate(overallMetrics.precision)} note="Share of blocked samples that were attacks" />
            <KpiCard label="Evaluated samples" value={Number(overallMetrics.samples) || 0} note="Exact denominator recorded with this run" />
          </div>
          {byCategory.length > 0 && <div className="evaluation-breakdown"><h4>Results by attack / content category</h4><div className="table-scroll"><table className="audit-table governance-table"><caption className="visually-hidden">Evaluation metrics by labeled category</caption><thead><tr><th scope="col">Category</th><th scope="col">Samples</th><th scope="col">TPR</th><th scope="col">FPR</th><th scope="col">Precision</th><th scope="col">TP / FP / TN / FN</th></tr></thead><tbody>{byCategory.map(([category, value]) => { const metric = isRecord(value) ? value : {}; return <tr key={category}><td>{category.replaceAll("-", " ")}</td><td>{String(metric.samples ?? 0)}</td><td>{formatRate(metric.tpr)}</td><td>{formatRate(metric.fpr)}</td><td>{formatRate(metric.precision)}</td><td>{String(metric.tp ?? 0)} / {String(metric.fp ?? 0)} / {String(metric.tn ?? 0)} / {String(metric.fn ?? 0)}</td></tr>; })}</tbody></table></div></div>}
          {byLanguage.length > 0 && <div className="evaluation-breakdown"><h4>Results by language</h4><div className="table-scroll"><table className="audit-table governance-table"><caption className="visually-hidden">Evaluation metrics by language tag</caption><thead><tr><th scope="col">Language tag</th><th scope="col">Samples</th><th scope="col">TPR</th><th scope="col">FPR</th><th scope="col">Precision</th><th scope="col">Benign block rate</th></tr></thead><tbody>{byLanguage.map(([language, value]) => { const metric = isRecord(value) ? value : {}; return <tr key={language}><td><code>{language}</code></td><td>{String(metric.samples ?? 0)}</td><td>{formatRate(metric.tpr)}</td><td>{formatRate(metric.fpr)}</td><td>{formatRate(metric.precision)}</td><td>{formatRate(metric.benign_block_rate)}</td></tr>; })}</tbody></table></div></div>}
        </div>}
      </section>
      <section className="panel governance-card">
        <div className="governance-section-title"><div><div className="eyebrow">DATASET AUTHORING · SCHEMA 2.0</div><h3>Add a labeled sample</h3><p>New samples are marked human-authored and remain unreviewed until independent evaluators reach consensus. Do not submit customer prompts, secrets, or personal data.</p></div><span className="pill pill-muted">SYNTHETIC / APPROVED DATA ONLY</span></div>
        <form className="governance-form" onSubmit={(event) => { event.preventDefault(); void addSample(); }}>
          <div className="governance-form-grid">
            <label className="settings-field"><span>Sample ID <small>Optional · generated when blank</small></span><input value={newSampleId} onChange={(event) => setNewSampleId(event.target.value)} maxLength={96} placeholder="CUSTOM-BN-001" /></label>
            <label className="settings-field"><span>Attack / content category</span><select value={newSampleCategory} onChange={(event) => setNewSampleCategory(event.target.value)}><option value="benign">Benign request</option><option value="prompt-injection">Prompt injection</option><option value="secret-disclosure">Sensitive information disclosure</option><option value="roleplay-injection">Role-play jailbreak</option><option value="developer-override">Developer role override</option><option value="encoded-injection">Encoded instruction payload</option></select></label>
          </div>
          <div className="label-taxonomy" aria-live="polite"><div><span>Expected disposition</span><strong>{TAXONOMY[newSampleCategory]?.disposition ?? "—"}</strong></div><div><span>Attack family</span><strong>{TAXONOMY[newSampleCategory]?.family ?? "—"}</strong></div><div><span>Technique</span><strong>{TAXONOMY[newSampleCategory]?.technique ?? "—"}</strong></div></div>
          <label className="settings-field"><span>Evaluation prompt <small>Maximum 16,000 characters</small></span><textarea value={newSamplePrompt} onChange={(event) => setNewSamplePrompt(event.target.value)} maxLength={16000} minLength={1} required rows={5} placeholder="Use synthetic or explicitly approved evaluation content." /><small className="field-counter">{newSamplePrompt.length.toLocaleString()} / 16,000 characters</small></label>
          <div className="governance-form-grid">
            <label className="settings-field"><span>Language tag <small>Use tags such as en, bn, zh-hans, or x-private</small></span><input value={newSampleLanguage} onChange={(event) => setNewSampleLanguage(event.target.value)} maxLength={16} minLength={2} pattern="[A-Za-z0-9]{1,8}(-[A-Za-z0-9]{1,8})*" required placeholder="en" /></label>
            <label className="settings-field"><span>Dataset split</span><select value={newSampleSplit} onChange={(event) => setNewSampleSplit(event.target.value)}><option value="train">Train</option><option value="validation">Validation</option></select></label>
          </div>
          <div className="governance-form-actions"><button type="submit" className="save-button" disabled={busy || loading || !hasSnapshot || !newSamplePrompt.trim()}>{busy ? "Adding sample…" : "Add unreviewed sample"}</button><span>Label provenance and consensus state are recorded by the gateway.</span></div>
        </form>
      </section>
      <section className="panel governance-card">
        <div className="governance-section-title"><div><div className="eyebrow">REVIEW QUEUE</div><h3>Review labels</h3><p>Each sample needs two independent votes. Reviewers must match category, language, disposition, attack family, and technique; disagreements require another independent vote.</p></div><span className={`pill ${hasSnapshot ? "pill-amber" : "pill-muted"}`}>{hasSnapshot ? `${reviewCounts.waiting.toLocaleString()} NEED REVIEW` : "NO VERIFIED SNAPSHOT"}</span></div>
        <div className="governance-table-toolbar">
          <label className="settings-field"><span>Search dataset</span><input type="search" value={sampleQuery} onChange={(event) => setSampleQuery(event.target.value)} placeholder="ID, category, family, technique, language" /></label>
          <label className="settings-field"><span>Review state</span><select value={sampleReviewFilter} onChange={(event) => setSampleReviewFilter(event.target.value)}><option value="all">All returned samples</option><option value="synthetic_unreviewed">Synthetic · unreviewed</option><option value="ambiguous">Needs review</option><option value="in_review">One independent vote</option><option value="adjudication_required">Disagreement · adjudication</option><option value="human_reviewed">Human reviewed · consensus</option></select></label>
          <button type="button" className="clear-button" disabled={sampleReviewFilter === "all" && !sampleQuery} onClick={() => { setSampleReviewFilter("all"); setSampleQuery(""); }}>Clear filters</button>
          <span className="governance-result-count">{hasSnapshot ? `${filteredSamples.length.toLocaleString()} matching · ${samples.length.toLocaleString()} returned` : "Dataset snapshot unavailable"}</span>
        </div>
        <div className="table-scroll">
          <table className="audit-table governance-table"><caption className="visually-hidden">Evaluation samples, expected outcomes, taxonomy, and independent review status</caption><thead><tr><th scope="col">Sample / prompt</th><th scope="col">Expected label</th><th scope="col">Taxonomy</th><th scope="col">Language / split</th><th scope="col">Provenance / version</th><th scope="col">Review state</th></tr></thead>
            <tbody>{visibleSamples.map((sample) => {
              const tone = sample.review_status === "human_reviewed" ? "good" : sample.review_status === "adjudication_required" ? "bad" : sample.review_status === "in_review" ? "warn" : "neutral";
              return <tr key={sample.id} className={selectedSampleId === sample.id ? "selected-row" : ""}>
                <td><button type="button" className="sample-select-button" onClick={() => setSelectedSampleId(sample.id)} aria-pressed={selectedSampleId === sample.id}><strong>{sample.id}</strong><span className="probe-description" title={sample.prompt}>{sample.prompt}</span></button></td>
                <td><strong>{sample.expected_disposition}</strong><small>{sample.category.replaceAll("-", " ")}</small></td>
                <td><span>{sample.attack_family}</span><small>{sample.technique}</small></td>
                <td><code>{sample.language}</code><small>{sample.split}</small></td>
                <td><span>{sample.source.replaceAll("_", " ")}</span><small>Label schema {sample.label_version}</small></td>
                <td><StatusTag value={sample.review_status} tone={tone} /><small>{sample.review_count} vote(s){sample.inter_reviewer_agreement !== null ? " · " + Math.round(sample.inter_reviewer_agreement * 100) + "% agreement" : ""}</small></td>
              </tr>;
            })}</tbody>
          </table>
          {!loading && !error && !visibleSamples.length && <div className="workspace-empty"><strong>{samples.length ? "No samples match these filters" : "No evaluation samples returned"}</strong><p>{samples.length ? "Adjust the search or review-state filter." : "Add a synthetic sample or connect an evaluator account."}</p></div>}
          {loadingState}
        </div>
        {hasSnapshot && <TableFooter label="evaluation samples" total={filteredSamples.length} page={samplePage} pageSize={samplePageSize} pageSizes={[15, 30, 50]} onPageChange={setSamplePage} onPageSizeChange={(size) => { setSamplePageSize(size); setSamplePage(1); }} />}
        {selectedSample && <div className="label-review">
          <div><div className="eyebrow">INDEPENDENT LABEL VOTE · {selectedSample.id}</div><h4>{selectedSample.prompt}</h4><p>{selectedSample.review_count} vote(s) submitted{selectedSample.inter_reviewer_agreement !== null ? " · " + Math.round(selectedSample.inter_reviewer_agreement * 100) + "% pairwise agreement" : ""}. Sample source: {selectedSample.source.replaceAll("_", " ")}. {selectedSample.review_status === "human_reviewed" ? "Consensus is complete; reviewed labels are immutable." : "The API enforces author exclusion and one vote per reviewer."}</p><dl className="label-provenance"><div><dt>Expected outcome</dt><dd>{selectedSample.expected_disposition}</dd></div><div><dt>Attack family</dt><dd>{selectedSample.attack_family}</dd></div><div><dt>Technique</dt><dd>{selectedSample.technique}</dd></div><div><dt>Dataset split</dt><dd>{selectedSample.split}</dd></div><div><dt>Label schema</dt><dd>{selectedSample.label_version}</dd></div><div><dt>Last review</dt><dd>{formatTime(selectedSample.reviewed_at)}</dd></div><div><dt>Reviewer provenance</dt><dd>{selectedSample.reviewer || "No consensus reviewers yet"}</dd></div></dl>
          </div>
          <form className="governance-form label-vote-form" onSubmit={(event) => { event.preventDefault(); void reviewSample(); }}>
            <div className="governance-form-grid">
              <label className="settings-field"><span>Category vote</span><select value={labels.category} onChange={(event) => { const category = event.target.value; const taxonomy = TAXONOMY[category]; setLabels({ category, expected_disposition: taxonomy.disposition, attack_family: taxonomy.family, technique: taxonomy.technique, language: labels.language }); }}><option value="benign">Benign request</option><option value="prompt-injection">Prompt injection</option><option value="secret-disclosure">Sensitive information disclosure</option><option value="roleplay-injection">Role-play jailbreak</option><option value="developer-override">Developer role override</option><option value="encoded-injection">Encoded instruction payload</option></select></label>
              <label className="settings-field"><span>Language tag</span><input value={labels.language} onChange={(event) => setLabels((value) => ({ ...value, language: event.target.value }))} maxLength={16} pattern="[A-Za-z0-9]{1,8}(-[A-Za-z0-9]{1,8})*" required /></label>
            </div>
            <div className="label-taxonomy"><div><span>Disposition</span><strong>{TAXONOMY[labels.category]?.disposition ?? "—"}</strong></div><div><span>Attack family</span><strong>{TAXONOMY[labels.category]?.family ?? "—"}</strong></div><div><span>Technique</span><strong>{TAXONOMY[labels.category]?.technique ?? "—"}</strong></div></div>
            <div className="governance-form-actions"><button type="submit" className="save-button" disabled={busy || loading || !hasSnapshot || selectedSample.review_status === "human_reviewed"}>{selectedSample.review_status === "human_reviewed" ? "Consensus reached" : busy ? "Recording vote…" : "Submit independent vote"}</button><span>Authors cannot vote on their own sample. Each evaluator can submit one immutable vote.</span></div>
          </form>
        </div>}
      </section>
      <section className="panel governance-card">
        <div className="governance-section-title"><div><div className="eyebrow">REPRODUCIBLE HISTORY</div><h3>Evaluation runs</h3><p>Each saved result is bound to the policy hash, dataset hash, split, and evidence quality used at run time.</p></div>{refreshMeta}</div>
        <div className="governance-table-toolbar"><label className="settings-field"><span>Search runs</span><input type="search" value={runQuery} onChange={(event) => setRunQuery(event.target.value)} placeholder="Run ID, policy digest, dataset digest" /></label><button type="button" className="clear-button" disabled={!runQuery} onClick={() => setRunQuery("")}>Clear search</button><span className="governance-result-count">{hasSnapshot ? `${filteredRuns.length.toLocaleString()} matching · ${runs.length.toLocaleString()} returned` : "Run history unavailable"}</span></div>
        <div className="table-scroll"><table className="audit-table governance-table"><caption className="visually-hidden">Saved deterministic evaluation runs</caption><thead><tr><th scope="col">Run / created</th><th scope="col">Dataset</th><th scope="col">Policy SHA-256</th><th scope="col">Dataset SHA-256</th><th scope="col">Evidence quality</th></tr></thead><tbody>{visibleRuns.map((run) => { const metrics = isRecord(run.metrics) ? run.metrics : {}; const overall = isRecord(metrics.overall) ? metrics.overall : {}; return <tr key={String(run.id)}><td><strong>{String(run.id ?? "—").slice(0, 12)}</strong><small>{formatTime(typeof run.created_at === "string" ? run.created_at : null)}</small></td><td>{String(metrics.split ?? "—")} · {String(overall.samples ?? 0)} samples{metrics.reviewed_only === true ? " · reviewed only" : ""}</td><td><code className="governance-digest" title={String(run.policy_sha256 ?? "")}>{String(run.policy_sha256 ?? "—").slice(0, 16)}</code></td><td><code className="governance-digest" title={String(run.dataset_sha256 ?? "")}>{String(run.dataset_sha256 ?? "—").slice(0, 16)}</code></td><td><StatusTag value={String(metrics.evidence_quality ?? "unknown")} tone={metrics.evidence_quality === "human_reviewed" ? "good" : "warn"} /></td></tr>; })}</tbody></table>{!loading && !error && !visibleRuns.length && <div className="workspace-empty"><strong>{runs.length ? "No runs match this search" : "No evaluation runs saved"}</strong><p>{runs.length ? "Search by run ID or policy and dataset digest." : "Run an evaluation to save a reproducible result."}</p></div>}{loadingState}</div>
        {hasSnapshot && <TableFooter label="evaluation runs" total={filteredRuns.length} page={runPage} pageSize={runPageSize} onPageChange={setRunPage} onPageSizeChange={(size) => { setRunPageSize(size); setRunPage(1); }} />}
      </section>
    </section>;
  }

  const now = Date.now();
  const activeKeys = keys.filter((key) => !key.revoked_at && Date.parse(key.expires_at) > now).length;
  const revokedKeys = keys.filter((key) => Boolean(key.revoked_at)).length;
  const expiringKeys = keys.filter((key) => !key.revoked_at && Date.parse(key.expires_at) > now && Date.parse(key.expires_at) <= now + 30 * 24 * 60 * 60 * 1000).length;
  const expiredKeys = keys.filter((key) => !key.revoked_at && Date.parse(key.expires_at) <= now).length;
  return <section className="governance-page">
    <PanelHeader eyebrow="IDENTITY & ACCESS · VERIFIED TENANT SCOPE" title="API key administration" description="Issue revocable, tenant-bound service credentials with explicit roles and expiry. Secret values are shown once and stored only as digests." action={<span className="pill pill-muted">{hasSnapshot ? `${keys.length.toLocaleString()} LOADED` : "NO VERIFIED SNAPSHOT"}</span>} />
    {noticeState}
    {accessNote}
    <div className="governance-kpi-grid" aria-label="API credential summary">
      <KpiCard label="Active" value={activeKeys} note="Not revoked or expired" available={hasSnapshot} />
      <KpiCard label="Expiring soon" value={expiringKeys} note="Expires within 30 days" tone={expiringKeys ? "warning" : ""} available={hasSnapshot} />
      <KpiCard label="Expired" value={expiredKeys} note="Credentials outside their expiry window" tone={expiredKeys ? "danger" : ""} available={hasSnapshot} />
      <KpiCard label="Revoked" value={revokedKeys} note="Revocation remains visible in the audit inventory" available={hasSnapshot} />
    </div>
    <section className="panel governance-card">
      <div className="eyebrow">CREATE CREDENTIAL</div><h3>Issue scoped API key</h3>
      <p className="governance-description">Use a service-specific name, the narrowest required role, and the shortest practical expiry. The secret appears only once.</p>
      <form className="governance-form" onSubmit={(event) => { event.preventDefault(); void createKey(); }}>
        <div className="governance-form-grid">
          <label className="settings-field"><span>Name <small>Required · 2–100 characters</small></span><input value={keyName} onChange={(event) => setKeyName(event.target.value)} minLength={2} maxLength={100} required placeholder="CI scanner · production" /></label>
          <label className="settings-field"><span>Tenant ID <small>Platform administrator may scope a tenant</small></span><input value={keyTenant} onChange={(event) => setKeyTenant(event.target.value)} maxLength={128} placeholder="acme-prod" /></label>
          <label className="settings-field"><span>Role</span><select value={keyRole} onChange={(event) => setKeyRole(event.target.value)}><option value="user">User · application request access</option><option value="analyst">Analyst · security review</option><option value="admin">Admin · platform administrator only</option></select></label>
          <label className="settings-field"><span>Expires in</span><select value={keyExpires} onChange={(event) => setKeyExpires(Number(event.target.value))}><option value={30}>30 days</option><option value={90}>90 days</option><option value={180}>180 days</option><option value={365}>365 days</option></select></label>
        </div>
        <div className="governance-form-actions"><button type="submit" className="save-button" disabled={busy || loading || !hasSnapshot || keyName.trim().length < 2}>{busy ? "Issuing credential…" : "Issue API key"}</button><span>Creation and revocation are tenant-authorized and audited by the gateway.</span></div>
      </form>
      {issuedToken && <div className="issued-token" role="status"><div><strong>Copy this credential now</strong><span>It cannot be retrieved again after hiding or leaving this page.</span></div><code>{issuedToken}</code><div className="governance-actions"><button type="button" className="clear-button" onClick={() => void copyIssuedToken()}>{copied ? "Copied" : "Copy key"}</button><button type="button" className="clear-button" onClick={() => { setIssuedToken(""); setCopied(false); }}>Hide credential</button></div></div>}
    </section>
    <section className="panel governance-card">
      <div className="governance-section-title"><div><div className="eyebrow">ACTIVE AND REVOKED</div><h3>Credential inventory</h3><p>Search by name, tenant, role, or key ID. Expiry and revocation are evaluated independently.</p></div><div className="governance-header-actions">{refreshMeta}<button type="button" className="clear-button" onClick={() => void load()} disabled={loading}>{loading ? "Refreshing…" : "Refresh"}</button></div></div>
      <div className="governance-table-toolbar">
        <label className="settings-field"><span>Search credentials</span><input type="search" value={keyQuery} onChange={(event) => setKeyQuery(event.target.value)} placeholder="Name, tenant, role, key ID" /></label>
        <label className="settings-field"><span>Credential state</span><select value={keyStatus} onChange={(event) => setKeyStatus(event.target.value)}><option value="all">All states</option><option value="active">Active</option><option value="expiring">Expires in 30 days</option><option value="expired">Expired</option><option value="revoked">Revoked</option></select></label>
        <button type="button" className="clear-button" disabled={keyStatus === "all" && !keyQuery} onClick={() => { setKeyQuery(""); setKeyStatus("all"); }}>Clear filters</button>
        <span className="governance-result-count">{hasSnapshot ? `${filteredKeys.length.toLocaleString()} matching · ${keys.length.toLocaleString()} loaded` : "Credential snapshot unavailable"}</span>
      </div>
      <div className="table-scroll">
        <table className="audit-table governance-table"><caption className="visually-hidden">Tenant API key inventory, expiry, and rotation actions</caption><thead><tr><th scope="col">Credential</th><th scope="col">Tenant / role</th><th scope="col">Created</th><th scope="col">Expires</th><th scope="col">State</th><th scope="col">Actions</th></tr></thead>
          <tbody>{visibleKeys.map((key) => {
            const expires = Date.parse(key.expires_at);
            const state = key.revoked_at ? "revoked" : expires <= Date.now() ? "expired" : expires <= Date.now() + 30 * 24 * 60 * 60 * 1000 ? "expiring soon" : "active";
            const tone = state === "active" ? "good" : state === "expired" || state === "revoked" ? "bad" : "warn";
            return <tr key={key.id}>
              <td><strong>{key.name}</strong><code>{key.id}</code></td><td><span>{key.tenant_id}</span><small>{key.role}</small></td><td><time>{formatTime(key.created_at)}</time></td><td><time>{formatTime(key.expires_at)}</time></td><td><StatusTag value={state} tone={tone} /></td>
              <td>{!key.revoked_at && state !== "expired" ? <div className="governance-actions"><button type="button" className="clear-button" disabled={busy || loading || !hasSnapshot} onClick={() => void rotateKey(key)}>Rotate</button><button type="button" className="clear-button danger-action" disabled={busy || loading || !hasSnapshot} onClick={() => void revokeKey(key)}>Revoke</button></div> : <span className="subtle-label">No action</span>}</td>
            </tr>;
          })}</tbody>
        </table>
        {!loading && !error && !visibleKeys.length && <div className="workspace-empty"><strong>{keys.length ? "No credentials match these filters" : "No API keys returned"}</strong><p>{keys.length ? "Adjust the search or state filter." : "Issue a scoped service credential to populate this inventory."}</p></div>}
        {loadingState}
      </div>
      {hasSnapshot && <TableFooter label="API keys" total={filteredKeys.length} page={keyPage} pageSize={keyPageSize} onPageChange={setKeyPage} onPageSizeChange={(size) => { setKeyPageSize(size); setKeyPage(1); }} />}
    </section>
  </section>;
}
