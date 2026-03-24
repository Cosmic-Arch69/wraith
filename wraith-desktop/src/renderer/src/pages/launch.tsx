import { useState, useCallback, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Rocket,
  Globe,
  Network,
  ShieldAlert,
  Plus,
  Trash2,
  ChevronRight,
  ChevronLeft,
  Target,
  Settings2,
  FileCheck2,
  Eye,
  EyeOff,
  FolderOpen,
  AlertCircle,
  CheckCircle2,
  Shuffle,
  Clock,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  type WizardState,
  type WizardHost,
  getDefaultConfig,
  validateConfig,
  generateConfigYaml,
} from '@/lib/yaml-config'
import { usePipelineStore } from '@/stores/pipeline-store'
import { useEngagementStore } from '@/stores/engagement-store'
import { cn } from '@/lib/utils'

// ---------------------------------------------------------------------------
// Step metadata
// ---------------------------------------------------------------------------

const STEPS = [
  { id: 1, label: 'Engagement & Target', icon: Target },
  { id: 2, label: 'Configuration', icon: Settings2 },
  { id: 3, label: 'Authorization', icon: FileCheck2 },
  { id: 4, label: 'Review & Launch', icon: Rocket },
] as const

type StepId = (typeof STEPS)[number]['id']

// ---------------------------------------------------------------------------
// Engagement type cards
// ---------------------------------------------------------------------------

const ENGAGEMENT_TYPES = [
  {
    value: 'external' as const,
    label: 'External',
    icon: Globe,
    description: 'Attack from outside the network perimeter. WAN IP required.',
  },
  {
    value: 'internal' as const,
    label: 'Internal',
    icon: Network,
    description: 'Simulate insider threat or compromised internal asset.',
  },
  {
    value: 'assumed-breach' as const,
    label: 'Assumed Breach',
    icon: ShieldAlert,
    description: 'Start with domain credentials. Emulate post-compromise.',
  },
]

// ---------------------------------------------------------------------------
// Objective cards
// ---------------------------------------------------------------------------

const OBJECTIVES = [
  {
    value: 'full_assessment',
    label: 'Full Assessment',
    description: 'Comprehensive attack surface coverage across all vectors.',
  },
  {
    value: 'domain_admin',
    label: 'Domain Admin',
    description: 'Focus on Active Directory privilege escalation paths.',
  },
  {
    value: 'web_only',
    label: 'Web Only',
    description: 'Restrict scope to web application attack surface.',
  },
  {
    value: 'credential_harvest',
    label: 'Credential Harvest',
    description: 'Prioritize credential extraction and lateral movement.',
  },
]

// ---------------------------------------------------------------------------
// Field label component
// ---------------------------------------------------------------------------

function FieldLabel({
  children,
  required,
}: {
  children: React.ReactNode
  required?: boolean
}) {
  return (
    <label className="block text-xs font-medium text-zinc-600 mb-1 uppercase tracking-wider">
      {children}
      {required && <span className="text-red-500 ml-1">*</span>}
    </label>
  )
}

// ---------------------------------------------------------------------------
// Section header component
// ---------------------------------------------------------------------------

function SectionHeader({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2 mb-3">
      <h3 className="text-xs font-semibold uppercase tracking-widest text-zinc-500">{children}</h3>
      <div className="flex-1 h-px bg-zinc-200" />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Step 1: Engagement & Target
// ---------------------------------------------------------------------------

function Step1({
  state,
  onChange,
}: {
  state: WizardState
  onChange: (patch: Partial<WizardState>) => void
}) {
  const [showPass, setShowPass] = useState(false)

  const addHost = useCallback(() => {
    const newHost: WizardHost = { ip: '', name: '', webUrl: '' }
    onChange({ hosts: [...state.hosts, newHost] })
  }, [state.hosts, onChange])

  const removeHost = useCallback(
    (idx: number) => {
      onChange({ hosts: state.hosts.filter((_, i) => i !== idx) })
    },
    [state.hosts, onChange],
  )

  const updateHost = useCallback(
    (idx: number, patch: Partial<WizardHost>) => {
      const updated = state.hosts.map((h, i) => (i === idx ? { ...h, ...patch } : h))
      onChange({ hosts: updated })
    },
    [state.hosts, onChange],
  )

  return (
    <div className="space-y-5">
      {/* Engagement type */}
      <div>
        <SectionHeader>Engagement Type</SectionHeader>
        <div className="grid grid-cols-3 gap-3">
          {ENGAGEMENT_TYPES.map(({ value, label, icon: Icon, description }) => (
            <button
              key={value}
              type="button"
              onClick={() => onChange({ engagementType: value })}
              className={cn(
                'relative text-left p-4 rounded-xl border-2 transition-all duration-150 cursor-pointer group',
                state.engagementType === value
                  ? 'border-red-500 bg-red-50 shadow-sm'
                  : 'border-zinc-200 bg-white hover:border-zinc-300 hover:bg-zinc-50',
              )}
            >
              <div className="flex items-center gap-2 mb-2">
                <Icon
                  className={cn(
                    'w-4 h-4',
                    state.engagementType === value ? 'text-red-500' : 'text-zinc-400',
                  )}
                />
                <span
                  className={cn(
                    'text-sm font-semibold',
                    state.engagementType === value ? 'text-red-700' : 'text-zinc-700',
                  )}
                >
                  {label}
                </span>
                {state.engagementType === value && (
                  <CheckCircle2 className="w-3.5 h-3.5 text-red-500 ml-auto" />
                )}
              </div>
              <p
                className={cn(
                  'text-xs leading-relaxed',
                  state.engagementType === value ? 'text-red-600/70' : 'text-zinc-500',
                )}
              >
                {description}
              </p>
            </button>
          ))}
        </div>
      </div>

      {/* WAN IP (external only) */}
      {state.engagementType === 'external' && (
        <div className="max-w-xs">
          <FieldLabel required>WAN IP Address</FieldLabel>
          <Input
            type="text"
            value={state.wanIp}
            onChange={(e) => onChange({ wanIp: e.target.value })}
            placeholder="203.0.113.1"
            className="font-mono text-sm"
          />
        </div>
      )}

      {/* Target */}
      <div>
        <SectionHeader>Target</SectionHeader>
        <div className="grid grid-cols-2 gap-3 mb-3">
          <div>
            <FieldLabel>Domain Name</FieldLabel>
            <Input
              type="text"
              value={state.domain}
              onChange={(e) => onChange({ domain: e.target.value })}
              placeholder="corp.local"
              className="font-mono text-sm"
            />
          </div>
          <div>
            <FieldLabel>Domain Controller IP</FieldLabel>
            <Input
              type="text"
              value={state.dc}
              onChange={(e) => onChange({ dc: e.target.value })}
              placeholder="192.168.1.5"
              className="font-mono text-sm"
            />
          </div>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <FieldLabel>Domain User</FieldLabel>
            <Input
              type="text"
              value={state.domainUser}
              onChange={(e) => onChange({ domainUser: e.target.value })}
              placeholder="administrator"
              className="font-mono text-sm"
            />
          </div>
          <div>
            <FieldLabel>Domain Password</FieldLabel>
            <div className="relative">
              <Input
                type={showPass ? 'text' : 'password'}
                value={state.domainPass}
                onChange={(e) => onChange({ domainPass: e.target.value })}
                placeholder="Password1"
                className="font-mono text-sm pr-8"
              />
              <button
                type="button"
                onClick={() => setShowPass((v) => !v)}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-600 transition-colors"
                tabIndex={-1}
              >
                {showPass ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Hosts */}
      <div>
        <SectionHeader>Target Hosts</SectionHeader>
        <div className="space-y-2">
          {state.hosts.length === 0 && (
            <p className="text-xs text-zinc-400 py-3 text-center border border-dashed border-zinc-200 rounded-lg bg-zinc-50">
              No hosts added. Add at least one target host for internal/assumed-breach engagements.
            </p>
          )}
          {state.hosts.map((host, idx) => (
            <div
              key={idx}
              className="grid grid-cols-[1fr_1fr_1fr_auto] gap-2 items-center bg-zinc-50 border border-zinc-200 rounded-lg px-3 py-2"
            >
              <div>
                <FieldLabel>IP Address</FieldLabel>
                <Input
                  type="text"
                  value={host.ip}
                  onChange={(e) => updateHost(idx, { ip: e.target.value })}
                  placeholder="192.168.1.10"
                  className="font-mono text-xs h-7"
                />
              </div>
              <div>
                <FieldLabel>Hostname</FieldLabel>
                <Input
                  type="text"
                  value={host.name}
                  onChange={(e) => updateHost(idx, { name: e.target.value })}
                  placeholder="WORKSTATION-01"
                  className="font-mono text-xs h-7"
                />
              </div>
              <div>
                <FieldLabel>Web URL (optional)</FieldLabel>
                <Input
                  type="text"
                  value={host.webUrl ?? ''}
                  onChange={(e) => updateHost(idx, { webUrl: e.target.value })}
                  placeholder="http://192.168.1.10:8080"
                  className="font-mono text-xs h-7"
                />
              </div>
              <button
                type="button"
                onClick={() => removeHost(idx)}
                className="mt-4 p-1.5 rounded text-zinc-400 hover:text-red-500 hover:bg-red-50 transition-colors"
                title="Remove host"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>
          ))}
          <Button
            variant="outline"
            size="sm"
            onClick={addHost}
            className="gap-1.5 text-xs border-zinc-200 text-zinc-600 hover:text-zinc-900"
          >
            <Plus className="w-3.5 h-3.5" />
            Add Host
          </Button>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Step 2: Configuration
// ---------------------------------------------------------------------------

function Step2({
  state,
  onChange,
}: {
  state: WizardState
  onChange: (patch: Partial<WizardState>) => void
}) {
  return (
    <div className="space-y-5">
      {/* Planning */}
      <div>
        <SectionHeader>Planning</SectionHeader>
        <div className="grid grid-cols-3 gap-3">
          <div>
            <FieldLabel required>Max Rounds</FieldLabel>
            <Input
              type="number"
              min={1}
              max={50}
              value={state.maxRounds}
              onChange={(e) => onChange({ maxRounds: parseInt(e.target.value) || 1 })}
              className="font-mono text-sm"
            />
            <p className="text-[10px] text-zinc-400 mt-1">1 - 50</p>
          </div>
          <div>
            <FieldLabel required>Max Agents</FieldLabel>
            <Input
              type="number"
              min={1}
              max={200}
              value={state.maxAgents}
              onChange={(e) => onChange({ maxAgents: parseInt(e.target.value) || 1 })}
              className="font-mono text-sm"
            />
            <p className="text-[10px] text-zinc-400 mt-1">1 - 200</p>
          </div>
          <div>
            <FieldLabel required>Concurrency</FieldLabel>
            <Input
              type="number"
              min={1}
              max={50}
              value={state.concurrency}
              onChange={(e) => onChange({ concurrency: parseInt(e.target.value) || 1 })}
              className="font-mono text-sm"
            />
            <p className="text-[10px] text-zinc-400 mt-1">Parallel agents</p>
          </div>
        </div>
      </div>

      {/* Objective */}
      <div>
        <SectionHeader>Objective</SectionHeader>
        <div className="grid grid-cols-2 gap-3">
          {OBJECTIVES.map(({ value, label, description }) => (
            <button
              key={value}
              type="button"
              onClick={() => onChange({ objective: value })}
              className={cn(
                'text-left p-4 rounded-xl border-2 transition-all duration-150 cursor-pointer',
                state.objective === value
                  ? 'border-red-500 bg-red-50'
                  : 'border-zinc-200 bg-white hover:border-zinc-300 hover:bg-zinc-50',
              )}
            >
              <div className="flex items-center justify-between mb-1">
                <span
                  className={cn(
                    'text-sm font-semibold',
                    state.objective === value ? 'text-red-700' : 'text-zinc-700',
                  )}
                >
                  {label}
                </span>
                {state.objective === value && (
                  <CheckCircle2 className="w-3.5 h-3.5 text-red-500" />
                )}
              </div>
              <p
                className={cn(
                  'text-xs',
                  state.objective === value ? 'text-red-600/70' : 'text-zinc-500',
                )}
              >
                {description}
              </p>
            </button>
          ))}
        </div>
      </div>

      {/* Attack behavior */}
      <div>
        <SectionHeader>Attack Behavior</SectionHeader>
        <div className="flex items-start gap-6">
          {/* Randomize toggle */}
          <div className="flex items-center gap-3 bg-zinc-50 border border-zinc-200 rounded-lg px-4 py-3">
            <Shuffle
              className={cn('w-4 h-4', state.randomize ? 'text-red-500' : 'text-zinc-400')}
            />
            <div>
              <div className="text-sm font-medium text-zinc-700">Randomize Techniques</div>
              <div className="text-xs text-zinc-500">Vary attack order to evade detection</div>
            </div>
            <button
              type="button"
              role="switch"
              aria-checked={state.randomize}
              onClick={() => onChange({ randomize: !state.randomize })}
              className={cn(
                'relative ml-4 w-9 h-5 rounded-full transition-colors duration-200 focus:outline-none',
                state.randomize ? 'bg-red-500' : 'bg-zinc-300',
              )}
            >
              <span
                className={cn(
                  'absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform duration-200',
                  state.randomize ? 'translate-x-4' : 'translate-x-0',
                )}
              />
            </button>
          </div>

          {/* Delay inputs */}
          <div className="flex items-end gap-3">
            <div>
              <FieldLabel>Delay Min (sec)</FieldLabel>
              <div className="relative">
                <Clock className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-zinc-400 pointer-events-none" />
                <Input
                  type="number"
                  min={0}
                  value={state.delayMin}
                  onChange={(e) => onChange({ delayMin: parseInt(e.target.value) || 0 })}
                  className="font-mono text-sm pl-6 w-28"
                />
              </div>
            </div>
            <div>
              <FieldLabel>Delay Max (sec)</FieldLabel>
              <div className="relative">
                <Clock className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-zinc-400 pointer-events-none" />
                <Input
                  type="number"
                  min={0}
                  value={state.delayMax}
                  onChange={(e) => onChange({ delayMax: parseInt(e.target.value) || 0 })}
                  className="font-mono text-sm pl-6 w-28"
                />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Step 3: Authorization
// ---------------------------------------------------------------------------

function Step3({
  state,
  onChange,
  authorized,
  onAuthorizedChange,
}: {
  state: WizardState
  onChange: (patch: Partial<WizardState>) => void
  authorized: boolean
  onAuthorizedChange: (v: boolean) => void
}) {
  return (
    <div className="space-y-5">
      {/* Tester info */}
      <div>
        <SectionHeader>Tester Information</SectionHeader>
        <div className="grid grid-cols-3 gap-3">
          <div>
            <FieldLabel required>Tester Name</FieldLabel>
            <Input
              type="text"
              value={state.testerName}
              onChange={(e) => onChange({ testerName: e.target.value })}
              placeholder="Jane Smith"
              className="text-sm"
            />
          </div>
          <div>
            <FieldLabel>Role</FieldLabel>
            <Input
              type="text"
              value={state.testerRole}
              onChange={(e) => onChange({ testerRole: e.target.value })}
              placeholder="Security Researcher"
              className="text-sm"
            />
          </div>
          <div>
            <FieldLabel>Organization</FieldLabel>
            <Input
              type="text"
              value={state.organization}
              onChange={(e) => onChange({ organization: e.target.value })}
              placeholder="Acme Corp"
              className="text-sm"
            />
          </div>
        </div>
      </div>

      {/* Scope descriptions */}
      <div>
        <SectionHeader>Scope & Context</SectionHeader>
        <div className="space-y-3">
          <div>
            <FieldLabel required>Infrastructure Description</FieldLabel>
            <textarea
              value={state.infrastructure}
              onChange={(e) => onChange({ infrastructure: e.target.value })}
              placeholder="Describe the infrastructure being tested..."
              rows={2}
              className="w-full text-sm font-sans border border-input bg-transparent rounded-lg px-3 py-2 placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:border-ring resize-none transition-colors"
            />
          </div>
          <div>
            <FieldLabel>Environment Description</FieldLabel>
            <textarea
              value={state.environment}
              onChange={(e) => onChange({ environment: e.target.value })}
              placeholder="Describe the environment (production, staging, lab, etc.)..."
              rows={2}
              className="w-full text-sm font-sans border border-input bg-transparent rounded-lg px-3 py-2 placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:border-ring resize-none transition-colors"
            />
          </div>
          <div>
            <FieldLabel>Monitoring in Place</FieldLabel>
            <textarea
              value={state.monitoring}
              onChange={(e) => onChange({ monitoring: e.target.value })}
              placeholder="List any SIEM, IDS/IPS, EDR, or monitoring systems active during the test..."
              rows={2}
              className="w-full text-sm font-sans border border-input bg-transparent rounded-lg px-3 py-2 placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:border-ring resize-none transition-colors"
            />
          </div>
        </div>
      </div>

      {/* Authorization checkbox */}
      <div
        className={cn(
          'flex items-start gap-3 p-4 rounded-xl border-2 transition-colors',
          authorized ? 'border-red-400 bg-red-50' : 'border-zinc-200 bg-zinc-50',
        )}
      >
        <div className="relative flex-shrink-0 mt-0.5">
          <input
            type="checkbox"
            id="authorization-confirm"
            checked={authorized}
            onChange={(e) => onAuthorizedChange(e.target.checked)}
            className="sr-only"
          />
          <button
            type="button"
            role="checkbox"
            aria-checked={authorized}
            onClick={() => onAuthorizedChange(!authorized)}
            className={cn(
              'w-5 h-5 rounded border-2 flex items-center justify-center transition-colors',
              authorized ? 'bg-red-500 border-red-500' : 'bg-white border-zinc-300',
            )}
          >
            {authorized && (
              <svg
                className="w-3 h-3 text-white"
                viewBox="0 0 12 12"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
              >
                <polyline points="2,6 5,9 10,3" />
              </svg>
            )}
          </button>
        </div>
        <label
          htmlFor="authorization-confirm"
          className="text-sm text-zinc-700 cursor-pointer leading-relaxed"
          onClick={() => onAuthorizedChange(!authorized)}
        >
          <span className="font-semibold text-zinc-900">
            I confirm I own this infrastructure and authorize this penetration test.
          </span>{' '}
          I understand that unauthorized access to computer systems is illegal and I take full
          responsibility for the execution of this engagement.
        </label>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Step 4: Review & Launch
// ---------------------------------------------------------------------------

function Step4({
  state,
  onChange,
  authorized,
  validationErrors,
  onLaunch,
  launching,
}: {
  state: WizardState
  onChange: (patch: Partial<WizardState>) => void
  authorized: boolean
  validationErrors: string[]
  onLaunch: () => void
  launching: boolean
}) {
  const yaml = generateConfigYaml(state)
  const canLaunch = authorized && validationErrors.length === 0 && !launching

  const handleBrowse = useCallback(async () => {
    try {
      const filePath = await window.wraithAPI.selectConfigFile()
      if (filePath) {
        onChange({ logDir: filePath })
      }
    } catch {
      // file dialog cancelled or failed
    }
  }, [onChange])

  return (
    <div className="space-y-5">
      {/* Validation errors */}
      {validationErrors.length > 0 && (
        <div className="rounded-xl border-2 border-red-300 bg-red-50 p-4">
          <div className="flex items-center gap-2 mb-2">
            <AlertCircle className="w-4 h-4 text-red-500" />
            <span className="text-sm font-semibold text-red-700">
              {validationErrors.length} validation {validationErrors.length === 1 ? 'error' : 'errors'}
            </span>
          </div>
          <ul className="space-y-1">
            {validationErrors.map((err, i) => (
              <li key={i} className="text-xs text-red-600 flex items-start gap-1.5">
                <span className="text-red-400 mt-0.5">--</span>
                {err}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Authorization status */}
      {!authorized && (
        <div className="flex items-center gap-2 text-xs text-amber-600 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2">
          <AlertCircle className="w-3.5 h-3.5 shrink-0" />
          Return to Authorization step and confirm ownership before launching.
        </div>
      )}

      {/* Engine path */}
      <div>
        <SectionHeader>Wraith Engine</SectionHeader>
        <div>
          <FieldLabel>Engine Path (dist/index.js)</FieldLabel>
          <div className="flex gap-2">
            <Input
              type="text"
              value={state.logDir === './attack-logs' ? '../../dist/index.js' : state.logDir}
              onChange={(e) => onChange({ logDir: e.target.value })}
              placeholder="../../dist/index.js"
              className="font-mono text-sm flex-1"
            />
            <Button variant="outline" size="sm" onClick={handleBrowse} className="gap-1.5 shrink-0">
              <FolderOpen className="w-3.5 h-3.5" />
              Browse
            </Button>
          </div>
          <p className="text-[10px] text-zinc-400 mt-1">
            Relative to wraith-desktop directory. Default: ../../dist/index.js
          </p>
        </div>

        {/* Skip preflight */}
        <div className="flex items-center gap-3 mt-3">
          <button
            type="button"
            role="switch"
            aria-checked={state.skipPreflight}
            onClick={() => onChange({ skipPreflight: !state.skipPreflight })}
            className={cn(
              'relative w-9 h-5 rounded-full transition-colors duration-200 focus:outline-none shrink-0',
              state.skipPreflight ? 'bg-red-500' : 'bg-zinc-300',
            )}
          >
            <span
              className={cn(
                'absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform duration-200',
                state.skipPreflight ? 'translate-x-4' : 'translate-x-0',
              )}
            />
          </button>
          <div>
            <span className="text-sm font-medium text-zinc-700">Skip Preflight Checks</span>
            <p className="text-xs text-zinc-500">
              Bypass pre-engagement connectivity and dependency validation.
            </p>
          </div>
        </div>
      </div>

      {/* YAML preview */}
      <div>
        <SectionHeader>Configuration Preview (YAML)</SectionHeader>
        <div className="relative">
          <pre className="font-mono text-xs text-zinc-300 bg-zinc-900 border border-zinc-700 rounded-xl p-4 overflow-auto max-h-64 leading-relaxed whitespace-pre">
            {yaml}
          </pre>
        </div>
      </div>

      {/* Launch button */}
      <button
        type="button"
        onClick={onLaunch}
        disabled={!canLaunch}
        className={cn(
          'w-full flex items-center justify-center gap-2 py-3 px-6 rounded-xl text-sm font-semibold transition-all duration-150',
          canLaunch
            ? 'bg-red-600 hover:bg-red-700 text-white shadow-md hover:shadow-red-900/20 cursor-pointer active:translate-y-px'
            : 'bg-zinc-200 text-zinc-400 cursor-not-allowed',
        )}
      >
        {launching ? (
          <>
            <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            Launching Engagement...
          </>
        ) : (
          <>
            <Rocket className="w-4 h-4" />
            Launch Engagement
          </>
        )}
      </button>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Step indicator
// ---------------------------------------------------------------------------

function StepIndicator({
  currentStep,
  onStepClick,
}: {
  currentStep: StepId
  onStepClick: (step: StepId) => void
}) {
  return (
    <div className="flex items-center gap-0 mb-8">
      {STEPS.map((step, idx) => {
        const Icon = step.icon
        const isActive = step.id === currentStep
        const isCompleted = step.id < currentStep
        const isClickable = step.id < currentStep

        return (
          <div key={step.id} className="flex items-center flex-1 last:flex-none">
            <button
              type="button"
              onClick={() => isClickable && onStepClick(step.id)}
              disabled={!isClickable && !isActive}
              className={cn(
                'flex items-center gap-2 py-2 px-3 rounded-lg transition-all duration-150 group',
                isActive
                  ? 'bg-red-50 border border-red-200 cursor-default'
                  : isCompleted
                    ? 'hover:bg-zinc-100 cursor-pointer border border-transparent'
                    : 'cursor-default opacity-50 border border-transparent',
              )}
            >
              <div
                className={cn(
                  'w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold transition-colors shrink-0',
                  isActive
                    ? 'bg-red-500 text-white'
                    : isCompleted
                      ? 'bg-zinc-700 text-white'
                      : 'bg-zinc-200 text-zinc-500',
                )}
              >
                {isCompleted ? (
                  <CheckCircle2 className="w-4 h-4" />
                ) : (
                  <Icon className="w-3.5 h-3.5" />
                )}
              </div>
              <div className="text-left hidden sm:block">
                <div
                  className={cn(
                    'text-[10px] font-medium uppercase tracking-wider',
                    isActive ? 'text-red-600' : isCompleted ? 'text-zinc-600' : 'text-zinc-400',
                  )}
                >
                  Step {step.id}
                </div>
                <div
                  className={cn(
                    'text-xs font-semibold',
                    isActive ? 'text-red-700' : isCompleted ? 'text-zinc-700' : 'text-zinc-400',
                  )}
                >
                  {step.label}
                </div>
              </div>
            </button>

            {idx < STEPS.length - 1 && (
              <div
                className={cn(
                  'flex-1 h-px mx-2 transition-colors',
                  step.id < currentStep ? 'bg-zinc-400' : 'bg-zinc-200',
                )}
              />
            )}
          </div>
        )
      })}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main LaunchPage
// ---------------------------------------------------------------------------

export default function LaunchPage() {
  const navigate = useNavigate()

  const [step, setStep] = useState<StepId>(1)
  const [state, setState] = useState<WizardState>(getDefaultConfig)
  const [authorized, setAuthorized] = useState(false)
  const [validationErrors, setValidationErrors] = useState<string[]>([])
  const [launching, setLaunching] = useState(false)
  const [wraithDistPath, setWraithDistPath] = useState('../../dist/index.js')

  const onChange = useCallback((patch: Partial<WizardState>) => {
    setState((prev) => ({ ...prev, ...patch }))
  }, [])

  // Re-validate whenever relevant state changes
  useEffect(() => {
    const errors = validateConfig(state)
    setValidationErrors(errors)
  }, [state])

  const handleNext = useCallback(() => {
    if (step < 4) setStep((s) => (s + 1) as StepId)
  }, [step])

  const handleBack = useCallback(() => {
    if (step > 1) setStep((s) => (s - 1) as StepId)
  }, [step])

  const handleStepClick = useCallback((targetStep: StepId) => {
    setStep(targetStep)
  }, [])

  const handleLaunch = useCallback(async () => {
    const errors = validateConfig(state)
    if (errors.length > 0) {
      setValidationErrors(errors)
      return
    }

    if (!authorized) return

    setLaunching(true)
    try {
      const configYaml = generateConfigYaml(state)

      // Reset stores
      useEngagementStore.getState().reset()
      usePipelineStore.getState().reset()
      usePipelineStore.getState().setRunState('starting')

      await window.wraithAPI.launch({
        configYaml,
        wraithDistPath,
        skipPreflight: state.skipPreflight,
      })

      navigate('/')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Launch failed'
      setValidationErrors([message])
      usePipelineStore.getState().setRunState('error')
    } finally {
      setLaunching(false)
    }
  }, [state, authorized, wraithDistPath, navigate])

  const stepTitles: Record<StepId, string> = {
    1: 'Define what you are targeting and how you are entering the network.',
    2: 'Tune the agent planning parameters and attack behavior.',
    3: 'Confirm authorization before any attacks are executed.',
    4: 'Review the generated configuration and start the engagement.',
  }

  return (
    <div className="flex flex-col gap-0 max-w-4xl mx-auto">
      {/* Page header */}
      <div className="flex items-center gap-3 mb-6">
        <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-red-50 border border-red-200">
          <Rocket className="w-4 h-4 text-red-500" />
        </div>
        <div>
          <h1 className="text-lg font-semibold tracking-tight text-foreground">New Engagement</h1>
          <p className="text-sm text-muted-foreground">Configure and launch a penetration test</p>
        </div>
      </div>

      {/* Step indicator */}
      <StepIndicator currentStep={step} onStepClick={handleStepClick} />

      {/* Step card */}
      <Card className="ring-1 ring-zinc-200 bg-white">
        <CardHeader className="border-b border-zinc-100 pb-4">
          <div className="flex items-center gap-2">
            <div className="flex items-center justify-center w-6 h-6 rounded bg-red-500 text-white text-xs font-bold">
              {step}
            </div>
            <div>
              <CardTitle className="text-base font-semibold text-zinc-900">
                {STEPS[step - 1].label}
              </CardTitle>
              <p className="text-xs text-zinc-500 mt-0.5">{stepTitles[step]}</p>
            </div>
          </div>
        </CardHeader>
        <CardContent className="pt-5 pb-5">
          {step === 1 && <Step1 state={state} onChange={onChange} />}
          {step === 2 && <Step2 state={state} onChange={onChange} />}
          {step === 3 && (
            <Step3
              state={state}
              onChange={onChange}
              authorized={authorized}
              onAuthorizedChange={setAuthorized}
            />
          )}
          {step === 4 && (
            <Step4
              state={state}
              onChange={(patch) => {
                // Handle wraithDistPath separately
                if ('logDir' in patch && patch.logDir !== './attack-logs') {
                  setWraithDistPath(patch.logDir as string)
                } else {
                  onChange(patch)
                }
              }}
              authorized={authorized}
              validationErrors={validationErrors}
              onLaunch={handleLaunch}
              launching={launching}
            />
          )}
        </CardContent>
      </Card>

      {/* Navigation footer */}
      <div className="flex items-center justify-between mt-4">
        <Button
          variant="outline"
          onClick={handleBack}
          disabled={step === 1}
          className="gap-1.5 border-zinc-200 text-zinc-600"
        >
          <ChevronLeft className="w-4 h-4" />
          Back
        </Button>

        <div className="flex items-center gap-1.5">
          {STEPS.map((s) => (
            <div
              key={s.id}
              className={cn(
                'w-1.5 h-1.5 rounded-full transition-colors',
                s.id === step ? 'bg-red-500' : s.id < step ? 'bg-zinc-500' : 'bg-zinc-200',
              )}
            />
          ))}
        </div>

        {step < 4 ? (
          <Button
            onClick={handleNext}
            className="gap-1.5 bg-zinc-900 hover:bg-zinc-800 text-white"
          >
            Next
            <ChevronRight className="w-4 h-4" />
          </Button>
        ) : (
          <div className="w-20" /> // spacer to keep layout balanced on step 4
        )}
      </div>
    </div>
  )
}
