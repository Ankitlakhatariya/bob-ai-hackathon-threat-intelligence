import { useEffect, useState } from 'react'
import { Bell, CheckCircle2, Database, Info, Moon, RotateCcw, SlidersHorizontal, Sun } from 'lucide-react'
import type { ReactNode } from 'react'
import { useTheme } from '../components/theme/ThemeProvider'

type ThemeMode = 'dark' | 'light'
type SeverityThreshold = 'all' | 'high' | 'critical'

interface SettingsState {
  severityThreshold: SeverityThreshold
  notifyInApp: boolean
  notifyEmail: boolean
  notifyChannel: boolean
}

const STORAGE_KEY = 'threatlens-settings'

const DEFAULT_SETTINGS: SettingsState = {
  severityThreshold: 'all',
  notifyInApp: true,
  notifyEmail: false,
  notifyChannel: true,
}

const thresholdOptions: { value: SeverityThreshold; label: string }[] = [
  { value: 'all', label: 'All severities' },
  { value: 'high', label: 'High & critical' },
  { value: 'critical', label: 'Critical only' },
]

function loadSettings(): SettingsState {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return DEFAULT_SETTINGS
    const parsed = JSON.parse(raw) as Partial<SettingsState>
    const severityThreshold = ['all', 'high', 'critical'].includes(parsed.severityThreshold ?? '')
      ? (parsed.severityThreshold as SeverityThreshold)
      : DEFAULT_SETTINGS.severityThreshold
    return {
      severityThreshold,
      notifyInApp: parsed.notifyInApp ?? DEFAULT_SETTINGS.notifyInApp,
      notifyEmail: parsed.notifyEmail ?? DEFAULT_SETTINGS.notifyEmail,
      notifyChannel: parsed.notifyChannel ?? DEFAULT_SETTINGS.notifyChannel,
    }
  } catch {
    return DEFAULT_SETTINGS
  }
}

function saveSettings(settings: SettingsState) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(settings))
  } catch {
    // no-op: simulated settings persistence is best-effort
  }
}

export function Settings() {
  const { theme, toggle } = useTheme()
  const [settings, setSettings] = useState<SettingsState>(loadSettings)
  const [resetNotice, setResetNotice] = useState(false)

  useEffect(() => {
    saveSettings(settings)
  }, [settings])

  function handleThemeMode(mode: ThemeMode) {
    if (mode !== theme) toggle()
  }

  function handleReset() {
    setSettings(DEFAULT_SETTINGS)
    setResetNotice(true)
    const timeout = window.setTimeout(() => setResetNotice(false), 3000)
    return () => window.clearTimeout(timeout)
  }

  return (
    <div className="mx-auto max-w-3xl">
      <h1 className="text-xl font-bold tracking-tight">Settings</h1>
      <p className="mt-1 text-sm text-foreground-muted">
        Analyst workspace preferences. Everything here is stored locally in your browser and is
        part of the simulated demo experience.
      </p>

      <div className="mt-6 grid gap-4">
        <SettingsCard
          icon={theme === 'dark' ? Moon : Sun}
          title="Appearance"
          description="Choose the colour theme used across the workspace."
        >
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-sm text-foreground-muted">
              Current theme: <span className="font-semibold text-foreground">{theme === 'dark' ? 'Dark' : 'Light'}</span>
            </p>
            <div
              className="inline-flex rounded-lg border border-border bg-surface p-1"
              role="group"
              aria-label="Theme mode"
            >
              {(['dark', 'light'] as const).map((mode) => (
                <button
                  key={mode}
                  type="button"
                  onClick={() => handleThemeMode(mode)}
                  aria-pressed={theme === mode}
                  className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold transition-colors ${
                    theme === mode
                      ? 'bg-primary text-primary-foreground'
                      : 'text-foreground-muted hover:text-foreground'
                  }`}
                >
                  {mode === 'dark' ? (
                    <Moon className="h-3.5 w-3.5" aria-hidden="true" />
                  ) : (
                    <Sun className="h-3.5 w-3.5" aria-hidden="true" />
                  )}
                  {mode === 'dark' ? 'Dark' : 'Light'}
                </button>
              ))}
            </div>
          </div>
        </SettingsCard>

        <SettingsCard
          icon={SlidersHorizontal}
          title="Alert thresholds"
          description="Set the minimum severity you want to focus on. Demo preference only — not yet wired to other pages."
        >
          <div className="grid gap-2 sm:grid-cols-3">
            {thresholdOptions.map((option) => (
              <button
                key={option.value}
                type="button"
                onClick={() =>
                  setSettings((current) => ({ ...current, severityThreshold: option.value }))
                }
                aria-pressed={settings.severityThreshold === option.value}
                className={`rounded-lg border px-3 py-2.5 text-left text-sm font-semibold transition-colors ${
                  settings.severityThreshold === option.value
                    ? 'border-primary bg-primary/10 text-primary'
                    : 'border-border bg-surface text-foreground-muted hover:bg-surface-2 hover:text-foreground'
                }`}
              >
                {option.label}
              </button>
            ))}
          </div>
        </SettingsCard>

        <SettingsCard
          icon={Bell}
          title="Notifications"
          description="Which simulated channels should surface critical activity."
        >
          <div className="divide-y divide-border">
            <SettingRow
              label="In-app alerts"
              description="Banners inside the demo workspace"
              control={
                <Switch
                  checked={settings.notifyInApp}
                  onChange={(checked) =>
                    setSettings((current) => ({ ...current, notifyInApp: checked }))
                  }
                  label="In-app alerts"
                />
              }
            />
            <SettingRow
              label="Email digest"
              description="Simulated daily summary"
              control={
                <Switch
                  checked={settings.notifyEmail}
                  onChange={(checked) =>
                    setSettings((current) => ({ ...current, notifyEmail: checked }))
                  }
                  label="Email digest"
                />
              }
            />
            <SettingRow
              label="Team channel push"
              description="Simulated shared channel notifications"
              control={
                <Switch
                  checked={settings.notifyChannel}
                  onChange={(checked) =>
                    setSettings((current) => ({ ...current, notifyChannel: checked }))
                  }
                  label="Team channel push"
                />
              }
            />
          </div>
        </SettingsCard>

        <SettingsCard
          icon={Database}
          title="Demo data"
          description="Reset locally saved preferences back to their defaults."
        >
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-sm text-foreground-muted">
              Clears the settings stored on this device. Mock alerts, incidents and briefs stay
              unchanged.
            </p>
            <button
              type="button"
              onClick={handleReset}
              className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-surface px-4 py-2 text-sm font-semibold text-foreground transition-colors hover:bg-surface-2"
            >
              <RotateCcw className="h-4 w-4" aria-hidden="true" />
              Reset preferences
            </button>
          </div>
          {resetNotice && (
            <p
              role="status"
              className="mt-3 inline-flex items-center gap-1.5 text-sm font-medium text-safe"
            >
              <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
              Demo settings reset to defaults.
            </p>
          )}
        </SettingsCard>

        <SettingsCard icon={Info} title="About" description="Build status for this demo environment.">
          <dl className="space-y-2 text-sm">
            <div className="flex items-center justify-between gap-4">
              <dt className="text-foreground-muted">Version</dt>
              <dd className="font-mono text-foreground">0.1.0</dd>
            </div>
            <div className="flex items-center justify-between gap-4">
              <dt className="text-foreground-muted">Data source</dt>
              <dd className="font-mono text-foreground">simulated mock data</dd>
            </div>
            <div className="flex items-center justify-between gap-4">
              <dt className="text-foreground-muted">Correlation engine</dt>
              <dd className="font-mono text-foreground">pending AI/backend integration</dd>
            </div>
          </dl>
          <p className="mt-4 text-[11px] leading-relaxed text-foreground-muted">
            ThreatLens is a hackathon demo. No real security data is processed and no claims about
            real-world detection are implied.
          </p>
        </SettingsCard>
      </div>
    </div>
  )
}

function SettingsCard({
  icon: Icon,
  title,
  description,
  children,
}: {
  icon: typeof Bell
  title: string
  description: string
  children: ReactNode
}) {
  return (
    <section className="rounded-xl border border-border bg-surface p-5">
      <div className="flex items-start gap-3">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-accent/15 text-accent">
          <Icon className="h-4 w-4" aria-hidden="true" />
        </div>
        <div>
          <h2 className="text-sm font-semibold">{title}</h2>
          <p className="mt-0.5 text-xs text-foreground-muted">{description}</p>
        </div>
      </div>
      <div className="mt-4">{children}</div>
    </section>
  )
}

function SettingRow({
  label,
  description,
  control,
}: {
  label: string
  description: string
  control: ReactNode
}) {
  return (
    <div className="flex items-center justify-between gap-4 py-3.5 first:pt-2 last:pb-2">
      <div>
        <p className="text-sm font-medium">{label}</p>
        <p className="mt-0.5 text-xs text-foreground-muted">{description}</p>
      </div>
      {control}
    </div>
  )
}

function Switch({
  checked,
  onChange,
  label,
}: {
  checked: boolean
  onChange: (checked: boolean) => void
  label: string
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full border transition-colors ${
        checked ? 'border-primary bg-primary' : 'border-border bg-surface-2'
      }`}
    >
      <span
        className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${
          checked ? 'translate-x-[22px]' : 'translate-x-1'
        }`}
      />
    </button>
  )
}