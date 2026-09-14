import { useEffect, useState } from 'react'
import { Link, NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import {
  BarChart3,
  Bell,
  FileText,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  Network,
  Settings,
  ShieldCheck,
  Sun,
  Target,
  X,
} from 'lucide-react'
import { ThreatLensLogo } from '../logo/ThreatLensLogo'
import { useTheme } from '../theme/ThemeProvider'
import { endDemoSession, getDemoSession } from '../../lib/demoSession'

const navItems = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/alerts', label: 'Alerts', icon: Bell, end: false },
  { to: '/incidents', label: 'Incidents', icon: Network, end: false },
  { to: '/mitre', label: 'MITRE ATT&CK', icon: Target, end: false },
  { to: '/briefs', label: 'BLUF Briefs', icon: FileText, end: false },
  { to: '/analytics', label: 'Analytics', icon: BarChart3, end: false },
  { to: '/settings', label: 'Settings', icon: Settings, end: false },
]

const pageTitles: Record<string, string> = {
  '/dashboard': 'Security overview',
  '/alerts': 'Alert intelligence',
  '/incidents': 'Threat correlation',
  '/mitre': 'MITRE ATT&CK',
  '/briefs': 'BLUF briefs',
  '/analytics': 'Analytics',
  '/settings': 'Settings',
}

function SidebarContent() {
  const session = getDemoSession()
  const displayName = session?.displayName ?? 'Guest analyst'

  return (
    <nav className="flex h-full flex-col" aria-label="Main navigation">
      <div className="flex h-16 items-center border-b border-border px-4">
        <Link to="/dashboard" className="rounded">
          <ThreatLensLogo size={28} withWordmark />
        </Link>
      </div>

      <ul className="flex-1 space-y-1 overflow-y-auto px-3 py-4">
        {navItems.map((item) => (
          <li key={item.to}>
            <NavLink
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-primary/15 text-primary'
                    : 'text-foreground-muted hover:bg-surface-2 hover:text-foreground'
                }`
              }
            >
              <item.icon className="h-4 w-4 shrink-0" aria-hidden="true" />
              {item.label}
            </NavLink>
          </li>
        ))}
      </ul>

      <div className="border-t border-border p-3">
        <div className="rounded-lg bg-surface-2/60 px-3 py-2.5">
          <p className="text-xs font-semibold text-foreground">{displayName}</p>
          <p className="mt-0.5 text-xs text-foreground-muted">Demo session · simulated</p>
        </div>
      </div>
    </nav>
  )
}

export function AppShell() {
  const { theme, toggle } = useTheme()
  const ThemeIcon = theme === 'dark' ? Sun : Moon
  const navigate = useNavigate()
  const location = useLocation()
  const [sidebarOpen, setSidebarOpen] = useState(false)

  const currentTitle = pageTitles[location.pathname] ?? 'ThreatLens'

  useEffect(() => {
    setSidebarOpen(false)
  }, [location.pathname])

  function handleSignOut() {
    endDemoSession()
    navigate('/login')
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-64 border-r border-border bg-surface lg:block">
        <SidebarContent />
      </aside>

      {sidebarOpen && (
        <div className="fixed inset-0 z-50 lg:hidden" role="dialog" aria-modal="true" aria-label="Navigation">
          <button
            type="button"
            className="absolute inset-0 h-full w-full bg-black/60"
            onClick={() => setSidebarOpen(false)}
            aria-label="Close navigation"
          />
          <div className="absolute inset-y-0 left-0 w-72 bg-surface shadow-2xl">
            <div className="flex h-16 items-center justify-between border-b border-border px-4">
              <ThreatLensLogo size={28} withWordmark />
              <button
                type="button"
                onClick={() => setSidebarOpen(false)}
                aria-label="Close navigation"
                className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-border bg-surface text-foreground-muted transition-colors hover:bg-surface-2 hover:text-foreground"
              >
                <X className="h-4 w-4" aria-hidden="true" />
              </button>
            </div>
            <div className="overflow-y-auto">
              <SidebarContent />
            </div>
          </div>
        </div>
      )}

      <div className="lg:pl-64">
        <header className="sticky top-0 z-30 border-b border-border bg-background/90 backdrop-blur">
          <div className="flex h-16 items-center justify-between gap-4 px-4 sm:px-6">
            <div className="flex min-w-0 items-center gap-3">
              <button
                type="button"
                onClick={() => setSidebarOpen(true)}
                aria-label="Open navigation"
                className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-border bg-surface text-foreground-muted transition-colors hover:bg-surface-2 hover:text-foreground lg:hidden"
              >
                <Menu className="h-4 w-4" aria-hidden="true" />
              </button>
              <div className="min-w-0">
                <p className="truncate text-sm font-semibold">{currentTitle}</p>
                <p className="hidden truncate text-xs text-foreground-muted sm:block">
                  ThreatLens demo environment
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 sm:gap-3">
              <span className="hidden items-center gap-1.5 rounded-full border border-primary/40 bg-primary/10 px-2.5 py-1 text-xs font-medium text-primary sm:inline-flex">
                <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
                Demo
              </span>
              <button
                type="button"
                onClick={toggle}
                aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
                className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-border bg-surface text-foreground-muted transition-colors hover:bg-surface-2 hover:text-foreground"
              >
                <ThemeIcon className="h-4 w-4" aria-hidden="true" />
              </button>
              <button
                type="button"
                onClick={handleSignOut}
                aria-label="Sign out of demo session"
                className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-border bg-surface text-foreground-muted transition-colors hover:bg-surface-2 hover:text-foreground"
              >
                <LogOut className="h-4 w-4" aria-hidden="true" />
              </button>
            </div>
          </div>
        </header>

        <main className="px-4 py-8 sm:px-6 lg:px-8">
          <Outlet />
        </main>
      </div>
    </div>
  )
}