import { Routes, Route } from 'react-router-dom'
import { Home } from './pages/Home'
import { Login } from './pages/Login'
import { Dashboard } from './pages/Dashboard'
import { Alerts } from './pages/Alerts'
import { AlertDetail } from './pages/AlertDetail'
import { Incidents } from './pages/Incidents'
import { NotFound } from './pages/NotFound'
import { PageStub } from './pages/PageStub'
import { AppShell } from './components/layout/AppShell'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/login" element={<Login />} />
      <Route element={<AppShell />}>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/alerts/:alertId" element={<AlertDetail />} />
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/mitre" element={<PageStub title="MITRE ATT&CK explorer" />} />
        <Route path="/briefs" element={<PageStub title="BLUF investigation briefs" />} />
        <Route path="/analytics" element={<PageStub title="Threat analytics" />} />
        <Route path="/settings" element={<PageStub title="Settings" />} />
      </Route>
      <Route path="*" element={<NotFound />} />
    </Routes>
  )
}