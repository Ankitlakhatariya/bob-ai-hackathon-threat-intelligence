import { Routes, Route } from 'react-router-dom'
import { Home } from './pages/Home'
import { Login } from './pages/Login'
import { Dashboard } from './pages/Dashboard'
import { Alerts } from './pages/Alerts'
import { AlertDetail } from './pages/AlertDetail'
import { Incidents } from './pages/Incidents'
import { Mitre } from './pages/Mitre'
import { Briefs } from './pages/Briefs'
import { Analytics } from './pages/Analytics'
import { Settings } from './pages/Settings'
import { NotFound } from './pages/NotFound'
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
        <Route path="/mitre" element={<Mitre />} />
        <Route path="/briefs" element={<Briefs />} />
        <Route path="/analytics" element={<Analytics />} />
        <Route path="/settings" element={<Settings />} />
      </Route>
      <Route path="*" element={<NotFound />} />
    </Routes>
  )
}