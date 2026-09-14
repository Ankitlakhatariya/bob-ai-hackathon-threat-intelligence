import { Routes, Route } from 'react-router-dom'
import { Home } from './pages/Home'
import { Login } from './pages/Login'
import { NotFound } from './pages/NotFound'
import { UnderConstruction } from './pages/UnderConstruction'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/login" element={<Login />} />
      <Route path="/dashboard" element={<UnderConstruction pageName="Security dashboard" />} />
      <Route path="*" element={<NotFound />} />
    </Routes>
  )
}