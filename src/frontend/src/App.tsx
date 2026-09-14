import { Routes, Route } from 'react-router-dom'
import { Home } from './pages/Home'
import { NotFound } from './pages/NotFound'
import { UnderConstruction } from './pages/UnderConstruction'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/login" element={<UnderConstruction pageName="Demo access" />} />
      <Route path="*" element={<NotFound />} />
    </Routes>
  )
}