import { useEffect, useRef, useState } from 'react'
import { getAccessToken } from '../lib/authSession'

export function useThreatUpdates(onUpdate?: (event: any) => void) {
  const ws = useRef<WebSocket | null>(null)
  const reconnectTimeout = useRef<number | null>(null)
  const [isConnected, setIsConnected] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true

    function connect() {
      if (!active) return

      const token = getAccessToken()
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const host = window.location.host
      
      // We route through vite proxy if in dev, or straight to backend in prod.
      // But Vite's proxy for WebSocket requires the same port or specifically configured proxy.
      // We'll use the same host, which is the vite dev server (e.g. localhost:5173).
      // Vite proxy is already set up for /api in vite.config.ts.
      // And websockets are supported by Vite proxy by default.
      const wsUrl = `${protocol}//${host}/api/v1/ws/threats${token ? `?token=${encodeURIComponent(token)}` : ''}`

      try {
        const socket = new WebSocket(wsUrl)
        ws.current = socket

        socket.onopen = () => {
          if (!active) {
            socket.close()
            return
          }
          console.log('WebSocket connected for real-time updates')
          setIsConnected(true)
          setError(null)
          
          // Send periodic pings to keep the connection alive, if necessary
          // But backend supports receiving 'ping' and returning 'pong'
          const intervalId = setInterval(() => {
            if (socket.readyState === WebSocket.OPEN) {
              socket.send('ping')
            }
          }, 30000)
          
          socket.addEventListener('close', () => clearInterval(intervalId))
        }

        socket.onmessage = (event) => {
          if (!active) return
          if (event.data === 'pong') return
          
          try {
            const payload = JSON.parse(event.data)
            console.log('Real-time update received:', payload)
            if (onUpdate) onUpdate(payload)
          } catch (err) {
            console.error('Error parsing WS message', err)
          }
        }

        socket.onclose = (event) => {
          if (!active) return
          setIsConnected(false)
          console.log('WebSocket disconnected', event.reason || event.code)
          
          // Reconnect with backoff (e.g., 5 seconds)
          reconnectTimeout.current = window.setTimeout(() => {
            connect()
          }, 5000)
        }
        
        socket.onerror = (err) => {
          if (!active) return
          console.error('WebSocket error:', err)
          setError('WebSocket connection error')
          // onclose will be called after onerror usually, which handles reconnection
        }
      } catch (err: any) {
        if (!active) return
        console.warn('WebSocket setup failed:', err)
        setError(err.message || 'WebSocket setup failed')
      }
    }

    connect()

    return () => {
      active = false
      if (reconnectTimeout.current !== null) {
        window.clearTimeout(reconnectTimeout.current)
      }
      if (ws.current) {
        ws.current.close()
      }
    }
  }, [onUpdate])

  return { isConnected, error }
}
