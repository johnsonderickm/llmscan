import { useCallback, useEffect, useRef, useState } from 'react'
import type { ScanEvent } from '../types'

interface UseScanFeedResult {
  events: ScanEvent[]
  connected: boolean
  error: string | null
}

export function useScanFeed(scanId: string | null): UseScanFeedResult {
  const [events, setEvents] = useState<ScanEvent[]>([])
  const [connected, setConnected] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const wsRef = useRef<WebSocket | null>(null)

  const connect = useCallback(() => {
    if (!scanId) return
    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${protocol}://${window.location.host}/ws/scan/${scanId}`)
    wsRef.current = ws

    ws.onopen = () => {
      setConnected(true)
      setError(null)
    }

    ws.onmessage = (e) => {
      try {
        const event: ScanEvent = JSON.parse(e.data)
        setEvents(prev => [...prev, event])
      } catch {
        // ignore malformed frames
      }
    }

    ws.onerror = () => setError('WebSocket connection error')

    ws.onclose = () => {
      setConnected(false)
      wsRef.current = null
    }
  }, [scanId])

  useEffect(() => {
    if (!scanId) return
    setEvents([])
    setError(null)
    connect()
    return () => {
      wsRef.current?.close()
    }
  }, [scanId, connect])

  return { events, connected, error }
}
