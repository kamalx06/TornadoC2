import { useSyncExternalStore } from 'react'
import { snapshot, subscribe } from './events'

export function useEvents(): ReturnType<typeof snapshot> {
  return useSyncExternalStore(subscribe, snapshot)
}
