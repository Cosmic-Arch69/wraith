import { ElectronAPI } from '@electron-toolkit/preload'
import type { WraithAPI } from '../shared/ipc-types'

declare global {
  interface Window {
    electron: ElectronAPI
    wraithAPI: WraithAPI
  }
}
