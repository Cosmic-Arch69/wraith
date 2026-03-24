import { contextBridge, ipcRenderer, type IpcRendererEvent } from 'electron'
import { electronAPI } from '@electron-toolkit/preload'
import { IPC, type WraithAPI, type PipelineEvent } from '../shared/ipc-types'

// Typed Wraith API exposed to renderer via contextBridge
// Renderer accesses this as window.wraithAPI
// This is the ONLY channel between renderer and Node.js
const wraithAPI: WraithAPI = {
  launch: (config) => ipcRenderer.invoke(IPC.LAUNCH, config),
  stop: () => ipcRenderer.invoke(IPC.STOP),
  getStatus: () => ipcRenderer.invoke(IPC.STATUS),
  onPipelineEvent: (cb) => {
    const handler = (_event: IpcRendererEvent, data: PipelineEvent): void => cb(data)
    ipcRenderer.on(IPC.PIPELINE_EVENT, handler)
    // Return cleanup function (prevents IPC listener accumulation -- research lesson)
    return (): void => {
      ipcRenderer.removeListener(IPC.PIPELINE_EVENT, handler)
    }
  },
  selectConfigFile: () => ipcRenderer.invoke(IPC.SELECT_CONFIG),
  platform: process.platform,
}

// Expose APIs via contextBridge (contextIsolation: true)
if (process.contextIsolated) {
  try {
    contextBridge.exposeInMainWorld('electron', electronAPI)
    contextBridge.exposeInMainWorld('wraithAPI', wraithAPI)
  } catch (error) {
    console.error(error)
  }
} else {
  // @ts-ignore (define in dts)
  window.electron = electronAPI
  // @ts-ignore (define in dts)
  window.wraithAPI = wraithAPI
}
