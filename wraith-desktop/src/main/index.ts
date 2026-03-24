import { app, shell, BrowserWindow, ipcMain, dialog } from 'electron'
import { join } from 'path'
import { electronApp, optimizer, is } from '@electron-toolkit/utils'
import icon from '../../resources/icon.png?asset'
import { PipelineManager } from './pipeline-manager'
import { IPC, type LaunchConfig } from '../shared/ipc-types'
import { buildAppMenu } from './menu'

const pipelineManager = new PipelineManager()

function createWindow(): void {
  const mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1024,
    minHeight: 700,
    title: 'Wraith v3.8.0',
    show: false,
    autoHideMenuBar: false,
    ...(process.platform === 'linux' ? { icon } : {}),
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false, // needed for preload contextBridge
    },
  })

  // Give pipeline manager the window reference for event forwarding
  pipelineManager.setMainWindow(mainWindow)
  buildAppMenu(mainWindow)

  mainWindow.on('ready-to-show', () => {
    mainWindow.show()
    if (is.dev) {
      mainWindow.webContents.openDevTools()
    }
  })

  mainWindow.webContents.setWindowOpenHandler((details) => {
    shell.openExternal(details.url)
    return { action: 'deny' }
  })

  // HMR for development, file:// for production
  if (is.dev && process.env['ELECTRON_RENDERER_URL']) {
    mainWindow.loadURL(process.env['ELECTRON_RENDERER_URL'])
  } else {
    mainWindow.loadFile(join(__dirname, '../renderer/index.html'))
  }
}

// ---- IPC Handlers ----

function registerIpcHandlers(): void {
  ipcMain.handle(IPC.LAUNCH, async (_event, config: LaunchConfig) => {
    return pipelineManager.launch(config)
  })

  ipcMain.handle(IPC.STOP, async () => {
    return pipelineManager.stop()
  })

  ipcMain.handle(IPC.STATUS, async () => {
    return pipelineManager.getStatus()
  })

  ipcMain.handle(IPC.SELECT_CONFIG, async () => {
    const result = await dialog.showOpenDialog({
      properties: ['openFile'],
      filters: [{ name: 'YAML Config', extensions: ['yaml', 'yml'] }],
    })
    return result.canceled ? null : result.filePaths[0]
  })
}

// ---- App Lifecycle ----

app.whenReady().then(() => {
  electronApp.setAppUserModelId('com.wraith.desktop')

  // F12 opens DevTools in development
  app.on('browser-window-created', (_, window) => {
    optimizer.watchWindowShortcuts(window)
  })

  registerIpcHandlers()
  createWindow()

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit()
  }
})

// Clean shutdown: stop pipeline before quitting
app.on('before-quit', async (event) => {
  const status = pipelineManager.getStatus()
  if (status.state === 'running' || status.state === 'starting') {
    event.preventDefault()
    await pipelineManager.stop()
    app.quit()
  }
})
