import { Menu, type BrowserWindow } from 'electron'
import { is } from '@electron-toolkit/utils'

export function buildAppMenu(mainWindow: BrowserWindow): void {
  const template: Electron.MenuItemConstructorOptions[] = [
    {
      label: 'File',
      submenu: [
        {
          label: 'New Engagement',
          accelerator: 'CmdOrCtrl+N',
          click: () => {
            mainWindow.webContents.executeJavaScript(
              "window.location.hash = '#/launch'"
            )
          },
        },
        { type: 'separator' },
        { role: 'quit' },
      ],
    },
    {
      label: 'View',
      submenu: [
        { role: 'reload' },
        { role: 'forceReload' },
        ...(is.dev
          ? [{ role: 'toggleDevTools' as const }]
          : []),
        { type: 'separator' as const },
        { role: 'resetZoom' as const },
        { role: 'zoomIn' as const },
        { role: 'zoomOut' as const },
        { type: 'separator' as const },
        { role: 'togglefullscreen' as const },
      ],
    },
    {
      label: 'Help',
      submenu: [
        {
          label: 'About Wraith',
          click: () => {
            const { dialog } = require('electron')
            dialog.showMessageBox(mainWindow, {
              type: 'info',
              title: 'About Wraith',
              message: 'Wraith v3.8.0',
              detail:
                'Autonomous AI Penetration Testing Framework\n\n' +
                'Built with Claude Agent SDK + Electron\n' +
                'github.com/Cosmic-Arch69/wraith',
            })
          },
        },
      ],
    },
  ]

  // macOS app menu
  if (process.platform === 'darwin') {
    template.unshift({
      label: 'Wraith',
      submenu: [
        { role: 'about' },
        { type: 'separator' },
        { role: 'hide' },
        { role: 'hideOthers' },
        { role: 'unhide' },
        { type: 'separator' },
        { role: 'quit' },
      ],
    })
  }

  const menu = Menu.buildFromTemplate(template)
  Menu.setApplicationMenu(menu)
}
