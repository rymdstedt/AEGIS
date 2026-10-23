function revealWindow(window) {
  if (!window || window.isDestroyed()) return false;
  if (window.isMinimized()) window.restore();
  if (!window.isVisible()) window.show();
  window.focus();
  return true;
}

function claimSingleInstance(app, getWindow, onWindowUnavailable) {
  if (!app.requestSingleInstanceLock()) {
    app.quit();
    return false;
  }

  app.on('second-instance', () => {
    if (!revealWindow(getWindow())) onWindowUnavailable();
  });
  return true;
}

module.exports = { claimSingleInstance, revealWindow };
