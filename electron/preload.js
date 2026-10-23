const { contextBridge, ipcRenderer } = require('electron');

const allowedKinds = new Set(['file', 'directory']);

// Sandboxed Electron preload scripts only expose a small allow-list of Node
// modules. Requiring `crypto` here prevents the entire preload bridge from
// loading in packaged builds, which disables every native Application
// Research action. This identifier only correlates progress events inside the
// same renderer; it is not an authentication token, so browser-provided
// randomness is sufficient.
function applicationChatRequestId() {
  return `appchat_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 14)}`;
}

contextBridge.exposeInMainWorld('aegisDesktop', Object.freeze({
  selectArtifact(kind) {
    if (!allowedKinds.has(kind)) {
      return Promise.reject(new Error('Unsupported artifact selection type'));
    }
    return ipcRenderer.invoke('aegis:select-artifact', kind);
  },
  revealApplicationEvidence(projectId, findingId) {
    return ipcRenderer.invoke(
      'aegis:reveal-application-evidence',
      String(projectId || ''),
      String(findingId || ''),
    );
  },
  deleteApplicationProject(projectId) {
    return ipcRenderer.invoke(
      'aegis:delete-application-project',
      String(projectId || ''),
    );
  },
  exportApplicationEvidence(projectId) {
    return ipcRenderer.invoke(
      'aegis:export-application-evidence',
      String(projectId || ''),
    );
  },
  exportApplicationRedacted(projectId) {
    return ipcRenderer.invoke(
      'aegis:export-application-redacted',
      String(projectId || ''),
    );
  },
  chatApplicationWithPrivateEvidence(request, onProgress) {
    const value = request && typeof request === 'object' ? request : {};
    const requestId = applicationChatRequestId();
    const listener = (_event, message) => {
      if (
        message?.requestId === requestId
        && typeof onProgress === 'function'
      ) {
        try { onProgress(message.progress); } catch (_) { /* renderer callback ended */ }
      }
    };
    ipcRenderer.on('aegis:application-chat-progress', listener);
    return ipcRenderer.invoke('aegis:chat-application-private', {
      projectId: String(value.projectId || ''),
      question: String(value.question || ''),
      lmUrl: String(value.lmUrl || ''),
      model: String(value.model || ''),
      history: Array.isArray(value.history)
        ? value.history.slice(-8).map((item) => ({
          role: String(item?.role || ''),
          content: String(item?.content || '').slice(0, 1200),
        }))
        : [],
      requestId,
    }).finally(() => {
      ipcRenderer.removeListener('aegis:application-chat-progress', listener);
    });
  },
}));
