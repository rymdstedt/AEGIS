const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const test = require('node:test');
const { claimSingleInstance, revealWindow } = require('../../electron/single-instance');

function fakeApp(lockAvailable) {
  const app = new EventEmitter();
  app.quitCount = 0;
  app.requestSingleInstanceLock = () => lockAvailable;
  app.quit = () => { app.quitCount += 1; };
  return app;
}

test('a second process quits without registering a launch handler', () => {
  const app = fakeApp(false);
  const primary = claimSingleInstance(app, () => null, () => {});
  assert.equal(primary, false);
  assert.equal(app.quitCount, 1);
  assert.equal(app.listenerCount('second-instance'), 0);
});

test('a second launch restores and focuses the existing window', () => {
  const app = fakeApp(true);
  const actions = [];
  const window = {
    isDestroyed: () => false,
    isMinimized: () => true,
    isVisible: () => false,
    restore: () => actions.push('restore'),
    show: () => actions.push('show'),
    focus: () => actions.push('focus'),
  };
  let deferred = false;
  assert.equal(claimSingleInstance(app, () => window, () => { deferred = true; }), true);
  app.emit('second-instance');
  assert.deepEqual(actions, ['restore', 'show', 'focus']);
  assert.equal(deferred, false);
  assert.equal(app.quitCount, 0);
});

test('a second launch during backend startup is deferred until the window exists', () => {
  const app = fakeApp(true);
  let deferred = false;
  claimSingleInstance(app, () => null, () => { deferred = true; });
  app.emit('second-instance');
  assert.equal(deferred, true);
  assert.equal(revealWindow(null), false);
  assert.equal(revealWindow({ isDestroyed: () => true }), false);
});
