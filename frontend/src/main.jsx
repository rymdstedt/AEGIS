import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'

// StrictMode disabled to avoid double WS connects / double effects in dev (per prior AEGIS debugging)
ReactDOM.createRoot(document.getElementById('root')).render(
  <App />
)
