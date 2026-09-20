// SPDX-License-Identifier: Apache-2.0
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { TokenScopeProvider } from './hooks/use-token-scope';
import './styles/index.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <TokenScopeProvider>
      <App />
    </TokenScopeProvider>
  </React.StrictMode>,
);
