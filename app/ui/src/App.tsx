// SPDX-License-Identifier: Apache-2.0
import { CommentaryCaptions } from './components/LiveCommentary';
import { startCommentaryLoop } from './lib/commentary';
import { useState, useEffect, useRef } from 'react';
import { useStore } from './store';
import { ThemeProvider } from './hooks/use-theme';
import { TooltipProvider } from './components/ui/tooltip';
import { ScrollArea } from './components/ui/scroll-area';
import { ToastContainer } from './components/ui/toast';
import Sidebar from './components/Sidebar';
import HealthBanner from './components/HealthBanner';
import Dashboard from './components/Dashboard';
import Threats from './components/Threats';
import BlockNotices, { addRefusals, type NoticeGroup } from './components/BlockNotices';
import type { RefusalEvent } from './lib/refusals';
import Sessions from './components/Sessions';
import Skills from './components/Skills';
import ProvenanceGraph from './components/ProvenanceGraph';
import Policy from './components/Policy';

export type Page =
  'dashboard' | 'sessions' | 'threats' | 'policy' | 'enforcement' | 'file-access' | 'skills' | 'graph';

export default function App() {
  const [currentPage, setCurrentPage] = useState<Page>('dashboard');
  const [notices, setNotices] = useState<NoticeGroup[]>([]);
  const { fetchStatus, fetchSkills, fetchEvents, initEventListener, events } = useStore();
  // Track which threat IDs we've already shown alerts for. Persisted to
  // localStorage so a dismissed alert does NOT re-fire every time the app is
  // reopened (otherwise old/known threats keep popping up on each launch).
  const [shownThreatIds, setShownThreatIds] = useState<Set<string>>(() => {
    try {
      const raw = localStorage.getItem('rz_shown_threat_ids');
      return raw ? new Set(JSON.parse(raw) as string[]) : new Set();
    } catch {
      return new Set();
    }
  });

  useEffect(() => {
    initEventListener();
  }, [initEventListener]);

  // Live commentary: fetch and speak while it is switched on.
  useEffect(() => startCommentaryLoop(), []);

  useEffect(() => {
    fetchStatus();
    fetchSkills();
    fetchEvents();

    const interval = setInterval(() => {
      fetchStatus();
      fetchEvents();
    }, 10000);

    return () => {
      clearInterval(interval);
    };
  }, [fetchStatus, fetchSkills, fetchEvents]);

  // A notice for each new refusal. Everything already in the feed when the
  // app opens counts as seen, so old refusals do not replay.
  const threatsSeeded = useRef(false);
  useEffect(() => {
    const remember = (ids: string[]) =>
      setShownThreatIds((prev) => {
        const next = new Set(prev);
        ids.forEach((id) => next.add(id));
        try {
          localStorage.setItem('rz_shown_threat_ids', JSON.stringify([...next].slice(-500)));
        } catch {
          /* non-fatal */
        }
        return next;
      });
    if (!threatsSeeded.current) {
      if (events.length === 0) return;
      threatsSeeded.current = true;
      remember(events.map((e) => e.id));
      return;
    }
    const fresh = events.filter((e) => !e.allowed && !shownThreatIds.has(e.id));
    if (fresh.length === 0) return;
    // The feed is newest first; notices read oldest first.
    setNotices((g) => addRefusals(g, [...fresh].reverse() as unknown as RefusalEvent[]));
    remember(fresh.map((e) => e.id));
  }, [events, shownThreatIds]);

  const renderPage = () => {
    switch (currentPage) {
      case 'dashboard':
        return <Dashboard onNavigate={setCurrentPage} />;
      case 'sessions':
        return <Sessions />;
      case 'threats':
        return <Threats />;
      case 'skills':
        return <Skills />;
      case 'graph':
        return <ProvenanceGraph />;
      case 'policy':
      case 'enforcement':
      case 'file-access':
        return <Policy />;
      default:
        return <Dashboard />;
    }
  };

  return (
    <ThemeProvider>
      <TooltipProvider>
        <div className="flex h-screen bg-background">
          <Sidebar currentPage={currentPage} onNavigate={setCurrentPage} />
          <div className="flex-1 flex flex-col min-w-0">
            <HealthBanner />
            <ScrollArea className="flex-1">
              <main className="p-6">{renderPage()}</main>
            </ScrollArea>
          </div>
        </div>

        <BlockNotices
          groups={notices}
          onDismiss={(key) => setNotices((g) => g.filter((x) => x.key !== key))}
          onNavigate={(page) => setCurrentPage(page)}
        />

        <CommentaryCaptions />
        <ToastContainer />
      </TooltipProvider>
    </ThemeProvider>
  );
}
