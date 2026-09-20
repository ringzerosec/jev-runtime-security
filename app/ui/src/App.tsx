// SPDX-License-Identifier: Apache-2.0
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
import ThreatAlert, { type ThreatData } from './components/ThreatAlert';
import Sessions from './components/Sessions';
import Skills from './components/Skills';
import ProvenanceGraph from './components/ProvenanceGraph';
import Enforcement from './components/Enforcement';
import FileAccess from './components/FileAccess';

export type Page =
  'dashboard' | 'sessions' | 'threats' | 'enforcement' | 'file-access' | 'skills' | 'graph';

export default function App() {
  const [currentPage, setCurrentPage] = useState<Page>('dashboard');
  const [threatAlertOpen, setThreatAlertOpen] = useState(false);
  const [currentThreat, setCurrentThreat] = useState<ThreatData | null>(null);
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

  // Auto-show threat alert on blocked events (only for new ones)
  const threatsSeeded = useRef(false);
  useEffect(() => {
    // First populated load: treat everything already in the feed as "seen" so
    // pre-existing threats don't replay as live popups when the app opens. Only
    // events that arrive AFTER startup raise an alert.
    if (!threatsSeeded.current) {
      if (events.length === 0) return;
      threatsSeeded.current = true;
      setShownThreatIds((prev) => {
        const next = new Set(prev);
        events.forEach((e) => next.add(e.id));
        try {
          localStorage.setItem('rz_shown_threat_ids', JSON.stringify([...next].slice(-500)));
        } catch {
          /* non-fatal */
        }
        return next;
      });
      return;
    }

    const lastEvent = events[0];
    if (lastEvent && !lastEvent.allowed && !shownThreatIds.has(lastEvent.id)) {
      const sensitivePatterns = [
        'credentials',
        'id_rsa',
        'id_ed25519',
        '.env',
        'secret',
        'token',
        'passwd',
      ];
      const isSensitiveFile = sensitivePatterns.some((p) =>
        lastEvent.target?.toLowerCase().includes(p),
      );
      const isNetworkBlock = lastEvent.type?.includes('Network');
      const isDlpBlock = lastEvent.type?.startsWith('dlp_') || lastEvent.type?.startsWith('proxy_');

      const markShown = () =>
        setShownThreatIds((prev) => {
          const next = new Set(prev).add(lastEvent.id);
          // Persist (cap to the most recent 500 ids so it can't grow unbounded).
          try {
            const ids = [...next].slice(-500);
            localStorage.setItem('rz_shown_threat_ids', JSON.stringify(ids));
          } catch {
            /* storage unavailable — non-fatal */
          }
          return next;
        });

      if (isSensitiveFile) {
        const threat = {
          id: lastEvent.id,
          title: 'Credential Access Attempt Blocked',
          description: 'An AI agent attempted to access sensitive credentials.',
          severity: 'critical' as const,
          confidence: 94,
          source: lastEvent.skill_name || 'Unknown',
          skillName: lastEvent.skill_name || 'unknown-skill',
          timeline: [
            {
              time: new Date(lastEvent.timestamp).toLocaleTimeString(),
              action: lastEvent.type || 'File Access',
              target: lastEvent.target,
              status: 'blocked' as const,
            },
          ],
          aiAnalysis: `Blocked attempt to access sensitive file: ${lastEvent.target}. This type of access is commonly associated with credential theft attempts (MAESTRO: LM-003, DO-001). The operation was blocked at the kernel level before the file could be read.`,
        };
        setCurrentThreat(threat);
        setThreatAlertOpen(true);
        markShown();
      } else if (isNetworkBlock) {
        const threat = {
          id: lastEvent.id,
          title: 'Data Exfiltration Attempt Blocked',
          description: `An AI agent attempted to connect to an unauthorized server: ${lastEvent.target}`,
          severity: 'critical' as const,
          confidence: 91,
          source: lastEvent.skill_name || 'Unknown',
          skillName: lastEvent.skill_name || 'unknown-skill',
          timeline: [
            {
              time: new Date(lastEvent.timestamp).toLocaleTimeString(),
              action: 'Network Connect',
              target: lastEvent.target,
              status: 'blocked' as const,
            },
          ],
          aiAnalysis: `Blocked outbound connection to ${lastEvent.target}. A tainted process attempted to exfiltrate data (MAESTRO: DO-002, EX-001).`,
        };
        setCurrentThreat(threat);
        setThreatAlertOpen(true);
        markShown();
      } else if (isDlpBlock) {
        const threat = {
          id: lastEvent.id,
          title: 'API Key Exfiltration Blocked',
          description: `DLP detected API key(s) being sent to unauthorized destination: ${lastEvent.target}`,
          severity: 'critical' as const,
          confidence: 97,
          source: lastEvent.skill_name || 'Unknown',
          skillName: lastEvent.skill_name || 'unknown-skill',
          timeline: [
            {
              time: new Date(lastEvent.timestamp).toLocaleTimeString(),
              action: 'Content Inspection',
              target: lastEvent.target,
              status: 'blocked' as const,
            },
          ],
          aiAnalysis: `DLP content inspection detected API key(s) in outbound traffic to ${lastEvent.target} (MAESTRO: EX-001, EX-002).`,
        };
        setCurrentThreat(threat);
        setThreatAlertOpen(true);
        markShown();
      }
    }
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
      case 'enforcement':
        return <Enforcement />;
      case 'file-access':
        return <FileAccess />;
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

        <ThreatAlert
          isOpen={threatAlertOpen}
          onClose={() => setThreatAlertOpen(false)}
          threat={currentThreat}
          onInvestigate={() => {
            setThreatAlertOpen(false);
            setCurrentPage('threats');
          }}
          onBlockOnce={() => setThreatAlertOpen(false)}
          onAllow={() => setThreatAlertOpen(false)}
        />

        <ToastContainer />
      </TooltipProvider>
    </ThemeProvider>
  );
}
