// SPDX-License-Identifier: Apache-2.0
import { useStore } from '../store';
import icon from '../ringzero-icon.svg';
import logo from '../ringzero-logo.svg';
import { cn } from '../lib/utils';
import { LayoutDashboard, ShieldAlert, Users, Package, Shield, FileIcon } from 'lucide-react';
import type { Page } from '../App';

interface SidebarProps {
  currentPage: string;
  onNavigate: (page: Page) => void;
}

export default function Sidebar({ currentPage, onNavigate }: SidebarProps) {
  const { events } = useStore();

  // Only count real threats in badge (skip benign runtime noise)
  const BENIGN_PROCS = ['node', 'npm', 'npx', 'python', 'python3', 'pip', 'deno', 'bun'];
  const blockedCount = events.filter((e) => {
    if (e.allowed) return false;
    const t = e.target?.toLowerCase() || '';
    if (t.match(/id_rsa|id_ed25519|credentials|shadow/)) return true;
    if (t.match(/\.env|passwd|secret|token/)) return true;
    // Skip benign child process spawns
    const proc = e.skill_name?.toLowerCase() || '';
    if (BENIGN_PROCS.includes(proc)) return false;
    const kind = e.type?.toLowerCase() || '';
    if (kind.includes('network')) return true;
    if (kind.includes('process')) return true;
    return false;
  }).length;

  const navItems = [
    { id: 'dashboard', label: 'Overview', icon: LayoutDashboard },
    { id: 'sessions', label: 'Sessions', icon: Users },
    {
      id: 'threats',
      label: 'Threats',
      icon: ShieldAlert,
      badge: blockedCount || undefined,
    },
    { id: 'skills', label: 'Agent Skills', icon: Package },
    { id: 'file-access', label: 'File Access', icon: FileIcon },
    { id: 'enforcement', label: 'Enforcement', icon: Shield },
  ];

  return (
    <aside className="w-56 border-r border-sidebar-border bg-sidebar flex flex-col">
      {/* Logo — full wordmark, with the icon as a graceful fallback */}
      <div className="px-4 pt-6 pb-5">
        <img
          src={logo}
          alt="Ring Zero Security"
          className="h-8 w-auto object-contain"
          onError={(e) => {
            (e.currentTarget as HTMLImageElement).src = icon;
          }}
        />
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3">
        <ul className="space-y-0.5">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = currentPage === item.id;
            return (
              <li key={item.id}>
                <button
                  onClick={() => onNavigate(item.id as Page)}
                  className={cn(
                    'w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-sm transition-colors',
                    active
                      ? 'bg-primary/10 text-primary font-medium'
                      : 'text-muted-foreground hover:text-foreground hover:bg-muted/50',
                  )}
                >
                  <Icon className="h-4 w-4" />
                  <span className="flex-1 text-left">{item.label}</span>
                  {item.badge ? (
                    <span className="text-[10px] font-medium bg-red-500/15 text-red-400 px-1.5 py-0.5 rounded-full min-w-[20px] text-center">
                      {item.badge}
                    </span>
                  ) : null}
                </button>
              </li>
            );
          })}
        </ul>
      </nav>
    </aside>
  );
}
