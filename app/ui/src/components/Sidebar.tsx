// SPDX-License-Identifier: Apache-2.0
import { CommentarySwitch } from './LiveCommentary';
import icon from '../ringzero-icon.svg';
import logo from '../ringzero-logo.svg';
import { cn } from '../lib/utils';
import { LayoutDashboard, ShieldAlert, Users, Package, Shield } from 'lucide-react';
import type { Page } from '../App';

interface SidebarProps {
  currentPage: string;
  onNavigate: (page: Page) => void;
}

export default function Sidebar({ currentPage, onNavigate }: SidebarProps) {

  const navItems = [
    { id: 'dashboard', label: 'Overview', icon: LayoutDashboard },
    { id: 'sessions', label: 'Sessions', icon: Users },
    {
      id: 'threats',
      label: 'Security history',
      icon: ShieldAlert,
    },
    { id: 'skills', label: 'Discovery', icon: Package },
    { id: 'policy', label: 'Policy', icon: Shield },
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
                </button>
              </li>
            );
          })}
        </ul>
      </nav>
      <CommentarySwitch />
    </aside>
  );
}
