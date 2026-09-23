// SPDX-License-Identifier: Apache-2.0
import { useState, useEffect, useCallback } from 'react';
import { cn } from '../../lib/utils';
import { X, CheckCircle2, AlertTriangle, XCircle, Info } from 'lucide-react';

// ── Types ──────────────────────────────────────────────────────────────────────

export type ToastVariant = 'success' | 'error' | 'warning' | 'info';

export interface Toast {
  id: string;
  title: string;
  description?: string;
  variant: ToastVariant;
  duration?: number; // ms — 0 for persistent
}

// ── Global toast state ─────────────────────────────────────────────────────────

let toastListeners: Array<() => void> = [];
let toasts: Toast[] = [];

function emit() {
  toastListeners.forEach((fn) => fn());
}

let nextId = 0;

export function toast(opts: Omit<Toast, 'id'>) {
  const id = `toast-${++nextId}`;
  const t: Toast = { id, duration: opts.variant === 'error' ? 0 : 5000, ...opts };
  toasts = [t, ...toasts].slice(0, 5);
  emit();

  if (t.duration && t.duration > 0) {
    setTimeout(() => {
      dismissToast(id);
    }, t.duration);
  }
}

export function dismissToast(id: string) {
  toasts = toasts.filter((t) => t.id !== id);
  emit();
}

function useToasts(): Toast[] {
  const [, setTick] = useState(0);
  useEffect(() => {
    const listener = () => setTick((t) => t + 1);
    toastListeners.push(listener);
    return () => {
      toastListeners = toastListeners.filter((l) => l !== listener);
    };
  }, []);
  return toasts;
}

// ── Variant config ─────────────────────────────────────────────────────────────

const variantStyles: Record<
  ToastVariant,
  { bg: string; border: string; text: string; icon: typeof Info }
> = {
  success: {
    bg: 'bg-[#dcfce7]',
    border: 'border-[#bbf7d0]',
    text: 'text-[#15803d]',
    icon: CheckCircle2,
  },
  error: { bg: 'bg-[#fee2e2]', border: 'border-[#fecaca]', text: 'text-[#991b1b]', icon: XCircle },
  warning: {
    bg: 'bg-[#fef3c7]',
    border: 'border-[#fde68a]',
    text: 'text-[#92400e]',
    icon: AlertTriangle,
  },
  info: { bg: 'bg-[#eff6ff]', border: 'border-[#bfdbfe]', text: 'text-[#1e40af]', icon: Info },
};

// ── Toast container ────────────────────────────────────────────────────────────

export function ToastContainer() {
  const items = useToasts();
  const dismiss = useCallback((id: string) => dismissToast(id), []);

  if (items.length === 0) return null;

  return (
    <div className="fixed top-4 right-4 z-[100] flex flex-col gap-2 w-[360px]">
      {items.map((t) => {
        const v = variantStyles[t.variant];
        const Icon = v.icon;
        return (
          <div
            key={t.id}
            className={cn(
              'flex items-start gap-3 px-4 py-3 rounded-[10px] border shadow-sm',
              'transition-all duration-200 ease-out',
              v.bg,
              v.border,
            )}
          >
            <Icon className={cn('h-4 w-4 mt-0.5 shrink-0', v.text)} />
            <div className="flex-1 min-w-0">
              <p className={cn('text-[13px] font-medium', v.text)}>{t.title}</p>
              {t.description && (
                <p className={cn('text-[12px] mt-0.5 opacity-80', v.text)}>{t.description}</p>
              )}
            </div>
            <button
              onClick={() => dismiss(t.id)}
              className={cn('shrink-0 p-0.5 rounded hover:bg-black/5 transition-colors', v.text)}
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        );
      })}
    </div>
  );
}
