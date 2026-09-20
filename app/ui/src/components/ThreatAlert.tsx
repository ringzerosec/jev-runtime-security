// SPDX-License-Identifier: Apache-2.0
import { useState, useEffect } from 'react';
import { cn } from '../lib/utils';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import {
  ShieldAlert,
  X,
  Clock,
  FileWarning,
  Globe,
  Cpu,
  AlertTriangle,
  Shield,
  ChevronDown,
  ChevronUp,
  Search,
  FolderOpen,
  Network,
  Terminal,
  Fingerprint,
} from 'lucide-react';

interface ThreatEvent {
  time: string;
  action: string;
  target: string;
  status: 'blocked' | 'detected';
}

export interface ThreatData {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  confidence: number;
  source: string;
  skillName: string;
  timeline: ThreatEvent[];
  aiAnalysis: string;
  processPath?: string;
  pid?: number;
  parentProcess?: string;
  cmdline?: string;
  filesPaths?: string[];
  networkDest?: string;
  detectionTags?: string[];
}

interface ThreatAlertProps {
  isOpen: boolean;
  onClose: () => void;
  threat: ThreatData | null;
  onInvestigate?: () => void;
  onBlockOnce: () => void;
  onAllow: () => void;
}

export default function ThreatAlert({
  isOpen,
  onClose,
  threat,
  onInvestigate,
  onBlockOnce,
  onAllow,
}: ThreatAlertProps) {
  const [isVisible, setIsVisible] = useState(false);
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    if (isOpen) {
      setIsVisible(true);
      setExpanded(false);
    } else {
      const timer = setTimeout(() => setIsVisible(false), 300);
      return () => clearTimeout(timer);
    }
  }, [isOpen]);

  if (!isVisible || !threat) return null;

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-red-600 bg-red-500/10 border-red-500/30';
      case 'high':
        return 'text-orange-600 bg-orange-500/10 border-orange-500/30';
      case 'medium':
        return 'text-yellow-600 bg-yellow-500/10 border-yellow-500/30';
      default:
        return 'text-blue-600 bg-blue-500/10 border-blue-500/30';
    }
  };

  const getEventIcon = (action: string) => {
    if (action.toLowerCase().includes('read') || action.toLowerCase().includes('file'))
      return FileWarning;
    if (
      action.toLowerCase().includes('connect') ||
      action.toLowerCase().includes('dns') ||
      action.toLowerCase().includes('network')
    )
      return Globe;
    return Cpu;
  };

  // Whether we have enough context to show deep analysis
  const hasDeepContext = !!(
    threat.processPath ||
    threat.pid ||
    threat.parentProcess ||
    threat.cmdline ||
    (threat.filesPaths && threat.filesPaths.length > 0) ||
    threat.networkDest ||
    (threat.detectionTags && threat.detectionTags.length > 0)
  );

  // Label: show "Process" unless source looks like a named skill
  const isNamedSkill =
    threat.skillName &&
    threat.skillName !== threat.source &&
    threat.skillName !== 'unknown-skill' &&
    threat.skillName !== 'unknown';

  return (
    <div
      className={cn(
        'fixed inset-0 z-50 flex items-center justify-center p-4 transition-all duration-300',
        isOpen ? 'opacity-100' : 'opacity-0 pointer-events-none',
      )}
    >
      {/* Backdrop */}
      <div
        className={cn(
          'absolute inset-0 bg-black/60 backdrop-blur-sm transition-opacity',
          isOpen ? 'opacity-100' : 'opacity-0',
        )}
        onClick={onClose}
      />

      {/* Modal */}
      <div
        className={cn(
          'relative w-full max-w-2xl bg-card text-card-foreground border rounded-xl shadow-2xl transition-all duration-300',
          isOpen ? 'scale-100 opacity-100' : 'scale-95 opacity-0',
          threat.severity === 'critical' && 'border-amber-500/50',
        )}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b bg-card">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-amber-500/20">
              <ShieldAlert className="h-6 w-6 text-amber-500" />
            </div>
            <div>
              <h2 className="text-lg font-bold flex items-center gap-2 text-foreground">
                Threat Blocked
                <Badge className={getSeverityColor(threat.severity)}>
                  {threat.severity.toUpperCase()}
                </Badge>
              </h2>
              <p className="text-sm text-muted-foreground">{threat.title}</p>
            </div>
          </div>
          <Button variant="ghost" size="icon" onClick={onClose}>
            <X className="h-5 w-5 text-foreground" />
          </Button>
        </div>

        {/* Content */}
        <div className="p-4 space-y-4">
          {/* Attack Timeline */}
          <div>
            <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
              <Clock className="h-4 w-4" />
              Attack Timeline
            </h3>
            <div className="bg-muted/50 rounded-lg p-3 space-y-2">
              {threat.timeline.map((event, index) => {
                const Icon = getEventIcon(event.action);
                return (
                  <div
                    key={index}
                    className={cn(
                      'flex items-center gap-3 p-2 rounded-lg text-sm',
                      event.status === 'blocked'
                        ? 'bg-muted/70 border border-border'
                        : 'bg-muted/50',
                    )}
                  >
                    <span className="text-xs text-muted-foreground font-mono w-20">
                      {event.time}
                    </span>
                    <Icon className="h-4 w-4 text-muted-foreground" />
                    <span className="font-medium text-foreground">{event.action}</span>
                    <code className="text-xs bg-background px-2 py-0.5 rounded ml-auto">
                      {event.target}
                    </code>
                    {event.status === 'blocked' && (
                      <Badge
                        variant="secondary"
                        className="text-xs bg-amber-500/20 text-amber-600 border-amber-500/30"
                      >
                        BLOCKED
                      </Badge>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Source Info */}
          <div className="flex items-center gap-4 p-3 bg-muted/30 rounded-lg">
            <div>
              <p className="text-xs text-muted-foreground">Source</p>
              <p className="font-medium text-foreground">{threat.source}</p>
            </div>
            {isNamedSkill && (
              <>
                <div className="w-px h-8 bg-border" />
                <div>
                  <p className="text-xs text-muted-foreground">Skill</p>
                  <p className="font-medium text-red-500">{threat.skillName}</p>
                </div>
              </>
            )}
            {threat.pid && (
              <>
                <div className="w-px h-8 bg-border" />
                <div>
                  <p className="text-xs text-muted-foreground">PID</p>
                  <p className="font-medium font-mono text-foreground">{threat.pid}</p>
                </div>
              </>
            )}
            <div className="w-px h-8 bg-border" />
            <div>
              <p className="text-xs text-muted-foreground">Confidence</p>
              <div className="flex items-center gap-2">
                <div className="w-24 h-2 bg-muted rounded-full overflow-hidden">
                  <div
                    className={cn(
                      'h-full rounded-full',
                      threat.confidence >= 90
                        ? 'bg-red-500'
                        : threat.confidence >= 70
                          ? 'bg-orange-500'
                          : 'bg-yellow-500',
                    )}
                    style={{ width: `${threat.confidence}%` }}
                  />
                </div>
                <span className="text-sm font-bold text-foreground">{threat.confidence}%</span>
              </div>
            </div>
          </div>

          {/* Analysis */}
          <div className="p-4 bg-gradient-to-r from-blue-500/10 to-purple-500/10 border border-blue-500/20 rounded-lg">
            <div className="flex items-start gap-3">
              <div className="p-1.5 bg-blue-500/20 rounded-lg">
                <Cpu className="h-4 w-4 text-blue-500" />
              </div>
              <div className="flex-1">
                <p className="text-sm font-semibold text-blue-500 mb-1">Analysis</p>
                <p className="text-sm text-muted-foreground leading-relaxed">{threat.aiAnalysis}</p>
              </div>
            </div>
          </div>

          {/* Process / file / network context, when the event carries it */}
          <div className="border border-border rounded-lg overflow-hidden">
            <button
              onClick={() => hasDeepContext && setExpanded((e) => !e)}
              className={cn(
                'w-full flex items-center justify-between px-4 py-3 bg-muted/30 transition-colors text-sm font-medium',
                hasDeepContext ? 'hover:bg-muted/50 cursor-pointer' : 'cursor-default opacity-60',
              )}
            >
              <div className="flex items-center gap-2">
                <Search className="h-4 w-4 text-muted-foreground" />
                <span>Details</span>
                {!expanded && hasDeepContext ? (
                  <Badge variant="outline" className="text-xs ml-1">
                    {
                      [
                        threat.processPath && 'process',
                        threat.cmdline && 'cmdline',
                        threat.filesPaths?.length && 'files',
                        threat.networkDest && 'network',
                        threat.detectionTags?.length && 'tags',
                      ].filter(Boolean).length
                    }{' '}
                    signals
                  </Badge>
                ) : null}
              </div>
              {hasDeepContext &&
                (expanded ? (
                  <ChevronUp className="h-4 w-4 text-muted-foreground" />
                ) : (
                  <ChevronDown className="h-4 w-4 text-muted-foreground" />
                ))}
            </button>

            {expanded && (
              <div className="p-4 space-y-3 text-sm">
                {/* Process info */}
                {(threat.processPath || threat.parentProcess) && (
                  <div className="space-y-1.5">
                    <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                      <Terminal className="h-3 w-3" /> Process
                    </p>
                    {threat.processPath && (
                      <div className="flex items-center gap-2 font-mono text-xs bg-muted/50 px-3 py-1.5 rounded">
                        <span className="text-muted-foreground">path</span>
                        <span className="text-foreground break-all">{threat.processPath}</span>
                      </div>
                    )}
                    {threat.parentProcess && (
                      <div className="flex items-center gap-2 font-mono text-xs bg-muted/50 px-3 py-1.5 rounded">
                        <span className="text-muted-foreground">parent</span>
                        <span className="text-foreground">{threat.parentProcess}</span>
                      </div>
                    )}
                    {threat.cmdline && (
                      <div className="font-mono text-xs bg-muted/50 px-3 py-1.5 rounded break-all">
                        <span className="text-muted-foreground">$ </span>
                        <span className="text-foreground">{threat.cmdline}</span>
                      </div>
                    )}
                  </div>
                )}

                {/* Files accessed */}
                {threat.filesPaths && threat.filesPaths.length > 0 && (
                  <div className="space-y-1.5">
                    <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                      <FolderOpen className="h-3 w-3" /> Files Accessed
                    </p>
                    {threat.filesPaths.map((f, i) => (
                      <div
                        key={i}
                        className="font-mono text-xs bg-muted/50 px-3 py-1.5 rounded text-red-400 break-all"
                      >
                        {f}
                      </div>
                    ))}
                  </div>
                )}

                {/* Network destination */}
                {threat.networkDest && (
                  <div className="space-y-1.5">
                    <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                      <Network className="h-3 w-3" /> Network Destination
                    </p>
                    <div className="font-mono text-xs bg-muted/50 px-3 py-1.5 rounded text-orange-400">
                      {threat.networkDest}
                    </div>
                  </div>
                )}

                {/* Detection tags */}
                {threat.detectionTags && threat.detectionTags.length > 0 && (
                  <div className="space-y-1.5">
                    <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                      <Fingerprint className="h-3 w-3" /> Detection Signals
                    </p>
                    <div className="flex flex-wrap gap-1.5">
                      {threat.detectionTags.map((tag, i) => (
                        <Badge key={i} variant="outline" className="text-xs font-mono">
                          {tag}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center justify-between p-4 border-t bg-muted/30">
          <Button variant="ghost" size="sm" className="text-muted-foreground">
            <AlertTriangle className="h-4 w-4 mr-2" />
            Report False Positive
          </Button>
          <div className="flex items-center gap-2">
            <Button variant="outline" onClick={onAllow} className="text-muted-foreground">
              Allow (Risky)
            </Button>
            <Button variant="secondary" onClick={onBlockOnce}>
              <Shield className="h-4 w-4 mr-2" />
              Block Once
            </Button>
            {onInvestigate && (
              <Button
                variant="default"
                onClick={onInvestigate}
                className="bg-blue-600 hover:bg-blue-700 text-white"
              >
                <Search className="h-4 w-4 mr-2" />
                Investigate
              </Button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
