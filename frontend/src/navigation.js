import {
  LayoutDashboard, Activity, ShieldCheck, ShieldAlert, Brain, FileText,
  Globe, BarChart2, Bell, Code, Users, Settings as SettingsIcon,
} from 'lucide-react';

/**
 * Single source of truth for the app's 13 nav destinations — grouped for
 * Sidebar.jsx, flattened for CommandPalette.jsx. Previously each of those
 * two kept its own hardcoded copy of the same list; this is the drift-prone
 * pattern that got fixed instead of repeated.
 */
export function getNavGroups(isAdmin) {
  return [
    {
      label: 'MONITORING',
      items: [
        { id: 'overview',  label: 'Overview',        icon: LayoutDashboard },
        { id: 'events',    label: 'Security Events',  icon: Activity, hasBadge: true },
      ]
    },
    {
      label: 'PROTECTION',
      items: [
        { id: 'protection',      label: 'Apps & DDoS Shield',        icon: ShieldCheck },
        { id: 'false_positives', label: 'False Positives & Exceptions', icon: ShieldAlert },
      ]
    },
    {
      label: 'ANALYSIS',
      items: [
        { id: 'ml_engine',      label: 'AI / ML Engine',    icon: Brain },
        { id: 'rules',          label: 'WAF Rules',          icon: FileText },
        { id: 'api_protection', label: 'API Protection',     icon: Globe },
        { id: 'reports',        label: 'Security Reports',   icon: BarChart2 },
      ]
    },
    {
      label: 'SYSTEM',
      items: [
        { id: 'integrations',    label: 'Alerts & Integrations', icon: Bell },
        ...(isAdmin ? [
          { id: 'virtual_patching', label: 'Virtual Patching', icon: Code, adminOnly: true },
          { id: 'users',            label: 'User Management',  icon: Users, adminOnly: true },
          { id: 'settings',         label: 'Settings',          icon: SettingsIcon, adminOnly: true },
        ] : []),
      ]
    }
  ];
}

/** Flat list of every destination, admin-only ones always included — the
 * command palette filters those out itself based on the caller's role. */
export function getFlatNavItems() {
  return getNavGroups(true).flatMap((group) => group.items.map((item) => ({ ...item, group: group.label })));
}
