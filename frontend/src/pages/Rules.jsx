// pages/Rules.jsx
import React, { useState } from 'react';
import { useApp } from '../store/AppStore';
import { SeverityBadge, Mono, ExportBtn } from '../components/UI';
import { exportJSON } from '../utils/export';

// Map new backend "mode" field to display
function modeLabel(mode) {
  switch ((mode || '').toLowerCase()) {
    case 'enforce': return { label: '✕ Kill', bg: 'rgba(255,59,59,.12)', color: '#ff6b6b' };
    case 'alert': return { label: '⚠ Alert', bg: 'rgba(255,140,66,.12)', color: '#ffac72' };
    case 'detect': return { label: '◎ Detect', bg: 'rgba(77,184,255,.10)', color: '#4db8ff' };
    default: return { label: '⚠ Alert', bg: 'rgba(255,140,66,.12)', color: '#ffac72' };
  }
}

// Get process trigger string from various rule fields
function getTrigger(rule) {
  if (rule.process_regex) return rule.process_regex;
  if (rule.processes && rule.processes.length > 0) return rule.processes.join(', ');
  if (rule.process) return rule.process;
  return '—';
}

// Get args info
function getArgsInfo(rule) {
  if (rule.args_any && rule.args_any.length > 0) return rule.args_any.slice(0, 2).join(' | ');
  if (rule.args_list && rule.args_list.length > 0) return rule.args_list.join(' & ');
  if (rule.args_regex) return rule.args_regex;
  if (rule.args) return rule.args;
  return '—';
}

// Normalize rule — handle both old frontend format and new backend format
function normalizeRule(r) {
  return {
    name: r.name || '?',
    severity: (r.severity || 'info').toLowerCase(),
    mode: r.mode || (r.action === 'Kill' ? 'enforce' : 'alert'),
    trigger: getTrigger(r) || r.trigger || '—',
    argsInfo: getArgsInfo(r),
    description: r.message || r.description || '—',
    enabled: r.enabled !== false, // default true if not set
    tags: r.tags || [],
    // keep raw for export
    _raw: r,
  };
}

export default function Rules() {
  const { state, actions } = useApp();
  const { rules } = state;

  const [reloading, setReloading] = useState(false);
  const [reloadMsg, setReloadMsg] = useState('');
  const [sevFilter, setSevFilter] = useState('all');
  const [modeFilter, setModeFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [expandedName, setExpandedName] = useState(null);

  const normalized = rules.map(normalizeRule);

  const filtered = normalized.filter(r => {
    if (sevFilter !== 'all' && r.severity !== sevFilter) return false;
    if (modeFilter !== 'all' && r.mode !== modeFilter) return false;
    if (search && !r.name.toLowerCase().includes(search.toLowerCase()) &&
      !r.trigger.toLowerCase().includes(search.toLowerCase()) &&
      !r.description.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const active = normalized.filter(r => r.enabled).length;
  const killRules = normalized.filter(r => r.mode === 'enforce').length;

  const doReload = async () => {
    setReloading(true);
    setReloadMsg('');
    const res = await actions.reloadRules();
    setReloading(false);
    setReloadMsg(res ? `✓ Reloaded ${res.count || ''} rules` : '✗ Reload failed');
    setTimeout(() => setReloadMsg(''), 3000);
  };

  const fBtn = (val, cur, set) => ({
    padding: '4px 10px', borderRadius: 6, fontSize: 10, cursor: 'pointer',
    fontFamily: "'JetBrains Mono', monospace",
    border: `1px solid ${cur === val ? '#00e5ff' : '#1a3050'}`,
    background: cur === val ? 'rgba(0,229,255,.1)' : 'transparent',
    color: cur === val ? '#00e5ff' : '#4d7090',
    transition: 'all .15s',
  });

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', padding: '12px 20px', gap: 10, overflow: 'hidden' }}>

      {/* Summary cards */}
      <div style={{ display: 'flex', gap: 10, flexShrink: 0, alignItems: 'stretch' }}>
        {[
          { label: 'TOTAL RULES', value: rules.length, color: '#4db8ff' },
          { label: 'ACTIVE', value: active, color: '#06d6a0' },
          { label: 'DISABLED', value: rules.length - active, color: '#7090b0' },
          { label: 'ENFORCE (KILL)', value: killRules, color: '#ff3b3b' },
        ].map(c => (
          <div key={c.label} style={{ flex: 1, background: '#0f1f36', border: '1px solid #1a3050', borderRadius: 10, padding: '12px 16px' }}>
            <div style={{ fontSize: 9, color: '#4d7090', fontFamily: "'JetBrains Mono', monospace", marginBottom: 6 }}>{c.label}</div>
            <div style={{ fontSize: 26, fontWeight: 800, color: c.color }}>{c.value}</div>
          </div>
        ))}

        {/* Actions */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, justifyContent: 'center' }}>
          <button
            onClick={doReload}
            disabled={reloading}
            style={{
              padding: '6px 14px', borderRadius: 6, fontSize: 10, cursor: reloading ? 'not-allowed' : 'pointer',
              fontFamily: "'JetBrains Mono', monospace",
              background: 'rgba(0,229,255,.1)', border: '1px solid rgba(0,229,255,.3)',
              color: '#00e5ff', opacity: reloading ? 0.6 : 1,
            }}
          >
            {reloading ? '↺ Reloading...' : '↺ Reload Rules'}
          </button>
          <ExportBtn
            label="Export JSON" icon="{}"
            onClick={() => exportJSON({ rules: normalized.map(r => r._raw), exported: new Date().toISOString() }, 'kubertsec-rules.json')}
          />
          {reloadMsg && (
            <div style={{
              fontSize: 10, fontFamily: "'JetBrains Mono', monospace",
              color: reloadMsg.startsWith('✓') ? '#06d6a0' : '#ff6b6b',
              textAlign: 'center',
            }}>{reloadMsg}</div>
          )}
        </div>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexShrink: 0, flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', gap: 5 }}>
          {['all', 'critical', 'high', 'medium', 'low'].map(f => (
            <button key={f} onClick={() => setSevFilter(f)} style={fBtn(f, sevFilter, setSevFilter)}>
              {f.toUpperCase()}
            </button>
          ))}
        </div>
        <div style={{ width: 1, height: 18, background: '#1a3050' }} />
        <div style={{ display: 'flex', gap: 5 }}>
          {['all', 'enforce', 'alert', 'detect'].map(f => (
            <button key={f} onClick={() => setModeFilter(f)} style={fBtn(f, modeFilter, setModeFilter)}>
              {f === 'enforce' ? '✕ KILL' : f === 'alert' ? '⚠ ALERT' : f === 'detect' ? '◎ DETECT' : 'ALL'}
            </button>
          ))}
        </div>
        <div style={{ width: 1, height: 18, background: '#1a3050' }} />
        <input
          placeholder="search rules..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{
            background: '#0d1b2e', border: '1px solid #1a3050', color: '#e2eaf7',
            padding: '4px 10px', borderRadius: 6, fontSize: 10,
            fontFamily: "'JetBrains Mono', monospace", outline: 'none', width: 160,
          }}
        />
        <Mono color="#4d7090" style={{ marginLeft: 'auto' }}>{filtered.length}/{normalized.length}</Mono>
      </div>

      {/* Rules table */}
      <div style={{ flex: 1, background: '#0f1f36', border: '1px solid #1a3050', borderRadius: 10, display: 'flex', flexDirection: 'column', overflow: 'hidden', minHeight: 0 }}>
        <div style={{ overflowY: 'auto', flex: 1, minHeight: 0 }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
            <thead style={{ position: 'sticky', top: 0, background: '#0f1f36', zIndex: 2 }}>
              <tr>
                {['SEVERITY', 'RULE NAME', 'MODE', 'PROCESS', 'ARGS MATCH', 'MESSAGE', 'ENABLED', '▾'].map(h => (
                  <th key={h} style={{
                    padding: '8px 12px', textAlign: 'left', color: '#4d7090',
                    fontWeight: 500, borderBottom: '1px solid #1a3050',
                    fontFamily: "'JetBrains Mono', monospace", fontSize: 9, letterSpacing: '.5px',
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ textAlign: 'center', color: '#4d7090', padding: 32 }}>
                    No rules match filters
                  </td>
                </tr>
              ) : filtered.map(rule => {
                const ml = modeLabel(rule.mode);
                const isExpanded = expandedName === rule.name;
                return (
                  <React.Fragment key={rule.name}>
                    <tr
                      style={{ opacity: rule.enabled ? 1 : 0.45, cursor: 'pointer' }}
                      onClick={() => setExpandedName(isExpanded ? null : rule.name)}
                      onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,.02)'}
                      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                    >
                      <td style={{ padding: '10px 12px', borderBottom: '1px solid #0d1f33' }}>
                        <SeverityBadge severity={rule.severity} />
                      </td>
                      <td style={{ padding: '10px 12px', borderBottom: '1px solid #0d1f33' }}>
                        <Mono color="#e2eaf7">{rule.name}</Mono>
                      </td>
                      <td style={{ padding: '10px 12px', borderBottom: '1px solid #0d1f33' }}>
                        <span style={{
                          background: ml.bg, color: ml.color,
                          padding: '3px 9px', borderRadius: 4, fontSize: 10,
                          fontFamily: "'JetBrains Mono', monospace", fontWeight: 600,
                        }}>{ml.label}</span>
                      </td>
                      <td style={{ padding: '10px 12px', borderBottom: '1px solid #0d1f33' }}>
                        <Mono color="#7c4dff">
                          {rule.trigger.length > 28 ? rule.trigger.slice(0, 28) + '..' : rule.trigger}
                        </Mono>
                      </td>
                      <td style={{ padding: '10px 12px', borderBottom: '1px solid #0d1f33' }}>
                        <Mono color="#4d7090">
                          {rule.argsInfo.length > 24 ? rule.argsInfo.slice(0, 24) + '..' : rule.argsInfo}
                        </Mono>
                      </td>
                      <td style={{ padding: '10px 12px', borderBottom: '1px solid #0d1f33', color: '#7090b0', fontSize: 11 }}>
                        {rule.description.length > 36 ? rule.description.slice(0, 36) + '..' : rule.description}
                      </td>
                      <td style={{ padding: '10px 12px', borderBottom: '1px solid #0d1f33' }}>
                        <div
                          onClick={e => { e.stopPropagation(); actions.toggleRule(rule.name); }}
                          style={{
                            width: 36, height: 20, borderRadius: 10,
                            background: rule.enabled ? '#06d6a0' : '#1a3050',
                            position: 'relative', cursor: 'pointer', transition: 'background .2s',
                            border: '1px solid rgba(255,255,255,.05)',
                          }}
                        >
                          <div style={{
                            position: 'absolute', top: 2, left: rule.enabled ? 18 : 2,
                            width: 14, height: 14, borderRadius: '50%',
                            background: '#fff', transition: 'left .2s',
                          }} />
                        </div>
                      </td>
                      <td style={{ padding: '10px 12px', borderBottom: '1px solid #0d1f33', color: '#4d7090', fontSize: 10 }}>
                        {isExpanded ? '▲' : '▼'}
                      </td>
                    </tr>

                    {/* Expanded detail */}
                    {isExpanded && (
                      <tr>
                        <td colSpan={8} style={{ padding: '0 12px 10px', background: '#07111e' }}>
                          <div style={{
                            background: '#07111e', border: '1px solid #1a3050',
                            borderRadius: 7, padding: '12px 16px',
                            fontFamily: "'JetBrains Mono', monospace", fontSize: 10,
                          }}>
                            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '10px 24px' }}>

                              <div>
                                <div style={{ color: '#4d7090', marginBottom: 4, fontSize: 9 }}>PROCESS MATCH</div>
                                <div style={{ color: '#7c4dff' }}>{rule.trigger}</div>
                              </div>

                              <div>
                                <div style={{ color: '#4d7090', marginBottom: 4, fontSize: 9 }}>ARGS MATCH</div>
                                <div style={{ color: '#e2eaf7' }}>{rule.argsInfo}</div>
                              </div>

                              <div>
                                <div style={{ color: '#4d7090', marginBottom: 4, fontSize: 9 }}>MODE</div>
                                <span style={{
                                  background: modeLabel(rule.mode).bg,
                                  color: modeLabel(rule.mode).color,
                                  padding: '2px 8px', borderRadius: 4,
                                }}>{rule.mode}</span>
                              </div>

                              <div>
                                <div style={{ color: '#4d7090', marginBottom: 4, fontSize: 9 }}>MESSAGE</div>
                                <div style={{ color: '#e2eaf7' }}>{rule.description}</div>
                              </div>

                              {rule._raw.namespaces?.length > 0 && (
                                <div>
                                  <div style={{ color: '#4d7090', marginBottom: 4, fontSize: 9 }}>NAMESPACES (only)</div>
                                  <div style={{ color: '#06d6a0' }}>{rule._raw.namespaces.join(', ')}</div>
                                </div>
                              )}

                              {rule._raw.exclude_namespaces?.length > 0 && (
                                <div>
                                  <div style={{ color: '#4d7090', marginBottom: 4, fontSize: 9 }}>EXCLUDE NAMESPACES</div>
                                  <div style={{ color: '#ff8c42' }}>{rule._raw.exclude_namespaces.join(', ')}</div>
                                </div>
                              )}

                              {rule._raw.parent_process && (
                                <div>
                                  <div style={{ color: '#4d7090', marginBottom: 4, fontSize: 9 }}>PARENT PROCESS</div>
                                  <div style={{ color: '#ffd166' }}>{rule._raw.parent_process}</div>
                                </div>
                              )}

                              {rule.tags.length > 0 && (
                                <div>
                                  <div style={{ color: '#4d7090', marginBottom: 4, fontSize: 9 }}>TAGS</div>
                                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                                    {rule.tags.map(t => (
                                      <span key={t} style={{
                                        background: 'rgba(77,184,255,.1)', color: '#4db8ff',
                                        padding: '1px 6px', borderRadius: 3, fontSize: 9,
                                      }}>{t}</span>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Footer */}
      <div style={{
        flexShrink: 0, padding: '7px 12px',
        background: 'rgba(77,184,255,.05)', border: '1px solid rgba(77,184,255,.15)',
        borderRadius: 8, fontSize: 10, color: '#4d7090',
        fontFamily: "'JetBrains Mono', monospace",
      }}>
        ℹ Rule toggles are UI-only. To persist changes: edit <span style={{ color: '#00e5ff' }}>configs/rules/process_rules.yaml</span> then click ↺ Reload Rules
      </div>
    </div>
  );
}