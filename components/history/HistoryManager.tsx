'use client';

import React, { useState } from 'react';
import { ScanReport, RiskVerdict } from '@/types/security';
import { VerdictBadge } from '@/components/ui/VerdictBadge';
import { deleteScanById, clearAllScans } from '@/lib/storage/scan-storage';
import {
  Search,
  Trash2,
  ExternalLink,
  Download,
  Filter,
  ArrowUpDown,
  Calendar,
  AlertTriangle,
} from 'lucide-react';

interface HistoryManagerProps {
  initialScans: ScanReport[];
  onSelectScan: (scan: ScanReport) => void;
  onRefresh: () => void;
}

export function HistoryManager({ initialScans, onSelectScan, onRefresh }: HistoryManagerProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [verdictFilter, setVerdictFilter] = useState<string>('ALL');
  const [sortBy, setSortBy] = useState<'date' | 'risk_desc' | 'risk_asc'>('date');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 8;

  const handleDelete = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    deleteScanById(id);
    onRefresh();
  };

  const handleClearAll = () => {
    if (confirm('Are you sure you want to clear all stored scan records?')) {
      clearAllScans();
      onRefresh();
    }
  };

  const handleExportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(initialScans, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `sentinelx_scan_history_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // Filter & Search
  let filtered = initialScans.filter((scan) => {
    const matchesSearch =
      scan.normalizedUrl.toLowerCase().includes(searchTerm.toLowerCase()) ||
      scan.urlFeatures.hostname.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesVerdict = verdictFilter === 'ALL' || scan.verdict === verdictFilter;
    return matchesSearch && matchesVerdict;
  });

  // Sorting
  filtered = [...filtered].sort((a, b) => {
    if (sortBy === 'risk_desc') return b.riskScore - a.riskScore;
    if (sortBy === 'risk_asc') return a.riskScore - b.riskScore;
    return new Date(b.scanTimestamp).getTime() - new Date(a.scanTimestamp).getTime();
  });

  const totalPages = Math.ceil(filtered.length / itemsPerPage) || 1;
  const paginated = filtered.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

  return (
    <div className="space-y-6">
      {/* Control Toolbar */}
      <div className="p-4 rounded-2xl bg-white dark:bg-cyber-900 border border-slate-200 dark:border-cyber-800 shadow-sm flex flex-col md:flex-row gap-4 items-stretch md:items-center justify-between">
        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search by URL or hostname..."
            value={searchTerm}
            onChange={(e) => {
              setSearchTerm(e.target.value);
              setCurrentPage(1);
            }}
            className="w-full pl-9 pr-4 py-2 text-xs font-mono rounded-xl border border-slate-200 dark:border-cyber-750 bg-slate-50 dark:bg-cyber-950 text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-cyber-500 focus:outline-none focus:ring-1 focus:ring-cyber-500"
          />
        </div>

        {/* Filters and Actions */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Verdict Filter */}
          <div className="flex items-center gap-1.5 text-xs">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <select
              value={verdictFilter}
              onChange={(e) => {
                setVerdictFilter(e.target.value);
                setCurrentPage(1);
              }}
              className="px-2.5 py-2 text-xs rounded-xl border border-slate-200 dark:border-cyber-750 bg-white dark:bg-cyber-850 text-slate-700 dark:text-cyber-200 focus:outline-none"
            >
              <option value="ALL">All Verdicts</option>
              <option value="SAFE">Safe</option>
              <option value="LOW_RISK">Low Risk</option>
              <option value="SUSPICIOUS">Suspicious</option>
              <option value="HIGH_RISK">High Risk</option>
              <option value="CRITICAL">Critical</option>
            </select>
          </div>

          {/* Sort By */}
          <div className="flex items-center gap-1.5 text-xs">
            <ArrowUpDown className="w-3.5 h-3.5 text-slate-400" />
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as any)}
              className="px-2.5 py-2 text-xs rounded-xl border border-slate-200 dark:border-cyber-750 bg-white dark:bg-cyber-850 text-slate-700 dark:text-cyber-200 focus:outline-none"
            >
              <option value="date">Most Recent</option>
              <option value="risk_desc">Highest Risk First</option>
              <option value="risk_asc">Lowest Risk First</option>
            </select>
          </div>

          {/* Export Button */}
          <button
            onClick={handleExportJson}
            disabled={initialScans.length === 0}
            type="button"
            className="p-2 text-xs font-semibold rounded-xl border border-slate-200 dark:border-cyber-750 bg-white dark:bg-cyber-850 text-slate-700 dark:text-cyber-200 hover:bg-slate-100 dark:hover:bg-cyber-800 disabled:opacity-50 transition-colors"
            title="Export History JSON"
          >
            <Download className="w-4 h-4" />
          </button>

          {/* Bulk Clear Button */}
          <button
            onClick={handleClearAll}
            disabled={initialScans.length === 0}
            type="button"
            className="p-2 text-xs font-semibold rounded-xl border border-rose-200 dark:border-rose-900/40 bg-rose-50/50 dark:bg-rose-950/30 text-rose-600 dark:text-rose-400 hover:bg-rose-100 disabled:opacity-50 transition-colors"
            title="Clear all records"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Scans Table / Cards */}
      <div className="overflow-hidden rounded-2xl border border-slate-200 dark:border-cyber-800 bg-white dark:bg-cyber-900 shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-200 dark:border-cyber-800 bg-slate-50 dark:bg-cyber-950 font-mono uppercase tracking-wider text-slate-500 dark:text-cyber-400">
              <tr>
                <th className="px-5 py-3.5">Scanned URL</th>
                <th className="px-5 py-3.5">Security Verdict</th>
                <th className="px-5 py-3.5 text-center">Risk Score</th>
                <th className="px-5 py-3.5 text-center">Confidence</th>
                <th className="px-5 py-3.5">Timestamp</th>
                <th className="px-5 py-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-cyber-800 font-mono">
              {paginated.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-5 py-12 text-center text-slate-400 dark:text-cyber-500">
                    No scan records match your filter criteria.
                  </td>
                </tr>
              ) : (
                paginated.map((scan) => (
                  <tr
                    key={scan.id}
                    onClick={() => onSelectScan(scan)}
                    className="hover:bg-slate-50/80 dark:hover:bg-cyber-850/50 cursor-pointer transition-colors"
                  >
                    <td className="px-5 py-4 font-semibold text-slate-900 dark:text-white max-w-xs sm:max-w-md truncate">
                      {scan.normalizedUrl}
                    </td>
                    <td className="px-5 py-4">
                      <VerdictBadge verdict={scan.verdict} size="sm" />
                    </td>
                    <td className="px-5 py-4 text-center">
                      <span
                        className="font-bold px-2 py-0.5 rounded"
                        style={{
                          color:
                            scan.riskScore >= 80
                              ? '#ef4444'
                              : scan.riskScore >= 60
                              ? '#f97316'
                              : scan.riskScore >= 40
                              ? '#f59e0b'
                              : '#10b981',
                        }}
                      >
                        {scan.riskScore} / 100
                      </span>
                    </td>
                    <td className="px-5 py-4 text-center text-slate-600 dark:text-cyber-300">
                      {scan.confidenceScore}%
                    </td>
                    <td className="px-5 py-4 text-slate-500 dark:text-cyber-400">
                      {new Date(scan.scanTimestamp).toLocaleDateString()}{' '}
                      {new Date(scan.scanTimestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </td>
                    <td className="px-5 py-4 text-right">
                      <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                        <button
                          type="button"
                          onClick={() => onSelectScan(scan)}
                          className="p-1.5 rounded-lg text-slate-500 hover:text-cyber-600 hover:bg-slate-100 dark:hover:bg-cyber-800"
                          title="View Full Report"
                        >
                          <ExternalLink className="w-4 h-4" />
                        </button>
                        <button
                          type="button"
                          onClick={(e) => handleDelete(scan.id, e)}
                          className="p-1.5 rounded-lg text-slate-400 hover:text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/40"
                          title="Delete Scan"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        {totalPages > 1 && (
          <div className="px-5 py-3 border-t border-slate-200 dark:border-cyber-800 bg-slate-50 dark:bg-cyber-950 flex items-center justify-between text-xs font-mono">
            <span className="text-slate-500 dark:text-cyber-400">
              Showing {(currentPage - 1) * itemsPerPage + 1} to{' '}
              {Math.min(currentPage * itemsPerPage, filtered.length)} of {filtered.length} scans
            </span>
            <div className="flex items-center gap-1">
              <button
                disabled={currentPage === 1}
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                className="px-2.5 py-1 rounded border border-slate-200 dark:border-cyber-800 disabled:opacity-40"
              >
                Prev
              </button>
              <span className="px-2 font-bold text-slate-700 dark:text-cyber-300">
                {currentPage} / {totalPages}
              </span>
              <button
                disabled={currentPage === totalPages}
                onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                className="px-2.5 py-1 rounded border border-slate-200 dark:border-cyber-800 disabled:opacity-40"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
