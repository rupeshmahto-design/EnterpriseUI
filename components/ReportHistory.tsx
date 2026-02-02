import React, { useState, useEffect } from 'react';
import { AssuranceReport } from '../types';
import { apiService, SavedReport } from '../services/apiService';
import { generateRiskControlMatrix } from '../services/excelService';
// @ts-ignore
import html2pdf from 'html2pdf.js';

interface ReportHistoryProps {
  onViewReport: (savedReport: SavedReport) => void;
}

const ReportHistory: React.FC<ReportHistoryProps> = ({ onViewReport }) => {
  const [savedReports, setSavedReports] = useState<SavedReport[]>([]);
  const [groupedReports, setGroupedReports] = useState<{ [key: string]: SavedReport[] }>({});
  const [expandedProjects, setExpandedProjects] = useState<Set<string>>(new Set());
  const [exporting, setExporting] = useState<string | null>(null);

  useEffect(() => {
    loadReports();
  }, []);

  const loadReports = async () => {
    try {
      const reports = await apiService.getReports();
      setSavedReports(reports);
      
      // Group by project number
      const grouped = reports.reduce((acc, report) => {
        const key = report.projectNumber || 'No Project Number';
        if (!acc[key]) {
          acc[key] = [];
        }
        acc[key].push(report);
        return acc;
      }, {} as { [key: string]: SavedReport[] });
      
      // Sort each group by timestamp (newest first)
      Object.keys(grouped).forEach(key => {
        grouped[key].sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
      });
      
      setGroupedReports(grouped);
    } catch (error) {
      console.error('Error loading reports:', error);
    }
  };

  const toggleProject = (projectNumber: string) => {
    setExpandedProjects(prev => {
      const newSet = new Set(prev);
      if (newSet.has(projectNumber)) {
        newSet.delete(projectNumber);
      } else {
        newSet.add(projectNumber);
      }
      return newSet;
    });
  };

  const deleteReport = async (reportId: string) => {
    if (confirm('Are you sure you want to delete this report?')) {
      try {
        await apiService.deleteReport(reportId);
        loadReports();
      } catch (error) {
        console.error('Error deleting report:', error);
        alert('Failed to delete report. Please try again.');
      }
    }
  };

  const exportReport = async (savedReport: SavedReport) => {
    setExporting(savedReport.id);
    
    // Create temporary container
    const container = document.createElement('div');
    container.style.position = 'absolute';
    container.style.left = '-9999px';
    document.body.appendChild(container);
    
    // Render appropriate component based on viewMode
    const elementId = savedReport.viewMode === 'professional' ? 'temp-professional-report' : 'temp-dashboard-report';
    container.innerHTML = `<div id="${elementId}"></div>`;
    
    try {
      // Import and render appropriate component
      if (savedReport.viewMode === 'professional') {
        const { default: ProfessionalReport } = await import('./ProfessionalReport');
        const React = await import('react');
        const ReactDOM = await import('react-dom/client');
        
        const root = ReactDOM.createRoot(container.querySelector(`#${elementId}`)!);
        root.render(
          React.createElement(ProfessionalReport, {
            report: savedReport.report,
            projectName: savedReport.projectName,
            projectNumber: savedReport.projectNumber,
            projectStage: savedReport.projectStage,
            documents: savedReport.documents.map(d => ({ name: d.name, category: 'Uploaded' }))
          })
        );
        
        // Wait for render
        await new Promise(resolve => setTimeout(resolve, 500));
      } else {
        const { default: ReportDashboard } = await import('./ReportDashboard');
        const React = await import('react');
        const ReactDOM = await import('react-dom/client');
        
        const root = ReactDOM.createRoot(container.querySelector(`#${elementId}`)!);
        root.render(
          React.createElement(ReportDashboard, {
            report: savedReport.report
          })
        );
        
        await new Promise(resolve => setTimeout(resolve, 500));
      }
      
      const element = container.querySelector(`#${elementId}`);
      
      const opt = {
        margin: 0,
        filename: `${savedReport.projectNumber}_${savedReport.projectName}_${new Date(savedReport.created_at).toISOString().split('T')[0]}.pdf`,
        image: { type: 'jpeg', quality: 0.98 },
        html2canvas: { scale: 2, useCORS: true, letterRendering: true },
        jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' }
      };

      await html2pdf().set(opt).from(element).save();
    } catch (error) {
      console.error('Export failed:', error);
      alert('Failed to export PDF. Please try viewing the report and using the export button there.');
    } finally {
      document.body.removeChild(container);
      setExporting(null);
    }
  };

  const formatDate = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleString('en-AU', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  return (
    <div className="max-w-6xl mx-auto space-y-8">
      <div className="text-center space-y-4">
        <h2 className="text-5xl font-black text-slate-900 tracking-tight">Report History</h2>
        <p className="text-slate-400 font-medium max-w-xl mx-auto text-lg leading-relaxed">
          View and manage your previously generated project assurance reports
        </p>
      </div>

      {Object.keys(groupedReports).length === 0 ? (
        <div className="bg-white rounded-[2rem] border border-slate-200 p-16 text-center">
          <div className="w-24 h-24 bg-slate-100 rounded-full flex items-center justify-center mx-auto mb-6">
            <i className="fa-solid fa-folder-open text-4xl text-slate-300"></i>
          </div>
          <h3 className="text-2xl font-black text-slate-900 mb-3">No Reports Yet</h3>
          <p className="text-slate-400 font-medium max-w-md mx-auto">
            Generate your first project assurance report to see it here
          </p>
        </div>
      ) : (
        <div className="space-y-6">
          {Object.keys(groupedReports).map(projectNumber => (
            <div key={projectNumber} className="bg-white rounded-[2rem] border border-slate-200 overflow-hidden shadow-sm">
              <button
                onClick={() => toggleProject(projectNumber)}
                className="w-full px-10 py-6 flex items-center justify-between hover:bg-slate-50 transition-all"
              >
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 bg-indigo-100 rounded-xl flex items-center justify-center">
                    <i className="fa-solid fa-folder text-indigo-600 text-xl"></i>
                  </div>
                  <div className="text-left">
                    <h3 className="text-xl font-black text-slate-900">{projectNumber}</h3>
                    <p className="text-sm text-slate-400 font-medium">
                      {groupedReports[projectNumber].length} report{groupedReports[projectNumber].length !== 1 ? 's' : ''}
                    </p>
                  </div>
                </div>
                <i className={`fa-solid fa-chevron-${expandedProjects.has(projectNumber) ? 'up' : 'down'} text-slate-400`}></i>
              </button>

              {expandedProjects.has(projectNumber) && (
                <div className="border-t border-slate-200 p-6 space-y-4 bg-slate-50">
                  {groupedReports[projectNumber].map(savedReport => (
                    <div
                      key={savedReport.id}
                      className="bg-white rounded-2xl border border-slate-200 p-6 hover:shadow-md transition-all"
                    >
                      <div className="flex items-start justify-between mb-4">
                        <div className="flex-1">
                          <h4 className="text-lg font-bold text-slate-900 mb-2">
                            {savedReport.projectName}
                          </h4>
                          <div className="flex items-center gap-4 text-sm text-slate-500 font-medium">
                            <span className="flex items-center gap-2">
                              <i className="fa-solid fa-calendar text-slate-400"></i>
                              {formatDate(savedReport.created_at)}
                            </span>
                            <span className="flex items-center gap-2">
                              <i className="fa-solid fa-layer-group text-slate-400"></i>
                              {savedReport.projectStage}
                            </span>
                            <span className="px-3 py-1 bg-indigo-50 text-indigo-600 rounded-lg text-xs font-black uppercase">
                              {savedReport.viewMode === 'professional' ? 'Professional' : 'Dashboard'}
                            </span>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => onViewReport(savedReport)}
                            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-xs font-black uppercase tracking-wider transition-all flex items-center gap-2"
                          >
                            <i className="fa-solid fa-eye"></i>
                            View
                          </button>
                          <button
                            onClick={() => exportReport(savedReport)}
                            disabled={exporting === savedReport.id}
                            className="px-4 py-2 bg-emerald-50 hover:bg-emerald-100 text-emerald-600 rounded-xl text-xs font-black uppercase tracking-wider transition-all flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                          >
                            {exporting === savedReport.id ? (
                              <>
                                <i className="fa-solid fa-spinner fa-spin"></i>
                                Exporting...
                              </>
                            ) : (
                              <>
                                <i className="fa-solid fa-download"></i>
                                Export PDF
                              </>
                            )}
                          </button>
                          <button
                            onClick={() => generateRiskControlMatrix(savedReport.report, savedReport.projectName, savedReport.projectNumber)}
                            className="px-4 py-2 bg-green-50 hover:bg-green-100 text-green-600 rounded-xl text-xs font-black uppercase tracking-wider transition-all flex items-center gap-2"
                            title="Export Risk & Control Matrix to Excel"
                          >
                            <i className="fa-solid fa-file-excel"></i>
                            Risk Matrix
                          </button>
                          <button
                            onClick={() => deleteReport(savedReport.id)}
                            className="px-4 py-2 bg-red-50 hover:bg-red-100 text-red-600 rounded-xl text-xs font-black uppercase tracking-wider transition-all"
                          >
                            <i className="fa-solid fa-trash"></i>
                          </button>
                        </div>
                      </div>

                      <div className="flex flex-wrap gap-2">
                        {savedReport.documents.slice(0, 3).map((doc, idx) => (
                          <span
                            key={idx}
                            className="px-3 py-1 bg-slate-100 text-slate-600 rounded-lg text-xs font-semibold"
                          >
                            {doc.name}
                          </span>
                        ))}
                        {savedReport.documents.length > 3 && (
                          <span className="px-3 py-1 bg-slate-100 text-slate-600 rounded-lg text-xs font-semibold">
                            +{savedReport.documents.length - 3} more
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default ReportHistory;
