import React, { useState } from 'react';

interface Assessment {
  id: number;
  project_name: string;
  project_number?: string;
  framework: string;
  created_at: string;
  status: string;
  critical_count: number;
  high_count: number;
  medium_count: number;
  version: number;
}

interface Project {
  project_name: string;
  project_number?: string;
  versions: Assessment[];
}

interface ReportHistoryProps {
  projects: Project[];
  onViewReport: (assessmentId: number) => void;
  onDownloadPdf: (assessmentId: number) => void;
}

const ReportHistory: React.FC<ReportHistoryProps> = ({ projects, onViewReport, onDownloadPdf }) => {
  const [groupByProject, setGroupByProject] = useState(true);
  const [expandedProjects, setExpandedProjects] = useState<Set<string>>(new Set());

  const formatDate = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const toggleProject = (projectKey: string) => {
    const newExpanded = new Set(expandedProjects);
    if (newExpanded.has(projectKey)) {
      newExpanded.delete(projectKey);
    } else {
      newExpanded.add(projectKey);
    }
    setExpandedProjects(newExpanded);
  };

  // Flatten all assessments for list view
  const allAssessments: Assessment[] = projects.flatMap(p => p.versions);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold text-slate-900 mb-2">📚 Past Assessments</h2>
          <p className="text-slate-600">View and download your threat assessment reports</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setGroupByProject(!groupByProject)}
            className={`px-4 py-2 rounded-lg font-medium transition-colors ${
              groupByProject
                ? 'bg-blue-600 text-white'
                : 'bg-slate-200 text-slate-700 hover:bg-slate-300'
            }`}
          >
            <i className="fas fa-layer-group mr-2"></i>
            {groupByProject ? 'Grouped by Project' : 'List View'}
          </button>
        </div>
      </div>

      {allAssessments.length === 0 ? (
        <div className="bg-white rounded-xl border border-slate-200 p-16 text-center">
          <div className="w-20 h-20 bg-slate-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <i className="fas fa-folder-open text-3xl text-slate-300"></i>
          </div>
          <h3 className="text-xl font-bold text-slate-900 mb-2">No Reports Yet</h3>
          <p className="text-slate-600">🔍 No past assessments yet. Create your first threat assessment!</p>
        </div>
      ) : groupByProject ? (
        <div className="space-y-6">
          {projects.map((project, idx) => {
            const projectKey = `${project.project_name}_${project.project_number || idx}`;
            const isExpanded = expandedProjects.has(projectKey);
            const latestVersion = project.versions[0];

            return (
              <div key={projectKey} className="bg-white rounded-xl border-2 border-slate-200 overflow-hidden">
                {/* Project Header */}
                <div
                  className="p-6 bg-gradient-to-r from-slate-50 to-white cursor-pointer hover:bg-slate-50 transition-colors"
                  onClick={() => toggleProject(projectKey)}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <h3 className="text-xl font-bold text-slate-900">
                          🔍 {project.project_name}
                        </h3>
                        {project.project_number && (
                          <span className="px-3 py-1 bg-blue-100 text-blue-700 text-sm font-semibold rounded-lg">
                            #{project.project_number}
                          </span>
                        )}
                        <span className="px-3 py-1 bg-purple-100 text-purple-700 text-sm font-semibold rounded-lg">
                          {project.versions.length} version{project.versions.length !== 1 ? 's' : ''}
                        </span>
                      </div>
                      <div className="flex items-center gap-4 text-sm text-slate-600">
                        <span><i className="fas fa-shield-alt mr-1"></i> {latestVersion.framework}</span>
                        <span><i className="fas fa-clock mr-1"></i> Latest: {formatDate(latestVersion.created_at)}</span>
                      </div>
                    </div>
                    <button className="text-slate-400 hover:text-slate-600 transition-colors">
                      <i className={`fas fa-chevron-${isExpanded ? 'up' : 'down'} text-xl`}></i>
                    </button>
                  </div>

                  {/* Risk Summary */}
                  <div className="flex gap-3 mt-4">
                    <div className="flex-1 bg-gradient-to-br from-red-50 to-red-100 rounded-lg p-3 border border-red-200">
                      <p className="text-red-700 text-xs font-bold uppercase">🔴 Critical</p>
                      <p className="text-red-900 text-2xl font-extrabold mt-1">{latestVersion.critical_count}</p>
                    </div>
                    <div className="flex-1 bg-gradient-to-br from-orange-50 to-orange-100 rounded-lg p-3 border border-orange-200">
                      <p className="text-orange-700 text-xs font-bold uppercase">🟠 High</p>
                      <p className="text-orange-900 text-2xl font-extrabold mt-1">{latestVersion.high_count}</p>
                    </div>
                    <div className="flex-1 bg-gradient-to-br from-yellow-50 to-yellow-100 rounded-lg p-3 border border-yellow-200">
                      <p className="text-yellow-700 text-xs font-bold uppercase">🟡 Medium</p>
                      <p className="text-yellow-900 text-2xl font-extrabold mt-1">{latestVersion.medium_count}</p>
                    </div>
                  </div>
                </div>

                {/* Versions List */}
                {isExpanded && (
                  <div className="p-6 bg-slate-50 border-t border-slate-200">
                    <h4 className="text-sm font-bold text-slate-700 uppercase mb-4">Version History</h4>
                    <div className="space-y-3">
                      {project.versions.map((assessment) => (
                        <div
                          key={assessment.id}
                          className="bg-white rounded-lg p-4 border border-slate-200"
                        >
                          <div className="flex items-center justify-between mb-3">
                            <div>
                              <span className="px-2 py-1 bg-blue-600 text-white text-xs font-bold rounded">
                                v{assessment.version}
                              </span>
                              <span className="ml-3 text-sm text-slate-600">
                                {formatDate(assessment.created_at)}
                              </span>
                            </div>
                            <span className="px-3 py-1 bg-green-100 text-green-700 text-xs font-bold rounded-lg uppercase">
                              {assessment.status}
                            </span>
                          </div>

                          <div className="flex items-center justify-between">
                            <div className="flex gap-4 text-sm">
                              <span className="text-red-600 font-semibold">
                                🔴 {assessment.critical_count}
                              </span>
                              <span className="text-orange-600 font-semibold">
                                🟠 {assessment.high_count}
                              </span>
                              <span className="text-yellow-600 font-semibold">
                                🟡 {assessment.medium_count}
                              </span>
                            </div>

                            <div className="flex gap-2">
                              <button
                                onClick={() => onDownloadPdf(assessment.id)}
                                className="px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm font-medium transition-colors"
                              >
                                <i className="fas fa-file-pdf mr-1"></i> PDF
                              </button>
                              <button
                                onClick={() => onViewReport(assessment.id)}
                                className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors"
                              >
                                <i className="fas fa-eye mr-1"></i> View
                              </button>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      ) : (
        <div className="space-y-4">
          {allAssessments.map((assessment) => (
            <div key={assessment.id} className="bg-white rounded-xl border-2 border-slate-200 p-6">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-xl font-bold text-slate-900">
                    🔍 {assessment.project_name}
                  </h3>
                  {assessment.project_number && (
                    <p className="text-sm text-slate-500 font-medium">
                      #{assessment.project_number}
                    </p>
                  )}
                </div>
                <span className="px-3 py-1 bg-green-100 text-green-700 text-xs font-bold rounded-lg uppercase">
                  {assessment.status}
                </span>
              </div>

              <div className="grid grid-cols-3 gap-4 mb-4">
                <div>
                  <p className="text-slate-500 text-xs font-semibold uppercase">Date</p>
                  <p className="text-slate-900 font-semibold">{formatDate(assessment.created_at)}</p>
                </div>
                <div>
                  <p className="text-slate-500 text-xs font-semibold uppercase">Framework</p>
                  <p className="text-slate-900 font-semibold">{assessment.framework}</p>
                </div>
                <div>
                  <p className="text-slate-500 text-xs font-semibold uppercase">Version</p>
                  <p className="text-slate-900 font-semibold">v{assessment.version}</p>
                </div>
              </div>

              <div className="flex gap-3 mb-4">
                <div className="flex-1 bg-gradient-to-br from-red-50 to-red-100 rounded-lg p-3 border border-red-200">
                  <p className="text-red-700 text-xs font-bold uppercase">🔴 Critical</p>
                  <p className="text-red-900 text-2xl font-extrabold mt-1">{assessment.critical_count}</p>
                </div>
                <div className="flex-1 bg-gradient-to-br from-orange-50 to-orange-100 rounded-lg p-3 border border-orange-200">
                  <p className="text-orange-700 text-xs font-bold uppercase">🟠 High</p>
                  <p className="text-orange-900 text-2xl font-extrabold mt-1">{assessment.high_count}</p>
                </div>
                <div className="flex-1 bg-gradient-to-br from-yellow-50 to-yellow-100 rounded-lg p-3 border border-yellow-200">
                  <p className="text-yellow-700 text-xs font-bold uppercase">🟡 Medium</p>
                  <p className="text-yellow-900 text-2xl font-extrabold mt-1">{assessment.medium_count}</p>
                </div>
              </div>

              <div className="flex gap-2">
                <button
                  onClick={() => onDownloadPdf(assessment.id)}
                  className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg font-medium transition-colors"
                >
                  <i className="fas fa-file-pdf mr-2"></i> Download PDF
                </button>
                <button
                  onClick={() => onViewReport(assessment.id)}
                  className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors"
                >
                  <i className="fas fa-eye mr-2"></i> View Full Report
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default ReportHistory;
