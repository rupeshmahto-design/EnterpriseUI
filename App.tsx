import React, { useState, useEffect } from 'react';
import { useAuth } from './context/AuthContext';
import { Login } from './components/Login';
import { Register } from './components/Register';
import { AdminDashboard } from './components/AdminDashboard';
import FileUpload from './components/FileUpload';
import ReportDashboard from './components/ReportDashboard';
import ProfessionalReport from './components/ProfessionalReport';
import ReportHistory from './components/ReportHistory';
import Sidebar from './components/Sidebar';
import { ProjectDocument, ThreatAssessment, SavedReport } from './types';
import { PROJECT_STAGES, FRAMEWORKS, BUSINESS_CRITICALITY, APPLICATION_TYPES, 
         DEPLOYMENT_MODELS, ENVIRONMENTS, RISK_FOCUS_AREAS, COMPLIANCE_REQUIREMENTS, API_BASE_URL } from './constants';

type ViewType = 'upload' | 'dashboard' | 'report' | 'history' | 'admin';

function App() {
  const { user, token, logout, isAdmin, loading } = useAuth();
  const [view, setView] = useState<ViewType>('upload');
  const [showAuthModal, setShowAuthModal] = useState<'login' | 'register' | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  
  // Project state
  const [projectName, setProjectName] = useState('');
  const [projectNumber, setProjectNumber] = useState('');
  const [projectStage, setProjectStage] = useState(PROJECT_STAGES[0]);
  const [framework, setFramework] = useState(FRAMEWORKS[0]);
  const [businessCriticality, setBusinessCriticality] = useState(BUSINESS_CRITICALITY[0]);
  const [applicationType, setApplicationType] = useState(APPLICATION_TYPES[0]);
  const [deploymentModel, setDeploymentModel] = useState(DEPLOYMENT_MODELS[0]);
  const [environment, setEnvironment] = useState(ENVIRONMENTS[0]);
  const [complianceRequirements, setComplianceRequirements] = useState<string[]>([]);
  const [riskFocusAreas, setRiskFocusAreas] = useState<string[]>([]);
  const [documents, setDocuments] = useState<ProjectDocument[]>([]);
  const [report, setReport] = useState<ThreatAssessment | null>(null);
  const [savedReports, setSavedReports] = useState<SavedReport[]>([]);
  
  // UI state
  const [isGenerating, setIsGenerating] = useState(false);
  const [error, setError] = useState('');

  // Check for authentication on mount
  useEffect(() => {
    if (!loading && !user) {
      setShowAuthModal('login');
    }
  }, [loading, user]);

  // Load saved reports when user logs in
  useEffect(() => {
    if (user && token) {
      fetchSavedReports();
    }
  }, [user, token]);

  const fetchSavedReports = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/reports`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (response.ok) {
        const data = await response.json();
        setSavedReports(data);
      }
    } catch (err) {
      console.error('Failed to fetch reports:', err);
    }
  };

  const handleFilesAdded = (newDocs: ProjectDocument[]) => {
    setDocuments([...documents, ...newDocs]);
    setError('');
  };

  const handleGenerateReport = async () => {
    if (!projectName || !projectNumber || documents.length === 0) {
      setError('Please provide project details and upload at least one document');
      return;
    }

    const apiKey = localStorage.getItem('anthropic_api_key');
    if (!apiKey) {
      setError('Please set your Anthropic API key in Settings');
      setSidebarOpen(true);
      return;
    }

    setIsGenerating(true);
    setError('');

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/threat-modeling`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          project_name: projectName,
          project_number: projectNumber,
          project_stage: projectStage,
          framework: framework,
          business_criticality: businessCriticality,
          application_type: applicationType,
          deployment_model: deploymentModel,
          environment: environment,
          compliance_requirements: complianceRequirements,
          risk_focus_areas: riskFocusAreas,
          documents: documents,
          anthropic_api_key: apiKey
        })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to generate threat assessment');
      }

      const reportData = await response.json();
      setReport(reportData.report);
      setView('dashboard');
      
      // Refresh saved reports
      await fetchSavedReports();
    } catch (err: any) {
      setError(err.message || 'Failed to generate threat assessment. Please check your API key and try again.');
      console.error('Threat assessment generation error:', err);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleResetForm = () => {
    setProjectName('');
    setProjectNumber('');
    setProjectStage(PROJECT_STAGES[0]);
    setFramework(FRAMEWORKS[0]);
    setDocuments([]);
    setReport(null);
    setView('upload');
    setError('');
  };

  const handleLoadReport = async (reportId: number) => {
    try {
      const response = await fetch(`${API_BASE_URL}/reports/${reportId}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (!response.ok) {
        throw new Error('Failed to load report');
      }

      const data = await response.json();
      setReport(data.report_data);
      setProjectName(data.project_name);
      setProjectNumber(data.project_number);
      setProjectStage(data.project_stage);
      setView('dashboard');
    } catch (err: any) {
      setError(err.message || 'Failed to load report');
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-slate-600">Loading...</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return (
      <>
        {showAuthModal === 'login' && (
          <Login onSwitchToRegister={() => setShowAuthModal('register')} />
        )}
        {showAuthModal === 'register' && (
          <Register onSwitchToLogin={() => setShowAuthModal('login')} />
        )}
      </>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50">
      {/* Header */}
      <header className="bg-white border-b border-slate-200 sticky top-0 z-30 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-gradient-to-br from-blue-600 to-indigo-600 rounded-lg flex items-center justify-center">
                <i className="fas fa-shield-halved text-white text-xl"></i>
              </div>
              <div>
                <h1 className="text-xl font-bold text-slate-900">Threat Modeling AI</h1>
                <p className="text-xs text-slate-500">AI-Powered Threat Analysis Platform</p>
              </div>
            </div>

            <nav className="hidden md:flex items-center gap-2">
              <button
                onClick={() => setView('upload')}
                className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                  view === 'upload'
                    ? 'bg-blue-100 text-blue-700'
                    : 'text-slate-600 hover:bg-slate-100'
                }`}
              >
                <i className="fas fa-upload mr-2"></i>New Assessment
              </button>
              {report && (
                <>
                  <button
                    onClick={() => setView('dashboard')}
                    className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                      view === 'dashboard'
                        ? 'bg-blue-100 text-blue-700'
                        : 'text-slate-600 hover:bg-slate-100'
                    }`}
                  >
                    <i className="fas fa-chart-line mr-2"></i>Dashboard
                  </button>
                  <button
                    onClick={() => setView('report')}
                    className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                      view === 'report'
                        ? 'bg-blue-100 text-blue-700'
                        : 'text-slate-600 hover:bg-slate-100'
                    }`}
                  >
                    <i className="fas fa-file-alt mr-2"></i>Full Report
                  </button>
                </>
              )}
              <button
                onClick={() => setView('history')}
                className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                  view === 'history'
                    ? 'bg-blue-100 text-blue-700'
                    : 'text-slate-600 hover:bg-slate-100'
                }`}
              >
                <i className="fas fa-history mr-2"></i>History
              </button>
              {isAdmin && (
                <button
                  onClick={() => setView('admin')}
                  className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                    view === 'admin'
                      ? 'bg-blue-100 text-blue-700'
                      : 'text-slate-600 hover:bg-slate-100'
                  }`}
                >
                  <i className="fas fa-user-shield mr-2"></i>Admin
                </button>
              )}
            </nav>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setSidebarOpen(true)}
                className="p-2 text-slate-600 hover:bg-slate-100 rounded-lg transition-colors"
                title="Settings"
              >
                <i className="fas fa-cog text-xl"></i>
              </button>
              <div className="flex items-center gap-3 px-4 py-2 bg-slate-100 rounded-lg">
                <div className="text-right">
                  <p className="text-sm font-medium text-slate-900">{user.full_name}</p>
                  <p className="text-xs text-slate-500">{user.role}</p>
                </div>
                <button
                  onClick={logout}
                  className="p-2 text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                  title="Logout"
                >
                  <i className="fas fa-sign-out-alt"></i>
                </button>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {error && (
          <div className="mb-6 bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg flex items-start gap-3">
            <i className="fas fa-exclamation-circle mt-0.5"></i>
            <div>
              <p className="font-medium">Error</p>
              <p className="text-sm">{error}</p>
            </div>
            <button onClick={() => setError('')} className="ml-auto text-red-700 hover:text-red-900">
              <i className="fas fa-times"></i>
            </button>
          </div>
        )}

        {view === 'upload' && (
          <div className="space-y-6">
            <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
              <h2 className="text-2xl font-bold text-slate-900 mb-6 flex items-center gap-2">
                <i className="fas fa-info-circle text-blue-600"></i>
                Project Information
              </h2>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-2">
                    Project Name *
                  </label>
                  <input
                    type="text"
                    value={projectName}
                    onChange={(e) => setProjectName(e.target.value)}
                    className="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    placeholder="e.g., Customer Portal Modernization"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-2">
                    Business Criticality *
                  </label>
                  <select
                    value={businessCriticality}
                    onChange={(e) => setBusinessCriticality(e.target.value)}
                    className="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    {BUSINESS_CRITICALITY.map(crit => (
                      <option key={crit} value={crit}>{crit}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-2">
                    Project Number
                  </label>
                  <input
                    type="text"
                    value={projectNumber}
                    onChange={(e) => setProjectNumber(e.target.value)}
                    className="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    placeholder="e.g., PRJ-2024-001"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-2">
                    Compliance Requirements
                  </label>
                  <select
                    multiple
                    value={complianceRequirements}
                    onChange={(e) => setComplianceRequirements(Array.from(e.target.selectedOptions, option => option.value))}
                    className="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    size={3}
                  >
                    {COMPLIANCE_REQUIREMENTS.map(req => (
                      <option key={req} value={req}>{req}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-2">
                    Application Type
                  </label>
                  <select
                    value={applicationType}
                    onChange={(e) => setApplicationType(e.target.value)}
                    className="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    {APPLICATION_TYPES.map(type => (
                      <option key={type} value={type}>{type}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-2">
                    Environment
                  </label>
                  <select
                    value={environment}
                    onChange={(e) => setEnvironment(e.target.value)}
                    className="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    {ENVIRONMENTS.map(env => (
                      <option key={env} value={env}>{env}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-2">
                    Deployment Model
                  </label>
                  <select
                    value={deploymentModel}
                    onChange={(e) => setDeploymentModel(e.target.value)}
                    className="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    {DEPLOYMENT_MODELS.map(model => (
                      <option key={model} value={model}>{model}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-2">
                    Project Stage
                  </label>
                  <select
                    value={projectStage}
                    onChange={(e) => setProjectStage(e.target.value)}
                    className="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    {PROJECT_STAGES.map(stage => (
                      <option key={stage} value={stage}>{stage}</option>
                    ))}
                  </select>
                </div>
              </div>
            </div>

            <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
              <h2 className="text-2xl font-bold text-slate-900 mb-6 flex items-center gap-2">
                <i className="fas fa-upload text-orange-600"></i>
                Upload Project Documents
              </h2>
              <FileUpload onFilesAdded={handleFilesAdded} />
              
              {documents.length > 0 && (
                <div className="mt-6">
                  <h3 className="font-semibold text-slate-900 mb-3">Uploaded Documents ({documents.length})</h3>
                  <div className="space-y-2">
                    {documents.map(doc => (
                      <div key={doc.id} className="flex items-center justify-between p-3 bg-slate-50 rounded-lg">
                        <div className="flex items-center gap-3">
                          <i className="fas fa-file-alt text-blue-600"></i>
                          <div>
                            <p className="font-medium text-slate-900">{doc.name}</p>
                            <p className="text-xs text-slate-500">{doc.category} • {doc.size}</p>
                          </div>
                        </div>
                        <button
                          onClick={() => setDocuments(documents.filter(d => d.id !== doc.id))}
                          className="text-red-600 hover:text-red-700"
                        >
                          <i className="fas fa-trash"></i>
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
              <h2 className="text-2xl font-bold text-slate-900 mb-6 flex items-center gap-2">
                <i className="fas fa-shield-alt text-red-600"></i>
                Select Threat Modeling Framework
              </h2>
              
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {FRAMEWORKS.map(fw => (
                  <div
                    key={fw}
                    onClick={() => setFramework(fw)}
                    className={`p-4 border-2 rounded-lg cursor-pointer transition-all ${
                      framework === fw
                        ? 'border-blue-600 bg-blue-50'
                        : 'border-slate-200 hover:border-blue-300'
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-2">
                      <input
                        type="radio"
                        checked={framework === fw}
                        onChange={() => setFramework(fw)}
                        className="text-blue-600"
                      />
                      <h3 className="font-bold text-slate-900">{fw}</h3>
                    </div>
                    <p className="text-xs text-slate-600">
                      {fw === 'MITRE ATT&CK' && 'Comprehensive framework for understanding adversary behavior'}
                      {fw === 'STRIDE' && "Microsoft's threat modeling methodology"}
                      {fw === 'PASTA' && 'Process for Attack Simulation and Threat Analysis'}
                      {fw === 'OCTAVE' && 'Operationally Critical Threat, Asset, and Vulnerability Evaluation'}
                      {fw === 'VAST' && 'Visual, Agile, and Simple Threat modeling'}
                      {fw === 'Custom Client Framework' && 'Organization-specific threat modeling approach'}
                    </p>
                  </div>
                ))}
              </div>
            </div>

            <div className="bg-white rounded-xl shadow-sm border border-slate-200 p-6">
              <h2 className="text-2xl font-bold text-slate-900 mb-6 flex items-center gap-2">
                <i className="fas fa-crosshairs text-purple-600"></i>
                Select Risk Focus Areas
              </h2>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {RISK_FOCUS_AREAS.map(area => (
                  <label
                    key={area}
                    className="flex items-center gap-3 p-4 border-2 border-slate-200 rounded-lg cursor-pointer hover:border-blue-300 transition-all"
                  >
                    <input
                      type="checkbox"
                      checked={riskFocusAreas.includes(area)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setRiskFocusAreas([...riskFocusAreas, area]);
                        } else {
                          setRiskFocusAreas(riskFocusAreas.filter(a => a !== area));
                        }
                      }}
                      className="w-5 h-5 text-blue-600"
                    />
                    <div>
                      <div className="font-semibold text-slate-900">{area}</div>
                      <div className="text-xs text-slate-600">Threats to {area}</div>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            <div className="flex justify-center">
              <button
                onClick={handleGenerateReport}
                disabled={isGenerating || !projectName || documents.length === 0}
                className="px-8 py-4 bg-gradient-to-r from-red-600 to-orange-600 text-white rounded-lg font-bold text-lg hover:from-red-700 hover:to-orange-700 disabled:from-gray-400 disabled:to-gray-400 disabled:cursor-not-allowed transition-all shadow-lg hover:shadow-xl flex items-center gap-3"
              >
                {isGenerating ? (
                  <>
                    <i className="fas fa-spinner fa-spin"></i>
                    Generating Threat Assessment...
                  </>
                ) : (
                  <>
                    <i className="fas fa-shield-virus"></i>
                    Generate Threat Assessment Report
                  </>
                )}
              </button>
            </div>
          </div>
        )}

        {view === 'dashboard' && report && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold text-slate-900">Threat Assessment Dashboard</h2>
              <button
                onClick={handleResetForm}
                className="px-4 py-2 bg-slate-600 text-white rounded-lg hover:bg-slate-700 transition-colors"
              >
                <i className="fas fa-plus mr-2"></i>New Assessment
              </button>
            </div>
            <ReportDashboard report={report} />
          </div>
        )}

        {view === 'report' && report && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold text-slate-900">Full Report</h2>
              <div className="flex gap-2">
                <button
                  onClick={() => window.print()}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                >
                  <i className="fas fa-print mr-2"></i>Print
                </button>
                <button
                  onClick={handleResetForm}
                  className="px-4 py-2 bg-slate-600 text-white rounded-lg hover:bg-slate-700 transition-colors"
                >
                  <i className="fas fa-plus mr-2"></i>New Report
                </button>
              </div>
            </div>
            <ProfessionalReport
              report={report}
              projectName={projectName}
              projectNumber={projectNumber}
              projectStage={projectStage}
              documents={documents}
            />
          </div>
        )}

        {view === 'history' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold text-slate-900">Report History</h2>
              <button
                onClick={() => setView('upload')}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
              >
                <i className="fas fa-plus mr-2"></i>New Report
              </button>
            </div>
            <ReportHistory reports={savedReports} onLoadReport={handleLoadReport} />
          </div>
        )}

        {view === 'admin' && isAdmin && (
          <div className="space-y-6">
            <h2 className="text-2xl font-bold text-slate-900">Admin Dashboard</h2>
            <AdminDashboard />
          </div>
        )}
      </main>

      {/* Sidebar */}
      <Sidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />
    </div>
  );
}

export default App;
