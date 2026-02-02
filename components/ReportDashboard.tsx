
import React from 'react';
import { AssuranceReport } from '../types';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts';

interface ReportDashboardProps {
  report: AssuranceReport;
}

const ReportDashboard: React.FC<ReportDashboardProps> = ({ report }) => {
  const COLORS = ['#10b981', '#f59e0b', '#ef4444'];
  
  const gapStats = [
    { name: 'Low', value: report.gapAnalysis.filter(g => g.severity === 'Low').length },
    { name: 'Medium', value: report.gapAnalysis.filter(g => g.severity === 'Medium').length },
    { name: 'High', value: report.gapAnalysis.filter(g => g.severity === 'High').length },
  ];

  const benefitData = report.benefitsRealisation.map(b => ({
    name: b.name.length > 12 ? b.name.substring(0, 10) + '...' : b.name,
    score: b.readinessScore
  }));

  return (
    <div id="assurance-report-content" className="space-y-12 animate-in fade-in duration-1000 bg-transparent p-1">
      
      {/* 1. EXECUTIVE VIEW */}
      <section className="space-y-6">
        <div className="flex items-center gap-3">
          <div className="w-2 h-6 bg-slate-900 rounded-full"></div>
          <h3 className="text-xs font-black uppercase tracking-[0.2em] text-slate-500">I. Executive Assurance View</h3>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
          <div className="bg-white border border-slate-200 p-8 rounded-2xl shadow-sm">
            <p className="text-[10px] font-black text-slate-400 uppercase mb-2 tracking-widest">Health Index</p>
            <div className="flex items-baseline gap-2">
              <span className={`text-5xl font-black ${report.overallScore > 75 ? 'text-emerald-600' : report.overallScore > 50 ? 'text-amber-500' : 'text-rose-600'}`}>
                {report.overallScore}
              </span>
              <span className="text-slate-300 font-bold">%</span>
            </div>
            <p className="text-[10px] text-slate-400 font-bold mt-4 uppercase">Overall Project Confidence</p>
          </div>

          <div className="bg-slate-900 p-8 rounded-2xl shadow-xl lg:col-span-3 text-white relative overflow-hidden">
            <div className="relative z-10">
              <p className="text-[10px] font-black text-slate-400 uppercase mb-4 tracking-widest flex items-center gap-2">
                <i className="fa-solid fa-quote-left text-indigo-400"></i>
                Auditor's Narrative
              </p>
              <p className="text-lg font-medium leading-relaxed text-slate-200 italic">
                "{report.summary}"
              </p>
            </div>
            <div className="absolute top-[-20%] right-[-10%] w-64 h-64 bg-indigo-500/10 rounded-full blur-3xl"></div>
          </div>
        </div>

        {/* Benefits Summary Cards */}
        {report.benefitsSummary && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mt-4">
            <div className="bg-gradient-to-br from-emerald-50 to-emerald-100 border border-emerald-200 p-6 rounded-xl">
              <p className="text-[10px] font-black text-emerald-600 uppercase tracking-widest mb-2">Total Planned Value</p>
              <p className="text-2xl font-black text-emerald-700">{report.benefitsSummary.totalPlannedValue}</p>
            </div>
            <div className="bg-gradient-to-br from-blue-50 to-blue-100 border border-blue-200 p-6 rounded-xl">
              <p className="text-[10px] font-black text-blue-600 uppercase tracking-widest mb-2">Projected Annual</p>
              <p className="text-2xl font-black text-blue-700">{report.benefitsSummary.projectedAnnualValue}</p>
            </div>
            <div className="bg-gradient-to-br from-purple-50 to-purple-100 border border-purple-200 p-6 rounded-xl">
              <p className="text-[10px] font-black text-purple-600 uppercase tracking-widest mb-2">Benefits Count</p>
              <p className="text-2xl font-black text-purple-700">{report.benefitsSummary.benefitsCount}</p>
            </div>
            <div className="bg-gradient-to-br from-amber-50 to-amber-100 border border-amber-200 p-6 rounded-xl">
              <p className="text-[10px] font-black text-amber-600 uppercase tracking-widest mb-2">Realization Outlook</p>
              <p className="text-xs font-bold text-amber-700 leading-tight">{report.benefitsSummary.realizationOutlook}</p>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
           <div className="bg-white border border-slate-200 p-6 rounded-xl flex items-center justify-between">
              <div>
                <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-1">Framework</p>
                <p className="text-sm font-black text-slate-800 uppercase">{report.frameworkAlignment.framework}</p>
              </div>
              <div className="text-2xl font-black text-indigo-600">{report.frameworkAlignment.alignmentScore}%</div>
           </div>
           <div className="bg-white border border-slate-200 p-6 rounded-xl flex items-center justify-between">
              <div>
                <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-1">Financial Risk</p>
                <p className="text-sm font-black text-slate-800 uppercase">{report.financialAssurance.budgetStatus}</p>
              </div>
              <div className="text-2xl font-black text-amber-500">{report.financialAssurance.riskScore}/10</div>
           </div>
           <div className="bg-white border border-slate-200 p-6 rounded-xl flex items-center justify-between">
              <div>
                <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-1">Active Gaps</p>
                <p className="text-sm font-black text-slate-800 uppercase">Findings Requiring Action</p>
              </div>
              <div className="text-2xl font-black text-rose-600">{report.gapAnalysis.length}</div>
           </div>
        </div>
      </section>

      {/* 2. STRATEGIC INQUIRY */}
      <section className="space-y-6 pt-4">
        <div className="flex items-center gap-3">
          <div className="w-2 h-6 bg-amber-500 rounded-full"></div>
          <h3 className="text-xs font-black uppercase tracking-[0.2em] text-slate-500">II. Strategic Inquiry (Critical Questions)</h3>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {report.criticalQuestions.map((q, i) => (
            <div key={i} className="group bg-amber-50/30 hover:bg-amber-50 border border-amber-200 p-6 rounded-2xl transition-all shadow-sm">
              <div className="flex justify-between items-start mb-4">
                <div className="px-3 py-1 bg-white border border-amber-200 rounded-full text-[9px] font-black text-amber-700 uppercase tracking-wider">
                  Target: {q.targetRole}
                </div>
                <div className="w-8 h-8 rounded-full bg-amber-100 flex items-center justify-center text-amber-600">
                  <i className="fa-solid fa-fire-burner text-sm"></i>
                </div>
              </div>
              <p className="text-slate-900 font-black text-base mb-2 group-hover:text-amber-900">{q.question}</p>
              <div className="p-3 bg-white/60 rounded-lg text-xs text-slate-500 leading-snug border border-amber-100">
                <span className="font-black text-[10px] uppercase text-slate-400 mr-2">Context:</span>
                {q.context}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* 3. DETAILED FINDINGS - FORCE NEW PAGE ON PRINT IF NEEDED */}
      <section className="space-y-6 pt-4 break-before-page">
        <div className="flex items-center gap-3">
          <div className="w-2 h-6 bg-indigo-600 rounded-full"></div>
          <h3 className="text-xs font-black uppercase tracking-[0.2em] text-slate-500">III. Detailed Artifact Findings</h3>
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <div className="lg:col-span-2 space-y-4">
            {report.gapAnalysis.map((gap, i) => (
              <div key={i} className="bg-white border border-slate-200 rounded-2xl overflow-hidden flex shadow-sm">
                <div className={`w-3 flex-shrink-0 ${
                  gap.severity === 'High' ? 'bg-rose-500' : gap.severity === 'Medium' ? 'bg-amber-500' : 'bg-emerald-500'
                }`}></div>
                <div className="p-6 flex-1">
                  <div className="flex justify-between items-center mb-3">
                    <span className="text-[10px] font-black uppercase tracking-widest px-2 py-1 bg-slate-100 text-slate-500 rounded">
                      {gap.area}
                    </span>
                    <span className={`text-[10px] font-black uppercase tracking-widest ${
                      gap.severity === 'High' ? 'text-rose-600' : 'text-slate-400'
                    }`}>
                      {gap.severity} Severity
                    </span>
                  </div>
                  <h4 className="font-black text-slate-800 text-lg mb-2">{gap.finding}</h4>
                  
                  {/* Observation */}
                  <div className="mb-3 p-3 bg-blue-50 rounded-lg border border-blue-100">
                    <p className="text-[10px] font-black text-blue-600 uppercase mb-1 flex items-center gap-2">
                      <i className="fa-solid fa-eye"></i> Observation
                    </p>
                    <p className="text-xs text-slate-600 leading-relaxed">{gap.observation}</p>
                  </div>

                  {/* Recommendation */}
                  <div className="flex items-start gap-3 p-4 bg-slate-50 rounded-xl border border-slate-100 mb-3">
                     <i className="fa-solid fa-screwdriver-wrench text-indigo-500 mt-1"></i>
                     <div>
                        <p className="text-[10px] font-black text-slate-400 uppercase mb-1">Mitigation Strategy</p>
                        <p className="text-sm text-slate-600 font-medium leading-relaxed">{gap.recommendation}</p>
                     </div>
                  </div>

                  {/* Leading Questions */}
                  {gap.leadingQuestions && gap.leadingQuestions.length > 0 && (
                    <div className="mt-3 p-3 bg-amber-50 rounded-lg border border-amber-200">
                      <p className="text-[10px] font-black text-amber-700 uppercase mb-2 flex items-center gap-2">
                        <i className="fa-solid fa-comment-dots"></i> Leading Questions
                      </p>
                      <ul className="space-y-1">
                        {gap.leadingQuestions.map((q, idx) => (
                          <li key={idx} className="text-xs text-slate-700 flex items-start gap-2">
                            <span className="text-amber-500 mt-0.5">•</span>
                            <span>{q}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>

          <div className="space-y-6">
            <div className="bg-white border border-slate-200 p-8 rounded-2xl shadow-sm">
              <h4 className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-6 text-center">Correlation Risk Mix</h4>
              <div className="h-48">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={gapStats} cx="50%" cy="50%" innerRadius={55} outerRadius={75} paddingAngle={4} dataKey="value">
                      <Cell fill="#10b981" stroke="none" />
                      <Cell fill="#f59e0b" stroke="none" />
                      <Cell fill="#ef4444" stroke="none" />
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="bg-indigo-600 p-8 rounded-2xl shadow-lg text-white">
              <h4 className="text-[10px] font-black text-indigo-200 uppercase tracking-widest mb-4">Framework Alignment</h4>
              <p className="text-sm font-medium leading-relaxed opacity-90">
                {report.frameworkAlignment.notes}
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* 4. BENEFITS REALISATION */}
      <section className="space-y-6 pt-4">
        <div className="flex items-center gap-3">
          <div className="w-2 h-6 bg-emerald-500 rounded-full"></div>
          <h3 className="text-xs font-black uppercase tracking-[0.2em] text-slate-500">IV. Benefits Realisation Readiness</h3>
        </div>
        <div className="bg-white border border-slate-200 p-10 rounded-3xl shadow-sm">
          <div className="h-64 mb-10">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={benefitData}>
                <XAxis dataKey="name" fontSize={9} axisLine={false} tickLine={false} tick={{fill: '#94a3b8', fontWeight: 900}} />
                <YAxis hide domain={[0, 100]} />
                <Tooltip cursor={{fill: '#f8fafc'}} />
                <Bar dataKey="score" fill="#10b981" radius={[8, 8, 0, 0]} barSize={40} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {report.benefitsRealisation.map((b, i) => {
              const categoryColors = {
                'Financial': 'bg-emerald-50 border-emerald-200 text-emerald-700',
                'Operational': 'bg-blue-50 border-blue-200 text-blue-700',
                'Strategic': 'bg-amber-50 border-amber-200 text-amber-700'
              };
              const categoryColor = categoryColors[b.category] || 'bg-slate-50 border-slate-200 text-slate-700';
              
              return (
                <div key={i} className={`p-6 rounded-2xl border-2 flex flex-col justify-between ${categoryColor}`}>
                  <div>
                    <div className="flex justify-between items-start mb-2">
                      <h5 className="font-black text-slate-800 text-sm leading-tight">{b.name}</h5>
                      <span className="text-emerald-600 font-black text-lg">{b.readinessScore}%</span>
                    </div>
                    
                    {/* Category Badge */}
                    <span className="inline-block px-2 py-1 bg-white/60 rounded text-[9px] font-black uppercase tracking-wider mb-3">
                      {b.category}
                    </span>
                    
                    <p className="text-xs text-slate-700 mb-3 leading-relaxed font-medium">{b.description}</p>
                    
                    {/* Baseline → Target */}
                    {b.baseline && b.target && (
                      <div className="mb-3 p-3 bg-white/80 rounded-lg">
                        <div className="flex items-center gap-2 text-[10px] font-black uppercase tracking-wider text-slate-500 mb-1">
                          <span>📊 Baseline → Target</span>
                        </div>
                        <div className="text-xs text-slate-700 font-bold">
                          {b.baseline} → {b.target}
                        </div>
                      </div>
                    )}
                    
                    {/* Financial Value */}
                    {b.financialValue && (
                      <div className="mb-3 p-2 bg-emerald-100 rounded-lg border border-emerald-300">
                        <p className="text-[9px] font-black text-emerald-700 uppercase mb-1">💰 Financial Value</p>
                        <p className="text-xs font-black text-emerald-800">{b.financialValue}</p>
                      </div>
                    )}
                    
                    {/* Owner */}
                    {b.owner && (
                      <div className="mb-3 text-[10px]">
                        <span className="font-black text-slate-500 uppercase">Owner: </span>
                        <span className="font-bold text-slate-700">{b.owner}</span>
                      </div>
                    )}
                  
                  {/* Observation */}
                  {b.observation && (
                    <div className="mb-3 p-2 bg-blue-50 rounded-lg border border-blue-100">
                      <p className="text-[9px] font-black text-blue-600 uppercase mb-1">Evidence Trail</p>
                      <p className="text-[10px] text-slate-600 leading-snug">{b.observation}</p>
                    </div>
                  )}

                  {/* Challenging Questions */}
                  {b.challengingQuestions && b.challengingQuestions.length > 0 && (
                    <div className="mb-3 p-2 bg-amber-50 rounded-lg border border-amber-200">
                      <p className="text-[9px] font-black text-amber-700 uppercase mb-1">Challenge Points</p>
                      <ul className="space-y-1">
                        {b.challengingQuestions.map((q, idx) => (
                          <li key={idx} className="text-[10px] text-slate-700 flex items-start gap-1">
                            <span className="text-amber-500">•</span>
                            <span>{q}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
                <div className="space-y-2 pt-4 border-t border-white/60">
                  <div className="text-[10px] font-black uppercase tracking-widest text-slate-500">
                    <span>Measurement Source</span>
                  </div>
                  <div className="text-[10px] text-slate-700 font-bold">{b.metric}</div>
                  <div className="flex justify-between text-[10px] font-black uppercase tracking-widest mt-2">
                    <span className="text-slate-400">Target Date</span>
                    <span className="text-slate-700">{b.targetDate}</span>
                  </div>
                </div>
              </div>
              );
            })}
          </div>
        </div>
      </section>

    </div>
  );
};

export default ReportDashboard;
