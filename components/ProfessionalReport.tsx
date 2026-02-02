import React from 'react';
import { AssuranceReport } from '../types';

interface ProfessionalReportProps {
  report: AssuranceReport;
  projectName: string;
  projectNumber: string;
  projectStage: string;
  documents: { name: string; category: string }[];
}

const ProfessionalReport: React.FC<ProfessionalReportProps> = ({ 
  report, 
  projectName, 
  projectNumber, 
  projectStage,
  documents 
}) => {
  const reportDate = 'January 31, 2026';
  const reportTime = '4:34 PM AEDT';
  const reportTimestamp = `${reportDate} at ${reportTime}`;

  return (
    <div id="professional-report" className="bg-white" style={{ 
      fontFamily: 'Arial, sans-serif',
      width: '210mm',
      margin: '0 auto',
      padding: '0',
      boxSizing: 'border-box'
    }}>
      
      {/* COVER PAGE */}
      <div className="cover-page" style={{ 
        height: '297mm',
        background: 'linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%)',
        padding: '80px 50px',
        color: 'white',
        pageBreakAfter: 'always',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        boxSizing: 'border-box'
      }}>
        <div style={{ maxWidth: '100%' }}>
          <div style={{ marginBottom: '60px' }}>
            <div style={{ 
              fontSize: '14px', 
              fontWeight: '600', 
              letterSpacing: '3px', 
              marginBottom: '20px',
              opacity: 0.9
            }}>
              PROJECT ASSURANCE REPORT
            </div>
            <div style={{ height: '3px', width: '100px', background: 'white', marginBottom: '40px' }}></div>
          </div>
          
          <h1 style={{ 
            fontSize: '42px', 
            fontWeight: '700', 
            lineHeight: '1.2', 
            marginBottom: '30px',
            textShadow: '0 2px 4px rgba(0,0,0,0.1)'
          }}>
            {projectName}
          </h1>
          
          <div style={{ 
            fontSize: '16px', 
            marginBottom: '60px',
            opacity: 0.95,
            lineHeight: '1.8'
          }}>
            <div style={{ marginBottom: '12px' }}>
              <strong>Project Number:</strong> {projectNumber}
            </div>
            <div style={{ marginBottom: '12px' }}>
              <strong>Project Stage:</strong> {projectStage}
            </div>
            <div style={{ marginBottom: '12px' }}>
              <strong>Report Generated:</strong> {reportTimestamp}
            </div>
          </div>
        </div>
        
        <div style={{ 
          paddingTop: '40px',
          borderTop: '1px solid rgba(255,255,255,0.3)'
        }}>
          <div style={{ fontSize: '16px', fontWeight: '600', marginBottom: '10px' }}>
            AssurePro AI
          </div>
          <div style={{ fontSize: '14px', opacity: 0.8 }}>
            AI-Generated Project Assurance Report | Enterprise Governance Platform
          </div>
        </div>
      </div>

      {/* DOCUMENT REGISTRY PAGE */}
      <div style={{ 
        padding: '50px',
        pageBreakAfter: 'always',
        pageBreakBefore: 'always',
        boxSizing: 'border-box'
      }}>
        <h2 style={{ 
          fontSize: '28px', 
          fontWeight: '700', 
          color: '#1e3a8a',
          marginBottom: '10px',
          borderBottom: '3px solid #3b82f6',
          paddingBottom: '15px'
        }}>
          Document Registry
        </h2>
        
        <p style={{ 
          fontSize: '13px', 
          color: '#6b7280', 
          marginBottom: '30px',
          lineHeight: '1.6'
        }}>
          This assessment is based on analysis of the following project artifacts. Each finding references specific documents and page sections where evidence was identified.
        </p>

        <div style={{ 
          background: '#f9fafb',
          border: '2px solid #e5e7eb',
          borderRadius: '8px',
          padding: '20px'
        }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '2px solid #d1d5db' }}>
                <th style={{ 
                  padding: '12px', 
                  textAlign: 'left', 
                  fontSize: '11px',
                  fontWeight: '700',
                  color: '#374151',
                  textTransform: 'uppercase',
                  letterSpacing: '0.5px'
                }}>
                  #
                </th>
                <th style={{ 
                  padding: '12px', 
                  textAlign: 'left', 
                  fontSize: '11px',
                  fontWeight: '700',
                  color: '#374151',
                  textTransform: 'uppercase',
                  letterSpacing: '0.5px'
                }}>
                  Document Name
                </th>
                <th style={{ 
                  padding: '12px', 
                  textAlign: 'left', 
                  fontSize: '11px',
                  fontWeight: '700',
                  color: '#374151',
                  textTransform: 'uppercase',
                  letterSpacing: '0.5px'
                }}>
                  Category
                </th>
              </tr>
            </thead>
            <tbody>
              {documents.map((doc, idx) => (
                <tr key={idx} style={{ borderBottom: '1px solid #e5e7eb' }}>
                  <td style={{ padding: '12px', fontSize: '12px', color: '#6b7280' }}>
                    {idx + 1}
                  </td>
                  <td style={{ padding: '12px', fontSize: '12px', color: '#111827', fontWeight: '500' }}>
                    {doc.name}
                  </td>
                  <td style={{ padding: '12px', fontSize: '12px', color: '#6b7280' }}>
                    {doc.category}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div style={{ 
          marginTop: '30px',
          padding: '20px',
          background: '#eff6ff',
          border: '2px solid #93c5fd',
          borderRadius: '8px'
        }}>
          <h3 style={{ fontSize: '14px', fontWeight: '700', color: '#1e40af', marginBottom: '10px' }}>
            📌 Analysis Methodology
          </h3>
          <p style={{ fontSize: '12px', lineHeight: '1.6', color: '#1e40af' }}>
            All findings are generated through AI-powered cross-document analysis using industry frameworks including PRINCE2, PMBOK, TOGAF, and ISO 31000. Each observation cites specific document sources and extraction logic to ensure traceability and audit compliance.
          </p>
        </div>
      </div>

      {/* EXECUTIVE SUMMARY PAGE */}
      <div className="summary-page" style={{ 
        padding: '50px',
        pageBreakAfter: 'always',
        pageBreakBefore: 'always',
        boxSizing: 'border-box'
      }}>
        <h2 style={{ 
          fontSize: '28px', 
          fontWeight: '700', 
          color: '#1e3a8a',
          marginBottom: '10px',
          borderBottom: '3px solid #3b82f6',
          paddingBottom: '15px'
        }}>
          Executive Summary
        </h2>
        
        <div style={{ fontSize: '13px', lineHeight: '1.7', color: '#374151', marginTop: '20px', whiteSpace: 'pre-wrap' }}>
          {report.summary}
        </div>

        {report.benefitsSummary && (
          <div style={{ marginTop: '40px' }}>
            <h3 style={{ fontSize: '18px', fontWeight: '700', color: '#1e3a8a', marginBottom: '20px' }}>
              Benefits Overview
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '20px' }}>
              <div style={{ 
                padding: '20px', 
                background: '#ecfdf5', 
                border: '2px solid #10b981',
                borderRadius: '8px',
                textAlign: 'center'
              }}>
                <div style={{ fontSize: '24px', fontWeight: '700', color: '#059669', marginBottom: '8px' }}>
                  ${report.benefitsSummary.totalPlannedValue.toLocaleString()}
                </div>
                <div style={{ fontSize: '12px', color: '#065f46', fontWeight: '600' }}>
                  Total Planned Value
                </div>
              </div>
              
              <div style={{ 
                padding: '20px', 
                background: '#f0f9ff', 
                border: '2px solid #3b82f6',
                borderRadius: '8px',
                textAlign: 'center'
              }}>
                <div style={{ fontSize: '24px', fontWeight: '700', color: '#2563eb', marginBottom: '8px' }}>
                  ${report.benefitsSummary.projectedAnnualValue.toLocaleString()}
                </div>
                <div style={{ fontSize: '12px', color: '#1e40af', fontWeight: '600' }}>
                  Projected Annual Value
                </div>
              </div>
              
              <div style={{ 
                padding: '20px', 
                background: '#fef3c7', 
                border: '2px solid #f59e0b',
                borderRadius: '8px',
                textAlign: 'center'
              }}>
                <div style={{ fontSize: '24px', fontWeight: '700', color: '#d97706', marginBottom: '8px' }}>
                  {report.benefitsSummary.benefitsCount}
                </div>
                <div style={{ fontSize: '12px', color: '#92400e', fontWeight: '600' }}>
                  Key Benefits Identified
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* KEY FINDINGS PAGE */}
      <div className="findings-page" style={{ 
        padding: '50px',
        pageBreakAfter: 'always',
        pageBreakBefore: 'always',
        boxSizing: 'border-box'
      }}>
        <h2 style={{ 
          fontSize: '28px', 
          fontWeight: '700', 
          color: '#1e3a8a',
          marginBottom: '10px',
          borderBottom: '3px solid #3b82f6',
          paddingBottom: '15px'
        }}>
          Key Findings & Gap Analysis
        </h2>

        <div style={{ marginTop: '30px' }}>
          {report.gapAnalysis.map((gap, idx) => (
            <div key={idx} style={{ 
              marginBottom: '30px',
              padding: '25px',
              background: '#f9fafb',
              border: '2px solid #e5e7eb',
              borderRadius: '8px'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '15px' }}>
                <h3 style={{ fontSize: '16px', fontWeight: '700', color: '#111827', margin: 0, flex: 1 }}>
                  {gap.area}
                </h3>
                <span style={{ 
                  padding: '4px 12px',
                  background: gap.severity === 'High' ? '#fef2f2' : gap.severity === 'Medium' ? '#fef3c7' : '#f0fdf4',
                  color: gap.severity === 'High' ? '#dc2626' : gap.severity === 'Medium' ? '#d97706' : '#16a34a',
                  fontSize: '11px',
                  fontWeight: '700',
                  borderRadius: '12px',
                  textTransform: 'uppercase',
                  letterSpacing: '0.5px'
                }}>
                  {gap.severity}
                </span>
              </div>

              <div style={{ marginBottom: '15px' }}>
                <div style={{ fontSize: '11px', fontWeight: '700', color: '#6b7280', marginBottom: '6px', textTransform: 'uppercase' }}>
                  Finding
                </div>
                <p style={{ fontSize: '13px', lineHeight: '1.6', color: '#374151', margin: 0 }}>
                  {gap.finding}
                </p>
              </div>

              {gap.observation && (
                <div style={{ 
                  marginBottom: '15px',
                  padding: '15px',
                  background: '#eff6ff',
                  border: '1px solid #93c5fd',
                  borderRadius: '6px'
                }}>
                  <div style={{ fontSize: '11px', fontWeight: '700', color: '#1e40af', marginBottom: '6px', textTransform: 'uppercase' }}>
                    📋 Document Analysis
                  </div>
                  <p style={{ fontSize: '12px', lineHeight: '1.6', color: '#1e40af', margin: 0, fontStyle: 'italic' }}>
                    {gap.observation}
                  </p>
                </div>
              )}

              <div style={{ marginBottom: '15px' }}>
                <div style={{ fontSize: '11px', fontWeight: '700', color: '#6b7280', marginBottom: '6px', textTransform: 'uppercase' }}>
                  Recommended Action
                </div>
                <p style={{ fontSize: '13px', lineHeight: '1.6', color: '#374151', margin: 0 }}>
                  {gap.recommendation}
                </p>
              </div>

              {gap.leadingQuestions && gap.leadingQuestions.length > 0 && (
                <div style={{ 
                  marginTop: '15px',
                  padding: '15px',
                  background: '#fefce8',
                  border: '1px solid #fde047',
                  borderRadius: '6px'
                }}>
                  <div style={{ fontSize: '11px', fontWeight: '700', color: '#854d0e', marginBottom: '8px', textTransform: 'uppercase' }}>
                    🤔 Leading Questions
                  </div>
                  <ul style={{ margin: 0, paddingLeft: '20px' }}>
                    {gap.leadingQuestions.map((q, qIdx) => (
                      <li key={qIdx} style={{ fontSize: '12px', color: '#854d0e', marginBottom: '5px', lineHeight: '1.5' }}>
                        {q}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* BENEFITS REALIZATION PAGE */}
      <div className="benefits-page" style={{ 
        padding: '50px',
        pageBreakAfter: 'always',
        pageBreakBefore: 'always',
        boxSizing: 'border-box'
      }}>
        <h2 style={{ 
          fontSize: '28px', 
          fontWeight: '700', 
          color: '#1e3a8a',
          marginBottom: '10px',
          borderBottom: '3px solid #3b82f6',
          paddingBottom: '15px'
        }}>
          Benefits Realization Plan
        </h2>

        <div style={{ marginTop: '30px' }}>
          {report.benefitsRealisation.map((benefit, idx) => (
            <div key={idx} style={{ 
              marginBottom: '25px',
              padding: '20px',
              background: '#f9fafb',
              border: '2px solid #e5e7eb',
              borderRadius: '8px'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '15px' }}>
                <h3 style={{ fontSize: '15px', fontWeight: '700', color: '#111827', margin: 0, flex: 1 }}>
                  {benefit.name}
                </h3>
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                  {benefit.category && (
                    <span style={{ 
                      padding: '4px 10px',
                      background: benefit.category === 'Financial' ? '#ecfdf5' : benefit.category === 'Operational' ? '#f0f9ff' : '#fef3c7',
                      color: benefit.category === 'Financial' ? '#059669' : benefit.category === 'Operational' ? '#2563eb' : '#d97706',
                      fontSize: '10px',
                      fontWeight: '700',
                      borderRadius: '10px',
                      textTransform: 'uppercase',
                      letterSpacing: '0.5px'
                    }}>
                      {benefit.category}
                    </span>
                  )}
                  {benefit.financialValue && (
                    <span style={{ 
                      padding: '4px 10px',
                      background: '#dcfce7',
                      color: '#166534',
                      fontSize: '11px',
                      fontWeight: '700',
                      borderRadius: '10px'
                    }}>
                      {benefit.financialValue}
                    </span>
                  )}
                </div>
              </div>

              <p style={{ fontSize: '13px', lineHeight: '1.6', color: '#374151', marginBottom: '15px' }}>
                {benefit.description}
              </p>

              {(benefit.baseline || benefit.target) && (
                <div style={{ 
                  display: 'flex',
                  alignItems: 'center',
                  gap: '15px',
                  padding: '12px',
                  background: '#eff6ff',
                  borderRadius: '6px',
                  marginBottom: '15px'
                }}>
                  {benefit.baseline && (
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: '10px', fontWeight: '700', color: '#6b7280', marginBottom: '4px', textTransform: 'uppercase' }}>
                        Baseline
                      </div>
                      <div style={{ fontSize: '13px', color: '#1e40af', fontWeight: '600' }}>
                        {benefit.baseline}
                      </div>
                    </div>
                  )}
                  {benefit.baseline && benefit.target && (
                    <div style={{ fontSize: '18px', color: '#3b82f6' }}>→</div>
                  )}
                  {benefit.target && (
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: '10px', fontWeight: '700', color: '#6b7280', marginBottom: '4px', textTransform: 'uppercase' }}>
                        Target
                      </div>
                      <div style={{ fontSize: '13px', color: '#16a34a', fontWeight: '600' }}>
                        {benefit.target}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {benefit.observation && (
                <div style={{ 
                  padding: '12px',
                  background: '#fef9c3',
                  border: '1px solid #fde047',
                  borderRadius: '6px',
                  marginBottom: '12px'
                }}>
                  <div style={{ fontSize: '10px', fontWeight: '700', color: '#854d0e', marginBottom: '4px', textTransform: 'uppercase' }}>
                    💡 Observation
                  </div>
                  <p style={{ fontSize: '12px', lineHeight: '1.5', color: '#854d0e', margin: 0 }}>
                    {benefit.observation}
                  </p>
                </div>
              )}

              {benefit.challengingQuestions && benefit.challengingQuestions.length > 0 && (
                <div style={{ 
                  padding: '12px',
                  background: '#fef2f2',
                  border: '1px solid #fecaca',
                  borderRadius: '6px'
                }}>
                  <div style={{ fontSize: '10px', fontWeight: '700', color: '#991b1b', marginBottom: '6px', textTransform: 'uppercase' }}>
                    ⚡ Challenge Points
                  </div>
                  <ul style={{ margin: 0, paddingLeft: '18px' }}>
                    {benefit.challengingQuestions.map((q, qIdx) => (
                      <li key={qIdx} style={{ fontSize: '11px', color: '#991b1b', marginBottom: '4px', lineHeight: '1.4' }}>
                        {q}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {benefit.owner && (
                <div style={{ marginTop: '12px', fontSize: '11px', color: '#6b7280' }}>
                  <strong>Benefit Owner:</strong> {benefit.owner}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* STRATEGIC QUESTIONS PAGE */}
      <div className="questions-page" style={{ 
        padding: '50px',
        pageBreakAfter: 'always',
        pageBreakBefore: 'always',
        boxSizing: 'border-box'
      }}>
        <h2 style={{ 
          fontSize: '28px', 
          fontWeight: '700', 
          color: '#1e3a8a',
          marginBottom: '10px',
          borderBottom: '3px solid #3b82f6',
          paddingBottom: '15px'
        }}>
          Strategic Questions for Leadership
        </h2>

        <p style={{ 
          fontSize: '13px', 
          color: '#6b7280', 
          marginBottom: '30px',
          lineHeight: '1.6'
        }}>
          These questions are designed to facilitate strategic dialogue and ensure alignment between project execution and organizational objectives.
        </p>

        <div style={{ marginTop: '30px' }}>
          {report.criticalQuestions.map((item, idx) => (
            <div key={idx} style={{ 
              marginBottom: '20px',
              padding: '20px',
              background: '#f0f9ff',
              border: '2px solid #3b82f6',
              borderLeft: '6px solid #3b82f6',
              borderRadius: '8px'
            }}>
              <div style={{ display: 'flex', alignItems: 'start', gap: '15px' }}>
                <div style={{ 
                  fontSize: '16px', 
                  fontWeight: '700', 
                  color: '#3b82f6',
                  minWidth: '30px'
                }}>
                  {idx + 1}.
                </div>
                <p style={{ fontSize: '14px', lineHeight: '1.6', color: '#1e40af', margin: 0, fontWeight: '500' }}>
                  {item.question}
                </p>
              </div>
            </div>
          ))}
        </div>

        <div style={{ 
          marginTop: '40px',
          padding: '20px',
          background: '#fef9c3',
          border: '2px solid #fde047',
          borderRadius: '8px'
        }}>
          <h3 style={{ fontSize: '14px', fontWeight: '700', color: '#854d0e', marginBottom: '10px' }}>
            💭 Next Steps
          </h3>
          <p style={{ fontSize: '12px', lineHeight: '1.6', color: '#854d0e', margin: 0 }}>
            We recommend scheduling a governance review session within the next 2 weeks to address these strategic questions and agree on action plans. Key stakeholders including the Project Board, Senior Responsible Owner, and Project Manager should participate.
          </p>
        </div>
      </div>

      {/* FOOTER */}
      <div style={{ 
        padding: '30px 50px',
        textAlign: 'center',
        color: '#9ca3af',
        fontSize: '11px',
        borderTop: '2px solid #e5e7eb'
      }}>
        <p style={{ marginBottom: '5px', fontWeight: '600' }}>
          <strong>AssurePro AI</strong> | Enterprise Project Assurance Platform
        </p>
        <p>AI-Generated Report | {reportTimestamp} | Confidential & Proprietary</p>
      </div>
    </div>
  );
};

export default ProfessionalReport;
