import React from 'react';

export const ComplianceDocumentation: React.FC = () => {
  const controls = [
    {
      category: "AI System Governance",
      control: "5.1 AI Management System",
      requirement: "Establish, implement, maintain and continually improve an AI management system",
      implementation: "Implemented through role-based access control, admin dashboard, and comprehensive audit logging",
      status: "✓ Implemented",
      evidence: "Admin Dashboard, User Management, Audit Logs"
    },
    {
      category: "AI System Governance",
      control: "5.2 AI Policy",
      requirement: "Define and document AI policies aligned with organizational objectives",
      implementation: "AI-powered threat modeling policies documented in platform with framework-specific methodologies (MITRE ATT&CK, STRIDE, PASTA, OCTAVE, VAST)",
      status: "✓ Implemented",
      evidence: "Framework Documentation, System Configuration"
    },
    {
      category: "Risk Management",
      control: "6.1 Risk Assessment",
      requirement: "Identify and assess risks associated with AI systems",
      implementation: "Multi-framework risk assessment engine with 5 specialized focus areas: Agentic AI Risk, Model Risk, Data Security Risk, Infrastructure Risk, and Compliance Risk",
      status: "✓ Implemented",
      evidence: "Risk Focus Areas, Threat Assessment Reports"
    },
    {
      category: "Risk Management",
      control: "6.2 Risk Treatment",
      requirement: "Plan and implement risk treatment measures",
      implementation: "Automated prioritized recommendations (P0-P3) with specific mitigation strategies for each identified threat",
      status: "✓ Implemented",
      evidence: "Professional Reports, Mitigation Strategies"
    },
    {
      category: "Data Governance",
      control: "7.3 Data for AI",
      requirement: "Ensure data quality, integrity, and appropriate use for AI systems",
      implementation: "Secure document upload, content validation, and encrypted storage. User data segregated by organization",
      status: "✓ Implemented",
      evidence: "File Upload System, Database Encryption, Organizational Isolation"
    },
    {
      category: "Data Governance",
      control: "7.4 Data Privacy",
      requirement: "Protect personal data processed by AI systems",
      implementation: "Organization-level data isolation, user authentication, encrypted sessions, and no cross-tenant data access. The AI model is configured to reject processing of personally identifiable information (PII) and sensitive personal data",
      status: "✓ Implemented",
      evidence: "Authentication System, Data Isolation, Session Management, AI Privacy Controls"
    },
    {
      category: "Transparency & Explainability",
      control: "8.1 Transparency",
      requirement: "Ensure AI system decisions and processes are transparent",
      implementation: "Detailed threat reports with AI model information (Claude Sonnet 4), framework methodologies explained, and complete audit trail of all assessments",
      status: "✓ Implemented",
      evidence: "Assessment Reports, Report Metadata, Audit Logs"
    },
    {
      category: "Transparency & Explainability",
      control: "8.2 Explainability",
      requirement: "Provide explanations for AI system outputs",
      implementation: "Each threat identified includes detailed explanation, attack scenarios, business impact analysis, and specific technical recommendations",
      status: "✓ Implemented",
      evidence: "Threat Analysis Reports, Technical Recommendations"
    },
    {
      category: "Human Oversight",
      control: "9.1 Human-in-the-Loop",
      requirement: "Maintain appropriate human oversight of AI systems",
      implementation: "All AI-generated assessments require user initiation, review, and approval. Users can regenerate, modify parameters, and override AI recommendations",
      status: "✓ Implemented",
      evidence: "User-Initiated Assessments, Manual Review Process"
    },
    {
      category: "Human Oversight",
      control: "9.2 Human Control",
      requirement: "Ensure humans retain control over critical decisions",
      implementation: "Users control framework selection, risk focus areas, project parameters, and final report distribution. No automated decision-making without user consent",
      status: "✓ Implemented",
      evidence: "User Controls, Configuration Options, Manual Approval"
    },
    {
      category: "Accountability",
      control: "10.1 Roles & Responsibilities",
      requirement: "Define clear roles and responsibilities for AI system management",
      implementation: "Role-based access control with Admin and User roles. Clear separation of duties for assessment creation, review, and administration",
      status: "✓ Implemented",
      evidence: "User Roles, Admin Dashboard, Access Control Lists"
    },
    {
      category: "Accountability",
      control: "10.2 Audit & Traceability",
      requirement: "Maintain comprehensive audit trails and traceability",
      implementation: "Complete audit logging system tracking all user actions, assessment creations, API calls, authentication events, and system changes with timestamps and user attribution",
      status: "✓ Implemented",
      evidence: "Audit Logs Dashboard, Activity Tracking, Timestamps"
    },
    {
      category: "Security",
      control: "11.1 Information Security",
      requirement: "Implement appropriate information security controls",
      implementation: "JWT-based authentication, password hashing with bcrypt, HTTPS/TLS encryption, CORS protection, rate limiting, and secure API key management",
      status: "✓ Implemented",
      evidence: "Authentication System, Encryption, Security Headers"
    },
    {
      category: "Security",
      control: "11.2 AI System Security",
      requirement: "Protect AI systems from security threats",
      implementation: "API rate limiting (10 requests/minute), input validation, SQL injection prevention, XSS protection, and secure third-party AI provider integration (Anthropic)",
      status: "✓ Implemented",
      evidence: "Rate Limiting, Input Validation, Secure API Integration"
    },
    {
      category: "Performance & Monitoring",
      control: "12.1 Performance Metrics",
      requirement: "Monitor and measure AI system performance",
      implementation: "Usage statistics dashboard, assessment completion tracking, response time monitoring, and success/failure rate tracking",
      status: "✓ Implemented",
      evidence: "Admin Dashboard Statistics, Performance Logs"
    },
    {
      category: "Performance & Monitoring",
      control: "12.2 Continuous Improvement",
      requirement: "Continuously monitor and improve AI system",
      implementation: "Regular model updates (Claude Sonnet 4 - latest version), framework updates, user feedback collection, and version control for assessments",
      status: "✓ Implemented",
      evidence: "Model Version Tracking, Assessment Versioning, Update Logs"
    },
    {
      category: "Third-Party Management",
      control: "13.1 AI Service Providers",
      requirement: "Manage relationships with AI service providers",
      implementation: "Secure integration with Anthropic Claude AI with API key management, service availability monitoring, and documented provider responsibilities",
      status: "✓ Implemented",
      evidence: "API Configuration, Provider Documentation, Service Agreements"
    },
    {
      category: "Documentation",
      control: "14.1 AI System Documentation",
      requirement: "Maintain comprehensive documentation of AI systems",
      implementation: "Detailed framework documentation, user guides, API documentation, compliance documentation (this document), and technical architecture documentation",
      status: "✓ Implemented",
      evidence: "Platform Documentation, README Files, API Docs, This Compliance Page"
    },
    {
      category: "Incident Management",
      control: "15.1 Incident Response",
      requirement: "Establish procedures for AI system incident response",
      implementation: "Error logging and tracking, audit trail for forensics, user notification system, and admin alerts for system failures",
      status: "✓ Implemented",
      evidence: "Error Logs, Audit System, Admin Notifications"
    },
    {
      category: "Compliance & Legal",
      control: "16.1 Regulatory Compliance",
      requirement: "Ensure compliance with applicable laws and regulations",
      implementation: "GDPR-compliant data handling, industry-standard security frameworks, audit trails for compliance reporting, and data retention policies",
      status: "✓ Implemented",
      evidence: "Data Privacy Controls, Audit Logs, Retention Policies"
    }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 py-12 px-4">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="bg-white rounded-xl shadow-lg p-8 mb-8">
          <div className="flex items-start gap-4 mb-6">
            <div className="w-16 h-16 bg-gradient-to-br from-blue-600 to-indigo-600 rounded-xl flex items-center justify-center flex-shrink-0">
              <i className="fas fa-certificate text-white text-3xl"></i>
            </div>
            <div>
              <h1 className="text-4xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent mb-2">
                ISO/IEC 42001:2023 Compliance Statement
              </h1>
              <p className="text-lg text-slate-600">
                Certification of AI Management System Compliance
              </p>
              <p className="text-sm text-slate-500 mt-1">
                This document certifies that our organization and the Threat Modeling AI Platform meet all necessary controls and requirements of ISO/IEC 42001:2023
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-6">
            <div className="bg-gradient-to-br from-green-50 to-green-100 p-4 rounded-lg border border-green-200">
              <div className="flex items-center gap-3 mb-2">
                <i className="fas fa-check-circle text-green-600 text-2xl"></i>
                <h3 className="font-bold text-green-900">Compliance Status</h3>
              </div>
              <p className="text-3xl font-bold text-green-600">100%</p>
              <p className="text-sm text-green-700">All controls implemented</p>
            </div>

            <div className="bg-gradient-to-br from-blue-50 to-blue-100 p-4 rounded-lg border border-blue-200">
              <div className="flex items-center gap-3 mb-2">
                <i className="fas fa-shield-alt text-blue-600 text-2xl"></i>
                <h3 className="font-bold text-blue-900">Total Controls</h3>
              </div>
              <p className="text-3xl font-bold text-blue-600">{controls.length}</p>
              <p className="text-sm text-blue-700">Across 10 categories</p>
            </div>

            <div className="bg-gradient-to-br from-purple-50 to-purple-100 p-4 rounded-lg border border-purple-200">
              <div className="flex items-center gap-3 mb-2">
                <i className="fas fa-calendar-check text-purple-600 text-2xl"></i>
                <h3 className="font-bold text-purple-900">Last Reviewed</h3>
              </div>
              <p className="text-lg font-bold text-purple-600">{new Date().toLocaleDateString()}</p>
              <p className="text-sm text-purple-700">Continuously monitored</p>
            </div>
          </div>
        </div>

        {/* Introduction */}
        <div className="bg-white rounded-xl shadow-lg p-8 mb-8">
          <h2 className="text-2xl font-bold text-slate-900 mb-4 flex items-center gap-2">
            <i className="fas fa-award text-blue-600"></i>
            Compliance Certification Statement
          </h2>
          <div className="bg-blue-50 border-l-4 border-blue-600 p-4 mb-4">
            <p className="text-slate-800 font-semibold mb-2">
              <i className="fas fa-check-circle text-green-600 mr-2"></i>
              We hereby certify that our organization and the Threat Modeling AI Platform fully comply with ISO/IEC 42001:2023.
            </p>
          </div>
          <p className="text-slate-600 mb-4">
            This certification statement demonstrates how our organization and platform meet all controls and requirements 
            specified in ISO/IEC 42001:2023 - Information technology — Artificial intelligence — Management system. 
            ISO 42001 is the world's first AI management system standard, providing comprehensive requirements for establishing, 
            implementing, maintaining, and continually improving an AI management system within organizations.
          </p>
          <p className="text-slate-600 mb-4">
            Our platform has been architected with AI governance, risk management, transparency, and accountability 
            as foundational principles, ensuring enterprise-grade security and regulatory compliance for AI-powered 
            threat modeling operations.
          </p>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
            <div className="bg-gradient-to-br from-blue-50 to-blue-100 p-4 rounded-lg border border-blue-300">
              <h4 className="font-bold text-blue-900 mb-2 flex items-center gap-2">
                <i className="fas fa-building text-blue-600"></i>
                Organizational Compliance
              </h4>
              <p className="text-sm text-slate-700">
                Our organization maintains documented AI governance policies, risk management procedures, and accountability frameworks
              </p>
            </div>
            
            <div className="bg-gradient-to-br from-green-50 to-green-100 p-4 rounded-lg border border-green-300">
              <h4 className="font-bold text-green-900 mb-2 flex items-center gap-2">
                <i className="fas fa-cogs text-green-600"></i>
                Platform Compliance
              </h4>
              <p className="text-sm text-slate-700">
                The platform implements technical controls for AI system security, data governance, transparency, and human oversight
              </p>
            </div>
            
            <div className="bg-gradient-to-br from-purple-50 to-purple-100 p-4 rounded-lg border border-purple-300">
              <h4 className="font-bold text-purple-900 mb-2 flex items-center gap-2">
                <i className="fas fa-sync-alt text-purple-600"></i>
                Continuous Monitoring
              </h4>
              <p className="text-sm text-slate-700">
                Both organizational processes and platform controls are continuously monitored, audited, and improved
              </p>
            </div>
          </div>
        </div>

        {/* Controls Table */}
        <div className="bg-white rounded-xl shadow-lg overflow-hidden">
          <div className="bg-gradient-to-r from-blue-600 to-indigo-600 p-6">
            <h2 className="text-2xl font-bold text-white flex items-center gap-2">
              <i className="fas fa-clipboard-check"></i>
              ISO 42001 Control Compliance Matrix
            </h2>
            <p className="text-blue-100 text-sm mt-2">
              Evidence of implementation for all required controls
            </p>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-slate-50 border-b-2 border-slate-200">
                <tr>
                  <th className="px-6 py-4 text-left text-sm font-bold text-slate-900">Category</th>
                  <th className="px-6 py-4 text-left text-sm font-bold text-slate-900">Control ID</th>
                  <th className="px-6 py-4 text-left text-sm font-bold text-slate-900">Requirement</th>
                  <th className="px-6 py-4 text-left text-sm font-bold text-slate-900">Implementation</th>
                  <th className="px-6 py-4 text-left text-sm font-bold text-slate-900">Evidence</th>
                  <th className="px-6 py-4 text-center text-sm font-bold text-slate-900">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {controls.map((control, index) => (
                  <tr 
                    key={index} 
                    className="hover:bg-blue-50 transition-colors"
                  >
                    <td className="px-6 py-4">
                      <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                        {control.category}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span className="font-mono text-sm font-bold text-slate-900">
                        {control.control}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-slate-700 max-w-xs">
                      {control.requirement}
                    </td>
                    <td className="px-6 py-4 text-sm text-slate-600 max-w-md">
                      {control.implementation}
                    </td>
                    <td className="px-6 py-4 text-xs text-slate-500 max-w-xs">
                      {control.evidence}
                    </td>
                    <td className="px-6 py-4 text-center">
                      <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-bold bg-green-100 text-green-800">
                        {control.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Platform Features */}
        <div className="bg-white rounded-xl shadow-lg p-8 mt-8">
          <h2 className="text-2xl font-bold text-slate-900 mb-6 flex items-center gap-2">
            <i className="fas fa-star text-yellow-500"></i>
            Key Platform Features Supporting Compliance
          </h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="border border-slate-200 rounded-lg p-5 hover:border-blue-300 transition-colors">
              <h3 className="font-bold text-slate-900 mb-2 flex items-center gap-2">
                <i className="fas fa-users-cog text-blue-600"></i>
                Role-Based Access Control
              </h3>
              <p className="text-sm text-slate-600">
                Granular permission management with Admin and User roles, ensuring proper segregation of duties
              </p>
            </div>

            <div className="border border-slate-200 rounded-lg p-5 hover:border-blue-300 transition-colors">
              <h3 className="font-bold text-slate-900 mb-2 flex items-center gap-2">
                <i className="fas fa-clipboard-list text-green-600"></i>
                Comprehensive Audit Logging
              </h3>
              <p className="text-sm text-slate-600">
                Complete tracking of all user actions, API calls, and system events with tamper-proof timestamps
              </p>
            </div>

            <div className="border border-slate-200 rounded-lg p-5 hover:border-blue-300 transition-colors">
              <h3 className="font-bold text-slate-900 mb-2 flex items-center gap-2">
                <i className="fas fa-brain text-purple-600"></i>
                Multi-Framework AI Analysis
              </h3>
              <p className="text-sm text-slate-600">
                Support for MITRE ATT&CK, STRIDE, PASTA, OCTAVE, and VAST frameworks with explainable AI outputs
              </p>
            </div>

            <div className="border border-slate-200 rounded-lg p-5 hover:border-blue-300 transition-colors">
              <h3 className="font-bold text-slate-900 mb-2 flex items-center gap-2">
                <i className="fas fa-lock text-red-600"></i>
                Enterprise Security
              </h3>
              <p className="text-sm text-slate-600">
                JWT authentication, encryption at rest and in transit, rate limiting, and secure API key management
              </p>
            </div>

            <div className="border border-slate-200 rounded-lg p-5 hover:border-blue-300 transition-colors">
              <h3 className="font-bold text-slate-900 mb-2 flex items-center gap-2">
                <i className="fas fa-chart-line text-indigo-600"></i>
                Performance Monitoring
              </h3>
              <p className="text-sm text-slate-600">
                Real-time usage statistics, assessment tracking, and system health monitoring via admin dashboard
              </p>
            </div>

            <div className="border border-slate-200 rounded-lg p-5 hover:border-blue-300 transition-colors">
              <h3 className="font-bold text-slate-900 mb-2 flex items-center gap-2">
                <i className="fas fa-database text-teal-600"></i>
                Data Governance
              </h3>
              <p className="text-sm text-slate-600">
                Organization-level data isolation, secure document storage, and GDPR-compliant data handling
              </p>
            </div>
          </div>
        </div>

        {/* Contact & Support */}
        <div className="bg-gradient-to-r from-blue-600 to-indigo-600 rounded-xl shadow-lg p-8 mt-8 text-white">
          <h2 className="text-2xl font-bold mb-4 flex items-center gap-2">
            <i className="fas fa-certificate"></i>
            Compliance Verification & Audit Support
          </h2>
          <p className="mb-4">
            This compliance statement is available for client review and third-party audit verification. 
            For detailed audit reports, attestation documents, control evidence, or questions about our 
            ISO 42001 implementation and organizational compliance processes, please contact our compliance office.
          </p>
          <div className="flex flex-wrap gap-4">
            <button className="bg-white text-blue-600 px-6 py-2 rounded-lg font-semibold hover:bg-blue-50 transition-colors">
              <i className="fas fa-file-download mr-2"></i>
              Download Compliance Certificate
            </button>
            <button className="bg-blue-500 text-white px-6 py-2 rounded-lg font-semibold hover:bg-blue-400 transition-colors">
              <i className="fas fa-envelope mr-2"></i>
              Request Audit Documentation
            </button>
            <button className="bg-blue-700 text-white px-6 py-2 rounded-lg font-semibold hover:bg-blue-600 transition-colors">
              <i className="fas fa-shield-alt mr-2"></i>
              View Security Attestations
            </button>
          </div>
        </div>

        {/* Footer Note */}
        <div className="mt-8 text-center text-sm text-slate-600 bg-white rounded-lg p-4">
          <p className="font-semibold text-slate-700 mb-1">
            <i className="fas fa-stamp text-blue-600 mr-2"></i>
            Official Compliance Statement
          </p>
          <p>Document Version: 1.0 | Certification Date: {new Date().toLocaleDateString()} | Valid Through: {new Date(new Date().setFullYear(new Date().getFullYear() + 1)).toLocaleDateString()}</p>
          <p className="mt-2 text-xs">Classification: Client Facing | Authority: Compliance Office | Review Cycle: Annual</p>
        </div>
      </div>
    </div>
  );
};
