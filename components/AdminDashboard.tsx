import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { API_BASE_URL } from '../constants';

interface User {
  id: number;
  email: string;
  username: string;
  full_name: string;
  role: string;
  is_org_admin: boolean;
  is_active: boolean;
  last_login_at: string;
  created_at: string;
}

interface AuditLog {
  id: number;
  user_id: number;
  action: string;
  resource_type: string;
  resource_id: number;
  details: any;
  ip_address: string;
  created_at: string;
}

interface DashboardStats {
  users: {
    total: number;
    active: number;
    inactive: number;
  };
  assessments: {
    total: number;
    last_30d: number;
    last_7d: number;
  };
  frameworks: Record<string, number>;
  risk_areas: Record<string, number>;
  recent_assessments: Array<{
    id: number;
    project_name: string;
    framework: string;
    created_at: string;
    user_email: string;
  }>;
  api: {
    active_keys: number;
    calls_this_month: number;
  };
}

export const AdminDashboard: React.FC = () => {
  const { user, logout } = useAuth();
  const [activeTab, setActiveTab] = useState<'overview' | 'users' | 'audit' | 'api-keys' | 'usage' | 'health' | 'settings'>('overview');
  const [users, setUsers] = useState<User[]>([]);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showInviteModal, setShowInviteModal] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<'admin' | 'manager' | 'user'>('user');
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [selectedUserId, setSelectedUserId] = useState<number | null>(null);
  const [newPassword, setNewPassword] = useState('');
  const [showRoleModal, setShowRoleModal] = useState(false);
  const [selectedRole, setSelectedRole] = useState<'admin' | 'manager' | 'user'>('user');
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);

  useEffect(() => {
    if (activeTab === 'overview') {
      loadDashboardStats();
    } else if (activeTab === 'users') {
      loadUsers();
    } else if (activeTab === 'audit') {
      loadAuditLogs();
    }
  }, [activeTab]);

  const loadDashboardStats = async () => {
    setLoading(true);
    setError(null);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE_URL}/api/dashboard/stats`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error(`Failed to load dashboard stats: ${response.status}`);
      }
      
      const data = await response.json();
      setStats(data);
    } catch (err: any) {
      console.error('Load stats error:', err);
      setError(err.message || 'Failed to load dashboard statistics');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (activeTab === 'users') {
      loadUsers();
    } else if (activeTab === 'audit') {
      loadAuditLogs();
    }
  }, [activeTab]);

  const loadUsers = async () => {
    setLoading(true);
    setError(null);
    try {
      const token = localStorage.getItem('token');
      console.log('Fetching users from:', `${API_BASE_URL}/api/users`);
      console.log('Token exists:', !!token);
      
      const response = await fetch(`${API_BASE_URL}/api/users`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      console.log('Response status:', response.status);
      
      if (!response.ok) {
        const errorData = await response.text();
        console.error('Error response:', errorData);
        throw new Error(`Failed to load users: ${response.status} ${response.statusText}`);
      }
      
      const data = await response.json();
      console.log('Users data:', data);
      setUsers(data.users || []);
    } catch (err: any) {
      console.error('Load users error:', err);
      setError(err.message || 'Failed to fetch users. Please check console for details.');
    } finally {
      setLoading(false);
    }
  };

  const loadAuditLogs = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE_URL}/api/audit-logs`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (!response.ok) throw new Error('Failed to load audit logs');
      
      const data = await response.json();
      setAuditLogs(data.logs || []);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleToggleUserStatus = async (userId: number, currentStatus: boolean) => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE_URL}/api/users/${userId}/status`, {
        method: 'PATCH',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ active: !currentStatus })
      });

      if (!response.ok) throw new Error('Failed to update user status');
      
      await loadUsers();
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleResetPassword = async () => {
    if (!selectedUserId || !newPassword) return;
    
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE_URL}/api/users/${selectedUserId}/password`, {
        method: 'PATCH',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ password: newPassword })
      });

      if (!response.ok) throw new Error('Failed to reset password');
      
      setShowPasswordModal(false);
      setNewPassword('');
      setSelectedUserId(null);
      alert('Password reset successfully');
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleChangeRole = async () => {
    if (!selectedUserId) return;
    
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE_URL}/api/users/${selectedUserId}/role`, {
        method: 'PATCH',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ role: selectedRole })
      });

      if (!response.ok) throw new Error('Failed to change role');
      
      setShowRoleModal(false);
      setSelectedUserId(null);
      await loadUsers();
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleInviteUser = async () => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE_URL}/api/users/invite`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email: inviteEmail, role: inviteRole })
      });

      if (!response.ok) throw new Error('Failed to send invitation');
      
      setShowInviteModal(false);
      setInviteEmail('');
      setInviteRole('user');
      alert('Invitation sent successfully');
    } catch (err: any) {
      alert(err.message);
    }
  };

  const handleDeleteUser = async (userId: number) => {
    if (!confirm('Are you sure you want to delete this user?')) return;

    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE_URL}/api/users/${userId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (!response.ok) throw new Error('Failed to delete user');
      
      loadUsers();
    } catch (err: any) {
      alert(err.message);
    }
  };

  if (user?.role !== 'admin') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-100">
        <div className="bg-white p-8 rounded-lg shadow-lg">
          <h2 className="text-2xl font-bold text-gray-900 mb-4">Access Denied</h2>
          <p className="text-gray-600">You don't have permission to access the admin dashboard.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-100">
      {/* Header */}
      <header className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 py-4 flex justify-between items-center">
          <div>
            <h1 className="text-xl font-bold text-gray-900">SecureAI - Admin Dashboard</h1>
            <p className="text-xs text-gray-600">{user?.organizationName}</p>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-sm text-gray-700">
              {user?.firstName} {user?.lastName}
            </span>
            <button
              onClick={logout}
              className="px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700"
            >
              Logout
            </button>
          </div>
        </div>
      </header>

      {/* Main Content with Sidebar */}
      <div className="max-w-7xl mx-auto px-4 mt-6">
        <div className="flex gap-6">
          {/* Sidebar Navigation */}
          <div className="w-64 bg-white rounded-lg shadow p-4 h-fit">
            <h2 className="text-sm font-bold text-gray-900 mb-4">Navigation</h2>
            <p className="text-xs text-gray-500 mb-3">Select a section</p>
            <nav className="space-y-1">
              <button
                onClick={() => setActiveTab('overview')}
                className={`w-full text-left px-3 py-2 rounded text-sm flex items-center gap-2 ${
                  activeTab === 'overview'
                    ? 'bg-blue-50 text-blue-700 font-medium'
                    : 'text-gray-700 hover:bg-gray-50'
                }`}
              >
                <i className="fas fa-chart-line w-4"></i> Overview
              </button>
              <button
                onClick={() => setActiveTab('users')}
                className={`w-full text-left px-3 py-2 rounded text-sm flex items-center gap-2 ${
                  activeTab === 'users'
                    ? 'bg-blue-50 text-blue-700 font-medium'
                    : 'text-gray-700 hover:bg-gray-50'
                }`}
              >
                <i className="fas fa-users w-4"></i> User Management
              </button>
              <button
                onClick={() => setActiveTab('audit')}
                className={`w-full text-left px-3 py-2 rounded text-sm flex items-center gap-2 ${
                  activeTab === 'audit'
                    ? 'bg-blue-50 text-blue-700 font-medium'
                    : 'text-gray-700 hover:bg-gray-50'
                }`}
              >
                <i className="fas fa-clipboard-list w-4"></i> Audit Logs
              </button>
              <button
                onClick={() => setActiveTab('api-keys')}
                className={`w-full text-left px-3 py-2 rounded text-sm flex items-center gap-2 ${
                  activeTab === 'api-keys'
                    ? 'bg-blue-50 text-blue-700 font-medium'
                    : 'text-gray-700 hover:bg-gray-50'
                }`}
              >
                <i className="fas fa-key w-4"></i> API Keys
              </button>
              <button
                onClick={() => setActiveTab('usage')}
                className={`w-full text-left px-3 py-2 rounded text-sm flex items-center gap-2 ${
                  activeTab === 'usage'
                    ? 'bg-blue-50 text-blue-700 font-medium'
                    : 'text-gray-700 hover:bg-gray-50'
                }`}
              >
                <i className="fas fa-chart-bar w-4"></i> Usage Statistics
              </button>
              <button
                onClick={() => setActiveTab('health')}
                className={`w-full text-left px-3 py-2 rounded text-sm flex items-center gap-2 ${
                  activeTab === 'health'
                    ? 'bg-blue-50 text-blue-700 font-medium'
                    : 'text-gray-700 hover:bg-gray-50'
                }`}
              >
                <i className="fas fa-heartbeat w-4"></i> System Health
              </button>
              <button
                onClick={() => setActiveTab('settings')}
                className={`w-full text-left px-3 py-2 rounded text-sm flex items-center gap-2 ${
                  activeTab === 'settings'
                    ? 'bg-blue-50 text-blue-700 font-medium'
                    : 'text-gray-700 hover:bg-gray-50'
                }`}
              >
                <i className="fas fa-cog w-4"></i> Settings
              </button>
            </nav>
          </div>
          
          {/* Content Area */}
          <div className="flex-1">
            {activeTab === 'overview' && (
              <div className="space-y-6">
                {loading ? (
                  <div className="p-8 text-center">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
                    <p className="mt-4 text-gray-600">Loading dashboard...</p>
                  </div>
                ) : error ? (
                  <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-sm text-red-800">
                    {error}
                  </div>
                ) : stats ? (
                  <>
                    <div>
                      <h2 className="text-lg font-bold text-gray-900 mb-4">📊 Organization Overview</h2>
                      
                      {/* Key Metrics Cards */}
                      <div className="grid grid-cols-4 gap-4 mb-6">
                        <div className="bg-gradient-to-br from-blue-500 to-blue-600 p-4 rounded-lg shadow-lg text-white">
                          <div className="flex items-center justify-between">
                            <div>
                              <p className="text-xs opacity-90 uppercase font-semibold">Total Users</p>
                              <p className="text-3xl font-bold mt-1">{stats.users.total}</p>
                              <p className="text-xs opacity-75 mt-1">{stats.users.active} active</p>
                            </div>
                            <div className="text-4xl opacity-20">
                              <i className="fas fa-users"></i>
                            </div>
                          </div>
                        </div>
                        
                        <div className="bg-gradient-to-br from-green-500 to-green-600 p-4 rounded-lg shadow-lg text-white">
                          <div className="flex items-center justify-between">
                            <div>
                              <p className="text-xs opacity-90 uppercase font-semibold">Total Assessments</p>
                              <p className="text-3xl font-bold mt-1">{stats.assessments.total}</p>
                              <p className="text-xs opacity-75 mt-1">{stats.assessments.last_30d} last 30d</p>
                            </div>
                            <div className="text-4xl opacity-20">
                              <i className="fas fa-shield-alt"></i>
                            </div>
                          </div>
                        </div>
                        
                        <div className="bg-gradient-to-br from-purple-500 to-purple-600 p-4 rounded-lg shadow-lg text-white">
                          <div className="flex items-center justify-between">
                            <div>
                              <p className="text-xs opacity-90 uppercase font-semibold">Active API Keys</p>
                              <p className="text-3xl font-bold mt-1">{stats.api.active_keys}</p>
                              <p className="text-xs opacity-75 mt-1">API access</p>
                            </div>
                            <div className="text-4xl opacity-20">
                              <i className="fas fa-key"></i>
                            </div>
                          </div>
                        </div>
                        
                        <div className="bg-gradient-to-br from-orange-500 to-orange-600 p-4 rounded-lg shadow-lg text-white">
                          <div className="flex items-center justify-between">
                            <div>
                              <p className="text-xs opacity-90 uppercase font-semibold">API Calls</p>
                              <p className="text-3xl font-bold mt-1">{stats.api.calls_this_month}</p>
                              <p className="text-xs opacity-75 mt-1">This month</p>
                            </div>
                            <div className="text-4xl opacity-20">
                              <i className="fas fa-chart-line"></i>
                            </div>
                          </div>
                        </div>
                      </div>
                      
                      {/* Charts Section */}
                      <div className="grid grid-cols-2 gap-6 mb-6">
                        <div className="bg-white p-6 rounded-lg shadow">
                          <h3 className="text-sm font-bold text-gray-900 mb-4">📊 Frameworks Distribution</h3>
                          {Object.keys(stats.frameworks).length > 0 ? (
                            <div className="space-y-3">
                              {Object.entries(stats.frameworks).map(([framework, count]) => {
                                const total = Object.values(stats.frameworks).reduce((a, b) => a + b, 0);
                                const percentage = ((count / total) * 100).toFixed(1);
                                const colors = ['bg-blue-600', 'bg-green-600', 'bg-purple-600', 'bg-red-600', 'bg-yellow-600', 'bg-indigo-600'];
                                const colorIndex = Object.keys(stats.frameworks).indexOf(framework);
                                return (
                                  <div key={framework}>
                                    <div className="flex justify-between text-xs mb-1">
                                      <span className="text-gray-700 font-medium">{framework}</span>
                                      <span className="text-gray-900 font-bold">{count} ({percentage}%)</span>
                                    </div>
                                    <div className="h-3 bg-gray-200 rounded-full overflow-hidden">
                                      <div 
                                        className={`h-full ${colors[colorIndex % colors.length]} transition-all duration-500`}
                                        style={{width: `${percentage}%`}}
                                      ></div>
                                    </div>
                                  </div>
                                );
                              })}
                            </div>
                          ) : (
                            <p className="text-sm text-gray-500 text-center py-4">No assessments yet</p>
                          )}
                        </div>
                        
                        <div className="bg-white p-6 rounded-lg shadow">
                          <h3 className="text-sm font-bold text-gray-900 mb-4">🎯 Risk Areas Coverage</h3>
                          {Object.keys(stats.risk_areas).length > 0 ? (
                            <div className="space-y-3">
                              {Object.entries(stats.risk_areas)
                                .sort(([, a], [, b]) => b - a)
                                .slice(0, 5)
                                .map(([area, count]) => {
                                  const maxCount = Math.max(...Object.values(stats.risk_areas));
                                  const percentage = ((count / maxCount) * 100).toFixed(0);
                                  return (
                                    <div key={area}>
                                      <div className="flex justify-between text-xs mb-1">
                                        <span className="text-gray-700 font-medium">{area}</span>
                                        <span className="text-gray-900 font-bold">{count}</span>
                                      </div>
                                      <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                                        <div 
                                          className="h-full bg-gradient-to-r from-blue-500 to-purple-500 transition-all duration-500"
                                          style={{width: `${percentage}%`}}
                                        ></div>
                                      </div>
                                    </div>
                                  );
                                })}
                            </div>
                          ) : (
                            <p className="text-sm text-gray-500 text-center py-4">No risk areas analyzed yet</p>
                          )}
                        </div>
                      </div>
                      
                      {/* Recent Assessments Table */}
                      <div className="bg-white p-6 rounded-lg shadow">
                        <h3 className="text-sm font-bold text-gray-900 mb-4">🕒 Recent Assessments</h3>
                        {stats.recent_assessments.length > 0 ? (
                          <div className="overflow-x-auto">
                            <table className="w-full text-xs">
                              <thead>
                                <tr className="bg-gray-50 border-b">
                                  <th className="text-left py-3 px-4 font-semibold text-gray-700">Project</th>
                                  <th className="text-left py-3 px-4 font-semibold text-gray-700">Framework</th>
                                  <th className="text-left py-3 px-4 font-semibold text-gray-700">User</th>
                                  <th className="text-left py-3 px-4 font-semibold text-gray-700">Date</th>
                                </tr>
                              </thead>
                              <tbody>
                                {stats.recent_assessments.map((assessment) => (
                                  <tr key={assessment.id} className="border-b hover:bg-gray-50 transition-colors">
                                    <td className="py-3 px-4 font-medium text-gray-900">{assessment.project_name}</td>
                                    <td className="py-3 px-4">
                                      <span className="bg-blue-100 text-blue-800 px-2 py-1 rounded text-xs font-medium">
                                        {assessment.framework}
                                      </span>
                                    </td>
                                    <td className="py-3 px-4 text-gray-600">{assessment.user_email}</td>
                                    <td className="py-3 px-4 text-gray-500">
                                      {new Date(assessment.created_at).toLocaleDateString()}
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        ) : (
                          <p className="text-sm text-gray-500 text-center py-8">No recent assessments</p>
                        )}
                      </div>
                      
                      {/* Activity Summary */}
                      <div className="grid grid-cols-3 gap-4">
                        <div className="bg-white p-4 rounded-lg shadow border-l-4 border-blue-500">
                          <p className="text-xs text-gray-500 font-semibold">Last 7 Days</p>
                          <p className="text-2xl font-bold text-gray-900 mt-1">{stats.assessments.last_7d}</p>
                          <p className="text-xs text-gray-600 mt-1">Assessments</p>
                        </div>
                        <div className="bg-white p-4 rounded-lg shadow border-l-4 border-green-500">
                          <p className="text-xs text-gray-500 font-semibold">Last 30 Days</p>
                          <p className="text-2xl font-bold text-gray-900 mt-1">{stats.assessments.last_30d}</p>
                          <p className="text-xs text-gray-600 mt-1">Assessments</p>
                        </div>
                        <div className="bg-white p-4 rounded-lg shadow border-l-4 border-purple-500">
                          <p className="text-xs text-gray-500 font-semibold">Active Users</p>
                          <p className="text-2xl font-bold text-gray-900 mt-1">{stats.users.active}</p>
                          <p className="text-xs text-gray-600 mt-1">of {stats.users.total} total</p>
                        </div>
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="text-center py-8 text-gray-500">
                    <p>No dashboard data available</p>
                  </div>
                )}
              </div>
            )}
            
            {activeTab === 'users' && (
              <div>
                <div className="flex justify-between items-center mb-4">
                  <h2 className="text-lg font-bold text-gray-900">👥 User Management</h2>
                  <button className="px-4 py-2 bg-blue-600 text-white text-sm rounded hover:bg-blue-700">
                    <i className="fas fa-plus mr-2"></i>Add New User
                  </button>
                </div>
                
                {error && (
                  <div className="mb-4 p-4 bg-red-100 border border-red-400 text-red-700 rounded">
                    {error}
                  </div>
                )}
                
                <div className="bg-white rounded-lg shadow">
                  <div className="p-4 border-b">
                    <h3 className="text-sm font-bold text-gray-900">Current Users</h3>
                  </div>
                  
                  {loading ? (
                    <div className="p-8 text-center">
                      <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
                      <p className="mt-4 text-gray-600">Loading users...</p>
                    </div>
                  ) : users.length === 0 ? (
                    <div className="p-8 text-center text-gray-500">
                      No users found
                    </div>
                  ) : (
                    <table className="w-full text-xs">
                      <thead className="bg-gray-50">
                        <tr>
                          <th className="px-4 py-3 text-left font-medium text-gray-700">#</th>
                          <th className="px-4 py-3 text-left font-medium text-gray-700">Email</th>
                          <th className="px-4 py-3 text-left font-medium text-gray-700">Full Name</th>
                          <th className="px-4 py-3 text-left font-medium text-gray-700">Role</th>
                          <th className="px-4 py-3 text-left font-medium text-gray-700">Status</th>
                          <th className="px-4 py-3 text-left font-medium text-gray-700">Last Login</th>
                          <th className="px-4 py-3 text-left font-medium text-gray-700">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-200">
                        {users.map((u, idx) => (
                        <tr key={u.id}>
                          <td className="px-4 py-3">{idx + 1}</td>
                          <td className="px-4 py-3">{u.email}</td>
                          <td className="px-4 py-3">{u.full_name || u.username}</td>
                          <td className="px-4 py-3">
                            <span className={`px-2 py-1 rounded text-xs font-medium ${
                              u.role === 'admin' ? 'bg-red-100 text-red-800' :
                              u.role === 'manager' ? 'bg-purple-100 text-purple-800' :
                              'bg-blue-100 text-blue-800'
                            }`}>{u.role}</span>
                          </td>
                          <td className="px-4 py-3">
                            <span className={`px-2 py-1 rounded text-xs font-medium ${
                              u.is_active ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
                            }`}>{u.is_active ? 'Active' : 'Inactive'}</span>
                          </td>
                          <td className="px-4 py-3 text-xs">{u.last_login_at ? new Date(u.last_login_at).toLocaleString() : 'Never'}</td>
                          <td className="px-4 py-3">
                            <div className="flex gap-2">
                              <button
                                onClick={() => {
                                  setSelectedUserId(u.id);
                                  setSelectedRole(u.role as any);
                                  setShowRoleModal(true);
                                }}
                                className="text-blue-600 hover:text-blue-800 text-xs"
                                title="Change Role"
                              >
                                <i className="fas fa-user-cog"></i>
                              </button>
                              <button
                                onClick={() => {
                                  setSelectedUserId(u.id);
                                  setShowPasswordModal(true);
                                }}
                                className="text-orange-600 hover:text-orange-800 text-xs"
                                title="Reset Password"
                              >
                                <i className="fas fa-key"></i>
                              </button>
                              <button
                                onClick={() => handleToggleUserStatus(u.id, u.is_active)}
                                className={`${u.is_active ? 'text-red-600 hover:text-red-800' : 'text-green-600 hover:text-green-800'} text-xs`}
                                title={u.is_active ? 'Disable User' : 'Enable User'}
                              >
                                <i className={`fas fa-${u.is_active ? 'ban' : 'check-circle'}`}></i>
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  )}
                </div>
              </div>
            )}
            
            {activeTab === 'audit' && (
              <div>
                <h2 className="text-lg font-bold text-gray-900 mb-4">📋 Audit Logs</h2>
                <div className="bg-white rounded-lg shadow p-6">
                  <div className="grid grid-cols-3 gap-4 mb-6">
                    <div>
                      <label className="block text-xs font-medium text-gray-700 mb-1">Time Period</label>
                      <select className="w-full px-3 py-2 border border-gray-300 rounded text-xs">
                        <option>Last 30 days</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-gray-700 mb-1">Action</label>
                      <select className="w-full px-3 py-2 border border-gray-300 rounded text-xs">
                        <option>All</option>
                        <option>user.login</option>
                        <option>user.create</option>
                        <option>threat_assessment.create</option>
                        <option>api_key.create</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-gray-700 mb-1">Status</label>
                      <select className="w-full px-3 py-2 border border-gray-300 rounded text-xs">
                        <option>All</option>
                      </select>
                    </div>
                  </div>
                  <div className="grid grid-cols-3 gap-4 mb-6">
                    <div className="bg-gray-50 p-4 rounded">
                      <p className="text-xs text-gray-500">TOTAL EVENTS</p>
                      <p className="text-2xl font-bold text-gray-900 mt-1">49</p>
                    </div>
                    <div className="bg-green-50 p-4 rounded">
                      <p className="text-xs text-green-700">SUCCESS RATE</p>
                      <p className="text-2xl font-bold text-green-900 mt-1">93.8%</p>
                    </div>
                    <div className="bg-blue-50 p-4 rounded">
                      <p className="text-xs text-blue-700">ACTION TYPES</p>
                      <p className="text-2xl font-bold text-blue-900 mt-1">2</p>
                    </div>
                  </div>
                  {loading ? (
                    <div className="text-center py-8">
                      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"></div>
                    </div>
                  ) : auditLogs.length > 0 ? (
                    <table className="w-full text-xs">
                      <thead className="bg-gray-50">
                        <tr>
                          <th className="px-3 py-2 text-left font-medium text-gray-700">Timestamp</th>
                          <th className="px-3 py-2 text-left font-medium text-gray-700">User</th>
                          <th className="px-3 py-2 text-left font-medium text-gray-700">Action</th>
                          <th className="px-3 py-2 text-left font-medium text-gray-700">Resource</th>
                          <th className="px-3 py-2 text-left font-medium text-gray-700">IP Address</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-200">
                        {auditLogs.map((log) => (
                          <tr key={log.id}>
                            <td className="px-3 py-2">{new Date(log.created_at).toLocaleString()}</td>
                            <td className="px-3 py-2">User #{log.user_id}</td>
                            <td className="px-3 py-2">
                              <span className="px-2 py-1 bg-blue-100 text-blue-800 rounded">{log.action}</span>
                            </td>
                            <td className="px-3 py-2">{log.resource_type} #{log.resource_id}</td>
                            <td className="px-3 py-2">{log.ip_address}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <div className="text-xs text-gray-600">No audit events found</div>
                  )}
                </div>
              </div>
            )}
            
            {activeTab === 'api-keys' && (
              <div>
                <div className="flex justify-between items-center mb-4">
                  <h2 className="text-lg font-bold text-gray-900">🔑 API Keys</h2>
                  <button className="px-4 py-2 bg-blue-600 text-white text-sm rounded hover:bg-blue-700">
                    <i className="fas fa-plus mr-2"></i>Generate New Key
                  </button>
                </div>
                <div className="bg-white rounded-lg shadow p-6">
                  <p className="text-sm text-gray-600 mb-4">Manage API keys for programmatic access to SecureAI</p>
                  <div className="text-xs text-gray-500">No API keys generated yet. Click "Generate New Key" to create one.</div>
                </div>
              </div>
            )}
            
            {activeTab === 'usage' && (
              <div>
                <h2 className="text-lg font-bold text-gray-900 mb-4">📊 Usage Statistics</h2>
                <div className="bg-white rounded-lg shadow p-6">
                  <p className="text-sm text-gray-600 mb-4">Monitor API usage and resource consumption</p>
                  <div className="text-xs text-gray-500">Usage statistics will be displayed here</div>
                </div>
              </div>
            )}
            
            {activeTab === 'health' && (
              <div>
                <h2 className="text-lg font-bold text-gray-900 mb-4">💚 System Health</h2>
                <div className="bg-white rounded-lg shadow p-6">
                  <div className="space-y-4">
                    <div className="flex items-center justify-between pb-3 border-b">
                      <div>
                        <p className="text-sm font-medium text-gray-900">API Status</p>
                        <p className="text-xs text-gray-500">Backend API health</p>
                      </div>
                      <span className="px-3 py-1 bg-green-100 text-green-800 rounded-full text-xs font-medium">Healthy</span>
                    </div>
                    <div className="flex items-center justify-between pb-3 border-b">
                      <div>
                        <p className="text-sm font-medium text-gray-900">Database</p>
                        <p className="text-xs text-gray-500">SQLite connection</p>
                      </div>
                      <span className="px-3 py-1 bg-green-100 text-green-800 rounded-full text-xs font-medium">Connected</span>
                    </div>
                    <div className="flex items-center justify-between pb-3 border-b">
                      <div>
                        <p className="text-sm font-medium text-gray-900">AI Service</p>
                        <p className="text-xs text-gray-500">Claude API status</p>
                      </div>
                      <span className="px-3 py-1 bg-green-100 text-green-800 rounded-full text-xs font-medium">Active</span>
                    </div>
                  </div>
                </div>
              </div>
            )}
            
            {activeTab === 'settings' && (
              <div>
                <h2 className="text-lg font-bold text-gray-900 mb-4">⚙️ Organization Settings</h2>
                <div className="bg-white rounded-lg shadow">
                  <div className="p-6 border-b">
                    <h3 className="text-sm font-bold text-gray-900 mb-4">Organization Details</h3>
                    <div className="space-y-4">
                      <div>
                        <label className="block text-xs font-medium text-gray-700 mb-1">Organization Name</label>
                        <input type="text" value="Default Organization" className="w-full px-3 py-2 border border-gray-300 rounded text-sm" />
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-gray-700 mb-1">Domain</label>
                        <input type="text" value="example.com" className="w-full px-3 py-2 border border-gray-300 rounded text-sm" />
                      </div>
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <label className="block text-xs font-medium text-gray-700 mb-1">Max Users</label>
                          <div className="flex">
                            <input type="number" value="50" className="flex-1 px-3 py-2 border border-gray-300 rounded-l text-sm" />
                            <button className="px-3 border-t border-b border-r border-gray-300 text-gray-600 hover:bg-gray-50 text-xs">-</button>
                            <button className="px-3 border-t border-b border-r border-gray-300 rounded-r text-gray-600 hover:bg-gray-50 text-xs">+</button>
                          </div>
                        </div>
                        <div>
                          <label className="block text-xs font-medium text-gray-700 mb-1">Storage Limit (GB)</label>
                          <div className="flex">
                            <input type="number" value="10.00" className="flex-1 px-3 py-2 border border-gray-300 rounded-l text-sm" />
                            <button className="px-3 border-t border-b border-r border-gray-300 text-gray-600 hover:bg-gray-50 text-xs">-</button>
                            <button className="px-3 border-t border-b border-r border-gray-300 rounded-r text-gray-600 hover:bg-gray-50 text-xs">+</button>
                          </div>
                        </div>
                      </div>
                      <div>
                        <label className="block text-xs font-medium text-gray-700 mb-1">Max API Calls/Month</label>
                        <input type="number" value="1000" className="w-full px-3 py-2 border border-gray-300 rounded text-sm" />
                      </div>
                      <button className="px-4 py-2 bg-blue-900 text-white rounded hover:bg-blue-800 text-sm">
                        <i className="fas fa-save mr-2"></i>Save Organization
                      </button>
                    </div>
                  </div>
                  <div className="p-6">
                    <h3 className="text-sm font-bold text-gray-900 mb-4">📢 SSO Configuration (SAML)</h3>
                    <label className="flex items-center gap-2 mb-4">
                      <input type="checkbox" className="rounded" />
                      <span className="text-xs text-gray-700">Enable SAML SSO</span>
                    </label>
                    <button className="px-4 py-2 bg-blue-900 text-white rounded hover:bg-blue-800 text-sm">
                      <i className="fas fa-save mr-2"></i>Save SSO Settings
                    </button>
                  </div>
                </div>
              </div>
            )}
            
            {/* Reset Password Modal */}
            {showPasswordModal && (
              <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
                <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">Reset User Password</h3>
                  <div className="space-y-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">New Password</label>
                      <input
                        type="password"
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                        className="w-full px-4 py-2 border border-gray-300 rounded-lg"
                        placeholder="Enter new password"
                      />
                    </div>
                  </div>
                  <div className="mt-6 flex justify-end gap-3">
                    <button
                      onClick={() => {
                        setShowPasswordModal(false);
                        setNewPassword('');
                        setSelectedUserId(null);
                      }}
                      className="px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50"
                    >
                      Cancel
                    </button>
                    <button
                      onClick={handleResetPassword}
                      className="px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700"
                    >
                      Reset Password
                    </button>
                  </div>
                </div>
              </div>
            )}
            
            {/* Change Role Modal */}
            {showRoleModal && (
              <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
                <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">Change User Role</h3>
                  <div className="space-y-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">Role</label>
                      <select
                        value={selectedRole}
                        onChange={(e) => setSelectedRole(e.target.value as any)}
                        className="w-full px-4 py-2 border border-gray-300 rounded-lg"
                      >
                        <option value="user">User</option>
                        <option value="manager">Manager</option>
                        <option value="admin">Admin</option>
                      </select>
                    </div>
                  </div>
                  <div className="mt-6 flex justify-end gap-3">
                    <button
                      onClick={() => {
                        setShowRoleModal(false);
                        setSelectedUserId(null);
                      }}
                      className="px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50"
                    >
                      Cancel
                    </button>
                    <button
                      onClick={handleChangeRole}
                      className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                    >
                      Change Role
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default AdminDashboard;
