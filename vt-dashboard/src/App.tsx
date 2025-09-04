import React, { useState, useEffect } from 'react';
import { Routes, Route } from 'react-router-dom';
import { ThemeProvider } from '@/components/theme-provider';
import { Sidebar } from '@/components/layout/Sidebar';
import { Summary } from '@/pages/Summary';
import { Dashboard } from '@/pages/Dashboard';
import { Reports } from '@/pages/Reports';
import { ReportDetail } from '@/pages/ReportDetail';
import { Search } from '@/pages/Search';

function App() {
  const [isCollapsed, setIsCollapsed] = useState(false);

  // Load collapsed state from localStorage on mount
  useEffect(() => {
    const savedCollapsed = localStorage.getItem('sidebar-collapsed');
    if (savedCollapsed) {
      setIsCollapsed(JSON.parse(savedCollapsed));
    }
  }, []);

  // Save collapsed state to localStorage when it changes
  useEffect(() => {
    localStorage.setItem('sidebar-collapsed', JSON.stringify(isCollapsed));
  }, [isCollapsed]);

  return (
    <ThemeProvider defaultTheme="system" storageKey="vt-dashboard-theme">
      <div className="flex h-screen bg-background">
        <Sidebar isCollapsed={isCollapsed} setIsCollapsed={setIsCollapsed} />
        <main className={`flex-1 overflow-auto transition-all duration-200 ease-in-out pt-14 lg:pt-0`}>
          <Routes>
            <Route path="/" element={<Summary />} />
            <Route path="/analytics" element={<Dashboard />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/reports/:reportId" element={<ReportDetail />} />
            <Route path="/search" element={<Search />} />
          </Routes>
        </main>
      </div>
    </ThemeProvider>
  );
}

export default App;
