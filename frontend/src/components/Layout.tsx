import React from 'react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { LayoutDashboard, Briefcase, Search, Share2 } from 'lucide-react';

const Layout: React.FC = () => {
  const location = useLocation();

  const navigation = [
    { name: 'Dashboard', href: '/', icon: LayoutDashboard },
    { name: 'Case Management', href: '/cases', icon: Briefcase },
    { name: 'Search', href: '/search', icon: Search },
    { name: 'Network Graph', href: '/graph', icon: Share2 },
  ];

  return (
    <div className="app-container">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <h1>NetPack</h1>
        </div>
        <nav className="nav-links">
          {navigation.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.name}
                to={item.href}
                className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
              >
                <Icon />
                {item.name}
              </NavLink>
            );
          })}
        </nav>
      </aside>

      {/* Main Content */}
      <div className="main-content">
        <header className="top-bar">
          <h2>
            {navigation.find((n) => n.href === location.pathname.replace(/\/$/, '') || n.href === location.pathname)?.name || 'NetPack'}
          </h2>
        </header>
        <main className="content-area">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export default Layout;
