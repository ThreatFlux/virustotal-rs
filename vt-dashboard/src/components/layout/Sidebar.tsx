import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { useTheme } from '@/components/theme-provider';
import {
  LayoutDashboard,
  FileText,
  Search,
  Shield,
  Moon,
  Sun,
  Monitor,
  Menu,
  X,
  ChevronLeft,
  ChevronRight,
  Palette,
  Activity,
  BarChart3,
} from 'lucide-react';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';

interface NavItem {
  name: string;
  href: string;
  icon: React.ComponentType<any>;
  current?: boolean;
}

const navigation: NavItem[] = [
  { name: 'Summary', href: '/', icon: Activity },
  { name: 'Analytics', href: '/analytics', icon: BarChart3 },
  { name: 'Reports', href: '/reports', icon: FileText },
  { name: 'Search', href: '/search', icon: Search },
];

interface SidebarProps {
  isCollapsed: boolean;
  setIsCollapsed: (collapsed: boolean) => void;
}

export function Sidebar({ isCollapsed, setIsCollapsed }: SidebarProps) {
  const location = useLocation();
  const { theme, setTheme } = useTheme();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <>
      {/* Mobile Menu Button */}
      <button
        onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
        className="fixed top-4 left-4 z-50 p-2 rounded-md bg-card border shadow-sm lg:hidden"
        aria-label="Toggle menu"
      >
        {mobileMenuOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
      </button>

      {/* Mobile Overlay */}
      {mobileMenuOpen && (
        <div
          className="fixed inset-0 z-40 bg-background/80 backdrop-blur-sm lg:hidden"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      {/* Sidebar */}
      <div className={cn(
        "fixed lg:static h-screen flex-col bg-card border-r z-40 transition-all duration-200 ease-in-out flex-shrink-0",
        isCollapsed ? "lg:w-16" : "lg:w-64",
        "w-64",
        mobileMenuOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0",
        "flex overflow-hidden"
      )}>
      {/* Logo/Brand with Collapse Button */}
      <div className="flex h-16 items-center border-b px-4">
        <div className="flex items-center w-full">
          {/* Desktop Collapse Button - Left of Logo */}
          <button
            onClick={() => setIsCollapsed(!isCollapsed)}
            className="hidden lg:flex p-1.5 rounded-md bg-card hover:bg-accent transition-all duration-200 ease-in-out flex-shrink-0"
            aria-label="Toggle sidebar"
          >
            {isCollapsed ? (
              <ChevronRight className="h-4 w-4" />
            ) : (
              <ChevronLeft className="h-4 w-4" />
            )}
          </button>
          
          {/* Hide Shield icon when collapsed on desktop, always show on mobile */}
          {!isCollapsed && (
            <Shield className="hidden lg:block h-8 w-8 text-primary flex-shrink-0 ml-2" />
          )}
          <Shield className="lg:hidden h-8 w-8 text-primary flex-shrink-0" />
          
          {(!isCollapsed || mobileMenuOpen) && (
            <div className="hidden lg:block ml-2">
              <h1 className="text-lg font-bold text-foreground">Security Center</h1>
              <p className="text-xs text-muted-foreground">Threat Analysis</p>
            </div>
          )}
          <div className="lg:hidden ml-2">
            <h1 className="text-lg font-bold text-foreground">Security Center</h1>
            <p className="text-xs text-muted-foreground">Threat Analysis</p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-4 space-y-2" style={{ paddingLeft: isCollapsed ? '8px' : '16px', paddingRight: isCollapsed ? '8px' : '16px' }}>
        {navigation.map((item, index) => {
          const isActive = 
            item.href === '/' 
              ? location.pathname === '/'
              : location.pathname.startsWith(item.href);
          
          return (
            <React.Fragment key={item.name}>
              <Link
                to={item.href}
                onClick={() => setMobileMenuOpen(false)}
                className={cn(
                  'flex items-center text-sm font-medium rounded-md transition-colors relative group',
                  isCollapsed && 'lg:justify-center lg:px-2 lg:py-3',
                  !isCollapsed && 'px-3 py-2',
                  'px-3 py-2', // Mobile always shows full
                  isActive
                    ? 'bg-primary text-primary-foreground shadow-sm'
                    : 'text-muted-foreground hover:text-foreground hover:bg-accent'
                )}
                title={isCollapsed ? item.name : undefined}
              >
                <item.icon className={cn(
                  'h-5 w-5 flex-shrink-0',
                  isCollapsed ? 'lg:mr-0' : 'mr-3'
                )} />
                {(!isCollapsed || mobileMenuOpen) && (
                  <span className={cn(
                    'hidden lg:inline',
                    mobileMenuOpen && 'lg:hidden'
                  )}>
                    {item.name}
                  </span>
                )}
                <span className="lg:hidden">{item.name}</span>
                
                {/* Tooltip for collapsed state */}
                {isCollapsed && (
                  <div className="absolute left-full ml-2 px-2 py-1 bg-popover text-popover-foreground text-xs rounded-md shadow-md opacity-0 group-hover:opacity-100 transition-opacity duration-200 pointer-events-none z-50 whitespace-nowrap hidden lg:block">
                    {item.name}
                  </div>
                )}
              </Link>
              
              {/* Add Theme Switcher after Search */}
              {item.name === 'Search' && (
                <div className="mt-2 mb-2">
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button 
                        variant="ghost" 
                        size="sm" 
                        className={cn(
                          "w-full transition-all duration-200 hover:bg-accent/50 border border-transparent hover:border-border/50",
                          isCollapsed ? 'lg:justify-center lg:px-2' : 'justify-start px-3 py-2',
                          "justify-start px-3 py-2" // Always justify-start on mobile
                        )}
                        title={isCollapsed ? `Current theme: ${theme}` : undefined}
                      >
                        {theme === 'light' && <Sun className={cn('h-5 w-5 mr-3', isCollapsed && 'lg:mr-0')} />}
                        {theme === 'dark' && <Moon className={cn('h-5 w-5 mr-3', isCollapsed && 'lg:mr-0')} />}
                        {theme === 'system' && <Monitor className={cn('h-5 w-5 mr-3', isCollapsed && 'lg:mr-0')} />}
                        {theme === 'modern' && <Palette className={cn('h-5 w-5 mr-3', isCollapsed && 'lg:mr-0')} />}
                        {/* Show theme text on mobile when menu is open, on desktop when not collapsed */}
                        <span className={cn(
                          "capitalize text-sm",
                          isCollapsed ? "hidden lg:hidden" : "hidden lg:inline", // Desktop: show when not collapsed
                          mobileMenuOpen && "inline lg:hidden" // Mobile: always show when menu open
                        )}>
                          Theme
                        </span>
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent 
                      align={isCollapsed ? "center" : "end"} 
                      side={isCollapsed ? "right" : "bottom"} 
                      sideOffset={isCollapsed ? 8 : 4} 
                      className="z-[60] min-w-[140px] lg:min-w-[160px]"
                    >
                      <DropdownMenuItem 
                        onClick={() => setTheme("light")} 
                        className={cn("cursor-pointer", theme === "light" && "bg-accent text-accent-foreground")}
                      >
                        <Sun className="mr-2 h-4 w-4" />
                        Light
                      </DropdownMenuItem>
                      <DropdownMenuItem 
                        onClick={() => setTheme("dark")} 
                        className={cn("cursor-pointer", theme === "dark" && "bg-accent text-accent-foreground")}
                      >
                        <Moon className="mr-2 h-4 w-4" />
                        Dark
                      </DropdownMenuItem>
                      <DropdownMenuItem 
                        onClick={() => setTheme("system")} 
                        className={cn("cursor-pointer", theme === "system" && "bg-accent text-accent-foreground")}
                      >
                        <Monitor className="mr-2 h-4 w-4" />
                        System
                      </DropdownMenuItem>
                      <DropdownMenuItem 
                        onClick={() => setTheme("modern")} 
                        className={cn("cursor-pointer", theme === "modern" && "bg-accent text-accent-foreground")}
                      >
                        <Palette className="mr-2 h-4 w-4" />
                        Modern
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              )}
            </React.Fragment>
          );
        })}
      </nav>

      {/* Footer */}
      <div className={cn(
        "border-t py-3 px-4",
        isCollapsed && "hidden lg:block lg:px-2",
        !isCollapsed && "block",
        mobileMenuOpen && "block lg:hidden" // Always show on mobile when menu is open
      )}>
        <p className="text-xs text-muted-foreground text-center">
          v1.0.0 • Built with React
        </p>
      </div>
    </div>
    </>
  );
}