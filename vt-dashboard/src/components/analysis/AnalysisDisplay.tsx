import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  FileCode,
  Package,
  Shield,
  Binary,
  FileText,
  Camera,
  Smartphone,
  Archive,
  Hash,
  FileSpreadsheet,
  Presentation,
  AlertTriangle,
  User,
  Calendar,
  Info,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';

interface AnalysisDisplayProps {
  report: any;
}

export function AnalysisDisplay({ report }: AnalysisDisplayProps) {
  const navigate = useNavigate();
  
  // PE Information Parser with enhanced visuals
  const renderPEInfo = (peInfo: any, typeTag?: string) => {
    if (!peInfo) return null;

    // Determine PE type and characteristics
    const isPacked = peInfo.packers?.length > 0;
    const hasOverlay = peInfo.overlay && peInfo.overlay.size > 0;
    const hasSignature = peInfo.signature_info ? true : false;
    const isDLL = typeTag === 'pedll';
    const isDriver = peInfo.import_list?.some((imp: any) => 
      imp.library_name?.toLowerCase().includes('ntoskrnl') || imp.library_name?.toLowerCase().includes('hal.dll')
    );
    
    // Security indicators
    const hasSuspiciousImports = peInfo.import_list?.some((imp: any) => 
      imp.imported_functions?.some((func: string) =>
        ['VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread', 'SetWindowsHookEx']
          .some(sus => func?.includes(sus))
      )
    );
    const hasAntiDebug = peInfo.import_list?.some((imp: any) =>
      imp.imported_functions?.some((func: string) =>
        ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess']
          .some(dbg => func?.includes(dbg))
      )
    );

    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Binary className="h-5 w-5 text-red-600" />
            Portable Executable Analysis
            <div className="flex gap-2 ml-auto">
              {isDLL && <Badge variant="secondary">DLL</Badge>}
              {isDriver && <Badge variant="destructive">DRIVER</Badge>}
              {isPacked && <Badge variant="destructive">PACKED</Badge>}
              {hasSignature && <Badge variant="default" className="bg-green-600">SIGNED</Badge>}
              {hasOverlay && <Badge variant="outline">OVERLAY</Badge>}
            </div>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* PE Header Information */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="text-sm font-medium text-muted-foreground">Entry Point</label>
              <p className="font-mono text-sm">0x{peInfo.entry_point?.toString(16).toUpperCase().padStart(8, '0')}</p>
            </div>
            <div>
              <label className="text-sm font-medium text-muted-foreground">Machine Type</label>
              <p className="text-sm font-medium">
                {peInfo.machine_type === 332 ? 'x86 (32-bit)' : 
                 peInfo.machine_type === 34404 ? 'x64 (64-bit)' : 
                 peInfo.machine_type === 452 ? 'ARM' :
                 peInfo.machine_type === 43620 ? 'ARM64' :
                 `Unknown (${peInfo.machine_type})`}
              </p>
            </div>
            <div>
              <label className="text-sm font-medium text-muted-foreground">Timestamp</label>
              <p className="text-sm">
                {peInfo.timestamp ? new Date(peInfo.timestamp * 1000).toLocaleString() : 'N/A'}
              </p>
            </div>
          </div>

          {/* Import Hash & Rich Header */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {peInfo.imphash && (
              <div>
                <label className="text-sm font-medium text-muted-foreground">Import Hash (ImpHash)</label>
                <button
                  onClick={() => navigate(`/search?q=${encodeURIComponent(peInfo.imphash)}`)}
                  className="font-mono text-xs break-all bg-muted/50 p-2 rounded text-left w-full text-primary hover:underline cursor-pointer transition-colors hover:bg-muted/70"
                  title={`Search for ImpHash: ${peInfo.imphash}`}
                >
                  {peInfo.imphash}
                </button>
              </div>
            )}
            {peInfo.rich_header_hash && (
              <div>
                <label className="text-sm font-medium text-muted-foreground">Rich Header Hash</label>
                <button
                  onClick={() => navigate(`/search?q=${encodeURIComponent(peInfo.rich_header_hash)}`)}
                  className="font-mono text-xs break-all bg-muted/50 p-2 rounded text-left w-full text-primary hover:underline cursor-pointer transition-colors hover:bg-muted/70"
                  title={`Search for Rich Header Hash: ${peInfo.rich_header_hash}`}
                >
                  {peInfo.rich_header_hash}
                </button>
              </div>
            )}
          </div>

          {/* Security Warnings */}
          {(hasSuspiciousImports || hasAntiDebug || isPacked) && (
            <div className="p-3 bg-red-100 dark:bg-red-900/20 rounded-lg border border-red-200 dark:border-red-800">
              <p className="text-sm font-semibold text-red-700 dark:text-red-300 mb-2">⚠️ Security Indicators</p>
              <div className="space-y-1">
                {isPacked && (
                  <p className="text-xs text-red-600 dark:text-red-400">
                    • Packed/Obfuscated: {peInfo.packers.join(', ')}
                  </p>
                )}
                {hasSuspiciousImports && (
                  <p className="text-xs text-red-600 dark:text-red-400">
                    • Contains suspicious API imports (process injection, hooking)
                  </p>
                )}
                {hasAntiDebug && (
                  <p className="text-xs text-red-600 dark:text-red-400">
                    • Contains anti-debugging techniques
                  </p>
                )}
              </div>
            </div>
          )}

          {/* Compiler/Packer Information */}
          {(peInfo.compiler_product_versions || peInfo.packers) && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {peInfo.compiler_product_versions && (
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Compiler/Linker</label>
                  <div className="mt-2 flex flex-wrap gap-1">
                    {peInfo.compiler_product_versions.map((version: string, idx: number) => (
                      <Badge key={idx} variant="outline" className="text-xs">
                        {version}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
              {peInfo.packers && peInfo.packers.length > 0 && (
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Packers/Protectors</label>
                  <div className="mt-2 flex flex-wrap gap-1">
                    {peInfo.packers.map((packer: string, idx: number) => (
                      <Badge 
                        key={idx} 
                        variant="destructive" 
                        className="text-xs cursor-pointer hover:opacity-80"
                        onClick={() => navigate(`/search?q=${encodeURIComponent(packer)}`)}
                        title={`Search for packer: ${packer}`}
                      >
                        {packer}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Exports */}
          {peInfo.exports && peInfo.exports.length > 0 && (
            <div>
              <label className="text-sm font-medium text-muted-foreground">
                Exported Functions ({peInfo.exports.length})
              </label>
              <ScrollArea className="h-32 mt-2">
                <div className="grid grid-cols-2 md:grid-cols-3 gap-1">
                  {peInfo.exports.map((exp: string, idx: number) => (
                    <div key={idx} className="font-mono text-xs p-1 hover:bg-muted rounded">
                      {exp}
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </div>
          )}

          {/* Imports */}
          {peInfo.import_list && peInfo.import_list.length > 0 && (
            <div>
              <label className="text-sm font-medium text-muted-foreground">
                Import Libraries ({peInfo.import_list.length})
                {hasSuspiciousImports && (
                  <span className="text-red-600 ml-2">⚠️ Suspicious</span>
                )}
              </label>
              <ScrollArea className="h-48 mt-2">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Library</TableHead>
                      <TableHead>Functions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {peInfo.import_list.map((imp: any, idx: number) => {
                      const isSuspicious = imp.imported_functions?.some((func: string) =>
                        ['VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread', 
                         'SetWindowsHookEx', 'IsDebuggerPresent'].some(s => func?.includes(s))
                      );
                      return (
                        <TableRow key={idx} className={isSuspicious ? 'bg-red-50 dark:bg-red-900/20' : ''}>
                          <TableCell className="font-mono text-sm">
                            {imp.library_name}
                            {isSuspicious && <span className="text-red-600 ml-2">⚠️</span>}
                          </TableCell>
                          <TableCell>
                            <Badge variant={isSuspicious ? "destructive" : "outline"} className="text-xs">
                              {imp.imported_functions?.length || 0} functions
                            </Badge>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </ScrollArea>
            </div>
          )}

          {/* Sections */}
          {peInfo.sections && peInfo.sections.length > 0 && (
            <div>
              <label className="text-sm font-medium text-muted-foreground">
                PE Sections ({peInfo.sections.length})
              </label>
              <ScrollArea className="h-48 mt-2">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Virtual Size</TableHead>
                      <TableHead>Raw Size</TableHead>
                      <TableHead>Entropy</TableHead>
                      <TableHead>MD5</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {peInfo.sections.map((section: any, idx: number) => (
                      <TableRow key={idx}>
                        <TableCell className="font-mono text-sm">{section.name}</TableCell>
                        <TableCell className="text-sm">{section.virtual_size?.toLocaleString()}</TableCell>
                        <TableCell className="text-sm">{section.raw_size?.toLocaleString()}</TableCell>
                        <TableCell className="text-sm">
                          <span className={section.entropy > 7.5 ? 'text-red-600 font-semibold' : ''}>
                            {section.entropy?.toFixed(2)}
                          </span>
                        </TableCell>
                        <TableCell className="font-mono text-[10px]">
                          {section.md5 ? `${section.md5.substring(0, 8)}...` : 'N/A'}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </ScrollArea>
            </div>
          )}

          {/* Resources */}
          {peInfo.resources && peInfo.resources.length > 0 && (
            <div>
              <label className="text-sm font-medium text-muted-foreground">
                Resources ({peInfo.resources.length})
              </label>
              <div className="mt-2 space-y-1">
                {peInfo.resources.slice(0, 5).map((res: any, idx: number) => (
                  <div key={idx} className="flex items-center justify-between p-2 bg-muted/50 rounded text-xs">
                    <span className="font-mono">{res.type || 'Unknown'}</span>
                    <span className="text-muted-foreground">{res.size ? `${(res.size / 1024).toFixed(1)} KB` : 'N/A'}</span>
                  </div>
                ))}
                {peInfo.resources.length > 5 && (
                  <p className="text-xs text-muted-foreground">...and {peInfo.resources.length - 5} more resources</p>
                )}
              </div>
            </div>
          )}

          {/* Overlay Data */}
          {hasOverlay && (
            <div className="p-3 bg-yellow-100 dark:bg-yellow-900/20 rounded-lg border border-yellow-200 dark:border-yellow-800">
              <p className="text-sm font-semibold text-yellow-700 dark:text-yellow-300">
                Overlay Data Detected
              </p>
              <p className="text-xs text-yellow-600 dark:text-yellow-400 mt-1">
                Size: {(peInfo.overlay.size / 1024).toFixed(1)} KB
                {peInfo.overlay.md5 && (
                  <span className="block mt-1 font-mono">MD5: {peInfo.overlay.md5}</span>
                )}
              </p>
            </div>
          )}

          {/* Digital Signature */}
          {peInfo.signature_info && (
            <div className="p-3 bg-green-100 dark:bg-green-900/20 rounded-lg border border-green-200 dark:border-green-800">
              <p className="text-sm font-semibold text-green-700 dark:text-green-300">
                ✓ Digitally Signed
              </p>
              {peInfo.signature_info.subject && (
                <p className="text-xs text-green-600 dark:text-green-400 mt-1">
                  Subject: {peInfo.signature_info.subject}
                </p>
              )}
              {peInfo.signature_info.issuer && (
                <p className="text-xs text-green-600 dark:text-green-400">
                  Issuer: {peInfo.signature_info.issuer}
                </p>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    );
  };

  // Helper function to check for email attachments
  const hasEmailAttachments = (officeInfo: any) => {
    if (!officeInfo.entries) return false;
    // Look for attachment entries in MSG files
    return officeInfo.entries.some((entry: any) => 
      entry.name?.includes('__attach_version') || 
      entry.name?.includes('__substg1.0_37')
    );
  };

  // Office Document Helper Functions
  const getOfficeIcon = (officeInfo: any, typeTag?: string) => {
    // Check if this is an email file
    if (typeTag === 'outlook' || typeTag === 'eml') {
      return <span className="text-2xl">📧</span>;
    }
    
    // Determine document type from CLSID or other indicators
    const rootEntry = officeInfo.entries?.find((entry: any) => entry.name === 'Root Entry');
    const clsid = rootEntry?.clsid_literal;
    
    if (clsid?.includes('PowerPoint') || officeInfo.document_summary_info?.slide_count !== undefined) {
      return <Presentation className="h-5 w-5 text-orange-500" />;
    } else if (clsid?.includes('Excel') || officeInfo.entries?.some((e: any) => e.name === 'Workbook')) {
      return <FileSpreadsheet className="h-5 w-5 text-green-500" />;
    } else if (clsid?.includes('Word') || officeInfo.entries?.some((e: any) => e.name?.includes('Word'))) {
      return <FileText className="h-5 w-5 text-blue-500" />;
    }
    return <FileText className="h-5 w-5" />;
  };

  const getOfficeTypeName = (officeInfo: any) => {
    const rootEntry = officeInfo.entries?.find((entry: any) => entry.name === 'Root Entry');
    const clsid = rootEntry?.clsid_literal;
    
    if (clsid?.includes('PowerPoint') || officeInfo.document_summary_info?.slide_count !== undefined) {
      return 'PowerPoint Presentation';
    } else if (clsid?.includes('Excel') || officeInfo.entries?.some((e: any) => e.name === 'Workbook')) {
      return 'Excel Spreadsheet';
    } else if (clsid?.includes('Word') || officeInfo.entries?.some((e: any) => e.name?.includes('Word'))) {
      return 'Word Document';
    }
    return 'Office Document';
  };

  const hasSecurityConcerns = (officeInfo: any) => {
    return (
      (officeInfo.macros && officeInfo.macros.length > 0) ||
      officeInfo.entries?.some((entry: any) => 
        entry.name?.includes('VBA') || 
        entry.name?.includes('Macro') ||
        entry.clsid_literal?.includes('VBA')
      )
    );
  };

  // Office Information Parser
  const renderOfficeInfo = (officeInfo: any, typeTag?: string) => {
    if (!officeInfo) return null;

    const [isExpanded, setIsExpanded] = React.useState(false);
    const isEmail = typeTag === 'outlook' || typeTag === 'eml';
    const documentType = isEmail ? 'Email Message' : getOfficeTypeName(officeInfo);
    const hasSecurity = hasSecurityConcerns(officeInfo) || (isEmail && hasEmailAttachments(officeInfo));

    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            {getOfficeIcon(officeInfo, typeTag)}
            <span>{documentType} Analysis</span>
            {hasSecurity && (
              <Badge variant="destructive" className="ml-auto">
                <AlertTriangle className="h-3 w-3 mr-1" />
                Security Alert
              </Badge>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Document Metadata */}
          {officeInfo.summary_info && (
            <div className="space-y-3">
              <h4 className="text-sm font-semibold flex items-center gap-2">
                <Info className="h-4 w-4" />
                Document Metadata
              </h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {officeInfo.summary_info.title && (
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">Title</label>
                    <button
                      onClick={() => navigate(`/search?q=${encodeURIComponent(officeInfo.summary_info.title)}`)}
                      className="text-sm font-medium text-primary hover:underline cursor-pointer text-left block"
                      title={`Search for: ${officeInfo.summary_info.title}`}
                    >
                      {officeInfo.summary_info.title}
                    </button>
                  </div>
                )}
                {officeInfo.summary_info.subject && (
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">Subject</label>
                    <button
                      onClick={() => navigate(`/search?q=${encodeURIComponent(officeInfo.summary_info.subject)}`)}
                      className="text-sm text-primary hover:underline cursor-pointer text-left block"
                      title={`Search for: ${officeInfo.summary_info.subject}`}
                    >
                      {officeInfo.summary_info.subject}
                    </button>
                  </div>
                )}
                {officeInfo.summary_info.author && (
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">Author</label>
                    <button
                      onClick={() => navigate(`/search?q=${encodeURIComponent(officeInfo.summary_info.author)}`)}
                      className="text-sm flex items-center gap-1 text-primary hover:underline cursor-pointer"
                      title={`Search for author: ${officeInfo.summary_info.author}`}
                    >
                      <User className="h-3 w-3" />
                      {officeInfo.summary_info.author}
                    </button>
                  </div>
                )}
                {officeInfo.summary_info.last_author && officeInfo.summary_info.last_author !== officeInfo.summary_info.author && (
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">Last Author</label>
                    <button
                      onClick={() => navigate(`/search?q=${encodeURIComponent(officeInfo.summary_info.last_author)}`)}
                      className="text-sm flex items-center gap-1 text-primary hover:underline cursor-pointer"
                      title={`Search for author: ${officeInfo.summary_info.last_author}`}
                    >
                      <User className="h-3 w-3" />
                      {officeInfo.summary_info.last_author}
                    </button>
                  </div>
                )}
                {officeInfo.summary_info.creation_datetime && (
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">Created</label>
                    <p className="text-sm flex items-center gap-1">
                      <Calendar className="h-3 w-3" />
                      {new Date(officeInfo.summary_info.creation_datetime).toLocaleString()}
                    </p>
                  </div>
                )}
                {officeInfo.summary_info.last_saved && (
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">Last Saved</label>
                    <p className="text-sm flex items-center gap-1">
                      <Calendar className="h-3 w-3" />
                      {new Date(officeInfo.summary_info.last_saved).toLocaleString()}
                    </p>
                  </div>
                )}
                {officeInfo.summary_info.application_name && (
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">Application</label>
                    <button
                      onClick={() => navigate(`/search?q=${encodeURIComponent(officeInfo.summary_info.application_name)}`)}
                      className="text-sm text-primary hover:underline cursor-pointer text-left block"
                      title={`Search for application: ${officeInfo.summary_info.application_name}`}
                    >
                      {officeInfo.summary_info.application_name}
                    </button>
                  </div>
                )}
                {officeInfo.summary_info.revision_number && (
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">Revision</label>
                    <p className="text-sm">{officeInfo.summary_info.revision_number}</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Document Summary Stats */}
          {officeInfo.document_summary_info && (
            <div className="space-y-3">
              <h4 className="text-sm font-semibold">Document Statistics</h4>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {officeInfo.document_summary_info.slide_count !== undefined && (
                  <div className="text-center p-3 bg-muted/50 rounded-lg">
                    <div className="text-2xl font-bold text-orange-500">{officeInfo.document_summary_info.slide_count}</div>
                    <div className="text-xs text-muted-foreground">Slides</div>
                  </div>
                )}
                {officeInfo.document_summary_info.paragraph_count !== undefined && (
                  <div className="text-center p-3 bg-muted/50 rounded-lg">
                    <div className="text-2xl font-bold text-blue-500">{officeInfo.document_summary_info.paragraph_count}</div>
                    <div className="text-xs text-muted-foreground">Paragraphs</div>
                  </div>
                )}
                {officeInfo.summary_info?.word_count !== undefined && (
                  <div className="text-center p-3 bg-muted/50 rounded-lg">
                    <div className="text-2xl font-bold text-green-500">{officeInfo.summary_info.word_count}</div>
                    <div className="text-xs text-muted-foreground">Words</div>
                  </div>
                )}
                {officeInfo.document_summary_info.note_count !== undefined && (
                  <div className="text-center p-3 bg-muted/50 rounded-lg">
                    <div className="text-2xl font-bold text-purple-500">{officeInfo.document_summary_info.note_count}</div>
                    <div className="text-xs text-muted-foreground">Notes</div>
                  </div>
                )}
              </div>
              
              {/* Additional format info */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
                {officeInfo.document_summary_info.byte_count !== undefined && (
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">Document Size</label>
                    <p className="text-sm">{(officeInfo.document_summary_info.byte_count / 1024).toFixed(1)} KB</p>
                  </div>
                )}
                {officeInfo.document_summary_info.presentation_format && (
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">Format</label>
                    <p className="text-sm">{officeInfo.document_summary_info.presentation_format}</p>
                  </div>
                )}
                {officeInfo.document_summary_info.code_page && (
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">Code Page</label>
                    <p className="text-sm">{officeInfo.document_summary_info.code_page}</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Security Concerns Section */}
          {hasSecurity && (
            <div className="p-4 bg-gray-100 dark:bg-gray-800 rounded-lg border border-red-200 dark:border-red-800">
              <h4 className="text-sm font-semibold text-red-800 dark:text-red-200 flex items-center gap-2 mb-3">
                <AlertTriangle className="h-4 w-4" />
                Security Concerns Detected
              </h4>
              
              {/* VBA Macros */}
              {officeInfo.macros && officeInfo.macros.length > 0 && (
                <div className="space-y-2">
                  <p className="text-sm text-red-700 dark:text-red-300 font-medium">
                    VBA Macros Found ({officeInfo.macros.length})
                  </p>
                  <ScrollArea className="h-32">
                    <div className="space-y-1">
                      {officeInfo.macros.map((macro: any, idx: number) => (
                        <div key={idx} className="p-2 bg-gray-200 dark:bg-gray-700 rounded text-sm">
                          <span className="font-mono">{macro.name || `Macro ${idx + 1}`}</span>
                          {macro.code_size && (
                            <span className="text-xs text-red-600 dark:text-red-400 ml-2">({macro.code_size} bytes)</span>
                          )}
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </div>
              )}
              
              {/* VBA-related OLE entries */}
              {officeInfo.entries?.some((entry: any) => entry.name?.includes('VBA') || entry.name?.includes('Macro')) && (
                <div className="mt-3">
                  <p className="text-sm text-red-700 dark:text-red-300 font-medium">VBA/Macro OLE Entries Found</p>
                  <div className="mt-1 space-y-1">
                    {officeInfo.entries
                      .filter((entry: any) => entry.name?.includes('VBA') || entry.name?.includes('Macro'))
                      .map((entry: any, idx: number) => (
                        <div key={idx} className="text-xs font-mono p-1 bg-gray-200 dark:bg-gray-700 rounded">
                          {entry.name}
                        </div>
                      ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* OLE Entries - Collapsible */}
          {officeInfo.entries && officeInfo.entries.length > 0 && (
            <div>
              <button 
                onClick={() => setIsExpanded(!isExpanded)}
                className="flex items-center gap-2 text-sm font-semibold hover:text-primary transition-colors"
              >
                {isExpanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                OLE Structure ({officeInfo.entries.length} entries)
              </button>
              {isExpanded && (
                <div className="mt-3">
                  <ScrollArea className="h-64">
                    <div className="space-y-2">
                      {officeInfo.entries.map((entry: any, idx: number) => (
                        <div key={idx} className="flex items-center justify-between p-3 bg-muted/50 rounded border">
                          <div className="flex-1">
                            <p className="text-sm font-mono font-medium">{entry.name || 'Unnamed'}</p>
                            <div className="flex items-center gap-4 mt-1">
                              {entry.clsid_literal && (
                                <p className="text-xs text-muted-foreground">{entry.clsid_literal}</p>
                              )}
                              {entry.sid !== undefined && (
                                <p className="text-xs text-muted-foreground">SID: {entry.sid}</p>
                              )}
                            </div>
                          </div>
                          <div className="text-right flex flex-col gap-1">
                            {entry.type_literal && (
                              <Badge variant={entry.type_literal === 'stream' ? 'default' : 'outline'} className="text-xs">
                                {entry.type_literal}
                              </Badge>
                            )}
                            {entry.size !== undefined && entry.size > 0 && (
                              <p className="text-xs text-muted-foreground">{(entry.size / 1024).toFixed(1)} KB</p>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    );
  };

  const renderPDFInfo = (pdfInfo: any) => {
    if (!pdfInfo) return null;

    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            PDF Document Analysis
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Basic PDF Statistics */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {pdfInfo.num_pages !== undefined && (
              <div>
                <label className="text-sm font-medium text-muted-foreground">Pages</label>
                <p className="text-sm font-semibold">{pdfInfo.num_pages}</p>
              </div>
            )}
            {pdfInfo.num_objects !== undefined && (
              <div>
                <label className="text-sm font-medium text-muted-foreground">Objects</label>
                <p className="text-sm font-semibold">{pdfInfo.num_objects}</p>
              </div>
            )}
            {pdfInfo.num_streams !== undefined && (
              <div>
                <label className="text-sm font-medium text-muted-foreground">Streams</label>
                <p className="text-sm font-semibold">{pdfInfo.num_streams}</p>
              </div>
            )}
            {pdfInfo.num_endstream !== undefined && (
              <div>
                <label className="text-sm font-medium text-muted-foreground">End Streams</label>
                <p className="text-sm font-semibold">{pdfInfo.num_endstream}</p>
              </div>
            )}
            {pdfInfo.num_obj !== undefined && (
              <div>
                <label className="text-sm font-medium text-muted-foreground">Obj Definitions</label>
                <p className="text-sm font-semibold">{pdfInfo.num_obj}</p>
              </div>
            )}
            {pdfInfo.num_endobj !== undefined && (
              <div>
                <label className="text-sm font-medium text-muted-foreground">End Obj</label>
                <p className="text-sm font-semibold">{pdfInfo.num_endobj}</p>
              </div>
            )}
          </div>

          {/* Suspicious Elements */}
          {(pdfInfo.num_js > 0 || pdfInfo.num_launch > 0 || pdfInfo.num_jbig2decode > 0) && (
            <div className="p-3 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg space-y-2">
              <h4 className="text-sm font-semibold text-yellow-800 dark:text-yellow-200">Suspicious Elements Detected</h4>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {pdfInfo.num_js > 0 && (
                  <div className="flex items-center gap-2">
                    <Badge variant="destructive">JavaScript</Badge>
                    <span className="text-sm">{pdfInfo.num_js} script(s)</span>
                  </div>
                )}
                {pdfInfo.num_launch > 0 && (
                  <div className="flex items-center gap-2">
                    <Badge variant="destructive">Launch Action</Badge>
                    <span className="text-sm">{pdfInfo.num_launch}</span>
                  </div>
                )}
                {pdfInfo.num_jbig2decode > 0 && (
                  <div className="flex items-center gap-2">
                    <Badge variant="destructive">JBIG2Decode</Badge>
                    <span className="text-sm">{pdfInfo.num_jbig2decode}</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* PDF Header */}
          {pdfInfo.header && (
            <div>
              <label className="text-sm font-medium text-muted-foreground">PDF Version</label>
              <p className="text-sm font-mono bg-muted p-2 rounded">{pdfInfo.header}</p>
            </div>
          )}

          {/* JavaScript Content */}
          {pdfInfo.js && pdfInfo.js.length > 0 && (
            <div>
              <label className="text-sm font-medium text-muted-foreground">JavaScript Code</label>
              <ScrollArea className="h-32 mt-2">
                <pre className="text-xs bg-muted p-2 rounded">{pdfInfo.js.join('\n')}</pre>
              </ScrollArea>
            </div>
          )}
        </CardContent>
      </Card>
    );
  };

  // Android/Androguard Parser
  const renderAndroidInfo = (androidInfo: any) => {
    if (!androidInfo) return null;

    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Smartphone className="h-5 w-5" />
            Android Analysis
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {androidInfo.package_name && (
            <div>
              <label className="text-sm font-medium text-muted-foreground">Package Name</label>
              <p className="font-mono text-sm">{androidInfo.package_name}</p>
            </div>
          )}

          {androidInfo.main_activity && (
            <div>
              <label className="text-sm font-medium text-muted-foreground">Main Activity</label>
              <p className="font-mono text-sm">{androidInfo.main_activity}</p>
            </div>
          )}

          {/* Permissions */}
          {androidInfo.permissions && androidInfo.permissions.length > 0 && (
            <div>
              <label className="text-sm font-medium text-muted-foreground">Permissions ({androidInfo.permissions.length})</label>
              <ScrollArea className="h-32 mt-2">
                <div className="space-y-1">
                  {androidInfo.permissions.map((perm: string, idx: number) => (
                    <Badge key={idx} variant={perm.includes('DANGEROUS') ? 'destructive' : 'outline'} className="text-xs mr-2 mb-1">
                      {perm}
                    </Badge>
                  ))}
                </div>
              </ScrollArea>
            </div>
          )}

          {/* Activities */}
          {androidInfo.activities && androidInfo.activities.length > 0 && (
            <div>
              <label className="text-sm font-medium text-muted-foreground">Activities</label>
              <ScrollArea className="h-32 mt-2">
                <div className="space-y-1">
                  {androidInfo.activities.map((activity: string, idx: number) => (
                    <div key={idx} className="font-mono text-xs p-1 hover:bg-muted rounded">
                      {activity}
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </div>
          )}
        </CardContent>
      </Card>
    );
  };

  // EXIF Data Parser
  const renderExifData = (exifData: any, typeTag?: string) => {
    if (!exifData) return null;

    // Check if this is an image file
    const isImage = ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'ico'].includes(typeTag || '') ||
                    ['PNG', 'JPEG', 'GIF', 'BMP', 'WebP'].includes(exifData.FileType || '');

    // Categorize EXIF fields for better organization
    const categorizeExifData = () => {
      const categories: Record<string, Record<string, any>> = {
        'Image Properties': {},
        'Camera Settings': {},
        'GPS Location': {},
        'File Information': {},
        'Other Metadata': {}
      };

      Object.entries(exifData).forEach(([key, value]) => {
        // Image properties
        if (['ImageWidth', 'ImageHeight', 'ImageSize', 'BitDepth', 'ColorType', 
             'ColorSpace', 'Compression', 'Resolution', 'Megapixels', 'AspectRatio',
             'Orientation', 'XResolution', 'YResolution', 'ResolutionUnit'].includes(key)) {
          categories['Image Properties'][key] = value;
        }
        // Camera settings
        else if (['Make', 'Model', 'LensModel', 'FNumber', 'ExposureTime', 'ISO', 
                  'FocalLength', 'Flash', 'WhiteBalance', 'DateTimeOriginal', 
                  'CreateDate', 'ModifyDate', 'ShutterSpeed', 'Aperture'].includes(key)) {
          categories['Camera Settings'][key] = value;
        }
        // GPS data
        else if (key.startsWith('GPS')) {
          categories['GPS Location'][key] = value;
        }
        // File info
        else if (['FileType', 'FileTypeExtension', 'MIMEType', 'FileSize', 
                  'FileModifyDate', 'FileAccessDate', 'FileCreateDate'].includes(key)) {
          categories['File Information'][key] = value;
        }
        // Other
        else {
          categories['Other Metadata'][key] = value;
        }
      });

      // Remove empty categories
      Object.keys(categories).forEach(cat => {
        if (Object.keys(categories[cat]).length === 0) {
          delete categories[cat];
        }
      });

      return categories;
    };

    const categorizedData = categorizeExifData();

    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Camera className="h-5 w-5" />
            {isImage ? 'Image Metadata' : 'EXIF Metadata'}
            {isImage && exifData.FileType && (
              <Badge variant="secondary">{exifData.FileType}</Badge>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Image Preview Section for image files */}
          {isImage && exifData.ImageSize && (
            <div className="bg-muted/50 p-4 rounded-lg">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                {exifData.ImageSize && (
                  <div>
                    <label className="text-xs font-medium text-muted-foreground">Dimensions</label>
                    <p className="font-semibold">{exifData.ImageSize}</p>
                  </div>
                )}
                {exifData.Megapixels && (
                  <div>
                    <label className="text-xs font-medium text-muted-foreground">Resolution</label>
                    <p className="font-semibold">{exifData.Megapixels} MP</p>
                  </div>
                )}
                {exifData.BitDepth && (
                  <div>
                    <label className="text-xs font-medium text-muted-foreground">Bit Depth</label>
                    <p className="font-semibold">{exifData.BitDepth} bit</p>
                  </div>
                )}
                {exifData.ColorType && (
                  <div>
                    <label className="text-xs font-medium text-muted-foreground">Color Type</label>
                    <p className="font-semibold">{exifData.ColorType}</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Camera Information if available */}
          {categorizedData['Camera Settings'] && Object.keys(categorizedData['Camera Settings']).length > 0 && (
            <div className="space-y-2">
              <h4 className="text-sm font-semibold flex items-center gap-2">
                <Camera className="h-4 w-4" />
                Camera Information
              </h4>
              <div className="bg-muted/30 p-3 rounded grid grid-cols-2 gap-2 text-sm">
                {categorizedData['Camera Settings'].Make && (
                  <div>
                    <span className="text-muted-foreground">Make:</span>{' '}
                    <button
                      onClick={() => navigate(`/search?q=${encodeURIComponent(categorizedData['Camera Settings'].Make)}`)}
                      className="text-primary hover:underline cursor-pointer"
                      title={`Search for: ${categorizedData['Camera Settings'].Make}`}
                    >
                      {categorizedData['Camera Settings'].Make}
                    </button>
                  </div>
                )}
                {categorizedData['Camera Settings'].Model && (
                  <div>
                    <span className="text-muted-foreground">Model:</span>{' '}
                    <button
                      onClick={() => navigate(`/search?q=${encodeURIComponent(categorizedData['Camera Settings'].Model)}`)}
                      className="text-primary hover:underline cursor-pointer"
                      title={`Search for: ${categorizedData['Camera Settings'].Model}`}
                    >
                      {categorizedData['Camera Settings'].Model}
                    </button>
                  </div>
                )}
                {categorizedData['Camera Settings'].DateTimeOriginal && (
                  <div className="col-span-2">
                    <span className="text-muted-foreground">Taken:</span> {categorizedData['Camera Settings'].DateTimeOriginal}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* GPS Warning if location data exists */}
          {categorizedData['GPS Location'] && Object.keys(categorizedData['GPS Location']).length > 0 && (
            <div className="p-3 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg">
              <div className="flex items-center gap-2 text-yellow-800 dark:text-yellow-200">
                <AlertTriangle className="h-4 w-4" />
                <span className="font-semibold text-sm">GPS Location Data Detected</span>
              </div>
              <p className="text-xs mt-1 text-yellow-700 dark:text-yellow-300">
                This image contains geographical location information
              </p>
            </div>
          )}

          {/* Detailed Metadata Table */}
          <div className="space-y-4">
            {Object.entries(categorizedData).map(([category, fields]) => (
              <div key={category} className="space-y-2">
                <h4 className="text-sm font-semibold text-muted-foreground">{category}</h4>
                <div className="border rounded">
                  <Table>
                    <TableBody>
                      {Object.entries(fields).map(([key, value], idx) => {
                        // Determine if this field should be searchable
                        const isSearchable = ['Make', 'Model', 'LensModel', 'Software', 'Creator', 
                                            'Author', 'Copyright', 'Artist', 'Title', 'Subject',
                                            'Keywords', 'Comment', 'UserComment', 'ImageDescription',
                                            'DocumentName', 'OwnerName', 'CameraOwnerName'].includes(key) ||
                                           (typeof value === 'string' && value.length > 3 && value.length < 100);
                        
                        return (
                          <TableRow key={idx}>
                            <TableCell className="font-medium text-sm py-2">
                              {key.replace(/([A-Z])/g, ' $1').trim()}
                            </TableCell>
                            <TableCell className="text-sm py-2 font-mono">
                              {isSearchable ? (
                                <button
                                  onClick={() => navigate(`/search?q=${encodeURIComponent(String(value))}`)}
                                  className="text-primary hover:underline cursor-pointer text-left"
                                  title={`Search for: ${value}`}
                                >
                                  {String(value)}
                                </button>
                              ) : (
                                String(value)
                              )}
                            </TableCell>
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    );
  };

  // TrID Analysis Parser
  const renderTrIDAnalysis = (trid: any) => {
    if (!trid || !Array.isArray(trid)) return null;

    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileCode className="h-5 w-5" />
            TrID File Type Analysis
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>File Type</TableHead>
                <TableHead>Extension</TableHead>
                <TableHead>Probability</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {trid.map((item: any, idx: number) => (
                <TableRow key={idx}>
                  <TableCell className="text-sm">{item.file_type}</TableCell>
                  <TableCell className="font-mono text-sm">{item.extension || 'N/A'}</TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <div className="w-20 bg-muted rounded-full h-2">
                        <div 
                          className="bg-primary h-2 rounded-full" 
                          style={{ width: `${item.probability}%` }}
                        />
                      </div>
                      <span className="text-sm">{item.probability}%</span>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    );
  };

  // Bundle Info Parser - Enhanced for Office Open XML
  const renderBundleInfo = (bundleInfo: any, typeTag?: string) => {
    if (!bundleInfo) return null;

    // Check if this is an Office Open XML file
    const isOfficeOpenXML = ['xlsx', 'docx', 'pptx'].includes(typeTag || '');
    const bundleType = bundleInfo.type?.toUpperCase();
    
    // Determine icon and title based on type
    let icon = <Archive className="h-5 w-5" />;
    let title = 'Bundle Information';
    let iconColor = 'text-gray-600';
    
    if (isOfficeOpenXML || ['XLSX', 'DOCX', 'PPTX'].includes(bundleType || '')) {
      title = 'Office Open XML Structure';
      if (bundleType === 'XLSX' || typeTag === 'xlsx') {
        icon = <FileSpreadsheet className="h-5 w-5 text-green-600" />;
        iconColor = 'text-green-600';
      } else if (bundleType === 'DOCX' || typeTag === 'docx') {
        icon = <FileText className="h-5 w-5 text-blue-600" />;
        iconColor = 'text-blue-600';
      } else if (bundleType === 'PPTX' || typeTag === 'pptx') {
        icon = <Presentation className="h-5 w-5 text-orange-600" />;
        iconColor = 'text-orange-600';
      }
    }

    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            {icon}
            {title}
            {isOfficeOpenXML && (
              <Badge variant="secondary" className="ml-2">XML-based</Badge>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Office Open XML Type Badge */}
          {bundleType && ['XLSX', 'DOCX', 'PPTX'].includes(bundleType) && (
            <div className="flex items-center gap-2">
              <Badge className={`${
                bundleType === 'XLSX' ? 'bg-green-100 text-green-800' :
                bundleType === 'DOCX' ? 'bg-blue-100 text-blue-800' :
                'bg-orange-100 text-orange-800'
              }`}>
                {bundleType === 'XLSX' ? 'Excel 2007+' :
                 bundleType === 'DOCX' ? 'Word 2007+' :
                 'PowerPoint 2007+'}
              </Badge>
              <span className="text-sm text-muted-foreground">Office Open XML Format</span>
            </div>
          )}

          {/* Bundle Statistics */}
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            {bundleInfo.num_children !== undefined && (
              <div className="bg-muted/50 p-2 rounded">
                <label className="text-xs font-medium text-muted-foreground">Components</label>
                <p className="text-lg font-semibold">{bundleInfo.num_children}</p>
              </div>
            )}
            {bundleInfo.num_files !== undefined && (
              <div className="bg-muted/50 p-2 rounded">
                <label className="text-xs font-medium text-muted-foreground">Files</label>
                <p className="text-lg font-semibold">{bundleInfo.num_files}</p>
              </div>
            )}
            {bundleInfo.uncompressed_size !== undefined && (
              <div className="bg-muted/50 p-2 rounded">
                <label className="text-xs font-medium text-muted-foreground">Uncompressed</label>
                <p className="text-lg font-semibold">
                  {(bundleInfo.uncompressed_size / 1024).toFixed(1)} KB
                </p>
              </div>
            )}
          </div>

          {/* File Extensions for XML files */}
          {bundleInfo.extensions && Object.keys(bundleInfo.extensions).length > 0 && (
            <div>
              <label className="text-sm font-medium text-muted-foreground">
                {isOfficeOpenXML ? 'XML Components' : 'File Extensions'}
              </label>
              <div className="mt-2 flex flex-wrap gap-2">
                {Object.entries(bundleInfo.extensions).map(([ext, count], idx) => (
                  <Badge 
                    key={idx} 
                    variant={ext === 'xml' ? 'default' : 'outline'}
                    className="text-xs"
                  >
                    .{ext} ({String(count)})
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {/* File Types */}
          {bundleInfo.file_types && Object.keys(bundleInfo.file_types).length > 0 && (
            <div>
              <label className="text-sm font-medium text-muted-foreground">
                {isOfficeOpenXML ? 'Content Types' : 'File Types'}
              </label>
              <div className="mt-2 space-y-1">
                {Object.entries(bundleInfo.file_types).map(([type, count], idx) => (
                  <div key={idx} className="flex items-center justify-between p-1">
                    <span className="text-sm">
                      {type === 'XML' && isOfficeOpenXML ? (
                        <span className="flex items-center gap-1">
                          <FileCode className="h-3 w-3" />
                          XML Documents
                        </span>
                      ) : type}
                    </span>
                    <Badge variant="outline" className="text-xs">{String(count)}</Badge>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Date Information */}
          {(bundleInfo.lowest_datetime || bundleInfo.highest_datetime) && (
            <div className="text-sm space-y-1">
              {bundleInfo.lowest_datetime && bundleInfo.lowest_datetime !== '1980-01-01 00:00:00' && (
                <div className="flex items-center gap-2">
                  <Calendar className="h-3 w-3 text-muted-foreground" />
                  <span className="text-muted-foreground">Created:</span>
                  <span>{bundleInfo.lowest_datetime}</span>
                </div>
              )}
              {bundleInfo.highest_datetime && bundleInfo.highest_datetime !== '1980-01-01 00:00:00' && (
                <div className="flex items-center gap-2">
                  <Calendar className="h-3 w-3 text-muted-foreground" />
                  <span className="text-muted-foreground">Modified:</span>
                  <span>{bundleInfo.highest_datetime}</span>
                </div>
              )}
            </div>
          )}

          {/* Contained Files */}
          {bundleInfo.contained_files && bundleInfo.contained_files.length > 0 && (
            <div>
              <label className="text-sm font-medium text-muted-foreground">
                {isOfficeOpenXML ? 'Document Components' : 'Contained Files'}
              </label>
              <ScrollArea className="h-48 mt-2">
                <div className="space-y-1">
                  {bundleInfo.contained_files.map((file: any, idx: number) => (
                    <div key={idx} className="p-2 border rounded text-sm">
                      <div className="font-mono break-all text-xs">
                        {file.name || file.path}
                      </div>
                      {file.sha256 && (
                        <div className="text-xs text-muted-foreground mt-1">
                          SHA256: {file.sha256.substring(0, 16)}...
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </div>
          )}
        </CardContent>
      </Card>
    );
  };

  // Detect It Easy Parser
  const renderDetectItEasy = (detectiteasy: any) => {
    if (!detectiteasy || !detectiteasy.values) return null;

    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Detect It Easy Analysis
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {detectiteasy.values.map((item: any, idx: number) => (
              <div key={idx} className="flex items-center justify-between p-2 border rounded">
                <div>
                  <div className="font-medium text-sm">{item.name}</div>
                  {item.version && (
                    <div className="text-xs text-muted-foreground">Version: {item.version}</div>
                  )}
                </div>
                <Badge variant="outline" className="text-xs">
                  {item.type || 'Detection'}
                </Badge>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    );
  };

  const hasAnalysisData = report.pe_info || report.pdf_info || report.office_info ||
                          report.androguard || report.bundle_info || report.exiftool || 
                          report.trid || report.detectiteasy;

  if (!hasAnalysisData) {
    return (
      <div className="text-center text-muted-foreground py-8">
        No special analysis data available for this file
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {renderPEInfo(report.pe_info, report.type_tag)}
      {renderOfficeInfo(report.office_info, report.type_tag)}
      {renderPDFInfo(report.pdf_info)}
      {renderAndroidInfo(report.androguard)}
      {renderBundleInfo(report.bundle_info, report.type_tag)}
      {renderExifData(report.exiftool, report.type_tag)}
      {renderTrIDAnalysis(report.trid)}
      {renderDetectItEasy(report.detectiteasy)}
    </div>
  );
}