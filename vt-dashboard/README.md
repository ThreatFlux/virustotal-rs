# VirusTotal Dashboard

A comprehensive React-based dashboard for analyzing VirusTotal data stored in Elasticsearch. This application provides an intuitive interface to browse, search, and analyze malware detection results with beautiful charts and detailed reports.

## Features

### 📊 Dashboard Overview
- **Statistics Cards**: Total reports, daily submissions, malicious/suspicious/clean/undetected file counts
- **Interactive Charts**: File type distribution, detection overview, and 30-day trends
- **Recent Reports Table**: Quick access to latest analysis results

### 📋 Reports Management
- **Paginated Reports List**: Browse all analysis reports with search and filtering
- **Advanced Filtering**: Filter by file type, verdict, date range, file size, and detection count
- **Quick Search**: Search by hash, filename, or file attributes

### 🔍 Detailed Analysis
- **Complete File Analysis**: View all analysis data in organized tabs
- **Detection Results**: Antivirus engine results with verdicts and signatures
- **Sandbox Analysis**: Dynamic analysis results from various sandboxes
- **Threat Intelligence**: YARA rules and crowdsourced threat data
- **File Relationships**: Related files and connections

### 🎯 Advanced Search
- **Multi-criteria Search**: Complex queries with multiple filters
- **Real-time Results**: Instant search results as you type
- **Saved Filters**: Remember frequently used search criteria

### 🎨 Modern UI/UX
- **Dark/Light Theme**: Automatic theme switching with manual override
- **Responsive Design**: Works perfectly on desktop, tablet, and mobile
- **Accessible Components**: Built with Radix UI primitives
- **Beautiful Charts**: Interactive visualizations using Recharts

## Technology Stack

- **React 19** - Modern React with latest features
- **TypeScript** - Full type safety and development experience
- **Vite** - Fast build tool and development server
- **Tailwind CSS** - Utility-first CSS framework
- **Radix UI** - Accessible component primitives
- **React Router** - Client-side routing
- **Recharts** - Beautiful React charts
- **Lucide React** - Modern icon library

## Prerequisites

- Node.js 18+ and npm
- Elasticsearch 7+ running on `localhost:9200`
- VirusTotal data indexed in the following Elasticsearch indices:
  - `vt_reports` - Main file reports
  - `vt_analysis_results` - Antivirus scan results
  - `vt_sandbox_verdicts` - Sandbox analysis results
  - `vt_crowdsourced_data` - Threat intelligence data
  - `vt_relationships` - File relationships

## Installation

1. **Clone and setup the project:**
   ```bash
   cd /path/to/virustotal-rs/vt-dashboard
   npm install
   ```

2. **Start the development server:**
   ```bash
   npm run dev
   ```

3. **Open your browser:**
   Navigate to `http://localhost:5173`

## Configuration

### Elasticsearch Connection
The dashboard connects to Elasticsearch via Vite's proxy configuration. By default, it proxies requests from `/api/elasticsearch` to `http://localhost:9200`.

To modify the Elasticsearch connection:
1. Edit `vite.config.ts`
2. Update the proxy target URL
3. Restart the development server

### Environment Variables
Create a `.env.local` file for custom configuration:
```env
VITE_ELASTICSEARCH_URL=http://your-elasticsearch:9200
```

## Data Structure

### Required Elasticsearch Mappings

The dashboard expects the following data structure in your Elasticsearch indices:

#### vt_reports
```json
{
  "report_uuid": "string",
  "sha256": "string",
  "sha1": "string",
  "md5": "string",
  "file_size": "number",
  "file_name": "string",
  "file_type": "string",
  "malicious": "number",
  "suspicious": "number",
  "harmless": "number",
  "undetected": "number",
  "created_at": "date"
}
```

#### vt_analysis_results
```json
{
  "report_uuid": "string",
  "engine_name": "string",
  "category": "string",
  "result": "string",
  "engine_version": "string",
  "created_at": "date"
}
```

#### vt_sandbox_verdicts
```json
{
  "report_uuid": "string",
  "sandbox_name": "string",
  "category": "string",
  "confidence": "number",
  "malware_classification": ["array"],
  "created_at": "date"
}
```

## Development

### Project Structure
```
src/
├── components/
│   ├── ui/              # Reusable UI components
│   ├── layout/          # Layout components (Sidebar, etc.)
│   └── dashboard/       # Dashboard-specific components
├── pages/               # Page components
├── services/            # API and data services
├── types/              # TypeScript type definitions
├── lib/                # Utility functions
└── main.tsx            # Application entry point
```

### Available Scripts
- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run preview` - Preview production build
- `npm run lint` - Run ESLint

### Adding New Features

1. **New Page**: Create in `src/pages/` and add route in `App.tsx`
2. **New Component**: Add to appropriate `components/` subdirectory
3. **New API**: Extend `services/elasticsearch.ts`
4. **New Types**: Add to `src/types/index.ts`

## Production Deployment

1. **Build the application:**
   ```bash
   npm run build
   ```

2. **Deploy the `dist/` folder** to your web server

3. **Configure reverse proxy** for Elasticsearch (recommended for production)

### Security Considerations

- **Never expose Elasticsearch directly** to the internet in production
- Use a reverse proxy with authentication
- Implement proper CORS policies
- Consider rate limiting for API endpoints

## Customization

### Themes
- Modify CSS variables in `src/index.css`
- Update color schemes for light/dark themes
- Add new theme variants in `ThemeProvider`

### Charts
- Customize chart colors in component files
- Add new chart types using Recharts
- Modify data aggregation in Elasticsearch service

### UI Components
- All components use Tailwind CSS for styling
- Extend component variants in individual component files
- Add new components following the existing patterns

## Troubleshooting

### Common Issues

**Dashboard shows no data:**
- Verify Elasticsearch is running on `localhost:9200`
- Check that the required indices exist and contain data
- Verify index mappings match expected structure

**Search not working:**
- Ensure Elasticsearch indices are searchable
- Check browser console for API errors
- Verify proxy configuration in `vite.config.ts`

**Build fails:**
- Clear node_modules and reinstall: `rm -rf node_modules package-lock.json && npm install`
- Check TypeScript errors: `npm run build`
- Verify all dependencies are properly installed

**Charts not displaying:**
- Check data format matches component expectations
- Verify Elasticsearch responses contain required fields
- Check browser console for JavaScript errors

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

## License

This project is part of the virustotal-rs ecosystem. Check the main repository for license information.

## Support

For issues and questions:
1. Check the troubleshooting section above
2. Search existing GitHub issues
3. Create a new issue with detailed information

---

Built with ❤️ using React, TypeScript, and Tailwind CSS.