# VirusTotal Dashboard - Testing Documentation

## Overview

This document describes the comprehensive testing setup for the VirusTotal Dashboard React application. The testing strategy covers unit tests, component tests, integration tests, and end-to-end tests to ensure high code quality and reliability.

## Testing Framework Stack

### Core Testing Technologies
- **Vitest**: Modern, fast unit testing framework optimized for Vite projects
- **React Testing Library**: Component testing focused on user interactions
- **MSW (Mock Service Worker)**: API mocking for realistic data scenarios
- **Playwright**: End-to-end browser testing
- **@vitest/coverage-v8**: Code coverage reporting

### Testing Utilities
- **jsdom/happy-dom**: DOM simulation for unit tests
- **@testing-library/user-event**: User interaction simulation
- **@testing-library/jest-dom**: Extended Jest matchers for DOM assertions

## Project Structure

```
src/
├── __tests__/                    # Integration tests
│   └── integration.test.tsx
├── test/                         # Test utilities and configuration
│   ├── utils/
│   │   ├── test-utils.tsx        # Custom render functions and helpers
│   │   └── mock-server.ts        # MSW mock server setup
│   ├── fixtures/
│   │   └── mock-data.ts          # Test data fixtures for all entities
│   └── mocks/
├── services/__tests__/           # Service layer unit tests
│   └── elasticsearch.test.ts    # Elasticsearch service tests (98.4% coverage)
├── components/
│   ├── ui/__tests__/            # UI component tests
│   │   ├── button.test.tsx
│   │   ├── card.test.tsx
│   │   ├── table.test.tsx
│   │   └── badge.test.tsx
│   └── dashboard/__tests__/     # Dashboard component tests
│       ├── StatsCard.test.tsx
│       ├── FileTypeChart.test.tsx
│       └── TrendChart.test.tsx
└── pages/__tests__/             # Page-level component tests
    └── Dashboard.test.tsx
e2e/                             # Playwright E2E tests
└── dashboard.spec.ts
```

## Test Categories

### 1. Unit Tests (Service Layer)
**Location**: `src/services/__tests__/elasticsearch.test.ts`

Tests the core Elasticsearch integration service with comprehensive coverage:

- ✅ **API Request/Response Handling**: All CRUD operations
- ✅ **Error Handling**: Network failures, API errors, malformed responses
- ✅ **Query Building**: Search filters, pagination, aggregations  
- ✅ **Data Transformation**: Response mapping, type validation
- ✅ **Dashboard Statistics**: Aggregation queries, trend calculations

**Coverage**: 98.4% (exceeds 80% target)

### 2. Component Tests (UI Layer)

#### UI Components (`src/components/ui/__tests__/`)
- **Button**: Variants, states, accessibility, interactions
- **Card**: Layout, composition, semantic structure
- **Table**: Data display, sorting, responsive behavior
- **Badge**: Status indication, color variants, accessibility

#### Dashboard Components (`src/components/dashboard/__tests__/`)
- **StatsCard**: Data formatting, variants, VirusTotal contexts
- **FileTypeChart**: Chart rendering, data visualization, responsive design
- **TrendChart**: Time series data, interactive tooltips

### 3. Page Tests (`src/pages/__tests__/`)
- **Dashboard**: Data loading, error states, component integration
- Loading state management
- API error handling
- Theme consistency

### 4. Integration Tests (`src/__tests__/integration.test.tsx`)
- **Data Flow**: End-to-end data from Elasticsearch to UI components
- **Component Interaction**: Parent-child component communication
- **Theme Integration**: Consistent styling across components
- **Error Recovery**: Graceful degradation during failures
- **Performance**: Load times and responsiveness

### 5. End-to-End Tests (`e2e/dashboard.spec.ts`)
- **User Workflows**: Complete dashboard usage scenarios
- **Cross-browser Testing**: Chrome, Firefox, Safari, Mobile
- **Performance Validation**: Load time requirements
- **Accessibility**: Keyboard navigation, screen readers
- **Responsive Design**: Multiple viewport sizes

## Mock Data Strategy

### Comprehensive Test Fixtures (`src/test/fixtures/mock-data.ts`)

Realistic test data covering all VirusTotal entities:

- **Reports**: 369 mock reports with varied file types and verdicts
- **Analysis Results**: 28,474 mock engine results across multiple categories
- **Sandbox Verdicts**: 229 mock sandbox analysis results  
- **Crowdsourced Data**: 158 mock YARA rules and community data
- **Relationships**: File relationship mapping
- **Dashboard Stats**: Aggregated statistics for visualization

### Mock Server Setup (`src/test/utils/mock-server.ts`)

MSW handles all Elasticsearch API endpoints:

- Smart query routing based on request structure
- Proper aggregation response simulation
- Error scenario simulation
- Realistic response times and data volumes

## Test Scripts

```bash
# Run all tests
npm run test

# Run tests with UI
npm run test:ui

# Run tests once (CI mode)
npm run test:run

# Generate coverage report
npm run test:coverage

# Run only unit tests
npm run test:unit

# Run only integration tests  
npm run test:integration

# Run E2E tests
npm run test:e2e

# Run E2E tests with UI
npm run test:e2e:ui

# Watch mode for development
npm run test:watch
```

## Coverage Requirements

- **Overall Target**: >80% code coverage
- **Critical Services**: >90% coverage (elasticsearch.ts: 98.4%)
- **Component Coverage**: Comprehensive behavioral testing
- **Integration Coverage**: Data flow and user journey validation

## Quality Assurance Features

### Accessibility Testing
- **ARIA Attributes**: Proper labeling and roles
- **Keyboard Navigation**: Tab order and interaction
- **Screen Reader Support**: Semantic HTML structure
- **Color Contrast**: Theme-aware accessibility

### Performance Testing
- **Load Time Validation**: <5 second dashboard load
- **Chart Rendering**: Responsive visualization performance
- **Memory Management**: No memory leaks during updates
- **API Efficiency**: Concurrent request handling

### Error Handling Validation
- **Network Failures**: Graceful degradation
- **Partial Data Loss**: Component resilience  
- **API Rate Limits**: User feedback and retry logic
- **Invalid Data**: Type safety and validation

## Continuous Integration

### Pre-commit Hooks
- Run relevant test suites
- Validate coverage thresholds
- Lint and format code

### CI Pipeline Integration
- Full test suite execution
- Cross-browser E2E validation
- Coverage reporting
- Performance benchmarks

## Development Workflow

### Test-Driven Development
1. Write failing tests for new features
2. Implement minimum viable functionality
3. Refactor with test safety net
4. Validate coverage requirements

### Bug Fix Process
1. Create reproduction test case
2. Verify test fails with current code
3. Fix implementation
4. Ensure test passes
5. Add regression protection

## Real-world Validation

### VirusTotal Data Scenarios
- **Malicious File Detection**: High-risk file handling
- **Clean File Processing**: False positive prevention  
- **Suspicious File Analysis**: Edge case validation
- **Bulk Report Processing**: Scalability testing

### Elasticsearch Integration
- **Query Performance**: Complex aggregation validation
- **Data Consistency**: Multi-index correlation testing
- **Index Management**: Large dataset handling
- **Connection Resilience**: Network interruption recovery

## Maintenance

### Regular Tasks
- Update mock data to match production patterns
- Refresh E2E test scenarios based on user feedback
- Monitor coverage metrics and improve low-coverage areas
- Performance benchmark tracking

### Dependencies
- Keep testing frameworks updated
- Monitor security advisories
- Validate compatibility with React/TypeScript updates

## Getting Started

1. **Install Dependencies**:
   ```bash
   npm install
   ```

2. **Run Test Suite**:
   ```bash
   npm run test:run
   ```

3. **Generate Coverage Report**:
   ```bash
   npm run test:coverage
   ```

4. **Start E2E Tests** (requires app running):
   ```bash
   npm run dev  # Terminal 1
   npm run test:e2e  # Terminal 2
   ```

This comprehensive testing setup ensures the VirusTotal Dashboard maintains high quality, reliability, and user experience standards while providing confidence for rapid development and deployment.