# TSO Compliance Tool

A governance, risk, and compliance (GRC) tool that assesses websites against cybersecurity frameworks.

## Initial Vision
**Goal:** Create an accessible web tool that:
- Automates compliance checks against multiple standards (Ghana Cybersecurity Act, HIPAA, ISO 27001, NIST)
- Provides actionable recommendations
- Works entirely client-side for easy deployment
- Offers intuitive visual reporting

**Target Users:** 
- Small businesses needing affordable compliance checks
- Developers verifying security configurations
- Auditors conducting preliminary assessments

## Technical Approach

### Architecture
    A[Client-Side Browser] -->|HTML/CSS/JS| B[GitHub Pages Hosting]
    A -->|API Calls| C[Demo Endpoints]
    D[Cloudflare Worker Proxy] -->|Optional| E[Target Websites]


## Key Components

### Frontend
    Bootstrap 5 + Chart.js interface
    Dynamic tabbed results display
    Drag-and-drop document upload

### Core Checks
    // Sample check structure
    {
      id: 'ssl',
      name: 'SSL/TLS Verification',
      run: async (url) => {
        return url.startsWith('https://') ? 'pass' : 'fail'
      }
    }

### Framework Adapters
    Modular design for each standard
    Configurable weightings per requirement


## Key Lessons Learned
### Browser Limitations Are Real
    Challenge:
    CORS restrictions blocked ~95% of cross-origin scans
    No direct header inspection possible
    
    Solutions:
    // Fallback analysis techniques
    const detectViaMetaTags = (html) => ({
      csp: html.includes('content-security-policy'),
      xFrame: html.includes('x-frame-options')
    });

### Progressive Enhancement Matters
    Implemented:
    Basic checks (HTTPS/SSL) always work
    Advanced checks show "Requires Proxy" badges
    Demo mode with pre-approved sites

### Error Handling is Critical
    Before:
    catch (err) {
     console.log(err); // User sees nothing
    }

    After:
    catch (err) {
     showAlert(`Limited scan results: ${userFriendlyMessages[err.type]}`);
     displayPartialResults();
    }

## Current Limitations
    Limitation	Workaround
    _CORS restrictions	Use proxy/serverless function
    No deep scanning	Add headless browser option
    Document verification	Client-side text pattern matching

## Future Roadmap
### Proxy Integration
    # Planned Cloudflare Worker deployment
    wrangler deploy src/proxy.js

### Enhanced Checks
    DNS record verification
    TLS certificate analysis
    CMS vulnerability detection

### Self-Hosting Option
    Docker container with pre-configured proxy


## Development Notes
    Getting Started
    git clone https://github.com/yemofio/tso-compliance-tool.git
    cd tso-audit-tool
    # Open index.html in browser

## Resources
- https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
- https://owasp.org/www-project-secure-headers/
- https://gdpr.eu/checklist/
