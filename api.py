"""
REST API for Threat Modeling Tool
FastAPI endpoints with API key authentication
"""

from fastapi import FastAPI, Depends, HTTPException, status, Header, Request, Response
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, PlainTextResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sqlalchemy.orm import Session
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, validator
from datetime import datetime, timedelta
import anthropic
import os
import secrets

from models import (
    Organization, User, APIKey, AuditLog, APIUsageLog, 
    ThreatAssessment, UsageStats
)
from database import get_db, engine
from auth import SessionManager, SAMLAuthHandler, InputValidator, get_password_hash, verify_password, create_access_token

# OAuth2 scheme for token-based auth
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

# Initialize FastAPI
app = FastAPI(
    title="AI Threat Modeling API",
    description="Enterprise-grade threat modeling API with AI-powered analysis",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Add rate limit handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    
    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    
    # Remove server header (MutableHeaders doesn't support pop in newer versions)
    if "Server" in response.headers:
        del response.headers["Server"]
    
    return response

# CORS middleware - Configure allowed origins from environment
allowed_origins_str = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8501")
# For development, allow all origins if explicitly set
if os.getenv("ENVIRONMENT", "development").lower() == "development":
    allowed_origins = ["*"]
else:
    allowed_origins = allowed_origins_str.split(",")
    if "*" in allowed_origins:
        raise RuntimeError("CRITICAL: Wildcard CORS (*) not allowed in production!")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,  # Cache preflight requests for 1 hour
)

# API Key authentication
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# Pydantic models for API requests/responses
class ThreatModelingRequest(BaseModel):
    project_name: str = Field(..., description="Name of the project", min_length=1, max_length=255)
    system_description: str = Field(..., description="Description of the system to analyze", min_length=10, max_length=50000)
    framework: str = Field(..., description="Threat modeling framework (STRIDE, MITRE ATT&CK, PASTA, etc.)")
    risk_type: Optional[str] = Field(None, description="Type of risk assessment (Agentic AI, Model Risk, etc.)", max_length=100)
    company_name: Optional[str] = Field(None, description="Company name for report branding", max_length=255)
    additional_context: Optional[Dict[str, Any]] = Field(None, description="Additional context for analysis")
    
    @validator('project_name', 'system_description', 'framework')
    def sanitize_text_fields(cls, v):
        """Sanitize text inputs"""
        return InputValidator.sanitize_text(v, max_length=50000)


class ThreatModelingResponse(BaseModel):
    assessment_id: int
    project_name: str
    framework: str
    status: str
    report: str
    report_html: Optional[str]
    report_metadata: Optional[Dict[str, Any]]
    created_at: datetime


class APIKeyResponse(BaseModel):
    id: int
    name: str
    key_prefix: str
    scopes: List[str]
    is_active: bool
    created_at: datetime
    expires_at: Optional[datetime]


class UserResponse(BaseModel):
    id: int
    email: str
    username: str
    full_name: Optional[str]
    role: str
    is_org_admin: bool
    organization_id: int
    created_at: datetime
    last_login: Optional[datetime]


class OrganizationResponse(BaseModel):
    id: int
    name: str
    slug: str
    max_users: int
    max_api_calls_per_month: int
    created_at: datetime


class AuditLogResponse(BaseModel):
    id: int
    user_email: Optional[str]
    action: str
    resource_type: Optional[str]
    description: Optional[str]
    status: str
    timestamp: datetime
    ip_address: Optional[str]


class UsageStatsResponse(BaseModel):
    total_assessments: int
    total_api_calls: int
    total_users: int
    active_users: int
    storage_used_gb: float
    assessments_by_framework: Optional[Dict[str, int]]
    api_calls_by_endpoint: Optional[Dict[str, int]]


# Startup initialization
@app.on_event("startup")
async def on_startup():
    secret = os.getenv("JWT_SECRET_KEY")
    if not secret:
        # Check if in production environment
        env = os.getenv("ENVIRONMENT", "development").lower()
        if env in ["production", "prod"]:
            raise RuntimeError(
                "CRITICAL: JWT_SECRET_KEY environment variable not set in production! "
                "Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
            )
        else:
            # Only allow fallback in development
            import warnings
            warnings.warn(
                "SECURITY WARNING: Using weak JWT secret in development. "
                "Set JWT_SECRET_KEY environment variable!",
                SecurityWarning
            )
            secret = "dev-secret-change-me-" + secrets.token_hex(16)
    
    SessionManager.init_secret_key(secret)


# Dependency to get current API key and user
async def get_current_api_key(
    api_key: str = Depends(api_key_header),
    db: Session = Depends(get_db)
) -> APIKey:
    """Validate API key and return the APIKey object"""
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key is missing"
        )
    
    # Hash the provided key
    key_hash = APIKey.hash_key(api_key)
    
    # Find the API key in database
    db_api_key = db.query(APIKey).filter(
        APIKey.key_hash == key_hash,
        APIKey.is_active == True
    ).first()
    
    if not db_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    # Check if expired
    if db_api_key.expires_at and db_api_key.expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has expired"
        )
    
    # Update last used
    db_api_key.last_used_at = datetime.utcnow()
    db.commit()
    
    return db_api_key


async def get_current_user(
    api_key: APIKey = Depends(get_current_api_key),
    db: Session = Depends(get_db)
) -> User:
    """Get the user associated with the API key"""
    user = db.query(User).filter(
        User.id == api_key.user_id,
        User.is_active == True
    ).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    
    return user


def require_scope(required_scope: str):
    """Dependency to check if API key has required scope"""
    def check_scope(api_key: APIKey = Depends(get_current_api_key)):
        if not api_key.scopes or required_scope not in api_key.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key does not have required scope: {required_scope}"
            )
        return api_key
    return check_scope


async def log_api_usage(
    request: Request,
    api_key: APIKey,
    status_code: int,
    response_time_ms: int,
    db: Session
):
    """Log API usage for analytics and rate limiting"""
    usage_log = APIUsageLog(
        api_key_id=api_key.id,
        endpoint=str(request.url.path),
        method=request.method,
        status_code=status_code,
        response_time_ms=response_time_ms,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    db.add(usage_log)
    db.commit()


# API Endpoints

@app.get("/api/health")
@limiter.limit("60/minute")
async def health_check(request: Request):
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


# ===== AUTHENTICATION ENDPOINTS =====

class UserRegister(BaseModel):
    email: str
    password: str
    full_name: str

class Token(BaseModel):
    access_token: str
    token_type: str

@app.post("/users/register")
async def register_user(user_data: UserRegister, db: Session = Depends(get_db)):
    """Register a new user"""
    # Check if user exists
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create or get default organization
    default_org = db.query(Organization).filter(Organization.slug == "default").first()
    if not default_org:
        default_org = Organization(
            name="Default Organization",
            slug="default",
            max_users=100,
            max_api_calls_per_month=10000
        )
        db.add(default_org)
        db.commit()
        db.refresh(default_org)
    
    # Generate username from email
    username = user_data.email.split('@')[0]
    # Ensure username is unique
    counter = 1
    original_username = username
    while db.query(User).filter(User.username == username).first():
        username = f"{original_username}{counter}"
        counter += 1
    
    # Create new user
    new_user = User(
        email=user_data.email,
        username=username,
        password_hash=get_password_hash(user_data.password),
        full_name=user_data.full_name,
        role="user",
        is_active=True,
        organization_id=default_org.id
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return {"message": "User created successfully", "user_id": new_user.id}

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Login endpoint to get access token"""
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create access token
    access_token = create_access_token(data={"sub": user.email})
    
    return {"access_token": access_token, "token_type": "bearer"}

async def get_current_user_from_token(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Get current user from JWT token"""
    import jwt
    from jwt import PyJWTError
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here-change-in-production")
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except PyJWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    
    return user

@app.get("/users/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_user_from_token)):
    """Get current user info"""
    return current_user


@app.post("/api/v1/threat-modeling", response_model=ThreatModelingResponse)
@limiter.limit("10/minute")  # Limit AI calls to prevent abuse
async def create_threat_assessment(
    request: Request,
    threat_request: ThreatModelingRequest,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new threat assessment using AI (rate limited to 10/minute)"""
    start_time = datetime.utcnow()
    
    try:
        # Validate inputs
        if not threat_request.project_name or len(threat_request.project_name) < 2:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Project name is required (minimum 2 characters)"
            )
        
        # Get API key from request or environment
        anthropic_api_key = threat_request.anthropic_api_key if hasattr(threat_request, 'anthropic_api_key') else os.getenv("ANTHROPIC_API_KEY")
        if not anthropic_api_key or anthropic_api_key.startswith("sk-ant-api03-CHANGE"):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="SecureAI API key is missing or invalid"
            )
        
        client = anthropic.Anthropic(api_key=anthropic_api_key)
        
        # Build comprehensive project info
        project_info = {
            'name': threat_request.project_name,
            'number': getattr(threat_request, 'project_number', 'N/A'),
            'app_type': getattr(threat_request, 'application_type', 'Web Application'),
            'deployment': getattr(threat_request, 'deployment_model', 'Cloud'),
            'criticality': getattr(threat_request, 'business_criticality', 'High'),
            'compliance': getattr(threat_request, 'compliance_requirements', []),
            'environment': getattr(threat_request, 'environment', 'Production')
        }
        
        # Get documents content
        documents_content = getattr(threat_request, 'system_description', 'No documentation provided')
        framework = threat_request.framework or 'MITRE ATT&CK'
        risk_areas = getattr(threat_request, 'risk_focus_areas', ['Infrastructure Risk', 'Data Security Risk'])
        
        # Build comprehensive evidence-based prompt
        prompt = f"""You are an expert cybersecurity consultant specializing in threat modeling and risk assessment. 
Perform a comprehensive threat assessment for the following project using the {framework} framework.

**PROJECT INFORMATION:**
- Project Name: {project_info['name']}
- Application Type: {project_info['app_type']}
- Deployment Model: {project_info['deployment']}
- Business Criticality: {project_info['criticality']}
- Compliance Requirements: {', '.join(project_info['compliance'])}
- Environment: {project_info['environment']}

**UPLOADED DOCUMENTATION:**
{documents_content}

**THREAT MODELING FRAMEWORK:** {framework}

**SPECIFIC RISK FOCUS AREAS TO ASSESS:**
{chr(10).join([f"- {area}" for area in risk_areas])}

**ASSESSMENT REQUIREMENTS - EVIDENCE-BASED ANALYSIS:**

Generate a professional threat assessment report with complete structure, extensive tables, and color-coded risk levels suitable for executive review.

**CRITICAL REQUIREMENT: Every finding, recommendation, and observation MUST include:**
1. **Document Reference:** Which uploaded document this observation is from
2. **Evidence Citation:** Specific quote or observation from the document
3. **Line Context:** Approximate location/section in the document
4. **Analysis:** How this evidence leads to the threat assessment finding
5. **Concrete Examples:** Specific examples from the documentation demonstrating the issue/risk

# EXECUTIVE SUMMARY

**Overall Risk Rating:** [CRITICAL/HIGH/MEDIUM/LOW]

[One paragraph describing assessment scope, methodology, and documents reviewed]

## Top 5 Critical Findings (with Document Evidence & Examples)

| Finding | Evidence Source (Doc) | Example from Docs | Risk Level | Business Impact | Timeline |
|---------|----------------------|-------------------|-----------|-----------------|----------|
| [Finding 1 with doc ref] | [Document: Name/Section] | [Specific example from doc] | CRITICAL | [Impact description] | Immediate (0-30 days) |

## Key Recommendations Summary

| Priority | Count | Sample Actions |
|----------|-------|----------------|
| P0 - CRITICAL | [count] | Immediate mitigations for critical risks |
| P1 - HIGH | [count] | High-priority security improvements |
| P2 - MEDIUM | [count] | Medium-term strengthening measures |

---

# THREAT MODELING ANALYSIS - {framework}

**Summary:** [2-3 sentence overview of the threat modeling analysis]

Comprehensive threat analysis organized by {framework} categories with risk scoring and mitigation paths, **with evidence citations and concrete examples from uploaded documentation**.

For each relevant category in {framework}, provide detailed analysis:

## [Category Name]

**Summary:** [1-2 sentences describing the threats found in this category]

| Threat ID | Threat Description | Document Evidence | Example from Documentation | Likelihood | Impact | Risk Score | Recommended Mitigation |
|-----------|-------------------|-------------------|---------------------------|-----------|--------|-----------|----------------------|
| T001 | [threat description] | [Doc: Name, Section/Quote] | [Specific example from doc] | [1-5] | [1-5] | [score] | [mitigation] |

---

# SPECIALIZED RISK ASSESSMENTS

**Summary:** [2-3 sentences describing the selected risk focus areas]

{chr(10).join([f'''## {area}

**Summary:** [1-2 sentences describing the risk landscape for {area}]

| Threat ID | Evidence Source (Doc) | Example from Docs | Threat | Likelihood | Impact | Risk Priority | Mitigation Strategy |
|-----------|-----------------------|-------------------|--------|-----------|--------|---------------|---------------------|
| T-{area[:3].upper()}-001 | [Doc: Section] | [Specific example] | [specific threat] | [1-5] | [1-5] | P0/P1/P2 | [specific action] |
''' for area in risk_areas])}

---

# COMPONENT-SPECIFIC THREAT ANALYSIS

**Summary:** [2-3 sentences describing the system architecture components]

| Component | Document Evidence | Example from Docs | Critical Threats | Risk Level | Mitigation Approach |
|-----------|-------------------|-------------------|-----------------|-----------|---------------------|
| Frontend/UI | [Doc: Section] | [example from doc] | [threats] | CRITICAL/HIGH | [approach] |
| Backend/App | [Doc: Section] | [example from doc] | [threats] | CRITICAL/HIGH | [approach] |
| Database/Data | [Doc: Section] | [example from doc] | [threats] | CRITICAL/HIGH | [approach] |

---

# ATTACK SCENARIOS & KILL CHAINS

**Summary:** [2-3 sentences describing the most likely attack scenarios]

## Scenario 1: [Attack Title - Highest Risk Scenario]

**Summary:** [1-2 sentences describing this specific attack scenario]

| Kill Chain Phase | Document Evidence | Example from Docs | Description | Detection Window | Mitigation Strategy |
|-----------------|-------------------|-------------------|-------------|------------------|---------------------|
| Reconnaissance | [Doc: Section] | [example from doc] | [phase details] | [detection opportunity] | [mitigation] |
| Exploitation | [Doc: Section] | [example from doc] | [phase details] | [detection opportunity] | [mitigation] |

---

# COMPREHENSIVE RISK MATRIX

**Summary:** [2-3 sentences explaining the risk scoring methodology]

## Risk Score Calculation

| Likelihood (L) | 1 - Rare | 2 - Unlikely | 3 - Possible | 4 - Likely | 5 - Very Likely |
|---|---|---|---|---|---|
| **5 - Catastrophic** | 5 | 10 | 15 | 20 | **25-CRITICAL** |
| **4 - Major** | 4 | 8 | 12 | **16-HIGH** | **20-CRITICAL** |
| **3 - Moderate** | 3 | 6 | **9-MEDIUM** | **12-HIGH** | **15-HIGH** |

## All Findings Risk Matrix

| Finding ID | Description | Likelihood | Impact | Risk Score | Risk Level | Priority | Owner | Remediation Timeline |
|----------|-------------|-----------|--------|-----------|-----------|----------|-------|----------------------|
| F001 | [critical finding] | [1-5] | [1-5] | [score] | **CRITICAL** | P0 | [owner] | 0-30 days |

---

# PRIORITIZED RECOMMENDATIONS

**Summary:** [2-3 sentences describing the remediation strategy]

## P0 - CRITICAL (Remediate in 0-30 days)

| Recommendation ID | Description | Document Evidence | Estimated Effort | Estimated Cost | Success Criteria |
|-------------------|-------------|-------------------|------------------|----------------|------------------|
| R-P0-001 | [critical action] | [Doc: Section] | [effort] | [cost] | [criteria] |

## P1 - HIGH (Remediate in 30-90 days)

| Recommendation ID | Description | Document Evidence | Estimated Effort | Estimated Cost | Success Criteria |
|-------------------|-------------|-------------------|------------------|----------------|------------------|
| R-P1-001 | [high priority action] | [Doc: Section] | [effort] | [cost] | [criteria] |

---

# COMPLIANCE ASSESSMENT

**Summary:** [2-3 sentences describing compliance status]

| Requirement | Standard | Current State | Gap | Evidence | Remediation | Priority |
|------------|----------|---------------|-----|----------|-------------|----------|
| [requirement] | {', '.join(project_info['compliance'])} | [state] | [gap] | [doc evidence] | [action] | [priority] |

---

# IMPLEMENTATION ROADMAP

**Summary:** [2-3 sentences describing the phased implementation approach]

## Phase 1: Immediate Actions (0-30 days)
- [Action 1 with document reference]
- [Action 2 with document reference]

## Phase 2: Short-term (30-90 days)
- [Action 1 with document reference]
- [Action 2 with document reference]

## Phase 3: Long-term (90+ days)
- [Action 1 with document reference]
- [Action 2 with document reference]
"""
        
        # Call Claude AI with error handling
        try:
            message = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=16000,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            report = message.content[0].text
        except Exception as ai_error:
            # Log error but don't expose internal details
            print(f"AI Service Error: {str(ai_error)}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Unable to generate threat assessment. Please try again later."
            )
        
        # Calculate risk counts from report
        report_upper = report.upper()
        critical_count = report_upper.count("CRITICAL")
        high_count = report_upper.count("HIGH")
        medium_count = report_upper.count("MEDIUM")
        
        # Create threat assessment record
        assessment = ThreatAssessment(
            organization_id=user.organization_id,
            user_id=user.id,
            project_name=threat_request.project_name,
            project_number=getattr(threat_request, 'project_number', None),
            framework=threat_request.framework,
            risk_type=', '.join(risk_areas[:3]) if risk_areas else None,
            system_description=documents_content[:500],
            assessment_report=report,
            report_html=report,
            status="completed",
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            report_meta={
                "framework": framework,
                "risk_areas": risk_areas,
                "generated_via": "API",
                "model": "claude-sonnet-4-20250514"
            }
        )
        db.add(assessment)
        
        # Log audit event
        audit_log = AuditLog(
            user_id=user.id,
            user_email=user.email,
            organization_id=user.organization_id,
            action="threat_assessment.create",
            resource_type="ThreatAssessment",
            resource_id=assessment.id,
            description=f"Created threat assessment via API: {threat_request.project_name}",
            status="success",
            metadata={
                "framework": threat_request.framework,
                "risk_areas": risk_areas
            },
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent")
        )
        db.add(audit_log)
        
        db.commit()
        db.refresh(assessment)
        
        # Log API usage
        response_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        
        return ThreatModelingResponse(
            assessment_id=assessment.id,
            project_name=assessment.project_name,
            framework=assessment.framework,
            status=assessment.status,
            report=assessment.assessment_report,
            report_html=assessment.report_html,
            report_metadata=assessment.report_meta or {},
            created_at=assessment.created_at
        )
        
    except Exception as e:
        # Log error
        audit_log = AuditLog(
            user_id=user.id,
            user_email=user.email,
            organization_id=user.organization_id,
            action="threat_assessment.create",
            resource_type="ThreatAssessment",
            description="Failed to create threat assessment via API",
            status="error",
            error_message=str(e),
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent")
        )
        db.add(audit_log)
        db.commit()
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create threat assessment: {str(e)}"
        )


@app.get("/api/v1/threat-modeling/{assessment_id}", response_model=ThreatModelingResponse)
async def get_threat_assessment(
    assessment_id: int,
    user: User = Depends(get_current_user),
    api_key: APIKey = Depends(require_scope("threat_modeling:read")),
    db: Session = Depends(get_db)
):
    """Get a specific threat assessment"""
    assessment = db.query(ThreatAssessment).filter(
        ThreatAssessment.id == assessment_id,
        ThreatAssessment.organization_id == user.organization_id
    ).first()
    
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat assessment not found"
        )
    
    return ThreatModelingResponse(
        assessment_id=assessment.id,
        project_name=assessment.project_name,
        framework=assessment.framework,
        status=assessment.status,
        report=assessment.assessment_report,
        report_html=assessment.report_html,
        report_metadata=assessment.report_metadata,
        created_at=assessment.created_at
    )


@app.get("/api/v1/threat-modeling", response_model=List[ThreatModelingResponse])
async def list_threat_assessments(
    skip: int = 0,
    limit: int = 20,
    user: User = Depends(get_current_user),
    api_key: APIKey = Depends(require_scope("threat_modeling:read")),
    db: Session = Depends(get_db)
):
    """List all threat assessments for the organization"""
    assessments = db.query(ThreatAssessment).filter(
        ThreatAssessment.organization_id == user.organization_id
    ).order_by(ThreatAssessment.created_at.desc()).offset(skip).limit(limit).all()
    
    return [
        ThreatModelingResponse(
            assessment_id=a.id,
            project_name=a.project_name,
            framework=a.framework,
            status=a.status,
            report=a.assessment_report,
            report_html=a.report_html,
            report_metadata=a.report_metadata,
            created_at=a.created_at
        )
        for a in assessments
    ]


# Admin endpoints

@app.get("/api/v1/admin/users", response_model=List[UserResponse])
async def list_users(
    user: User = Depends(get_current_user),
    api_key: APIKey = Depends(require_scope("admin:users")),
    db: Session = Depends(get_db)
):
    """List all users in the organization (admin only)"""
    if not user.is_org_admin and user.role != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    users = db.query(User).filter(
        User.organization_id == user.organization_id
    ).all()
    
    return [
        UserResponse(
            id=u.id,
            email=u.email,
            username=u.username,
            full_name=u.full_name,
            role=u.role,
            is_org_admin=u.is_org_admin,
            organization_id=u.organization_id,
            created_at=u.created_at,
            last_login=u.last_login
        )
        for u in users
    ]


@app.get("/api/v1/admin/audit-logs", response_model=List[AuditLogResponse])
async def get_audit_logs(
    skip: int = 0,
    limit: int = 100,
    action: Optional[str] = None,
    user: User = Depends(get_current_user),
    api_key: APIKey = Depends(require_scope("admin:audit")),
    db: Session = Depends(get_db)
):
    """Get audit logs for the organization (admin only)"""
    if not user.is_org_admin and user.role != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    query = db.query(AuditLog).filter(
        AuditLog.organization_id == user.organization_id
    )
    
    if action:
        query = query.filter(AuditLog.action == action)
    
    logs = query.order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit).all()
    
    return [
        AuditLogResponse(
            id=log.id,
            user_email=log.user_email,
            action=log.action,
            resource_type=log.resource_type,
            description=log.description,
            status=log.status,
            timestamp=log.timestamp,
            ip_address=log.ip_address
        )
        for log in logs
    ]


@app.get("/api/v1/admin/usage-stats", response_model=UsageStatsResponse)
async def get_usage_stats(
    user: User = Depends(get_current_user),
    api_key: APIKey = Depends(require_scope("admin:stats")),
    db: Session = Depends(get_db)
):
    """Get usage statistics for the organization (admin only)"""
    if not user.is_org_admin and user.role != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    # Get latest usage stats
    stats = db.query(UsageStats).filter(
        UsageStats.organization_id == user.organization_id
    ).order_by(UsageStats.created_at.desc()).first()
    
    if not stats:
        # Return empty stats if none exist
        return UsageStatsResponse(
            total_assessments=0,
            total_api_calls=0,
            total_users=0,
            active_users=0,
            storage_used_gb=0.0,
            assessments_by_framework={},
            api_calls_by_endpoint={}
        )
    
    return UsageStatsResponse(
        total_assessments=stats.total_assessments,
        total_api_calls=stats.total_api_calls,
        total_users=stats.total_users,
        active_users=stats.active_users,
        storage_used_gb=stats.storage_used_gb,
        assessments_by_framework=stats.assessments_by_framework,
        api_calls_by_endpoint=stats.api_calls_by_endpoint
    )


# ============== SAML SSO Endpoints ==============

def _get_org_by_slug(db: Session, org_slug: str) -> Organization:
    org = db.query(Organization).filter(Organization.slug == org_slug).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    if not org.saml_enabled:
        raise HTTPException(status_code=400, detail="SAML not enabled for organization")
    return org


@app.get("/saml/metadata/{org_slug}", response_class=PlainTextResponse)
async def saml_metadata(org_slug: str, db: Session = Depends(get_db)):
    """
    Generate SAML Service Provider metadata XML
    Includes signing certificate if configured
    """
    from onelogin.saml2.settings import OneLogin_Saml2_Settings

    org = _get_org_by_slug(db, org_slug)
    handler = SAMLAuthHandler(org)
    
    try:
        settings = OneLogin_Saml2_Settings(settings=handler._build_saml_settings(), sp_validation_only=True)
        metadata = settings.get_sp_metadata()
        errors = settings.validate_metadata(metadata)
        
        if len(errors) > 0:
            raise HTTPException(
                status_code=500, 
                detail=f"SAML metadata validation errors: {', '.join(errors)}"
            )
        
        return PlainTextResponse(content=metadata, media_type="application/xml")
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate SAML metadata: {str(e)}"
        )


@app.get("/saml/login/{org_slug}")
async def saml_login(org_slug: str, request: Request, db: Session = Depends(get_db)):
    org = _get_org_by_slug(db, org_slug)
    handler = SAMLAuthHandler(org)
    # Build a minimal request dict for python3-saml
    req_data = {
        'https': request.url.scheme == 'https',
        'http_host': request.client.host if request.client else 'localhost',
        'server_port': request.url.port or (443 if request.url.scheme == 'https' else 80),
        'script_name': request.url.path,
        'get_data': dict(request.query_params),
        'post_data': {}
    }
    redirect_url = handler.initiate_login(req_data)
    return RedirectResponse(url=redirect_url)


@app.post("/saml/acs/{org_slug}")
async def saml_acs(org_slug: str, request: Request, db: Session = Depends(get_db)):
    org = _get_org_by_slug(db, org_slug)
    handler = SAMLAuthHandler(org)

    form = await request.form()
    req_data = {
        'https': request.url.scheme == 'https',
        'http_host': request.client.host if request.client else 'localhost',
        'server_port': request.url.port or (443 if request.url.scheme == 'https' else 80),
        'script_name': request.url.path,
        'get_data': dict(request.query_params),
        'post_data': dict(form),
        'ip_address': request.client.host if request.client else None,
        'user_agent': request.headers.get('user-agent')
    }

    user = handler.process_response(req_data, db)
    if not user:
        raise HTTPException(status_code=401, detail="SAML authentication failed")

    # Issue JWT and set HttpOnly cookie
    access = SessionManager.create_access_token(user)
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:8501")
    # Also include the token in query string to let Streamlit capture it server-side
    redirect_with_token = f"{frontend_url}?token={access}"
    resp = RedirectResponse(url=redirect_with_token)
    # 1 hour expiry cookie
    resp.set_cookie(
        key="access_token",
        value=access,
        httponly=True,
        secure=False,  # set True in production behind HTTPS
        samesite="lax",
        max_age=3600
    )
    return resp


@app.get("/saml/sls/{org_slug}")
@app.post("/saml/sls/{org_slug}")
async def saml_sls(org_slug: str, request: Request, db: Session = Depends(get_db)):
    """
    SAML Single Logout Service (SLS)
    Handles logout requests from IdP
    """
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    
    org = _get_org_by_slug(db, org_slug)
    handler = SAMLAuthHandler(org)
    
    # Build request dict
    if request.method == "POST":
        form = await request.form()
        post_data = dict(form)
    else:
        post_data = {}
    
    req_data = {
        'https': request.url.scheme == 'https',
        'http_host': request.client.host if request.client else 'localhost',
        'server_port': request.url.port or (443 if request.url.scheme == 'https' else 80),
        'script_name': request.url.path,
        'get_data': dict(request.query_params),
        'post_data': post_data
    }
    
    req = handler.prepare_request(req_data)
    auth = OneLogin_Saml2_Auth(req, handler.settings)
    
    # Process logout request
    url = auth.process_slo(delete_session_cb=lambda: None)
    errors = auth.get_errors()
    
    if errors:
        raise HTTPException(status_code=400, detail=f"SAML SLO error: {', '.join(errors)}")
    
    # Clear cookies and redirect
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:8501")
    resp = RedirectResponse(url=url or frontend_url)
    resp.delete_cookie("access_token")
    return resp


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
