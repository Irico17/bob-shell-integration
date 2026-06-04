---
name: deep-code-review
description: Orchestrates comprehensive code review by systematically applying all custom skills for security, architecture, and code quality analysis
---

# Deep Code Review Skill

## Purpose
Orchestrates a comprehensive, multi-layered code review by applying all available custom skills in a systematic way. This skill ensures thorough analysis across security, architecture, code quality, and best practices.

## Scope
- **Comprehensive Analysis**: Reviews code from multiple perspectives
- **Skill Orchestration**: Applies all custom skills systematically
- **Prioritized Findings**: Groups issues by severity and category
- **Actionable Recommendations**: Provides specific, implementable fixes

## Review Methodology

### Phase 1: Security Analysis
Apply security-focused skills first as they have highest priority:

1. **SQL Injection Prevention**
   - Check for string concatenation in queries
   - Verify parameterized queries usage
   - Validate input sanitization

2. **Security Vulnerabilities**
   - Scan for hardcoded credentials
   - Check authentication/authorization
   - Verify secure data handling
   - Review error messages for information leakage

### Phase 2: Architecture Review
Evaluate structural and design aspects:

1. **SOLID Principles**
   - Single Responsibility Principle
   - Open/Closed Principle
   - Liskov Substitution Principle
   - Interface Segregation Principle
   - Dependency Inversion Principle

2. **Architecture Patterns**
   - Design pattern usage
   - Separation of concerns
   - Modularity and cohesion
   - Dependency management

### Phase 3: Code Quality Assessment
Review code maintainability and readability:

1. **Code Quality Standards**
   - Naming conventions
   - Code complexity
   - DRY principle adherence
   - Function/method length
   - Comment quality
   - Magic numbers/strings

2. **Best Practices**
   - Error handling
   - Logging practices
   - Resource management
   - Performance considerations

### Phase 4: Integration Analysis
Check how components work together:

1. **Cross-cutting Concerns**
   - Consistency across codebase
   - Shared utilities usage
   - Common patterns adherence
   - Technical debt identification

## Review Output Format

### Executive Summary
```markdown
## Deep Code Review Summary

**Overall Assessment**: [Excellent/Good/Needs Improvement/Critical Issues]
**Total Issues Found**: X
**Critical**: X | **High**: X | **Medium**: X | **Low**: X

### Key Findings
1. [Most critical issue]
2. [Second most critical issue]
3. [Third most critical issue]

### Recommendations Priority
1. [Highest priority action]
2. [Second priority action]
3. [Third priority action]
```

### Detailed Findings by Category

#### 1. Security Issues
```markdown
### Critical Security Issues

#### [Issue Title]
- **File**: path/to/file.ext:line
- **Severity**: Critical
- **Category**: Security
- **Rule**: [Which skill/rule detected this]
- **Description**: [Clear explanation]
- **Risk**: [What could happen]
- **Fix**: [Specific solution]
- **Example**:
  ```language
  // Before (vulnerable)
  [bad code]
  
  // After (secure)
  [good code]
  ```
```

#### 2. Architecture Issues
```markdown
### Architecture Violations

#### [Issue Title]
- **File**: path/to/file.ext:line
- **Severity**: High/Medium
- **Category**: Architecture
- **Principle**: [SOLID principle or pattern]
- **Description**: [Clear explanation]
- **Impact**: [How it affects maintainability]
- **Refactoring**: [Specific solution]
```

#### 3. Code Quality Issues
```markdown
### Code Quality Concerns

#### [Issue Title]
- **File**: path/to/file.ext:line
- **Severity**: Medium/Low
- **Category**: Code Quality
- **Issue**: [Specific problem]
- **Recommendation**: [How to improve]
```

### Metrics and Statistics
```markdown
## Code Metrics

### Complexity
- High complexity functions: X
- Average cyclomatic complexity: X
- Functions exceeding threshold: X

### Maintainability
- Code duplication instances: X
- Long functions (>50 lines): X
- Deep nesting levels (>3): X

### Documentation
- Undocumented functions: X
- Missing docstrings: X
- Unclear comments: X
```

### Action Plan
```markdown
## Recommended Action Plan

### Immediate Actions (Critical/High)
1. [ ] Fix SQL injection in auth/login.py:45
2. [ ] Remove hardcoded credentials from config.py:12
3. [ ] Add input validation to user_service.py:78

### Short-term Improvements (Medium)
1. [ ] Refactor large function in processor.py:120
2. [ ] Extract magic numbers in calculator.py:34
3. [ ] Improve error handling in api_client.py:56

### Long-term Enhancements (Low)
1. [ ] Improve naming in utils.py
2. [ ] Add missing docstrings
3. [ ] Reduce code duplication in helpers/
```

## Review Guidelines

### Severity Classification

**Critical**
- Security vulnerabilities
- Data loss risks
- System crashes
- Authentication/authorization bypasses

**High**
- Major architecture violations
- Significant security concerns
- Performance bottlenecks
- Data integrity issues

**Medium**
- SOLID principle violations
- Code maintainability issues
- Minor security concerns
- Moderate complexity

**Low**
- Style inconsistencies
- Minor naming issues
- Documentation gaps
- Optimization opportunities

### Best Practices for Deep Review

1. **Be Thorough**: Check every aspect systematically
2. **Be Specific**: Provide exact locations and solutions
3. **Be Constructive**: Focus on improvement, not criticism
4. **Be Prioritized**: Order by severity and impact
5. **Be Actionable**: Give clear, implementable recommendations

### Context Considerations

When reviewing, consider:
- **Project Type**: Web app, API, library, etc.
- **Language**: Python, JavaScript, Java, etc.
- **Framework**: Django, React, Spring, etc.
- **Team Size**: Solo, small team, large organization
- **Stage**: Prototype, production, legacy

### Integration with Other Skills

This skill should:
1. Load all available custom skills
2. Apply each skill's rules systematically
3. Aggregate findings across all skills
4. Deduplicate similar issues
5. Prioritize by severity and impact
6. Generate unified report

## Usage Examples

### Example 1: Full Branch Review
```markdown
Review the entire main branch:
- Apply all security skills
- Check all architecture patterns
- Assess code quality
- Generate comprehensive report
```

### Example 2: Feature Branch Review
```markdown
Review feature/new-api branch:
- Focus on new/changed files
- Apply relevant skills
- Compare against main branch
- Highlight regressions
```

### Example 3: Pre-merge Review
```markdown
Review PR before merge:
- Quick security scan
- Architecture compliance check
- Code quality assessment
- Generate merge recommendation
```

## Success Criteria

A successful deep review should:
- ✅ Apply all available skills
- ✅ Find all critical issues
- ✅ Provide actionable recommendations
- ✅ Include code examples
- ✅ Prioritize by severity
- ✅ Generate clear action plan
- ✅ Be comprehensive yet concise

## Continuous Improvement

This skill should evolve by:
- Adding new review dimensions
- Refining severity classifications
- Improving recommendation quality
- Learning from past reviews
- Adapting to project context