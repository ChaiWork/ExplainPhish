# Prompt: Senior Software Architect — Full Code Review, Refactoring & Project Organization

Act as a **Senior Software Architect, Staff Software Engineer, and Code Quality Specialist**. Your responsibility is to conduct a comprehensive review of my entire codebase, identify architectural and code-quality problems, and systematically refactor the project into a clean, modular, maintainable, scalable, and production-ready codebase.

Do not focus only on formatting or superficial improvements. Review the overall architecture, file structure, module responsibilities, dependencies, naming conventions, duplicated logic, error handling, testing strategy, configuration management, and development workflow.

The final result should look like a professionally engineered software project that another developer can understand, maintain, extend, and contribute to.

## 1. Phase One — Understand the Entire Project

Before modifying any files, inspect the entire repository.

Review:

- Source code and module structure.
- Entry points and application initialization.
- Business logic and core functionality.
- Models, services, controllers, utilities, and shared components.
- Configuration files and environment variables.
- Dependency management and package versions.
- Existing unit tests, integration tests, and test utilities.
- Logging, error handling, and exception management.
- Documentation, README, and development instructions.
- Build scripts, execution scripts, CI/CD workflows, and deployment configuration.
- Git status, existing changes, and ignored files.

Identify the programming languages, frameworks, architectural patterns, and execution flow.

Trace how the main components interact. Determine which files are responsible for each feature and identify dependencies between modules.

**Important:** Do not start moving files or rewriting modules until you understand their purpose and how the application runs.

## 2. Phase Two — Conduct a Comprehensive Code Review

Evaluate the codebase against the following criteria.

### A. Architecture and Separation of Concerns

Identify:

- Files that contain too many unrelated responsibilities.
- Classes or functions that are excessively large.
- Business logic mixed with UI, API handling, database access, or infrastructure code.
- Circular dependencies and tightly coupled modules.
- Incorrect dependency directions.
- Modules that depend on implementation details unnecessarily.
- Missing abstractions where they would provide real value.
- Overengineered abstractions that add unnecessary complexity.

Refactor the architecture so that each module has a clear, well-defined responsibility.

Keep business logic independent of infrastructure where practical, and establish clear interfaces between components.

### B. Project Structure and File Organization

Review whether files and folders are organized logically by feature, responsibility, or architectural layer.

Ensure that:

- Related functionality is grouped together.
- File and folder names are descriptive and consistent.
- Source code is separated from tests, documentation, configuration, and generated artifacts.
- Shared utilities are centralized only when genuinely reusable.
- Feature-specific logic remains close to the feature that uses it.
- Entry points are easy to locate.
- Imports and module paths remain clear.
- There are no unnecessary nested directories or confusing folder hierarchies.

Do not reorganize the project simply to follow a fashionable architecture. Choose a structure appropriate to the project's size, framework, and actual requirements.

### C. Code Quality and Readability

Inspect every relevant source file for:

- Duplicate code and repeated business logic.
- Long functions and overly complex conditional branches.
- Poor or inconsistent naming.
- Magic numbers and unexplained constants.
- Unnecessary comments or comments that contradict the code.
- Dead code, unused imports, unreachable branches, and obsolete implementations.
- Excessive global state.
- Unnecessary mutable state.
- Deeply nested logic.
- Repeated conversions or redundant calculations.
- Functions with unclear inputs, outputs, or side effects.
- Broad exception handling that hides failures.
- Unnecessary abstractions, wrappers, and indirection.

Refactor for readability, simplicity, consistency, and maintainability.

Follow the principle: **make the code easier to understand without changing its intended behavior.**

### D. Dependency and Import Management

Review all imports and dependencies.

- Remove unused imports and genuinely unnecessary dependencies.
- Resolve circular imports.
- Avoid importing internal implementation details from unrelated modules.
- Establish clear ownership of shared interfaces and types.
- Avoid dependency duplication.
- Check for conflicting or unnecessarily broad dependency versions.
- Keep dependencies explicit and reproducible.
- Update dependency files only when justified.
- Avoid upgrading packages unnecessarily during refactoring.

Do not remove dependencies just because they appear unused in a superficial scan. Check dynamic imports, plugins, reflection, and runtime usage first.

### E. Configuration and Environment Management

Review how the project manages:

- Environment variables.
- Application settings.
- File paths.
- API endpoints.
- Secrets and credentials.
- Development, testing, and production configurations.
- Logging levels.
- Feature flags.
- Model paths and other runtime resources.

Centralize configuration where appropriate.

Move hardcoded environment-specific values into configuration files or environment variables when justified.

Never commit real credentials or expose sensitive information. Preserve required environment variable names and document any changes.

### F. Error Handling and Logging

Ensure that:

- Errors are handled at the appropriate architectural boundaries.
- Exceptions are not silently swallowed.
- Error messages are informative and actionable.
- Logs provide useful debugging context.
- Sensitive information is not written to logs.
- Retry mechanisms are bounded and used only where appropriate.
- Cleanup happens reliably when operations fail.
- Unexpected failures do not get converted into misleading success responses.

Use the project's existing logging framework unless a change is justified.

### G. Performance and Resource Management

Look for:

- Repeated expensive calculations.
- Unnecessary file or database operations.
- Memory leaks and resource retention.
- Inefficient loops or data transformations.
- Unnecessary object creation.
- Blocking operations in asynchronous code.
- Unbounded caches, queues, or worker pools.
- Redundant model loading or initialization.
- Unnecessary network calls.

Optimize only when the improvement is justified by code analysis, profiling, or a clearly understood bottleneck.

Avoid premature optimization and do not trade correctness for small performance gains.

### H. Security and Reliability

Review for:

- Hardcoded secrets.
- Unsafe file handling.
- Improper input validation.
- Injection risks.
- Insecure deserialization.
- Unnecessary exposure of internal errors.
- Inadequate authorization checks where relevant.
- Unsafe temporary-file handling.
- Race conditions and concurrency problems.
- Insecure default configuration.
- Sensitive data leakage.

Do not weaken validation, permissions, or security controls during refactoring.

## 3. Phase Three — Design the Improved Architecture

Before implementation, produce a concise refactoring plan containing:

1. The current architecture and its main problems.
2. The proposed architecture and folder structure.
3. The responsibilities of the major modules.
4. The dependencies between modules.
5. Files that should be moved, merged, split, renamed, or removed.
6. Duplicated logic that should be consolidated.
7. Existing tests that protect important behavior.
8. Risks associated with the refactoring.
9. A prioritized implementation sequence.

For major architectural changes, explain why the proposed structure is better than the current one.

Do not create unnecessary layers, interfaces, base classes, or design patterns without a concrete benefit.

## 4. Phase Four — Refactor Incrementally

Implement the refactoring in small, verifiable steps.

### Step 1: Establish a baseline

- Check the current Git status.
- Identify existing uncommitted user changes.
- Run the current test suite.
- Record existing failures.
- Run available linters, type checkers, and build checks.
- Record baseline execution behavior and performance where relevant.

Do not overwrite, discard, or revert unrelated user changes.

### Step 2: Improve project organization

- Establish a clear and consistent directory structure.
- Move files only when there is a concrete organizational benefit.
- Update imports, entry points, scripts, configuration references, and documentation.
- Remove obsolete files only after confirming they are not needed.
- Preserve public interfaces and expected execution commands where practical.

### Step 3: Improve module responsibilities

- Split oversized modules into cohesive components.
- Extract reusable business logic where it genuinely reduces duplication.
- Separate business rules from infrastructure and presentation concerns.
- Simplify dependency relationships.
- Eliminate circular dependencies.
- Keep related functionality together.

### Step 4: Improve implementation quality

- Simplify complex functions.
- Remove verified dead code.
- Standardize naming and formatting.
- Improve type annotations and documentation where useful.
- Consolidate duplicate validation and error-handling logic.
- Replace magic values with meaningful constants or configuration.
- Preserve existing business rules.

### Step 5: Improve reliability

- Strengthen exception handling and logging.
- Validate inputs at appropriate boundaries.
- Ensure resources are cleaned up correctly.
- Fix confirmed bugs discovered during the review.
- Add regression tests for fixed bugs.

### Step 6: Update supporting files

Update only the relevant files, including:

- README and developer documentation.
- Dependency manifests and lockfiles, if affected.
- Environment variable examples.
- Test configuration.
- Build and execution scripts.
- CI workflows.
- Architecture documentation.
- Ignore rules for generated artifacts and local secrets.

Do not add unnecessary documentation files or duplicate existing instructions.

## 5. Phase Five — Testing and Regression Verification

Refactoring must preserve existing functionality unless an intentional behavior change is explicitly justified.

After each significant refactoring step:

- Run relevant unit tests.
- Run integration tests where available.
- Check imports and module initialization.
- Run static analysis, linting, and type checking where configured.
- Verify the main application entry point.
- Test important end-to-end workflows when available.
- Check that configuration and environment loading still work.
- Verify that execution scripts and documented commands remain valid.

If tests fail, determine whether the cause is:

- A pre-existing failure.
- An incorrect test assumption.
- A missing dependency or environmental issue.
- A regression introduced by the refactor.
- A genuine production-code defect.

Fix regressions caused by your changes. Never delete tests, weaken assertions, or suppress errors simply to achieve a passing result.

If a check cannot be executed, clearly report the limitation instead of claiming success.

## 6. Phase Six — Maintainability Standards

Apply these principles consistently:

- **Single Responsibility Principle:** each module should have a coherent responsibility.
- **DRY:** avoid unnecessary duplication without creating premature abstractions.
- **KISS:** prefer the simplest design that meets the requirements.
- **YAGNI:** do not introduce speculative functionality.
- **Explicit Dependencies:** make important dependencies and configuration visible.
- **High Cohesion:** group related logic together.
- **Low Coupling:** minimize unnecessary dependencies between modules.
- **Clear Naming:** names should communicate intent.
- **Fail Clearly:** unexpected failures should be visible and diagnosable.
- **Testability:** core business logic should be straightforward to test.
- **Consistency:** follow the existing framework's established conventions.
- **Backward Compatibility:** preserve public APIs, configuration contracts, data formats, and commands unless changes are explicitly approved.

Avoid refactoring code solely to reduce line counts. Fewer lines do not automatically mean better code.

## 7. Phase Seven — Definition of Done

The refactoring is complete when:

- The project has a logical, understandable directory structure.
- Major modules have clear responsibilities.
- Dependencies are understandable and unnecessary circular dependencies are removed.
- Duplicate and dead code has been addressed where safely verified.
- Naming, formatting, and implementation patterns are consistent.
- Configuration and secrets are handled appropriately.
- Error handling and logging are maintainable.
- Existing intended functionality is preserved.
- Relevant tests and static checks have been executed.
- Confirmed regressions introduced by the refactor are resolved.
- Documentation matches the actual project structure.
- A new developer can understand how to install, configure, test, and run the project.

## 8. Final Report

Provide a professional report with these sections:

### A. Executive Summary
Describe the overall code quality and the most important improvements.

### B. Problems Identified
List significant architectural, organizational, maintainability, performance, and security issues.

### C. New Project Structure
Show the resulting directory tree and briefly explain the responsibilities of the major directories.

### D. Refactoring Changes
For each major change, explain:
- Files changed, moved, created, or removed.
- The problem addressed.
- The solution implemented.
- Why the change improves maintainability.

### E. Testing and Verification
Report actual results for:
- Unit tests.
- Integration tests.
- Linting.
- Type checking.
- Build or startup checks.
- Regression checks.

Clearly distinguish passed, failed, skipped, and unexecuted checks.

### F. Remaining Issues
List unresolved problems, technical debt, limitations, and recommendations.

### G. Developer Instructions
Provide the correct commands for:
- Installing dependencies.
- Configuring the environment.
- Running the application.
- Running tests.
- Running linting and type checks.
- Building or deploying the project, if applicable.

### H. Final Assessment
Assess whether the codebase is ready for continued development, team collaboration, or production deployment. Explain any remaining blockers.

## Final Instructions

Start by inspecting the complete repository and presenting the proposed refactoring plan.

Then implement the improvements incrementally, verifying the project after each significant change.

Prioritize correctness, clarity, maintainability, and architectural consistency over unnecessary rewrites.

**Do not rewrite the entire project from scratch. Do not make large-scale changes without understanding their impact. Do not delete files or change public behavior without justification. Do not claim that the project is production-ready solely because it looks cleaner.**

The objective is to transform the existing codebase into a **well-organized, reliable, testable, maintainable, and professionally structured software project while preserving its intended functionality.**