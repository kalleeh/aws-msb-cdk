# Contributing to AWS MSB CDK

Thank you for your interest in contributing to the AWS Minimum Security Baseline CDK project. This document provides guidelines for making contributions to this project.

## Git Commit Best Practices

### Commit Structure

1. **Commit Related Changes**
   - Each commit should contain related changes only
   - Fix different bugs or implement different features in separate commits
   - Use the staging area to create granular commits

2. **Commit Often**
   - Keep commits small and focused
   - Share your code frequently to avoid merge conflicts
   - Aim for logical, complete units of work

3. **Don't Commit Half-Done Work**
   - Only commit when a logical component is completed
   - Use `git stash` for temporary storage of work-in-progress changes

4. **Test Before Committing**
   - Ensure your code works as expected before committing
   - Run relevant tests to verify functionality
   - Check for side effects

### Commit Message Format

```
<type>: <subject>

<body>

<footer>
```

1. **Subject Line**
   - Capitalized, imperative mood
   - 50 characters or less
   - No period at the end
   - Examples: "Add IAM password policy", "Fix S3 bucket encryption"

2. **Message Body**
   - Separated from subject by a blank line
   - Wrapped at 72 characters
   - Explains what and why (not how)
   - Use imperative, present tense

3. **Message Footer**
   - Reference issues or tickets
   - Mention breaking changes

### Commit Types

- **feat**: A new feature
- **fix**: A bug fix
- **docs**: Documentation changes
- **style**: Formatting, missing semicolons, etc; no code change
- **refactor**: Code change that neither fixes a bug nor adds a feature
- **test**: Adding or updating tests
- **chore**: Updating build tasks, package manager configs, etc

## Branching Strategy

1. **Main Branch**
   - Always deployable
   - Never commit directly to main

2. **Feature Branches**
   - Create from main
   - Name format: `feature/<description>`
   - Merge back to main when complete

3. **Fix Branches**
   - Create from main
   - Name format: `fix/<description>`
   - Merge back to main when complete

## Pull Request Process

1. Update documentation as needed
2. Add or update tests as needed
3. Follow the commit message format
4. Request review from at least one team member
5. Merge only after approval

## Code Style

Follow the established code style in the project:
- Use consistent indentation (spaces, not tabs)
- Follow Python PEP 8 guidelines
- Use meaningful variable and function names
- Add comments for complex logic