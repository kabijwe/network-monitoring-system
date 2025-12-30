#!/bin/bash

# Network Monitoring System - GitHub Setup Script
# This script helps you push your project to GitHub

echo "🚀 Network Monitoring System - GitHub Setup"
echo "============================================="

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo "❌ Git is not installed. Please install Git first."
    exit 1
fi

echo "✅ Git is installed"

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    echo "📁 Initializing Git repository..."
    git init
    echo "✅ Git repository initialized"
else
    echo "✅ Already in a Git repository"
fi

# Check if there are any commits
if ! git rev-parse --verify HEAD >/dev/null 2>&1; then
    echo "📝 Making initial commit..."
    
    # Add all files
    git add .
    
    # Make initial commit
    git commit -m "Initial commit: Network Monitoring System

- Complete Django backend with authentication and RBAC
- Ping monitoring system with configurable thresholds  
- Advanced alerting system with multi-channel notifications
- Support for Email, Telegram, Slack, Teams, and SMS notifications
- Data import/export functionality (Excel, CSV, JSON, PDF)
- Comprehensive audit logging system
- Docker configuration for easy deployment
- Extensive test coverage and property-based testing setup"
    
    echo "✅ Initial commit created"
else
    echo "✅ Repository already has commits"
fi

# Get GitHub username
echo ""
echo "📋 GitHub Repository Setup"
echo "-------------------------"
read -p "Enter your GitHub username: " github_username

if [ -z "$github_username" ]; then
    echo "❌ GitHub username is required"
    exit 1
fi

# Get repository name
read -p "Enter repository name (default: network-monitoring-system): " repo_name
repo_name=${repo_name:-network-monitoring-system}

# Check if remote already exists
if git remote get-url origin >/dev/null 2>&1; then
    echo "⚠️  Remote 'origin' already exists:"
    git remote get-url origin
    read -p "Do you want to update it? (y/n): " update_remote
    
    if [ "$update_remote" = "y" ] || [ "$update_remote" = "Y" ]; then
        git remote set-url origin https://github.com/$github_username/$repo_name.git
        echo "✅ Remote origin updated"
    fi
else
    # Add remote origin
    git remote add origin https://github.com/$github_username/$repo_name.git
    echo "✅ Remote origin added"
fi

# Show current status
echo ""
echo "📊 Current Git Status:"
echo "---------------------"
git status --short

echo ""
echo "🔗 Remote Repository:"
echo "--------------------"
git remote -v

echo ""
echo "🚀 Ready to Push!"
echo "=================="
echo ""
echo "Next steps:"
echo "1. Create repository on GitHub: https://github.com/new"
echo "   - Repository name: $repo_name"
echo "   - Description: Comprehensive network monitoring solution for ISPs"
echo "   - Make it Public or Private (your choice)"
echo "   - DO NOT initialize with README, .gitignore, or license"
echo ""
echo "2. After creating the repository, run:"
echo "   git branch -M main"
echo "   git push -u origin main"
echo ""
echo "3. If you get authentication errors:"
echo "   - Use Personal Access Token instead of password"
echo "   - Or set up SSH key authentication"
echo ""

# Ask if user wants to push now
read -p "Do you want to push to GitHub now? (y/n): " push_now

if [ "$push_now" = "y" ] || [ "$push_now" = "Y" ]; then
    echo ""
    echo "🚀 Pushing to GitHub..."
    
    # Set main branch
    git branch -M main
    
    # Push to GitHub
    if git push -u origin main; then
        echo ""
        echo "🎉 Successfully pushed to GitHub!"
        echo "🔗 Repository URL: https://github.com/$github_username/$repo_name"
        echo ""
        echo "✅ Your Network Monitoring System is now on GitHub!"
    else
        echo ""
        echo "❌ Push failed. Common solutions:"
        echo "1. Make sure the repository exists on GitHub"
        echo "2. Check your authentication (use Personal Access Token)"
        echo "3. Verify the repository URL is correct"
        echo ""
        echo "Manual push command:"
        echo "git push -u origin main"
    fi
else
    echo ""
    echo "📝 Manual push commands:"
    echo "git branch -M main"
    echo "git push -u origin main"
fi

echo ""
echo "📚 For detailed instructions, see: GITHUB_SETUP.md"
echo "🆘 Need help? Check the troubleshooting section in GITHUB_SETUP.md"