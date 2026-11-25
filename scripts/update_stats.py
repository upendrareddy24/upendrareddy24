#!/usr/bin/env python3
"""
Automated profile stats updater for upendrareddy24 GitHub profile README.md.
Fetches live stats from GitHub API and updates metrics table in README.md.
Adapted from BNTiyan/update_stats.py — single-account edition.
"""

import os
import re
import json
import urllib.request

USERNAME = "upendrareddy24"


def get_headers():
    token = os.environ.get("GITHUB_TOKEN")
    headers = {"User-Agent": "GitHub-Stats-Updater"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_json(url):
    req = urllib.request.Request(url, headers=get_headers())
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None


def get_user_stats(username):
    user = fetch_json(f"https://api.github.com/users/{username}")
    if not user or not isinstance(user, dict):
        return None
    return {
        "public_repos": user.get("public_repos", 0),
        "followers": user.get("followers", 0),
    }


def get_repo_breakdown(username):
    """Return per-domain repo counts matching the README's domain buckets."""
    repos = []
    page = 1
    while True:
        batch = fetch_json(
            f"https://api.github.com/users/{username}/repos?per_page=100&page={page}"
        )
        if not batch or not isinstance(batch, list) or len(batch) == 0:
            break
        repos.extend(batch)
        if len(batch) < 100:
            break
        page += 1

    if not repos:
        return None

    finance_keywords = {
        "investors_dashboard", "options_analysis", "stock-analyst-pro",
        "strategy-stock-tracker", "portfolio_tracker", "live_stock_picks",
        "stock_screener", "stock_bot", "budgetwise",
    }
    automotive_keywords = {
        "automotive-skill-hub", "fusainterviewsim", "faang_mock_interview_simulator",
        "resume_py", "job_scout_ai", "upendra-machunuru",
    }

    finance_count = 0
    automotive_count = 0
    ai_automation_count = 0
    total_stars = 0

    for r in repos:
        name = r.get("name", "").lower()
        total_stars += r.get("stargazers_count", 0)
        if name in finance_keywords:
            finance_count += 1
        elif name in automotive_keywords:
            automotive_count += 1
        # AI/automation heuristic: job_scout_ai, youtubeautomation, stock_bot, budgetwise
        if any(kw in name for kw in ["ai", "automation", "bot", "scout", "auto"]):
            ai_automation_count += 1

    return {
        "total_repos": len(repos),
        "total_stars": total_stars,
        "finance_count": finance_count,
        "automotive_count": automotive_count,
        "ai_automation_count": ai_automation_count,
    }


def update_readme():
    user_stats = get_user_stats(USERNAME)
    if not user_stats or user_stats.get("public_repos", 0) == 0:
        print("Warning: Could not fetch valid user stats from GitHub API. Skipping update.")
        return

    repo_stats = get_repo_breakdown(USERNAME)
    total_repos = repo_stats["total_repos"] if repo_stats else user_stats["public_repos"]
    repo_count = max(user_stats["public_repos"], total_repos)
    finance_count = repo_stats["finance_count"] if repo_stats else 9
    automotive_count = repo_stats["automotive_count"] if repo_stats else 6
    ai_count = repo_stats["ai_automation_count"] if repo_stats else 6

    print(
        f"Fetched stats: {repo_count} public repos | "
        f"{finance_count} finance | {automotive_count} automotive | {ai_count} AI/automation"
    )

    readme_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "README.md"
    )
    if not os.path.exists(readme_path):
        readme_path = "README.md"

    with open(readme_path, "r", encoding="utf-8") as f:
        content = f.read()

    new_content = content

    # Update | 📁 **Public Repositories** | ... |
    new_content = re.sub(
        r"(\| 📁 \*\*Public Repositories\*\* \| )(\*\*[^\*]+\*\*)",
        rf"\g<1>**{repo_count}+ Active Repos**",
        new_content,
    )

    # Update | 💹 **Finance & Trading Tools** | ... |
    new_content = re.sub(
        r"(\| 💹 \*\*Finance & Trading Tools\*\* \| )(\*\*[^\*]+\*\*)",
        rf"\g<1>**{finance_count} Projects**",
        new_content,
    )

    # Update | 🤖 **AI & Automation Projects** | ... |
    new_content = re.sub(
        r"(\| 🤖 \*\*AI & Automation Projects\*\* \| )(\*\*[^\*]+\*\*)",
        rf"\g<1>**{ai_count} Projects**",
        new_content,
    )

    # Update | 🏭 **Automotive / Career Projects** | ... |
    new_content = re.sub(
        r"(\| 🏭 \*\*Automotive / Career Projects\*\* \| )(\*\*[^\*]+\*\*)",
        rf"\g<1>**{automotive_count} Projects**",
        new_content,
    )

    if new_content != content:
        with open(readme_path, "w", encoding="utf-8") as f:
            f.write(new_content)
        print("README.md updated with latest stats successfully.")
    else:
        print("README.md is already up to date with the latest stats.")


if __name__ == "__main__":
    update_readme()
