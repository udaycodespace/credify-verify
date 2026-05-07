Here it is. Every placeholder has a comment telling you exactly what to write and what to avoid.

---

```markdown
<!-- ═══════════════════════════════════════════════════════════════════
     LOGO
     Use your actual project logo or icon.
     Square or circular works best at this size.
     No placeholder "logo.png" — if you don't have one, delete this block.
     Don't use a stock icon from flaticon and call it your logo.
     ═══════════════════════════════════════════════════════════════════ -->

<div align="center">

<img src="./assets/logo.png" width="68" alt="[Project Name]" />

<br/><br/>

<!-- ═══════════════════════════════════════════════════════════════════
     PROJECT NAME
     Just the name. No tagline here. No version number.
     ═══════════════════════════════════════════════════════════════════ -->

# [Project Name]

<!-- ═══════════════════════════════════════════════════════════════════
     TAGLINE — the single most important line in this file.
     One sentence. Under 12 words. No adjectives. No hype.

     Answer exactly one question: what does this do and who is it for?

     WRITE:   "Role-based task manager for small engineering teams."
     WRITE:   "Inter-college event platform — students, admins, one system."
     WRITE:   "Blockchain credential verifier for academic transcripts."

     DON'T:   "A powerful, cutting-edge solution that streamlines workflows."
     DON'T:   "Empowering teams to collaborate and innovate at scale."
     DON'T:   Anything with the words "seamless", "robust", or "next-gen".
     ═══════════════════════════════════════════════════════════════════ -->

**[What it does. Who it's for. One sentence, no adjectives.]**

<br/>

<!-- ═══════════════════════════════════════════════════════════════════
     BADGES
     Keep it to 3-4. More than that looks like badge hoarding.

     Status values:    active | wip | complete | archived
     Status colors:    brightgreen | orange | blue | lightgrey

     For the "built with" badge:
     - logo= takes any slug from https://simpleicons.org
     - color= takes any hex without the #, e.g. 61DAFB for React

     If the repo is private or not deployed, skip the "live" badge.
     ═══════════════════════════════════════════════════════════════════ -->

[![Status](https://img.shields.io/badge/status-[active|wip|complete|archived]-[brightgreen|orange|blue|lightgrey]?style=flat-square)](.)
[![License](https://img.shields.io/github/license/[username]/[repo]?style=flat-square)](./LICENSE)
[![Last commit](https://img.shields.io/github/last-commit/[username]/[repo]?style=flat-square)](https://github.com/[username]/[repo]/commits)
[![Built with](https://img.shields.io/badge/[PrimaryTech]-[color]?style=flat-square&logo=[simpleicons_slug]&logoColor=white)](https://[tech-docs-url])

<br/>

<!-- ═══════════════════════════════════════════════════════════════════
     QUICK LINKS
     Live → only if actually deployed. Delete if not.
     Issues → keep if others might use this.
     Docs → only if you have actual docs beyond this README.
     Delete any link that points nowhere real.
     ═══════════════════════════════════════════════════════════════════ -->

[Live →](https://[your-deployed-url]) &nbsp;·&nbsp; [Issues](https://github.com/[username]/[repo]/issues) &nbsp;·&nbsp; [Docs](./docs)

</div>

---

<!-- ═══════════════════════════════════════════════════════════════════
     HERO VISUAL — second most important thing after the tagline.

     DEPLOYED:     Use a real screenshot. Crop to show the most
                   interesting screen. Annotate if the UI isn't obvious.

     NOT DEPLOYED: Export a mockup from Figma, or take a screenshot
                   of the running local app. Do not use wireframes
                   or placeholder images — they signal unfinished work.

     Caption:      Describe what's visible in the image specifically.
     WRITE:   "Admin dashboard — task board with assignee and deadline columns"
     DON'T:   "Screenshot of the app" or leave the alt text blank.
     ═══════════════════════════════════════════════════════════════════ -->

<div align="center">
  <img
    src="./assets/preview.png"
    width="100%"
    alt="[Project Name] — [describe what's on screen, e.g. 'admin dashboard showing task board with role switcher']"
  />
  <br/>
  <!-- Caption: 5-10 words. Name the screen and the key thing it shows. -->
  <sub>[e.g. Admin dashboard · task board · role-based view]</sub>
</div>

---

## What this is

<!-- ═══════════════════════════════════════════════════════════════════
     2-4 sentences. That's the cap.

     Answer in order:
     1. What type of thing is it? (web app, CLI, API, library)
     2. What specific problem does it solve?
     3. Why did you build it? (one honest line — a gap, a learning goal,
        a frustration — not a mission statement)
     4. Scope, if relevant. (solo project, internship, team of 3, etc.)

     WRITE:   "[Name] is a MERN stack event management platform for
               inter-college fests. Students register, college admins
               approve, and a superadmin oversees everything. Built
               during my internship to explore a different stack from
               what I'd been using with Frappe."

     DON'T:   "In today's rapidly evolving digital landscape, managing
               events has never been more important. [Name] is here to
               revolutionize how institutions connect and collaborate."

     DON'T use: "powerful", "seamless", "robust", "innovative",
                "comprehensive", "cutting-edge", or "state-of-the-art".
     ═══════════════════════════════════════════════════════════════════ -->

[Project Name] is a [type] that [does what] for [who].

[One honest sentence on why you built it.]

[Optional: one sentence on scope — team size, context, timeframe.]

---

## Stack

<!-- ═══════════════════════════════════════════════════════════════════
     List the actual tech you used. Be specific about versions
     if they matter (e.g. React 18, not just "React").

     Add or remove rows to match your actual stack.
     Don't list things you tried and abandoned.
     Don't add a row for every npm package — just the major layers.
     ═══════════════════════════════════════════════════════════════════ -->

| Layer | Tech |
|---|---|
| Frontend | [e.g. React 18 + Vite + Tailwind CSS] |
| Backend | [e.g. Node.js + Express / Frappe Framework / Spring Boot] |
| Database | [e.g. MongoDB / PostgreSQL / SQLite] |
| Auth | [e.g. JWT + bcrypt / OAuth 2.0] |
| Storage | [e.g. Cloudinary / AWS S3 — or delete this row if not applicable] |
| Email | [e.g. Nodemailer + Gmail SMTP — or delete if not applicable] |
| Deployment | [e.g. Vercel + Railway / Docker — or "Not deployed"] |

---

## Features

<!-- ═══════════════════════════════════════════════════════════════════
     List only what's actually built and working.
     Not what you plan to add. That goes in the roadmap section.

     Each bullet:
     - Start with a verb
     - Say what it does concretely
     - One sentence per feature

     WRITE:   "- Role-based access for Superadmin, College Admin, and
                 Student — each role sees only its own scope"
     WRITE:   "- Email verification on signup via Nodemailer + Gmail SMTP"
     WRITE:   "- Waitlist system with automatic promotion when a spot opens"

     DON'T:   "- Powerful dashboard with rich insights and analytics"
     DON'T:   "- Seamless user experience across all devices"
     DON'T:   List a feature you started but didn't finish.
     ═══════════════════════════════════════════════════════════════════ -->

- [Feature — start with a verb, be specific]
- [Feature]
- [Feature]
- [Feature]
- [Feature]
- [Add or remove lines to match what's actually shipped]

---

## Screens

<!-- ═══════════════════════════════════════════════════════════════════
     KEEP THIS BLOCK if the project is not deployed.
     DELETE THIS BLOCK if deployed — the live link in the header is enough.

     Name each screen what it actually is, not "Screen 1".
     Use real screenshots from the running local app.
     Aim for 4-8 screens covering the main flows.

     File naming: use descriptive names.
     GOOD: login.png, dashboard-admin.png, task-detail.png
     BAD:  screenshot1.png, image.png, final_v3.png

     If a screen needs context to understand, add a <sub> caption under
     the table. One line, plain language.
     ═══════════════════════════════════════════════════════════════════ -->

> Not deployed. These are screenshots of the running local interface.

| [Screen name — e.g. Login] | [Screen name — e.g. Admin dashboard] |
|:---:|:---:|
| ![Login](./assets/screens/login.png) | ![Dashboard](./assets/screens/dashboard.png) |

| [Screen name — e.g. Task board] | [Screen name — e.g. Employee view] |
|:---:|:---:|
| ![Tasks](./assets/screens/tasks.png) | ![Employee](./assets/screens/employee.png) |

<!-- Add more rows as needed. Same pattern. -->

---

## Running locally

<!-- ═══════════════════════════════════════════════════════════════════
     KEEP THIS BLOCK if someone might clone this — an interviewer,
     a collaborator, or future you on a new machine.

     DELETE THIS BLOCK if this is a purely academic submission
     that no one will ever clone and run.

     Every command here must work cold — assume a fresh machine,
     no prior context, no global installs beyond what's listed.

     If startup order matters (e.g. backend before frontend),
     say so explicitly. Don't assume it's obvious.
     ═══════════════════════════════════════════════════════════════════ -->

**Prerequisites**

<!-- List the minimum required tools. Versions matter if they matter. -->
- [e.g. Node.js v18+]
- [e.g. Python 3.10+]
- [e.g. MongoDB running on localhost:27017]

```bash
# Clone
git clone https://github.com/[username]/[repo].git
cd [repo]

# Install
[npm install / pip install -r requirements.txt / mvn install]

# Environment variables
cp .env.example .env
# Open .env and fill in your values — see the table below

# Start
[npm run dev / python app.py / bench start / mvn spring-boot:run]
```

<!-- Add any non-obvious steps here.
     e.g. "Run the backend first, then the frontend in a separate terminal."
     e.g. "Run npm run seed once to populate the database with test data."
     If setup is just those 4 commands above, delete this comment. -->

App runs at `http://localhost:[port]`.

**Environment variables**

<!-- List every key in .env.example.
     Description: what it does, not just what it is.

     WRITE:   | `JWT_SECRET` | Any long random string — used to sign tokens |
     WRITE:   | `GMAIL_PASS` | Gmail app password, not your account password |
     DON'T:   | `API_KEY` | API key |
     ═══════════════════════════════════════════════════════════════════ -->

| Key | What it does |
|---|---|
| `[VAR_NAME]` | [e.g. MongoDB connection string] |
| `[VAR_NAME]` | [e.g. JWT secret — any long random string] |
| `[VAR_NAME]` | [e.g. Cloudinary cloud name] |
| `[VAR_NAME]` | [e.g. Gmail app password — not your regular account password] |

---

## Project structure

<!-- ═══════════════════════════════════════════════════════════════════
     INCLUDE if the repo has multiple top-level folders or a layout
     that isn't obvious from glancing at the file tree.

     DELETE for small single-folder projects. Don't pad with structure
     docs for a project that's 3 files.

     Comment each folder in plain language — what lives there,
     not what it's "responsible for".
     ═══════════════════════════════════════════════════════════════════ -->

```
[repo-name]/
├── [client/]      # [e.g. React app — components, pages, hooks]
├── [server/]      # [e.g. Express API — routes, models, middleware]
├── [docs/]        # [e.g. setup guides, API reference]
└── .env.example   # all required env keys, values blanked out
```

---

## Known gaps

<!-- ═══════════════════════════════════════════════════════════════════
     Be honest. Every experienced dev looks for this section.
     An honest gap list reads as self-aware.
     Hiding known issues reads as unaware.

     WRITE things that are actually missing or broken.
     DON'T write "everything works perfectly" and leave this empty.
     DON'T write vague items like "could be improved".

     WRITE:   "- No mobile layout — desktop only right now"
     WRITE:   "- File upload size not validated server-side"
     WRITE:   "- No test coverage"
     ═══════════════════════════════════════════════════════════════════ -->

- [ ] [Specific gap — e.g. No mobile responsive layout]
- [ ] [e.g. No test coverage]
- [ ] [e.g. Error messages are not user-friendly on the frontend]

---

## Roadmap

<!-- ═══════════════════════════════════════════════════════════════════
     What you'd actually add if you kept working on this.
     Specific, not vague. Say what and roughly how.

     WRITE:   "- Email notifications when a task goes overdue"
     WRITE:   "- Export task history to CSV"
     DON'T:   "- Improve performance"
     DON'T:   "- Better UI"
     DON'T:   List things that are already in the features section.
     ═══════════════════════════════════════════════════════════════════ -->

- [ ] [e.g. Email alert when task deadline passes]
- [ ] [e.g. Export reports to CSV]
- [ ] [e.g. Mobile responsive layout]
- [ ] [e.g. Dark mode]

---

## Status

<!-- ═══════════════════════════════════════════════════════════════════
     Pick ONE block below. Delete the other two entirely.
     Be accurate — don't say "active" if you've moved on.
     ═══════════════════════════════════════════════════════════════════ -->

<!-- IF ACTIVE: remove the other two blocks -->
![active](https://img.shields.io/badge/status-active-brightgreen?style=flat-square)
Actively maintained.

<!-- IF COMPLETE/SUBMITTED: remove the other two blocks -->
![complete](https://img.shields.io/badge/status-complete-blue?style=flat-square)
Built for [context — e.g. "internship at Inkers Technology, Apr 2026"]. Stable, not actively maintained.

<!-- IF ARCHIVED: remove the other two blocks -->
![archived](https://img.shields.io/badge/status-archived-lightgrey?style=flat-square)
No longer maintained. Code is here for reference.

---

## License

[MIT](./LICENSE)

---

<div align="center">
  <sub>
    Built by <a href="https://github.com/[username]">[Your Name]</a> &nbsp;·&nbsp; [Year]
  </sub>
</div>
```

---

**The 6 things that kill READMEs after you fill the template:**

**1. Tagline with adjectives.** Go back and read yours out loud. If it contains "powerful", "seamless", "robust", "innovative", or "cutting-edge" — rewrite it. Every bad SaaS README has those words.

**2. Features that aren't shipped.** If you haven't built it, it goes in the roadmap. Not the features list. Interviewers clone repos.

**3. Empty or stock hero image.** A placeholder image is worse than no image. Take a real screenshot of the running app, even locally. Crop it well.

**4. Env table with useless descriptions.** `API_KEY | API key` tells nobody anything. Say what the key does and where to get it.

**5. Status mismatch.** If you submitted this for an internship and moved on, mark it `complete`. Don't leave it on `active` with a last commit from 6 months ago.

**6. Footer with filler.** `Built by [you] · [year]`. That's it. No "feel free to reach out." No "hope this helps." The work speaks.