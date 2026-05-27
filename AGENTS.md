# AGENTS.md — Backend Agent Instructions

This AGENTS.md applies only to the backend located in:

Backend/

The frontend is located one level above in:

../src/

The shared project documentation is located in:

../docs/ai/

Before making backend changes, read the relevant docs from:

../docs/ai/PROJECT_CONTEXT.md
../docs/ai/BACKEND_API_CONTRACT.md
../docs/ai/DATABASE_SCHEMA.md
../docs/ai/FRONTEND_ROADMAP.md
../docs/ai/UI_RULES.md

## Project context

This is the FastAPI backend for a Collaborative Threat Intelligence Platform.

The frontend is already completed separately with React + Tailwind CSS.

Current focus:

- web development integration only
- backend + frontend functionality
- no blockchain implementation for now
- no chatbot implementation for now

Do not work on blockchain or chatbot unless explicitly asked.

## Current backend stack

The backend runs with Docker Compose.

Services:

- api: FastAPI / Uvicorn / Python 3.11
- db: PostgreSQL 15 Alpine
- redis: Redis 7 Alpine
- mailpit: local email testing server

The backend uses:

- Dockerfile
- docker-compose.yml
- pyproject.toml
- PostgreSQL through asyncpg
- Redis through REDIS_URL
- Mailpit for SMTP testing

The API is exposed on:

http://localhost:8000

Swagger should be available on:

http://localhost:8000/docs

Mailpit web UI is available on:

http://localhost:8025

## Important development rule

Do not Dockerize the frontend now.

The expected local development setup is:

- backend runs with `docker compose up --build`
- frontend runs locally with `npm run dev`
- frontend calls backend through `http://localhost:8000`

## Business logic

Public visitors:

- do not log in
- can access public dashboard
- can view only public validated data
- public data means TLP green or white only
- must not see red or amber data
- must not see rejected, revoked, pending, deprecated, or false_positive submissions

Organizations:

- submit a contributor application form
- application starts as pending
- admin can approve or reject the organization

Admin:

- logs in from the shared frontend login page
- backend decides that the user is admin
- admin is redirected by frontend to `/admin`
- admin can approve/reject organizations
- admin can generate/revoke API keys
- admin can view all submissions and global statistics

Contributor:

- created when admin approves an organization
- receives by email:
  - username/email
  - temporary password
  - API key for automation
- logs in from the same shared frontend login page
- backend decides that the user is contributor
- contributor is redirected by frontend to `/contributor`
- contributor can change password
- if `must_change_password = true`, contributor must change password before using dashboard
- contributor can view only own submissions
- contributor can submit new IOCs
- contributor can submit new malware samples
- contributor can submit new threat actors
- contributor cannot edit submissions
- contributor cannot delete submissions
- contributor can mark owned IOCs as false positive
- contributor can mark owned malware samples as false positive
- contributor can mark owned threat actors as false positive

API key:

- API key is for automation/scripts only
- API key is not the normal web dashboard login method
- dashboard login should use username/email + password and JWT/session auth

## False positive rule

False positive must apply to all three intelligence types:

- IOC
- malware sample
- threat actor

Marking as false positive is the only correction action allowed after submission.

The backend must verify ownership before allowing a contributor to mark something as false positive.

## Backend routes expected by frontend

The exact current frontend routes may need to be checked, but the backend should support the following concepts:

Authentication:

- login endpoint for shared admin/contributor login
- contributor change password
- current user endpoint

Public:

- public dashboard stats
- public list of IOCs
- public IOC details
- public list of malware samples
- public malware details
- public list of threat actors
- public threat actor details

Contributor:

- list own IOCs
- create IOC
- mark own IOC as false positive
- list own malware samples
- create malware sample
- mark own malware sample as false positive
- list own threat actors
- create threat actor
- mark own threat actor as false positive

Admin:

- list organization applications
- approve organization
- reject organization
- list contributors
- revoke API key
- view all submissions
- view global statistics

Email:

- when admin approves an organization, send credentials and API key through SMTP/Mailpit

## Technical rules

- Do not rewrite the backend from scratch.
- Keep the existing FastAPI structure.
- Keep Docker Compose.
- Keep PostgreSQL.
- Keep Redis if currently used.
- Keep Mailpit for local email testing.
- Do not implement blockchain now.
- Do not implement chatbot now.
- Do not modify frontend files.
- Do not invent fields blindly.
- If database schema changes are needed, add migrations if the project uses migrations.
- If there are tests, update/add tests for changed behavior.
- Keep changes small and focused.

## Frontend integration context

The frontend is already completed and is located one level above this backend folder:

../src/

The frontend project root is:

../

The shared project documentation is located in:

../docs/ai/

When working on backend/frontend integration, you may inspect frontend files to understand:

- frontend routes
- API client configuration
- expected endpoint paths
- request payloads
- response shapes
- auth token storage
- role-based redirects
- naming conventions used by components

Important:

- You may read frontend files.
- Do not modify frontend files unless explicitly asked.
- Backend fixes should be made inside this Backend/ folder.
- If the frontend expects an endpoint that does not exist, prefer implementing or adapting the backend route instead of changing the frontend.
- If the frontend expectation is clearly wrong or unsafe, stop and report it before changing anything.
