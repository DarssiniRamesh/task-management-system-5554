# Integration Notes: Frontend and Backend

See also the corresponding notes in the frontend workspace.

## Environment Configuration

Backend .env (task-management-system-5554/to_do_backend/.env):

DATABASE_URL=sqlite:///./app.db
SECRET_KEY=change-me-in-prod  # TODO: replace in production
ACCESS_TOKEN_EXPIRE_MINUTES=60
CORS_ALLOW_ORIGINS=http://localhost:3000
ENVIRONMENT=development

Frontend .env (task-management-system-5553/to_do_frontend/.env):

REACT_APP_API_URL=http://localhost:3001

## Validation

- Confirm backend at http://localhost:3001/docs
- Confirm frontend at http://localhost:3000
- From the frontend origin, fetch(`${process.env.REACT_APP_API_URL}/`) should succeed without CORS errors
- Execute smoke flows: register, login, list/create/update/toggle/delete tasks

Note: Restart services after changing environment files. Do not commit real secrets.
