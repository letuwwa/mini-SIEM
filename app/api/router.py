from fastapi import APIRouter

from app.api.v1 import auth_router
from app.api.v1.security_events import router as security_events_router

api_router = APIRouter()
api_router.include_router(auth_router)
api_router.include_router(security_events_router)
