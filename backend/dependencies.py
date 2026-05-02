"""
Shared FastAPI dependencies: auth, rate limiting, role checks.
"""
from fastapi import Depends, HTTPException, status
from api.routes.auth import get_current_user
from api.models.database import User, RoleEnum

ROLE_HIERARCHY = {RoleEnum.VIEWER: 0, RoleEnum.ANALYST: 1, RoleEnum.ADMIN: 2}

def require_role(min_role: str):
    async def checker(current_user: User = Depends(get_current_user)) -> User:
        required_level = ROLE_HIERARCHY.get(RoleEnum(min_role), 0)
        user_level = ROLE_HIERARCHY.get(current_user.role, 0)
        if user_level < required_level:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Role '{min_role}' or higher required.")
        return current_user
    return checker
