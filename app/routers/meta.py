"""Read-only introspection of the authorization model.

Publishing the matrix to authenticated users makes the policy auditable without
revealing anything an attacker could not infer by probing.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.authz import require_permission
from app.models import User
from app.permissions import Permission, matrix_as_dict, permissions_for

router = APIRouter(prefix="/api/meta", tags=["meta"])


@router.get("/permissions")
def permission_matrix(
    current_user: User = Depends(require_permission(Permission.META_READ)),
) -> dict[str, object]:
    return {
        "matrix": matrix_as_dict(),
        "your_role": current_user.role.value,
        "your_permissions": sorted(p.value for p in permissions_for(current_user.role)),
    }
