"""finding confidence + deciding layer

Revision ID: b41d2e8c9f03
Revises: 7c3f9a1e4b22
Create Date: 2026-11-11 00:00:00.000000

Phase 15 B: the risk score now caps low-confidence findings at Medium
(see core/risk.py), so each Finding records the classifier confidence and
which layer decided its verdict. Both are nullable — rows written before
this migration have neither, and core/risk.py treats a NULL confidence as
full confidence so historical scan scores don't change.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b41d2e8c9f03"
down_revision: Union[str, None] = "7c3f9a1e4b22"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("finding", sa.Column("confidence", sa.Float(), nullable=True))
    op.add_column(
        "finding", sa.Column("decided_by_layer", sa.Integer(), nullable=True)
    )


def downgrade() -> None:
    with op.batch_alter_table("finding") as batch_op:
        batch_op.drop_column("decided_by_layer")
        batch_op.drop_column("confidence")
