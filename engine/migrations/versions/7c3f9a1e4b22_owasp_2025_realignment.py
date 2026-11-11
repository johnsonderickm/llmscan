"""owasp 2025 realignment: plugin renames, plugin_run table, simulated column

Revision ID: 7c3f9a1e4b22
Revises: 480bb51ec296
Create Date: 2026-10-23 00:00:00.000000

Remaps existing Finding rows for the 5 plugins renamed/relabelled to match
the real OWASP LLM Top 10 (2025) numbering (see CLAUDE.md "Phase 15"), adds
the `plugin_run` table (per-plugin run status: TESTED/NOT_APPLICABLE/ERROR/
SKIPPED, so a category with no plugin run never silently renders as
"Clean"), and adds `finding.simulated` (set when a finding came from a
text-based fallback classifier rather than a real structured signal, e.g.
LLM06 tool-calling when the target rejects the tools field).

`failure_mode` on SQLite is a plain VARCHAR with no CHECK constraint (no
native enum support), so adding `FailureMode.INCONCLUSIVE` to the Python
enum needs no schema change here.
"""
from typing import Sequence, Union

import sqlalchemy as sa
import sqlmodel
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "7c3f9a1e4b22"
down_revision: Union[str, None] = "480bb51ec296"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# (plugin_id, owasp_id) before -> after, for the 5 renamed/relabelled plugins.
_RENAMES: list[tuple[str, str, str, str]] = [
    ("llm03_output", "LLM03", "llm05_output_handling", "LLM05"),
    ("llm04_dos", "LLM04", "llm10_unbounded_consumption", "LLM10"),
    ("llm05_supply", "LLM05", "llm03_supply_chain", "LLM03"),
    ("llm08_overreliance", "LLM08", "llm09_misinformation", "LLM09"),
    ("llm10_multimodal", "LLM10", "llm01_multimodal", "LLM01"),
]


def upgrade() -> None:
    op.create_table(
        "pluginrun",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("plugin_id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("owasp_id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "TESTED", "NOT_APPLICABLE", "ERROR", "SKIPPED", name="pluginrunstatus"
            ),
            nullable=False,
        ),
        sa.Column("payloads_sent", sa.Integer(), nullable=False),
        sa.Column("errors", sa.Integer(), nullable=False),
        sa.Column("findings", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scan.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_pluginrun_scan_id"), "pluginrun", ["scan_id"], unique=False
    )

    op.add_column(
        "finding",
        sa.Column(
            "simulated", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
    )

    for old_plugin_id, old_owasp_id, new_plugin_id, new_owasp_id in _RENAMES:
        op.execute(
            sa.text(
                "UPDATE finding SET plugin_id = :new_plugin_id, "
                "owasp_id = :new_owasp_id "
                "WHERE plugin_id = :old_plugin_id AND owasp_id = :old_owasp_id"
            ).bindparams(
                new_plugin_id=new_plugin_id,
                new_owasp_id=new_owasp_id,
                old_plugin_id=old_plugin_id,
                old_owasp_id=old_owasp_id,
            )
        )


def downgrade() -> None:
    for old_plugin_id, old_owasp_id, new_plugin_id, new_owasp_id in _RENAMES:
        op.execute(
            sa.text(
                "UPDATE finding SET plugin_id = :old_plugin_id, "
                "owasp_id = :old_owasp_id "
                "WHERE plugin_id = :new_plugin_id AND owasp_id = :new_owasp_id"
            ).bindparams(
                old_plugin_id=old_plugin_id,
                old_owasp_id=old_owasp_id,
                new_plugin_id=new_plugin_id,
                new_owasp_id=new_owasp_id,
            )
        )

    op.drop_column("finding", "simulated")

    op.drop_index(op.f("ix_pluginrun_scan_id"), table_name="pluginrun")
    op.drop_table("pluginrun")
