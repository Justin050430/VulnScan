"""Invitation email binding and token lookup indexes.

Revision ID: d9f2a4c8b1e7
Revises: c4d8f1a2b6e9
Create Date: 2026-11-13 10:20:00.000000

Additive only: records the email address an invitation was issued to (so the
acceptance can prove the signed-in account owns that address) and indexes the
token hash used to look an invitation up.  The frozen core eight entities and
the existing Trust Boundary columns are unchanged.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd9f2a4c8b1e7'
down_revision = 'c4d8f1a2b6e9'
branch_labels = None
depends_on = None


MEMBERSHIP_TABLES = ("TrustOrganisationMembership", "TrustProjectMembership")


def upgrade():
    for table in MEMBERSHIP_TABLES:
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.add_column(
                sa.Column('InviteEmail', sa.String(length=100), nullable=True)
            )
            batch_op.create_index(
                batch_op.f(f'ix_{table}_InviteTokenHash'),
                ['InviteTokenHash'],
                unique=False,
            )


def downgrade():
    for table in MEMBERSHIP_TABLES:
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.drop_index(batch_op.f(f'ix_{table}_InviteTokenHash'))
            batch_op.drop_column('InviteEmail')
