"""Temporary scan credentials for authenticated assessments.

Revision ID: c4d8f1a2b6e9
Revises: aaf9e35de1fe
Create Date: 2026-11-11 23:30:00.000000

Additive only: adds TrustScanCredential and its single-use binding table.  The
frozen core eight entities and the existing Trust Boundary tables are not
modified.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c4d8f1a2b6e9'
down_revision = 'aaf9e35de1fe'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'TrustScanCredential',
        sa.Column('CredentialID', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('OrganisationID', sa.Integer(), nullable=False),
        sa.Column('ProjectID', sa.Integer(), nullable=False),
        sa.Column('AssetID', sa.Integer(), nullable=False),
        sa.Column('Name', sa.String(length=100), nullable=False),
        sa.Column('AuthType', sa.String(length=10), nullable=False),
        sa.Column('LoginURL', sa.String(length=500), nullable=False),
        sa.Column('UsernameField', sa.String(length=64), nullable=True),
        sa.Column('PasswordField', sa.String(length=64), nullable=True),
        sa.Column('ExtraFieldsJson', sa.String(length=1000), nullable=True),
        sa.Column('SuccessURLContains', sa.String(length=255), nullable=True),
        sa.Column('SuccessText', sa.String(length=255), nullable=True),
        sa.Column('Username', sa.String(length=255), nullable=False),
        sa.Column('SecretEncrypted', sa.Text(), nullable=True),
        sa.Column('Status', sa.String(length=20), nullable=False),
        sa.Column('ExpiresAt', sa.DateTime(), nullable=False),
        sa.Column('CreatedByUserID', sa.Integer(), nullable=False),
        sa.Column('ApprovedByUserID', sa.Integer(), nullable=True),
        sa.Column('ApprovedAt', sa.DateTime(), nullable=True),
        sa.Column('ApprovalStatementHash', sa.String(length=64), nullable=True),
        sa.Column('RejectedAt', sa.DateTime(), nullable=True),
        sa.Column('RevokedAt', sa.DateTime(), nullable=True),
        sa.Column('RevokedByUserID', sa.Integer(), nullable=True),
        sa.Column('StatusReason', sa.String(length=500), nullable=True),
        sa.Column('UsedAt', sa.DateTime(), nullable=True),
        sa.Column('LastUsedAt', sa.DateTime(), nullable=True),
        sa.Column('LastTestedAt', sa.DateTime(), nullable=True),
        sa.Column('FailureReason', sa.String(length=500), nullable=True),
        sa.Column('CreatedAt', sa.DateTime(), nullable=False),
        sa.Column('UpdatedAt', sa.DateTime(), nullable=False),
        sa.Column('Version', sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "Status IN ('PendingApproval','Approved','Rejected','Revoked','Expired','Used')",
            name=op.f('ck_TrustScanCredential_ck_trust_credential_status'),
        ),
        sa.CheckConstraint(
            "AuthType IN ('FORM')",
            name=op.f('ck_TrustScanCredential_ck_trust_credential_auth_type'),
        ),
        sa.ForeignKeyConstraint(
            ['OrganisationID', 'ProjectID'],
            ['TrustProject.OrganisationID', 'TrustProject.ProjectID'],
            name='fk_trust_credential_project',
            ondelete='NO ACTION',
        ),
        sa.ForeignKeyConstraint(
            ['ProjectID', 'AssetID'],
            ['TrustAsset.ProjectID', 'TrustAsset.AssetID'],
            name='fk_trust_credential_asset',
            ondelete='NO ACTION',
        ),
        sa.ForeignKeyConstraint(
            ['ApprovedByUserID'], ['User.UserID'],
            name=op.f('fk_TrustScanCredential_ApprovedByUserID_User'),
            ondelete='NO ACTION',
        ),
        sa.ForeignKeyConstraint(
            ['CreatedByUserID'], ['User.UserID'],
            name=op.f('fk_TrustScanCredential_CreatedByUserID_User'),
            ondelete='NO ACTION',
        ),
        sa.ForeignKeyConstraint(
            ['RevokedByUserID'], ['User.UserID'],
            name=op.f('fk_TrustScanCredential_RevokedByUserID_User'),
            ondelete='NO ACTION',
        ),
        sa.PrimaryKeyConstraint('CredentialID', name=op.f('pk_TrustScanCredential')),
    )
    with op.batch_alter_table('TrustScanCredential', schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f('ix_TrustScanCredential_AssetID'), ['AssetID'], unique=False
        )
        batch_op.create_index(
            batch_op.f('ix_TrustScanCredential_CreatedByUserID'),
            ['CreatedByUserID'], unique=False,
        )
        batch_op.create_index(
            batch_op.f('ix_TrustScanCredential_OrganisationID'),
            ['OrganisationID'], unique=False,
        )
        batch_op.create_index(
            batch_op.f('ix_TrustScanCredential_ProjectID'),
            ['ProjectID'], unique=False,
        )

    op.create_table(
        'TrustScanCredentialBinding',
        sa.Column('ScanID', sa.Integer(), nullable=False),
        sa.Column('CredentialID', sa.Integer(), nullable=False),
        sa.Column('BoundAt', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ['CredentialID'], ['TrustScanCredential.CredentialID'],
            name=op.f('fk_TrustScanCredentialBinding_CredentialID_TrustScanCredential'),
            ondelete='NO ACTION',
        ),
        sa.ForeignKeyConstraint(
            ['ScanID'], ['Scan.ScanID'],
            name=op.f('fk_TrustScanCredentialBinding_ScanID_Scan'),
            ondelete='CASCADE',
        ),
        sa.PrimaryKeyConstraint('ScanID', name=op.f('pk_TrustScanCredentialBinding')),
        sa.UniqueConstraint(
            'CredentialID',
            name=op.f('uq_TrustScanCredentialBinding_CredentialID'),
        ),
    )
    with op.batch_alter_table('TrustScanCredentialBinding', schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f('ix_TrustScanCredentialBinding_CredentialID'),
            ['CredentialID'], unique=False,
        )


def downgrade():
    with op.batch_alter_table('TrustScanCredentialBinding', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_TrustScanCredentialBinding_CredentialID'))
    op.drop_table('TrustScanCredentialBinding')

    with op.batch_alter_table('TrustScanCredential', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_TrustScanCredential_ProjectID'))
        batch_op.drop_index(batch_op.f('ix_TrustScanCredential_OrganisationID'))
        batch_op.drop_index(batch_op.f('ix_TrustScanCredential_CreatedByUserID'))
        batch_op.drop_index(batch_op.f('ix_TrustScanCredential_AssetID'))
    op.drop_table('TrustScanCredential')
