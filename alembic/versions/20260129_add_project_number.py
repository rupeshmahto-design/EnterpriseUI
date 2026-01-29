"""add project_number to threat_assessments

Revision ID: 20260129_0001
Revises: 20260125_0001_initial
Create Date: 2026-01-29

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '20260129_0001'
down_revision = '20260125_0001_initial'
branch_labels = None
depends_on = None


def upgrade():
    """Add project_number column to threat_assessments table"""
    op.add_column('threat_assessments', sa.Column('project_number', sa.String(length=100), nullable=True))
    op.create_index(op.f('ix_threat_assessments_project_number'), 'threat_assessments', ['project_number'], unique=False)


def downgrade():
    """Remove project_number column from threat_assessments table"""
    op.drop_index(op.f('ix_threat_assessments_project_number'), table_name='threat_assessments')
    op.drop_column('threat_assessments', 'project_number')
