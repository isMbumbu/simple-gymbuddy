"""empty message

Revision ID: ca3318ce32a7
Revises: 
Create Date: 2025-01-30 23:02:09.570133

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ca3318ce32a7'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('booking', schema=None) as batch_op:
        batch_op.alter_column('class_id',
               existing_type=sa.INTEGER(),
               nullable=False)
        batch_op.alter_column('trainer_id',
               existing_type=sa.INTEGER(),
               nullable=False)
        batch_op.alter_column('member_id',
               existing_type=sa.INTEGER(),
               nullable=False)
        batch_op.drop_index('no_double_booking')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('booking', schema=None) as batch_op:
        batch_op.create_index('no_double_booking', ['class_id', 'start_time', 'end_time'], unique=True)
        batch_op.alter_column('member_id',
               existing_type=sa.INTEGER(),
               nullable=True)
        batch_op.alter_column('trainer_id',
               existing_type=sa.INTEGER(),
               nullable=True)
        batch_op.alter_column('class_id',
               existing_type=sa.INTEGER(),
               nullable=True)

    # ### end Alembic commands ###
