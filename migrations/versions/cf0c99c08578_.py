"""Audit log changed datetime columns

Revision ID: cf0c99c08578
Revises:
Create Date: 2017-12-12 21:12:56.282095

"""
from datetime import datetime

from alembic import op
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy_continuum import version_class

from tracker import db
from tracker.model import CVE
from tracker.model import Advisory
from tracker.model import CVEGroup

# revision identifiers, used by Alembic.
revision = 'cf0c99c08578'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # TODO: update insert CVE
    # TODO: create/drop transaction index

    op.add_column('cve_group',
                  Column('changed',
                         DateTime,
                         default=datetime.utcnow,
                         nullable=True,
                         index=True))

    for group in CVEGroup.query.all():
        group.changed = group.created

    db.session.commit()
    db.session.flush()

    with op.batch_alter_table('cve_group', schema=None) as batch_op:
        batch_op.alter_column('changed', nullable=False)

    op.add_column('advisory',
                  Column('changed',
                         DateTime,
                         default=datetime.utcnow,
                         nullable=True,
                         index=True))

    for advisory in Advisory.query.all():
        advisory.changed = group.created

    db.session.commit()
    db.session.flush()

    with op.batch_alter_table('advisory', schema=None) as batch_op:
        batch_op.alter_column('changed', nullable=False)

    # set all fields to modified for initial insert
    VersionClassCVE = version_class(CVE)
    VersionClassCVE.query.update({
        VersionClassCVE.operation_type: 0,
        VersionClassCVE.issue_type_mod: 1,
        VersionClassCVE.description_mod: 1,
        VersionClassCVE.severity_mod: 1,
        VersionClassCVE.remote_mod: 1,
        VersionClassCVE.reference_mod: 1,
        VersionClassCVE.notes_mod: 1
    })
    VersionClassGroup = version_class(CVEGroup)
    VersionClassGroup.query.update({
        VersionClassGroup.operation_type: 0,
        VersionClassGroup.status_mod: 1,
        VersionClassGroup.severity_mod: 1,
        VersionClassGroup.affected_mod: 1,
        VersionClassGroup.fixed_mod: 1,
        VersionClassGroup.bug_ticket_mod: 1,
        VersionClassGroup.reference_mod: 1,
        VersionClassGroup.notes_mod: 1,
        VersionClassGroup.created_mod: 1,
        VersionClassGroup.changed_mod: 1,
        VersionClassGroup.advisory_qualified_mod: 1
    })
    VersionClassAdvisory = version_class(Advisory)
    VersionClassAdvisory.query.update({
        VersionClassAdvisory.operation_type: 0,
        VersionClassAdvisory.group_package_id_mod: 1,
        VersionClassAdvisory.advisory_type_mod: 1,
        VersionClassAdvisory.publication_mod: 1,
        VersionClassAdvisory.workaround_mod: 1,
        VersionClassAdvisory.impact_mod: 1,
        VersionClassAdvisory.content_mod: 1,
        VersionClassAdvisory.created_mod: 1,
        VersionClassAdvisory.changed_mod: 1,
        VersionClassAdvisory.reference_mod: 1
    })
    db.session.commit()

    'CREATE UNIQUE INDEX ix_transaction_id ON "transaction" (id);'


def downgrade():
    with op.batch_alter_table('cve_group', schema=None) as batch_op:
        batch_op.drop_index('ix_cve_group_changed')
        batch_op.drop_column('changed')

    with op.batch_alter_table('advisory', schema=None) as batch_op:
        batch_op.drop_index('ix_advisory_changed')
        batch_op.drop_column('changed')

    VersionClassCVE = version_class(CVE)
    VersionClassCVE.query.delete()

    VersionClassGroup = version_class(CVEGroup)
    VersionClassGroup.query.delete()

    VersionClassAdvisory = version_class(Advisory)
    VersionClassAdvisory.query.delete()

    db.session.commit()
