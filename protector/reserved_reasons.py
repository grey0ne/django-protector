from __future__ import unicode_literals

TEST_REASON = 'TEST REASON'
GENERIC_GROUP_UPDATE_REASON = 'Groups were created due to foreign key links update'


def ADMIN_PANEL_DELETE_REASON(user):
    if not user or not user.username:
        user = 'unknown user'
    return 'Relation was deleted through admin panel by {}'.format(user.username)


def MEMBER_FK_UPDATE_REASON(field):
    return 'User was added to group due to {} foreign key update'.format(field)
