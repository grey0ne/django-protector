from protector.models import OwnerToPermission, HistoryOwnerToPermission
from test_app.models import TestUser


def check():
    u = TestUser.objects.last()
    o = OwnerToPermission.objects.last()
    o.delete(u, 'some reason')

    print(OwnerToPermission.objects.all(), HistoryOwnerToPermission.objects.all())
