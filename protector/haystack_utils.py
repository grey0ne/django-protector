from haystack import indexes
from haystack.query import SearchQuerySet

from protector.helpers import filter_object_id_list
from protector.models import get_view_permission


class ProtectedIndex(indexes.SearchIndex):
    restriction_id = indexes.IntegerField(
        model_attr='restriction_id', indexed=False, null=True
    )
    restriction_content_type_id = indexes.IntegerField(
        model_attr='restriction_content_type_id', indexed=False, null=True
    )


class RestrictedSearchQuerySet(SearchQuerySet):
    def __init__(self, *args, **kwargs):
        super(RestrictedSearchQuerySet, self).__init__(*args, **kwargs)
        self.user = None

    def visible(self, user):
        result = self.all()
        result.user = user
        return result

    def post_process_results(self, results):
        to_cache = super(RestrictedSearchQuerySet, self).post_process_results(results)

        view_perm = get_view_permission()
        view_perm_name = "{0}.{1}".format(view_perm.content_type.app_label, view_perm.codename)
        if self.user.has_perm(view_perm_name):
            return to_cache

        check_ids = []
        for result in to_cache:
            if result.restriction_id and result.restriction_content_type_id:
                check_ids.append((result.restriction_content_type_id, result.restriction_id))

        if self.user and check_ids:
            result_ids = set(
                filter_object_id_list(check_ids, self.user.id, get_view_permission().id)
            )
        else:
            result_ids = set()

        def check_id(result):
            in_ids = (result.restriction_content_type_id, result.restriction_id) in result_ids
            return in_ids or result.restriction_id is None

        return [result for result in to_cache if check_id(result)]

    def _clone(self):
        clone = super(RestrictedSearchQuerySet, self)._clone()
        clone.user = self.user
        return clone
