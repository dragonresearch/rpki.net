import json
from django import http
from rpki.gui.cacheview.models import ROAPrefixV4
from rpki import resource_set

def roa_list(request):
    "return all ROAs that cover a given prefix"
    prefix = resource_set.resource_range_ipv4.parse_str(request.GET['prefix'])
    matches = []
    for obj in ROAPrefixV4.objects.filter(prefix_min__lte=prefix.min,
                                          prefix_max__gte=prefix.max):
        for r in obj.roas.all():
            matches.append({"prefix": str(obj.as_resource_range()),
                            "max_length": obj.max_length,
                            "asn": r.asid})
    return http.HttpResponse(json.dumps(matches), content_type='text/javascript')

