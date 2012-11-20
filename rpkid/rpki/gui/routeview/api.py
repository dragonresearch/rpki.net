# Copyright (C) 2012  SPARTA, Inc. a Parsons Company
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND SPARTA DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL SPARTA BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

__version__ = '$Id$'

import json
from django import http
from rpki.gui.routeview.models import RouteOrigin, RouteOriginV6
from rpki import resource_set
import rpki.exceptions

def route_list(request):
    """Implements the REST query against the route models to allow the client
    to search for routes.

    The only search currently supported is returning all the routes covered by
    the prefix given in the 'prefix__in=' query string parameter.

    By default, only returns up to 10 matching routes, but the client may
    request a different limit with the 'count=' query string parameter.

    """
    hard_limit = 100

    if request.method == 'GET' and 'prefix__in' in request.GET:
        # find all routers covered by this prefix
        match_prefix = request.GET.get('prefix__in')
        # max number of items to return
        limit = request.GET.get('count', 10)
        if limit < 1 or limit > hard_limit:
            return http.HttpResponseBadRequest('invalid value for count parameter')

        try:
            if ':' in match_prefix:
                # v6
                pfx = resource_set.resource_range_ipv6.parse_str(match_prefix)
                manager = RouteOriginV6
            else:
                # v4
                pfx = resource_set.resource_range_ipv4.parse_str(match_prefix)
                manager = RouteOrigin
        except (AssertionError, rpki.exceptions.BadIPResource), e:
            return http.HttpResponseBadRequest(e)

        try:
            qs = manager.objects.filter(prefix_min__gte=pfx.min,
                                        prefix_max__lte=pfx.max)[:limit]
            # FIXME - a REST API should really return the url of the resource,
            # but since we are combining two separate tables, the .pk is not a
            # unique identifier.
            matches = [{'prefix': str(x.as_resource_range()), 'asn': x.asn} for x in qs]
        except IndexError:
            # no matches
            matches = []

        return http.HttpResponse(json.dumps(matches), content_type='text/javascript')

    return http.HttpResponseBadRequest()
