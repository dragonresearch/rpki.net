from django import template

register = template.Library()


class BootstrapPagerNode(template.Node):
    def __init__(self, request, pager_object):
        self.request = template.Variable(request)
        self.pager_object = template.Variable(pager_object)

    def render(self, context):
        request = self.request.resolve(context)
        pager_object = self.pager_object.resolve(context)
        r = ['<div class="pagination"><ul>']
        if pager_object.number == 1:
            r.append('<li class="disabled"><a>&laquo;</a></li>')
        else:
            r.append('<li><a href="%s?page=%d">&laquo;</a></li>' % (request.path, pager_object.number - 1))

        # display at most 5 pages around the current page
        min_page = max(pager_object.number - 2, 1)
        max_page = min(min_page + 5, pager_object.paginator.num_pages)

        if min_page > 1:
            r.append('<li class="disabled"><a>&hellip;</a></li>')

        for i in range(min_page, max_page + 1):
            r.append('<li %s><a href="%s?page=%d">%d</a></li>' % ('' if i != pager_object.number else 'class="active"', request.path, i, i))

        if max_page < pager_object.paginator.num_pages:
            r.append('<li class="disabled"><a>&hellip;</a></li>')

        if pager_object.number < pager_object.paginator.num_pages:
            r.append('<li><a href="%s?page=%d">&raquo;</a></li>' % (request.path, pager_object.number + 1))
        else:
            r.append('<li class="disabled"><a>&raquo;</a></li>')


        r.append('</ul></div>')
        return '\n'.join(r)


@register.tag
def bootstrap_pager(parser, token):
    try:
        tag_name, request, pager_object = token.split_contents()
    except ValueError:
        raise template.TemplateSyntaxError("%r tag requires two arguments" % token.contents.split()[0])
    return BootstrapPagerNode(request, pager_object)
