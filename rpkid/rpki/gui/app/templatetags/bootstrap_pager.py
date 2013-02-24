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

        for i in pager_object.paginator.page_range:
            r.append('<li %s><a href="%s?page=%d">%d</a></li>' % ('' if i != pager_object.number else 'class="active"', request.path, i, i))


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
