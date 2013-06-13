from django import template

register = template.Library()


@register.simple_tag
def verbose_name(obj):
    "Return the model class' verbose name."
    return obj._meta.verbose_name.capitalize()


@register.simple_tag
def verbose_name_plural(qs):
    "Return the verbose name for the model class."
    return qs.model._meta.verbose_name_plural.capitalize()

css = {
    'valid': 'label-success',
    'invalid': 'label-important'
}


@register.simple_tag
def validity_label(validity):
    return '<span class="label %s">%s</span>' % (css.get(validity, ''), validity)


@register.simple_tag
def severity_class(severity):
    css = {
        0: 'label-info',
        1: 'label-warning',
        2: 'label-important',
    }
    return css.get(severity)


@register.simple_tag
def alert_count(conf):
    qs = conf.alerts.filter(seen=False)
    unread = len(qs)
    if unread:
        severity = max([x.severity for x in qs])
        css = {
            0: 'badge-info',
            1: 'badge-warning',
            2: 'badge-important'
        }
        css_class = css.get(severity)
    else:
        css_class = 'badge-default'
    return u'<span class="badge %s">%d</span>' % (css_class, unread)


@register.simple_tag
def rpki_version():
    import rpki.version
    return rpki.version.VERSION
