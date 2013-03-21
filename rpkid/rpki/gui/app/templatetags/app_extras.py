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
