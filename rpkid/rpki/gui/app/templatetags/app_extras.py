from django import template

register = template.Library()

@register.simple_tag
def verbose_name(obj):
    "Return the model class' verbose name."
    return obj._meta.verbose_name

@register.simple_tag
def verbose_name_plural(qs):
    "Return the verbose name for the model class."
    return qs.model._meta.verbose_name_plural
