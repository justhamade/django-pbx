from django.template import Library

register = Library()

@register.filter
def pretty(value):
    bits = value.title().replace('Ivr', 'IVR').split('_')
    for i in xrange(len(bits) - 1, 0, -1):
        if bits[i - 1] == 'Mod':
            bits[i -1] = '_'.join((bits[i - 1], bits[i])).capitalize()
            del bits[i]
    return ' '.join(bits)
