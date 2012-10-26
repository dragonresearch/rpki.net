from _POW import *

# Set callback to let POW construct rpki.sundial.datetime objects

from rpki.sundial import datetime as sundial_datetime
customDatetime(sundial_datetime)
del sundial_datetime
