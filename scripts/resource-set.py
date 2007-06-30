# $Id$

class resource(object):

  def __init__(self, car, cdr):
    self.car = car
    self.cdr = cdr

  def __str__(self):
    return "(" + str(self.car) + " . " + str(self.cdr) + ")"

  def __eq__(self, other):
    return self.car == other.car and self.cdr == other.cdr

  def __hash__(self):
    return self.car.__hash__() + self.cdr.__hash__()

class resource_set(set):

  def __init__(self, *elts):
    for e in elts:
      assert isinstance(e, resource)
    set.__init__(self, elts)

  def __str__(self):
    return "(" + " ".join(map(str, self)) + ")"

s = resource_set(resource("a", "b"), resource("c", "d"), resource("a", "b"))

print s

print len(s)

for i in s:
  print i
