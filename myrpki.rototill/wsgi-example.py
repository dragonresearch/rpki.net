# $Id$

# Every WSGI application must have an application object - a callable
# object that accepts two arguments. For that purpose, we're going to
# use a function (note that you're not limited to a function, you can
# use a class for example). The first argument passed to the function
# is a dictionary containing CGI-style envrironment variables and the
# second variable is the callable object (see PEP333)

# See http://pythonpaste.org/do-it-yourself-framework.html for a
# somewhat more complete introduction, although it's a lead-in to the
# Paste package which we might not want to use.

def hello_world_app(environ, start_response):
  status = '200 OK' # HTTP Status
  headers = [('Content-type', 'text/plain')] # HTTP Headers
  start_response(status, headers)

  # The returned object is going to be printed
  return ["Hello World"]

# Run server with this app on port 8000 if invoked as a script

if __name__ == "__main__":
  from wsgiref.simple_server import make_server
  print "Serving on port 8000..."
  make_server('', 8000, hello_world_app).serve_forever()
