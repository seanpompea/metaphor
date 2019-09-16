import BaseHTTPServer as http
import SocketServer as socketserver
import socket
import ssl
import logging

__all__ = ['listen']

#-------------------------------------------------------------------------------

class metaphor_handler(http.BaseHTTPRequestHandler):
  '''Handler class facilitates simple routing. Unlike the parent class,
  this version drops the convention of do_GET/do_POST methods.'''
  
  # overrides
  def handle_one_request(self):
    '''Handle a single HTTP request.
    This overrides the parent method; much of the original code is 
    reused; but rather than determine the HTTP method 
    and then pass to do_GET/do_POST, etc., we build a request-shaped map 
    (which includes the method name), hand it to the appropriate function as 
    specified in the routes data structure, and then hand whatever gets 
    returned (which should be a response-shaped map) to the _transmit 
    method.'''
    try:
      self.raw_requestline = self.rfile.readline(65537)
      if len(self.raw_requestline) > 65536:
        # Bail if the URL is too long.
        self.requestline = ''
        self.request_version = ''
        self.command = ''
        self.send_error(414)
        self.wfile.flush()
        return
      if not self.raw_requestline:
        self.close_connection = 1
        return
      if not self.parse_request():
        # An error code has been written by parse_request()
        self.wfile.flush()
        return
      # Build request map.
      req = {'path': self.path
            ,'method': self.command
            ,'client_ip': self.client_address[0]}
      if req['method'] == 'POST':
        content_len = int(self.headers.getheader('content-length', 0))
        post_body = self.rfile.read(content_len)
        req['data'] = post_body
      # Is client IP in list?
      if not self.server.filterlist or req['client_ip'] in self.server.filterlist:
        # Handle if so.
        resp = self._route(self.server.routes, req) 
      else:
        resp = self.send_error(403)
        self.wfile.flush()
        return
      # send response to client via socket
      #raise Exception('artificial: uncomment to test error handling')
      self._transmit(resp)
      self.wfile.flush()
    # Catch 'TLv1 unknown CA', etc.  This can occur when using
    # self-signed cert and client is Firefox or similar.
    # Note taht we *don't* return a response -- ssl handshake
    # never even finished, so conn wasn't really established. 
    # See:
    #   https://hg.python.org/cpython/file/2.7/Lib/ssl.py
    #   https://stackoverflow.com/a/37359283
    except ssl.SSLError, e:
      msg = 'Caught SSLError. One possible situation: '\
            'server using a self-signed cert and client is Firefox.'
      self.log_error(msg + ' -- ' + str(e)) 
    # This except block is same as parent version.
    except socket.timeout, e:
      # A read or write timed out. Discard this connection.
      self.log_error("Request timed out: %r", e)
    # Lastly, deal w/ anything else...
    except Exception, e1:
      # A way to test this final except block is by putting 
      # 'raise Exception("thrown!")' temporarily at the top just 
      # beneath the start of the try.
      try:
        self.log_error('Exception caught; details: ' + str(type(e1)) + ': ' + str(e1))
        self.send_error(500, 'Server Error')
        self.wfile.flush() # Not sure whether BaseHTTPServer does this, so we do it to be safe.
      except Exception, e2:
        self.log_error('Caught exception and then another while sending error: e1=[{}].' \
                       ' e2=[{}].'.format(str(e1), str(e2)))
    finally:
      self.close_connection = 1

  # overrides
  def log_error(self, format, *args):
    msg = "%s - - [%s] %s" % (self.client_address[0],
                              self.log_date_time_string(),
                              format%args)
    if self.server.logger:
      self.server.logger.error(msg)
    else:
      http.BaseHTTPRequestHandler.log_error(self, format, *args)

  # overrides
  def log_request(self, code='-', size='-'):
    if self.server.logger:
      msg = '%s "%s" %s %s' % (self.client_address[0]
                              ,self.requestline # er, self.raw_requestline?
                              ,str(code)
                              ,str(size))
      self.server.logger.info(msg)
    else:
      http.BaseHTTPRequestHandler.log_request(self, code, size)

  # overrides
  def send_error(self, code, message=None):
    """Send and log an error reply.

    *Purpose of overriding:* to allow for additional custom logic
    defined by the user of the framework. Everything else is the same. 
    (Can't use 'super()' since this is an old-style class.
    Maybe there's a better way?)

    Arguments are the error code, and a detailed message.
    The detailed message defaults to the short entry matching the
    response code.

    This sends an error response (so it must be called before any
    output has been generated), logs the error, and finally sends
    a piece of HTML explaining the error to the user.

    """
    def _quote_html(html):
      """ From BaseHTTPServer module. """
      return html.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # Do custom logic, maybe.
    if int(code) == 500 and self.server.special_500_logic:
      self.server.special_500_logic(message)
    # Rest is the same as parent.
    try:
        short, long = self.responses[code]
    except KeyError:
        short, long = '???', '???'
    if message is None:
        message = short
    explain = long
    self.log_error("code %d, message %s", code, message)
    # using _quote_html to prevent Cross Site Scripting attacks (see bug #1100201)
    content = (self.error_message_format %
               {'code': code, 'message': _quote_html(message), 'explain': explain})
    self.send_response(code, message)
    self.send_header("Content-Type", self.error_content_type)
    self.send_header('Connection', 'close')
    self.end_headers()
    if self.command != 'HEAD' and code >= 200 and code not in (204, 304):
        self.wfile.write(content)

  def _route(self, routes, request):
    if request['path'] in routes.keys():
      return (routes[request['path']])(request)
    else:
      return {'status': 404, 'body': '404'}

  def _transmit(self, response):
    '''This is the final step. Here we step down a layer and 
    begin to use the handler obj's send_* functions and go 
    through the final steps to wrap up the 
    request/response cycle and transmit (i.e., flush wfile).
    Things we do:
      - send 500 if there's no status in response
      - if the status is a string, try to convert to int.
      - assume content type of text/plain if not present
      - body defaults to status value if not already defined.'''
    status = response.get('status', -1)
    # If we get here and status is missing, a handler somewhere
    # upstream isn't working right; send error 500.
    if status == -1:
      self.send_error(500)
      return
    if type(status) == str:
      status = int(status)    
    body = response.get('body', response.get('status'))
    content_type = response.get('content-type', 'text/plain')
    self.send_response(status)
    if body:
      self.send_header('Content-type', content_type)
    self.end_headers()
    if body:
      self.wfile.write(body)
    self.wfile.flush()

# end handler class

#-------------------------------------------------------------------------------
# server

class threaded_http_server(socketserver.ThreadingMixIn, http.HTTPServer):
  pass

class metaphor_server(threaded_http_server): 

  def __init__(self, server_address, handler_class):
    threaded_http_server.__init__(self, server_address, handler_class)
    self.routes = {}
    self.filterlist = []
    self.special_500_logic=None

  def load_routes(self, routes):
    self.routes = routes.copy()

  def load_filterlist(self, filterlist):
    self.filterlist = list(filterlist)

#-------------------------------------------------------------------------------
# api

def listen(routes
         , port
         , path_to_key
         , path_to_pem
         , filterlist=set()
         , logger=None
         , special_500_logic=None):

  """Start the HTTPS server.

  Arguments:
    port        integer indicating port to listen on.
    path_to_key The path to the private key (for HTTPS). If null, skips.
    path_to_pem The path to the PEM file (for HTTPS). 
    filterlist   A set containing one or IPs as strings. 
                If missing, all IPs are filterlisted.
    logger      A Logger object; if missing, logs to console.
    special_500_logic 
               Function to call when sending 500, if one is passed in.

  routes is a dictionary formatted like so:
    { '/path1' : handler_func_1
    , '/path2' : handler_func_2 }
  A route string of '/route1' correlates to: https://localhost:8000/route1

  At a high level, a request/response cycle does this:
    1) confirm the remote requester is filterlisted
    2) log request
    3) route to handler based on endpoint
    4) log response
    5) send response

  request/response conventions:
    A 'request' is a dictionary formatted like so:
        { 'method'    : 'POST'
        , 'path'      : '/requestedpath'
        , 'client_ip' : '1.1.1.1'
        , 'data'      : '{"foo":"bar"}' }
        ... where method is one of 'GET', 'POST', etc.
            and data is the data passed when method was POST;
            otherwise, data will not be present. 
    Likewise, a response is a dictionary formatted like so:
       { 'status' : 200
       , 'content-type' : 'text/plain'
       , 'body' : 'Hello world...' }
        ... where 'status' corresponds to any typical HTTP status and
            and content-type corresponds to a mime type.
    At minimum, a response must contain a 'status'.

  Errors
    Common errors:
      o socket.error: [Errno 13] Permission denied
        You are likely trying to listen on a port that is restricted (e.g.
        1024 or below). See: https://serverfault.com/questions/268099/bind-to-ports-less-than-1024-without-root-access
  """
  try:
    config = ('', port) # First arg to config is server_address; seems fine to
                        # leave it blank.
    svr = metaphor_server(config, metaphor_handler)
    if logger:
      if isinstance(logger, logging.Logger):
        svr.logger = logger
      else:
        raise ValueError('logger must be type logging.Logger')
    else:
      svr.logger = None # just to be clear.
    if path_to_key:
      svr.socket = ssl.wrap_socket(svr.socket, keyfile=path_to_key
                                  ,certfile=path_to_pem, server_side=True)
    else:
      svr.socket = ssl.wrap_socket(svr.socket
                                  ,certfile=path_to_pem, server_side=True)
    svr.load_routes(routes)
    if filterlist:
      svr.load_filterlist(filterlist)
    if special_500_logic:
      svr.special_500_logic = special_500_logic 
    # and... start!
    svr.serve_forever()
  except KeyboardInterrupt:
    print " KeyboardInterrupt ... shutting down server."
  except IOError, e: 
    print str(e)
    if logger: logger.error(str(e))
    raise
  finally:
    if 'svr' in locals():
      svr.socket.close()

