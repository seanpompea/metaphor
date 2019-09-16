import time
import metaphor
import logging
from logging.handlers import RotatingFileHandler
import os

def handle_hello(request):
  """Handler for /hello route."""
  print "handle_hello called."
  print request
  return {'status': 200
         ,'body': "Hello user! Your IP is: " + request['client_ip']}

def handle_datetime(request):
  """Handler for /datetime route.""" 
  print "handle_datetime called."
  print request
  currtime = time.asctime(time.localtime(time.time()))
  return {'status' : 200
         ,'body' : "The current date and time is: " + currtime}

# write 2 things to stdout:
# 1 the client IP
# 2 the post payload
def handle_posttest(request):
  """Handler for /posttest route."""
  print "handle_posttest called."
  print "client ip: " + request['client_ip']
  dat = request['data'] if 'data' in request else ''
  dat = request.get('data', 'no data')
  print "body of data: " + dat
  print "returning..."
  return {'status': 200
         ,'content-type': 'text/plain'
         ,'body': ("IP is: " + request['client_ip']
                    +"\nData was: " + dat)}

def handle_raise500(request):
  '''Handler for /raise500
  Here, intentionally invoke 500 status by raising an Exception'''
  raise Exception 

def create_logger(path, tag):
  """Put together a reasonable logger.
  See: https://docs.python.org/2.7/library/logging.html 
  and: http://www.blog.pythonlibrary.org/2014/02/11/python-how-to-create-rotating-logs/
  """
  #logging.basicConfig(filename=path)
  log = logging.getLogger(tag)
  log.setLevel(logging.INFO)
  handler = RotatingFileHandler( path 
                               , maxBytes=33554432 
                               , backupCount=16)
  fmt = logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s")
  handler.setFormatter(fmt)
  log.addHandler(handler)
  return log

def do_when_500(message):
  '''Demonstrate how custom logic can be invoked 
  when error (HTTP status 500) happens'''
  print 'Got Status 500.'

def run_example_server():
  '''Usage: python example.py'''
  routes = { '/hello' : handle_hello
           , '/datetime' : handle_datetime 
           , '/posttest' : handle_posttest            
           , '/raise500' : handle_raise500
          }
  path_to_pem = 'enclave/server.pem'
  print "Example Metaphor server starting.\n"
  # try different args
  log = create_logger('exampleserver.log', 'exampleserver')
  log.info('------------Starting...-------------')
  #metaphor.listen(routes, 4443, path_to_pem, set(['127.0.0.1']), 'My Example Metaphor Server!')
  #metaphor.listen(routes, 4443, path_to_pem, set(['127.0.0.2']), 'My Example Metaphor Server!')
  #metaphor.listen(routes, 2814, path_to_pem, logger=log)
  metaphor.listen(routes, 2814, None, path_to_pem, logger=log, special_500_logic=do_when_500)
  
if __name__ == "__main__":
  run_example_server()

