# metaphor

Simple HTTPS microframework written in Python with routing and IP filtering.

## how to run

- Use `listen`, the function that launches the HTTPS listener. See docstring for details.


## minimalist example

    import metaphor
    
    path_to_private_key = '/my/private.key'
    path_to_public_pem = '/my/public.pem' 
    port = 2814  
    routes = {'/hello': lambda req: {'status': 200, 'body': 'Hello!'}}     
                         
    metaphor.listen(routes
                   ,port
                   ,path_to_private_key
                   ,path_to_public_pem)

## routing

The `routes` argument to `listen` should be a set of key-value pairs where the keys are paths and the values are functions (handlers). See the example above.

## filtering IPs

The optional argument `filterlist` can be passed `listen`; it should be a collection of IP addresses.


## writing handlers

A handler is a function that should be prepared to receive a *request map* with the following keys:

* `'path'` — e.g., '/hello'
* `'client_ip'`
* `'method'` — e.g., 'GET'
* `'data'` — This will only be present when the HTTP method is 'POST'.

It should return a *response map* that contains, minimally, a single key-value pair:

* `'status'` — the value should be an HTTP status code

Optionally, the response map can also contain the following keys, but they're not required:

* `'content-type'`
* `'body'`

## example.py

`example.py` is a more complete example showing how to use Metaphor with a logger, multiple routes, and custom logic to run during status 500 scenarios.

## requirements

Python 2.7

## back matter

Inspired by Ring for the Clojure programming language: https://github.com/ring-clojure/ring/wiki/Concepts

