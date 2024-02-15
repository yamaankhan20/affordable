# from flask import request
#
# class JWTMiddleware:
#     def __init__(self, app):
#         self.app = app
#
#     def __call__(self, environ, start_response):
#         token = self.extract_token_from_request(environ)
#         if token:
#             environ["HTTP_AUTHORIZATION"] = f"Bearer {token}"
#         return self.app(environ, start_response)
#
#     def extract_token_from_request(self, environ):
#         auth_header = environ.get("HTTP_AUTHORIZATION")
#         if auth_header:
#             parts = auth_header.split()
#             if len(parts) == 2 and parts[0].lower() == "bearer":
#                 return parts[1]
#         return None
