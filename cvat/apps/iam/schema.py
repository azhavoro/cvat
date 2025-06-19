# Copyright (C) 2022 Intel Corporation
# Copyright (C) CVAT.ai Corporation
#
# SPDX-License-Identifier: MIT

import re
import textwrap

from drf_spectacular.authentication import SessionScheme
from drf_spectacular.extensions import OpenApiAuthenticationExtension
from drf_spectacular.openapi import AutoSchema
from rest_framework import serializers


class SignatureAuthenticationScheme(OpenApiAuthenticationExtension):
    """
    Adds the signature auth method to schema
    """

    target_class = "cvat.apps.iam.authentication.SignatureAuthentication"
    name = "signatureAuth"  # name used in the schema

    def get_security_definition(self, auto_schema):
        return {
            "type": "apiKey",
            "in": "query",
            "name": "sign",
            "description": "Can be used to share URLs to private links",
        }


class CookieAuthenticationScheme(SessionScheme):
    """
    This class adds csrftoken cookie into security sections. It must be used together with
    the 'sessionid' cookie.
    """

    name = ["sessionAuth", "csrfAuth"]
    priority = 0

    def get_security_definition(self, auto_schema):
        sessionid_schema = super().get_security_definition(auto_schema)
        sessionid_schema["description"] = textwrap.dedent(
            """\
            This cookie can be obtained after performing a login request.
            """
        )

        csrftoken_schema = {
            "type": "apiKey",
            "in": "cookie",
            "name": "csrftoken",
            "description": textwrap.dedent(
                """\
            Can be sent as a cookie or as the X-CSRFTOKEN header.
            This cookie can be obtained after performing a login request.
            """
            ),
        }
        return [sessionid_schema, csrftoken_schema]


class CustomAutoSchema(AutoSchema):
    def get_operation_id(self):
        # Change style of operation ids to [viewset _ action _ object]
        # This form is simpler to handle during SDK generation

        tokenized_path = self._tokenize_path()
        # replace dashes as they can be problematic later in code generation
        tokenized_path = [t.replace("-", "_") for t in tokenized_path]

        if self.method == "GET" and self._is_list_view():
            action = "list"
        else:
            action = self.method_mapping[self.method.lower()]

        if not tokenized_path:
            tokenized_path.append("root")

        if re.search(r"<drf_format_suffix\w*:\w+>", self.path_regex):
            tokenized_path.append("formatted")

        return "_".join([tokenized_path[0]] + [action] + tokenized_path[1:])

    def _get_request_for_media_type(self, serializer, *args, **kwargs):
        # Enables support for required=False serializers in request body specification
        # in drf-spectacular. Doesn't block other extensions on the target serializer.
        # This is supported by OpenAPI and by SDK generator, but not by drf-spectacular

        schema, required = super()._get_request_for_media_type(serializer, *args, **kwargs)

        if isinstance(serializer, serializers.Serializer):
            if not serializer.required:
                required = False

        return schema, required
