#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
File: main.py
Author: William Jellesma

This file houses all of the main functionality of the app that can't be refactored
"""
#Google app engine imports
import webapp2

#templating modules
import jinja2

#models, routes
import models
import routes

#OS modules
import os
template_dir = os.path.join(os.path.dirname(__file__), 'views')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

"""
Args: template (string), params (unlimited)

Returns:
render the template and any extra parameters to the screen
"""
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

"""
Args: response (string), post (GQL value)

Returns:
render the post
"""
#renders the post with all of the necessary content
def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

#this is where the app starts
app = routes.routes()
